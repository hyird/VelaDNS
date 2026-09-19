package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hyird/VelaDNS/internal/statewire"
	"github.com/miekg/dns"
)

const dohBridgeAddr = "127.0.0.1:5307"

type resolverFunc func(context.Context, *dns.Msg) (*dns.Msg, error)

// Bootstrapped upstreams are dialed through Mihomo, so their dial addresses
// are fake IPs. Those are stable while Mihomo runs but are reassigned when its
// fake-IP pool is rebuilt, and a stale entry then points at another domain's
// mapping. Cache them long enough to keep the bootstrap query off the hot dial
// path, and discard them as soon as an exchange fails.
const dialAddressTTL = time.Minute

type dohUpstream struct {
	tag               string
	url               string
	client            *http.Client
	invalidateDialIPs func()
	observe           func(dohObservation, time.Duration, time.Time)
	backoffMu         sync.Mutex
	backoffStep       uint
	failures          uint
	retryAt           time.Time
	probing           bool
}

type dohBridge struct {
	resolvers []resolverFunc
	log       *logger
	udp       *dns.Server
	tcp       *dns.Server
	closeOnce sync.Once
	warnMu    sync.Mutex
	lastWarn  time.Time
}

func startDoHBridge(
	ctx context.Context,
	cfg config,
	state *runtimeState,
	log *logger,
) (*dohBridge, error) {
	bridge := &dohBridge{
		log: log,
	}
	for _, upstream := range selectDoHUpstreams(ctx, cfg, state, log) {
		bridge.resolvers = append(bridge.resolvers, upstream.exchange)
	}

	udpConn, err := net.ListenPacket("udp4", dohBridgeAddr)
	if err != nil {
		return nil, fmt.Errorf("listen encrypted bridge UDP: %w", err)
	}
	tcpListener, err := net.Listen("tcp4", dohBridgeAddr)
	if err != nil {
		_ = udpConn.Close()
		return nil, fmt.Errorf("listen encrypted bridge TCP: %w", err)
	}
	bridge.udp = &dns.Server{PacketConn: udpConn, Handler: bridge}
	bridge.tcp = &dns.Server{Listener: tcpListener, Handler: bridge}
	state.update("doh_bridge", func(component *statewire.Component) {
		component.Up = true
	})

	serve := func(network string, server *dns.Server) {
		if err := server.ActivateAndServe(); err != nil && ctx.Err() == nil {
			log.errorf("encrypted bridge %s stopped: %v", network, err)
			state.update("doh_bridge", func(component *statewire.Component) {
				component.Up = false
			})
		}
	}
	go serve("UDP", bridge.udp)
	go serve("TCP", bridge.tcp)
	go func() {
		<-ctx.Done()
		bridge.close()
		state.update("doh_bridge", func(component *statewire.Component) {
			component.Up = false
		})
	}()
	log.infof("encrypted DoH bridge ready on %s", dohBridgeAddr)
	return bridge, nil
}

func selectDoHUpstreams(
	ctx context.Context,
	cfg config,
	state *runtimeState,
	log *logger,
) []*dohUpstream {
	upstreams := make([]*dohUpstream, 0, 4)
	for _, upstream := range autoDoHUpstreams(cfg) {
		attachDoHObservation(state, upstream)
		if err := probeDoHUpstream(ctx, upstream); err != nil {
			// A failed startup probe is recoverable and is already exported
			// through the provider metrics. Runtime exhaustion still produces
			// a rate-limited warning from warnUnavailable.
			log.infof(
				"encrypted upstream %s is unavailable at startup; automatic retry remains enabled: %v",
				upstream.tag,
				err,
			)
		} else {
			log.infof("encrypted upstream %s enabled through AUTO_FORWARD", upstream.tag)
		}
		upstreams = append(upstreams, upstream)
	}
	for _, upstream := range directDoHUpstreams() {
		attachDoHObservation(state, upstream)
		upstreams = append(upstreams, upstream)
	}
	return upstreams
}

func attachDoHObservation(state *runtimeState, upstream *dohUpstream) {
	state.registerDoHUpstream(upstream.tag)
	upstream.observe = func(result dohObservation, duration time.Duration, retryAt time.Time) {
		state.observeDoHUpstream(upstream.tag, result, duration, retryAt)
	}
}

func autoDoHUpstreams(cfg config) []*dohUpstream {
	if !cfg.autoEnabled {
		return nil
	}
	return []*dohUpstream{
		newBootstrappedDoHUpstream(
			"nextdns-via-auto-forward",
			"https://dns.nextdns.io",
			"dns.nextdns.io",
			cfg.autoDNS,
		),
		newBootstrappedDoHUpstream(
			"quad9-via-auto-forward",
			"https://dns.quad9.net/dns-query",
			"dns.quad9.net",
			cfg.autoDNS,
		),
	}
}

func directDoHUpstreams() []*dohUpstream {
	return []*dohUpstream{
		newDoHUpstream(
			"cloudflare",
			"https://cloudflare-dns.com/dns-query",
			"cloudflare-dns.com",
			[]string{"104.16.248.249", "104.16.249.249"},
		),
		newDoHUpstream(
			"360",
			"https://doh.360.cn/dns-query",
			"doh.360.cn",
			[]string{
				"101.226.4.6",
				"218.30.118.6",
				"101.91.111.153",
				"36.99.170.86",
				"106.63.24.74",
			},
		),
	}
}

func probeDoHUpstream(ctx context.Context, upstream *dohUpstream) error {
	query := new(dns.Msg)
	query.SetQuestion("dns.google.", dns.TypeA)
	query.SetEdns0(1232, true)
	query.CheckingDisabled = true
	probeCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	response, err := upstream.exchange(probeCtx, query)
	if err != nil {
		return err
	}
	if response.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("probe returned %s", dns.RcodeToString[response.Rcode])
	}
	hasAddress := false
	hasSignature := false
	for _, record := range response.Answer {
		switch record.Header().Rrtype {
		case dns.TypeA:
			hasAddress = true
		case dns.TypeRRSIG:
			hasSignature = true
		}
	}
	if !hasAddress {
		return errors.New("probe returned no IPv4 address")
	}
	if !hasSignature {
		return errors.New("probe stripped DNSSEC signatures")
	}
	return nil
}

func newDoHUpstream(tag, url, serverName string, dialIPs []string) *dohUpstream {
	return newDoHUpstreamWithResolver(tag, url, serverName, func(context.Context) ([]string, error) {
		return dialIPs, nil
	}, nil)
}

func newBootstrappedDoHUpstream(tag, url, serverName, bootstrapDNS string) *dohUpstream {
	cache := new(dialAddressCache)
	return newDoHUpstreamWithResolver(tag, url, serverName, func(ctx context.Context) ([]string, error) {
		return cache.get(ctx, func(ctx context.Context) ([]string, error) {
			return resolveDoHAddresses(ctx, bootstrapDNS, serverName)
		})
	}, cache.invalidate)
}

// dialAddressCache keeps the bootstrap lookup off the per-connection dial path.
// Resolving it inline meant every cold dial spent up to a second on a bootstrap
// query to Mihomo before the TCP connect and TLS handshake had even started,
// which no realistic request deadline could absorb.
type dialAddressCache struct {
	mu        sync.Mutex
	addresses []string
	expiresAt time.Time
}

func (c *dialAddressCache) get(
	ctx context.Context,
	resolve func(context.Context) ([]string, error),
) ([]string, error) {
	c.mu.Lock()
	if len(c.addresses) > 0 && time.Now().Before(c.expiresAt) {
		cached := c.addresses
		c.mu.Unlock()
		return cached, nil
	}
	c.mu.Unlock()

	addresses, err := resolve(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.addresses = addresses
	c.expiresAt = time.Now().Add(dialAddressTTL)
	c.mu.Unlock()
	return addresses, nil
}

func (c *dialAddressCache) invalidate() {
	c.mu.Lock()
	c.addresses = nil
	c.expiresAt = time.Time{}
	c.mu.Unlock()
}

func newDoHUpstreamWithResolver(
	tag, url, serverName string,
	resolveDialIPs func(context.Context) ([]string, error),
	invalidateDialIPs func(),
) *dohUpstream {
	var next atomic.Uint64
	dialer := &net.Dialer{Timeout: 1500 * time.Millisecond, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: serverName,
		},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialIPs, err := resolveDialIPs(ctx)
			if err != nil {
				return nil, fmt.Errorf("%s resolve dial address: %w", tag, err)
			}
			if len(dialIPs) == 0 {
				return nil, errors.New("encrypted upstream has no dial address")
			}
			index := int(next.Add(1)-1) % len(dialIPs)
			return dialer.DialContext(ctx, network, net.JoinHostPort(dialIPs[index], "443"))
		},
	}
	return &dohUpstream{
		tag:               tag,
		url:               url,
		invalidateDialIPs: invalidateDialIPs,
		client: &http.Client{
			Transport: transport,
			// This budget covers the TCP connect and the TLS handshake, not
			// just the request. A cold connection cannot complete inside the
			// dialer's own timeout, so anything shorter fails every upstream
			// whose idle connection has expired and pushes it into backoff.
			Timeout: 3 * time.Second,
		},
	}
}

func resolveDoHAddresses(ctx context.Context, bootstrapDNS, serverName string) ([]string, error) {
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(serverName), dns.TypeA)
	client := &dns.Client{
		Net:     "tcp",
		Timeout: time.Second,
	}
	response, _, err := client.ExchangeContext(ctx, query, bootstrapDNS)
	if err != nil {
		return nil, err
	}
	if response.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("bootstrap DNS returned %s", dns.RcodeToString[response.Rcode])
	}
	addresses := make([]string, 0, len(response.Answer))
	for _, record := range response.Answer {
		if address, ok := record.(*dns.A); ok {
			addresses = append(addresses, address.A.String())
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("bootstrap DNS returned no IPv4 address")
	}
	return addresses, nil
}

func (u *dohUpstream) exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	startedAt := time.Now()
	permit, allowed := u.acquire()
	if !allowed {
		u.record(dohBackoffSkip, time.Since(startedAt))
		return nil, fmt.Errorf("%s retry is in exponential backoff", u.tag)
	}
	answer, err := u.exchangeOnce(ctx, query)
	if err != nil {
		if u.invalidateDialIPs != nil {
			u.invalidateDialIPs()
		}
		u.fail(permit)
		u.record(dohFailure, time.Since(startedAt))
		return nil, err
	}
	u.succeed()
	u.record(dohSuccess, time.Since(startedAt))
	return answer, nil
}

func (u *dohUpstream) record(result dohObservation, duration time.Duration) {
	if u.observe == nil {
		return
	}
	u.backoffMu.Lock()
	retryAt := u.retryAt
	u.backoffMu.Unlock()
	u.observe(result, duration, retryAt)
}

// dohFailureThreshold is the number of consecutive failures tolerated before an
// upstream is parked. One timeout is normal on a congested link; parking the
// preferred provider for minutes over it strands every query on the emergency
// fallbacks, which are exactly the ones most likely to be polluted.
const dohFailureThreshold = 2

type dohPermit struct {
	probe bool
}

func (u *dohUpstream) acquire() (dohPermit, bool) {
	u.backoffMu.Lock()
	defer u.backoffMu.Unlock()
	if u.backoffStep == 0 {
		return dohPermit{}, true
	}
	if time.Now().Before(u.retryAt) || u.probing {
		return dohPermit{}, false
	}
	u.probing = true
	return dohPermit{probe: true}, true
}

func (u *dohUpstream) fail(permit dohPermit) {
	u.backoffMu.Lock()
	defer u.backoffMu.Unlock()
	if u.backoffStep == 0 {
		u.failures++
		if u.failures < dohFailureThreshold {
			return
		}
		u.backoffStep = 1
	} else if permit.probe && u.probing {
		u.backoffStep++
	} else {
		return
	}
	u.probing = false
	u.retryAt = time.Now().Add(jitterDoHBackoff(u.backoffStep))
}

func (u *dohUpstream) succeed() {
	u.backoffMu.Lock()
	defer u.backoffMu.Unlock()
	u.backoffStep = 0
	u.failures = 0
	u.retryAt = time.Time{}
	u.probing = false
}

func jitterDoHBackoff(step uint) time.Duration {
	const maximum = 5 * time.Minute
	delay := time.Second
	for current := uint(1); current < step && delay < maximum; current++ {
		delay *= 2
		if delay >= maximum {
			delay = maximum
			break
		}
	}
	spread := delay / 5
	jittered := delay - spread + time.Duration(rand.Int63n(int64(2*spread)+1))
	if jittered > maximum {
		return maximum
	}
	return jittered
}

func (u *dohUpstream) exchangeOnce(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	payload, err := query.Pack()
	if err != nil {
		return nil, fmt.Errorf("%s pack query: %w", u.tag, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, u.url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("%s create request: %w", u.tag, err)
	}
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("Content-Type", "application/dns-message")
	response, err := u.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s request: %w", u.tag, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned HTTP %d", u.tag, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, dns.MaxMsgSize))
	if err != nil {
		return nil, fmt.Errorf("%s read response: %w", u.tag, err)
	}
	answer := new(dns.Msg)
	if err := answer.Unpack(body); err != nil {
		return nil, fmt.Errorf("%s decode response: %w", u.tag, err)
	}
	if !answer.Response || len(answer.Question) != len(query.Question) {
		return nil, fmt.Errorf("%s returned an invalid DNS response", u.tag)
	}
	answer.Id = query.Id
	return answer, nil
}

func (b *dohBridge) ServeDNS(writer dns.ResponseWriter, query *dns.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var lastErr error
	for _, resolver := range b.resolvers {
		response, err := resolver(ctx, query.Copy())
		if err == nil && response != nil {
			_ = writer.WriteMsg(response)
			return
		}
		lastErr = err
		if ctx.Err() != nil {
			lastErr = ctx.Err()
			break
		}
	}
	b.warnUnavailable(lastErr)
	failure := new(dns.Msg)
	failure.SetRcode(query, dns.RcodeServerFailure)
	_ = writer.WriteMsg(failure)
}

func (b *dohBridge) warnUnavailable(err error) {
	b.warnMu.Lock()
	defer b.warnMu.Unlock()
	if time.Since(b.lastWarn) < 30*time.Second {
		return
	}
	b.lastWarn = time.Now()
	b.log.warnf("all encrypted DNS upstreams failed: %v", err)
}

func (b *dohBridge) close() {
	b.closeOnce.Do(func() {
		if b.udp != nil {
			_ = b.udp.Shutdown()
		}
		if b.tcp != nil {
			_ = b.tcp.Shutdown()
		}
	})
}
