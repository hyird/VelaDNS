package circuitplugin

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

const pluginType = "veladns_circuit"

var (
	errCircuitOpen    = errors.New("AUTO_FORWARD circuit is open")
	errNoResponse     = errors.New("AUTO_FORWARD upstream returned no response")
	errAttemptTimeout = errors.New("AUTO_FORWARD upstream attempt timed out")
)

type Args struct {
	Primary              string `yaml:"primary"`
	FailureThreshold     int    `yaml:"failure_threshold"`
	Attempts             int    `yaml:"attempts"`
	AttemptTimeoutMillis int    `yaml:"attempt_timeout_millis"`
	InitialBackoffMillis int    `yaml:"initial_backoff_millis"`
	MaxBackoffMillis     int    `yaml:"max_backoff_millis"`
	FailureRCodes        []int  `yaml:"failure_rcodes"`
}

type permit struct {
	probe bool
}

type circuit struct {
	mu                  sync.Mutex
	name                string
	consecutiveFailures int
	backoffStep         uint
	retryAt             time.Time
	probing             bool
	failureThreshold    int
	initialBackoff      time.Duration
	maxBackoff          time.Duration
	stateGauge          prometheus.Gauge
	backoffGauge        prometheus.Gauge
	failureCounter      prometheus.Counter
	bypassCounter       prometheus.Counter
	logger              *zap.Logger
	jitter              func(time.Duration, time.Duration) time.Duration
}

func (c *circuit) acquire() (permit, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.backoffStep == 0 {
		return permit{}, true
	}
	if time.Now().Before(c.retryAt) || c.probing {
		c.bypassCounter.Inc()
		return permit{}, false
	}
	c.probing = true
	c.stateGauge.Set(2)
	c.backoffGauge.Set(0)
	return permit{probe: true}, true
}

func (c *circuit) succeed() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.backoffStep > 0 {
		c.logger.Info("AUTO_FORWARD circuit recovered", zap.String("circuit", c.name))
	}
	c.consecutiveFailures = 0
	c.backoffStep = 0
	c.retryAt = time.Time{}
	c.probing = false
	c.stateGauge.Set(0)
	c.backoffGauge.Set(0)
}

func (c *circuit) fail(p permit, cause error) {
	c.failureCounter.Inc()
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.backoffStep == 0 {
		if p.probe {
			return
		}
		c.consecutiveFailures++
		if c.consecutiveFailures < c.failureThreshold {
			c.logger.Warn("AUTO_FORWARD failure below circuit threshold",
				zap.String("circuit", c.name),
				zap.Int("failures", c.consecutiveFailures),
				zap.Int("threshold", c.failureThreshold),
				zap.Error(cause))
			return
		}
		c.backoffStep = 1
	} else {
		if !p.probe || !c.probing {
			return
		}
		c.backoffStep++
	}

	c.probing = false
	nominal := exponentialDelay(c.initialBackoff, c.maxBackoff, c.backoffStep)
	delay := c.jitter(nominal, c.maxBackoff)
	c.retryAt = time.Now().Add(delay)
	c.stateGauge.Set(1)
	c.backoffGauge.Set(delay.Seconds())
	c.logger.Warn("AUTO_FORWARD circuit opened",
		zap.String("circuit", c.name),
		zap.Uint("backoff_step", c.backoffStep),
		zap.Duration("retry_after", delay),
		zap.Error(cause))
}

func exponentialDelay(initial, maximum time.Duration, step uint) time.Duration {
	delay := initial
	for i := uint(1); i < step && delay < maximum; i++ {
		delay *= 2
		if delay >= maximum {
			return maximum
		}
	}
	return delay
}

func jitterDelay(nominal, maximum time.Duration) time.Duration {
	if nominal <= 0 {
		return 0
	}
	spread := nominal / 5
	if spread == 0 {
		return nominal
	}
	delay := nominal - spread + time.Duration(rand.Int63n(int64(2*spread)+1))
	if delay > maximum {
		return maximum
	}
	return delay
}

type Plugin struct {
	primary        sequence.Executable
	circuit        *circuit
	attempts       int
	attemptTimeout time.Duration
	failureRCodes  map[int]struct{}
	registerer     prometheus.Registerer
	collectors     []prometheus.Collector
}

func init() {
	coremain.RegNewPluginFunc(pluginType, initPlugin, func() any { return new(Args) })
}

func initPlugin(bp *coremain.BP, raw any) (any, error) {
	args := raw.(*Args)
	primary := sequence.ToExecutable(bp.M().GetPlugin(args.Primary))
	if primary == nil {
		return nil, fmt.Errorf("primary executable %q was not found", args.Primary)
	}
	threshold := args.FailureThreshold
	if threshold <= 0 {
		threshold = 2
	}
	attempts := args.Attempts
	if attempts <= 0 {
		attempts = 1
	}
	attemptTimeout := time.Duration(args.AttemptTimeoutMillis) * time.Millisecond
	if attemptTimeout <= 0 {
		attemptTimeout = time.Second
	}
	initial := time.Duration(args.InitialBackoffMillis) * time.Millisecond
	if initial <= 0 {
		initial = time.Second
	}
	maximum := time.Duration(args.MaxBackoffMillis) * time.Millisecond
	if maximum < initial {
		maximum = 5 * time.Minute
	}

	labels := prometheus.Labels{"name": bp.Tag()}
	stateGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "veladns_circuit_state",
		Help:        "AUTO_FORWARD circuit state: 0 closed, 1 open, 2 half-open.",
		ConstLabels: labels,
	})
	backoffGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "veladns_circuit_backoff_seconds",
		Help:        "Current AUTO_FORWARD retry delay in seconds.",
		ConstLabels: labels,
	})
	failureCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "veladns_circuit_failures_total",
		Help:        "Total failures observed by the AUTO_FORWARD circuit.",
		ConstLabels: labels,
	})
	bypassCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "veladns_circuit_bypass_total",
		Help:        "Queries that bypassed AUTO_FORWARD while its circuit was open.",
		ConstLabels: labels,
	})
	collectors := []prometheus.Collector{
		stateGauge, backoffGauge, failureCounter, bypassCounter,
	}
	registerer := bp.M().GetMetricsReg()
	for _, collector := range collectors {
		if err := registerer.Register(collector); err != nil {
			return nil, fmt.Errorf("register circuit metrics: %w", err)
		}
	}

	failureRCodes := make(map[int]struct{}, len(args.FailureRCodes))
	for _, rcode := range args.FailureRCodes {
		failureRCodes[rcode] = struct{}{}
	}
	return &Plugin{
		primary:        primary,
		attempts:       attempts,
		attemptTimeout: attemptTimeout,
		circuit: &circuit{
			name:             bp.Tag(),
			failureThreshold: threshold,
			initialBackoff:   initial,
			maxBackoff:       maximum,
			stateGauge:       stateGauge,
			backoffGauge:     backoffGauge,
			failureCounter:   failureCounter,
			bypassCounter:    bypassCounter,
			logger:           bp.L(),
			jitter:           jitterDelay,
		},
		failureRCodes: failureRCodes,
		registerer:    registerer,
		collectors:    collectors,
	}, nil
}

func (p *Plugin) Exec(ctx context.Context, qCtx *query_context.Context) error {
	permit, allowed := p.circuit.acquire()
	if !allowed {
		qCtx.SetResponse(nil)
		return errCircuitOpen
	}

	// A dropped datagram on the container bridge must not be reported as an
	// unusable Mihomo. Losing the fake IP silently downgrades the routing
	// policy to a real address, so retry the plain-UDP hop before giving up.
	attempts := p.attempts
	if attempts <= 0 {
		attempts = 1
	}
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		var response *dns.Msg
		response, err = p.attemptOnce(ctx, qCtx)
		if err == nil && response != nil {
			if _, failed := p.failureRCodes[response.Rcode]; !failed {
				qCtx.SetResponse(response)
				p.circuit.succeed()
				return nil
			}
			// SERVFAIL/REFUSED is a verdict from a Mihomo that did answer.
			// Retrying it only adds latency to a decided failure.
			err = fmt.Errorf("upstream DNS rcode %s", dns.RcodeToString[response.Rcode])
			break
		}
		if ctx.Err() != nil {
			qCtx.SetResponse(nil)
			return context.Cause(ctx)
		}
		if err == nil {
			err = errNoResponse
		}
	}

	qCtx.SetResponse(nil)
	p.circuit.fail(permit, err)
	return err
}

func (p *Plugin) attemptOnce(
	ctx context.Context,
	qCtx *query_context.Context,
) (*dns.Msg, error) {
	// MosDNS's forward plugin uses a fixed five-second upstream deadline. Run
	// it against a private query context so VelaDNS can declare the attempt
	// failed sooner without a late response mutating the caller's context.
	attemptCtx := qCtx.Copy()
	result := make(chan error, 1)
	go func() {
		result <- p.primary.Exec(ctx, attemptCtx)
	}()

	timer := time.NewTimer(p.attemptTimeout)
	defer timer.Stop()

	select {
	case err := <-result:
		return attemptCtx.R(), err
	case <-timer.C:
		return nil, errAttemptTimeout
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

func (p *Plugin) Close() error {
	for _, collector := range p.collectors {
		p.registerer.Unregister(collector)
	}
	return nil
}

var _ sequence.Executable = (*Plugin)(nil)
