package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDoHBridgeReturnsFirstSuccessfulResponse(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	bridge := &dohBridge{
		log: newLogger("error"),
		resolvers: []resolverFunc{
			func(context.Context, *dns.Msg) (*dns.Msg, error) {
				return nil, errors.New("unavailable")
			},
			func(_ context.Context, request *dns.Msg) (*dns.Msg, error) {
				response := new(dns.Msg)
				response.SetReply(request)
				response.Answer = append(response.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   request.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					A: net.ParseIP("192.0.2.1"),
				})
				return response, nil
			},
		},
	}
	writer := newCaptureDNSWriter()
	bridge.ServeDNS(writer, query)
	if writer.response == nil || writer.response.Rcode != dns.RcodeSuccess {
		t.Fatalf("response = %#v", writer.response)
	}
	if len(writer.response.Answer) != 1 {
		t.Fatalf("answer count = %d", len(writer.response.Answer))
	}
}

func TestDoHBridgeReturnsServfailWhenAllUpstreamsFail(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	bridge := &dohBridge{
		log: newLogger("error"),
		resolvers: []resolverFunc{
			func(context.Context, *dns.Msg) (*dns.Msg, error) {
				return nil, errors.New("unavailable")
			},
		},
	}
	writer := newCaptureDNSWriter()
	bridge.ServeDNS(writer, query)
	if writer.response == nil || writer.response.Rcode != dns.RcodeServerFailure {
		t.Fatalf("response = %#v", writer.response)
	}
}

func TestDoHBridgeUsesUpstreamsInOrder(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	secondCalled := false
	bridge := &dohBridge{
		log: newLogger("error"),
		resolvers: []resolverFunc{
			func(_ context.Context, request *dns.Msg) (*dns.Msg, error) {
				response := new(dns.Msg)
				response.SetReply(request)
				return response, nil
			},
			func(context.Context, *dns.Msg) (*dns.Msg, error) {
				secondCalled = true
				return nil, errors.New("must not be called")
			},
		},
	}
	writer := newCaptureDNSWriter()
	bridge.ServeDNS(writer, query)
	if writer.response == nil || writer.response.Rcode != dns.RcodeSuccess {
		t.Fatalf("response = %#v", writer.response)
	}
	if secondCalled {
		t.Fatal("lower-priority upstream was called after a successful response")
	}
}

func TestResolveDoHAddressesUsesConfiguredDNS(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{
		Listener: listener,
		Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
			response := new(dns.Msg)
			response.SetReply(request)
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   request.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("198.18.0.42"),
			})
			_ = writer.WriteMsg(response)
		}),
	}
	done := make(chan error, 1)
	go func() {
		done <- server.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = server.Shutdown()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("bootstrap DNS server did not stop")
		}
	})

	addresses, err := resolveDoHAddresses(context.Background(), listener.Addr().String(), "dns.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 1 || addresses[0] != "198.18.0.42" {
		t.Fatalf("addresses = %#v", addresses)
	}
}

func TestDoHUpstreamRetriesAfterExponentialBackoff(t *testing.T) {
	upstream := &dohUpstream{
		tag:         "test",
		backoffStep: 1,
		retryAt:     time.Now().Add(time.Minute),
	}
	if _, allowed := upstream.acquire(); allowed {
		t.Fatal("upstream allowed a request while backoff was active")
	}
	upstream.retryAt = time.Now().Add(-time.Millisecond)
	permit, allowed := upstream.acquire()
	if !allowed || !permit.probe {
		t.Fatal("upstream did not allow a half-open retry")
	}
	upstream.succeed()
	if upstream.backoffStep != 0 || !upstream.retryAt.IsZero() || upstream.probing {
		t.Fatal("successful retry did not close the circuit")
	}
}

type captureDNSWriter struct {
	response *dns.Msg
}

func newCaptureDNSWriter() *captureDNSWriter {
	return new(captureDNSWriter)
}

func (w *captureDNSWriter) LocalAddr() net.Addr  { return &net.UDPAddr{} }
func (w *captureDNSWriter) RemoteAddr() net.Addr { return &net.UDPAddr{} }
func (w *captureDNSWriter) WriteMsg(message *dns.Msg) error {
	w.response = message.Copy()
	return nil
}
func (w *captureDNSWriter) Write(payload []byte) (int, error) {
	message := new(dns.Msg)
	if err := message.Unpack(payload); err != nil {
		return 0, err
	}
	w.response = message
	return len(payload), nil
}
func (w *captureDNSWriter) Close() error        { return nil }
func (w *captureDNSWriter) TsigStatus() error   { return nil }
func (w *captureDNSWriter) TsigTimersOnly(bool) {}
func (w *captureDNSWriter) Hijack()             {}
