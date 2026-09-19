package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCheckSupervisorHealth(t *testing.T) {
	for _, body := range []string{"ok\n", "degraded: unbound is restarting\n"} {
		t.Run(body[:2], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			if err := checkSupervisorHealth(server.URL); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCheckSupervisorHealthRejectsUnhealthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unhealthy", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	if err := checkSupervisorHealth(server.URL); err == nil {
		t.Fatal("unhealthy supervisor response was accepted")
	}
}

func TestCheckSecureDNS(t *testing.T) {
	address, closeServer := startHealthDNSServer(t, true)
	defer closeServer()
	if err := checkSecureDNS(address, "example.com."); err != nil {
		t.Fatal(err)
	}
}

func TestCheckSecureDNSRequiresARecord(t *testing.T) {
	address, closeServer := startHealthDNSServer(t, false)
	defer closeServer()
	if err := checkSecureDNS(address, "example.com."); err == nil {
		t.Fatal("NODATA health response was accepted")
	}
}

func startHealthDNSServer(t *testing.T, includeA bool) (string, func()) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{
		PacketConn: conn,
		Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
			response := new(dns.Msg)
			response.SetReply(request)
			if includeA {
				response.Answer = append(response.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   request.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					A: net.ParseIP("192.0.2.1"),
				})
			}
			_ = writer.WriteMsg(response)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	time.Sleep(10 * time.Millisecond)
	return conn.LocalAddr().String(), func() {
		_ = server.Shutdown()
		_ = conn.Close()
	}
}
