package main

import (
	"context"
	"os"
	"testing"

	"github.com/miekg/dns"
)

func TestLiveDoHUpstreams(t *testing.T) {
	if os.Getenv("VELADNS_LIVE_DOH_TEST") != "1" {
		t.Skip("set VELADNS_LIVE_DOH_TEST=1 to query public DoH upstreams")
	}
	cfg := config{}
	if autoDNS := os.Getenv("VELADNS_LIVE_AUTO_DNS"); autoDNS != "" {
		cfg.autoEnabled = true
		cfg.autoDNS = autoDNS
	}
	for _, upstream := range append(autoDoHUpstreams(cfg), directDoHUpstreams()...) {
		t.Run(upstream.tag+"/signed", func(t *testing.T) {
			response := liveDoHQuery(t, upstream, "dns.google.")
			if response.Rcode != dns.RcodeSuccess {
				t.Fatalf("signed domain returned %s", dns.RcodeToString[response.Rcode])
			}
			if !hasRRType(response, dns.TypeA) {
				t.Fatal("signed domain returned no A record")
			}
			if !hasRRType(response, dns.TypeRRSIG) {
				t.Fatal("upstream stripped DNSSEC signatures")
			}
		})

		t.Run(upstream.tag+"/bogus", func(t *testing.T) {
			response := liveDoHQuery(t, upstream, "dnssec-failed.org.")
			if response.Rcode != dns.RcodeServerFailure && !hasRRType(response, dns.TypeRRSIG) {
				t.Fatalf(
					"bogus domain returned %s without signatures for local validation",
					dns.RcodeToString[response.Rcode],
				)
			}
		})
	}
}

func liveDoHQuery(t *testing.T, upstream *dohUpstream, name string) *dns.Msg {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion(name, dns.TypeA)
	query.SetEdns0(1232, true)
	response, err := upstream.exchange(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf(
		"rcode=%s answer=%d authority=%d authenticated=%v",
		dns.RcodeToString[response.Rcode],
		len(response.Answer),
		len(response.Ns),
		response.AuthenticatedData,
	)
	return response
}

func hasRRType(message *dns.Msg, rrType uint16) bool {
	for _, section := range [][]dns.RR{message.Answer, message.Ns, message.Extra} {
		for _, record := range section {
			if record.Header().Rrtype == rrType {
				return true
			}
		}
	}
	return false
}
