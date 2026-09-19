package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	healthStatusURL = "http://127.0.0.1:5308/plugins/veladns/readyz"
	healthDNSAddr   = "127.0.0.1:5304"
	healthDNSName   = "example.com."
)

func runHealthcheck() error {
	if err := checkSupervisorHealth(healthStatusURL); err != nil {
		return err
	}
	return checkSecureDNS(healthDNSAddr, healthDNSName)
}

func checkSupervisorHealth(url string) error {
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("supervisor endpoint: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 256))
	if err != nil {
		return fmt.Errorf("supervisor response: %w", err)
	}
	status := strings.TrimSpace(string(body))
	if response.StatusCode != http.StatusOK ||
		(!strings.HasPrefix(status, "ok") && !strings.HasPrefix(status, "degraded")) {
		return fmt.Errorf("supervisor is not ready: HTTP %d: %s", response.StatusCode, status)
	}
	return nil
}

func checkSecureDNS(address, name string) error {
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(name), dns.TypeA)
	response, _, err := (&dns.Client{Timeout: 3 * time.Second}).Exchange(query, address)
	if err != nil {
		return fmt.Errorf("secure DNS query: %w", err)
	}
	if response == nil {
		return fmt.Errorf("secure DNS query returned no response")
	}
	if response.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("secure DNS query returned %s", dns.RcodeToString[response.Rcode])
	}
	for _, answer := range response.Answer {
		if answer.Header().Rrtype == dns.TypeA {
			return nil
		}
	}
	return fmt.Errorf("secure DNS query returned no A record")
}
