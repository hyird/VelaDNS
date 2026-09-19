package tcpserverplugin

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestCancellationLoggerSuppressesExpectedDisconnects(t *testing.T) {
	registry := prometheus.NewRegistry()
	registerer := prometheus.WrapRegistererWithPrefix("mosdns_", registry)
	events, err := cancellationCounter(registerer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cancellationCounter(registerer); err != nil {
		t.Fatalf("second TCP listener could not share cancellation metrics: %v", err)
	}
	core, observed := observer.New(zap.WarnLevel)
	logger := cancellationLogger(zap.New(core), events, "main_tcp")

	logger.Warn("entry err", zap.Error(errors.New("connection ctx canceled")))
	logger.Warn("entry err", zap.Error(errors.New("upstream returned SERVFAIL")))

	if observed.Len() != 1 {
		t.Fatalf("warning count = %d, want 1", observed.Len())
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var got float64
	for _, family := range families {
		if family.GetName() != "mosdns_veladns_client_cancel_events_total" {
			continue
		}
		for _, metric := range family.Metric {
			if metric.GetCounter() != nil {
				got += metric.GetCounter().GetValue()
			}
		}
	}
	if got != 1 {
		t.Fatalf("cancellation count = %v, want 1", got)
	}
}

func TestCancellationLoggerKeepsUnrelatedWarnings(t *testing.T) {
	registry := prometheus.NewRegistry()
	events, err := cancellationCounter(registry)
	if err != nil {
		t.Fatal(err)
	}
	core, observed := observer.New(zap.WarnLevel)
	logger := cancellationLogger(zap.New(core), events, "secure_tcp")

	logger.Warn("different warning", zap.Error(errors.New("connection ctx canceled")))

	if observed.Len() != 1 {
		t.Fatalf("warning count = %d, want 1", observed.Len())
	}
}
