package decisionplugin

import (
	"context"
	"errors"
	"strings"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/prometheus/client_golang/prometheus"
)

const pluginType = "veladns_decision"

type executable struct {
	counter prometheus.Counter
}

func init() {
	sequence.MustRegExecQuickSetup(pluginType, quickSetup)
}

func quickSetup(bp sequence.BQ, raw string) (any, error) {
	decision := strings.TrimSpace(raw)
	if decision == "" {
		return nil, errors.New("decision name is required")
	}
	counter, err := decisionCounter(bp.M().GetMetricsReg(), decision)
	if err != nil {
		return nil, err
	}
	return &executable{counter: counter}, nil
}

func decisionCounter(
	registerer prometheus.Registerer,
	decision string,
) (prometheus.Counter, error) {
	vector := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "veladns_decisions_total",
		Help: "Total DNS routing decisions made by VelaDNS.",
	}, []string{"decision"})
	if err := registerer.Register(vector); err != nil {
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if !errors.As(err, &alreadyRegistered) {
			return nil, err
		}
		var ok bool
		vector, ok = alreadyRegistered.ExistingCollector.(*prometheus.CounterVec)
		if !ok {
			return nil, errors.New("veladns decision metric has an incompatible collector")
		}
	}
	return vector.WithLabelValues(decision), nil
}

func (e *executable) Exec(context.Context, *query_context.Context) error {
	e.counter.Inc()
	return nil
}

var _ sequence.Executable = (*executable)(nil)
