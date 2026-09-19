package requestmetricsplugin

import (
	"context"
	"errors"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/hyird/VelaDNS/internal/cancelclassify"
	"github.com/prometheus/client_golang/prometheus"
)

const pluginType = "veladns_metrics_collector"

type collector struct {
	queryTotal      prometheus.Counter
	errTotal        prometheus.Counter
	canceledTotal   prometheus.Counter
	thread          prometheus.Gauge
	responseLatency prometheus.Histogram
}

func init() {
	sequence.MustRegExecQuickSetup(pluginType, quickSetup)
}

func newCollector(registerer prometheus.Registerer, name string) (*collector, error) {
	if name == "" {
		return nil, errors.New("collector name is required")
	}
	labels := prometheus.Labels{"name": name}
	c := &collector{
		queryTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "query_total",
			Help:        "The total number of queries pass through",
			ConstLabels: labels,
		}),
		errTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "err_total",
			Help:        "The total number of queries failed",
			ConstLabels: labels,
		}),
		canceledTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "canceled_total",
			Help:        "The total number of queries canceled by downstream clients",
			ConstLabels: labels,
		}),
		thread: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:        "thread",
			Help:        "The number of threads that are currently being processed",
			ConstLabels: labels,
		}),
		responseLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:        "response_latency_millisecond",
			Help:        "The response latency in millisecond",
			Buckets:     []float64{1, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000},
			ConstLabels: labels,
		}),
	}
	for _, metric := range []prometheus.Collector{
		c.queryTotal,
		c.errTotal,
		c.canceledTotal,
		c.thread,
		c.responseLatency,
	} {
		if err := registerer.Register(metric); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func quickSetup(bp sequence.BQ, name string) (any, error) {
	registerer := prometheus.WrapRegistererWithPrefix("metrics_collector_", bp.M().GetMetricsReg())
	return newCollector(registerer, name)
}

func (c *collector) Exec(
	ctx context.Context,
	qCtx *query_context.Context,
	next sequence.ChainWalker,
) error {
	c.thread.Inc()
	defer c.thread.Dec()

	c.queryTotal.Inc()
	startedAt := time.Now()
	err := next.ExecNext(ctx, qCtx)
	switch {
	case err == nil:
	case cancelclassify.Expected(err):
		c.canceledTotal.Inc()
	default:
		c.errTotal.Inc()
	}
	if qCtx.R() != nil {
		c.responseLatency.Observe(float64(time.Since(startedAt).Milliseconds()))
	}
	return err
}

var _ sequence.RecursiveExecutable = (*collector)(nil)
