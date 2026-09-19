package supervisorplugin

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/go-chi/chi/v5"
	"github.com/hyird/VelaDNS/internal/statewire"
	"github.com/prometheus/client_golang/prometheus"
)

const pluginType = "veladns_supervisor"

type Args struct {
	Socket string `yaml:"socket"`
}

type Plugin struct {
	mu         sync.RWMutex
	snapshot   statewire.Snapshot
	receivedAt time.Time
	socketPath string
	conn       *net.UnixConn
	registerer prometheus.Registerer
}

func init() {
	coremain.RegNewPluginFunc(pluginType, initPlugin, func() any { return new(Args) })
}

func initPlugin(bp *coremain.BP, raw any) (any, error) {
	args := raw.(*Args)
	if args.Socket == "" {
		return nil, errors.New("socket is required")
	}
	_ = os.Remove(args.Socket)
	addr, err := net.ResolveUnixAddr("unixgram", args.Socket)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(args.Socket, 0660); err != nil {
		_ = conn.Close()
		return nil, err
	}

	p := &Plugin{
		socketPath: args.Socket,
		conn:       conn,
		registerer: bp.M().GetMetricsReg(),
	}
	if err := p.registerer.Register(p); err != nil {
		_ = conn.Close()
		return nil, err
	}
	mux := chi.NewRouter()
	mux.Get("/livez", p.live)
	mux.Get("/readyz", p.ready)
	mux.Get("/healthz", p.ready)
	mux.Get("/dependencies", p.dependencies)
	bp.RegAPI(mux)
	go p.readLoop()
	return p, nil
}

func (p *Plugin) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, _, err := p.conn.ReadFromUnix(buf)
		if err != nil {
			return
		}
		var snapshot statewire.Snapshot
		if json.Unmarshal(buf[:n], &snapshot) != nil {
			continue
		}
		p.mu.Lock()
		p.snapshot = snapshot
		p.receivedAt = time.Now()
		p.mu.Unlock()
	}
}

func (p *Plugin) currentSnapshot() (statewire.Snapshot, time.Duration) {
	p.mu.RLock()
	snapshot := p.snapshot
	age := time.Since(p.receivedAt)
	p.mu.RUnlock()
	return snapshot, age
}

func liveStatus(snapshot statewire.Snapshot, age time.Duration) (int, string) {
	if snapshot.Timestamp == 0 || age > 5*time.Second {
		return http.StatusServiceUnavailable, "unhealthy: supervisor state is stale"
	}
	if mosdns, ok := snapshot.Components["mosdns"]; ok && mosdns.Enabled && !mosdns.Up {
		return http.StatusServiceUnavailable, "unhealthy: mosdns is restarting"
	}
	return http.StatusOK, "ok"
}

func readyStatus(snapshot statewire.Snapshot, age time.Duration) (int, string) {
	if status, message := liveStatus(snapshot, age); status != http.StatusOK {
		return status, message
	}
	if bridge, ok := snapshot.Components["doh_bridge"]; ok && bridge.Enabled && !bridge.Up {
		return http.StatusServiceUnavailable, "unhealthy: encrypted DNS bridge is unavailable"
	}
	if unbound, ok := snapshot.Components["unbound"]; ok && unbound.Enabled && !unbound.Up {
		return http.StatusOK, "degraded: unbound is restarting"
	}
	// Losing the CN classifier costs mainland names their local answer, not
	// their resolution: they fall through to the encrypted path.
	if cn, ok := snapshot.Components["unbound_recursive"]; ok && cn.Enabled && !cn.Up {
		return http.StatusOK, "degraded: CN classification resolver is restarting"
	}
	return http.StatusOK, "ok"
}

func writeStatus(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	_, _ = w.Write([]byte(message + "\n"))
}

func (p *Plugin) live(w http.ResponseWriter, _ *http.Request) {
	snapshot, age := p.currentSnapshot()
	status, message := liveStatus(snapshot, age)
	writeStatus(w, status, message)
}

func (p *Plugin) ready(w http.ResponseWriter, _ *http.Request) {
	snapshot, age := p.currentSnapshot()
	status, message := readyStatus(snapshot, age)
	writeStatus(w, status, message)
}

type dependencyReport struct {
	Status          string                           `json:"status"`
	Message         string                           `json:"message"`
	Timestamp       int64                            `json:"timestamp"`
	StateAgeSeconds float64                          `json:"state_age_seconds"`
	Components      map[string]statewire.Component   `json:"components"`
	DoHUpstreams    map[string]statewire.DoHUpstream `json:"doh_upstreams"`
}

func (p *Plugin) dependencies(w http.ResponseWriter, _ *http.Request) {
	snapshot, age := p.currentSnapshot()
	_, message := readyStatus(snapshot, age)
	status := "ready"
	switch {
	case strings.HasPrefix(message, "unhealthy"):
		status = "unhealthy"
	case strings.HasPrefix(message, "degraded"):
		status = "degraded"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(dependencyReport{
		Status:          status,
		Message:         message,
		Timestamp:       snapshot.Timestamp,
		StateAgeSeconds: age.Seconds(),
		Components:      snapshot.Components,
		DoHUpstreams:    snapshot.DoHUpstreams,
	})
}

func (p *Plugin) Describe(ch chan<- *prometheus.Desc) {
	ch <- prometheus.NewDesc(
		"veladns_component_up",
		"Whether a supervised VelaDNS component is running.",
		[]string{"component"}, nil,
	)
	ch <- prometheus.NewDesc(
		"veladns_component_enabled",
		"Whether a supervised VelaDNS component is enabled.",
		[]string{"component"}, nil,
	)
	ch <- prometheus.NewDesc(
		"veladns_component_restarts_total",
		"Total restarts of a supervised VelaDNS component.",
		[]string{"component"}, nil,
	)
	ch <- prometheus.NewDesc(
		"veladns_component_backoff_seconds",
		"Current restart delay for a supervised VelaDNS component.",
		[]string{"component"}, nil,
	)
	ch <- prometheus.NewDesc(
		"veladns_supervisor_state_age_seconds",
		"Age of the last supervisor state update.",
		nil, nil,
	)
	for _, desc := range dohMetricDescriptions() {
		ch <- desc
	}
}

func (p *Plugin) Collect(ch chan<- prometheus.Metric) {
	p.mu.RLock()
	snapshot := p.snapshot
	receivedAt := p.receivedAt
	p.mu.RUnlock()

	for name, component := range snapshot.Components {
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc("veladns_component_up", "Whether a supervised VelaDNS component is running.", []string{"component"}, nil),
			prometheus.GaugeValue, boolFloat(component.Up), name,
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc("veladns_component_enabled", "Whether a supervised VelaDNS component is enabled.", []string{"component"}, nil),
			prometheus.GaugeValue, boolFloat(component.Enabled), name,
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc("veladns_component_restarts_total", "Total restarts of a supervised VelaDNS component.", []string{"component"}, nil),
			prometheus.CounterValue, float64(component.Restarts), name,
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc("veladns_component_backoff_seconds", "Current restart delay for a supervised VelaDNS component.", []string{"component"}, nil),
			prometheus.GaugeValue, component.BackoffSeconds, name,
		)
	}
	age := 0.0
	if !receivedAt.IsZero() {
		age = time.Since(receivedAt).Seconds()
	}
	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc("veladns_supervisor_state_age_seconds", "Age of the last supervisor state update.", nil, nil),
		prometheus.GaugeValue, age,
	)
	now := time.Now()
	descriptions := dohMetricDescriptions()
	for name, upstream := range snapshot.DoHUpstreams {
		values := []struct {
			valueType prometheus.ValueType
			value     float64
		}{
			{prometheus.CounterValue, float64(upstream.Requests)},
			{prometheus.CounterValue, float64(upstream.Successes)},
			{prometheus.CounterValue, float64(upstream.Failures)},
			{prometheus.CounterValue, float64(upstream.BackoffSkips)},
			{prometheus.CounterValue, float64(upstream.DurationMicroseconds) / float64(time.Second/time.Microsecond)},
			{prometheus.GaugeValue, remainingBackoffSeconds(upstream, now)},
			{prometheus.GaugeValue, float64(upstream.LastSuccessUnix)},
			{prometheus.GaugeValue, float64(upstream.LastFailureUnix)},
		}
		for i, metric := range values {
			ch <- prometheus.MustNewConstMetric(
				descriptions[i],
				metric.valueType,
				metric.value,
				name,
			)
		}
	}
}

func dohMetricDescriptions() []*prometheus.Desc {
	labels := []string{"upstream"}
	return []*prometheus.Desc{
		prometheus.NewDesc("veladns_doh_upstream_requests_total", "Total requests considered by a DoH upstream.", labels, nil),
		prometheus.NewDesc("veladns_doh_upstream_successes_total", "Total successful DoH upstream requests.", labels, nil),
		prometheus.NewDesc("veladns_doh_upstream_failures_total", "Total failed DoH upstream requests.", labels, nil),
		prometheus.NewDesc("veladns_doh_upstream_backoff_skips_total", "Total DoH upstream requests skipped during backoff.", labels, nil),
		prometheus.NewDesc("veladns_doh_upstream_request_duration_seconds_total", "Cumulative time spent on DoH upstream requests.", labels, nil),
		prometheus.NewDesc("veladns_doh_upstream_backoff_seconds", "Seconds until a DoH upstream can be retried.", labels, nil),
		prometheus.NewDesc("veladns_doh_upstream_last_success_timestamp_seconds", "Unix timestamp of the last successful DoH upstream request.", labels, nil),
		prometheus.NewDesc("veladns_doh_upstream_last_failure_timestamp_seconds", "Unix timestamp of the last failed DoH upstream request.", labels, nil),
	}
}

func remainingBackoffSeconds(upstream statewire.DoHUpstream, now time.Time) float64 {
	if upstream.RetryAtUnixMilli == 0 {
		return 0
	}
	remaining := time.UnixMilli(upstream.RetryAtUnixMilli).Sub(now)
	if remaining < 0 {
		return 0
	}
	return remaining.Seconds()
}

func boolFloat(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

func (p *Plugin) Close() error {
	p.registerer.Unregister(p)
	err := p.conn.Close()
	_ = os.Remove(p.socketPath)
	return err
}
