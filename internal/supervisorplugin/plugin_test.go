package supervisorplugin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hyird/VelaDNS/internal/statewire"
	"github.com/prometheus/client_golang/prometheus"
)

func TestReadyStates(t *testing.T) {
	tests := []struct {
		name       string
		snapshot   statewire.Snapshot
		receivedAt time.Time
		status     int
		body       string
	}{
		{
			name:   "stale",
			status: http.StatusServiceUnavailable,
			body:   "stale",
		},
		{
			name: "mosdns restarting",
			snapshot: statewire.Snapshot{
				Timestamp: time.Now().Unix(),
				Components: map[string]statewire.Component{
					"mosdns":  {Enabled: true},
					"unbound": {Enabled: true, Up: true},
				},
			},
			receivedAt: time.Now(),
			status:     http.StatusServiceUnavailable,
			body:       "mosdns",
		},
		{
			name: "unbound degraded",
			snapshot: statewire.Snapshot{
				Timestamp: time.Now().Unix(),
				Components: map[string]statewire.Component{
					"mosdns":  {Enabled: true, Up: true},
					"unbound": {Enabled: true},
				},
			},
			receivedAt: time.Now(),
			status:     http.StatusOK,
			body:       "degraded",
		},
		{
			name: "encrypted bridge unavailable",
			snapshot: statewire.Snapshot{
				Timestamp: time.Now().Unix(),
				Components: map[string]statewire.Component{
					"doh_bridge": {Enabled: true},
					"mosdns":     {Enabled: true, Up: true},
					"unbound":    {Enabled: true, Up: true},
				},
			},
			receivedAt: time.Now(),
			status:     http.StatusServiceUnavailable,
			body:       "bridge",
		},
		{
			name: "healthy",
			snapshot: statewire.Snapshot{
				Timestamp: time.Now().Unix(),
				Components: map[string]statewire.Component{
					"mosdns":  {Enabled: true, Up: true},
					"unbound": {Enabled: true, Up: true},
				},
			},
			receivedAt: time.Now(),
			status:     http.StatusOK,
			body:       "ok",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plugin := &Plugin{snapshot: test.snapshot, receivedAt: test.receivedAt}
			recorder := httptest.NewRecorder()
			plugin.ready(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d", recorder.Code, test.status)
			}
			if !strings.Contains(recorder.Body.String(), test.body) {
				t.Fatalf("body = %q, want substring %q", recorder.Body.String(), test.body)
			}
		})
	}
}

func TestLiveIgnoresDependencyFailure(t *testing.T) {
	plugin := &Plugin{
		snapshot: statewire.Snapshot{
			Timestamp: time.Now().Unix(),
			Components: map[string]statewire.Component{
				"mosdns":     {Enabled: true, Up: true},
				"doh_bridge": {Enabled: true, Up: false},
				"unbound":    {Enabled: true, Up: false},
			},
		},
		receivedAt: time.Now(),
	}
	recorder := httptest.NewRecorder()
	plugin.live(recorder, httptest.NewRequest(http.MethodGet, "/livez", nil))
	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != "ok" {
		t.Fatalf("live response = HTTP %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestDependenciesReportsComponentsAndDoHUpstreams(t *testing.T) {
	plugin := &Plugin{
		snapshot: statewire.Snapshot{
			Timestamp: time.Now().Unix(),
			Components: map[string]statewire.Component{
				"mosdns":  {Enabled: true, Up: true},
				"unbound": {Enabled: true, Up: false},
			},
			DoHUpstreams: map[string]statewire.DoHUpstream{
				"cloudflare": {Requests: 3, Successes: 2, Failures: 1},
			},
		},
		receivedAt: time.Now(),
	}
	recorder := httptest.NewRecorder()
	plugin.dependencies(recorder, httptest.NewRequest(http.MethodGet, "/dependencies", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	var report dependencyReport
	if err := json.Unmarshal(recorder.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "degraded" || report.DoHUpstreams["cloudflare"].Requests != 3 {
		t.Fatalf("report = %#v", report)
	}
}

func TestCollectExportsDoHUpstreamMetrics(t *testing.T) {
	now := time.Now()
	plugin := &Plugin{
		snapshot: statewire.Snapshot{
			Timestamp:  now.Unix(),
			Components: map[string]statewire.Component{},
			DoHUpstreams: map[string]statewire.DoHUpstream{
				"cloudflare": {
					Requests:             5,
					Successes:            4,
					Failures:             1,
					DurationMicroseconds: uint64((250 * time.Millisecond).Microseconds()),
					RetryAtUnixMilli:     now.Add(time.Second).UnixMilli(),
				},
			},
		},
		receivedAt: now,
	}
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(plugin)
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, family := range families {
		found[family.GetName()] = true
	}
	for _, name := range []string{
		"veladns_doh_upstream_requests_total",
		"veladns_doh_upstream_request_duration_seconds_total",
		"veladns_doh_upstream_backoff_seconds",
	} {
		if !found[name] {
			t.Errorf("metric %s was not exported", name)
		}
	}
}
