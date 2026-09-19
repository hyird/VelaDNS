package main

import (
	"encoding/json"
	"net"
	"sync"
	"time"

	"github.com/hyird/VelaDNS/internal/statewire"
)

type runtimeState struct {
	mu           sync.RWMutex
	components   map[string]statewire.Component
	dohUpstreams map[string]statewire.DoHUpstream
}

func newRuntimeState() *runtimeState {
	return &runtimeState{
		components: map[string]statewire.Component{
			"doh_bridge":        {Enabled: true},
			"mosdns":            {Enabled: true},
			"unbound":           {Enabled: true},
			"unbound_recursive": {Enabled: true},
		},
		dohUpstreams: make(map[string]statewire.DoHUpstream),
	}
}

func (s *runtimeState) update(name string, fn func(*statewire.Component)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	component := s.components[name]
	fn(&component)
	s.components[name] = component
}

type dohObservation int

const (
	dohSuccess dohObservation = iota
	dohFailure
	dohBackoffSkip
)

func (s *runtimeState) registerDoHUpstream(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.dohUpstreams[name]; !ok {
		s.dohUpstreams[name] = statewire.DoHUpstream{}
	}
}

func (s *runtimeState) observeDoHUpstream(
	name string,
	result dohObservation,
	duration time.Duration,
	retryAt time.Time,
) {
	s.mu.Lock()
	defer s.mu.Unlock()

	upstream := s.dohUpstreams[name]
	upstream.Requests++
	if duration > 0 {
		upstream.DurationMicroseconds += uint64(duration.Microseconds())
	}
	now := time.Now().Unix()
	switch result {
	case dohSuccess:
		upstream.Successes++
		upstream.LastSuccessUnix = now
	case dohFailure:
		upstream.Failures++
		upstream.LastFailureUnix = now
	case dohBackoffSkip:
		upstream.BackoffSkips++
	}
	if retryAt.IsZero() {
		upstream.RetryAtUnixMilli = 0
	} else {
		upstream.RetryAtUnixMilli = retryAt.UnixMilli()
	}
	s.dohUpstreams[name] = upstream
}

func (s *runtimeState) snapshot() statewire.Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	components := make(map[string]statewire.Component, len(s.components))
	for name, component := range s.components {
		components[name] = component
	}
	dohUpstreams := make(map[string]statewire.DoHUpstream, len(s.dohUpstreams))
	for name, upstream := range s.dohUpstreams {
		dohUpstreams[name] = upstream
	}
	return statewire.Snapshot{
		Timestamp:    time.Now().Unix(),
		Components:   components,
		DoHUpstreams: dohUpstreams,
	}
}

func sendStateLoop(ctx doneContext, state *runtimeState, socketPath string) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		sendState(state, socketPath)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func sendState(state *runtimeState, socketPath string) {
	payload, err := json.Marshal(state.snapshot())
	if err != nil {
		return
	}
	addr, err := net.ResolveUnixAddr("unixgram", socketPath)
	if err != nil {
		return
	}
	conn, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		return
	}
	_, _ = conn.Write(payload)
	_ = conn.Close()
}

type doneContext interface {
	Done() <-chan struct{}
}
