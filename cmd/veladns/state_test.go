package main

import (
	"testing"
	"time"
)

func TestRuntimeStateTracksDoHUpstreamResults(t *testing.T) {
	state := newRuntimeState()
	state.registerDoHUpstream("cloudflare")
	state.observeDoHUpstream("cloudflare", dohSuccess, 125*time.Millisecond, time.Time{})
	state.observeDoHUpstream("cloudflare", dohFailure, 250*time.Millisecond, time.Now().Add(time.Second))
	state.observeDoHUpstream("cloudflare", dohBackoffSkip, 0, time.Now().Add(time.Second))

	upstream := state.snapshot().DoHUpstreams["cloudflare"]
	if upstream.Requests != 3 ||
		upstream.Successes != 1 ||
		upstream.Failures != 1 ||
		upstream.BackoffSkips != 1 {
		t.Fatalf("upstream counters = %#v", upstream)
	}
	if upstream.DurationMicroseconds != uint64((375 * time.Millisecond).Microseconds()) {
		t.Fatalf("duration = %d microseconds", upstream.DurationMicroseconds)
	}
	if upstream.LastSuccessUnix == 0 ||
		upstream.LastFailureUnix == 0 ||
		upstream.RetryAtUnixMilli == 0 {
		t.Fatalf("upstream timestamps = %#v", upstream)
	}
}
