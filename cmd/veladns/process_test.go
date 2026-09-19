package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestRestartDelayBoundsAndGrowth(t *testing.T) {
	for step := uint(1); step <= 10; step++ {
		delay := restartDelay(step)
		if delay < 800*time.Millisecond {
			t.Fatalf("step %d delay too short: %s", step, delay)
		}
		if delay > restartMaximum {
			t.Fatalf("step %d delay exceeded maximum: %s", step, delay)
		}
	}
}

func TestChildLogWriterSuppressesOnlyRedundantDeadlineWarnings(t *testing.T) {
	var output bytes.Buffer
	writer := newChildLogWriter(newChildLogDeduper("mosdns", false), &output)
	lines := []string{
		"2026-07-26T20:00:00+0800\tWARN\tclassify_lookup\tsecondary error\t{\"uqid\":1,\"error\":\"context deadline exceeded\"}\n",
		"2026-07-26T20:00:01+0800\tWARN\tmain_tcp\tentry err\t{\"uqid\":2,\"error\":\"context deadline exceeded\"}\n",
		"2026-07-26T20:00:02+0800\tWARN\tforward_unbound\tupstream error\t{\"uqid\":2,\"error\":\"context deadline exceeded\"}\n",
		"2026-07-26T20:00:03+0800\tWARN\trecursive_unbound\tupstream error\t{\"uqid\":3,\"error\":\"context deadline exceeded\"}\n",
		"2026-07-26T20:00:04+0800\tWARN\tforward_unbound\tupstream error\t{\"uqid\":2,\"error\":\"SERVFAIL\"}\n",
	}
	input := strings.Join(lines, "")
	for _, part := range []string{input[:37], input[37:113], input[113:]} {
		if _, err := writer.Write([]byte(part)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	want := lines[0] + lines[1] + lines[3] + lines[4]
	if got != want {
		t.Fatalf("filtered output:\n%s\nwant:\n%s", got, want)
	}
}

func TestChildLogWriterDoesNotFilterOtherProcesses(t *testing.T) {
	var output bytes.Buffer
	writer := newChildLogWriter(newChildLogDeduper("unbound", false), &output)
	line := "recursive_unbound upstream error: context deadline exceeded\n"
	if _, err := writer.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if output.String() != line {
		t.Fatalf("unbound output = %q, want %q", output.String(), line)
	}
}

func TestChildLogWriterSuppressesUnboundStartupInfoOnlyInQuietMode(t *testing.T) {
	var output bytes.Buffer
	writer := newChildLogWriter(newChildLogDeduper("unbound_recursive", true), &output)
	startup := "Jul 26 20:44:43 unbound[15:0] info: start of service (unbound 1.25.1).\n"
	warning := "Jul 26 20:44:44 unbound[15:0] warning: validation failed\n"
	if _, err := writer.Write([]byte(startup + warning)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if output.String() != warning {
		t.Fatalf("filtered output = %q, want %q", output.String(), warning)
	}
}
