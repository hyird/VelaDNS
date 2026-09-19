package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hyird/VelaDNS/internal/statewire"
)

const (
	restartInitial = time.Second
	restartMaximum = 30 * time.Second
	stableRuntime  = 5 * time.Minute
	shutdownGrace  = 5 * time.Second
)

type childSpec struct {
	name                string
	path                string
	args                []string
	suppressStartupInfo bool
}

func superviseChild(
	ctx context.Context,
	spec childSpec,
	state *runtimeState,
	log *logger,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	var step uint

	for {
		if ctx.Err() != nil {
			return
		}
		cmd := exec.Command(spec.path, spec.args...)
		deduper := newChildLogDeduper(spec.name, spec.suppressStartupInfo)
		stdout := newChildLogWriter(deduper, os.Stdout)
		stderr := newChildLogWriter(deduper, os.Stderr)
		cmd.Stdout = stdout
		cmd.Stderr = stderr
		configureProcess(cmd)
		startedAt := time.Now()
		if err := cmd.Start(); err != nil {
			log.errorf("%s failed to start: %v", spec.name, err)
			state.update(spec.name, func(component *statewire.Component) {
				component.Up = false
			})
		} else {
			state.update(spec.name, func(component *statewire.Component) {
				component.Up = true
				component.BackoffSeconds = 0
			})
			log.infof("%s started pid=%d", spec.name, cmd.Process.Pid)

			waited := make(chan error, 1)
			go func() {
				err := cmd.Wait()
				if flushErr := stdout.Flush(); err == nil {
					err = flushErr
				}
				if flushErr := stderr.Flush(); err == nil {
					err = flushErr
				}
				waited <- err
			}()
			select {
			case err := <-waited:
				state.update(spec.name, func(component *statewire.Component) {
					component.Up = false
				})
				if ctx.Err() != nil {
					return
				}
				log.warnf("%s exited after %s: %v", spec.name, time.Since(startedAt).Round(time.Millisecond), err)
			case <-ctx.Done():
				terminateProcess(cmd)
				select {
				case <-waited:
				case <-time.After(shutdownGrace):
					killProcess(cmd)
					<-waited
				}
				state.update(spec.name, func(component *statewire.Component) {
					component.Up = false
				})
				return
			}
		}

		if time.Since(startedAt) >= stableRuntime {
			step = 0
		}
		step++
		delay := restartDelay(step)
		state.update(spec.name, func(component *statewire.Component) {
			component.Up = false
			component.Restarts++
			component.BackoffSeconds = delay.Seconds()
		})
		log.warnf("%s restart scheduled in %s", spec.name, delay.Round(time.Millisecond))
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

type childLogWriter struct {
	mu      sync.Mutex
	deduper *childLogDeduper
	dst     io.Writer
	pending []byte
}

func newChildLogWriter(deduper *childLogDeduper, dst io.Writer) *childLogWriter {
	return &childLogWriter{deduper: deduper, dst: dst}
}

func (w *childLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	accepted := len(p)
	w.pending = append(w.pending, p...)
	for {
		end := bytes.IndexByte(w.pending, '\n')
		if end < 0 {
			return accepted, nil
		}
		line := append([]byte(nil), w.pending[:end+1]...)
		w.pending = w.pending[end+1:]
		if w.deduper.suppress(string(line)) {
			continue
		}
		if _, err := w.dst.Write(line); err != nil {
			return accepted, err
		}
	}
}

func (w *childLogWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.pending) == 0 {
		return nil
	}
	line := w.pending
	w.pending = nil
	if w.deduper.suppress(string(line)) {
		return nil
	}
	_, err := w.dst.Write(line)
	return err
}

const childLogDedupeWindow = 10 * time.Second

var queryIDPattern = regexp.MustCompile(`"uqid":\s*([0-9]+)`)

type childLogDeduper struct {
	mu                  sync.Mutex
	child               string
	suppressStartupInfo bool
	boundaries          map[string]time.Time
}

func newChildLogDeduper(child string, suppressStartupInfo bool) *childLogDeduper {
	return &childLogDeduper{
		child:               child,
		suppressStartupInfo: suppressStartupInfo,
		boundaries:          make(map[string]time.Time),
	}
}

func (d *childLogDeduper) suppress(line string) bool {
	if d.suppressStartupInfo &&
		(d.child == "unbound" || d.child == "unbound_recursive") &&
		strings.Contains(line, " info: start of service (unbound ") {
		return true
	}
	if d.child != "mosdns" || !strings.Contains(line, "context deadline exceeded") {
		return false
	}
	match := queryIDPattern.FindStringSubmatch(line)
	if len(match) != 2 {
		return false
	}

	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	for queryID, recordedAt := range d.boundaries {
		if now.Sub(recordedAt) > childLogDedupeWindow {
			delete(d.boundaries, queryID)
		}
	}

	queryID := match[1]
	if strings.Contains(line, "\tmain_tcp\tentry err\t") ||
		strings.Contains(line, "\tmain_udp\tentry err\t") {
		d.boundaries[queryID] = now
		return false
	}
	internal := strings.Contains(line, "\tclassify_lookup\tsecondary error\t") ||
		strings.Contains(line, "\tforward_unbound\tupstream error\t") ||
		strings.Contains(line, "\trecursive_unbound\tupstream error\t")
	if !internal {
		return false
	}
	recordedAt, ok := d.boundaries[queryID]
	return ok && now.Sub(recordedAt) <= childLogDedupeWindow
}

func restartDelay(step uint) time.Duration {
	nominal := restartInitial
	for i := uint(1); i < step && nominal < restartMaximum; i++ {
		nominal *= 2
		if nominal >= restartMaximum {
			nominal = restartMaximum
			break
		}
	}
	spread := nominal / 5
	delay := nominal - spread + time.Duration(rand.Int63n(int64(2*spread)+1))
	if delay > restartMaximum {
		return restartMaximum
	}
	return delay
}

func waitForTCP(ctx context.Context, address string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return fmt.Errorf("%s did not become ready within %s", address, timeout)
}
