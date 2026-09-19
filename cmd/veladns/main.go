package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"
)

var version = "dev"

func main() {
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "version":
			fmt.Println(version)
			return
		case "healthcheck":
			if err := runHealthcheck(); err != nil {
				fmt.Fprintf(os.Stderr, "VelaDNS health check failed: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: veladns [version|healthcheck]")
		os.Exit(2)
	}

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "VelaDNS configuration error: %v\n", err)
		os.Exit(2)
	}
	log := newLogger(cfg.logLevel)
	if err := prepareRuntime(cfg); err != nil {
		log.errorf("runtime initialization failed: %v", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), terminationSignals()...)
	defer stop()

	state := newRuntimeState()
	go sendStateLoop(ctx, state, supervisorSocket)
	bridge, err := startDoHBridge(ctx, cfg, state, log)
	if err != nil {
		log.errorf("encrypted DNS bridge failed to start: %v", err)
		os.Exit(1)
	}
	defer bridge.close()

	var managers sync.WaitGroup
	quietUnboundStartup := cfg.logLevel == "warn" || cfg.logLevel == "error"
	managers.Add(1)
	go superviseChild(ctx, childSpec{
		name:                "unbound",
		path:                "/usr/sbin/unbound",
		args:                []string{"-d", "-c", unboundRuntimeConfig},
		suppressStartupInfo: quietUnboundStartup,
	}, state, log, &managers)

	managers.Add(1)
	go superviseChild(ctx, childSpec{
		name:                "unbound_recursive",
		path:                "/usr/sbin/unbound",
		args:                []string{"-d", "-c", unboundRecursiveRuntimeConfig},
		suppressStartupInfo: quietUnboundStartup,
	}, state, log, &managers)

	if err := waitForTCP(ctx, "127.0.0.1:5306", 3*time.Second); err != nil {
		log.warnf("Unbound is not ready; starting MosDNS in degraded mode: %v", err)
	}
	// The CN classifier degrades to the encrypted path on its own, so a slow
	// start here must not hold up the listeners.
	if err := waitForTCP(ctx, "127.0.0.1:5305", 3*time.Second); err != nil {
		log.warnf("CN classification resolver is not ready: %v", err)
	}

	managers.Add(1)
	go superviseChild(ctx, childSpec{
		name: "mosdns",
		path: "/usr/local/bin/mosdns",
		args: []string{"start", "-c", mosdnsRuntimeConfig},
	}, state, log, &managers)

	mode := "secure"
	if cfg.autoEnabled {
		mode = "auto-forward"
	}
	if err := waitForTCP(ctx, "127.0.0.1:53", 5*time.Second); err != nil {
		log.warnf("MosDNS is not ready and will keep restarting: %v", err)
	} else {
		log.infof("ready mode=%s dns=:53 secure=:5304 metrics=:5308", mode)
	}

	<-ctx.Done()
	log.infof("shutdown requested")
	managers.Wait()
}
