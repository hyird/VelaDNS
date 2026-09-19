package main

import (
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/IrineSistiana/mosdns/v5/plugin/server/tcp_server"
	"go.uber.org/zap/zapcore"
)

func TestBootstrapLogLevelMatchesRuntimeDefault(t *testing.T) {
	tests := map[string]zapcore.Level{
		"":        zapcore.WarnLevel,
		"debug":   zapcore.DebugLevel,
		"info":    zapcore.InfoLevel,
		"warn":    zapcore.WarnLevel,
		"error":   zapcore.ErrorLevel,
		"invalid": zapcore.WarnLevel,
	}
	for raw, want := range tests {
		if got := bootstrapLogLevel(raw); got != want {
			t.Fatalf("bootstrapLogLevel(%q) = %s, want %s", raw, got, want)
		}
	}
}

func TestVelaDNSPluginsInitializeTogether(t *testing.T) {
	entry := sequence.Args{
		{Exec: "veladns_metrics_collector main"},
		{Exec: "veladns_decision first"},
		{Exec: "veladns_decision second"},
		{Exec: "reject 0"},
	}
	secureEntry := sequence.Args{
		{Exec: "veladns_metrics_collector secure"},
		{Exec: "veladns_decision secure"},
		{Exec: "reject 0"},
	}
	cfg := &coremain.Config{Plugins: []coremain.PluginConfig{
		{Tag: "entry", Type: "sequence", Args: &entry},
		{Tag: "secure_entry", Type: "sequence", Args: &secureEntry},
		{
			Tag:  "main_tcp",
			Type: "veladns_tcp_server",
			Args: &tcp_server.Args{
				Entry:  "entry",
				Listen: "127.0.0.1:0",
			},
		},
		{
			Tag:  "secure_tcp",
			Type: "veladns_tcp_server",
			Args: &tcp_server.Args{
				Entry:  "secure_entry",
				Listen: "127.0.0.1:0",
			},
		},
	}}
	instance, err := coremain.NewMosdns(cfg)
	if err != nil {
		t.Fatal(err)
	}
	instance.CloseWithErr(nil)
	if err := instance.GetSafeClose().WaitClosed(); err != nil {
		t.Fatal(err)
	}
}
