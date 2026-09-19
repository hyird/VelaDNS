package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseForwardEndpoint(t *testing.T) {
	tests := []struct {
		input, host, port string
	}{
		{"10.10.10.3", "10.10.10.3", "53"},
		{"10.10.10.3:5353", "10.10.10.3", "5353"},
		{"mihomo.local", "mihomo.local", "53"},
	}
	for _, test := range tests {
		host, port, err := parseForwardEndpoint(test.input)
		if err != nil {
			t.Fatalf("%s: %v", test.input, err)
		}
		if host != test.host || port != test.port {
			t.Fatalf("%s: got %s:%s", test.input, host, port)
		}
	}
}

func TestParseForwardEndpointRejectsInvalidValues(t *testing.T) {
	for _, input := range []string{"", ":53", "host:no", "host:0", "host:65536", "a:b:53", "bad/value"} {
		if _, _, err := parseForwardEndpoint(input); err == nil {
			t.Fatalf("%q was accepted", input)
		}
	}
}

func TestLoadConfigUsesOneLogLevelForAllProcesses(t *testing.T) {
	tests := map[string]string{
		"debug": "3",
		"info":  "2",
		"warn":  "0",
		"error": "0",
	}
	for level, unbound := range tests {
		t.Run(level, func(t *testing.T) {
			t.Setenv("AUTO_FORWARD", "no")
			t.Setenv("LOG_LEVEL", level)
			cfg, err := loadConfig()
			if err != nil {
				t.Fatal(err)
			}
			if cfg.unboundLog != unbound {
				t.Fatalf("Unbound verbosity = %s, want %s", cfg.unboundLog, unbound)
			}
		})
	}
}

func TestPrepareDomainListsCopiesSemanticDefaults(t *testing.T) {
	dataPath := t.TempDir()
	defaultsPath := t.TempDir()
	for _, spec := range domainListSpecs {
		content := []byte("full:" + spec.name + ".example\n")
		if err := os.WriteFile(filepath.Join(defaultsPath, spec.name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := prepareDomainLists(dataPath, defaultsPath); err != nil {
		t.Fatal(err)
	}
	for _, spec := range domainListSpecs {
		content, err := os.ReadFile(filepath.Join(dataPath, spec.name))
		if err != nil {
			t.Fatal(err)
		}
		expectedContent := "full:" + spec.name + ".example\n"
		if string(content) != expectedContent {
			t.Fatalf("%s content = %q, want %q", spec.name, content, expectedContent)
		}
	}
}
