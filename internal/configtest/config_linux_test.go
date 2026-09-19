//go:build linux

package configtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	_ "github.com/IrineSistiana/mosdns/v5/plugin"
	_ "github.com/IrineSistiana/mosdns/v5/tools"
	_ "github.com/hyird/VelaDNS/internal/circuitplugin"
	_ "github.com/hyird/VelaDNS/internal/decisionplugin"
	_ "github.com/hyird/VelaDNS/internal/requestmetricsplugin"
	_ "github.com/hyird/VelaDNS/internal/rulesplugin"
	_ "github.com/hyird/VelaDNS/internal/supervisorplugin"
	_ "github.com/hyird/VelaDNS/internal/tcpserverplugin"
)

func TestRuntimeConfigsInitialize(t *testing.T) {
	for _, mode := range []string{"secure", "auto"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			rules := filepath.Join(dir, "domains.txt")
			cidr := filepath.Join(dir, "cncidr.txt")
			if err := os.WriteFile(rules, []byte("domain:example.com\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(cidr, []byte("1.0.1.0/24\n"), 0600); err != nil {
				t.Fatal(err)
			}

			foreignSource := filepath.Join("..", "..", "config", "foreign-secure.yaml")
			if mode == "auto" {
				foreignSource = filepath.Join("..", "..", "config", "foreign-mihomo.yaml.tmpl")
			}
			foreign := readFile(t, foreignSource)
			foreign = strings.ReplaceAll(foreign, "__AUTO_FORWARD_ENDPOINT__", "127.0.0.1:5353")
			foreignPath := filepath.Join(dir, "foreign.yaml")
			writeFile(t, foreignPath, foreign)

			mainConfig := readFile(t, filepath.Join("..", "..", "config", "mosdns.yaml.tmpl"))
			mainConfig = strings.NewReplacer(
				"__LOG_LEVEL__", "error",
				"/run/veladns/foreign.yaml", foreignPath,
				"/run/veladns/supervisor.sock", filepath.Join(dir, "supervisor.sock"),
				"/data/direct.txt", rules,
				"/data/proxy.txt", rules,
				"/usr/share/veladns/rules/proxy.txt", rules,
				"/usr/share/veladns/rules/cncidr.txt", cidr,
				"http: '0.0.0.0:5308'", "http: ''",
				"listen: '0.0.0.0:53'", "listen: '127.0.0.1:0'",
				"listen: '0.0.0.0:5304'", "listen: '127.0.0.1:0'",
			).Replace(mainConfig)
			mainPath := filepath.Join(dir, "mosdns.yaml")
			writeFile(t, mainPath, mainConfig)

			cfg := decodeConfig(t, mainPath)
			instance, err := coremain.NewMosdns(cfg)
			if err != nil {
				t.Fatalf("initialize %s config: %v", mode, err)
			}
			instance.CloseWithErr(nil)
			if err := instance.GetSafeClose().WaitClosed(); err != nil {
				t.Fatalf("close %s config: %v", mode, err)
			}
		})
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
