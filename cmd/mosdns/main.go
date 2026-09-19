package main

import (
	"fmt"
	"os"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/mlog"
	_ "github.com/IrineSistiana/mosdns/v5/plugin"
	_ "github.com/IrineSistiana/mosdns/v5/tools"
	_ "github.com/hyird/VelaDNS/internal/circuitplugin"
	_ "github.com/hyird/VelaDNS/internal/decisionplugin"
	_ "github.com/hyird/VelaDNS/internal/requestmetricsplugin"
	_ "github.com/hyird/VelaDNS/internal/rulesplugin"
	_ "github.com/hyird/VelaDNS/internal/supervisorplugin"
	_ "github.com/hyird/VelaDNS/internal/tcpserverplugin"
	"github.com/spf13/cobra"
	"go.uber.org/zap/zapcore"
)

var version = "v5.3.4-veladns"

func init() {
	coremain.AddSubCmd(&cobra.Command{
		Use:   "version",
		Short: "Print version and exit.",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println(version)
		},
	})
}

func main() {
	// coremain logs once before it loads mosdns.yaml. Configure that bootstrap
	// logger from the same environment as the rendered runtime configuration so
	// warn/error deployments do not leak an informational startup line.
	mlog.SetLevel(bootstrapLogLevel(os.Getenv("LOG_LEVEL")))
	if err := coremain.Run(); err != nil {
		mlog.S().Fatal(err)
	}
}

func bootstrapLogLevel(raw string) zapcore.Level {
	if raw == "" {
		raw = "warn"
	}
	level, err := zapcore.ParseLevel(raw)
	if err != nil {
		return zapcore.WarnLevel
	}
	return level
}
