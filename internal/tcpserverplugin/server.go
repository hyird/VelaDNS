package tcpserverplugin

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/IrineSistiana/mosdns/v5/pkg/server_handler"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/IrineSistiana/mosdns/v5/plugin/server/server_utils"
	"github.com/IrineSistiana/mosdns/v5/plugin/server/tcp_server"
	"github.com/hyird/VelaDNS/internal/cancelclassify"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const pluginType = "veladns_tcp_server"

type Plugin struct {
	listener net.Listener
}

func init() {
	coremain.RegNewPluginFunc(pluginType, initPlugin, func() any {
		return new(tcp_server.Args)
	})
}

func initPlugin(bp *coremain.BP, raw any) (any, error) {
	args := raw.(*tcp_server.Args)
	if args.Listen == "" {
		args.Listen = "127.0.0.1:53"
	}
	if args.IdleTimeout <= 0 {
		args.IdleTimeout = 10
	}
	entry := sequence.ToExecutable(bp.M().GetPlugin(args.Entry))
	if entry == nil {
		return nil, fmt.Errorf("cannot find executable entry by tag %s", args.Entry)
	}

	events, err := cancellationCounter(bp.M().GetMetricsReg())
	if err != nil {
		return nil, err
	}
	logger := cancellationLogger(bp.L(), events, bp.Tag())
	handler := server_handler.NewEntryHandler(server_handler.EntryHandlerOpts{
		Logger: logger,
		Entry:  entry,
	})

	var tlsConfig *tls.Config
	if args.Key != "" || args.Cert != "" {
		tlsConfig = new(tls.Config)
		if err := server.LoadCert(tlsConfig, args.Cert, args.Key); err != nil {
			return nil, fmt.Errorf("read TLS certificate: %w", err)
		}
	}

	socketOptions := server_utils.ListenerSocketOpts{
		SO_REUSEPORT: true,
		SO_RCVBUF:    64 * 1024,
	}
	listenConfig := net.ListenConfig{
		Control: server_utils.ListenerControl(socketOptions),
	}
	network := "tcp"
	if strings.HasPrefix(args.Listen, "@") {
		network = "unix"
	}
	listener, err := listenConfig.Listen(context.Background(), network, args.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}
	bp.L().Info(
		"veladns TCP server started",
		zap.Stringer("addr", listener.Addr()),
		zap.Bool("tls", tlsConfig != nil),
	)

	go func() {
		defer listener.Close()
		err := server.ServeTCP(listener, handler, server.TCPServerOpts{
			Logger:      logger,
			IdleTimeout: time.Duration(args.IdleTimeout) * time.Second,
		})
		bp.M().GetSafeClose().SendCloseSignal(err)
	}()
	return &Plugin{listener: listener}, nil
}

func cancellationCounter(registerer prometheus.Registerer) (*prometheus.CounterVec, error) {
	vector := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "veladns_client_cancel_events_total",
		Help: "Expected downstream TCP cancellation events suppressed from warning logs.",
	}, []string{"listener", "stage"})
	if err := registerer.Register(vector); err != nil {
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if !errors.As(err, &alreadyRegistered) {
			return nil, fmt.Errorf("register client cancellation metric: %w", err)
		}
		var ok bool
		vector, ok = alreadyRegistered.ExistingCollector.(*prometheus.CounterVec)
		if !ok {
			return nil, errors.New("client cancellation metric has an incompatible collector")
		}
	}
	return vector, nil
}

func cancellationLogger(
	logger *zap.Logger,
	events *prometheus.CounterVec,
	listener string,
) *zap.Logger {
	return logger.WithOptions(zap.WrapCore(func(core zapcore.Core) zapcore.Core {
		return &cancellationCore{
			Core:     core,
			events:   events,
			listener: listener,
		}
	}))
}

type cancellationCore struct {
	zapcore.Core
	events   *prometheus.CounterVec
	listener string
}

func (c *cancellationCore) With(fields []zapcore.Field) zapcore.Core {
	return &cancellationCore{
		Core:     c.Core.With(fields),
		events:   c.events,
		listener: c.listener,
	}
}

func (c *cancellationCore) Check(entry zapcore.Entry, checked *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return checked.AddCore(entry, c)
	}
	return checked
}

func (c *cancellationCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	stage := cancellationStage(entry.Message)
	if stage != "" && fieldsContainExpectedCancellation(fields) {
		c.events.WithLabelValues(c.listener, stage).Inc()
		return nil
	}
	return c.Core.Write(entry, fields)
}

func cancellationStage(message string) string {
	switch message {
	case "entry err":
		return "entry"
	case "failed to write response":
		return "write"
	default:
		return ""
	}
}

func fieldsContainExpectedCancellation(fields []zapcore.Field) bool {
	for _, field := range fields {
		if field.Type != zapcore.ErrorType {
			continue
		}
		err, ok := field.Interface.(error)
		if ok && cancelclassify.Expected(err) {
			return true
		}
	}
	return false
}

func (p *Plugin) Close() error {
	return p.listener.Close()
}
