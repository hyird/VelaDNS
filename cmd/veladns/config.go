package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	runtimeDir                    = "/run/veladns"
	unboundRuntimeDir             = "/run/veladns/unbound"
	unboundRecursiveRuntimeDir    = "/run/veladns/unbound-recursive"
	configDir                     = "/etc/veladns"
	dataDir                       = "/data"
	supervisorSocket              = "/run/veladns/supervisor.sock"
	mosdnsRuntimeConfig           = "/run/veladns/mosdns.yaml"
	foreignRuntimeConfig          = "/run/veladns/foreign.yaml"
	unboundRuntimeConfig          = "/run/veladns/unbound.conf"
	unboundRecursiveRuntimeConfig = "/run/veladns/unbound-recursive.conf"
)

var safeHost = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

type config struct {
	autoForwardRaw string
	autoEnabled    bool
	autoDNS        string
	logLevel       string
	unboundLog     string
}

type domainListSpec struct {
	name string
}

var domainListSpecs = []domainListSpec{
	{name: "direct.txt"},
	{name: "proxy.txt"},
}

func loadConfig() (config, error) {
	cfg := config{
		autoForwardRaw: envDefault("AUTO_FORWARD", "no"),
		logLevel:       envDefault("LOG_LEVEL", "warn"),
	}
	switch cfg.logLevel {
	case "debug":
		cfg.unboundLog = "3"
	case "info":
		cfg.unboundLog = "2"
	case "warn":
		// Unbound verbosity 1 emits operational startup notices rather than
		// warnings. Keep warn mode aligned with its name and reserve those
		// notices for info/debug runs.
		cfg.unboundLog = "0"
	case "error":
		cfg.unboundLog = "0"
	default:
		return config{}, errors.New("LOG_LEVEL must be debug, info, warn, or error")
	}
	if cfg.autoForwardRaw == "no" {
		return cfg, nil
	}

	host, port, err := parseForwardEndpoint(cfg.autoForwardRaw)
	if err != nil {
		return config{}, err
	}
	cfg.autoEnabled = true
	cfg.autoDNS = net.JoinHostPort(host, port)
	return cfg, nil
}

func envDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func parseForwardEndpoint(value string) (host, port string, err error) {
	host = value
	port = "53"
	switch strings.Count(value, ":") {
	case 0:
	case 1:
		host, port, _ = strings.Cut(value, ":")
	default:
		return "", "", errors.New("AUTO_FORWARD supports hostname or IPv4 host[:port]")
	}
	if host == "" {
		return "", "", errors.New("AUTO_FORWARD host must not be empty")
	}
	if !safeHost.MatchString(host) {
		return "", "", errors.New("AUTO_FORWARD host contains invalid characters")
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		return "", "", errors.New("AUTO_FORWARD port must be an integer")
	}
	if number < 1 || number > 65535 {
		return "", "", errors.New("AUTO_FORWARD port must be between 1 and 65535")
	}
	return host, strconv.Itoa(number), nil
}

func prepareRuntime(cfg config) error {
	for _, dir := range []string{
		runtimeDir, unboundRuntimeDir, unboundRecursiveRuntimeDir, dataDir,
	} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	if err := prepareDomainLists(dataDir, filepath.Join(configDir, "defaults")); err != nil {
		return err
	}

	rootKeySource := ""
	for _, candidate := range []string{
		"/usr/share/dnssec-root/trusted-key.key",
		"/usr/share/dnssec-root/root.key",
		"/etc/unbound/root.key",
	} {
		if info, err := os.Stat(candidate); err == nil && info.Size() > 0 {
			rootKeySource = candidate
			break
		}
	}
	if rootKeySource == "" {
		return errors.New("DNSSEC root trust anchor was not found")
	}
	rootKey := filepath.Join(unboundRuntimeDir, "root.key")
	if err := copyFile(rootKeySource, rootKey, 0644); err != nil {
		return err
	}
	if err := chownUnbound(unboundRuntimeDir, rootKey, unboundRecursiveRuntimeDir); err != nil {
		return err
	}

	unboundTemplate, err := os.ReadFile(filepath.Join(configDir, "unbound.conf.tmpl"))
	if err != nil {
		return err
	}
	unboundConfig := strings.ReplaceAll(string(unboundTemplate), "__UNBOUND_VERBOSITY__", cfg.unboundLog)
	if err := writeRendered(unboundRuntimeConfig, unboundConfig); err != nil {
		return err
	}
	recursiveTemplate, err := os.ReadFile(filepath.Join(configDir, "unbound-recursive.conf.tmpl"))
	if err != nil {
		return err
	}
	recursiveConfig := strings.ReplaceAll(
		string(recursiveTemplate), "__UNBOUND_VERBOSITY__", cfg.unboundLog)
	if err := writeRendered(unboundRecursiveRuntimeConfig, recursiveConfig); err != nil {
		return err
	}
	mainTemplate, err := os.ReadFile(filepath.Join(configDir, "mosdns.yaml.tmpl"))
	if err != nil {
		return err
	}
	mainConfig := strings.ReplaceAll(string(mainTemplate), "__LOG_LEVEL__", cfg.logLevel)
	if err := writeRendered(mosdnsRuntimeConfig, mainConfig); err != nil {
		return err
	}

	foreignSource := filepath.Join(configDir, "foreign-secure.yaml")
	if cfg.autoEnabled {
		foreignSource = filepath.Join(configDir, "foreign-mihomo.yaml.tmpl")
	}
	foreignTemplate, err := os.ReadFile(foreignSource)
	if err != nil {
		return err
	}
	foreignConfig := string(foreignTemplate)
	if cfg.autoEnabled {
		foreignConfig = strings.ReplaceAll(foreignConfig, "__AUTO_FORWARD_ENDPOINT__", cfg.autoDNS)
	}
	if err := writeRendered(foreignRuntimeConfig, foreignConfig); err != nil {
		return err
	}

	_ = os.Remove(filepath.Join(unboundRuntimeDir, "unbound.pid"))
	_ = os.Remove(filepath.Join(unboundRecursiveRuntimeDir, "unbound.pid"))
	for _, config := range []string{unboundRuntimeConfig, unboundRecursiveRuntimeConfig} {
		check := exec.Command("unbound-checkconf", config)
		if output, err := check.CombinedOutput(); err != nil {
			return fmt.Errorf(
				"unbound config validation failed for %s: %w: %s",
				config, err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func prepareDomainLists(dataPath, defaultsPath string) error {
	for _, spec := range domainListSpecs {
		dst := filepath.Join(dataPath, spec.name)
		if _, err := os.Stat(dst); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}

		if err := copyFile(filepath.Join(defaultsPath, spec.name), dst, 0644); err != nil {
			return err
		}
	}
	return nil
}

func writeRendered(path, content string) error {
	if strings.Contains(content, "__") {
		return fmt.Errorf("unresolved template placeholder in %s", path)
	}
	return writeFileAtomic(path, []byte(content), 0644)
}

func copyFile(src, dst string, mode os.FileMode) error {
	input, err := os.Open(src)
	if err != nil {
		return err
	}
	defer input.Close()
	tmp := dst + ".tmp"
	output, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	return os.Rename(tmp, dst)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func chownUnbound(paths ...string) error {
	account, err := user.Lookup("unbound")
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	for _, path := range paths {
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
	}
	return nil
}
