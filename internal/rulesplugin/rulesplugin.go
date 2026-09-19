package rulesplugin

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

const (
	PluginType       = "veladns_rule_file"
	reloadDebounce    = 200 * time.Millisecond
	maxRuleFileBytes  = 1 << 20
	maxRegexpRuleSize = 4096
)

var _ data_provider.DomainMatcherProvider = (*RuleFile)(nil)

func init() {
	coremain.RegNewPluginFunc(PluginType, initPlugin, func() any { return new(Args) })
}

type Args struct {
	File     string   `yaml:"file"`
	Includes []string `yaml:"includes"`
}

func initPlugin(bp *coremain.BP, raw any) (any, error) {
	return NewRuleFile(bp.L(), raw.(*Args))
}

// RuleFile keeps a domain matcher backed by one operator-maintained file. Its
// matcher is swapped only after the new file has been completely validated.
type RuleFile struct {
	path     string
	includes []string
	logger   *zap.Logger

	mu       sync.RWMutex
	matcher  domain.Matcher[struct{}]
	lastGood []byte
	loaded   bool

	watcher   *fsnotify.Watcher
	done      chan struct{}
	closeOnce sync.Once
}

func NewRuleFile(logger *zap.Logger, args *Args) (*RuleFile, error) {
	return newRuleFile(logger, args, true)
}

func newRuleFile(logger *zap.Logger, args *Args, watch bool) (*RuleFile, error) {
	if args == nil || args.File == "" {
		return nil, fmt.Errorf("file is required")
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	path, err := filepath.Abs(args.File)
	if err != nil {
		return nil, fmt.Errorf("resolve rule file path: %w", err)
	}
	r := &RuleFile{
		path:     path,
		includes: append([]string(nil), args.Includes...),
		logger:   logger,
		done:     make(chan struct{}),
	}
	if err := r.reload(); err != nil {
		return nil, err
	}
	if !watch {
		return r, nil
	}

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create rule watcher: %w", err)
	}
	if err := w.Add(filepath.Dir(path)); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("watch rule directory: %w", err)
	}
	r.watcher = w
	go r.watch()
	return r, nil
}

func (r *RuleFile) GetDomainMatcher() domain.Matcher[struct{}] {
	return r
}

func (r *RuleFile) Match(name string) (struct{}, bool) {
	r.mu.RLock()
	matcher := r.matcher
	r.mu.RUnlock()
	if matcher == nil {
		return struct{}{}, false
	}
	return matcher.Match(name)
}

func (r *RuleFile) Close() error {
	r.closeOnce.Do(func() {
		close(r.done)
		if r.watcher != nil {
			_ = r.watcher.Close()
		}
	})
	return nil
}

func (r *RuleFile) watch() {
	var timer *time.Timer
	var timerC <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		select {
		case <-r.done:
			return
		case event, ok := <-r.watcher.Events:
			if !ok {
				return
			}
			if filepath.Clean(event.Name) != r.path ||
				event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) == 0 {
				continue
			}
			if timer == nil {
				timer = time.NewTimer(reloadDebounce)
				timerC = timer.C
				continue
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(reloadDebounce)
			timerC = timer.C
		case err, ok := <-r.watcher.Errors:
			if !ok {
				return
			}
			r.logger.Warn("rule file watcher error", zap.String("file", r.path), zap.Error(err))
		case <-timerC:
			timerC = nil
			if err := r.reload(); err != nil {
				r.logger.Warn("rule file reload rejected", zap.String("file", r.path), zap.Error(err))
			}
		}
	}
}

func (r *RuleFile) reload() error {
	raw, err := os.ReadFile(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return r.restoreOrClear(fmt.Errorf("rule file was removed"))
		}
		return fmt.Errorf("read rule file: %w", err)
	}
	rules, cleaned, stats, err := sanitizeRules(raw)
	if err != nil {
		return r.restoreOrClear(err)
	}

	r.mu.RLock()
	lastGood := append([]byte(nil), r.lastGood...)
	loaded := r.loaded
	r.mu.RUnlock()
	if stats.meaningful > 0 && len(rules) == 0 && loaded {
		if err := writeFileAtomic(r.path, lastGood); err != nil {
			return fmt.Errorf("restore last valid rule file: %w", err)
		}
		r.logger.Warn("all changed rules were invalid; restored the previous valid rules",
			zap.String("file", r.path), zap.Int("rejected", stats.rejected))
		return nil
	}

	matcher, err := buildMatcher(rules, r.includes)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, cleaned) {
		if err := writeFileAtomic(r.path, cleaned); err != nil {
			return fmt.Errorf("write sanitized rule file: %w", err)
		}
	}

	r.mu.Lock()
	unchanged := r.loaded && bytes.Equal(r.lastGood, cleaned)
	r.matcher = matcher
	r.lastGood = append(r.lastGood[:0], cleaned...)
	r.loaded = true
	r.mu.Unlock()
	if !unchanged {
		r.logger.Info("rule file reloaded", zap.String("file", r.path),
			zap.Int("accepted", len(rules)), zap.Int("rejected", stats.rejected))
	}
	return nil
}

func (r *RuleFile) restoreOrClear(cause error) error {
	r.mu.RLock()
	lastGood := append([]byte(nil), r.lastGood...)
	loaded := r.loaded
	r.mu.RUnlock()
	if loaded {
		if err := writeFileAtomic(r.path, lastGood); err != nil {
			return fmt.Errorf("restore last valid rule file after %v: %w", cause, err)
		}
		r.logger.Warn("invalid rule file was replaced with the previous valid rules",
			zap.String("file", r.path), zap.Error(cause))
		return nil
	}
	if err := writeFileAtomic(r.path, nil); err != nil {
		return fmt.Errorf("clear invalid initial rule file after %v: %w", cause, err)
	}
	matcher, err := buildMatcher(nil, r.includes)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.matcher = matcher
	r.lastGood = nil
	r.loaded = true
	r.mu.Unlock()
	r.logger.Warn("invalid initial rule file was cleared", zap.String("file", r.path), zap.Error(cause))
	return nil
}

func buildMatcher(rules, includes []string) (domain.Matcher[struct{}], error) {
	matcher := domain.NewDomainMixMatcher()
	for _, rule := range rules {
		if err := matcher.Add(rule, struct{}{}); err != nil {
			return nil, fmt.Errorf("add validated rule %q: %w", rule, err)
		}
	}
	for _, include := range includes {
		content, err := os.ReadFile(include)
		if err != nil {
			return nil, fmt.Errorf("read bundled rule file %s: %w", include, err)
		}
		if err := domain.LoadFromTextReader[struct{}](matcher, bytes.NewReader(content), nil); err != nil {
			return nil, fmt.Errorf("load bundled rule file %s: %w", include, err)
		}
	}
	return matcher, nil
}

type ruleStats struct {
	meaningful int
	rejected   int
}

func sanitizeRules(raw []byte) ([]string, []byte, ruleStats, error) {
	if len(raw) > maxRuleFileBytes {
		return nil, nil, ruleStats{}, fmt.Errorf("rule file exceeds %d bytes", maxRuleFileBytes)
	}

	var rules []string
	var stats ruleStats
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSuffix(line, "\r")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if index := inlineCommentIndex(line); index >= 0 {
			line = strings.TrimSpace(line[:index])
		}
		stats.meaningful++
		rule, err := normalizeRule(line)
		if err != nil {
			stats.rejected++
			continue
		}
		rules = append(rules, rule)
	}
	if len(rules) == 0 {
		return rules, nil, stats, nil
	}
	return rules, []byte(strings.Join(rules, "\n") + "\n"), stats, nil
}

func inlineCommentIndex(line string) int {
	for index := 1; index < len(line); index++ {
		if line[index] == '#' && (line[index-1] == ' ' || line[index-1] == '\t') {
			return index
		}
	}
	return -1
}

func normalizeRule(line string) (string, error) {
	if !utf8.ValidString(line) || strings.IndexFunc(line, unicode.IsSpace) >= 0 {
		return "", fmt.Errorf("rule must be one non-space expression")
	}
	typ, pattern, hasType := strings.Cut(line, ":")
	if !hasType {
		typ, pattern = domain.MatcherDomain, line
	}
	if pattern == "" {
		return "", fmt.Errorf("rule pattern is empty")
	}

	switch typ {
	case domain.MatcherDomain, domain.MatcherFull, domain.MatcherKeyword:
		pattern, err := normalizeDomainPattern(pattern)
		if err != nil {
			return "", err
		}
		return typ + ":" + pattern, nil
	case domain.MatcherRegexp:
		if len(pattern) > maxRegexpRuleSize {
			return "", fmt.Errorf("regexp rule exceeds %d bytes", maxRegexpRuleSize)
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return "", fmt.Errorf("invalid regexp: %w", err)
		}
		return typ + ":" + pattern, nil
	default:
		return "", fmt.Errorf("unsupported matcher type %q", typ)
	}
}

func normalizeDomainPattern(pattern string) (string, error) {
	pattern = strings.TrimSuffix(strings.ToLower(pattern), ".")
	if pattern == "" || len(pattern) > 253 || net.ParseIP(pattern) != nil {
		return "", fmt.Errorf("invalid domain pattern")
	}
	for _, label := range strings.Split(pattern, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", fmt.Errorf("invalid domain label")
		}
		for _, char := range label {
			if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' || char == '_') {
				return "", fmt.Errorf("invalid domain label")
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid domain label")
		}
	}
	return pattern, nil
}

func writeFileAtomic(path string, data []byte) error {
	info, err := os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	mode := os.FileMode(0644)
	if err == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
