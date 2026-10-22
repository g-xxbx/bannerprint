package fingerprint

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Rule 是一条识别规则。一条规则 = 一个协议（可选产品）+ 一个匹配正则。
//
// 匹配在原始字节上进行，因此既可以写文本规则（SSH/HTTP/FTP），
// 也可以写二进制规则（MySQL 握手包），不需要任何协议专属代码。
type Rule struct {
	ID       string `yaml:"id" json:"id"`
	Protocol string `yaml:"protocol" json:"protocol"`
	Product  string `yaml:"product" json:"product"`
	Priority int    `yaml:"priority" json:"priority"`

	// Kind 仅用于可读性与调试：text | binary。匹配行为由正则本身决定。
	Kind string `yaml:"kind" json:"kind"`

	// Match 必须命中；Version 命中时取第一个捕获组；OSHint 命中时填 os_hint。
	Match   string   `yaml:"match" json:"match"`
	Version string   `yaml:"version" json:"version"`
	OSHint  []OSHint `yaml:"os_hint" json:"os_hint"`

	// Confidence 为 0 时按证据分级自动计算（见 confidence 方法）。
	Confidence float64 `yaml:"confidence" json:"confidence"`

	matchRE   *regexp.Regexp
	versionRE *regexp.Regexp
	osRE      []osMatcher
}

// OSHint 是“正则 → 归一化操作系统名”的映射项。
type OSHint struct {
	Match string `yaml:"match" json:"match"`
	Value string `yaml:"value" json:"value"`
}

type osMatcher struct {
	re    *regexp.Regexp
	value string
}

// Engine 是编译后的规则集合，只读、可并发使用。
type Engine struct {
	rules []Rule
}

// NewEngine 编译并校验规则，按 priority 降序（同优先级按 ID）排序。
// 任何一条规则写错都会导致启动失败，避免“静默降级”。
func NewEngine(rules []Rule) (*Engine, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("empty rule set")
	}

	seen := make(map[string]struct{}, len(rules))
	compiled := make([]Rule, 0, len(rules))

	for _, r := range rules {
		if strings.TrimSpace(r.ID) == "" {
			return nil, fmt.Errorf("rule without id")
		}
		if _, dup := seen[r.ID]; dup {
			return nil, fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = struct{}{}

		if strings.TrimSpace(r.Protocol) == "" {
			return nil, fmt.Errorf("rule %q: empty protocol", r.ID)
		}
		switch r.Kind {
		case "", "text", "binary":
		default:
			return nil, fmt.Errorf("rule %q: unsupported kind %q", r.ID, r.Kind)
		}

		re, err := regexp.Compile(r.Match)
		if err != nil {
			return nil, fmt.Errorf("rule %q: invalid match regex: %w", r.ID, err)
		}
		r.matchRE = re

		if r.Version != "" {
			vre, err := regexp.Compile(r.Version)
			if err != nil {
				return nil, fmt.Errorf("rule %q: invalid version regex: %w", r.ID, err)
			}
			r.versionRE = vre
		}

		for _, h := range r.OSHint {
			ore, err := regexp.Compile(h.Match)
			if err != nil {
				return nil, fmt.Errorf("rule %q: invalid os_hint regex: %w", r.ID, err)
			}
			r.osRE = append(r.osRE, osMatcher{re: ore, value: h.Value})
		}

		compiled = append(compiled, r)
	}

	sort.SliceStable(compiled, func(i, j int) bool {
		if compiled[i].Priority != compiled[j].Priority {
			return compiled[i].Priority > compiled[j].Priority
		}
		return compiled[i].ID < compiled[j].ID
	})

	return &Engine{rules: compiled}, nil
}

// Len 返回规则条数（/health 会暴露，便于确认规则是否加载成功）。
func (e *Engine) Len() int { return len(e.rules) }

// Rules 返回规则副本，供 -list-rules 展示。
func (e *Engine) Rules() []Rule {
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// Fingerprint 识别单条数据。首条命中即返回（规则已按优先级排序）。
// 任何 panic 都被收敛为 unknown，保证“认不出来不崩服务”。
func (e *Engine) Fingerprint(in Input) (res Result) {
	defer func() {
		if r := recover(); r != nil {
			res = Unknown(in)
		}
	}()

	raw := []byte(in.Banner)
	// 文本协议常因抓包/协商残留前置的 CRLF、空白或 NUL；匹配前统一裁掉。
	// 二进制规则（MySQL/TLS/RESP）保持原始字节，避免破坏长度前缀。
	text := bytes.TrimLeft(raw, " \t\r\n\v\f\x00")

	for i := range e.rules {
		r := &e.rules[i]

		subject := raw
		if r.Kind != "binary" {
			subject = text
		}
		if !r.matchRE.Match(subject) {
			continue
		}
		return r.apply(in, subject)
	}
	return Unknown(in)
}

func (r *Rule) apply(in Input, raw []byte) Result {
	res := Result{
		IP:       in.IP,
		Port:     in.Port,
		Protocol: r.Protocol,
		Product:  r.Product,
	}

	if r.versionRE != nil {
		if m := r.versionRE.FindSubmatch(raw); len(m) > 0 {
			if len(m) > 1 {
				res.Version = cleanField(string(m[1]))
			} else {
				res.Version = cleanField(string(m[0]))
			}
		}
	}

	for _, h := range r.osRE {
		if h.re.Match(raw) {
			res.OSHint = h.value
			break
		}
	}

	res.Confidence = r.confidence(res.Version, res.OSHint)
	return res
}

// confidence 实现证据分级：
//
//	版本 + OS 佐证   0.95
//	仅版本           0.90
//	仅产品           0.70
//	仅协议           0.50
//
// 规则可用 confidence 字段显式覆盖（例如 Jetty = 0.85）。
func (r *Rule) confidence(version, osHint string) float64 {
	if r.Confidence > 0 {
		return r.Confidence
	}
	switch {
	case version != "" && osHint != "":
		return 0.95
	case version != "":
		return 0.9
	case r.Product != "":
		return 0.7
	default:
		return 0.5
	}
}

// cleanField 去掉二进制握手残留的空字节与首尾空白。
func cleanField(s string) string {
	s = strings.TrimRight(s, "\x00")
	return strings.TrimSpace(s)
}
