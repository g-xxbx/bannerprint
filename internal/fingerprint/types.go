// Package fingerprint 定义 Banner 指纹识别的输入/输出契约与规则引擎。
//
// 设计要点：识别能力全部由 YAML 规则（rules/ 目录）提供，本包只负责
// “加载规则 → 按优先级匹配原始字节 → 填充字段 → 计算置信度”。
// 新增协议或产品不需要修改本包任何代码。
package fingerprint

import (
	"encoding/json"
	"strconv"
	"strings"
)

// ProtocolUnknown 是所有规则都未命中时的协议取值（题目要求，不许报错）。
const ProtocolUnknown = "unknown"

// ConfidenceUnknown 是未知结果的固定置信度：能确认的只有“没见过”。
const ConfidenceUnknown = 0.1

// Input 是一条扫描原始数据。
//
// 反序列化是宽松的：真实扫描器导出的 port 可能是数字（22）、字符串（"22"）
// 甚至浮点（22.0），banner 可能缺失或为 null。这些都不应让整批数据失败。
type Input struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// UnmarshalJSON 对 port 做数字/字符串/浮点兼容，对 banner 做 null 兼容。
func (in *Input) UnmarshalJSON(data []byte) error {
	var raw struct {
		IP     json.RawMessage `json:"ip"`
		Port   json.RawMessage `json:"port"`
		Banner json.RawMessage `json:"banner"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	in.IP = coerceString(raw.IP)
	in.Port = coercePort(raw.Port)
	in.Banner = coerceString(raw.Banner)
	return nil
}

func coerceString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String()
	}
	return ""
}

func coercePort(raw json.RawMessage) int {
	if len(raw) == 0 || string(raw) == "null" {
		return 0
	}

	var port int
	if err := json.Unmarshal(raw, &port); err == nil {
		return port
	}

	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return int(f)
	}

	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
			return v
		}
	}
	return 0
}

// Result 是识别结果，字段与题目示例严格一致。
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// Unknown 生成标准的“未识别”结果：协议为 unknown，其余字段留空。
func Unknown(in Input) Result {
	return Result{
		IP:         in.IP,
		Port:       in.Port,
		Protocol:   ProtocolUnknown,
		Confidence: ConfidenceUnknown,
	}
}
