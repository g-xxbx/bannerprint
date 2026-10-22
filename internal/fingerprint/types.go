// Package fingerprint 定义 Banner 指纹识别的输入/输出契约与规则引擎。
//
// 设计要点：识别能力全部由 YAML 规则（rules/ 目录）提供，本包只负责
// “加载规则 → 按优先级匹配原始字节 → 填充字段 → 计算置信度”。
// 新增协议或产品不需要修改本包任何代码。
package fingerprint

// ProtocolUnknown 是所有规则都未命中时的协议取值（题目要求，不许报错）。
const ProtocolUnknown = "unknown"

// ConfidenceUnknown 是未知结果的固定置信度：能确认的只有“没见过”。
const ConfidenceUnknown = 0.1

// Input 是一条扫描原始数据。
type Input struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
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
