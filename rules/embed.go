// Package rules 以 YAML 描述识别规则，并通过 go:embed 编进二进制。
//
// 规则与代码解耦：新增协议/产品只改本目录的 YAML，不改任何 Go 代码。
// 运行时也可以通过 FP_RULES_DIR 指向只读挂载的目录来覆盖内置规则。
package rules

import "embed"

// FS 是内置规则的只读文件系统（根目录就是本包目录）。
//
//go:embed *.yaml
var FS embed.FS

// Dir 是内置规则在 FS 中的根路径。
const Dir = "."
