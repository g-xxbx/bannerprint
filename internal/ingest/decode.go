// Package ingest 把“扫描器原始输出”解析成标准输入批次。
//
// 现实中的 banner 数据经常不是合法 JSON：例如 MySQL 抓包常被导出成
// "J\x00\x00\x00\n8.0.32\x00"，而 \x 不是 JSON 合法转义。若严格解析失败，
// 这里会先做一次 \xNN -> \u00NN 的转义修复再重试，避免整批数据 400。
package ingest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"

	"bannerprint/internal/fingerprint"
)

// 匹配非标准 \xNN 转义（JSON 只认 \uNNNN）。
var xEscape = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)

// envelope 兼容“裸数组”之外的常见包装格式。
type envelope struct {
	Items []fingerprint.Input `json:"items"`
	Data  []fingerprint.Input `json:"data"`
	Batch []fingerprint.Input `json:"batch"`
}

// Batch 解析一个批次。支持：
//   - 裸数组：[{"ip":...}, ...]
//   - 包装对象：{"items":[...]} / {"data":[...]} / {"batch":[...]}
//   - 含 \xNN 非标准转义的畸形 JSON
func Batch(r io.Reader) ([]fingerprint.Input, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	items, err := strict(data)
	if err == nil {
		return items, nil
	}

	if fixed := repairEscapes(data); !bytes.Equal(fixed, data) {
		if items, retryErr := strict(fixed); retryErr == nil {
			return items, nil
		}
	}

	return nil, err
}

func strict(data []byte) ([]fingerprint.Input, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, fmt.Errorf("empty body")
	}

	var items []fingerprint.Input
	arrayErr := json.Unmarshal(data, &items)
	if arrayErr == nil {
		if items == nil {
			items = []fingerprint.Input{}
		}
		return items, nil
	}

	var env envelope
	if err := json.Unmarshal(data, &env); err == nil {
		switch {
		case env.Items != nil:
			return env.Items, nil
		case env.Data != nil:
			return env.Data, nil
		case env.Batch != nil:
			return env.Batch, nil
		}
	}

	return nil, fmt.Errorf("invalid request body: %w", arrayErr)
}

// repairEscapes 把 \xNN 改写成合法转义 \u00NN（保持字节语义不变）。
func repairEscapes(data []byte) []byte {
	return xEscape.ReplaceAllFunc(data, func(m []byte) []byte {
		return []byte(`\u00` + string(m[2:]))
	})
}
