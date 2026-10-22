package fingerprint

import (
	"fmt"
	"io/fs"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// ruleFile 是单个 YAML 文件的顶层结构。
type ruleFile struct {
	Version int    `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

// LoadFS 读取 dir 下所有 *.yaml 规则文件并合并。
// 规则缺失或解析失败都返回错误，由调用方决定是否终止启动。
func LoadFS(fsys fs.FS, dir string) ([]Rule, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("read rules dir %q: %w", dir, err)
	}

	var (
		out   []Rule
		files int
	)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		files++

		name := path.Join(dir, entry.Name())
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}

		var rf ruleFile
		if err := yaml.Unmarshal(data, &rf); err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		out = append(out, rf.Rules...)
	}

	if files == 0 {
		return nil, fmt.Errorf("no *.yaml rules found in %q", dir)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no rules defined in %q", dir)
	}
	return out, nil
}
