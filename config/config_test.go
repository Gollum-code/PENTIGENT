package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	c := Default()
	if c.Server.Addr == "" || c.Database.DSN == "" {
		t.Errorf("默认值不应为空: addr=%q dsn=%q", c.Server.Addr, c.Database.DSN)
	}
	if c.Agent.Workers <= 0 {
		t.Errorf("workers 应为正数: %d", c.Agent.Workers)
	}
	if c.Log.File == "" || c.Log.MaxSizeMB <= 0 {
		t.Errorf("日志默认配置异常: file=%q max=%d", c.Log.File, c.Log.MaxSizeMB)
	}
}

func TestLoadOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{
  "database": {"dsn": "postgres://u:p@host:5432/db"},
  "server": {"addr": ":9999"},
  "agent": {"workers": 8, "mock_write_probe": true},
  "auth": {"disabled": true},
  "llm": {"profile": "openai"}
}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Addr != ":9999" {
		t.Errorf("addr 未生效: %s", c.Server.Addr)
	}
	if c.Agent.Workers != 8 {
		t.Errorf("workers 未生效: %d", c.Agent.Workers)
	}
	if !c.Agent.MockWriteProbe {
		t.Error("mock_write_probe 未生效")
	}
	if !c.Auth.Disabled {
		t.Error("auth.disabled 未生效")
	}
	if c.Database.DSN != "postgres://u:p@host:5432/db" {
		t.Errorf("dsn 未生效: %s", c.Database.DSN)
	}
	// 未覆盖的字段应保留默认值
	if c.Log.MaxSizeMB != Default().Log.MaxSizeMB {
		t.Errorf("未覆盖字段应保持默认: %d", c.Log.MaxSizeMB)
	}
}

// BOM 是本轮修复的真实 bug：Windows 编辑器保存会带 BOM，
// 修复前 json.Unmarshal 直接失败导致服务起不来。
func TestLoadTolerantOfBOM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bom.json")
	withBOM := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"server":{"addr":":7777"}}`)...)
	if err := os.WriteFile(path, withBOM, 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("带 BOM 的配置应能解析: %v", err)
	}
	if c.Server.Addr != ":7777" {
		t.Errorf("BOM 配置解析后值错误: %q", c.Server.Addr)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Error("读取不存在的文件应报错")
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(path, []byte(`{invalid json`), 0o644)
	if _, err := Load(path); err == nil {
		t.Error("非法 JSON 应报错")
	}
}