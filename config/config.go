package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	Database struct {
		DSN string `json:"dsn"`
	} `json:"database"`
	SkillDir string `json:"skill_dir"`
	Server   struct {
		Addr string `json:"addr"`
	} `json:"server"`
	Auth struct {
		JWTSecret string `json:"jwt_secret"`
		// Disabled 关闭认证（仅本地开发使用；关闭后任何能访问服务的人都能操纵工具）
		Disabled bool `json:"disabled"`
	} `json:"auth"`
	Agent struct {
		Workers  int `json:"workers"`
		Debounce int `json:"debounce_ms"`
		// MockWriteProbe 允许 mock LLM 对目标发写操作(POST)探测（默认关闭）
		MockWriteProbe bool `json:"mock_write_probe"`
	} `json:"agent"`
	LLM struct {
		Profile string `json:"profile"`
	} `json:"llm"`
	// Tools 工具执行行为
	Tools struct {
		// UserAgent 探测请求的 UA（空=用默认 pentigent-pentest/1.0）
		UserAgent string `json:"user_agent"`
		// BashTimeoutSec bash 单次执行超时（秒，默认 30）
		BashTimeoutSec int `json:"bash_timeout_sec"`
	} `json:"tools"`
	Log struct {
		// File 日志路径；空则只输出 stdout
		File string `json:"file"`
		// MaxSizeMB 单文件超过该大小即轮转
		MaxSizeMB int `json:"max_size_mb"`
		// MaxBackups 保留的历史文件数
		MaxBackups int `json:"max_backups"`
	} `json:"log"`
}

func Default() *Config {
	c := &Config{}
	c.Database.DSN = "postgres://postgres:postgres@127.0.0.1:5432/pentigent?sslmode=disable"
	c.SkillDir = "skills"
	c.Server.Addr = ":8080"
	c.Auth.JWTSecret = "dev-secret-change-me"
	c.Agent.Workers = 4
	c.Agent.Debounce = 500
	c.LLM.Profile = "default-mock"
	c.Log.File = "logs/pentigent.log"
	c.Log.MaxSizeMB = 32
	c.Log.MaxBackups = 5
	return c
}

func Load(path string) (*Config, error) {
	c := Default()
	if path == "" {
		// 尝试默认位置
		for _, p := range []string{"config.json", filepath.Join("..", "config.json")} {
			if _, err := os.Stat(p); err == nil {
				path = p
				break
			}
		}
	}
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	// Windows 编辑器（如记事本）保存 JSON 常带 UTF-8 BOM，会让 json.Unmarshal 失败
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return c, nil
}
