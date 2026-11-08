package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Database struct {
		DSN string `json:"dsn"`
	} `json:"database"`
	SkillDir string `json:"skill_dir"`
	Server   struct {
		Addr string `json:"addr"`
		// AllowedOrigins 额外允许的跨域来源（如开发期前端跑在 http://localhost:3000）。
		// 空 = 只允许同源；生产嵌入模式无需配置。
		AllowedOrigins []string `json:"allowed_origins"`
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
		// IntentBudget 单任务最大意图数（0=不限）
		IntentBudget int `json:"intent_budget"`
		// TokenBudget 单任务最大 token 消耗（0=不限）
		TokenBudget int `json:"token_budget"`
		// MaxRounds 单条意图内 worker 最多 LLM 轮次
		MaxRounds int `json:"max_rounds"`
		// MaxRuntimeSec 单任务最长运行时长（秒，0=不限；默认 30 分钟）
		MaxRuntimeSec int `json:"max_runtime_sec"`
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
		// WebfetchTimeoutSec webfetch 单次请求超时（秒，默认 20）
		WebfetchTimeoutSec int `json:"webfetch_timeout_sec"`
	} `json:"tools"`
	// Notify 外部通知（新漏洞推送到 IM/Webhook）
	Notify struct {
		// WebhookURL 非空时，每产生一条新 finding 异步 POST 一次 JSON
		WebhookURL string `json:"webhook_url"`
	} `json:"notify"`
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
	c.Agent.IntentBudget = 15
	c.Agent.TokenBudget = 150000
	c.Agent.MaxRounds = 12
	c.Agent.MaxRuntimeSec = 1800 // 30 分钟：防工具/LLM 卡死导致任务无限运行
	c.LLM.Profile = "default-mock"
	c.Tools.BashTimeoutSec = 30
	c.Tools.WebfetchTimeoutSec = 20
	c.Log.File = "logs/pentigent.log"
	c.Log.MaxSizeMB = 32
	c.Log.MaxBackups = 5
	return c
}

// applyEnv 允许用环境变量覆盖配置，便于 Docker/CI 部署（无需改 config.json）。
func applyEnv(c *Config) {
	if v := os.Getenv("PENTIGENT_DSN"); v != "" {
		c.Database.DSN = v
	}
	if v := os.Getenv("PENTIGENT_ADDR"); v != "" {
		c.Server.Addr = v
	}
	if v := os.Getenv("PENTIGENT_JWT_SECRET"); v != "" {
		c.Auth.JWTSecret = v
	}
	if v := os.Getenv("PENTIGENT_AUTH_DISABLED"); v != "" {
		c.Auth.Disabled = v == "1" || v == "true" || v == "TRUE"
	}
	if v := os.Getenv("PENTIGENT_LLM_PROFILE"); v != "" {
		c.LLM.Profile = v
	}
	if v := os.Getenv("PENTIGENT_LOG_FILE"); v != "" {
		c.Log.File = v
	}
	if v := os.Getenv("PENTIGENT_ALLOWED_ORIGINS"); v != "" {
		for _, o := range strings.Split(v, ",") {
			if o = strings.TrimSpace(o); o != "" {
				c.Server.AllowedOrigins = append(c.Server.AllowedOrigins, o)
			}
		}
	}
	if v := os.Getenv("PENTIGENT_WEBHOOK_URL"); v != "" {
		c.Notify.WebhookURL = v
	}
	if v := os.Getenv("PENTIGENT_BASH_TIMEOUT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Tools.BashTimeoutSec = n
		}
	}
	if v := os.Getenv("PENTIGENT_WEBFETCH_TIMEOUT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Tools.WebfetchTimeoutSec = n
		}
	}
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
		applyEnv(c)
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
	applyEnv(c)
	return c, nil
}
