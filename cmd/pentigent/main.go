package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"pentigent/agent"
	"pentigent/config"
	"pentigent/db"
	"pentigent/logging"
	"pentigent/server"
	"pentigent/webui"
)

// parseArgs 支持：pentigent [config.json] [-reset-admin]
func parseArgs(args []string) (configPath string, resetAdmin bool) {
	for _, a := range args {
		if a == "-reset-admin" {
			resetAdmin = true
			continue
		}
		if configPath == "" {
			configPath = a
		}
	}
	return
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("AI 渗透测试系统 · MVP 启动")

	cfgPath, resetAdmin := parseArgs(os.Args[1:])
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	// 安全护栏：启用鉴权却用默认 secret = 任何人都能伪造 token。
	if !cfg.Auth.Disabled && (cfg.Auth.JWTSecret == "" || cfg.Auth.JWTSecret == "dev-secret-change-me" || strings.Contains(cfg.Auth.JWTSecret, "change-me")) {
		log.Fatalf("安全错误：auth 已启用，但 jwt_secret 为空或仍是默认/示例值，请先设置强随机 secret")
	}
	if cfg.Auth.Disabled {
		log.Println("警告：auth.disabled=true，任何能访问端口的人都能操纵工具，仅限本地开发")
	}

	// 日志落文件（stdout + 按大小轮转）
	// 日志落文件（stdout + 按大小轮转）；closeLog 释放文件句柄
	closeLog := logging.Setup(cfg.Log.File, cfg.Log.MaxSizeMB, cfg.Log.MaxBackups)
	defer closeLog()
	log.Println("AI 渗透测试系统 · MVP 启动")

	// 数据库
	database, err := db.Open(context.Background(), cfg.Database.DSN)
	if err != nil {
		log.Fatalf("连接数据库失败: %v", err)
	}
	defer database.Close()
	if err := database.Migrate(context.Background()); err != nil {
		log.Fatalf("执行迁移失败: %v", err)
	}
	log.Println("数据库就绪")

	// -reset-admin：删除管理员密码哈希，下次访问 /login 可重新初始化。
	if resetAdmin {
		if _, err := database.Pool().Exec(context.Background(), `DELETE FROM settings WHERE key='admin'`); err != nil {
			log.Fatalf("重置管理员密码失败: %v", err)
		}
		log.Println("管理员密码已重置，请重新访问 /login 初始化")
		return
	}

	// LLM provider：按配置选择 mock 或真实 OpenAI
	switch cfg.LLM.Profile {
	case "default-off", "default-mock", "", "mock":
		mock := agent.NewMockProvider()
		mock.SetAllowWriteProbe(cfg.Agent.MockWriteProbe)
		agent.SetCurrentProvider(mock)
		log.Printf("LLM: mock 模式（无 key 闭环演示，写操作探测=%v）", cfg.Agent.MockWriteProbe)
	default:
		prov := agent.NewOpenAIProvider(cfg.LLM.Profile, "", "")
		if !prov.HasKey() {
			log.Fatalf("LLM profile %q 需要 OPENAI_API_KEY 环境变量；无 key 请配置 llm.profile=default-mock", cfg.LLM.Profile)
		}
		agent.SetCurrentProvider(prov)
		log.Printf("LLM: %s（OpenAI 兼容，model=%s）", prov.Name(), prov.Model())
	}

	// 工具执行配置
	if cfg.Tools.UserAgent != "" {
		agent.SetUserAgent(cfg.Tools.UserAgent)
	}
	if cfg.Tools.BashTimeoutSec > 0 {
		agent.SetBashTimeoutSeconds(cfg.Tools.BashTimeoutSec)
	}
	if cfg.Tools.WebfetchTimeoutSec > 0 {
		agent.SetWebfetchTimeoutSeconds(cfg.Tools.WebfetchTimeoutSec)
	}

	// 新漏洞 Webhook 推送（异步，失败只记日志，不影响任务）
	if cfg.Notify.WebhookURL != "" {
		webhookURL := cfg.Notify.WebhookURL
		agent.SetFindingHook(func(f agent.Finding) {
			go func() {
				payload, _ := json.Marshal(map[string]any{"event": "finding", "finding": f})
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, strings.NewReader(string(payload)))
				if err != nil {
					log.Printf("webhook: 构造请求失败: %v", err)
					return
				}
				req.Header.Set("Content-Type", "application/json")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					log.Printf("webhook: 推送失败: %v", err)
					return
				}
				defer resp.Body.Close()
				_, _ = io.Copy(io.Discard, resp.Body)
				if resp.StatusCode >= 300 {
					log.Printf("webhook: 上游返回 %d", resp.StatusCode)
				}
			}()
		})
		log.Printf("Webhook: 新漏洞将推送到 %s", webhookURL)
	}

	// HTTP 服务
	srv := server.NewServer(cfg, database)
	srv.SetStatic(webui.Handler())
	httpSrv := &http.Server{
		Addr:    cfg.Server.Addr,
		Handler: srv.Handler(),
	}

	// 优雅关闭：先停止接收新请求，再等运行中的任务收敛
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		log.Println("收到退出信号，优雅关闭...")
		// 1) 停止 HTTP 服务，不再接收新请求
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = httpSrv.Shutdown(ctx)
		cancel()
		// 2) 等待运行中的任务自然收敛（给 worker 完成当前工具调用的时间）
		if n := srv.Engine().RunningCount(); n > 0 {
			log.Printf("等待 %d 个运行中任务收敛...", n)
			if left := srv.Engine().WaitAllIdle(30 * time.Second); left > 0 {
				log.Printf("仍有 %d 个任务未收敛，标记为 stopped（下次启动可断点续跑）", left)
				srv.Engine().StopAll()
			}
		}
		log.Println("已退出")
	}()

	log.Printf("HTTP 监听 %s（API: /api/*）", cfg.Server.Addr)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP 服务失败: %v", err)
	}
}
