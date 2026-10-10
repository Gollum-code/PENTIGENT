package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"artex/agent"
	"artex/config"
	"artex/db"
	"artex/logging"
	"artex/server"
	"artex/webui"
)

func configPath() string {
	if len(os.Args) > 1 {
		return os.Args[1]
	}
	return ""
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("AI 渗透测试系统 · MVP 启动")

	cfg, err := config.Load(configPath())
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	// 日志落文件（stdout + 按大小轮转）
	logging.Setup(cfg.Log.File, cfg.Log.MaxSizeMB, cfg.Log.MaxBackups)
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

	// LLM provider：按配置选择 mock 或真实 OpenAI
	switch cfg.LLM.Profile {
	case "default-off", "default-mock", "", "mock":
		agent.SetCurrentProvider(agent.NewMockProvider())
		log.Println("LLM: mock 模式（无 key 闭环演示）")
	default:
		prov := agent.NewOpenAIProvider(cfg.LLM.Profile, "", "")
		if !prov.HasKey() {
			log.Fatalf("LLM profile %q 需要 OPENAI_API_KEY 环境变量；无 key 请配置 llm.profile=default-mock", cfg.LLM.Profile)
		}
		agent.SetCurrentProvider(prov)
		log.Printf("LLM: %s（OpenAI 兼容，model=%s）", prov.Name(), prov.Model())
	}

	// HTTP 服务
	srv := server.NewServer(cfg, database)
	srv.SetStatic(webui.Handler())
	httpSrv := &http.Server{
		Addr:    cfg.Server.Addr,
		Handler: srv.Handler(),
	}

	// 优雅关闭
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		log.Println("收到退出信号，优雅关闭...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}()

	log.Printf("HTTP 监听 %s（API: /api/*）", cfg.Server.Addr)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP 服务失败: %v", err)
	}
	log.Println("已退出")
}