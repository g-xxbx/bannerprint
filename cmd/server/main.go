// Command server 提供 Banner 指纹识别 HTTP 服务。
//
// 子命令：
//
//	server healthcheck [-url ...]   容器健康检查（scratch 镜像内没有 shell/curl）
//	server version                  打印版本
//
// 主要参数：
//
//	-addr       监听地址，默认 :8080（也可用 FP_ADDR）
//	-rules      外部规则目录，覆盖内置规则（也可用 FP_RULES_DIR）
//	-list-rules 打印已加载规则后退出
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"bannerprint/internal/fingerprint"
	"bannerprint/internal/httpapi"
	"bannerprint/rules"
)

// version 由 -ldflags "-X main.version=..." 注入。
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			os.Exit(runHealthcheck(os.Args[2:]))
		case "version":
			fmt.Println(version)
			return
		}
	}

	addr := flag.String("addr", envOr("FP_ADDR", ":8080"), "listen address")
	rulesDir := flag.String("rules", os.Getenv("FP_RULES_DIR"), "external rules directory (overrides embedded rules)")
	listRules := flag.Bool("list-rules", false, "print loaded rules and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	logger := newLogger()

	engine, err := loadEngine(*rulesDir)
	if err != nil {
		logger.Error("load rules failed", "error", err)
		os.Exit(1)
	}

	if *listRules {
		for _, r := range engine.Rules() {
			fmt.Printf("%-20s %-8s %-16s priority=%-4d confidence=%.2f\n",
				r.ID, r.Protocol, r.Product, r.Priority, r.Confidence)
		}
		return
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           httpapi.New(httpapi.Options{Engine: engine, Logger: logger, Version: version}).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	logger.Info("server started", "addr", *addr, "version", version, "rules", engine.Len())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	case sig := <-sigCh:
		logger.Info("shutting down", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
		}
	}
}

// loadEngine 优先使用外部规则目录，否则使用 go:embed 的内置规则。
func loadEngine(dir string) (*fingerprint.Engine, error) {
	var fsys fs.FS = rules.FS
	root := rules.Dir
	if dir != "" {
		fsys = os.DirFS(dir)
		root = "."
	}

	loaded, err := fingerprint.LoadFS(fsys, root)
	if err != nil {
		return nil, err
	}
	return fingerprint.NewEngine(loaded)
}

// runHealthcheck 探测 /health，返回进程退出码（0=健康）。
func runHealthcheck(args []string) int {
	fset := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := fset.String("url", "http://127.0.0.1:8080/health", "health endpoint")
	timeout := fset.Duration("timeout", 2*time.Second, "request timeout")
	if err := fset.Parse(args); err != nil {
		return 2
	}

	client := &http.Client{Timeout: *timeout}
	resp, err := client.Get(*url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: unexpected status %d\n", resp.StatusCode)
		return 1
	}
	return 0
}

func newLogger() *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("FP_LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
