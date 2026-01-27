
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/anthropics/phantom-server/internal/config"
	"github.com/anthropics/phantom-server/internal/logger"
	"github.com/anthropics/phantom-server/internal/metrics"
	"github.com/anthropics/phantom-server/internal/server"
	"github.com/anthropics/phantom-server/internal/setup"
)

// SetupOptions 安装向导选项
type SetupOptions struct {
	Domain   string
	CFToken  string
	CFZoneID string
	Email    string
	TCPPort  int
	UDPPort  int
}

// runServer 启动服务器
func runServer(configPath string) error {
	// 加载配置
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("加载配置失败: %w", err)
	}

	// 验证配置
	if err := config.Validate(cfg); err != nil {
		return fmt.Errorf("配置无效: %w", err)
	}

	// 初始化日志
	log, err := logger.New(cfg.Log.Level, cfg.Log.File)
	if err != nil {
		return fmt.Errorf("初始化日志失败: %w", err)
	}
	defer log.Close()

	// 打印启动横幅
	printStartupBanner(log, cfg)

	// 初始化指标收集器
	metricsCollector := metrics.New()

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建服务器
	srv, err := server.New(cfg, log, metricsCollector)
	if err != nil {
		return fmt.Errorf("创建服务器失败: %w", err)
	}

	// 后台启动服务器
	errCh := make(chan error, 1)
	go func() {
		if err := srv.Start(ctx); err != nil {
			errCh <- err
		}
	}()

	// 等待启动完成
	time.Sleep(100 * time.Millisecond)

	log.Info("════════════════════════════════════════════════════════════════")
	log.Info("服务器已成功启动")
	log.Info("════════════════════════════════════════════════════════════════")

	// 启动指标打印（调试模式）
	if cfg.Log.Level == "debug" {
		go printMetricsPeriodically(ctx, log, metricsCollector)
	}

	// 等待关闭信号
	go waitForShutdown(cancel, log)

	// 等待错误或上下文取消
	select {
	case err := <-errCh:
		log.Error("服务器错误: %v", err)
		return err
	case <-ctx.Done():
	}

	// 优雅关闭
	log.Info("正在关闭服务器...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	srv.Shutdown(shutdownCtx)
	log.Info("服务器已停止")

	return nil
}

// printStartupBanner 打印启动横幅
func printStartupBanner(log *logger.Logger, cfg *config.Config) {
	log.Info("╔═══════════════════════════════════════════════════════════════╗")
	log.Info("║              Phantom Server v%s                            ║", Version)
	log.Info("║          战术级隐匿代理协议 - 快・稳・隐                      ║")
	log.Info("╚═══════════════════════════════════════════════════════════════╝")
	log.Info("")
	log.Info("┌─ 监听配置 ─────────────────────────────────────────────────────")
	log.Info("│  UDP: %s:%d", cfg.Listen.Address, cfg.Listen.UDPPort)
	log.Info("│  TCP: %s:%d (TLS: %v)", cfg.Listen.Address, cfg.Listen.TCPPort, cfg.TLS.Enabled)
	log.Info("│")
	log.Info("├─ FEC 配置 ─────────────────────────────────────────────────────")
	log.Info("│  启用: %v", cfg.FEC.Enabled)
	if cfg.FEC.Enabled {
		log.Info("│  模式: %s", cfg.FEC.Mode)
		log.Info("│  初始: %d 数据分片 + %d 冗余分片", cfg.FEC.DataShards, cfg.FEC.FECShards)
		if cfg.FEC.Mode == "adaptive" {
			log.Info("│  自适应范围: %d-%d 冗余分片", cfg.FEC.MinParity, cfg.FEC.MaxParity)
		}
	}
	log.Info("│")
	log.Info("├─ 多路复用 ────────────────────────────────────────────────────")
	log.Info("│  启用: %v", cfg.Mux.Enabled)
	if cfg.Mux.Enabled {
		log.Info("│  最大流数: %d", cfg.Mux.MaxStreams)
	}
	log.Info("│")
	log.Info("└─ 代理配置 ────────────────────────────────────────────────────")
	log.Info("   SOCKS5: %v (UDP: %v)", cfg.Proxy.SOCKS5.Enabled, cfg.Proxy.SOCKS5.UDPEnabled)
	log.Info("   HTTP:   %v", cfg.Proxy.HTTP.Enabled)
	log.Info("")
}

// printMetricsPeriodically 定期打印指标
func printMetricsPeriodically(ctx context.Context, log *logger.Logger, m *metrics.Collector) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			stats := m.Snapshot()
			log.Debug("═══ 运行指标 ═══════════════════════════════════════")
			log.Debug("  活动会话: %d | 活动流: %d", stats.ActiveSessions, stats.ActiveStreams)
			log.Debug("  发送: %s | 接收: %s", formatBytes(stats.BytesSent), formatBytes(stats.BytesRecv))
			log.Debug("  丢包率: %.2f%% | RTT: %dms", stats.PacketLoss*100, stats.RTT.Milliseconds())
			log.Debug("  FEC 冗余: %d | FEC 恢复: %d", stats.CurrentParity, stats.FECRecovered)
			log.Debug("═══════════════════════════════════════════════════")
		case <-ctx.Done():
			return
		}
	}
}

// formatBytes 格式化字节数
func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// runSetup 执行安装向导
func runSetup(opts *SetupOptions) error {
	// 验证必需参数
	if opts.Domain == "" {
		return fmt.Errorf("--domain 是必需的")
	}
	if opts.CFToken == "" {
		return fmt.Errorf("--cf-token 是必需的")
	}
	if opts.CFZoneID == "" {
		return fmt.Errorf("--cf-zone-id 是必需的")
	}

	// 默认邮箱
	if opts.Email == "" {
		opts.Email = "admin@" + opts.Domain
	}

	// 创建安装实例
	s := setup.New(&setup.Options{
		Domain:   opts.Domain,
		CFToken:  opts.CFToken,
		CFZoneID: opts.CFZoneID,
		Email:    opts.Email,
		TCPPort:  opts.TCPPort,
		UDPPort:  opts.UDPPort,
	})

	// 执行安装
	result, err := s.Run()
	if err != nil {
		return err
	}

	// 打印结果
	printSetupResult(result)

	return nil
}

// printSetupResult 打印安装结果
func printSetupResult(result *setup.Result) {
	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║              Phantom Server v1.1 安装完成！                        ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("┌─────────────────────────────────────────────────────────────────────┐")
	fmt.Printf("│  域名:       %-54s │\n", result.Domain)
	fmt.Printf("│  服务器IP:   %-54s │\n", result.ServerIP)
	fmt.Printf("│  TCP端口:    %-54d │\n", result.TCPPort)
	fmt.Printf("│  UDP端口:    %-54d │\n", result.UDPPort)
	fmt.Println("├─────────────────────────────────────────────────────────────────────┤")
	fmt.Printf("│  PSK:        %-54s │\n", result.PSK)
	fmt.Println("├─────────────────────────────────────────────────────────────────────┤")
	fmt.Println("│  功能状态:                                                          │")
	fmt.Println("│    ✓ TSKD 0-RTT 认证                                               │")
	fmt.Println("│    ✓ Adaptive FEC (动态冗余)                                       │")
	fmt.Println("│    ✓ SOCKS5 代理 (含 UDP ASSOCIATE)                                │")
	fmt.Println("│    ✓ HTTP 代理                                                     │")
	fmt.Println("│    ✓ 多路复用                                                      │")
	fmt.Println("└─────────────────────────────────────────────────────────────────────┘")
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════════════")
	fmt.Println("客户端分享链接:")
	fmt.Println()
	fmt.Println(result.ShareLink)
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println("管理命令:")
	fmt.Println("  启动服务:  systemctl start phantom")
	fmt.Println("  停止服务:  systemctl stop phantom")
	fmt.Println("  重启服务:  systemctl restart phantom")
	fmt.Println("  查看日志:  journalctl -u phantom -f")
	fmt.Println()
}

