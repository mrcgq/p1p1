
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/anthropics/phantom-server/internal/logger"
)

var (
	Version   = "1.1.0"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func main() {
	// 设置最大 CPU 核心数
	runtime.GOMAXPROCS(runtime.NumCPU())

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "run":
		runCmd := flag.NewFlagSet("run", flag.ExitOnError)
		configPath := runCmd.String("c", "/etc/phantom/config.yaml", "配置文件路径")
		if err := runCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "解析参数错误: %v\n", err)
			os.Exit(1)
		}

		if err := runServer(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "错误: %v\n", err)
			os.Exit(1)
		}

	case "setup":
		setupCmd := flag.NewFlagSet("setup", flag.ExitOnError)
		opts := &SetupOptions{}
		setupCmd.StringVar(&opts.Domain, "domain", "", "域名 (必需)")
		setupCmd.StringVar(&opts.CFToken, "cf-token", "", "Cloudflare API Token (必需)")
		setupCmd.StringVar(&opts.CFZoneID, "cf-zone-id", "", "Cloudflare Zone ID (必需)")
		setupCmd.StringVar(&opts.Email, "email", "", "证书邮箱")
		setupCmd.IntVar(&opts.TCPPort, "tcp-port", 443, "TCP 端口")
		setupCmd.IntVar(&opts.UDPPort, "udp-port", 54321, "UDP 端口")

		if err := setupCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "解析参数错误: %v\n", err)
			os.Exit(1)
		}

		if err := runSetup(opts); err != nil {
			fmt.Fprintf(os.Stderr, "错误: %v\n", err)
			os.Exit(1)
		}

	case "version", "-v", "--version":
		printVersion()

	case "help", "-h", "--help":
		printUsage()

	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printVersion() {
	fmt.Printf(`Phantom Server v%s
  构建时间: %s
  Git 提交: %s
  Go 版本:  %s
  操作系统: %s/%s
`, Version, BuildTime, GitCommit, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func printUsage() {
	fmt.Print(`
╔═══════════════════════════════════════════════════════════════════════════╗
║                     Phantom Server v1.1                                   ║
║            下一代战术级隐匿代理协议                                        ║
╠═══════════════════════════════════════════════════════════════════════════╣
║                                                                           ║
║  特性:                                                                    ║
║    • TSKD 0-RTT 认证 - 首包即数据，无握手延迟                             ║
║    • Adaptive FEC - 智能动态冗余，对抗丢包                                ║
║    • 完整代理支持 - SOCKS5 (含 UDP) / HTTP                                ║
║    • 多路复用 - 单连接承载多流                                            ║
║    • 抗探测设计 - 无特征流量，静默丢弃                                    ║
║                                                                           ║
╠═══════════════════════════════════════════════════════════════════════════╣
║                                                                           ║
║  用法:                                                                    ║
║    phantom-server <命令> [选项]                                           ║
║                                                                           ║
║  命令:                                                                    ║
║    run       启动服务器                                                   ║
║    setup     初始化配置 (DNS + 证书 + 配置文件)                           ║
║    version   显示版本信息                                                 ║
║    help      显示帮助信息                                                 ║
║                                                                           ║
║  Run 选项:                                                                ║
║    -c <path>     配置文件路径 (默认: /etc/phantom/config.yaml)            ║
║                                                                           ║
║  Setup 选项:                                                              ║
║    --domain      域名 (必需)                                              ║
║    --cf-token    Cloudflare API Token (必需)                              ║
║    --cf-zone-id  Cloudflare Zone ID (必需)                                ║
║    --email       证书邮箱 (默认: admin@域名)                              ║
║    --tcp-port    TCP 端口 (默认: 443)                                     ║
║    --udp-port    UDP 端口 (默认: 54321)                                   ║
║                                                                           ║
║  示例:                                                                    ║
║    # 初始化配置                                                           ║
║    phantom-server setup --domain vpn.example.com \                        ║
║        --cf-token "your-token" --cf-zone-id "your-zone-id"                ║
║                                                                           ║
║    # 启动服务器                                                           ║
║    phantom-server run -c /etc/phantom/config.yaml                         ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
`)
}

// waitForShutdown 等待系统信号并触发优雅关闭
func waitForShutdown(cancel context.CancelFunc, log *logger.Logger) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	sig := <-sigCh
	log.Info("收到信号 %v，正在优雅关闭...", sig)
	cancel()
}
