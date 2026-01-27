
package config

import (
	"time"
)

// Config 服务器主配置结构
type Config struct {
	Listen ListenConfig `yaml:"listen"`
	Auth   AuthConfig   `yaml:"auth"`
	TLS    TLSConfig    `yaml:"tls"`
	FEC    FECConfig    `yaml:"fec"`
	Mux    MuxConfig    `yaml:"mux"`
	Proxy  ProxyConfig  `yaml:"proxy"`
	Log    LogConfig    `yaml:"log"`
}

// ListenConfig 监听地址配置
type ListenConfig struct {
	Address string `yaml:"address"` // 监听地址
	TCPPort int    `yaml:"tcp_port"` // TCP 端口
	UDPPort int    `yaml:"udp_port"` // UDP 端口
}

// AuthConfig 认证配置
type AuthConfig struct {
	PSK        string `yaml:"psk"`         // 预共享密钥 (Base64)
	TimeWindow int    `yaml:"time_window"` // TSKD 时间窗口 (秒)
}

// TLSConfig TLS 配置
type TLSConfig struct {
	Enabled    bool   `yaml:"enabled"`     // 是否启用 TLS
	CertFile   string `yaml:"cert_file"`   // 证书文件路径
	KeyFile    string `yaml:"key_file"`    // 私钥文件路径
	ServerName string `yaml:"server_name"` // SNI 服务器名称
}

// FECConfig 前向纠错配置
type FECConfig struct {
	Enabled    bool   `yaml:"enabled"`     // 是否启用 FEC
	Mode       string `yaml:"mode"`        // 模式: static | adaptive
	DataShards int    `yaml:"data_shards"` // 数据分片数
	FECShards  int    `yaml:"fec_shards"`  // 冗余分片数 (static 模式)
	
	// Adaptive 模式参数
	MinParity       int           `yaml:"min_parity"`       // 最小冗余分片
	MaxParity       int           `yaml:"max_parity"`       // 最大冗余分片
	TargetLoss      float64       `yaml:"target_loss"`      // 目标丢包恢复率
	AdjustInterval  time.Duration `yaml:"adjust_interval"`  // 调整间隔
}

// MuxConfig 多路复用配置
type MuxConfig struct {
	Enabled          bool          `yaml:"enabled"`           // 是否启用多路复用
	MaxStreams       int           `yaml:"max_streams"`       // 单连接最大流数
	StreamBuffer     int           `yaml:"stream_buffer"`     // 流缓冲区大小
	KeepAliveInterval time.Duration `yaml:"keepalive_interval"` // 心跳间隔
	IdleTimeout      time.Duration `yaml:"idle_timeout"`      // 空闲超时
}

// ProxyConfig 代理配置
type ProxyConfig struct {
	SOCKS5 SOCKS5Config `yaml:"socks5"`
	HTTP   HTTPConfig   `yaml:"http"`
}

// SOCKS5Config SOCKS5 代理配置
type SOCKS5Config struct {
	Enabled    bool `yaml:"enabled"`     // 是否启用
	UDPEnabled bool `yaml:"udp_enabled"` // 是否启用 UDP ASSOCIATE
	UDPTimeout int  `yaml:"udp_timeout"` // UDP 会话超时 (秒)
}

// HTTPConfig HTTP 代理配置
type HTTPConfig struct {
	Enabled bool `yaml:"enabled"` // 是否启用
}

// LogConfig 日志配置
type LogConfig struct {
	Level string `yaml:"level"` // 日志级别: debug, info, warn, error
	File  string `yaml:"file"`  // 日志文件路径 (空则输出到 stdout)
}

// Default 返回默认配置
func Default() *Config {
	return &Config{
		Listen: ListenConfig{
			Address: "0.0.0.0",
			TCPPort: 443,
			UDPPort: 54321,
		},
		Auth: AuthConfig{
			TimeWindow: 30,
		},
		TLS: TLSConfig{
			Enabled: true,
		},
		FEC: FECConfig{
			Enabled:        true,
			Mode:           "adaptive",
			DataShards:     10,
			FECShards:      3,
			MinParity:      1,
			MaxParity:      8,
			TargetLoss:     0.01, // 1% 目标丢包率
			AdjustInterval: 5 * time.Second,
		},
		Mux: MuxConfig{
			Enabled:           true,
			MaxStreams:        256,
			StreamBuffer:      65536,
			KeepAliveInterval: 30 * time.Second,
			IdleTimeout:       5 * time.Minute,
		},
		Proxy: ProxyConfig{
			SOCKS5: SOCKS5Config{
				Enabled:    true,
				UDPEnabled: true,
				UDPTimeout: 60,
			},
			HTTP: HTTPConfig{
				Enabled: true,
			},
		},
		Log: LogConfig{
			Level: "info",
		},
	}
}


