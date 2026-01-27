
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Load 从文件加载配置
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件: %w", err)
	}

	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件: %w", err)
	}

	// 设置默认值
	setDefaults(cfg)

	return cfg, nil
}

// setDefaults 设置配置默认值
func setDefaults(cfg *Config) {
	// FEC 默认值
	if cfg.FEC.Mode == "" {
		cfg.FEC.Mode = "adaptive"
	}
	if cfg.FEC.MinParity == 0 {
		cfg.FEC.MinParity = 1
	}
	if cfg.FEC.MaxParity == 0 {
		cfg.FEC.MaxParity = 8
	}
	if cfg.FEC.TargetLoss == 0 {
		cfg.FEC.TargetLoss = 0.01
	}
	if cfg.FEC.AdjustInterval == 0 {
		cfg.FEC.AdjustInterval = 5 * time.Second
	}

	// Mux 默认值
	if cfg.Mux.MaxStreams == 0 {
		cfg.Mux.MaxStreams = 256
	}
	if cfg.Mux.StreamBuffer == 0 {
		cfg.Mux.StreamBuffer = 65536
	}
	if cfg.Mux.KeepAliveInterval == 0 {
		cfg.Mux.KeepAliveInterval = 30 * time.Second
	}
	if cfg.Mux.IdleTimeout == 0 {
		cfg.Mux.IdleTimeout = 5 * time.Minute
	}

	// SOCKS5 默认值
	if cfg.Proxy.SOCKS5.UDPTimeout == 0 {
		cfg.Proxy.SOCKS5.UDPTimeout = 60
	}
}

// Save 保存配置到文件
func Save(cfg *Config, path string) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("序列化配置: %w", err)
	}

	// 添加注释头
	header := 
  `#═══════════════════════════════════════════════════════════════════
# Phantom Server v1.1 配置文件
# 战术级隐匿代理协议 - TSKD + Adaptive FEC + 多路复用
#═══════════════════════════════════════════════════════════════════

`
	data = append([]byte(header), data...)

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("写入配置文件: %w", err)
	}

	return nil
}

// Validate 验证配置有效性
func Validate(cfg *Config) error {
	// 验证认证配置
	if cfg.Auth.PSK == "" {
		return fmt.Errorf("auth.psk 是必需的")
	}
	if cfg.Auth.TimeWindow <= 0 || cfg.Auth.TimeWindow > 300 {
		return fmt.Errorf("auth.time_window 必须在 1-300 秒之间")
	}

	// 验证端口
	if cfg.Listen.TCPPort <= 0 || cfg.Listen.TCPPort > 65535 {
		return fmt.Errorf("无效的 tcp_port: %d", cfg.Listen.TCPPort)
	}
	if cfg.Listen.UDPPort <= 0 || cfg.Listen.UDPPort > 65535 {
		return fmt.Errorf("无效的 udp_port: %d", cfg.Listen.UDPPort)
	}

	// 验证 TLS 配置
	if cfg.TLS.Enabled {
		if cfg.TLS.CertFile == "" {
			return fmt.Errorf("启用 TLS 时 tls.cert_file 是必需的")
		}
		if cfg.TLS.KeyFile == "" {
			return fmt.Errorf("启用 TLS 时 tls.key_file 是必需的")
		}
		if _, err := os.Stat(cfg.TLS.CertFile); err != nil {
			return fmt.Errorf("证书文件不存在: %s", cfg.TLS.CertFile)
		}
		if _, err := os.Stat(cfg.TLS.KeyFile); err != nil {
			return fmt.Errorf("私钥文件不存在: %s", cfg.TLS.KeyFile)
		}
	}

	// 验证 FEC 配置
	if cfg.FEC.Enabled {
		if cfg.FEC.Mode != "static" && cfg.FEC.Mode != "adaptive" {
			return fmt.Errorf("fec.mode 必须是 'static' 或 'adaptive'")
		}
		if cfg.FEC.DataShards <= 0 || cfg.FEC.DataShards > 128 {
			return fmt.Errorf("fec.data_shards 必须在 1-128 之间")
		}
		if cfg.FEC.Mode == "static" {
			if cfg.FEC.FECShards <= 0 || cfg.FEC.FECShards > 128 {
				return fmt.Errorf("fec.fec_shards 必须在 1-128 之间")
			}
		} else {
			if cfg.FEC.MinParity <= 0 {
				return fmt.Errorf("fec.min_parity 必须大于 0")
			}
			if cfg.FEC.MaxParity < cfg.FEC.MinParity {
				return fmt.Errorf("fec.max_parity 必须大于等于 min_parity")
			}
			if cfg.FEC.TargetLoss <= 0 || cfg.FEC.TargetLoss >= 1 {
				return fmt.Errorf("fec.target_loss 必须在 0-1 之间")
			}
		}
		if cfg.FEC.DataShards+cfg.FEC.MaxParity > 256 {
			return fmt.Errorf("分片总数不能超过 256")
		}
	}

	// 验证多路复用配置
	if cfg.Mux.Enabled {
		if cfg.Mux.MaxStreams <= 0 || cfg.Mux.MaxStreams > 65535 {
			return fmt.Errorf("mux.max_streams 必须在 1-65535 之间")
		}
	}

	return nil
}


