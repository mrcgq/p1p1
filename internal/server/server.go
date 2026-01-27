
package server

import (
	"context"
	"sync"
	"time"

	"github.com/anthropics/phantom-server/internal/config"
	"github.com/anthropics/phantom-server/internal/crypto"
	"github.com/anthropics/phantom-server/internal/fec"
	"github.com/anthropics/phantom-server/internal/logger"
	"github.com/anthropics/phantom-server/internal/metrics"
	"github.com/anthropics/phantom-server/internal/protocol"
)

// Server 是主 Phantom 服务器
type Server struct {
	config  *config.Config
	handler *protocol.Handler
	fec     *fec.FECEncoder
	log     *logger.Logger
	metrics *metrics.Collector

	udpServer *UDPServer
	tcpServer *TCPServer

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// New 创建新的服务器实例
func New(cfg *config.Config, log *logger.Logger, m *metrics.Collector) (*Server, error) {
	// 解码 PSK
	psk, err := crypto.DecodePSK(cfg.Auth.PSK)
	if err != nil {
		return nil, err
	}

	// 创建协议处理器
	handlerConfig := protocol.HandlerConfig{
		PSK:        psk,
		TimeWindow: cfg.Auth.TimeWindow,
		MuxEnabled: cfg.Mux.Enabled,
		MuxConfig: protocol.MuxConfig{
			MaxStreams:        cfg.Mux.MaxStreams,
			StreamBufferSize:  cfg.Mux.StreamBuffer,
			KeepAliveInterval: cfg.Mux.KeepAliveInterval,
			IdleTimeout:       cfg.Mux.IdleTimeout,
		},
	}
	handler := protocol.NewHandler(handlerConfig, log, m)

	// 创建 FEC 编码器
	var fecEncoder *fec.FECEncoder
	if cfg.FEC.Enabled {
		if cfg.FEC.Mode == "adaptive" {
			adaptiveConfig := fec.AdaptiveConfig{
				DataShards:        cfg.FEC.DataShards,
				MinParity:         cfg.FEC.MinParity,
				MaxParity:         cfg.FEC.MaxParity,
				InitialParity:     cfg.FEC.FECShards,
				TargetLossRate:    cfg.FEC.TargetLoss,
				AdjustInterval:    cfg.FEC.AdjustInterval,
				IncreaseThreshold: 0.05,
				DecreaseThreshold: 0.01,
				StepUp:            1,
				StepDown:          1,
			}
			fecEncoder, err = fec.NewAdaptiveFECEncoder(adaptiveConfig)
			if err != nil {
				return nil, err
			}
			log.Info("Adaptive FEC 已启用: %d 数据分片, %d-%d 冗余分片",
				cfg.FEC.DataShards, cfg.FEC.MinParity, cfg.FEC.MaxParity)
		} else {
			fecEncoder, err = fec.NewFECEncoder(cfg.FEC.DataShards, cfg.FEC.FECShards)
			if err != nil {
				return nil, err
			}
			log.Info("Static FEC 已启用: %d 数据分片 + %d 冗余分片",
				cfg.FEC.DataShards, cfg.FEC.FECShards)
		}
	}

	return &Server{
		config:  cfg,
		handler: handler,
		fec:     fecEncoder,
		log:     log,
		metrics: m,
		stopCh:  make(chan struct{}),
	}, nil
}

// Start 启动所有服务器组件
func (s *Server) Start(ctx context.Context) error {
	// 启动 FEC 自适应调整
	if s.fec != nil && s.fec.IsAdaptive() {
		s.fec.Start(ctx)
	}

	// 启动会话清理器
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.handler.GetSessionManager().StartCleaner(s.stopCh)
	}()

	// 启动重放过滤器清理器
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.cleanupLoop()
	}()

	// 启动 UDP 服务器
	s.udpServer = NewUDPServer(s.config, s.handler, s.fec, s.log, s.metrics)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.udpServer.Start(ctx); err != nil {
			s.log.Error("UDP 服务器错误: %v", err)
		}
	}()

	// 启动 TCP 服务器
	s.tcpServer = NewTCPServer(s.config, s.handler, s.log, s.metrics)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.tcpServer.Start(ctx); err != nil {
			s.log.Error("TCP 服务器错误: %v", err)
		}
	}()

	// 启动指标更新
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.updateMetrics()
	}()

	return nil
}

// Stop 停止所有服务器组件
func (s *Server) Stop() {
	close(s.stopCh)

	if s.udpServer != nil {
		s.udpServer.Stop()
	}
	if s.tcpServer != nil {
		s.tcpServer.Stop()
	}

	s.wg.Wait()
	s.log.Info("所有服务器组件已停止")
}

// Shutdown 优雅关闭
func (s *Server) Shutdown(ctx context.Context) {
	// 停止接受新连接
	if s.udpServer != nil {
		s.udpServer.Stop()
	}
	if s.tcpServer != nil {
		s.tcpServer.Stop()
	}

	// 等待现有连接处理完成或超时
	done := make(chan struct{})
	go func() {
		s.handler.GetSessionManager().CloseAll()
		close(done)
	}()

	select {
	case <-done:
		s.log.Info("所有会话已优雅关闭")
	case <-ctx.Done():
		s.log.Warn("关闭超时，强制终止")
	}

	close(s.stopCh)
	s.wg.Wait()
}

// cleanupLoop 清理循环
func (s *Server) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.handler.CleanupReplayFilters()
		case <-s.stopCh:
			return
		}
	}
}

// updateMetrics 更新 FEC 相关指标
func (s *Server) updateMetrics() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if s.fec != nil {
				s.metrics.SetCurrentParity(int32(s.fec.GetCurrentParity()))
			}
		case <-s.stopCh:
			return
		}
	}
}

// Stats 返回服务器统计信息
func (s *Server) Stats() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["active_sessions"] = s.handler.GetSessionManager().Count()
	stats["metrics"] = s.metrics.Snapshot()

	if s.fec != nil {
		stats["fec_parity"] = s.fec.GetCurrentParity()
		stats["fec_data_shards"] = s.fec.GetDataShards()
	}

	return stats
}


