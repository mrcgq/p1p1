package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/anthropics/phantom-server/internal/config"
	"github.com/anthropics/phantom-server/internal/fec"
	"github.com/anthropics/phantom-server/internal/logger"
	"github.com/anthropics/phantom-server/internal/metrics"
	"github.com/anthropics/phantom-server/internal/protocol"
)

// UDPServer UDP 服务器
type UDPServer struct {
	config  *config.Config
	handler *protocol.Handler
	fec     *fec.FECEncoder
	log     *logger.Logger
	metrics *metrics.Collector

	conn     *net.UDPConn
	collector *fec.ShardCollector

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewUDPServer 创建新的 UDP 服务器
func NewUDPServer(cfg *config.Config, handler *protocol.Handler, fecEncoder *fec.FECEncoder, log *logger.Logger, m *metrics.Collector) *UDPServer {
	s := &UDPServer{
		config:  cfg,
		handler: handler,
		fec:     fecEncoder,
		log:     log,
		metrics: m,
		stopCh:  make(chan struct{}),
	}

	// 创建 FEC 分片收集器
	if fecEncoder != nil {
		s.collector = fec.NewShardCollector(5 * time.Second)
	}

	return s
}

// Start 启动 UDP 服务器
func (s *UDPServer) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.config.Listen.Address, s.config.Listen.UDPPort)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("解析 UDP 地址: %w", err)
	}

	s.conn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("监听 UDP: %w", err)
	}

	s.log.Info("UDP 服务器已启动: %s", addr)

	// 设置读缓冲区
	s.conn.SetReadBuffer(4 * 1024 * 1024) // 4MB
	s.conn.SetWriteBuffer(4 * 1024 * 1024)

	// 启动清理协程
	if s.collector != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.cleanupLoop()
		}()
	}

	// 启动多个工作协程
	workerCount := 4
	for i := 0; i < workerCount; i++ {
		s.wg.Add(1)
		go func(id int) {
			defer s.wg.Done()
			s.readLoop(ctx, id)
		}(i)
	}

	return nil
}

// readLoop 读取循环
func (s *UDPServer) readLoop(ctx context.Context, workerID int) {
	buf := make([]byte, 65535)

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		default:
		}

		// 设置读取超时
		s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		n, remoteAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-s.stopCh:
				return
			default:
				s.log.Debug("UDP 读取错误: %v", err)
				continue
			}
		}

		if n == 0 {
			continue
		}

		// 复制数据进行处理
		data := make([]byte, n)
		copy(data, buf[:n])

		// 异步处理数据包
		go s.handlePacket(ctx, data, remoteAddr)
	}
}

// handlePacket 处理单个数据包
func (s *UDPServer) handlePacket(ctx context.Context, data []byte, from *net.UDPAddr) {
	var plainData []byte
	var err error

	// 如果启用 FEC，尝试从分片重建
	if s.fec != nil && s.collector != nil && len(data) > fec.ShardHeaderSize {
		// 尝试解析为 FEC 分片
		plainData, err = s.collector.AddShard(data)
		if err != nil {
			// 不是 FEC 分片，直接处理
			plainData = data
		} else if plainData == nil {
			// 需要更多分片，等待
			return
		} else {
			// FEC 重建成功
			s.metrics.FECRecovered()
		}
	} else {
		plainData = data
	}

	// 处理数据包
	response, err := s.handler.HandlePacket(ctx, plainData, from)
	if err != nil {
		// 静默丢弃无效数据包（抗探测）
		s.log.Debug("处理数据包失败: %v", err)
		return
	}

	if response != nil {
		s.sendResponse(response, from)
	}
}

// sendResponse 发送响应
func (s *UDPServer) sendResponse(data []byte, to *net.UDPAddr) {
	// 如果启用 FEC，将响应编码为分片
	if s.fec != nil {
		shards, err := s.fec.Encode(data)
		if err != nil {
			s.log.Debug("FEC 编码失败: %v", err)
			// 回退到直接发送
			s.conn.WriteToUDP(data, to)
			return
		}

		// 发送所有分片
		for _, shard := range shards {
			s.conn.WriteToUDP(shard, to)
		}
	} else {
		s.conn.WriteToUDP(data, to)
	}
}

// cleanupLoop FEC 分片清理循环
func (s *UDPServer) cleanupLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if s.collector != nil {
				s.collector.Cleanup()
			}
		case <-s.stopCh:
			return
		}
	}
}

// Stop 停止 UDP 服务器
func (s *UDPServer) Stop() {
	close(s.stopCh)
	if s.conn != nil {
		s.conn.Close()
	}
	s.wg.Wait()
	s.log.Info("UDP 服务器已停止")
}

// Stats 返回统计信息
func (s *UDPServer) Stats() map[string]interface{} {
	stats := make(map[string]interface{})
	if s.collector != nil {
		collectorStats := s.collector.Stats()
		stats["fec_pending_groups"] = collectorStats.PendingGroups
		stats["fec_completed_groups"] = collectorStats.CompletedGroups
		stats["fec_failed_groups"] = collectorStats.FailedGroups
	}
	return stats
}
