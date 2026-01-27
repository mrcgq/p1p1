
package protocol

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrMuxClosed      = errors.New("多路复用器已关闭")
	ErrMaxStreams     = errors.New("已达到最大流数")
	ErrStreamNotFound = errors.New("流未找到")
	ErrInvalidStream  = errors.New("无效的流 ID")
)

// Mux 多路复用器
type Mux struct {
	sessionID uint32
	config    MuxConfig

	streams     sync.Map // map[uint32]*Stream
	streamCount atomic.Int32
	nextID      atomic.Uint32

	closed atomic.Bool

	// 回调
	onNewStream func(*Stream)

	// 心跳
	lastPing  time.Time
	lastPong  time.Time
	pingTimer *time.Timer

	mu sync.RWMutex
}

// MuxConfig 多路复用配置
type MuxConfig struct {
	MaxStreams        int
	StreamBufferSize  int
	KeepAliveInterval time.Duration
	IdleTimeout       time.Duration
	MaxWindow         int32
}

// DefaultMuxConfig 默认配置
func DefaultMuxConfig() MuxConfig {
	return MuxConfig{
		MaxStreams:        256,
		StreamBufferSize:  65536,
		KeepAliveInterval: 30 * time.Second,
		IdleTimeout:       5 * time.Minute,
		MaxWindow:         65536,
	}
}

// NewMux 创建新的多路复用器
func NewMux(sessionID uint32, config MuxConfig) *Mux {
	return &Mux{
		sessionID: sessionID,
		config:    config,
		lastPing:  time.Now(),
		lastPong:  time.Now(),
	}
}

// SessionID 返回会话 ID
func (m *Mux) SessionID() uint32 {
	return m.sessionID
}

// OpenStream 打开新流
func (m *Mux) OpenStream() (*Stream, error) {
	if m.closed.Load() {
		return nil, ErrMuxClosed
	}

	if m.streamCount.Load() >= int32(m.config.MaxStreams) {
		return nil, ErrMaxStreams
	}

	id := m.nextID.Add(1)
	stream := NewStream(id, m.sessionID, StreamConfig{
		BufferSize: m.config.StreamBufferSize,
		MaxWindow:  m.config.MaxWindow,
	})

	m.streams.Store(id, stream)
	m.streamCount.Add(1)

	return stream, nil
}

// AcceptStream 接受新流（由远端发起）
func (m *Mux) AcceptStream(id uint32) (*Stream, error) {
	if m.closed.Load() {
		return nil, ErrMuxClosed
	}

	if m.streamCount.Load() >= int32(m.config.MaxStreams) {
		return nil, ErrMaxStreams
	}

	// 检查是否已存在
	if _, exists := m.streams.Load(id); exists {
		return nil, ErrInvalidStream
	}

	stream := NewStream(id, m.sessionID, StreamConfig{
		BufferSize: m.config.StreamBufferSize,
		MaxWindow:  m.config.MaxWindow,
	})

	m.streams.Store(id, stream)
	m.streamCount.Add(1)

	if m.onNewStream != nil {
		go m.onNewStream(stream)
	}

	return stream, nil
}

// GetStream 获取流
func (m *Mux) GetStream(id uint32) (*Stream, bool) {
	if v, ok := m.streams.Load(id); ok {
		return v.(*Stream), true
	}
	return nil, false
}

// CloseStream 关闭流
func (m *Mux) CloseStream(id uint32) error {
	if v, ok := m.streams.LoadAndDelete(id); ok {
		stream := v.(*Stream)
		stream.Close()
		m.streamCount.Add(-1)
		return nil
	}
	return ErrStreamNotFound
}

// Close 关闭多路复用器
func (m *Mux) Close() error {
	if m.closed.Swap(true) {
		return nil // 已经关闭
	}

	// 关闭所有流
	m.streams.Range(func(key, value interface{}) bool {
		stream := value.(*Stream)
		stream.Close()
		m.streams.Delete(key)
		return true
	})

	m.streamCount.Store(0)

	if m.pingTimer != nil {
		m.pingTimer.Stop()
	}

	return nil
}

// IsClosed 检查是否已关闭
func (m *Mux) IsClosed() bool {
	return m.closed.Load()
}

// StreamCount 返回当前流数
func (m *Mux) StreamCount() int {
	return int(m.streamCount.Load())
}

// SetOnNewStream 设置新流回调
func (m *Mux) SetOnNewStream(fn func(*Stream)) {
	m.onNewStream = fn
}

// StartKeepalive 启动心跳
func (m *Mux) StartKeepalive(ctx context.Context, sendPing func() error) {
	if m.config.KeepAliveInterval <= 0 {
		return
	}

	ticker := time.NewTicker(m.config.KeepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if m.closed.Load() {
				return
			}

			// 检查空闲超时
			if time.Since(m.lastPong) > m.config.IdleTimeout {
				m.Close()
				return
			}

			// 发送心跳
			m.lastPing = time.Now()
			if err := sendPing(); err != nil {
				continue
			}
		}
	}
}

// OnPong 收到心跳响应
func (m *Mux) OnPong() {
	m.lastPong = time.Now()
}

// RTT 获取 RTT（基于最近的心跳）
func (m *Mux) RTT() time.Duration {
	if m.lastPong.After(m.lastPing) {
		return 0
	}
	return m.lastPong.Sub(m.lastPing)
}

// HandlePacket 处理多路复用数据包
func (m *Mux) HandlePacket(pkt *Packet) error {
	if m.closed.Load() {
		return ErrMuxClosed
	}

	switch pkt.Type {
	case PacketTypeStreamOpen:
		return m.handleStreamOpen(pkt)
	case PacketTypeStreamData:
		return m.handleStreamData(pkt)
	case PacketTypeStreamClose:
		return m.handleStreamClose(pkt)
	case PacketTypeStreamAck:
		return m.handleStreamAck(pkt)
	case PacketTypePing:
		// 由上层处理
		return nil
	case PacketTypePong:
		m.OnPong()
		return nil
	default:
		return fmt.Errorf("未知多路复用包类型: %d", pkt.Type)
	}
}

// handleStreamOpen 处理打开流请求
func (m *Mux) handleStreamOpen(pkt *Packet) error {
	_, err := m.AcceptStream(pkt.StreamID)
	return err
}

// handleStreamData 处理流数据
func (m *Mux) handleStreamData(pkt *Packet) error {
	stream, ok := m.GetStream(pkt.StreamID)
	if !ok {
		return ErrStreamNotFound
	}

	// 更新序列号
	stream.UpdateRecvSeq(pkt.Sequence)

	// 推送数据
	if len(pkt.Payload) > 0 {
		return stream.PushData(pkt.Payload)
	}

	return nil
}

// handleStreamClose 处理关闭流
func (m *Mux) handleStreamClose(pkt *Packet) error {
	return m.CloseStream(pkt.StreamID)
}

// handleStreamAck 处理流确认
func (m *Mux) handleStreamAck(pkt *Packet) error {
	stream, ok := m.GetStream(pkt.StreamID)
	if !ok {
		return nil // 忽略未知流的确认
	}

	// 更新发送窗口
	if pkt.Payload != nil && len(pkt.Payload) >= 4 {
		windowUpdate := int32(binary.BigEndian.Uint32(pkt.Payload))
		stream.UpdateSendWindow(windowUpdate)
	}

	return nil
}

// ForEachStream 遍历所有流
func (m *Mux) ForEachStream(fn func(*Stream) bool) {
	m.streams.Range(func(key, value interface{}) bool {
		stream := value.(*Stream)
		return fn(stream)
	})
}

// CleanExpiredStreams 清理过期流
func (m *Mux) CleanExpiredStreams(timeout time.Duration) int {
	now := time.Now()
	count := 0

	m.streams.Range(func(key, value interface{}) bool {
		stream := value.(*Stream)
		if now.Sub(stream.LastActive()) > timeout {
			m.CloseStream(stream.ID())
			count++
		}
		return true
	})

	return count
}

// Stats 多路复用器统计
type MuxStats struct {
	SessionID   uint32
	StreamCount int
	Closed      bool
	LastPing    time.Time
	LastPong    time.Time
}

// Stats 获取统计
func (m *Mux) Stats() MuxStats {
	return MuxStats{
		SessionID:   m.sessionID,
		StreamCount: m.StreamCount(),
		Closed:      m.closed.Load(),
		LastPing:    m.lastPing,
		LastPong:    m.lastPong,
	}
}

import (
	"encoding/binary"
	"fmt"
)


