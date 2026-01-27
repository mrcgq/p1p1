
package protocol

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrStreamClosed    = errors.New("流已关闭")
	ErrStreamReset     = errors.New("流已重置")
	ErrBufferFull      = errors.New("缓冲区已满")
	ErrWriteTimeout    = errors.New("写入超时")
	ErrReadTimeout     = errors.New("读取超时")
)

// StreamState 流状态
type StreamState uint32

const (
	StreamStateIdle StreamState = iota
	StreamStateOpen
	StreamStateHalfClosed
	StreamStateClosed
	StreamStateReset
)

// Stream 表示多路复用中的单个流
type Stream struct {
	id        uint32
	sessionID uint32
	state     atomic.Uint32

	// 读缓冲区
	readBuf    []byte
	readCond   *sync.Cond
	readMu     sync.Mutex
	readClosed bool

	// 写缓冲区
	writeBuf    []byte
	writeCond   *sync.Cond
	writeMu     sync.Mutex
	writeClosed bool

	// 序列号
	sendSeq atomic.Uint32
	recvSeq atomic.Uint32
	ackSeq  atomic.Uint32

	// 流控
	sendWindow atomic.Int32
	recvWindow atomic.Int32
	maxWindow  int32

	// 回调
	onData  func([]byte) error
	onClose func()

	// 时间追踪
	created    time.Time
	lastActive atomic.Value // time.Time

	// 目标信息
	network    string
	targetAddr string
}

// StreamConfig 流配置
type StreamConfig struct {
	BufferSize    int
	MaxWindow     int32
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
}

// DefaultStreamConfig 默认流配置
func DefaultStreamConfig() StreamConfig {
	return StreamConfig{
		BufferSize:   65536,
		MaxWindow:    65536,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
}

// NewStream 创建新流
func NewStream(id, sessionID uint32, config StreamConfig) *Stream {
	s := &Stream{
		id:         id,
		sessionID:  sessionID,
		readBuf:    make([]byte, 0, config.BufferSize),
		writeBuf:   make([]byte, 0, config.BufferSize),
		maxWindow:  config.MaxWindow,
		created:    time.Now(),
	}
	s.state.Store(uint32(StreamStateOpen))
	s.sendWindow.Store(config.MaxWindow)
	s.recvWindow.Store(config.MaxWindow)
	s.lastActive.Store(time.Now())

	s.readCond = sync.NewCond(&s.readMu)
	s.writeCond = sync.NewCond(&s.writeMu)

	return s
}

// ID 返回流 ID
func (s *Stream) ID() uint32 {
	return s.id
}

// SessionID 返回会话 ID
func (s *Stream) SessionID() uint32 {
	return s.sessionID
}

// State 返回流状态
func (s *Stream) State() StreamState {
	return StreamState(s.state.Load())
}

// SetState 设置流状态
func (s *Stream) SetState(state StreamState) {
	s.state.Store(uint32(state))
}

// Touch 更新最后活动时间
func (s *Stream) Touch() {
	s.lastActive.Store(time.Now())
}

// LastActive 返回最后活动时间
func (s *Stream) LastActive() time.Time {
	return s.lastActive.Load().(time.Time)
}

// Read 实现 io.Reader
func (s *Stream) Read(p []byte) (n int, err error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	for len(s.readBuf) == 0 {
		if s.readClosed {
			return 0, io.EOF
		}
		if s.State() >= StreamStateClosed {
			return 0, ErrStreamClosed
		}
		s.readCond.Wait()
	}

	n = copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	s.Touch()

	// 更新接收窗口
	s.recvWindow.Add(int32(n))

	return n, nil
}

// Write 实现 io.Writer
func (s *Stream) Write(p []byte) (n int, err error) {
	if s.State() >= StreamStateClosed {
		return 0, ErrStreamClosed
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// 检查发送窗口
	for s.sendWindow.Load() < int32(len(p)) {
		if s.writeClosed {
			return 0, ErrStreamClosed
		}
		s.writeCond.Wait()
	}

	s.writeBuf = append(s.writeBuf, p...)
	n = len(p)
	s.sendWindow.Add(-int32(n))
	s.Touch()

	// 通知数据回调
	if s.onData != nil {
		data := make([]byte, len(s.writeBuf))
		copy(data, s.writeBuf)
		s.writeBuf = s.writeBuf[:0]
		go s.onData(data)
	}

	return n, nil
}

// Close 关闭流
func (s *Stream) Close() error {
	if !s.state.CompareAndSwap(uint32(StreamStateOpen), uint32(StreamStateClosed)) {
		return nil // 已经关闭
	}

	s.readMu.Lock()
	s.readClosed = true
	s.readCond.Broadcast()
	s.readMu.Unlock()

	s.writeMu.Lock()
	s.writeClosed = true
	s.writeCond.Broadcast()
	s.writeMu.Unlock()

	if s.onClose != nil {
		go s.onClose()
	}

	return nil
}

// Reset 重置流
func (s *Stream) Reset() {
	s.state.Store(uint32(StreamStateReset))

	s.readMu.Lock()
	s.readClosed = true
	s.readCond.Broadcast()
	s.readMu.Unlock()

	s.writeMu.Lock()
	s.writeClosed = true
	s.writeCond.Broadcast()
	s.writeMu.Unlock()

	if s.onClose != nil {
		go s.onClose()
	}
}

// PushData 推送接收到的数据
func (s *Stream) PushData(data []byte) error {
	if s.State() >= StreamStateClosed {
		return ErrStreamClosed
	}

	s.readMu.Lock()
	defer s.readMu.Unlock()

	s.readBuf = append(s.readBuf, data...)
	s.recvWindow.Add(-int32(len(data)))
	s.readCond.Signal()
	s.Touch()

	return nil
}

// UpdateSendWindow 更新发送窗口
func (s *Stream) UpdateSendWindow(delta int32) {
	s.sendWindow.Add(delta)
	s.writeCond.Signal()
}

// NextSendSeq 返回并递增发送序列号
func (s *Stream) NextSendSeq() uint32 {
	return s.sendSeq.Add(1)
}

// UpdateRecvSeq 更新接收序列号
func (s *Stream) UpdateRecvSeq(seq uint32) {
	for {
		old := s.recvSeq.Load()
		if seq <= old {
			return
		}
		if s.recvSeq.CompareAndSwap(old, seq) {
			return
		}
	}
}

// GetRecvSeq 获取当前接收序列号
func (s *Stream) GetRecvSeq() uint32 {
	return s.recvSeq.Load()
}

// SetOnData 设置数据回调
func (s *Stream) SetOnData(fn func([]byte) error) {
	s.onData = fn
}

// SetOnClose 设置关闭回调
func (s *Stream) SetOnClose(fn func()) {
	s.onClose = fn
}

// SetTarget 设置目标信息
func (s *Stream) SetTarget(network, addr string) {
	s.network = network
	s.targetAddr = addr
}

// Target 获取目标信息
func (s *Stream) Target() (network, addr string) {
	return s.network, s.targetAddr
}

// IsClosed 检查流是否已关闭
func (s *Stream) IsClosed() bool {
	return s.State() >= StreamStateClosed
}

// Stats 流统计
type StreamStats struct {
	ID          uint32
	SessionID   uint32
	State       StreamState
	SendSeq     uint32
	RecvSeq     uint32
	SendWindow  int32
	RecvWindow  int32
	ReadBufLen  int
	WriteBufLen int
	Created     time.Time
	LastActive  time.Time
}

// Stats 获取流统计
func (s *Stream) Stats() StreamStats {
	s.readMu.Lock()
	readLen := len(s.readBuf)
	s.readMu.Unlock()

	s.writeMu.Lock()
	writeLen := len(s.writeBuf)
	s.writeMu.Unlock()

	return StreamStats{
		ID:          s.id,
		SessionID:   s.sessionID,
		State:       s.State(),
		SendSeq:     s.sendSeq.Load(),
		RecvSeq:     s.recvSeq.Load(),
		SendWindow:  s.sendWindow.Load(),
		RecvWindow:  s.recvWindow.Load(),
		ReadBufLen:  readLen,
		WriteBufLen: writeLen,
		Created:     s.created,
		LastActive:  s.LastActive(),
	}
}


