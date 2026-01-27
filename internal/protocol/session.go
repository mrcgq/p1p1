
package protocol

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Session 代表一个代理会话
type Session struct {
	ID         uint32
	Target     net.Conn   // 直接连接目标
	Network    string     // 网络类型
	TargetAddr string     // 目标地址
	Created    time.Time
	lastActive atomic.Value // time.Time
	closed     atomic.Bool

	// 多路复用
	mux        *Mux
	muxEnabled bool

	// 序列号（非多路复用模式）
	sendSeq atomic.Uint32
	recvSeq atomic.Uint32

	// 统计
	bytesSent atomic.Uint64
	bytesRecv atomic.Uint64

	mu sync.RWMutex
}

// NewSession 创建新会话
func NewSession(id uint32, target net.Conn, network, addr string) *Session {
	s := &Session{
		ID:         id,
		Target:     target,
		Network:    network,
		TargetAddr: addr,
		Created:    time.Now(),
	}
	s.lastActive.Store(time.Now())
	return s
}

// NewMuxSession 创建多路复用会话
func NewMuxSession(id uint32, config MuxConfig) *Session {
	s := &Session{
		ID:         id,
		mux:        NewMux(id, config),
		muxEnabled: true,
		Created:    time.Now(),
	}
	s.lastActive.Store(time.Now())
	return s
}

// IsMux 是否为多路复用会话
func (s *Session) IsMux() bool {
	return s.muxEnabled && s.mux != nil
}

// GetMux 获取多路复用器
func (s *Session) GetMux() *Mux {
	return s.mux
}

// Touch 更新最后活动时间
func (s *Session) Touch() {
	s.lastActive.Store(time.Now())
}

// GetLastActive 获取最后活动时间
func (s *Session) GetLastActive() time.Time {
	return s.lastActive.Load().(time.Time)
}

// NextSendSeq 返回并递增发送序列号
func (s *Session) NextSendSeq() uint32 {
	return s.sendSeq.Add(1)
}

// UpdateRecvSeq 更新接收序列号
func (s *Session) UpdateRecvSeq(seq uint32) {
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
func (s *Session) GetRecvSeq() uint32 {
	return s.recvSeq.Load()
}

// Write 向目标连接写入数据
func (s *Session) Write(data []byte) (int, error) {
	s.Touch()
	n, err := s.Target.Write(data)
	if n > 0 {
		s.bytesSent.Add(uint64(n))
	}
	return n, err
}

// Read 从目标连接读取数据
func (s *Session) Read(buf []byte) (int, error) {
	s.Touch()
	n, err := s.Target.Read(buf)
	if n > 0 {
		s.bytesRecv.Add(uint64(n))
	}
	return n, err
}

// Close 关闭会话
func (s *Session) Close() error {
	if s.closed.Swap(true) {
		return nil // 已经关闭
	}

	// 关闭多路复用器
	if s.mux != nil {
		s.mux.Close()
	}

	// 关闭目标连接
	if s.Target != nil {
		return s.Target.Close()
	}

	return nil
}

// IsClosed 返回会话是否已关闭
func (s *Session) IsClosed() bool {
	return s.closed.Load()
}

// Stats 会话统计
type SessionStats struct {
	ID         uint32
	Network    string
	TargetAddr string
	Created    time.Time
	LastActive time.Time
	BytesSent  uint64
	BytesRecv  uint64
	IsMux      bool
	StreamCount int
	Closed     bool
}

// Stats 获取会话统计
func (s *Session) Stats() SessionStats {
	stats := SessionStats{
		ID:         s.ID,
		Network:    s.Network,
		TargetAddr: s.TargetAddr,
		Created:    s.Created,
		LastActive: s.GetLastActive(),
		BytesSent:  s.bytesSent.Load(),
		BytesRecv:  s.bytesRecv.Load(),
		IsMux:      s.muxEnabled,
		Closed:     s.closed.Load(),
	}

	if s.mux != nil {
		stats.StreamCount = s.mux.StreamCount()
	}

	return stats
}

// SessionManager 管理多个会话
type SessionManager struct {
	sessions sync.Map // map[uint32]*Session
	timeout  time.Duration
	nextID   atomic.Uint32

	// 统计
	totalSessions  atomic.Uint64
	activeSessions atomic.Int64

	// 回调
	onSessionClose func(uint32)

	mu sync.RWMutex
}

// NewSessionManager 创建新的会话管理器
func NewSessionManager(timeout time.Duration) *SessionManager {
	return &SessionManager{
		timeout: timeout,
	}
}

// Create 创建新会话
func (m *SessionManager) Create(target net.Conn, network, addr string) *Session {
	id := m.nextID.Add(1)
	session := NewSession(id, target, network, addr)
	m.sessions.Store(id, session)
	m.totalSessions.Add(1)
	m.activeSessions.Add(1)
	return session
}

// CreateMux 创建多路复用会话
func (m *SessionManager) CreateMux(config MuxConfig) *Session {
	id := m.nextID.Add(1)
	session := NewMuxSession(id, config)
	m.sessions.Store(id, session)
	m.totalSessions.Add(1)
	m.activeSessions.Add(1)
	return session
}

// Get 根据 ID 获取会话
func (m *SessionManager) Get(id uint32) *Session {
	if v, ok := m.sessions.Load(id); ok {
		return v.(*Session)
	}
	return nil
}

// Delete 删除会话
func (m *SessionManager) Delete(id uint32) {
	if v, ok := m.sessions.LoadAndDelete(id); ok {
		session := v.(*Session)
		session.Close()
		m.activeSessions.Add(-1)

		if m.onSessionClose != nil {
			go m.onSessionClose(id)
		}
	}
}

// CleanExpired 清理过期会话
func (m *SessionManager) CleanExpired() int {
	now := time.Now()
	count := 0

	m.sessions.Range(func(key, value interface{}) bool {
		session := value.(*Session)
		if now.Sub(session.GetLastActive()) > m.timeout {
			m.sessions.Delete(key)
			session.Close()
			m.activeSessions.Add(-1)
			count++

			if m.onSessionClose != nil {
				go m.onSessionClose(session.ID)
			}
		}
		return true
	})

	return count
}

// Count 返回活动会话数量
func (m *SessionManager) Count() int {
	return int(m.activeSessions.Load())
}

// TotalCount 返回总会话数量
func (m *SessionManager) TotalCount() uint64 {
	return m.totalSessions.Load()
}

// StartCleaner 启动后台清理协程
func (m *SessionManager) StartCleaner(stopCh <-chan struct{}) {
	ticker := time.NewTicker(m.timeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.CleanExpired()
		case <-stopCh:
			return
		}
	}
}

// CloseAll 关闭所有会话
func (m *SessionManager) CloseAll() {
	m.sessions.Range(func(key, value interface{}) bool {
		session := value.(*Session)
		session.Close()
		m.sessions.Delete(key)
		return true
	})
	m.activeSessions.Store(0)
}

// SetOnSessionClose 设置会话关闭回调
func (m *SessionManager) SetOnSessionClose(fn func(uint32)) {
	m.onSessionClose = fn
}

// ForEach 遍历所有会话
func (m *SessionManager) ForEach(fn func(*Session) bool) {
	m.sessions.Range(func(key, value interface{}) bool {
		return fn(value.(*Session))
	})
}

// ManagerStats 管理器统计
type ManagerStats struct {
	ActiveSessions int64
	TotalSessions  uint64
	Timeout        time.Duration
}

// Stats 获取管理器统计
func (m *SessionManager) Stats() ManagerStats {
	return ManagerStats{
		ActiveSessions: m.activeSessions.Load(),
		TotalSessions:  m.totalSessions.Load(),
		Timeout:        m.timeout,
	}
}


