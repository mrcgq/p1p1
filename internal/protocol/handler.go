
// internal/protocol/handler.go

package protocol

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/anthropics/phantom-server/internal/crypto"
	"github.com/anthropics/phantom-server/internal/logger"
	"github.com/anthropics/phantom-server/internal/metrics"
)

// Handler 处理 Phantom 协议数据包
type Handler struct {
	psk        []byte
	userID     [crypto.UserIDLength]byte
	timeWindow int
	sessions   *SessionManager
	log        *logger.Logger
	metrics    *metrics.Collector

	// 多路复用配置
	muxConfig  MuxConfig
	muxEnabled bool

	// UDP 处理器
	udpHandler *UDPStreamHandler

	// 重放保护
	replayFilters sync.Map // map[int64]*sync.Map

	// AEAD 缓存
	aeadCache sync.Map // map[int64]*crypto.AEAD

	mu sync.RWMutex
}

// HandlerConfig 处理器配置
type HandlerConfig struct {
	PSK        []byte
	TimeWindow int
	MuxEnabled bool
	MuxConfig  MuxConfig
	UDPTimeout time.Duration // UDP 超时时间
}

// ============================================================================
// UDPDatagram - 与客户端 udp_associate.go 完全匹配的数据报格式
// ============================================================================

// UDPDatagram 封装 UDP 数据报用于隧道传输
type UDPDatagram struct {
	Data []byte
}

// WriteTo 将数据报写入流（4字节长度前缀 + 数据）
func (d *UDPDatagram) WriteTo(w io.Writer) error {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(d.Data)))

	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(d.Data)
	return err
}

// ReadFrom 从流读取数据报
func (d *UDPDatagram) ReadFrom(r io.Reader) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}

	length := binary.BigEndian.Uint32(header)
	if length > 65535 {
		return fmt.Errorf("UDP datagram too large: %d", length)
	}

	d.Data = make([]byte, length)
	_, err := io.ReadFull(r, d.Data)
	return err
}

// ============================================================================
// UDPStreamHandler - UDP 流处理器
// ============================================================================

// UDPStreamHandler 处理 UDP 流
type UDPStreamHandler struct {
	sessions sync.Map // streamID -> *UDPProxySession
	log      *logger.Logger
	metrics  *metrics.Collector
	timeout  time.Duration
}

// UDPProxySession UDP 代理会话
type UDPProxySession struct {
	StreamID   uint32
	TargetAddr string
	UDPConn    *net.UDPConn
	Stream     io.ReadWriteCloser
	LastActive time.Time
	closed     bool
	mu         sync.Mutex
}

// NewUDPStreamHandler 创建 UDP 流处理器
func NewUDPStreamHandler(log *logger.Logger, m *metrics.Collector, timeout time.Duration) *UDPStreamHandler {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	h := &UDPStreamHandler{
		log:     log,
		metrics: m,
		timeout: timeout,
	}

	// 启动清理协程
	go h.cleanup()

	return h
}

// HandleUDPStream 处理 UDP 类型的流
func (h *UDPStreamHandler) HandleUDPStream(stream io.ReadWriteCloser, streamID uint32, targetAddr string) error {
	// 解析目标地址
	addr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return fmt.Errorf("解析 UDP 地址失败: %w", err)
	}

	// 创建 UDP 连接到目标
	udpConn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("连接 UDP 目标失败: %w", err)
	}

	session := &UDPProxySession{
		StreamID:   streamID,
		TargetAddr: targetAddr,
		UDPConn:    udpConn,
		Stream:     stream,
		LastActive: time.Now(),
	}

	h.sessions.Store(streamID, session)

	h.log.Debug("UDP 代理会话已创建: streamID=%d, target=%s", streamID, targetAddr)

	// 启动双向转发
	go h.forwardStreamToUDP(session)
	go h.forwardUDPToStream(session)

	return nil
}

// forwardStreamToUDP 从流读取数据转发到 UDP 目标
func (h *UDPStreamHandler) forwardStreamToUDP(session *UDPProxySession) {
	defer h.closeSession(session)

	for {
		// 检查是否已关闭
		session.mu.Lock()
		if session.closed {
			session.mu.Unlock()
			return
		}
		session.mu.Unlock()

		// 读取 UDPDatagram 格式数据（与客户端 WriteTo 匹配）
		datagram := &UDPDatagram{}
		if err := datagram.ReadFrom(session.Stream); err != nil {
			if err != io.EOF {
				h.log.Debug("读取 UDP 数据报失败: streamID=%d, error=%v", session.StreamID, err)
			}
			return
		}

		// 更新活跃时间
		session.mu.Lock()
		session.LastActive = time.Now()
		session.mu.Unlock()

		// 发送到 UDP 目标
		session.UDPConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		n, err := session.UDPConn.Write(datagram.Data)
		if err != nil {
			h.log.Debug("发送 UDP 数据到目标失败: streamID=%d, target=%s, error=%v",
				session.StreamID, session.TargetAddr, err)
			return
		}

		h.log.Debug("UDP 数据已转发到目标: streamID=%d, target=%s, size=%d",
			session.StreamID, session.TargetAddr, n)

		if h.metrics != nil {
			h.metrics.BytesSent(uint64(n))
		}
	}
}

// forwardUDPToStream 从 UDP 目标读取响应转发到流
func (h *UDPStreamHandler) forwardUDPToStream(session *UDPProxySession) {
	defer h.closeSession(session)

	buf := make([]byte, 65535)

	for {
		// 检查是否已关闭
		session.mu.Lock()
		if session.closed {
			session.mu.Unlock()
			return
		}
		session.mu.Unlock()

		// 设置读取超时
		session.UDPConn.SetReadDeadline(time.Now().Add(h.timeout))
		n, err := session.UDPConn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 超时，检查是否应该继续
				session.mu.Lock()
				if time.Since(session.LastActive) > h.timeout {
					session.mu.Unlock()
					h.log.Debug("UDP 会话超时: streamID=%d", session.StreamID)
					return
				}
				session.mu.Unlock()
				continue
			}
			h.log.Debug("从 UDP 目标读取失败: streamID=%d, error=%v", session.StreamID, err)
			return
		}

		// 更新活跃时间
		session.mu.Lock()
		session.LastActive = time.Now()
		if session.closed {
			session.mu.Unlock()
			return
		}
		session.mu.Unlock()

		// 封装为 UDPDatagram 格式并发送到流（与客户端 ReadFrom 匹配）
		datagram := &UDPDatagram{Data: buf[:n]}
		if err := datagram.WriteTo(session.Stream); err != nil {
			h.log.Debug("发送 UDP 响应到流失败: streamID=%d, error=%v", session.StreamID, err)
			return
		}

		h.log.Debug("UDP 响应已转发到流: streamID=%d, target=%s, size=%d",
			session.StreamID, session.TargetAddr, n)

		if h.metrics != nil {
			h.metrics.BytesRecv(uint64(n))
		}
	}
}

// closeSession 关闭 UDP 代理会话
func (h *UDPStreamHandler) closeSession(session *UDPProxySession) {
	session.mu.Lock()
	if session.closed {
		session.mu.Unlock()
		return
	}
	session.closed = true
	session.mu.Unlock()

	// 从映射中删除
	h.sessions.Delete(session.StreamID)

	// 关闭连接
	if session.UDPConn != nil {
		session.UDPConn.Close()
	}
	if session.Stream != nil {
		session.Stream.Close()
	}

	h.log.Debug("UDP 代理会话已关闭: streamID=%d, target=%s", session.StreamID, session.TargetAddr)
}

// cleanup 定期清理过期的 UDP 会话
func (h *UDPStreamHandler) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		h.sessions.Range(func(key, value interface{}) bool {
			session := value.(*UDPProxySession)

			session.mu.Lock()
			lastActive := session.LastActive
			closed := session.closed
			session.mu.Unlock()

			if !closed && now.Sub(lastActive) > h.timeout {
				h.log.Debug("清理过期 UDP 会话: streamID=%d", session.StreamID)
				h.closeSession(session)
			}
			return true
		})
	}
}

// GetActiveSessionCount 返回活跃会话数量
func (h *UDPStreamHandler) GetActiveSessionCount() int {
	count := 0
	h.sessions.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

// Close 关闭所有 UDP 会话
func (h *UDPStreamHandler) Close() {
	h.sessions.Range(func(key, value interface{}) bool {
		session := value.(*UDPProxySession)
		h.closeSession(session)
		return true
	})
}

// ============================================================================
// Handler 主处理器
// ============================================================================

// NewHandler 创建新的协议处理器
func NewHandler(config HandlerConfig, log *logger.Logger, m *metrics.Collector) *Handler {
	udpTimeout := config.UDPTimeout
	if udpTimeout <= 0 {
		udpTimeout = 5 * time.Minute
	}

	h := &Handler{
		psk:        config.PSK,
		userID:     crypto.DeriveUserID(config.PSK),
		timeWindow: config.TimeWindow,
		sessions:   NewSessionManager(5 * time.Minute),
		log:        log,
		metrics:    m,
		muxConfig:  config.MuxConfig,
		muxEnabled: config.MuxEnabled,
		udpHandler: NewUDPStreamHandler(log, m, udpTimeout),
	}
	return h
}

// GetUserID 返回预期的用户 ID
func (h *Handler) GetUserID() [crypto.UserIDLength]byte {
	return h.userID
}

// ValidateUserID 检查用户 ID 是否匹配
func (h *Handler) ValidateUserID(id [crypto.UserIDLength]byte) bool {
	return id == h.userID
}

// HandlePacket 处理传入的数据包
func (h *Handler) HandlePacket(ctx context.Context, data []byte, from net.Addr) ([]byte, error) {
	// 解析头部
	header, err := ParseHeader(data)
	if err != nil {
		return nil, fmt.Errorf("解析头部: %w", err)
	}

	// 验证用户 ID（快速路径拒绝）
	if !h.ValidateUserID(header.UserID) {
		return nil, fmt.Errorf("用户 ID 无效")
	}

	// 验证时间戳
	if !crypto.ValidateTimestamp(header.Timestamp, h.timeWindow) {
		return nil, fmt.Errorf("时间戳超出范围")
	}

	// 尝试使用有效时间窗口解密
	var plaintext []byte
	var decryptWindow int64
	encryptedPart := data[HeaderSize:]

	for _, window := range crypto.ValidWindows(h.timeWindow) {
		aead := h.getAEAD(window)
		if aead == nil {
			continue
		}

		plaintext, err = aead.DecryptPacket(encryptedPart)
		if err == nil {
			decryptWindow = window
			// 检查重放攻击
			if h.isReplay(decryptWindow, data[:HeaderSize+crypto.NonceSize]) {
				return nil, fmt.Errorf("检测到重放攻击")
			}
			break
		}
	}

	if plaintext == nil {
		return nil, fmt.Errorf("解密失败")
	}

	// 记录指标
	h.metrics.PacketRecv()
	h.metrics.BytesRecv(uint64(len(data)))

	// 解析数据包
	packet, err := ParsePacket(plaintext)
	if err != nil {
		return nil, fmt.Errorf("解析数据包: %w", err)
	}
	packet.Header = *header

	// 根据数据包类型处理
	var response []byte

	switch packet.Type {
	case PacketTypeConnect:
		response, err = h.handleConnect(ctx, packet, from)
	case PacketTypeData:
		response, err = h.handleData(ctx, packet)
	case PacketTypeClose:
		response, err = h.handleClose(packet)
	case PacketTypePing:
		response, err = h.handlePing(packet)
	case PacketTypeStreamOpen:
		response, err = h.handleStreamOpen(packet)
	case PacketTypeStreamData:
		response, err = h.handleStreamData(packet)
	case PacketTypeStreamClose:
		response, err = h.handleStreamClose(packet)
	default:
		return nil, fmt.Errorf("未知数据包类型: %d", packet.Type)
	}

	if err != nil {
		return nil, err
	}

	if response != nil {
		h.metrics.PacketSent()
		h.metrics.BytesSent(uint64(len(response)))
	}

	return response, nil
}

// getAEAD 获取或创建 AEAD
func (h *Handler) getAEAD(window int64) *crypto.AEAD {
	if v, ok := h.aeadCache.Load(window); ok {
		return v.(*crypto.AEAD)
	}

	sessionKey := crypto.DeriveSessionKey(h.psk, window)
	aead, err := crypto.NewAEAD(sessionKey)
	if err != nil {
		return nil
	}

	h.aeadCache.Store(window, aead)
	return aead
}

// handleConnect 处理连接请求
func (h *Handler) handleConnect(ctx context.Context, packet *Packet, from net.Addr) ([]byte, error) {
	// 解析连接载荷
	conn, err := ParseConnectPayload(packet.Payload)
	if err != nil {
		return nil, fmt.Errorf("解析连接载荷: %w", err)
	}

	h.log.Debug("连接请求: %s 来自 %v", conn.String(), from)

	// 检查是否请求多路复用会话
	if packet.IsMux() && h.muxEnabled {
		return h.handleMuxConnect(packet)
	}

	// 连接目标
	network := conn.NetworkString()
	addr := fmt.Sprintf("%s:%d", conn.Address, conn.Port)

	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var target net.Conn
	var dialer net.Dialer
	target, err = dialer.DialContext(dialCtx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("连接目标失败: %w", err)
	}

	// 创建会话
	session := h.sessions.Create(target, network, addr)
	h.metrics.SessionOpened()

	h.log.Debug("会话 %d 已创建，目标: %s", session.ID, addr)

	// 构建响应
	resp := &Packet{
		Type:      PacketTypeConnectAck,
		SessionID: session.ID,
		Sequence:  0,
		AckSeq:    packet.Sequence,
		Flags:     FlagACK,
	}

	return h.encryptPacket(resp)
}

// handleMuxConnect 处理多路复用连接请求
func (h *Handler) handleMuxConnect(packet *Packet) ([]byte, error) {
	session := h.sessions.CreateMux(h.muxConfig)
	h.metrics.SessionOpened()

	h.log.Debug("多路复用会话 %d 已创建", session.ID)

	resp := &Packet{
		Type:      PacketTypeConnectAck,
		SessionID: session.ID,
		Sequence:  0,
		AckSeq:    packet.Sequence,
		Flags:     FlagACK | FlagMUX,
	}

	return h.encryptPacket(resp)
}

// handleData 处理数据包
func (h *Handler) handleData(ctx context.Context, packet *Packet) ([]byte, error) {
	session := h.sessions.Get(packet.SessionID)
	if session == nil {
		return nil, fmt.Errorf("会话未找到: %d", packet.SessionID)
	}

	if session.IsClosed() {
		return nil, fmt.Errorf("会话已关闭")
	}

	// 更新接收序列号
	session.UpdateRecvSeq(packet.Sequence)

	// 写入目标
	if len(packet.Payload) > 0 {
		if _, err := session.Write(packet.Payload); err != nil {
			session.Close()
			h.metrics.SessionClosed()
			return nil, fmt.Errorf("写入目标失败: %w", err)
		}
	}

	// 从目标读取响应（非阻塞）
	buf := make([]byte, 4096)
	session.Target.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	n, err := session.Read(buf)

	var respPayload []byte
	if err == nil && n > 0 {
		respPayload = buf[:n]
	}

	// 构建响应
	resp := &Packet{
		Type:      PacketTypeData,
		SessionID: session.ID,
		Sequence:  session.NextSendSeq(),
		AckSeq:    session.GetRecvSeq(),
		Flags:     FlagACK,
		Payload:   respPayload,
	}

	return h.encryptPacket(resp)
}

// handleClose 处理关闭请求
func (h *Handler) handleClose(packet *Packet) ([]byte, error) {
	session := h.sessions.Get(packet.SessionID)
	if session != nil {
		h.log.Debug("会话 %d 已关闭", session.ID)
		h.sessions.Delete(packet.SessionID)
		h.metrics.SessionClosed()
	}

	// 发送关闭确认
	resp := &Packet{
		Type:      PacketTypeCloseAck,
		SessionID: packet.SessionID,
		Sequence:  0,
		AckSeq:    packet.Sequence,
		Flags:     FlagACK | FlagFIN,
	}

	return h.encryptPacket(resp)
}

// handlePing 处理心跳请求
func (h *Handler) handlePing(packet *Packet) ([]byte, error) {
	session := h.sessions.Get(packet.SessionID)
	if session != nil {
		session.Touch()
	}

	resp := &Packet{
		Type:      PacketTypePong,
		SessionID: packet.SessionID,
		Sequence:  0,
		AckSeq:    packet.Sequence,
		Flags:     FlagACK,
		Payload:   packet.Payload, // 回显 payload 用于 RTT 计算
	}

	return h.encryptPacket(resp)
}

// handleStreamOpen 处理打开流请求
func (h *Handler) handleStreamOpen(packet *Packet) ([]byte, error) {
	session := h.sessions.Get(packet.SessionID)
	if session == nil || !session.IsMux() {
		return nil, fmt.Errorf("会话未找到或不是多路复用会话")
	}

	mux := session.GetMux()
	stream, err := mux.AcceptStream(packet.StreamID)
	if err != nil {
		return nil, fmt.Errorf("接受流失败: %w", err)
	}

	h.metrics.StreamOpened()

	// 解析目标地址
	if len(packet.Payload) > 0 {
		conn, err := ParseConnectPayload(packet.Payload)
		if err == nil {
			network := conn.NetworkString()
			addr := fmt.Sprintf("%s:%d", conn.Address, conn.Port)

			// 根据网络类型选择不同的处理方式
			if network == "udp" {
				// UDP 流：使用 UDPStreamHandler 处理
				h.log.Debug("处理 UDP 流: streamID=%d, target=%s", stream.ID(), addr)

				go func() {
					if err := h.udpHandler.HandleUDPStream(stream, stream.ID(), addr); err != nil {
						h.log.Error("UDP 流处理失败: streamID=%d, error=%v", stream.ID(), err)
					}
				}()
			} else {
				// TCP 流：设置目标并启动 TCP 转发
				stream.SetTarget(network, addr)
				go h.handleTCPStream(stream, network, addr)
			}
		}
	}

	resp := &Packet{
		Type:      PacketTypeStreamAck,
		SessionID: session.ID,
		StreamID:  stream.ID(),
		Sequence:  0,
		AckSeq:    packet.Sequence,
		Flags:     FlagACK | FlagMUX,
	}

	return h.encryptPacket(resp)
}

// handleTCPStream 处理 TCP 流的数据转发
func (h *Handler) handleTCPStream(stream *Stream, network, addr string) {
	defer func() {
		stream.Close()
		h.metrics.StreamClosed()
	}()

	// 连接到目标
	conn, err := net.DialTimeout(network, addr, 10*time.Second)
	if err != nil {
		h.log.Error("连接 TCP 目标失败: streamID=%d, target=%s, error=%v", stream.ID(), addr, err)
		return
	}
	defer conn.Close()

	h.log.Debug("TCP 流已连接: streamID=%d, target=%s", stream.ID(), addr)

	// 双向数据转发
	var wg sync.WaitGroup
	wg.Add(2)

	// 从流到目标
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := stream.Read(buf)
			if err != nil {
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	// 从目标到流
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if _, err := stream.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

// handleStreamData 处理流数据
func (h *Handler) handleStreamData(packet *Packet) ([]byte, error) {
	session := h.sessions.Get(packet.SessionID)
	if session == nil || !session.IsMux() {
		return nil, fmt.Errorf("会话未找到")
	}

	mux := session.GetMux()
	stream, ok := mux.GetStream(packet.StreamID)
	if !ok {
		return nil, fmt.Errorf("流未找到: %d", packet.StreamID)
	}

	// 推送数据到流
	if len(packet.Payload) > 0 {
		stream.PushData(packet.Payload)
	}

	// 更新序列号
	stream.UpdateRecvSeq(packet.Sequence)

	return nil, nil
}

// handleStreamClose 处理关闭流
func (h *Handler) handleStreamClose(packet *Packet) ([]byte, error) {
	session := h.sessions.Get(packet.SessionID)
	if session == nil || !session.IsMux() {
		return nil, nil
	}

	mux := session.GetMux()
	mux.CloseStream(packet.StreamID)
	h.metrics.StreamClosed()

	return nil, nil
}

// encryptPacket 加密响应数据包
func (h *Handler) encryptPacket(packet *Packet) ([]byte, error) {
	window := crypto.CurrentWindow(h.timeWindow)
	aead := h.getAEAD(window)
	if aead == nil {
		return nil, fmt.Errorf("创建 AEAD 失败")
	}

	// 序列化数据包
	plaintext := packet.Serialize()

	// 加密
	encrypted, err := aead.EncryptPacket(plaintext)
	if err != nil {
		return nil, fmt.Errorf("加密: %w", err)
	}

	// 构建完整数据包（带头部）
	header := &PacketHeader{
		UserID:    h.userID,
		Timestamp: crypto.TimestampLow16(),
	}

	result := make([]byte, HeaderSize+len(encrypted))
	copy(result[:HeaderSize], header.Serialize())
	copy(result[HeaderSize:], encrypted)

	return result, nil
}

// isReplay 检查数据包是否为重放
func (h *Handler) isReplay(window int64, identifier []byte) bool {
	key := string(identifier)

	// 获取或创建该窗口的过滤器
	filterI, _ := h.replayFilters.LoadOrStore(window, &sync.Map{})
	filter := filterI.(*sync.Map)

	// 检查是否已存在
	if _, exists := filter.Load(key); exists {
		return true
	}

	// 添加到过滤器
	filter.Store(key, struct{}{})
	return false
}

// GetSessionManager 返回会话管理器
func (h *Handler) GetSessionManager() *SessionManager {
	return h.sessions
}

// GetUDPHandler 返回 UDP 处理器
func (h *Handler) GetUDPHandler() *UDPStreamHandler {
	return h.udpHandler
}

// CleanupReplayFilters 清理旧的重放过滤器条目
func (h *Handler) CleanupReplayFilters() {
	currentWindow := crypto.CurrentWindow(h.timeWindow)

	h.replayFilters.Range(func(key, _ interface{}) bool {
		window := key.(int64)
		// 删除超过 2 个窗口的旧条目
		if currentWindow-window > 2 {
			h.replayFilters.Delete(key)
		}
		return true
	})

	// 同时清理 AEAD 缓存
	h.aeadCache.Range(func(key, _ interface{}) bool {
		window := key.(int64)
		if currentWindow-window > 2 {
			h.aeadCache.Delete(key)
		}
		return true
	})
}

// GetStats 返回处理器统计信息
func (h *Handler) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"active_sessions":     h.sessions.Count(),
		"active_udp_sessions": h.udpHandler.GetActiveSessionCount(),
		"mux_enabled":         h.muxEnabled,
	}
}

// Close 关闭处理器
func (h *Handler) Close() {
	// 关闭 UDP 处理器
	if h.udpHandler != nil {
		h.udpHandler.Close()
	}

	// 关闭所有会话
	h.sessions.CloseAll()
}



