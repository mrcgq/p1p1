package protocol

import (
	"context"
	"fmt"
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
}

// NewHandler 创建新的协议处理器
func NewHandler(config HandlerConfig, log *logger.Logger, m *metrics.Collector) *Handler {
	h := &Handler{
		psk:        config.PSK,
		userID:     crypto.DeriveUserID(config.PSK),
		timeWindow: config.TimeWindow,
		sessions:   NewSessionManager(5 * time.Minute),
		log:        log,
		metrics:    m,
		muxConfig:  config.MuxConfig,
		muxEnabled: config.MuxEnabled,
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
			stream.SetTarget(conn.NetworkString(), fmt.Sprintf("%s:%d", conn.Address, conn.Port))
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

	// 推送数据
	if len(packet.Payload) > 0 {
		stream.PushData(packet.Payload)
	}

	// 更新序列号
	stream.UpdateRecvSeq(packet.Sequence)

	// 这里简化处理，实际应该异步发送数据
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

// Close 关闭处理器
func (h *Handler) Close() {
	h.sessions.CloseAll()
}
