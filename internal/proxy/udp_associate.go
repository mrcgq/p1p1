
package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// UDPAssociateHandler 处理 SOCKS5 UDP ASSOCIATE
type UDPAssociateHandler struct {
	timeout      time.Duration
	associations sync.Map // map[string]*UDPAssociation

	// UDP 监听器池
	listeners sync.Map // map[int]*net.UDPConn
}

// UDPAssociation UDP 关联
type UDPAssociation struct {
	ID         string
	ClientAddr net.Addr
	UDPConn    *net.UDPConn
	Created    time.Time
	LastActive time.Time
	
	// 目标连接缓存
	targets sync.Map // map[string]*net.UDPConn

	closed bool
	mu     sync.Mutex
}

// NewUDPAssociateHandler 创建 UDP ASSOCIATE 处理器
func NewUDPAssociateHandler(timeout time.Duration) *UDPAssociateHandler {
	h := &UDPAssociateHandler{
		timeout: timeout,
	}

	// 启动清理协程
	go h.cleanup()

	return h
}

// CreateAssociation 创建新的 UDP 关联
func (h *UDPAssociateHandler) CreateAssociation(clientAddr net.Addr) (*net.UDPAddr, func(), error) {
	// 创建 UDP 监听器
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, nil, fmt.Errorf("创建 UDP 监听器失败: %w", err)
	}

	localAddr := udpConn.LocalAddr().(*net.UDPAddr)

	assoc := &UDPAssociation{
		ID:         fmt.Sprintf("%s-%d", clientAddr.String(), time.Now().UnixNano()),
		ClientAddr: clientAddr,
		UDPConn:    udpConn,
		Created:    time.Now(),
		LastActive: time.Now(),
	}

	h.associations.Store(assoc.ID, assoc)

	// 启动处理协程
	go h.handleAssociation(assoc)

	cleanup := func() {
		h.closeAssociation(assoc.ID)
	}

	return localAddr, cleanup, nil
}

// handleAssociation 处理单个 UDP 关联
func (h *UDPAssociateHandler) handleAssociation(assoc *UDPAssociation) {
	buf := make([]byte, 65535)

	for {
		assoc.UDPConn.SetReadDeadline(time.Now().Add(h.timeout))
		n, remoteAddr, err := assoc.UDPConn.ReadFromUDP(buf)
		if err != nil {
			break
		}

		assoc.mu.Lock()
		if assoc.closed {
			assoc.mu.Unlock()
			break
		}
		assoc.LastActive = time.Now()
		assoc.mu.Unlock()

		// 解析 SOCKS5 UDP 请求头
		if n < 10 {
			continue
		}

		// 检查 RSV 和 FRAG
		if buf[0] != 0 || buf[1] != 0 {
			continue // 不支持分片
		}

		frag := buf[2]
		if frag != 0 {
			continue // 不支持分片
		}

		// 解析目标地址
		atyp := buf[3]
		var targetAddr string
		var offset int

		switch atyp {
		case AtypIPv4:
			if n < 10 {
				continue
			}
			ip := net.IP(buf[4:8])
			port := binary.BigEndian.Uint16(buf[8:10])
			targetAddr = fmt.Sprintf("%s:%d", ip.String(), port)
			offset = 10

		case AtypIPv6:
			if n < 22 {
				continue
			}
			ip := net.IP(buf[4:20])
			port := binary.BigEndian.Uint16(buf[20:22])
			targetAddr = fmt.Sprintf("[%s]:%d", ip.String(), port)
			offset = 22

		case AtypDomain:
			if n < 7 {
				continue
			}
			domainLen := int(buf[4])
			if n < 7+domainLen {
				continue
			}
			domain := string(buf[5 : 5+domainLen])
			port := binary.BigEndian.Uint16(buf[5+domainLen : 7+domainLen])
			targetAddr = fmt.Sprintf("%s:%d", domain, port)
			offset = 7 + domainLen

		default:
			continue
		}

		// 获取数据
		data := buf[offset:n]

		// 发送到目标
		go h.forwardToTarget(assoc, targetAddr, data, remoteAddr)
	}
}

// forwardToTarget 转发数据到目标
func (h *UDPAssociateHandler) forwardToTarget(assoc *UDPAssociation, targetAddr string, data []byte, clientUDP *net.UDPAddr) {
	// 获取或创建到目标的连接
	var targetConn *net.UDPConn
	if v, ok := assoc.targets.Load(targetAddr); ok {
		targetConn = v.(*net.UDPConn)
	} else {
		// 解析目标地址
		udpAddr, err := net.ResolveUDPAddr("udp", targetAddr)
		if err != nil {
			return
		}

		// 创建连接
		conn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			return
		}

		assoc.targets.Store(targetAddr, conn)
		targetConn = conn

		// 启动接收协程
		go h.receiveFromTarget(assoc, targetConn, targetAddr, clientUDP)
	}

	// 发送数据
	targetConn.Write(data)
}

// receiveFromTarget 从目标接收数据
func (h *UDPAssociateHandler) receiveFromTarget(assoc *UDPAssociation, targetConn *net.UDPConn, targetAddr string, clientUDP *net.UDPAddr) {
	buf := make([]byte, 65535)

	for {
		targetConn.SetReadDeadline(time.Now().Add(h.timeout))
		n, err := targetConn.Read(buf)
		if err != nil {
			break
		}

		assoc.mu.Lock()
		if assoc.closed {
			assoc.mu.Unlock()
			break
		}
		assoc.LastActive = time.Now()
		assoc.mu.Unlock()

		// 构建 SOCKS5 UDP 响应
		response := h.buildUDPResponse(targetAddr, buf[:n])

		// 发送给客户端
		assoc.UDPConn.WriteToUDP(response, clientUDP)
	}
}

// buildUDPResponse 构建 SOCKS5 UDP 响应
func (h *UDPAssociateHandler) buildUDPResponse(targetAddr string, data []byte) []byte {
	host, portStr, _ := net.SplitHostPort(targetAddr)
	port, _ := net.LookupPort("udp", portStr)

	var response []byte
	response = append(response, 0, 0, 0) // RSV, RSV, FRAG

	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		response = append(response, AtypIPv4)
		response = append(response, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		response = append(response, AtypIPv6)
		response = append(response, ip6...)
	} else {
		response = append(response, AtypDomain)
		response = append(response, byte(len(host)))
		response = append(response, []byte(host)...)
	}

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(port))
	response = append(response, portBuf...)

	response = append(response, data...)
	return response
}

// closeAssociation 关闭关联
func (h *UDPAssociateHandler) closeAssociation(id string) {
	if v, ok := h.associations.LoadAndDelete(id); ok {
		assoc := v.(*UDPAssociation)
		
		assoc.mu.Lock()
		assoc.closed = true
		assoc.mu.Unlock()

		// 关闭所有目标连接
		assoc.targets.Range(func(key, value interface{}) bool {
			conn := value.(*net.UDPConn)
			conn.Close()
			return true
		})

		// 关闭 UDP 连接
		assoc.UDPConn.Close()
	}
}

// cleanup 清理过期关联
func (h *UDPAssociateHandler) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		h.associations.Range(func(key, value interface{}) bool {
			assoc := value.(*UDPAssociation)
			assoc.mu.Lock()
			lastActive := assoc.LastActive
			assoc.mu.Unlock()

			if now.Sub(lastActive) > h.timeout {
				h.closeAssociation(key.(string))
			}
			return true
		})
	}
}

// Stats 返回统计信息
func (h *UDPAssociateHandler) Stats() map[string]interface{} {
	count := 0
	h.associations.Range(func(_, _ interface{}) bool {
		count++
		return true
	})

	return map[string]interface{}{
		"active_associations": count,
	}
}


