
package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// SOCKS5 常量
const (
	SOCKS5Version = 0x05

	// 认证方法
	AuthNone     = 0x00
	AuthPassword = 0x02
	AuthNoAccept = 0xFF

	// 命令
	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUDPAssociate = 0x03

	// 地址类型
	AtypIPv4   = 0x01
	AtypDomain = 0x03
	AtypIPv6   = 0x04

	// 回复状态
	RepSuccess          = 0x00
	RepServerFailure    = 0x01
	RepNotAllowed       = 0x02
	RepNetworkUnreach   = 0x03
	RepHostUnreach      = 0x04
	RepConnectionRefuse = 0x05
	RepTTLExpired       = 0x06
	RepCmdNotSupported  = 0x07
	RepAtypNotSupported = 0x08
)

var (
	ErrBadVersion     = errors.New("不支持的 SOCKS 版本")
	ErrNoAuth         = errors.New("不支持的认证方法")
	ErrBadRequest     = errors.New("无效的请求")
	ErrCmdNotSupport  = errors.New("不支持的命令")
	ErrAtypNotSupport = errors.New("不支持的地址类型")
)

// SOCKS5Config SOCKS5 配置
type SOCKS5Config struct {
	Username   string
	Password   string
	UDPEnabled bool
	Timeout    time.Duration
}

// SOCKS5Server SOCKS5 代理服务器
type SOCKS5Server struct {
	config      SOCKS5Config
	dialFunc    DialFunc
	udpHandler  *UDPAssociateHandler
}

// DialFunc 拨号函数类型
type DialFunc func(network, addr string) (net.Conn, error)

// SOCKS5Request 请求结构
type SOCKS5Request struct {
	Version  byte
	Command  byte
	AddrType byte
	DstAddr  string
	DstPort  uint16
}

// NewSOCKS5Server 创建 SOCKS5 服务器
func NewSOCKS5Server(config SOCKS5Config, dialFunc DialFunc) *SOCKS5Server {
	s := &SOCKS5Server{
		config:   config,
		dialFunc: dialFunc,
	}

	if config.UDPEnabled {
		s.udpHandler = NewUDPAssociateHandler(config.Timeout)
	}

	return s
}

// Handle 处理 SOCKS5 连接
func (s *SOCKS5Server) Handle(conn net.Conn) error {
	defer conn.Close()

	if s.config.Timeout > 0 {
		conn.SetDeadline(time.Now().Add(s.config.Timeout))
	}

	// 1. 握手
	if err := s.handleHandshake(conn); err != nil {
		return fmt.Errorf("握手失败: %w", err)
	}

	// 2. 读取请求
	req, err := s.readRequest(conn)
	if err != nil {
		return fmt.Errorf("读取请求失败: %w", err)
	}

	// 3. 处理请求
	switch req.Command {
	case CmdConnect:
		return s.handleConnect(conn, req)
	case CmdUDPAssociate:
		if s.config.UDPEnabled {
			return s.handleUDPAssociate(conn, req)
		}
		s.sendReply(conn, RepCmdNotSupported, nil)
		return ErrCmdNotSupport
	default:
		s.sendReply(conn, RepCmdNotSupported, nil)
		return ErrCmdNotSupport
	}
}

// handleHandshake 处理握手
func (s *SOCKS5Server) handleHandshake(conn net.Conn) error {
	// 读取版本和方法数量
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	if buf[0] != SOCKS5Version {
		return ErrBadVersion
	}

	nMethods := int(buf[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// 检查认证方法
	var selectedMethod byte = AuthNoAccept
	needAuth := s.config.Username != "" || s.config.Password != ""

	for _, m := range methods {
		if needAuth && m == AuthPassword {
			selectedMethod = AuthPassword
			break
		}
		if !needAuth && m == AuthNone {
			selectedMethod = AuthNone
			break
		}
	}

	// 发送选择的方法
	conn.Write([]byte{SOCKS5Version, selectedMethod})

	if selectedMethod == AuthNoAccept {
		return ErrNoAuth
	}

	// 如果需要密码认证
	if selectedMethod == AuthPassword {
		if err := s.handleAuth(conn); err != nil {
			return err
		}
	}

	return nil
}

// handleAuth 处理用户名密码认证
func (s *SOCKS5Server) handleAuth(conn net.Conn) error {
	// 读取认证请求
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	// 版本必须是 1
	if buf[0] != 0x01 {
		return errors.New("认证版本错误")
	}

	// 读取用户名
	uLen := int(buf[1])
	username := make([]byte, uLen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}

	// 读取密码长度和密码
	pLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, pLenBuf); err != nil {
		return err
	}

	pLen := int(pLenBuf[0])
	password := make([]byte, pLen)
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	// 验证
	if string(username) != s.config.Username || string(password) != s.config.Password {
		conn.Write([]byte{0x01, 0x01}) // 认证失败
		return errors.New("认证失败")
	}

	// 认证成功
	conn.Write([]byte{0x01, 0x00})
	return nil
}

// readRequest 读取请求
func (s *SOCKS5Server) readRequest(conn net.Conn) (*SOCKS5Request, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	if buf[0] != SOCKS5Version {
		return nil, ErrBadVersion
	}

	req := &SOCKS5Request{
		Version:  buf[0],
		Command:  buf[1],
		AddrType: buf[3],
	}

	// 读取地址
	switch req.AddrType {
	case AtypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		req.DstAddr = net.IP(addr).String()

	case AtypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		req.DstAddr = net.IP(addr).String()

	case AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, err
		}
		req.DstAddr = string(domain)

	default:
		return nil, ErrAtypNotSupport
	}

	// 读取端口
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, err
	}
	req.DstPort = binary.BigEndian.Uint16(portBuf)

	return req, nil
}

// handleConnect 处理 CONNECT 命令
func (s *SOCKS5Server) handleConnect(conn net.Conn, req *SOCKS5Request) error {
	addr := net.JoinHostPort(req.DstAddr, strconv.Itoa(int(req.DstPort)))

	target, err := s.dialFunc("tcp", addr)
	if err != nil {
		s.sendReply(conn, RepHostUnreach, nil)
		return fmt.Errorf("连接 %s 失败: %w", addr, err)
	}
	defer target.Close()

	// 获取本地地址用于回复
	localAddr := target.LocalAddr().(*net.TCPAddr)
	s.sendReply(conn, RepSuccess, localAddr)

	// 取消超时
	conn.SetDeadline(time.Time{})

	// 双向复制
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(target, conn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(conn, target)
		errCh <- err
	}()

	<-errCh
	return nil
}

// handleUDPAssociate 处理 UDP ASSOCIATE 命令
func (s *SOCKS5Server) handleUDPAssociate(conn net.Conn, req *SOCKS5Request) error {
	if s.udpHandler == nil {
		s.sendReply(conn, RepCmdNotSupported, nil)
		return ErrCmdNotSupport
	}

	// 创建 UDP 监听
	udpAddr, cleanup, err := s.udpHandler.CreateAssociation(conn.RemoteAddr())
	if err != nil {
		s.sendReply(conn, RepServerFailure, nil)
		return err
	}

	// 发送 UDP 监听地址给客户端
	s.sendReply(conn, RepSuccess, udpAddr)

	// 保持 TCP 连接，直到客户端断开
	// 这表示 UDP 关联结束
	buf := make([]byte, 1)
	conn.Read(buf) // 阻塞直到连接断开

	cleanup()
	return nil
}

// sendReply 发送回复
func (s *SOCKS5Server) sendReply(conn net.Conn, rep byte, addr net.Addr) {
	reply := []byte{SOCKS5Version, rep, 0x00}

	if addr == nil {
		reply = append(reply, AtypIPv4, 0, 0, 0, 0, 0, 0)
	} else {
		switch a := addr.(type) {
		case *net.TCPAddr:
			if ip4 := a.IP.To4(); ip4 != nil {
				reply = append(reply, AtypIPv4)
				reply = append(reply, ip4...)
			} else {
				reply = append(reply, AtypIPv6)
				reply = append(reply, a.IP.To16()...)
			}
			portBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(portBuf, uint16(a.Port))
			reply = append(reply, portBuf...)

		case *net.UDPAddr:
			if ip4 := a.IP.To4(); ip4 != nil {
				reply = append(reply, AtypIPv4)
				reply = append(reply, ip4...)
			} else {
				reply = append(reply, AtypIPv6)
				reply = append(reply, a.IP.To16()...)
			}
			portBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(portBuf, uint16(a.Port))
			reply = append(reply, portBuf...)
		}
	}

	conn.Write(reply)
}

// TargetAddr 返回目标地址
func (r *SOCKS5Request) TargetAddr() string {
	return net.JoinHostPort(r.DstAddr, strconv.Itoa(int(r.DstPort)))
}


