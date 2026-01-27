package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/anthropics/phantom-server/internal/config"
	"github.com/anthropics/phantom-server/internal/logger"
	"github.com/anthropics/phantom-server/internal/metrics"
	"github.com/anthropics/phantom-server/internal/protocol"
	"github.com/anthropics/phantom-server/internal/proxy"
)

// TCPServer TCP 服务器
type TCPServer struct {
	config  *config.Config
	handler *protocol.Handler
	log     *logger.Logger
	metrics *metrics.Collector

	listener   net.Listener
	tlsConfig  *tls.Config
	socks5     *proxy.SOCKS5Server
	httpProxy  *proxy.HTTPProxy

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewTCPServer 创建新的 TCP 服务器
func NewTCPServer(cfg *config.Config, handler *protocol.Handler, log *logger.Logger, m *metrics.Collector) *TCPServer {
	s := &TCPServer{
		config:  cfg,
		handler: handler,
		log:     log,
		metrics: m,
		stopCh:  make(chan struct{}),
	}

	// 创建拨号函数
	dialFunc := func(network, addr string) (net.Conn, error) {
		return net.DialTimeout(network, addr, 10*time.Second)
	}

	// 初始化 SOCKS5 服务器
	if cfg.Proxy.SOCKS5.Enabled {
		socks5Config := proxy.SOCKS5Config{
			UDPEnabled: cfg.Proxy.SOCKS5.UDPEnabled,
			Timeout:    time.Duration(cfg.Proxy.SOCKS5.UDPTimeout) * time.Second,
		}
		s.socks5 = proxy.NewSOCKS5Server(socks5Config, dialFunc)
	}

	// 初始化 HTTP 代理
	if cfg.Proxy.HTTP.Enabled {
		httpConfig := proxy.HTTPConfig{
			Timeout: 30 * time.Second,
		}
		s.httpProxy = proxy.NewHTTPProxy(httpConfig, dialFunc)
	}

	return s
}

// Start 启动 TCP 服务器
func (s *TCPServer) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.config.Listen.Address, s.config.Listen.TCPPort)

	var err error
	if s.config.TLS.Enabled {
		// 加载 TLS 配置
		s.tlsConfig, err = s.loadTLSConfig()
		if err != nil {
			return fmt.Errorf("加载 TLS 配置: %w", err)
		}
		s.listener, err = tls.Listen("tcp", addr, s.tlsConfig)
		if err != nil {
			return fmt.Errorf("TLS 监听: %w", err)
		}
		s.log.Info("TCP/TLS 服务器已启动: %s", addr)
	} else {
		s.listener, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("TCP 监听: %w", err)
		}
		s.log.Info("TCP 服务器已启动: %s", addr)
	}

	// 接受连接
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptLoop(ctx)
	}()

	return nil
}

// loadTLSConfig 加载 TLS 配置
func (s *TCPServer) loadTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(s.config.TLS.CertFile, s.config.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("加载证书: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}, nil
}

// acceptLoop 接受连接循环
func (s *TCPServer) acceptLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		default:
		}

		// 设置接受超时
		if tcpListener, ok := s.listener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-s.stopCh:
				return
			default:
				s.log.Debug("接受连接错误: %v", err)
				continue
			}
		}

		// 处理连接
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(ctx, conn)
		}()
	}
}

// handleConnection 处理单个连接
func (s *TCPServer) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// 设置初始读取超时，用于协议检测
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// 读取第一个字节进行协议检测
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err != nil {
		if err != io.EOF {
			s.log.Debug("读取首字节失败: %v", err)
		}
		return
	}
	if n == 0 {
		return
	}

	// 创建预读连接
	prefixConn := &prefixConn{
		Conn:   conn,
		prefix: buf[:n],
	}

	// 协议检测
	switch buf[0] {
	case 0x05: // SOCKS5
		if s.socks5 != nil {
			if err := s.socks5.Handle(prefixConn); err != nil {
				s.log.Debug("SOCKS5 处理错误: %v", err)
			}
		}
	case 'C', 'G', 'P', 'H', 'D', 'O', 'T': // HTTP 方法
		if s.httpProxy != nil {
			if err := s.httpProxy.Handle(prefixConn); err != nil {
				s.log.Debug("HTTP 代理处理错误: %v", err)
			}
		}
	default:
		// Phantom 协议或其他
		s.handlePhantomTCP(ctx, prefixConn)
	}
}

// handlePhantomTCP 处理 Phantom TCP 连接
func (s *TCPServer) handlePhantomTCP(ctx context.Context, conn net.Conn) {
	// 读取完整数据包
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	// 处理数据包
	response, err := s.handler.HandlePacket(ctx, buf[:n], conn.RemoteAddr())
	if err != nil {
		s.log.Debug("Phantom TCP 处理错误: %v", err)
		return
	}

	if response != nil {
		conn.Write(response)
	}

	// 继续处理后续数据包
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}

		response, err := s.handler.HandlePacket(ctx, buf[:n], conn.RemoteAddr())
		if err != nil {
			s.log.Debug("Phantom TCP 处理错误: %v", err)
			continue
		}

		if response != nil {
			conn.Write(response)
		}
	}
}

// Stop 停止 TCP 服务器
func (s *TCPServer) Stop() {
	close(s.stopCh)
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	s.log.Info("TCP 服务器已停止")
}

// prefixConn 预读连接包装器
type prefixConn struct {
	net.Conn
	prefix []byte
	read   bool
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if !c.read && len(c.prefix) > 0 {
		c.read = true
		n := copy(b, c.prefix)
		if n < len(c.prefix) {
			c.prefix = c.prefix[n:]
			c.read = false
		}
		return n, nil
	}
	return c.Conn.Read(b)
}
