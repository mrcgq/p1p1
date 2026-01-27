
package proxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// HTTPConfig HTTP 代理配置
type HTTPConfig struct {
	Username string
	Password string
	Timeout  time.Duration
}

// HTTPProxy HTTP 代理服务器
type HTTPProxy struct {
	config   HTTPConfig
	dialFunc DialFunc
}

// NewHTTPProxy 创建 HTTP 代理
func NewHTTPProxy(config HTTPConfig, dialFunc DialFunc) *HTTPProxy {
	return &HTTPProxy{
		config:   config,
		dialFunc: dialFunc,
	}
}

// Handle 处理 HTTP 代理请求
func (p *HTTPProxy) Handle(conn net.Conn) error {
	defer conn.Close()

	if p.config.Timeout > 0 {
		conn.SetDeadline(time.Now().Add(p.config.Timeout))
	}

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return fmt.Errorf("读取请求失败: %w", err)
	}

	// 认证检查
	if p.config.Username != "" || p.config.Password != "" {
		if !p.checkAuth(req) {
			p.sendAuthRequired(conn)
			return fmt.Errorf("认证失败")
		}
	}

	if req.Method == http.MethodConnect {
		return p.handleConnect(conn, req)
	}

	return p.handleHTTP(conn, req)
}

// checkAuth 检查认证
func (p *HTTPProxy) checkAuth(req *http.Request) bool {
	auth := req.Header.Get("Proxy-Authorization")
	if auth == "" {
		return false
	}

	if !strings.HasPrefix(auth, "Basic ") {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return false
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return false
	}

	return parts[0] == p.config.Username && parts[1] == p.config.Password
}

// sendAuthRequired 发送认证要求响应
func (p *HTTPProxy) sendAuthRequired(conn net.Conn) {
	response := "HTTP/1.1 407 Proxy Authentication Required\r\n"
	response += "Proxy-Authenticate: Basic realm=\"Phantom Proxy\"\r\n"
	response += "Content-Length: 0\r\n"
	response += "\r\n"
	conn.Write([]byte(response))
}

// handleConnect 处理 CONNECT 请求
func (p *HTTPProxy) handleConnect(conn net.Conn, req *http.Request) error {
	target, err := p.dialFunc("tcp", req.Host)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return fmt.Errorf("连接 %s 失败: %w", req.Host, err)
	}
	defer target.Close()

	// 发送成功响应
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

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

// handleHTTP 处理普通 HTTP 请求
func (p *HTTPProxy) handleHTTP(conn net.Conn, req *http.Request) error {
	// 确保有 Host
	if req.Host == "" {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return fmt.Errorf("缺少 Host")
	}

	// 确定目标地址
	targetAddr := req.Host
	if !strings.Contains(targetAddr, ":") {
		if req.URL.Scheme == "https" {
			targetAddr += ":443"
		} else {
			targetAddr += ":80"
		}
	}

	// 连接目标
	target, err := p.dialFunc("tcp", targetAddr)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return fmt.Errorf("连接 %s 失败: %w", targetAddr, err)
	}
	defer target.Close()

	// 移除代理相关的头
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")

	// 修改请求路径（从绝对路径变为相对路径）
	req.URL.Scheme = ""
	req.URL.Host = ""

	// 发送请求
	if err := req.Write(target); err != nil {
		return fmt.Errorf("发送请求失败: %w", err)
	}

	// 读取响应并发送给客户端
	_, err = io.Copy(conn, target)
	return err
}

// IsHTTPConnect 判断是否为 HTTP CONNECT 请求
func IsHTTPConnect(data []byte) bool {
	return len(data) >= 7 && string(data[:7]) == "CONNECT"
}

// IsHTTP 判断是否为 HTTP 请求
func IsHTTP(data []byte) bool {
	methods := []string{"GET ", "POST", "PUT ", "HEAD", "DELE", "OPTI", "PATC"}
	if len(data) < 4 {
		return false
	}
	prefix := string(data[:4])
	for _, m := range methods {
		if strings.HasPrefix(prefix, m[:min(len(prefix), len(m))]) {
			return true
		}
	}
	return IsHTTPConnect(data)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

