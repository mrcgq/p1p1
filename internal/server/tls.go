package server

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/anthropics/phantom-server/internal/logger"
)

// TLSManager 管理 TLS 证书
type TLSManager struct {
	certFile string
	keyFile  string
	log      *logger.Logger

	cert      *tls.Certificate
	certMtime time.Time
	keyMtime  time.Time

	mu sync.RWMutex
}

// NewTLSManager 创建新的 TLS 管理器
func NewTLSManager(certFile, keyFile string, log *logger.Logger) *TLSManager {
	return &TLSManager{
		certFile: certFile,
		keyFile:  keyFile,
		log:      log,
	}
}

// LoadCertificate 加载证书
func (m *TLSManager) LoadCertificate() (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cert, err := tls.LoadX509KeyPair(m.certFile, m.keyFile)
	if err != nil {
		return nil, fmt.Errorf("加载证书: %w", err)
	}

	// 记录文件修改时间
	if certInfo, err := os.Stat(m.certFile); err == nil {
		m.certMtime = certInfo.ModTime()
	}
	if keyInfo, err := os.Stat(m.keyFile); err == nil {
		m.keyMtime = keyInfo.ModTime()
	}

	m.cert = &cert
	return &cert, nil
}

// GetCertificate 获取当前证书（用于 tls.Config.GetCertificate）
func (m *TLSManager) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	cert := m.cert
	m.mu.RUnlock()

	if cert == nil {
		return m.LoadCertificate()
	}
	return cert, nil
}

// CheckAndReload 检查证书文件是否更新，如果更新则重新加载
func (m *TLSManager) CheckAndReload() (bool, error) {
	certInfo, err := os.Stat(m.certFile)
	if err != nil {
		return false, fmt.Errorf("检查证书文件: %w", err)
	}

	keyInfo, err := os.Stat(m.keyFile)
	if err != nil {
		return false, fmt.Errorf("检查密钥文件: %w", err)
	}

	m.mu.RLock()
	needReload := certInfo.ModTime().After(m.certMtime) || keyInfo.ModTime().After(m.keyMtime)
	m.mu.RUnlock()

	if needReload {
		if _, err := m.LoadCertificate(); err != nil {
			return false, err
		}
		m.log.Info("TLS 证书已重新加载")
		return true, nil
	}

	return false, nil
}

// StartAutoReload 启动自动重载
func (m *TLSManager) StartAutoReload(stopCh <-chan struct{}) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if _, err := m.CheckAndReload(); err != nil {
				m.log.Error("证书重载失败: %v", err)
			}
		case <-stopCh:
			return
		}
	}
}

// BuildTLSConfig 构建 TLS 配置
func (m *TLSManager) BuildTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}
}
