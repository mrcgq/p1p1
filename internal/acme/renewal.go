package acme

import (
	"os/exec"
	"time"
)

// RenewalManager 证书续期管理器
type RenewalManager struct {
	certPath string
	keyPath  string
	domain   string
	interval time.Duration
	stopCh   chan struct{}
}

// NewRenewalManager 创建续期管理器
func NewRenewalManager(certPath, keyPath, domain string) *RenewalManager {
	return &RenewalManager{
		certPath: certPath,
		keyPath:  keyPath,
		domain:   domain,
		interval: 24 * time.Hour,
		stopCh:   make(chan struct{}),
	}
}

// Start 启动自动续期
func (m *RenewalManager) Start() {
	go m.renewLoop()
}

// Stop 停止自动续期
func (m *RenewalManager) Stop() {
	close(m.stopCh)
}

// renewLoop 续期循环
func (m *RenewalManager) renewLoop() {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.tryRenew()
		case <-m.stopCh:
			return
		}
	}
}

// tryRenew 尝试续期
func (m *RenewalManager) tryRenew() error {
	// 尝试 certbot
	if _, err := exec.LookPath("certbot"); err == nil {
		cmd := exec.Command("certbot", "renew", "--quiet")
		if err := cmd.Run(); err == nil {
			return nil
		}
	}

	// 尝试 acme.sh
	if _, err := exec.LookPath("acme.sh"); err == nil {
		cmd := exec.Command("acme.sh", "--renew", "-d", m.domain)
		return cmd.Run()
	}

	return nil
}
