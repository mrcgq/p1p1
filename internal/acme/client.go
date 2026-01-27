package acme

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Client ACME 客户端
type Client struct {
	email    string
	domain   string
	certDir  string
	cfToken  string
	cfZoneID string
}

// NewClient 创建 ACME 客户端
func NewClient(email, domain, certDir string) *Client {
	return &Client{
		email:   email,
		domain:  domain,
		certDir: certDir,
	}
}

// SetCloudflare 设置 Cloudflare 凭据
func (c *Client) SetCloudflare(token, zoneID string) {
	c.cfToken = token
	c.cfZoneID = zoneID
}

// ObtainCertificate 获取证书
func (c *Client) ObtainCertificate() (certPath, keyPath string, err error) {
	// 创建证书目录
	if err := os.MkdirAll(c.certDir, 0755); err != nil {
		return "", "", fmt.Errorf("创建证书目录: %w", err)
	}

	certPath = filepath.Join(c.certDir, "cert.pem")
	keyPath = filepath.Join(c.certDir, "key.pem")

	// 检查是否已有证书
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return certPath, keyPath, nil
		}
	}

	// 尝试使用 certbot
	if err := c.tryCertbot(certPath, keyPath); err == nil {
		return certPath, keyPath, nil
	}

	// 尝试使用 acme.sh
	if err := c.tryAcmeSh(certPath, keyPath); err == nil {
		return certPath, keyPath, nil
	}

	// 生成自签名证书
	return c.generateSelfSigned(certPath, keyPath)
}

// tryCertbot 尝试使用 certbot
func (c *Client) tryCertbot(certPath, keyPath string) error {
	if _, err := exec.LookPath("certbot"); err != nil {
		return err
	}

	cmd := exec.Command("certbot", "certonly",
		"--standalone",
		"--non-interactive",
		"--agree-tos",
		"--email", c.email,
		"-d", c.domain,
	)

	return cmd.Run()
}

// tryAcmeSh 尝试使用 acme.sh
func (c *Client) tryAcmeSh(certPath, keyPath string) error {
	if _, err := exec.LookPath("acme.sh"); err != nil {
		return err
	}

	cmd := exec.Command("acme.sh", "--issue",
		"--standalone",
		"-d", c.domain,
		"--fullchain-file", certPath,
		"--key-file", keyPath,
	)

	if c.cfToken != "" {
		cmd.Env = append(os.Environ(),
			"CF_Token="+c.cfToken,
			"CF_Zone_ID="+c.cfZoneID,
		)
		cmd = exec.Command("acme.sh", "--issue",
			"--dns", "dns_cf",
			"-d", c.domain,
			"--fullchain-file", certPath,
			"--key-file", keyPath,
		)
	}

	return cmd.Run()
}

// generateSelfSigned 生成自签名证书
func (c *Client) generateSelfSigned(certPath, keyPath string) (string, string, error) {
	cmd := exec.Command("openssl", "req", "-x509", "-nodes",
		"-days", "365",
		"-newkey", "rsa:2048",
		"-keyout", keyPath,
		"-out", certPath,
		"-subj", fmt.Sprintf("/CN=%s", c.domain),
	)

	if err := cmd.Run(); err != nil {
		return "", "", fmt.Errorf("生成自签名证书: %w", err)
	}

	return certPath, keyPath, nil
}
