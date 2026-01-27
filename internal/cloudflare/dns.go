package cloudflare

import (
	"fmt"
)

// DNSManager DNS 管理器
type DNSManager struct {
	client *Client
	domain string
}

// NewDNSManager 创建 DNS 管理器
func NewDNSManager(token, zoneID, domain string) *DNSManager {
	return &DNSManager{
		client: NewClient(token, zoneID),
		domain: domain,
	}
}

// SetupARecord 设置 A 记录
func (m *DNSManager) SetupARecord(ip string) error {
	record := &DNSRecord{
		Type:    "A",
		Name:    m.domain,
		Content: ip,
		TTL:     120,
		Proxied: false,
	}

	return m.client.CreateOrUpdateDNS(record)
}

// SetupAAAARecord 设置 AAAA 记录
func (m *DNSManager) SetupAAAARecord(ip string) error {
	record := &DNSRecord{
		Type:    "AAAA",
		Name:    m.domain,
		Content: ip,
		TTL:     120,
		Proxied: false,
	}

	return m.client.CreateOrUpdateDNS(record)
}

// Verify 验证 DNS 配置
func (m *DNSManager) Verify() error {
	record, err := m.client.FindDNSRecord("A", m.domain)
	if err != nil {
		return fmt.Errorf("验证 DNS: %w", err)
	}
	if record == nil {
		return fmt.Errorf("DNS 记录不存在")
	}
	return nil
}
