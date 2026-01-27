package cloudflare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client Cloudflare API 客户端
type Client struct {
	token   string
	zoneID  string
	baseURL string
	http    *http.Client
}

// NewClient 创建新的 Cloudflare 客户端
func NewClient(token, zoneID string) *Client {
	return &Client{
		token:   token,
		zoneID:  zoneID,
		baseURL: "https://api.cloudflare.com/client/v4",
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// DNSRecord DNS 记录
type DNSRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

// APIResponse API 响应
type APIResponse struct {
	Success bool        `json:"success"`
	Errors  []APIError  `json:"errors"`
	Result  interface{} `json:"result"`
}

// APIError API 错误
type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// CreateOrUpdateDNS 创建或更新 DNS 记录
func (c *Client) CreateOrUpdateDNS(record *DNSRecord) error {
	// 首先查找是否存在
	existing, err := c.FindDNSRecord(record.Type, record.Name)
	if err != nil {
		return err
	}

	if existing != nil {
		// 更新现有记录
		return c.UpdateDNSRecord(existing.ID, record)
	}

	// 创建新记录
	return c.CreateDNSRecord(record)
}

// FindDNSRecord 查找 DNS 记录
func (c *Client) FindDNSRecord(recordType, name string) (*DNSRecord, error) {
	url := fmt.Sprintf("%s/zones/%s/dns_records?type=%s&name=%s",
		c.baseURL, c.zoneID, recordType, name)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	c.setHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Success bool        `json:"success"`
		Result  []DNSRecord `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if !result.Success || len(result.Result) == 0 {
		return nil, nil
	}

	return &result.Result[0], nil
}

// CreateDNSRecord 创建 DNS 记录
func (c *Client) CreateDNSRecord(record *DNSRecord) error {
	url := fmt.Sprintf("%s/zones/%s/dns_records", c.baseURL, c.zoneID)

	body, err := json.Marshal(record)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}

	c.setHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return c.checkResponse(resp)
}

// UpdateDNSRecord 更新 DNS 记录
func (c *Client) UpdateDNSRecord(id string, record *DNSRecord) error {
	url := fmt.Sprintf("%s/zones/%s/dns_records/%s", c.baseURL, c.zoneID, id)

	body, err := json.Marshal(record)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", url, bytes.NewReader(body))
	if err != nil {
		return err
	}

	c.setHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return c.checkResponse(resp)
}

// setHeaders 设置请求头
func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
}

// checkResponse 检查响应
func (c *Client) checkResponse(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("API 错误 (%d): %s", resp.StatusCode, string(body))
}
