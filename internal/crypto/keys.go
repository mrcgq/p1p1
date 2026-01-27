
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// PSKLength 预共享密钥长度 (字节)
	PSKLength = 32

	// UserIDLength 用户ID长度 (字节)
	UserIDLength = 4

	// SessionKeyLength 会话密钥长度 (字节)
	SessionKeyLength = 32

	// StreamKeyLength 流密钥长度 (字节)
	StreamKeyLength = 32
)

// GeneratePSK 生成随机预共享密钥
func GeneratePSK() ([]byte, error) {
	psk := make([]byte, PSKLength)
	if _, err := rand.Read(psk); err != nil {
		return nil, fmt.Errorf("生成随机字节: %w", err)
	}
	return psk, nil
}

// EncodePSK 将 PSK 编码为 Base64 字符串
func EncodePSK(psk []byte) string {
	return base64.StdEncoding.EncodeToString(psk)
}

// DecodePSK 将 Base64 PSK 解码为字节
func DecodePSK(encoded string) ([]byte, error) {
	psk, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("解码 PSK: %w", err)
	}
	if len(psk) != PSKLength {
		return nil, fmt.Errorf("PSK 长度无效: 期望 %d, 实际 %d", PSKLength, len(psk))
	}
	return psk, nil
}

// DeriveUserID 从 PSK 派生 4 字节用户 ID
// 用于快速过滤无效数据包，无需解密
func DeriveUserID(psk []byte) [UserIDLength]byte {
	var userID [UserIDLength]byte

	reader := hkdf.New(sha256.New, psk, nil, []byte("phantom-user-id-v1.1"))
	if _, err := io.ReadFull(reader, userID[:]); err != nil {
		panic(fmt.Sprintf("HKDF 失败: %v", err))
	}

	return userID
}

// DeriveSessionKey 从 PSK 和时间窗口派生会话密钥
// 这是 TSKD (时间同步密钥派生) 的核心实现
func DeriveSessionKey(psk []byte, window int64) []byte {
	// 使用时间窗口作为盐值
	salt := make([]byte, 8)
	binary.BigEndian.PutUint64(salt, uint64(window))

	// 使用 HKDF 派生会话密钥
	reader := hkdf.New(sha256.New, psk, salt, []byte("phantom-session-key-v1.1"))

	sessionKey := make([]byte, SessionKeyLength)
	if _, err := io.ReadFull(reader, sessionKey); err != nil {
		panic(fmt.Sprintf("HKDF 失败: %v", err))
	}

	return sessionKey
}

// DeriveStreamKey 为特定流派生独立密钥
func DeriveStreamKey(sessionKey []byte, streamID uint32) []byte {
	salt := make([]byte, 4)
	binary.BigEndian.PutUint32(salt, streamID)

	reader := hkdf.New(sha256.New, sessionKey, salt, []byte("phantom-stream-key-v1.1"))

	streamKey := make([]byte, StreamKeyLength)
	if _, err := io.ReadFull(reader, streamKey); err != nil {
		panic(fmt.Sprintf("HKDF 失败: %v", err))
	}

	return streamKey
}

// DeriveNonceKey 派生 nonce 生成密钥
func DeriveNonceKey(psk []byte, window int64) []byte {
	salt := make([]byte, 8)
	binary.BigEndian.PutUint64(salt, uint64(window))

	reader := hkdf.New(sha256.New, psk, salt, []byte("phantom-nonce-key-v1.1"))

	nonceKey := make([]byte, 16)
	if _, err := io.ReadFull(reader, nonceKey); err != nil {
		panic(fmt.Sprintf("HKDF 失败: %v", err))
	}

	return nonceKey
}

// GenerateRandom 生成指定长度的随机字节
func GenerateRandom(length int) ([]byte, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("生成随机字节: %w", err)
	}
	return buf, nil
}

