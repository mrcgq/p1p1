
package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// NonceSize ChaCha20-Poly1305 的 nonce 大小
	NonceSize = chacha20poly1305.NonceSize // 12 字节

	// TagSize 认证标签大小
	TagSize = chacha20poly1305.Overhead // 16 字节

	// KeySize 加密密钥大小
	KeySize = chacha20poly1305.KeySize // 32 字节
)

// AEAD 封装 ChaCha20-Poly1305 AEAD
type AEAD struct {
	aead     cipher.AEAD
	nonceSeq uint64 // 用于顺序 nonce 生成
}

// NewAEAD 创建新的 ChaCha20-Poly1305 AEAD 实例
func NewAEAD(key []byte) (*AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("密钥长度无效: 期望 %d, 实际 %d", KeySize, len(key))
	}
	
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("创建 AEAD: %w", err)
	}
	
	return &AEAD{aead: aead}, nil
}

// GenerateNonce 生成随机 nonce
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("生成 nonce: %w", err)
	}
	return nonce, nil
}

// Encrypt 加密明文
// 返回: 密文 + 认证标签
func (a *AEAD) Encrypt(nonce, plaintext, additionalData []byte) []byte {
	return a.aead.Seal(nil, nonce, plaintext, additionalData)
}

// Decrypt 解密密文
// 如果认证失败返回错误
func (a *AEAD) Decrypt(nonce, ciphertext, additionalData []byte) ([]byte, error) {
	plaintext, err := a.aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("解密失败: %w", err)
	}
	return plaintext, nil
}

// EncryptPacket 加密完整数据包（包含随机 nonce）
// 返回: nonce + 密文 + 认证标签
func (a *AEAD) EncryptPacket(plaintext []byte) ([]byte, error) {
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, err
	}

	// 预分配缓冲区: nonce + 密文 + 标签
	result := make([]byte, NonceSize+len(plaintext)+TagSize)
	copy(result[:NonceSize], nonce)

	// 原地加密
	a.aead.Seal(result[NonceSize:NonceSize], nonce, plaintext, nil)

	return result, nil
}

// DecryptPacket 解密完整数据包
// 输入: nonce + 密文 + 认证标签
// 返回: 明文
func (a *AEAD) DecryptPacket(packet []byte) ([]byte, error) {
	if len(packet) < NonceSize+TagSize {
		return nil, fmt.Errorf("数据包过短: 长度 %d", len(packet))
	}

	nonce := packet[:NonceSize]
	ciphertext := packet[NonceSize:]

	return a.Decrypt(nonce, ciphertext, nil)
}

// EncryptWithAD 带附加数据的加密
func (a *AEAD) EncryptWithAD(plaintext, additionalData []byte) ([]byte, error) {
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, err
	}

	result := make([]byte, NonceSize+len(plaintext)+TagSize)
	copy(result[:NonceSize], nonce)
	a.aead.Seal(result[NonceSize:NonceSize], nonce, plaintext, additionalData)

	return result, nil
}

// DecryptWithAD 带附加数据的解密
func (a *AEAD) DecryptWithAD(packet, additionalData []byte) ([]byte, error) {
	if len(packet) < NonceSize+TagSize {
		return nil, fmt.Errorf("数据包过短: 长度 %d", len(packet))
	}

	nonce := packet[:NonceSize]
	ciphertext := packet[NonceSize:]

	return a.Decrypt(nonce, ciphertext, additionalData)
}

// Overhead 返回加密开销
func (a *AEAD) Overhead() int {
	return NonceSize + TagSize
}

