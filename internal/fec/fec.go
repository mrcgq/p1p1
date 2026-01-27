
package fec

import (
	"fmt"
	"sync"

	"github.com/klauspost/reedsolomon"
)

// FEC 实现 Reed-Solomon 前向纠错
type FEC struct {
	dataShards   int
	parityShards int
	encoder      reedsolomon.Encoder
	mu           sync.RWMutex
}

// New 创建新的 FEC 编码器/解码器
func New(dataShards, parityShards int) (*FEC, error) {
	if dataShards <= 0 || parityShards <= 0 {
		return nil, fmt.Errorf("分片数必须为正数")
	}
	if dataShards+parityShards > 256 {
		return nil, fmt.Errorf("分片总数不能超过 256")
	}

	encoder, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("创建 RS 编码器: %w", err)
	}

	return &FEC{
		dataShards:   dataShards,
		parityShards: parityShards,
		encoder:      encoder,
	}, nil
}

// TotalShards 返回分片总数
func (f *FEC) TotalShards() int {
	return f.dataShards + f.parityShards
}

// DataShards 返回数据分片数
func (f *FEC) DataShards() int {
	return f.dataShards
}

// ParityShards 返回冗余分片数
func (f *FEC) ParityShards() int {
	return f.parityShards
}

// Encode 将数据编码为数据分片 + 冗余分片
func (f *FEC) Encode(data []byte) ([][]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("数据不能为空")
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	// 计算分片大小（所有分片必须等长）
	shardSize := (len(data) + f.dataShards - 1) / f.dataShards

	// 创建分片
	shards := make([][]byte, f.TotalShards())
	for i := 0; i < f.TotalShards(); i++ {
		shards[i] = make([]byte, shardSize)
	}

	// 将数据复制到数据分片
	offset := 0
	for i := 0; i < f.dataShards; i++ {
		if offset >= len(data) {
			break
		}
		n := copy(shards[i], data[offset:])
		offset += n
	}

	// 生成冗余分片
	if err := f.encoder.Encode(shards); err != nil {
		return nil, fmt.Errorf("编码分片: %w", err)
	}

	return shards, nil
}

// Decode 从分片重建数据（部分分片可能为 nil/丢失）
func (f *FEC) Decode(shards [][]byte, dataLen int) ([]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if len(shards) != f.TotalShards() {
		return nil, fmt.Errorf("分片数量错误: 期望 %d, 实际 %d",
			f.TotalShards(), len(shards))
	}

	// 统计可用分片
	available := 0
	for _, shard := range shards {
		if shard != nil && len(shard) > 0 {
			available++
		}
	}

	// 需要至少 dataShards 个分片才能重建
	if available < f.dataShards {
		return nil, fmt.Errorf("分片不足: 需要 %d, 可用 %d",
			f.dataShards, available)
	}

	// 如果需要，进行重建
	if err := f.encoder.Reconstruct(shards); err != nil {
		return nil, fmt.Errorf("重建分片: %w", err)
	}

	// 验证重建结果
	ok, err := f.encoder.Verify(shards)
	if err != nil {
		return nil, fmt.Errorf("验证分片: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("分片验证失败")
	}

	// 合并数据分片
	data := make([]byte, 0, dataLen)
	for i := 0; i < f.dataShards; i++ {
		data = append(data, shards[i]...)
		if len(data) >= dataLen {
			break
		}
	}

	// 裁剪到原始长度
	if len(data) > dataLen {
		data = data[:dataLen]
	}

	return data, nil
}

// CanRecover 检查给定的分片是否足以恢复数据
func (f *FEC) CanRecover(shards [][]byte) bool {
	available := 0
	for _, shard := range shards {
		if shard != nil && len(shard) > 0 {
			available++
		}
	}
	return available >= f.dataShards
}

// MissingShards 返回缺失的分片索引
func (f *FEC) MissingShards(shards [][]byte) []int {
	missing := make([]int, 0)
	for i, shard := range shards {
		if shard == nil || len(shard) == 0 {
			missing = append(missing, i)
		}
	}
	return missing
}

// RecoveryInfo 恢复信息
type RecoveryInfo struct {
	TotalShards   int
	DataShards    int
	ParityShards  int
	ReceivedCount int
	MissingCount  int
	CanRecover    bool
	RecoveredFrom int // 从多少个丢失分片恢复
}

// GetRecoveryInfo 获取恢复信息
func (f *FEC) GetRecoveryInfo(shards [][]byte) RecoveryInfo {
	received := 0
	for _, shard := range shards {
		if shard != nil && len(shard) > 0 {
			received++
		}
	}

	missing := f.TotalShards() - received
	canRecover := received >= f.dataShards

	return RecoveryInfo{
		TotalShards:   f.TotalShards(),
		DataShards:    f.dataShards,
		ParityShards:  f.parityShards,
		ReceivedCount: received,
		MissingCount:  missing,
		CanRecover:    canRecover,
		RecoveredFrom: min(missing, f.parityShards),
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

