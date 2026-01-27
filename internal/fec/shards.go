package fec

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/klauspost/reedsolomon"
)

const (
	// ShardHeaderSize 分片头大小
	// groupID(4) + index(1) + total(1) + parity(1) + reserved(1) + dataLen(2) + timestamp(4)
	ShardHeaderSize = 14
)

// ShardHeader 表示 FEC 分片的头部
type ShardHeader struct {
	GroupID   uint32 // 标识此分片所属的组
	Index     uint8  // 分片索引（0 = 第一个数据分片）
	Total     uint8  // 组中分片总数
	Parity    uint8  // 冗余分片数（用于解码）
	Reserved  uint8  // 保留字段
	DataLen   uint16 // 原始数据长度
	Timestamp uint32 // 时间戳（低 32 位）
}

// ParseShardHeader 从字节解析分片头
func ParseShardHeader(data []byte) (*ShardHeader, error) {
	if len(data) < ShardHeaderSize {
		return nil, fmt.Errorf("数据过短，无法解析分片头")
	}

	return &ShardHeader{
		GroupID:   binary.BigEndian.Uint32(data[0:4]),
		Index:     data[4],
		Total:     data[5],
		Parity:    data[6],
		Reserved:  data[7],
		DataLen:   binary.BigEndian.Uint16(data[8:10]),
		Timestamp: binary.BigEndian.Uint32(data[10:14]),
	}, nil
}

// Serialize 序列化分片头为字节
func (h *ShardHeader) Serialize() []byte {
	buf := make([]byte, ShardHeaderSize)
	binary.BigEndian.PutUint32(buf[0:4], h.GroupID)
	buf[4] = h.Index
	buf[5] = h.Total
	buf[6] = h.Parity
	buf[7] = h.Reserved
	binary.BigEndian.PutUint16(buf[8:10], h.DataLen)
	binary.BigEndian.PutUint32(buf[10:14], h.Timestamp)
	return buf
}

// DataShards 返回数据分片数
func (h *ShardHeader) DataShards() int {
	return int(h.Total) - int(h.Parity)
}

// ShardGroup 收集用于重建的分片
type ShardGroup struct {
	GroupID   uint32
	Shards    [][]byte
	DataLen   int
	Parity    int
	Received  int
	Created   time.Time
	Completed bool
	Timestamp uint32
}

// ShardCollector 收集并重建 FEC 分片组
type ShardCollector struct {
	adaptiveFEC *AdaptiveFEC
	staticFEC   *FEC
	useAdaptive bool

	groups  map[uint32]*ShardGroup
	timeout time.Duration

	// 统计
	totalGroups     uint64
	completedGroups uint64
	failedGroups    uint64

	mu sync.Mutex
}

// NewShardCollector 创建新的分片收集器
func NewShardCollector(timeout time.Duration) *ShardCollector {
	return &ShardCollector{
		groups:  make(map[uint32]*ShardGroup),
		timeout: timeout,
	}
}

// NewShardCollectorWithAdaptive 创建带自适应 FEC 的分片收集器
func NewShardCollectorWithAdaptive(af *AdaptiveFEC, timeout time.Duration) *ShardCollector {
	return &ShardCollector{
		adaptiveFEC: af,
		useAdaptive: true,
		groups:      make(map[uint32]*ShardGroup),
		timeout:     timeout,
	}
}

// NewShardCollectorWithStatic 创建带静态 FEC 的分片收集器
func NewShardCollectorWithStatic(fec *FEC, timeout time.Duration) *ShardCollector {
	return &ShardCollector{
		staticFEC: fec,
		groups:    make(map[uint32]*ShardGroup),
		timeout:   timeout,
	}
}

// AddShard 添加分片并尝试重建
// 如果重建成功返回重建的数据，否则返回 nil
func (c *ShardCollector) AddShard(data []byte) ([]byte, error) {
	if len(data) < ShardHeaderSize {
		return nil, fmt.Errorf("分片过短")
	}

	header, err := ParseShardHeader(data)
	if err != nil {
		return nil, err
	}

	shardData := data[ShardHeaderSize:]

	c.mu.Lock()
	defer c.mu.Unlock()

	// 获取或创建组
	group, exists := c.groups[header.GroupID]
	if !exists {
		group = &ShardGroup{
			GroupID:   header.GroupID,
			Shards:    make([][]byte, header.Total),
			DataLen:   int(header.DataLen),
			Parity:    int(header.Parity),
			Created:   time.Now(),
			Timestamp: header.Timestamp,
		}
		c.groups[header.GroupID] = group
		c.totalGroups++
	}

	// 检查是否已完成
	if group.Completed {
		return nil, nil
	}

	// 验证索引
	if int(header.Index) >= len(group.Shards) {
		return nil, fmt.Errorf("分片索引超出范围: %d >= %d", header.Index, len(group.Shards))
	}

	// 添加分片（如果尚未收到）
	if group.Shards[header.Index] == nil {
		group.Shards[header.Index] = make([]byte, len(shardData))
		copy(group.Shards[header.Index], shardData)
		group.Received++
	}

	// 计算需要的数据分片数
	dataShards := header.DataShards()

	// 如果有足够的分片，尝试重建
	if group.Received >= dataShards {
		var reconstructed []byte
		var recErr error

		if c.useAdaptive && c.adaptiveFEC != nil {
			reconstructed, recErr = c.adaptiveFEC.Decode(group.Shards, group.DataLen, group.Parity)
		} else if c.staticFEC != nil {
			reconstructed, recErr = c.staticFEC.Decode(group.Shards, group.DataLen)
		} else {
			// 创建临时 FEC 解码器
			fec, fecErr := New(dataShards, group.Parity)
			if fecErr != nil {
				return nil, fmt.Errorf("创建解码器: %w", fecErr)
			}
			reconstructed, recErr = fec.Decode(group.Shards, group.DataLen)
		}

		if recErr == nil {
			group.Completed = true
			c.completedGroups++
			return reconstructed, nil
		}
	}

	return nil, nil
}

// Cleanup 删除过期的组
func (c *ShardCollector) Cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	count := 0

	for id, group := range c.groups {
		if now.Sub(group.Created) > c.timeout {
			if !group.Completed {
				c.failedGroups++
			}
			delete(c.groups, id)
			count++
		}
	}

	return count
}

// CollectorStats 返回收集器统计信息
type CollectorStats struct {
	PendingGroups   int
	CompletedGroups uint64
	FailedGroups    uint64
	TotalGroups     uint64
}

// Stats 获取统计
func (c *ShardCollector) Stats() CollectorStats {
	c.mu.Lock()
	defer c.mu.Unlock()

	pending := 0
	for _, group := range c.groups {
		if !group.Completed {
			pending++
		}
	}

	return CollectorStats{
		PendingGroups:   pending,
		CompletedGroups: c.completedGroups,
		FailedGroups:    c.failedGroups,
		TotalGroups:     c.totalGroups,
	}
}

// FECEncoder 封装带有数据包帧的 FEC（支持自适应和静态模式）
type FECEncoder struct {
	adaptiveFEC *AdaptiveFEC
	staticFEC   *FEC
	useAdaptive bool

	groupID uint32
	mu      sync.Mutex
}

// NewFECEncoder 创建静态模式 FEC 编码器
func NewFECEncoder(dataShards, parityShards int) (*FECEncoder, error) {
	fec, err := New(dataShards, parityShards)
	if err != nil {
		return nil, err
	}
	return &FECEncoder{staticFEC: fec}, nil
}

// NewAdaptiveFECEncoder 创建自适应模式 FEC 编码器
func NewAdaptiveFECEncoder(config AdaptiveConfig) (*FECEncoder, error) {
	af, err := NewAdaptiveFEC(config)
	if err != nil {
		return nil, err
	}
	return &FECEncoder{
		adaptiveFEC: af,
		useAdaptive: true,
	}, nil
}

// Encode 将数据编码为带头部的多个分片
func (e *FECEncoder) Encode(data []byte) ([][]byte, error) {
	e.mu.Lock()
	e.groupID++
	groupID := e.groupID
	e.mu.Unlock()

	var shards [][]byte
	var parity int
	var err error

	if e.useAdaptive && e.adaptiveFEC != nil {
		shards, parity, err = e.adaptiveFEC.Encode(data)
	} else if e.staticFEC != nil {
		shards, err = e.staticFEC.Encode(data)
		parity = e.staticFEC.ParityShards()
	} else {
		return nil, fmt.Errorf("未初始化 FEC")
	}

	if err != nil {
		return nil, err
	}

	// 为每个分片添加头部
	timestamp := uint32(time.Now().Unix() & 0xFFFFFFFF)
	result := make([][]byte, len(shards))

	for i, shard := range shards {
		header := &ShardHeader{
			GroupID:   groupID,
			Index:     uint8(i),
			Total:     uint8(len(shards)),
			Parity:    uint8(parity),
			DataLen:   uint16(len(data)),
			Timestamp: timestamp,
		}
		result[i] = append(header.Serialize(), shard...)
	}

	return result, nil
}

// Start 启动自适应调整（如果使用自适应模式）
func (e *FECEncoder) Start(ctx context.Context) {
	if e.useAdaptive && e.adaptiveFEC != nil {
		e.adaptiveFEC.Start(ctx)
	}
}

// RecordRTT 记录 RTT
func (e *FECEncoder) RecordRTT(rtt time.Duration) {
	if e.useAdaptive && e.adaptiveFEC != nil {
		e.adaptiveFEC.RecordRTT(rtt)
	}
}

// GetCurrentParity 获取当前冗余分片数
func (e *FECEncoder) GetCurrentParity() int {
	if e.useAdaptive && e.adaptiveFEC != nil {
		return e.adaptiveFEC.GetCurrentParity()
	}
	if e.staticFEC != nil {
		return e.staticFEC.ParityShards()
	}
	return 0
}

// GetDataShards 获取数据分片数
func (e *FECEncoder) GetDataShards() int {
	if e.useAdaptive && e.adaptiveFEC != nil {
		return e.adaptiveFEC.GetDataShards()
	}
	if e.staticFEC != nil {
		return e.staticFEC.DataShards()
	}
	return 0
}

// IsAdaptive 是否为自适应模式
func (e *FECEncoder) IsAdaptive() bool {
	return e.useAdaptive
}

// 确保使用了 reedsolomon 包（避免未使用导入错误）
var _ reedsolomon.Encoder = nil
