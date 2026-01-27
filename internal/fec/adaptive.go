
package fec

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/klauspost/reedsolomon"
)

// AdaptiveConfig 自适应 FEC 配置
type AdaptiveConfig struct {
	DataShards     int           // 固定的数据分片数
	MinParity      int           // 最小冗余分片数
	MaxParity      int           // 最大冗余分片数
	InitialParity  int           // 初始冗余分片数
	TargetLossRate float64       // 目标丢包恢复率 (0-1)
	AdjustInterval time.Duration // 调整间隔
	
	// 调整策略参数
	IncreaseThreshold float64 // 增加冗余的丢包率阈值
	DecreaseThreshold float64 // 减少冗余的丢包率阈值
	StepUp            int     // 每次增加的分片数
	StepDown          int     // 每次减少的分片数
}

// DefaultAdaptiveConfig 默认自适应配置
func DefaultAdaptiveConfig() AdaptiveConfig {
	return AdaptiveConfig{
		DataShards:        10,
		MinParity:         1,
		MaxParity:         8,
		InitialParity:     3,
		TargetLossRate:    0.01,
		AdjustInterval:    5 * time.Second,
		IncreaseThreshold: 0.05, // 5% 丢包率时增加
		DecreaseThreshold: 0.01, // 1% 丢包率时减少
		StepUp:            1,
		StepDown:          1,
	}
}

// AdaptiveFEC 自适应前向纠错
type AdaptiveFEC struct {
	config    AdaptiveConfig
	estimator *LossEstimator

	// 当前编码器
	currentParity int
	encoder       reedsolomon.Encoder

	// 编码器缓存（避免频繁创建）
	encoderCache map[int]reedsolomon.Encoder

	// 统计
	adjustCount  int
	lastAdjust   time.Time
	parityHistory []parityRecord

	mu sync.RWMutex
}

// parityRecord 冗余调整记录
type parityRecord struct {
	Timestamp time.Time
	OldParity int
	NewParity int
	LossRate  float64
	Reason    string
}

// NewAdaptiveFEC 创建自适应 FEC
func NewAdaptiveFEC(config AdaptiveConfig) (*AdaptiveFEC, error) {
	if config.MinParity < 1 {
		config.MinParity = 1
	}
	if config.MaxParity < config.MinParity {
		config.MaxParity = config.MinParity
	}
	if config.InitialParity < config.MinParity {
		config.InitialParity = config.MinParity
	}
	if config.InitialParity > config.MaxParity {
		config.InitialParity = config.MaxParity
	}

	encoder, err := reedsolomon.New(config.DataShards, config.InitialParity)
	if err != nil {
		return nil, fmt.Errorf("创建初始编码器: %w", err)
	}

	af := &AdaptiveFEC{
		config:        config,
		estimator:     NewLossEstimator(),
		currentParity: config.InitialParity,
		encoder:       encoder,
		encoderCache:  make(map[int]reedsolomon.Encoder),
		lastAdjust:    time.Now(),
		parityHistory: make([]parityRecord, 0, 100),
	}

	// 预创建编码器缓存
	for p := config.MinParity; p <= config.MaxParity; p++ {
		enc, err := reedsolomon.New(config.DataShards, p)
		if err != nil {
			return nil, fmt.Errorf("创建编码器 (parity=%d): %w", p, err)
		}
		af.encoderCache[p] = enc
	}

	return af, nil
}

// Start 启动自适应调整
func (af *AdaptiveFEC) Start(ctx context.Context) {
	go af.adjustLoop(ctx)
}

// adjustLoop 调整循环
func (af *AdaptiveFEC) adjustLoop(ctx context.Context) {
	ticker := time.NewTicker(af.config.AdjustInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			af.adjust()
		}
	}
}

// adjust 执行一次调整
func (af *AdaptiveFEC) adjust() {
	af.mu.Lock()
	defer af.mu.Unlock()

	lossRate := af.estimator.GetLossRate()
	oldParity := af.currentParity
	newParity := oldParity
	reason := ""

	// 决定是否调整
	if lossRate > af.config.IncreaseThreshold {
		// 丢包率过高，增加冗余
		newParity = min(oldParity+af.config.StepUp, af.config.MaxParity)
		reason = fmt.Sprintf("丢包率 %.2f%% > %.2f%%", lossRate*100, af.config.IncreaseThreshold*100)
	} else if lossRate < af.config.DecreaseThreshold && oldParity > af.config.MinParity {
		// 丢包率很低，可以减少冗余
		newParity = max(oldParity-af.config.StepDown, af.config.MinParity)
		reason = fmt.Sprintf("丢包率 %.2f%% < %.2f%%", lossRate*100, af.config.DecreaseThreshold*100)
	}

	if newParity != oldParity {
		// 更新编码器
		if enc, ok := af.encoderCache[newParity]; ok {
			af.encoder = enc
			af.currentParity = newParity
			af.adjustCount++
			af.lastAdjust = time.Now()

			// 记录历史
			record := parityRecord{
				Timestamp: time.Now(),
				OldParity: oldParity,
				NewParity: newParity,
				LossRate:  lossRate,
				Reason:    reason,
			}
			af.parityHistory = append(af.parityHistory, record)

			// 保留最近 100 条记录
			if len(af.parityHistory) > 100 {
				af.parityHistory = af.parityHistory[1:]
			}
		}
	}
}

// Encode 编码数据
func (af *AdaptiveFEC) Encode(data []byte) ([][]byte, int, error) {
	if len(data) == 0 {
		return nil, 0, fmt.Errorf("数据不能为空")
	}

	af.mu.RLock()
	encoder := af.encoder
	currentParity := af.currentParity
	dataShards := af.config.DataShards
	af.mu.RUnlock()

	totalShards := dataShards + currentParity

	// 计算分片大小
	shardSize := (len(data) + dataShards - 1) / dataShards

	// 创建分片
	shards := make([][]byte, totalShards)
	for i := 0; i < totalShards; i++ {
		shards[i] = make([]byte, shardSize)
	}

	// 复制数据
	offset := 0
	for i := 0; i < dataShards; i++ {
		if offset >= len(data) {
			break
		}
		n := copy(shards[i], data[offset:])
		offset += n
	}

	// 编码
	if err := encoder.Encode(shards); err != nil {
		return nil, 0, fmt.Errorf("编码: %w", err)
	}

	// 记录发送
	af.estimator.RecordSent(uint64(totalShards))

	return shards, currentParity, nil
}

// Decode 解码数据
func (af *AdaptiveFEC) Decode(shards [][]byte, dataLen int, parityUsed int) ([]byte, error) {
	af.mu.RLock()
	dataShards := af.config.DataShards
	af.mu.RUnlock()

	totalShards := dataShards + parityUsed

	if len(shards) != totalShards {
		return nil, fmt.Errorf("分片数量错误: 期望 %d, 实际 %d", totalShards, len(shards))
	}

	// 获取对应的编码器
	encoder, ok := af.encoderCache[parityUsed]
	if !ok {
		var err error
		encoder, err = reedsolomon.New(dataShards, parityUsed)
		if err != nil {
			return nil, fmt.Errorf("创建解码器: %w", err)
		}
	}

	// 统计丢失的分片
	received := 0
	for _, shard := range shards {
		if shard != nil && len(shard) > 0 {
			received++
		}
	}
	lost := totalShards - received

	// 记录接收和丢失
	af.estimator.RecordReceived(uint64(received))
	if lost > 0 {
		af.estimator.RecordLost(uint64(lost))
	}

	// 检查是否可恢复
	if received < dataShards {
		af.estimator.RecordRecovered(0) // 恢复失败
		return nil, fmt.Errorf("分片不足: 需要 %d, 可用 %d", dataShards, received)
	}

	// 重建
	if err := encoder.Reconstruct(shards); err != nil {
		return nil, fmt.Errorf("重建: %w", err)
	}

	// 验证
	ok, err := encoder.Verify(shards)
	if err != nil {
		return nil, fmt.Errorf("验证: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("验证失败")
	}

	// 记录成功恢复
	if lost > 0 {
		af.estimator.RecordRecovered(uint64(lost))
	}

	// 合并数据
	data := make([]byte, 0, dataLen)
	for i := 0; i < dataShards; i++ {
		data = append(data, shards[i]...)
		if len(data) >= dataLen {
			break
		}
	}

	if len(data) > dataLen {
		data = data[:dataLen]
	}

	return data, nil
}

// RecordRTT 记录 RTT
func (af *AdaptiveFEC) RecordRTT(rtt time.Duration) {
	af.estimator.RecordRTT(rtt)
}

// GetCurrentParity 获取当前冗余分片数
func (af *AdaptiveFEC) GetCurrentParity() int {
	af.mu.RLock()
	defer af.mu.RUnlock()
	return af.currentParity
}

// GetDataShards 获取数据分片数
func (af *AdaptiveFEC) GetDataShards() int {
	return af.config.DataShards
}

// GetEstimator 获取估算器
func (af *AdaptiveFEC) GetEstimator() *LossEstimator {
	return af.estimator
}

// AdaptiveStats 自适应统计
type AdaptiveStats struct {
	CurrentParity int
	DataShards    int
	LossRate      float64
	RTT           time.Duration
	AdjustCount   int
	LastAdjust    time.Time
	History       []parityRecord
}

// Stats 获取统计
func (af *AdaptiveFEC) Stats() AdaptiveStats {
	af.mu.RLock()
	defer af.mu.RUnlock()

	snapshot := af.estimator.Snapshot()

	history := make([]parityRecord, len(af.parityHistory))
	copy(history, af.parityHistory)

	return AdaptiveStats{
		CurrentParity: af.currentParity,
		DataShards:    af.config.DataShards,
		LossRate:      snapshot.LossRate,
		RTT:           snapshot.RTT,
		AdjustCount:   af.adjustCount,
		LastAdjust:    af.lastAdjust,
		History:       history,
	}
}

// SetParity 手动设置冗余分片数（用于测试或覆盖）
func (af *AdaptiveFEC) SetParity(parity int) error {
	if parity < af.config.MinParity || parity > af.config.MaxParity {
		return fmt.Errorf("冗余分片数超出范围 [%d, %d]",
			af.config.MinParity, af.config.MaxParity)
	}

	af.mu.Lock()
	defer af.mu.Unlock()

	if enc, ok := af.encoderCache[parity]; ok {
		af.encoder = enc
		af.currentParity = parity
	}

	return nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}


