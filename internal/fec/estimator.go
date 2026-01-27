
package fec

import (
	"math"
	"sync"
	"time"
)

// PacketStats 数据包统计
type PacketStats struct {
	Sent      uint64
	Received  uint64
	Lost      uint64
	Recovered uint64
}

// LossEstimator 丢包率估算器
// 使用指数加权移动平均 (EWMA) 算法
type LossEstimator struct {
	// EWMA 参数
	alpha float64 // 平滑因子 (0-1)

	// 当前估计值
	lossRate    float64
	jitter      float64
	rtt         time.Duration
	bandwidth   float64 // 估计带宽 (bytes/s)

	// 历史数据
	samples     []LossSample
	maxSamples  int
	sampleIndex int

	// 统计
	stats PacketStats

	// 时间追踪
	lastUpdate  time.Time
	windowStart time.Time
	windowSent  uint64
	windowLost  uint64

	mu sync.RWMutex
}

// LossSample 丢包样本
type LossSample struct {
	Timestamp time.Time
	LossRate  float64
	RTT       time.Duration
	Sent      uint64
	Lost      uint64
}

// NewLossEstimator 创建新的丢包估算器
func NewLossEstimator() *LossEstimator {
	return &LossEstimator{
		alpha:       0.125, // 类似 TCP 的 SRTT alpha
		maxSamples:  100,
		samples:     make([]LossSample, 100),
		lastUpdate:  time.Now(),
		windowStart: time.Now(),
	}
}

// RecordSent 记录发送的数据包
func (e *LossEstimator) RecordSent(count uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.stats.Sent += count
	e.windowSent += count
}

// RecordReceived 记录接收的数据包（用于确认）
func (e *LossEstimator) RecordReceived(count uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.stats.Received += count
}

// RecordLost 记录丢失的数据包
func (e *LossEstimator) RecordLost(count uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.stats.Lost += count
	e.windowLost += count

	// 更新估计
	e.updateEstimate()
}

// RecordRecovered 记录通过 FEC 恢复的数据包
func (e *LossEstimator) RecordRecovered(count uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.stats.Recovered += count
}

// RecordRTT 记录 RTT 样本
func (e *LossEstimator) RecordRTT(rtt time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.rtt == 0 {
		e.rtt = rtt
	} else {
		// EWMA 更新
		e.rtt = time.Duration(float64(e.rtt)*(1-e.alpha) + float64(rtt)*e.alpha)
	}

	// 计算抖动
	diff := float64(rtt - e.rtt)
	if diff < 0 {
		diff = -diff
	}
	e.jitter = e.jitter*(1-e.alpha) + diff*e.alpha
}

// updateEstimate 更新丢包率估计
func (e *LossEstimator) updateEstimate() {
	now := time.Now()
	elapsed := now.Sub(e.windowStart)

	// 每秒更新一次
	if elapsed < time.Second {
		return
	}

	// 计算窗口内丢包率
	var windowLoss float64
	if e.windowSent > 0 {
		windowLoss = float64(e.windowLost) / float64(e.windowSent)
	}

	// EWMA 更新
	if e.lossRate == 0 {
		e.lossRate = windowLoss
	} else {
		e.lossRate = e.lossRate*(1-e.alpha) + windowLoss*e.alpha
	}

	// 存储样本
	sample := LossSample{
		Timestamp: now,
		LossRate:  windowLoss,
		RTT:       e.rtt,
		Sent:      e.windowSent,
		Lost:      e.windowLost,
	}
	e.samples[e.sampleIndex%e.maxSamples] = sample
	e.sampleIndex++

	// 重置窗口
	e.windowStart = now
	e.windowSent = 0
	e.windowLost = 0
	e.lastUpdate = now
}

// GetLossRate 获取当前估计的丢包率
func (e *LossEstimator) GetLossRate() float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.lossRate
}

// GetRTT 获取估计的 RTT
func (e *LossEstimator) GetRTT() time.Duration {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.rtt
}

// GetJitter 获取抖动估计
func (e *LossEstimator) GetJitter() time.Duration {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return time.Duration(e.jitter)
}

// GetStats 获取统计信息
func (e *LossEstimator) GetStats() PacketStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.stats
}

// GetRecentSamples 获取最近的样本
func (e *LossEstimator) GetRecentSamples(count int) []LossSample {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if count > e.maxSamples {
		count = e.maxSamples
	}
	if count > e.sampleIndex {
		count = e.sampleIndex
	}

	samples := make([]LossSample, count)
	startIdx := e.sampleIndex - count
	for i := 0; i < count; i++ {
		samples[i] = e.samples[(startIdx+i)%e.maxSamples]
	}
	return samples
}

// Snapshot 估算器快照
type EstimatorSnapshot struct {
	LossRate    float64
	RTT         time.Duration
	Jitter      time.Duration
	Stats       PacketStats
	LastUpdate  time.Time
	SampleCount int
}

// Snapshot 获取快照
func (e *LossEstimator) Snapshot() EstimatorSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return EstimatorSnapshot{
		LossRate:    e.lossRate,
		RTT:         e.rtt,
		Jitter:      time.Duration(e.jitter),
		Stats:       e.stats,
		LastUpdate:  e.lastUpdate,
		SampleCount: min(e.sampleIndex, e.maxSamples),
	}
}

// Reset 重置估算器
func (e *LossEstimator) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.lossRate = 0
	e.jitter = 0
	e.rtt = 0
	e.stats = PacketStats{}
	e.sampleIndex = 0
	e.windowStart = time.Now()
	e.windowSent = 0
	e.windowLost = 0
	e.lastUpdate = time.Now()
}

// EstimateBurstLoss 估计突发丢包概率
// 返回连续丢失 n 个包的概率
func (e *LossEstimator) EstimateBurstLoss(n int) float64 {
	lossRate := e.GetLossRate()
	return math.Pow(lossRate, float64(n))
}


