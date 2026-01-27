
package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// Collector 收集运行指标
type Collector struct {
	// 连接和会话
	activeSessions atomic.Int64
	activeStreams  atomic.Int64
	totalSessions  atomic.Uint64
	totalStreams   atomic.Uint64

	// 流量统计
	bytesSent atomic.Uint64
	bytesRecv atomic.Uint64
	packetsSent atomic.Uint64
	packetsRecv atomic.Uint64

	// 丢包和延迟
	packetsLost   atomic.Uint64
	rttSum        atomic.Int64
	rttCount      atomic.Int64

	// FEC 统计
	fecRecovered   atomic.Uint64
	fecFailed      atomic.Uint64
	currentParity  atomic.Int32

	// UDP ASSOCIATE 统计
	udpAssocActive atomic.Int64
	udpPacketsSent atomic.Uint64
	udpPacketsRecv atomic.Uint64

	// 时间相关
	startTime time.Time
	
	mu sync.RWMutex
}

// Snapshot 指标快照
type Snapshot struct {
	ActiveSessions int64
	ActiveStreams  int64
	TotalSessions  uint64
	TotalStreams   uint64

	BytesSent   uint64
	BytesRecv   uint64
	PacketsSent uint64
	PacketsRecv uint64

	PacketLoss    float64
	RTT           time.Duration
	
	FECRecovered  uint64
	FECFailed     uint64
	CurrentParity int32

	UDPAssocActive int64
	UDPPacketsSent uint64
	UDPPacketsRecv uint64

	Uptime time.Duration
}

// New 创建新的指标收集器
func New() *Collector {
	return &Collector{
		startTime: time.Now(),
	}
}

// SessionOpened 会话已打开
func (c *Collector) SessionOpened() {
	c.activeSessions.Add(1)
	c.totalSessions.Add(1)
}

// SessionClosed 会话已关闭
func (c *Collector) SessionClosed() {
	c.activeSessions.Add(-1)
}

// StreamOpened 流已打开
func (c *Collector) StreamOpened() {
	c.activeStreams.Add(1)
	c.totalStreams.Add(1)
}

// StreamClosed 流已关闭
func (c *Collector) StreamClosed() {
	c.activeStreams.Add(-1)
}

// BytesSent 记录发送的字节数
func (c *Collector) BytesSent(n uint64) {
	c.bytesSent.Add(n)
}

// BytesRecv 记录接收的字节数
func (c *Collector) BytesRecv(n uint64) {
	c.bytesRecv.Add(n)
}

// PacketSent 记录发送的数据包
func (c *Collector) PacketSent() {
	c.packetsSent.Add(1)
}

// PacketRecv 记录接收的数据包
func (c *Collector) PacketRecv() {
	c.packetsRecv.Add(1)
}

// PacketLost 记录丢失的数据包
func (c *Collector) PacketLost(n uint64) {
	c.packetsLost.Add(n)
}

// RecordRTT 记录 RTT
func (c *Collector) RecordRTT(rtt time.Duration) {
	c.rttSum.Add(int64(rtt))
	c.rttCount.Add(1)
}

// FECRecovered 记录 FEC 恢复
func (c *Collector) FECRecovered() {
	c.fecRecovered.Add(1)
}

// FECFailed 记录 FEC 失败
func (c *Collector) FECFailed() {
	c.fecFailed.Add(1)
}

// SetCurrentParity 设置当前冗余分片数
func (c *Collector) SetCurrentParity(parity int32) {
	c.currentParity.Store(parity)
}

// UDPAssocOpened UDP ASSOCIATE 已打开
func (c *Collector) UDPAssocOpened() {
	c.udpAssocActive.Add(1)
}

// UDPAssocClosed UDP ASSOCIATE 已关闭
func (c *Collector) UDPAssocClosed() {
	c.udpAssocActive.Add(-1)
}

// UDPPacketSent UDP 数据包已发送
func (c *Collector) UDPPacketSent() {
	c.udpPacketsSent.Add(1)
}

// UDPPacketRecv UDP 数据包已接收
func (c *Collector) UDPPacketRecv() {
	c.udpPacketsRecv.Add(1)
}

// Snapshot 获取指标快照
func (c *Collector) Snapshot() Snapshot {
	packetsRecv := c.packetsRecv.Load()
	packetsLost := c.packetsLost.Load()
	
	var packetLoss float64
	totalPackets := packetsRecv + packetsLost
	if totalPackets > 0 {
		packetLoss = float64(packetsLost) / float64(totalPackets)
	}

	var avgRTT time.Duration
	rttCount := c.rttCount.Load()
	if rttCount > 0 {
		avgRTT = time.Duration(c.rttSum.Load() / rttCount)
	}

	return Snapshot{
		ActiveSessions: c.activeSessions.Load(),
		ActiveStreams:  c.activeStreams.Load(),
		TotalSessions:  c.totalSessions.Load(),
		TotalStreams:   c.totalStreams.Load(),

		BytesSent:   c.bytesSent.Load(),
		BytesRecv:   c.bytesRecv.Load(),
		PacketsSent: c.packetsSent.Load(),
		PacketsRecv: packetsRecv,

		PacketLoss: packetLoss,
		RTT:        avgRTT,

		FECRecovered:  c.fecRecovered.Load(),
		FECFailed:     c.fecFailed.Load(),
		CurrentParity: c.currentParity.Load(),

		UDPAssocActive: c.udpAssocActive.Load(),
		UDPPacketsSent: c.udpPacketsSent.Load(),
		UDPPacketsRecv: c.udpPacketsRecv.Load(),

		Uptime: time.Since(c.startTime),
	}
}

// Reset 重置所有计数器（用于测试）
func (c *Collector) Reset() {
	c.activeSessions.Store(0)
	c.activeStreams.Store(0)
	c.totalSessions.Store(0)
	c.totalStreams.Store(0)
	c.bytesSent.Store(0)
	c.bytesRecv.Store(0)
	c.packetsSent.Store(0)
	c.packetsRecv.Store(0)
	c.packetsLost.Store(0)
	c.rttSum.Store(0)
	c.rttCount.Store(0)
	c.fecRecovered.Store(0)
	c.fecFailed.Store(0)
	c.currentParity.Store(0)
	c.udpAssocActive.Store(0)
	c.udpPacketsSent.Store(0)
	c.udpPacketsRecv.Store(0)
	c.startTime = time.Now()
}

