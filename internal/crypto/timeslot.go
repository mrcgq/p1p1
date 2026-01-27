
package crypto

import (
	"encoding/binary"
	"time"
)

// TimeSlot 管理时间窗口操作
type TimeSlot struct {
	windowSize int
}

// NewTimeSlot 创建时间窗口管理器
func NewTimeSlot(windowSize int) *TimeSlot {
	return &TimeSlot{windowSize: windowSize}
}

// CurrentWindow 返回当前时间窗口索引
func (t *TimeSlot) CurrentWindow() int64 {
	return time.Now().Unix() / int64(t.windowSize)
}

// CurrentWindowStatic 静态方法：返回当前时间窗口索引
func CurrentWindow(windowSize int) int64 {
	return time.Now().Unix() / int64(windowSize)
}

// ValidWindows 返回用于验证的有效时间窗口列表
// 允许 ±1 个窗口的容差以处理时钟偏差
func (t *TimeSlot) ValidWindows() []int64 {
	current := t.CurrentWindow()
	return []int64{
		current - 1, // 前一个窗口 (慢时钟)
		current,     // 当前窗口
		current + 1, // 下一个窗口 (快时钟)
	}
}

// ValidWindowsStatic 静态方法：返回有效时间窗口列表
func ValidWindows(windowSize int) []int64 {
	current := CurrentWindow(windowSize)
	return []int64{
		current - 1,
		current,
		current + 1,
	}
}

// TimestampLow16 返回当前时间戳的低 16 位
// 用于数据包头的额外时间绑定
func TimestampLow16() uint16 {
	return uint16(time.Now().Unix() & 0xFFFF)
}

// TimestampLow32 返回当前时间戳的低 32 位
func TimestampLow32() uint32 {
	return uint32(time.Now().Unix() & 0xFFFFFFFF)
}

// ValidateTimestamp 检查时间戳是否在可接受范围内
func ValidateTimestamp(ts uint16, windowSize int) bool {
	current := TimestampLow16()
	diff := int(current) - int(ts)

	// 处理环绕
	if diff < -32768 {
		diff += 65536
	} else if diff > 32768 {
		diff -= 65536
	}

	// 取绝对值
	if diff < 0 {
		diff = -diff
	}

	return diff <= windowSize*2 // 允许 2 倍窗口容差
}

// ValidateTimestamp32 验证 32 位时间戳
func ValidateTimestamp32(ts uint32, windowSize int) bool {
	current := TimestampLow32()
	diff := int64(current) - int64(ts)

	if diff < 0 {
		diff = -diff
	}

	return diff <= int64(windowSize)*2
}

// WindowToTime 将窗口索引转换为起始时间
func WindowToTime(window int64, windowSize int) time.Time {
	return time.Unix(window*int64(windowSize), 0)
}

// EncodeTimestamp 编码时间戳到字节
func EncodeTimestamp(ts uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, ts)
	return buf
}

// DecodeTimestamp 从字节解码时间戳
func DecodeTimestamp(data []byte) uint32 {
	if len(data) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(data)
}


