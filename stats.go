package main

import (
	"encoding/json" // JSON 编解码
	"fmt"           // 格式化输出
	"sync"          // 同步原语
	"sync/atomic"   // 原子操作
	"time"          // 时间处理
)

// Stats 服务器统计信息结构体，记录连接、流量等数据
type Stats struct {
	// 连接统计
	TotalConnections  int64 `json:"total_connections"`  // 总连接数
	ActiveConnections int64 `json:"active_connections"` // 活跃连接数
	FailedConnections int64 `json:"failed_connections"` // 失败连接数

	// 流量统计（字节）
	TotalUpload   int64 `json:"total_upload"`   // 总上传流量
	TotalDownload int64 `json:"total_download"` // 总下载流量

	// UDP 统计
	UDPAssociations       int64 `json:"udp_associations"`        // 总 UDP 关联数
	ActiveUDPAssociations int64 `json:"active_udp_associations"` // 活跃 UDP 关联数

	// 启动时间
	StartTime time.Time `json:"start_time"` // 服务器启动时间

	mu sync.RWMutex // 读写锁，保护 JSON 序列化时的访问
}

// NewStats 创建并初始化统计对象
func NewStats() *Stats {
	return &Stats{
		StartTime: time.Now(), // 记录当前时间为启动时间
	}
}

// AddConnection 增加连接计数（原子操作）
func (s *Stats) AddConnection() {
	atomic.AddInt64(&s.TotalConnections, 1)  // 总连接数 +1
	atomic.AddInt64(&s.ActiveConnections, 1) // 活跃连接数 +1
}

// RemoveConnection 减少活跃连接计数（原子操作）
func (s *Stats) RemoveConnection() {
	atomic.AddInt64(&s.ActiveConnections, -1) // 活跃连接数 -1
}

// AddFailedConnection 增加失败连接计数（原子操作）
func (s *Stats) AddFailedConnection() {
	atomic.AddInt64(&s.FailedConnections, 1) // 失败连接数 +1
}

// AddUpload 增加上传流量统计（原子操作）
func (s *Stats) AddUpload(bytes int64) {
	atomic.AddInt64(&s.TotalUpload, bytes) // 累加上传字节数
}

// AddDownload 增加下载流量统计（原子操作）
func (s *Stats) AddDownload(bytes int64) {
	atomic.AddInt64(&s.TotalDownload, bytes) // 累加下载字节数
}

// AddUDPAssociation 增加 UDP 关联计数（原子操作）
func (s *Stats) AddUDPAssociation() {
	atomic.AddInt64(&s.UDPAssociations, 1)       // 总 UDP 关联数 +1
	atomic.AddInt64(&s.ActiveUDPAssociations, 1) // 活跃 UDP 关联数 +1
}

// RemoveUDPAssociation 减少活跃 UDP 关联计数（原子操作）
func (s *Stats) RemoveUDPAssociation() {
	atomic.AddInt64(&s.ActiveUDPAssociations, -1)
}

// GetUptime 获取服务器运行时长
func (s *Stats) GetUptime() time.Duration {
	return time.Since(s.StartTime) // 返回从启动时间到现在的时间差
}

// String 返回统计信息的字符串表示（用于日志打印）
func (s *Stats) String() string {
	return fmt.Sprintf(
		"统计 {连接：%d/%d, 失败：%d, UDP: %d/%d, 流量：↑%s/↓%s, 运行时间：%s}",
		atomic.LoadInt64(&s.ActiveConnections),          // 活跃连接数
		atomic.LoadInt64(&s.TotalConnections),           // 总连接数
		atomic.LoadInt64(&s.FailedConnections),          // 失败连接数
		atomic.LoadInt64(&s.ActiveUDPAssociations),      // 活跃 UDP
		atomic.LoadInt64(&s.UDPAssociations),            // 总 UDP
		formatBytes(atomic.LoadInt64(&s.TotalUpload)),   // 上传流量
		formatBytes(atomic.LoadInt64(&s.TotalDownload)), // 下载流量
		s.GetUptime().Round(time.Second),                // 运行时间
	)
}

// JSON 返回 JSON 格式的统计信息（带锁保护）
func (s *Stats) JSON() ([]byte, error) {
	// 使用原子操作读取，不需要额外的锁
	data := map[string]interface{}{
		"total_connections":       atomic.LoadInt64(&s.TotalConnections),           // 总连接数
		"active_connections":      atomic.LoadInt64(&s.ActiveConnections),          // 活跃连接数
		"failed_connections":      atomic.LoadInt64(&s.FailedConnections),          // 失败连接数
		"total_upload_bytes":      atomic.LoadInt64(&s.TotalUpload),                // 上传字节数
		"total_download_bytes":    atomic.LoadInt64(&s.TotalDownload),              // 下载字节数
		"total_upload":            formatBytes(atomic.LoadInt64(&s.TotalUpload)),   // 格式化上传
		"total_download":          formatBytes(atomic.LoadInt64(&s.TotalDownload)), // 格式化下载
		"udp_associations":        atomic.LoadInt64(&s.UDPAssociations),            // UDP 总数
		"active_udp_associations": atomic.LoadInt64(&s.ActiveUDPAssociations),      // 活跃 UDP
		"start_time":              s.StartTime.Format(time.RFC3339),                // RFC3339 格式
		"uptime_seconds":          int(s.GetUptime().Seconds()),                    // 运行秒数
	}

	// 序列化为带缩进的 JSON
	return json.MarshalIndent(data, "", "  ")
}

// formatBytes 将字节数格式化为人类可读的字符串（B/KB/MB/GB/TB）
func formatBytes(bytes int64) string {
	const (
		KB = 1024      // 千字节
		MB = 1024 * KB // 兆字节
		GB = 1024 * MB // 吉字节
		TB = 1024 * GB // 太字节
	)

	// 根据大小选择合适的单位
	switch {
	case bytes >= TB:
		return fmt.Sprintf("%.2f TB", float64(bytes)/TB)
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
