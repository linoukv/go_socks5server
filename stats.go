// Package main 实现 SOCKS5 代理服务器的统计信息收集模块。
// 提供连接数、流量、UDP 关联等指标的实时统计和格式化输出。
package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Stats 统计信息结构体，记录服务器的运行状态。
// 所有计数字段均使用原子操作确保高并发下的线程安全。
type Stats struct {
	TotalConnections      int64        `json:"total_connections"`       // 累计接收的连接总数
	ActiveConnections     int64        `json:"active_connections"`      // 当前活跃连接数
	FailedConnections     int64        `json:"failed_connections"`      // 失败的连接数（认证失败等）
	TotalUpload           int64        `json:"total_upload"`            // 累计上传流量（字节）
	TotalDownload         int64        `json:"total_download"`          // 累计下载流量（字节）
	UDPAssociations       int64        `json:"udp_associations"`        // 累计 UDP 关联总数
	ActiveUDPAssociations int64        `json:"active_udp_associations"` // 当前活跃的 UDP 关联数
	StartTime             time.Time    `json:"start_time"`              // 服务器启动时间
	mu                    sync.RWMutex // 保留字段（当前未使用，统计使用原子操作）
}

// NewStats 创建并初始化一个新的统计信息实例。
// 自动记录当前时间为服务器启动时间。
//
// 返回:
//   - *Stats: 初始化后的统计信息实例
func NewStats() *Stats {
	return &Stats{
		StartTime: time.Now(),
	}
}

// AddConnection 增加连接计数。
// 在接收新连接时调用，同时增加总连接数和活跃连接数。
func (s *Stats) AddConnection() {
	atomic.AddInt64(&s.TotalConnections, 1)
	atomic.AddInt64(&s.ActiveConnections, 1)
}

// RemoveConnection 减少活跃连接计数。
// 在连接关闭时调用。
func (s *Stats) RemoveConnection() {
	atomic.AddInt64(&s.ActiveConnections, -1)
}

// AddFailedConnection 增加失败连接计数。
// 在认证失败或握手失败时调用。
func (s *Stats) AddFailedConnection() {
	atomic.AddInt64(&s.FailedConnections, 1)
}

// AddUpload 增加上传流量统计。
//
// 参数:
//   - bytes: 上传的字节数
func (s *Stats) AddUpload(bytes int64) {
	atomic.AddInt64(&s.TotalUpload, bytes)
}

// AddDownload 增加下载流量统计。
//
// 参数:
//   - bytes: 下载的字节数
func (s *Stats) AddDownload(bytes int64) {
	atomic.AddInt64(&s.TotalDownload, bytes)
}

// AddUDPAssociation 增加 UDP 关联计数。
// 在建立新的 UDP 关联时调用。
func (s *Stats) AddUDPAssociation() {
	atomic.AddInt64(&s.UDPAssociations, 1)
	atomic.AddInt64(&s.ActiveUDPAssociations, 1)
}

// RemoveUDPAssociation 减少活跃 UDP 关联计数。
// 在 UDP 关联关闭时调用。
func (s *Stats) RemoveUDPAssociation() {
	atomic.AddInt64(&s.ActiveUDPAssociations, -1)
}

// GetUptime 获取服务器运行时长。
//
// 返回:
//   - time.Duration: 从启动到现在的时长
func (s *Stats) GetUptime() time.Duration {
	return time.Since(s.StartTime)
}

// String 返回统计信息的可读字符串表示。
// 用于日志输出和调试。
//
// 返回:
//   - string: 格式化的统计信息字符串
func (s *Stats) String() string {
	return fmt.Sprintf(
		"统计 {连接：%d/%d, 失败：%d, UDP: %d/%d, 流量：↑%s/↓%s, 运行时间：%s}",
		atomic.LoadInt64(&s.ActiveConnections),
		atomic.LoadInt64(&s.TotalConnections),
		atomic.LoadInt64(&s.FailedConnections),
		atomic.LoadInt64(&s.ActiveUDPAssociations),
		atomic.LoadInt64(&s.UDPAssociations),
		formatBytes(atomic.LoadInt64(&s.TotalUpload)),
		formatBytes(atomic.LoadInt64(&s.TotalDownload)),
		s.GetUptime().Round(time.Second),
	)
}

// JSON 将统计信息序列化为 JSON 格式。
// 包含原始字节数和人类可读的格式化字符串。
//
// 返回:
//   - []byte: JSON 编码的字节切片
//   - error: 序列化错误
func (s *Stats) JSON() ([]byte, error) {
	data := map[string]interface{}{
		"total_connections":       atomic.LoadInt64(&s.TotalConnections),
		"active_connections":      atomic.LoadInt64(&s.ActiveConnections),
		"failed_connections":      atomic.LoadInt64(&s.FailedConnections),
		"total_upload_bytes":      atomic.LoadInt64(&s.TotalUpload),
		"total_download_bytes":    atomic.LoadInt64(&s.TotalDownload),
		"total_upload":            formatBytes(atomic.LoadInt64(&s.TotalUpload)),
		"total_download":          formatBytes(atomic.LoadInt64(&s.TotalDownload)),
		"udp_associations":        atomic.LoadInt64(&s.UDPAssociations),
		"active_udp_associations": atomic.LoadInt64(&s.ActiveUDPAssociations),
		"start_time":              s.StartTime.Format(time.RFC3339),
		"uptime_seconds":          int(s.GetUptime().Seconds()),
	}

	return json.MarshalIndent(data, "", "  ")
}

// formatBytes 将字节数格式化为人类可读的单位表示。
// 根据数值大小自动选择合适的单位（B/KB/MB/GB/TB）。
//
// 参数:
//   - bytes: 字节数
//
// 返回:
//   - string: 格式化后的字符串，如 "1.23 GB"
func formatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
		TB = 1024 * GB
	)

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
