// Package main 实现 SOCKS5 代理服务器的统计信息收集模块。
// 提供连接数、流量、UDP 关联等指标的实时统计和格式化输出。
package main

// 导入 encoding/json 包，用于 JSON 数据的编码和解码
import (
	"encoding/json"
	// 导入 fmt 包，提供格式化输入输出的功能
	"fmt"
	// 导入 sync 包，提供同步原语如互斥锁
	"sync"
	// 导入 sync/atomic 包，提供低级别的原子操作，用于无锁并发
	"sync/atomic"
	// 导入 time 包，提供时间相关的测量和显示功能
	"time"
)

// Stats 统计信息结构体，记录服务器的运行状态。
// 所有计数字段均使用原子操作确保高并发下的线程安全。
type Stats struct {
	// TotalConnections 累计接收的连接总数，使用原子操作保证线程安全
	TotalConnections int64 `json:"total_connections"`
	// ActiveConnections 当前活跃连接数，反映实时负载情况
	ActiveConnections int64 `json:"active_connections"`
	// FailedConnections 失败的连接数（认证失败、握手失败等）
	FailedConnections int64 `json:"failed_connections"`
	// TotalUpload 累计上传流量，单位为字节
	TotalUpload int64 `json:"total_upload"`
	// TotalDownload 累计下载流量，单位为字节
	TotalDownload int64 `json:"total_download"`
	// UDPAssociations 累计 UDP 关联总数，包括已关闭的
	UDPAssociations int64 `json:"udp_associations"`
	// ActiveUDPAssociations 当前活跃的 UDP 关联数
	ActiveUDPAssociations int64 `json:"active_udp_associations"`
	// StartTime 服务器启动时间，用于计算运行时长
	StartTime time.Time `json:"start_time"`
	// mu 读写互斥锁，保留字段（当前未使用，统计主要依赖原子操作）
	mu sync.RWMutex
}

// NewStats 创建并初始化一个新的统计信息实例。
// 自动记录当前时间为服务器启动时间。
//
// 返回:
//   - *Stats: 初始化后的统计信息实例
func NewStats() *Stats {
	// 创建并返回一个新的 Stats 结构体指针
	return &Stats{
		// 将当前时间设置为服务器启动时间
		StartTime: time.Now(),
	}
}

// AddConnection 增加连接计数。
// 在接收新连接时调用，同时增加总连接数和活跃连接数。
func (s *Stats) AddConnection() {
	// 使用原子操作将总连接数加 1
	atomic.AddInt64(&s.TotalConnections, 1)
	// 使用原子操作将活跃连接数加 1
	atomic.AddInt64(&s.ActiveConnections, 1)
}

// RemoveConnection 减少活跃连接计数。
// 在连接关闭时调用。
func (s *Stats) RemoveConnection() {
	// 使用原子操作将活跃连接数减 1
	atomic.AddInt64(&s.ActiveConnections, -1)
}

// AddFailedConnection 增加失败连接计数。
// 在认证失败或握手失败时调用。
func (s *Stats) AddFailedConnection() {
	// 使用原子操作将失败连接数加 1
	atomic.AddInt64(&s.FailedConnections, 1)
}

// AddUpload 增加上传流量统计。
//
// 参数:
//   - bytes: 上传的字节数
func (s *Stats) AddUpload(bytes int64) {
	// 使用原子操作将上传流量累加指定的字节数
	atomic.AddInt64(&s.TotalUpload, bytes)
}

// AddDownload 增加下载流量统计。
//
// 参数:
//   - bytes: 下载的字节数
func (s *Stats) AddDownload(bytes int64) {
	// 使用原子操作将下载流量累加指定的字节数
	atomic.AddInt64(&s.TotalDownload, bytes)
}

// AddUDPAssociation 增加 UDP 关联计数。
// 在建立新的 UDP 关联时调用。
func (s *Stats) AddUDPAssociation() {
	// 使用原子操作将 UDP 关联总数加 1
	atomic.AddInt64(&s.UDPAssociations, 1)
	// 使用原子操作将活跃 UDP 关联数加 1
	atomic.AddInt64(&s.ActiveUDPAssociations, 1)
}

// RemoveUDPAssociation 减少活跃 UDP 关联计数。
// 在 UDP 关联关闭时调用。
func (s *Stats) RemoveUDPAssociation() {
	// 使用原子操作将活跃 UDP 关联数减 1
	atomic.AddInt64(&s.ActiveUDPAssociations, -1)
}

// GetUptime 获取服务器运行时长。
//
// 返回:
//   - time.Duration: 从启动到现在的时长
func (s *Stats) GetUptime() time.Duration {
	// 计算当前时间与启动时间的差值，返回运行时长
	return time.Since(s.StartTime)
}

// String 返回统计信息的可读字符串表示。
// 用于日志输出和调试。
//
// 返回:
//   - string: 格式化的统计信息字符串
func (s *Stats) String() string {
	// 使用 fmt.Sprintf 格式化统计信息为人类可读的字符串
	return fmt.Sprintf(
		// 格式化模板，包含各项统计指标
		"统计 {连接：%d/%d, 失败：%d, UDP: %d/%d, 流量：↑%s/↓%s, 运行时间：%s}",
		// 使用原子加载获取当前活跃连接数
		atomic.LoadInt64(&s.ActiveConnections),
		// 使用原子加载获取总连接数
		atomic.LoadInt64(&s.TotalConnections),
		// 使用原子加载获取失败连接数
		atomic.LoadInt64(&s.FailedConnections),
		// 使用原子加载获取活跃 UDP 关联数
		atomic.LoadInt64(&s.ActiveUDPAssociations),
		// 使用原子加载获取 UDP 关联总数
		atomic.LoadInt64(&s.UDPAssociations),
		// 格式化上传流量为人类可读的单位
		formatBytes(atomic.LoadInt64(&s.TotalUpload)),
		// 格式化下载流量为人类可读的单位
		formatBytes(atomic.LoadInt64(&s.TotalDownload)),
		// 获取运行时长并四舍五入到秒
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
	// 创建一个映射，存储所有需要序列化的统计数据
	data := map[string]interface{}{
		// 总连接数
		"total_connections": atomic.LoadInt64(&s.TotalConnections),
		// 活跃连接数
		"active_connections": atomic.LoadInt64(&s.ActiveConnections),
		// 失败连接数
		"failed_connections": atomic.LoadInt64(&s.FailedConnections),
		// 上传流量原始字节数
		"total_upload_bytes": atomic.LoadInt64(&s.TotalUpload),
		// 下载流量原始字节数
		"total_download_bytes": atomic.LoadInt64(&s.TotalDownload),
		// 上传流量格式化字符串
		"total_upload": formatBytes(atomic.LoadInt64(&s.TotalUpload)),
		// 下载流量格式化字符串
		"total_download": formatBytes(atomic.LoadInt64(&s.TotalDownload)),
		// UDP 关联总数
		"udp_associations": atomic.LoadInt64(&s.UDPAssociations),
		// 活跃 UDP 关联数
		"active_udp_associations": atomic.LoadInt64(&s.ActiveUDPAssociations),
		// 服务器启动时间，格式化为 RFC3339 标准
		"start_time": s.StartTime.Format(time.RFC3339),
		// 运行时长（秒）
		"uptime_seconds": int(s.GetUptime().Seconds()),
	}

	// 将数据映射序列化为带缩进的 JSON 格式并返回
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
	// 定义常量，表示各个存储单位的字节数
	const (
		// 1 KB = 1024 字节
		KB = 1024
		// 1 MB = 1024 KB
		MB = 1024 * KB
		// 1 GB = 1024 MB
		GB = 1024 * MB
		// 1 TB = 1024 GB
		TB = 1024 * GB
	)

	// 使用 switch 语句根据字节数大小选择合适的单位
	switch {
	// 如果字节数大于等于 1 TB
	case bytes >= TB:
		// 格式化为 TB 单位，保留两位小数
		return fmt.Sprintf("%.2f TB", float64(bytes)/TB)
	// 如果字节数大于等于 1 GB
	case bytes >= GB:
		// 格式化为 GB 单位，保留两位小数
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	// 如果字节数大于等于 1 MB
	case bytes >= MB:
		// 格式化为 MB 单位，保留两位小数
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	// 如果字节数大于等于 1 KB
	case bytes >= KB:
		// 格式化为 KB 单位，保留两位小数
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	// 其他情况（小于 1 KB）
	default:
		// 直接以字节为单位显示
		return fmt.Sprintf("%d B", bytes)
	}
}
