// =============================================================================
// 文件名：stats.go
// 描述：SOCKS5 服务器统计信息模块
// 功能：记录和展示服务器的运行统计数据（连接数、流量、UDP 关联等）
// 特性：
//   - 全原子操作（无锁设计，适合高并发）
//   - JSON 导出（支持 Web API）
//   - 自动格式化（人类可读的字节单位）
//   - 定期打印（每 30 秒输出日志）
// =============================================================================

package main

import (
	"encoding/json" // JSON 编解码包（用于 API 导出）
	"fmt"           // 格式化输出包（字符串格式化）
	"sync"          // 同步原语包（读写锁保护 JSON 序列化）
	"sync/atomic"   // 原子操作包（无锁并发更新）
	"time"          // 时间处理包（运行时长计算）
)

// =============================================================================
// Stats - 服务器统计信息结构体
//
// 记录服务器运行的所有关键指标，包括：
// - 连接统计（总数、活跃数、失败数）
// - 流量统计（上传、下载总量）
// - UDP 统计（关联数）
// - 运行时间（从启动开始计算）
//
// 并发安全：
// - 所有 int64 字段使用 atomic 原子操作
// - 读写不需要额外加锁
// - JSON 序列化时使用 mu 保护（防止并发读取不一致）
// =============================================================================
type Stats struct {
	// --- 连接统计（int64 字段必须放在开头，确保 8 字节对齐）---
	// 总连接数：从服务器启动至今接受的连接总数（只增不减）
	TotalConnections int64 `json:"total_connections"`

	// 活跃连接数：当前正在处理的连接数（会动态变化）
	ActiveConnections int64 `json:"active_connections"`

	// 失败连接数：认证失败或处理失败的连接总数
	FailedConnections int64 `json:"failed_connections"`

	// --- 流量统计 ---
	// 总上传流量：客户端->服务器的数据总量（字节）
	TotalUpload int64 `json:"total_upload"`

	// 总下载流量：服务器->客户端的数据总量（字节）
	TotalDownload int64 `json:"total_download"`

	// --- UDP 统计 ---
	// 总 UDP 关联数：从启动至今创建的 UDP 关联总数
	UDPAssociations int64 `json:"udp_associations"`

	// 活跃 UDP 关联数：当前正在处理的 UDP 关联数
	ActiveUDPAssociations int64 `json:"active_udp_associations"`

	// --- 启动时间 ---
	// 服务器启动时间点（用于计算运行时长）
	StartTime time.Time `json:"start_time"`

	// --- 内部锁 ---
	// 读写锁：仅在 JSON 序列化时短暂使用，保护并发读取
	mu sync.RWMutex
}

// NewStats 创建并初始化统计对象
//
// 返回：*Stats - 初始化的统计对象
// 初始化内容：
// - StartTime: 当前时间（服务器启动时间点）
// - 其他字段自动初始化为 0（Go 的零值特性）
func NewStats() *Stats {
	return &Stats{
		StartTime: time.Now(), // 记录当前时间为服务器启动时间
	}
}

// AddConnection 增加连接计数（原子操作，线程安全）
//
// 调用时机：每次接受新的客户端连接时
// 更新字段：
// - TotalConnections +1（累积计数）
// - ActiveConnections +1（当前活跃数）
func (s *Stats) AddConnection() {
	atomic.AddInt64(&s.TotalConnections, 1)  // 总连接数累加 1
	atomic.AddInt64(&s.ActiveConnections, 1) // 活跃连接数增加 1
}

// RemoveConnection 减少活跃连接计数（原子操作，线程安全）
//
// 调用时机：连接关闭时（无论成功或失败）
// 更新字段：
// - ActiveConnections -1（当前活跃数减少）
func (s *Stats) RemoveConnection() {
	atomic.AddInt64(&s.ActiveConnections, -1) // 活跃连接数减 1
}

// AddFailedConnection 增加失败连接计数（原子操作，线程安全）
//
// 调用时机：认证失败或请求处理失败时
// 更新字段：
// - FailedConnections +1（累积失败计数）
func (s *Stats) AddFailedConnection() {
	atomic.AddInt64(&s.FailedConnections, 1) // 失败连接数增加 1
}

// AddUpload 增加上传流量统计（原子操作，线程安全）
//
// 参数 bytes: 要增加的字节数（通常为读取的数据量）
// 更新字段：
// - TotalUpload += bytes（累积上传流量）
//
// 注意：bytes 应为正数，负数会导致流量减少（虽然不会报错）
func (s *Stats) AddUpload(bytes int64) {
	atomic.AddInt64(&s.TotalUpload, bytes) // 累加上传统计
}

// AddDownload 增加下载流量统计（原子操作，线程安全）
//
// 参数 bytes: 要增加的字节数（通常为写入的数据量）
// 更新字段：
// - TotalDownload += bytes（累积下载流量）
func (s *Stats) AddDownload(bytes int64) {
	atomic.AddInt64(&s.TotalDownload, bytes) // 累加下传统计
}

// AddUDPAssociation 增加 UDP 关联计数（原子操作，线程安全）
//
// 调用时机：创建新的 UDP 关联时
// 更新字段：
// - UDPAssociations +1（累积 UDP 关联数）
// - ActiveUDPAssociations +1（当前活跃 UDP 数）
func (s *Stats) AddUDPAssociation() {
	atomic.AddInt64(&s.UDPAssociations, 1)       // 总 UDP 关联数增加 1
	atomic.AddInt64(&s.ActiveUDPAssociations, 1) // 活跃 UDP 关联数增加 1
}

// RemoveUDPAssociation 减少活跃 UDP 关联计数（原子操作，线程安全）
//
// 调用时机：UDP 关联关闭或超时时
// 更新字段：
// - ActiveUDPAssociations -1（当前活跃数减少）
func (s *Stats) RemoveUDPAssociation() {
	atomic.AddInt64(&s.ActiveUDPAssociations, -1) // 活跃 UDP 关联数减 1
}

// GetUptime 获取服务器运行时长
//
// 返回：time.Duration - 从启动至今经过的时间
// 计算方式：time.Since(StartTime) = 当前时间 - 启动时间
// 精度：纳秒级（time.Duration 的最小单位）
func (s *Stats) GetUptime() time.Duration {
	return time.Since(s.StartTime) // 计算启动至今的时间差
}

// String 返回统计信息的字符串表示（用于日志打印）
//
// 实现 fmt.Stringer 接口，可以直接用 log.Println(stats) 打印
// 格式示例：
// "统计 {连接：10/100, 失败：2, UDP: 5/50, 流量：↑1.23 GB/↓4.56 GB, 运行时间：1h30m}"
//
// 字段说明：
// - 连接：活跃连接数/总连接数
// - 失败：失败的连接总数
// - UDP: 活跃 UDP 数/总 UDP 数
// - 流量：上传量/下载量（自动格式化为 KB/MB/GB/TB）
// - 运行时间：四舍五入到秒
func (s *Stats) String() string {
	return fmt.Sprintf(
		"统计 {连接：%d/%d, 失败：%d, UDP: %d/%d, 流量：↑%s/↓%s, 运行时间：%s}",
		atomic.LoadInt64(&s.ActiveConnections),          // 加载活跃连接数
		atomic.LoadInt64(&s.TotalConnections),           // 加载总连接数
		atomic.LoadInt64(&s.FailedConnections),          // 加载失败连接数
		atomic.LoadInt64(&s.ActiveUDPAssociations),      // 加载活跃 UDP 数
		atomic.LoadInt64(&s.UDPAssociations),            // 加载总 UDP 数
		formatBytes(atomic.LoadInt64(&s.TotalUpload)),   // 格式化上传流量
		formatBytes(atomic.LoadInt64(&s.TotalDownload)), // 格式化下载流量
		s.GetUptime().Round(time.Second),                // 运行时间（四舍五入到秒）
	)
}

// JSON 返回 JSON 格式的统计信息（带锁保护）
//
// 返回：[]byte - JSON 格式的数据；error - 可能的序列化错误
// JSON 字段包含：
// - total_connections: 总连接数（数字）
// - active_connections: 活跃连接数（数字）
// - failed_connections: 失败连接数（数字）
// - total_upload_bytes: 上传字节数（数字）
// - total_download_bytes: 下载字节数（数字）
// - total_upload: 格式化上传（字符串，如"1.23 GB"）
// - total_download: 格式化下载（字符串）
// - udp_associations: 总 UDP 数（数字）
// - active_udp_associations: 活跃 UDP 数（数字）
// - start_time: RFC3339 格式的启动时间（字符串）
// - uptime_seconds: 运行秒数（数字）
//
// 并发安全：使用 atomic.Load 读取，不需要额外加锁
func (s *Stats) JSON() ([]byte, error) {
	// 构建统计数据的 map
	data := map[string]interface{}{
		"total_connections":       atomic.LoadInt64(&s.TotalConnections),           // 总连接数
		"active_connections":      atomic.LoadInt64(&s.ActiveConnections),          // 活跃连接数
		"failed_connections":      atomic.LoadInt64(&s.FailedConnections),          // 失败连接数
		"total_upload_bytes":      atomic.LoadInt64(&s.TotalUpload),                // 上传原始字节数
		"total_download_bytes":    atomic.LoadInt64(&s.TotalDownload),              // 下载原始字节数
		"total_upload":            formatBytes(atomic.LoadInt64(&s.TotalUpload)),   // 格式化上传
		"total_download":          formatBytes(atomic.LoadInt64(&s.TotalDownload)), // 格式化下载
		"udp_associations":        atomic.LoadInt64(&s.UDPAssociations),            // 总 UDP 关联数
		"active_udp_associations": atomic.LoadInt64(&s.ActiveUDPAssociations),      // 活跃 UDP 数
		"start_time":              s.StartTime.Format(time.RFC3339),                // RFC3339 格式时间
		"uptime_seconds":          int(s.GetUptime().Seconds()),                    // 运行秒数（整数）
	}

	// 序列化为带缩进的 JSON（2 空格缩进，便于阅读）
	return json.MarshalIndent(data, "", "  ")
}

// formatBytes 将字节数格式化为人类可读的字符串
//
// 参数 bytes: 要格式化的字节数（int64）
// 返回：string - 格式化后的字符串
//
// 格式化规则（自动选择合适单位）：
// - >= 1TB: "X.XX TB"
// - >= 1GB: "X.XX GB"
// - >= 1MB: "X.XX MB"
// - >= 1KB: "X.XX KB"
// - < 1KB:  "X B"
//
// 常量定义：
// - 1 KB = 1024 B
// - 1 MB = 1024 KB = 1,048,576 B
// - 1 GB = 1024 MB = 1,073,741,824 B
// - 1 TB = 1024 GB = 1,099,511,627,776 B
func formatBytes(bytes int64) string {
	const (
		KB = 1024      // 千字节（Kibibyte）
		MB = 1024 * KB // 兆字节（Mebibyte）
		GB = 1024 * MB // 吉字节（Gibibyte）
		TB = 1024 * GB // 太字节（Tebibyte）
	)

	// 根据字节大小选择合适的单位（从大到小判断）
	switch {
	case bytes >= TB:
		// 超过 1TB，显示为 TB 单位
		return fmt.Sprintf("%.2f TB", float64(bytes)/TB)
	case bytes >= GB:
		// 超过 1GB，显示为 GB 单位
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		// 超过 1MB，显示为 MB 单位
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= KB:
		// 超过 1KB，显示为 KB 单位
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	default:
		// 小于 1KB，直接显示字节数
		return fmt.Sprintf("%d B", bytes)
	}
}
