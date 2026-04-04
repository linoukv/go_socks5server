package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type Stats struct {
	TotalConnections      int64     `json:"total_connections"`
	ActiveConnections     int64     `json:"active_connections"`
	FailedConnections     int64     `json:"failed_connections"`
	TotalUpload           int64     `json:"total_upload"`
	TotalDownload         int64     `json:"total_download"`
	UDPAssociations       int64     `json:"udp_associations"`
	ActiveUDPAssociations int64     `json:"active_udp_associations"`
	StartTime             time.Time `json:"start_time"`
	mu                    sync.RWMutex
}

func NewStats() *Stats {
	return &Stats{
		StartTime: time.Now(),
	}
}

func (s *Stats) AddConnection() {
	atomic.AddInt64(&s.TotalConnections, 1)
	atomic.AddInt64(&s.ActiveConnections, 1)
}

func (s *Stats) RemoveConnection() {
	atomic.AddInt64(&s.ActiveConnections, -1)
}

func (s *Stats) AddFailedConnection() {
	atomic.AddInt64(&s.FailedConnections, 1)
}

func (s *Stats) AddUpload(bytes int64) {
	atomic.AddInt64(&s.TotalUpload, bytes)
}

func (s *Stats) AddDownload(bytes int64) {
	atomic.AddInt64(&s.TotalDownload, bytes)
}

func (s *Stats) AddUDPAssociation() {
	atomic.AddInt64(&s.UDPAssociations, 1)
	atomic.AddInt64(&s.ActiveUDPAssociations, 1)
}

func (s *Stats) RemoveUDPAssociation() {
	atomic.AddInt64(&s.ActiveUDPAssociations, -1)
}

func (s *Stats) GetUptime() time.Duration {
	return time.Since(s.StartTime)
}

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
