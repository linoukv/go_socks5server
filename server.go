// =============================================================================
// 文件名：server.go
// 描述：SOCKS5 代理服务器核心实现文件
// 功能：服务器启动、连接处理、认证协商、请求分发、TCP/UDP 代理
// 性能优化：万兆网络优化（16MB TCP 缓冲区、缓冲池复用、原子操作统计）
// =============================================================================

package main

import (
	"context"     // 上下文控制包（用于优雅关闭）
	"fmt"         // 格式化输出包
	"io"          // IO 操作包（数据复制）
	"log"         // 日志记录包
	"net"         // 网络操作包（TCP/UDP 连接）
	"runtime"     // 运行时信息包（获取 CPU 核心数）
	"strings"     // 字符串处理包（错误类型判断）
	"sync"        // 同步原语包（互斥锁、等待组）
	"sync/atomic" // 原子操作包（无锁并发计数）
	"time"        // 时间处理包（超时控制）
)

// =============================================================================
// Config - SOCKS5 服务器配置结构体
//
// 包含所有可配置的参数，支持从数据库加载和用户自定义设置
// 默认配置通过 DefaultConfig() 函数提供（万兆性能优化版）
// =============================================================================
type Config struct {
	// --- 限速配置（int64 字段必须放在开头，确保 8 字节对齐）---
	// 读取速度限制（上传方向：客户端->服务器），单位：字节/秒，0 表示不限速
	ReadSpeedLimit int64
	// 写入速度限制（下载方向：服务器->客户端），单位：字节/秒，0 表示不限速
	WriteSpeedLimit int64

	// --- 基础配置 ---
	// 监听地址：格式为 "IP:端口"，示例："0.0.0.0:1080" 或 "127.0.0.1:1080"
	ListenAddr string

	// 认证器接口：实现 Authenticator 接口的对象，用于用户认证
	// 可选实现：*NoAuth（无认证）、*PasswordAuth（密码认证）
	Auth Authenticator

	// --- 并发控制配置 ---
	// 最大工作协程数：0 表示无限制，由 GOMAXPROCS 自动调度（推荐）
	// 说明：设置具体数值可以限制最大并发，但可能影响性能
	MaxWorkers int

	// 单 IP 最大连接数：防止单个 IP 占用过多资源，0 表示无限制
	// 默认值：200000（超高并发优化）
	MaxConnPerIP int

	// --- 多用户管理配置 ---
	// 是否启用多用户管理：true=需要认证，false=无认证模式
	EnableUserManagement bool

	// --- 超时配置 ---
	// 握手超时时间：客户端必须在指定时间内完成认证，否则断开连接
	// 默认值：10 秒（快速释放资源）
	HandshakeTimeout time.Duration

	// --- 性能优化配置 ---
	// TCP Keepalive 心跳周期：发送心跳包检测死连接的间隔
	// 默认值：5 秒（更快检测死连接，及时释放资源）
	TCPKeepAlivePeriod time.Duration

	// 是否禁用 Nagle 算法：true=禁用（减少传输延迟），false=启用（合并小包）
	// 说明：禁用后可以立即发送数据，适合实时性要求高的场景
	TCPNoDelay bool

	// 接收缓冲区池：预分配的缓冲区池，减少内存分配和 GC 压力
	// 默认值：2MB（万兆优化，提升大流量吞吐性能）
	RecvBufferPool *BufferPool

	// 发送缓冲区池：用于发送数据的缓冲区池
	SendBufferPool *BufferPool
}

// DefaultConfig 返回默认配置参数（万兆性能优化版）
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:         "0.0.0.0:1080",                 // 默认监听所有网卡的 1080 端口
		Auth:               &NoAuth{},                      // 默认无认证
		MaxWorkers:         0,                              // 默认无限制（让 GOMAXPROCS 决定）
		MaxConnPerIP:       200000,                         // 默认单 IP 最多 200000 连接（万兆超高并发优化）
		HandshakeTimeout:   10 * time.Second,               // 握手超时 10 秒（更快释放资源）
		TCPKeepAlivePeriod: 15 * time.Second,               // TCP Keepalive，15 秒一次
		TCPNoDelay:         true,                           // 禁用 Nagle 算法，减少传输延迟
		RecvBufferPool:     NewBufferPool(2 * 1024 * 1024), // 接收缓冲区池 2MB（万兆优化）
		SendBufferPool:     NewBufferPool(2 * 1024 * 1024), // 发送缓冲区池 2MB
	}
}

// Server SOCKS5 服务器核心结构
type Server struct {
	config      *Config      // 服务器配置
	listener    net.Listener // TCP 监听器
	pool        *WorkerPool  // 工作协程池
	connManager *ConnManager // 连接管理器
	stats       *Stats       // 统计信息
	bufferPool  *BufferPool  // 全局缓冲区池

	mu      sync.RWMutex       // 读写锁
	running int32              // 运行状态标志（原子操作）
	wg      sync.WaitGroup     // 等待组
	ctx     context.Context    // 上下文
	cancel  context.CancelFunc // 取消函数

	// 性能优化：预分配的零拷贝缓冲区（用于小数据包）
	zeroBuf []byte // 512 字节零拷贝缓冲区，用于小响应

	// 多用户管理：连接地址到用户名的映射
	connUserMap map[string]string // {clientIP:port: username}
	connUserMu  sync.RWMutex      // 保护 connUserMap 的锁
}

// NewServer 创建并初始化新的 SOCKS5 服务器实例（优化版）
func NewServer(config *Config) *Server {
	if config == nil {
		config = DefaultConfig() // 使用默认配置
	}

	ctx, cancel := context.WithCancel(context.Background()) // 创建可取消的上下文

	// 初始化缓冲区池（如果未提供则创建默认的）
	recvBufferPool := config.RecvBufferPool
	if recvBufferPool == nil {
		recvBufferPool = NewBufferPool(32 * 1024) // 32KB 缓冲区
	}

	return &Server{
		config:      config,                              // 配置
		pool:        NewWorkerPool(config.MaxWorkers),    // 工作池
		connManager: NewConnManager(config.MaxConnPerIP), // 连接管理器
		stats:       NewStats(),                          // 统计对象
		bufferPool:  recvBufferPool,                      // 缓冲区池
		ctx:         ctx,                                 // 上下文
		cancel:      cancel,                              // 取消函数
		zeroBuf:     make([]byte, 512),                   // 预分配小缓冲区，减少小对象 GC
		connUserMap: make(map[string]string),             // 初始化连接 - 用户映射
	}
}

// Start 启动服务器，开始监听并处理客户端连接
func (s *Server) Start() error {
	// 使用原子操作检查服务器是否已在运行
	if !atomic.CompareAndSwapInt32(&s.running, 0, 1) {
		return fmt.Errorf("服务器已在运行中")
	}

	// 创建 TCP 监听器
	listener, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		atomic.StoreInt32(&s.running, 0)
		return fmt.Errorf("监听失败：%w", err)
	}
	s.listener = listener

	// 启用 SO_REUSEADDR 和 TCP_FASTOPEN（如果支持）
	if tcpListener, ok := listener.(*net.TCPListener); ok {
		_ = tcpListener.SetDeadline(time.Time{}) // 设置无超时
	}

	log.Printf("SOCKS5 服务器已启动在 %s (GOMAXPROCS=%d)", s.config.ListenAddr, runtime.GOMAXPROCS(0))

	// 启动统计打印 goroutine，定期输出服务器状态
	go s.statsReporter()

	// 启动用户数据持久化 goroutine（每 10 秒保存一次）
	if s.config.EnableUserManagement {
		go s.userDataPersister()
	}

	// 主循环：接受客户端连接
	for atomic.LoadInt32(&s.running) == 1 {
		conn, err := listener.Accept() // 阻塞等待新连接
		if err != nil {
			select {
			case <-s.ctx.Done(): // 上下文已取消
				return nil
			default:
				log.Printf("接受连接错误：%v", err)
				continue // 错误后继续接受下一个连接
			}
		}

		// 万兆优化：TCP 连接参数（16MB 缓冲区实现万兆吞吐）
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			// 设置 TCP_NODELAY 禁用 Nagle 算法，减少延迟
			if s.config.TCPNoDelay {
				tcpConn.SetNoDelay(true)
			}
			// 设置 TCP_KEEPALIVE 检测死连接（更短周期）
			if s.config.TCPKeepAlivePeriod > 0 {
				tcpConn.SetKeepAlive(true)
				tcpConn.SetKeepAlivePeriod(s.config.TCPKeepAlivePeriod)
			}
			// 万兆优化：16MB 缓冲区（关键优化：10Gbps 必需）
			tcpConn.SetReadBuffer(16 * 1024 * 1024)  // 16MB 读缓冲区
			tcpConn.SetWriteBuffer(16 * 1024 * 1024) // 16MB 写缓冲区
			// 启用 TCP_FASTOPEN（如果系统支持）
			// 注意：Windows 需要 TCP_FASTOPEN 支持，Linux 需要内核 4.11+
			_ = tcpConn // 占位符，实际 FASTOPEN 需要平台特定代码
		}

		// 检查 IP 连接数限制，防止单 IP 占用过多资源
		clientIP := getClientIP(conn)
		if !s.connManager.AddConn(clientIP) {
			log.Printf("IP 连接数超限：%s", clientIP)
			conn.Close()
			continue
		}

		s.wg.Add(1)             // 增加等待计数
		s.stats.AddConnection() // 更新统计

		// 提交到工作池处理连接
		s.pool.Submit(func() {
			defer func() {
				s.connManager.RemoveConn(clientIP) // 移除连接记录
				s.stats.RemoveConnection()         // 更新统计
				s.wg.Done()                        // 减少等待计数，允许服务器优雅关闭
			}()
			s.handleConnection(conn) // 处理具体连接逻辑
		})
	}

	return nil
}

// Stop 优雅停止服务器，关闭监听和工作协程
func (s *Server) Stop() error {
	// 原子操作设置服务器为停止状态
	if !atomic.CompareAndSwapInt32(&s.running, 1, 0) {
		return fmt.Errorf("服务器未运行")
	}

	s.cancel() // 取消上下文，通知所有 goroutine

	if s.listener != nil {
		s.listener.Close() // 关闭监听器，不再接受新连接
	}

	s.pool.Stop() // 停止工作池
	s.wg.Wait()   // 等待所有正在处理的连接完成

	log.Println("SOCKS5 服务器已停止")
	return nil
}

// IsRunning 检查服务器当前是否处于运行状态
func (s *Server) IsRunning() bool {
	return atomic.LoadInt32(&s.running) == 1
}

// handleConnection 处理单个客户端连接的完整流程
func (s *Server) handleConnection(conn net.Conn) {
	defer func() {
		// 清理连接映射中的用户信息
		s.connUserMu.Lock()
		delete(s.connUserMap, conn.RemoteAddr().String())
		s.connUserMu.Unlock()
		conn.Close() // 确保连接最终关闭
	}()

	// 从池中获取缓冲区，减少内存分配开销
	buf := s.bufferPool.Get()
	defer s.bufferPool.Put(buf) // 确保归还缓冲区

	// 设置握手超时时间，防止恶意客户端长时间不完成握手
	conn.SetDeadline(time.Now().Add(s.config.HandshakeTimeout))

	// 第一步：认证协商
	if err := s.handleAuth(conn); err != nil {
		log.Printf("认证失败来自 %s：%v", conn.RemoteAddr(), err)
		s.stats.AddFailedConnection() // 记录失败连接
		return
	}

	// 第二步：处理 SOCKS5 请求
	if err := s.handleRequest(conn); err != nil {

		// 只统计真正的失败（排除 DNS 和连接目标服务器失败）
		if !isDNSError(err) && !isConnectionError(err) {
			s.stats.AddFailedConnection()
		}
		return
	}
}

// handleAuth 处理客户端认证流程
func (s *Server) handleAuth(conn net.Conn) error {
	// 读取客户端发送的认证请求
	req, err := ReadAuthRequest(conn)
	if err != nil {
		return fmt.Errorf("读取认证请求：%w", err)
	}

	// 根据客户端支持的方法和服务端配置选择合适的认证方法
	serverMethods := []byte{s.config.Auth.Method()}
	selectedMethod := SelectAuthMethod(req.Methods, serverMethods)

	// 发送认证响应给客户端
	if err := WriteAuthResponse(conn, selectedMethod); err != nil {
		return fmt.Errorf("写入认证响应：%w", err)
	}

	if selectedMethod == AuthNoAccept {
		return ErrInvalidAuthMethod // 没有共同支持的认证方法
	}

	// 如果选择了密码认证，则进行密码验证
	if selectedMethod == AuthPassword {
		if err := s.handlePasswordAuth(conn); err != nil {
			return err
		}
	}

	return nil
}

// handlePasswordAuth 处理用户名/密码认证流程
func (s *Server) handlePasswordAuth(conn net.Conn) error {
	// 读取客户端发送的密码认证请求
	req, err := ReadPasswordAuthRequest(conn)
	if err != nil {
		return fmt.Errorf("读取密码认证：%w", err)
	}

	// 验证用户名和密码是否正确
	if !s.config.Auth.Authenticate(req.Uname, req.Passwd) {
		WritePasswordAuthResponse(conn, 0x01) // 发送认证失败响应
		return ErrAuthFailed
	}

	// 如果启用了多用户管理，检查用户连接数和 IP 限制
	if s.config.EnableUserManagement {
		if auth, ok := s.config.Auth.(*PasswordAuth); ok {
			// 获取客户端 IP
			clientIP := getClientIP(conn)

			// 检查是否超过 IP 连接数限制
			if !auth.CheckUserIPLimit(req.Uname, clientIP) {
				log.Printf("用户 %s IP 连接数超限（当前 IP：%s，已连接 IP 数：%d）",
					req.Uname, clientIP, auth.GetUserIPCount(req.Uname))
				WritePasswordAuthResponse(conn, 0x01)
				return fmt.Errorf("用户 IP 连接数超限")
			}

			// 检查是否超过连接数限制
			if !auth.CheckUserConnectionLimit(req.Uname) {
				log.Printf("用户 %s 连接数超限（当前：%d）", req.Uname, auth.GetUserConnectionCount(req.Uname))
				WritePasswordAuthResponse(conn, 0x01)
				return fmt.Errorf("用户连接数超限")
			}

			// 增加用户连接数和 IP 记录
			auth.IncrementUserConnection(req.Uname)
			auth.AddUserIP(req.Uname, clientIP)
			// 记录连接地址到用户名的映射，用于后续识别用户
			s.connUserMu.Lock()
			s.connUserMap[conn.RemoteAddr().String()] = req.Uname
			s.connUserMu.Unlock()
		}
	}

	// 认证成功，发送成功响应
	if err := WritePasswordAuthResponse(conn, 0x00); err != nil {
		return fmt.Errorf("写入密码认证响应：%w", err)
	}

	return nil
}

// handleRequest 处理 SOCKS5 协议请求（CONNECT/BIND/UDP ASSOCIATE）
func (s *Server) handleRequest(conn net.Conn) error {
	// 读取客户端的 SOCKS5 请求
	req, err := ReadRequest(conn)
	if err != nil {
		return fmt.Errorf("读取请求：%w", err)
	}

	// 清除握手超时，设置连接为永久阻塞（禁用空闲超时）
	conn.SetDeadline(time.Time{}) // 无限等待

	// 根据命令类型分发处理
	switch req.Cmd {
	case CmdConnect: // TCP 连接请求
		return s.handleConnect(conn, req)
	case CmdBind: // TCP 绑定请求（较少使用）
		return s.handleBind(conn, req)
	case CmdUDPAssociate: // UDP 关联请求
		return s.handleUDPAssociate(conn, req)
	default:
		WriteResponse(conn, ReplyCmdNotSupported, AddrTypeIPv4, "0.0.0.0", 0)
		return ErrInvalidCommand
	}
}

// handleConnect 处理 CONNECT 命令：建立到目标服务器的 TCP 连接
func (s *Server) handleConnect(conn net.Conn, req *Request) error {
	// 创建 TCP 代理对象处理转发
	proxy := NewTCPProxy(conn, s)
	proxy.SetBufferPool(s.bufferPool) // 传递缓冲区池以减少内存分配

	// 如果启用了多用户管理，从认证器获取当前用户名
	if s.config.EnableUserManagement {
		if auth, ok := s.config.Auth.(*PasswordAuth); ok {
			// 优先从连接映射中获取用户名（快速路径）
			s.connUserMu.RLock()
			username, exists := s.connUserMap[conn.RemoteAddr().String()]
			s.connUserMu.RUnlock()

			// 如果映射中不存在，尝试从 IP 映射中查找（容错路径）
			if !exists {
				clientIP := getClientIP(conn)
				username, exists = auth.FindUserByIP(clientIP)
			}

			if exists {
				proxy.SetUsername(username)
			}
		}
	}

	return proxy.HandleConnect(req.DstAddr, req.DstPort) // 连接到目标地址
}

// handleBind 处理 BIND 命令（简化实现，返回不支持）
// BIND 命令用于被动连接场景，实际使用较少
func (s *Server) handleBind(conn net.Conn, req *Request) error {
	// BIND 命令在实际中很少使用，这里返回不支持
	WriteResponse(conn, ReplyCmdNotSupported, AddrTypeIPv4, "0.0.0.0", 0)
	return fmt.Errorf("不支持 BIND 命令")
}

// handleUDPAssociate 处理 UDP ASSOCIATE 命令：建立 UDP 代理关联
func (s *Server) handleUDPAssociate(conn net.Conn, req *Request) error {
	// 创建 UDP 关联对象
	udpAssoc := NewUDPAssociation(conn, s)
	s.stats.AddUDPAssociation() // 更新统计
	defer s.stats.RemoveUDPAssociation()

	// 如果启用了多用户管理，从认证器获取当前用户名
	if s.config.EnableUserManagement {
		if auth, ok := s.config.Auth.(*PasswordAuth); ok {
			// 优先从连接映射中获取用户名（快速路径）
			s.connUserMu.RLock()
			username, exists := s.connUserMap[conn.RemoteAddr().String()]
			s.connUserMu.RUnlock()

			// 如果映射中不存在，尝试从 IP 映射中查找（容错路径）
			if !exists {
				clientIP := getClientIP(conn)
				username, exists = auth.FindUserByIP(clientIP)
			}

			if exists {
				udpAssoc.SetUsername(username)
			}
		}
	}

	// 注意：不在这里调用 wg.Add(1)，因为 UDPAssociation 的 Close() 也不应该调用 wg.Done()
	// UDP 关联的生命周期由 handleUDPData() 和 waitForClose() 管理，不需要纳入服务器的 wg 管理

	return udpAssoc.HandleUDPAssociate()
}

// statsReporter 定期打印服务器统计信息（每 30 秒）
func (s *Server) statsReporter() {
	ticker := time.NewTicker(30 * time.Second) // 创建 30 秒定时器
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Println(s.stats.String()) // 打印统计信息
		case <-s.ctx.Done():
			return // 上下文取消时退出
		}
	}
}

// GetStats 获取当前服务器的统计信息
func (s *Server) GetStats() *Stats {
	return s.stats
}

// getClientIP 从连接中提取客户端 IP 地址
// 参数 conn: 网络连接对象
// 返回：客户端 IP 地址字符串
func getClientIP(conn net.Conn) string {
	addr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if ok {
		return addr.IP.String() // 返回 IP 字符串
	}
	return conn.RemoteAddr().String() // 备用方案
}

// isDNSError 判断错误是否为 DNS 解析失败
// 参数 err: 需要判断的错误对象
// 返回：true 表示是 DNS 错误，false 表示不是
func isDNSError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// 检查是否包含 DNS 相关错误信息
	return strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "lookup") ||
		strings.Contains(errStr, "DNS")
}

// isConnectionError 判断错误是否是连接目标服务器失败（非代理服务器问题）
// 参数 err: 需要判断的错误对象
// 返回：true 表示是连接错误，false 表示不是
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// 检查是否包含连接错误信息
	return strings.Contains(errStr, "i/o timeout") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connect:")
}

// copyWithBuffer 使用指定缓冲区复制数据，减少内存分配
// 参数 dst: 目标写入器；src: 源读取器；buf: 缓冲区
// 返回：复制的字节数和可能的错误
func copyWithBuffer(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	return io.CopyBuffer(dst, src, buf)
}

// userDataPersister 定期持久化用户数据到数据库（防止重启丢失）
func (s *Server) userDataPersister() {
	ticker := time.NewTicker(10 * time.Second) // 每 10 秒保存一次
	defer ticker.Stop()

	for range ticker.C {
		select {
		case <-s.ctx.Done():
			return
		default:
			// 如果是 PasswordAuth，持久化所有用户数据
			if auth, ok := s.config.Auth.(*PasswordAuth); ok {
				s.persistUsers(auth)
			}
		}
	}
}

// persistUsers 持久化用户数据到数据库
func (s *Server) persistUsers(auth *PasswordAuth) {
	// 先复制数据，避免持有锁期间进行数据库 IO 操作
	auth.mu.RLock()
	type userSnapshot struct {
		username string
		user     *User
	}
	snapshots := make([]userSnapshot, 0, len(auth.users))

	for username, user := range auth.users {
		// 读取原子值并创建副本
		snapshot := &User{
			Username:         user.Username,
			Password:         user.Password,
			ReadSpeedLimit:   user.ReadSpeedLimit,
			WriteSpeedLimit:  user.WriteSpeedLimit,
			MaxConnections:   user.MaxConnections,
			MaxIPConnections: user.MaxIPConnections,
			Enabled:          user.Enabled,
			UploadTotal:      atomic.LoadInt64(&user.UploadTotal),
			DownloadTotal:    atomic.LoadInt64(&user.DownloadTotal),
			CreateTime:       user.CreateTime,
			LastActivity:     atomic.LoadInt64(&user.LastActivity),
			QuotaPeriod:      user.QuotaPeriod,
			QuotaBytes:       user.QuotaBytes,
			QuotaUsed:        atomic.LoadInt64(&user.QuotaUsed),
			QuotaResetTime:   user.QuotaResetTime,
			QuotaStartTime:   user.QuotaStartTime,
			QuotaEndTime:     user.QuotaEndTime,
		}
		snapshots = append(snapshots, userSnapshot{username: username, user: snapshot})
	}
	auth.mu.RUnlock()

	if dbManager == nil {
		log.Printf("警告：数据库管理器未初始化，无法持久化用户数据")
		return
	}

	savedCount := 0
	failedCount := 0

	// 释放锁后进行数据库写入
	for _, snapshot := range snapshots {
		username := snapshot.username
		userCopy := snapshot.user

		// 保存到数据库
		if err := dbManager.SaveUser(userCopy); err != nil {
			log.Printf("❌ 持久化用户 [%s] 失败：%v", username, err)
			failedCount++
		} else {
			if userCopy.QuotaUsed > 0 {
				log.Printf("✅ 持久化用户 [%s] 成功 (配额：%.2f MB / %.2f MB)",
					username, float64(userCopy.QuotaUsed)/1024/1024, float64(userCopy.QuotaBytes)/1024/1024)
			}
			savedCount++
		}
	}

}
