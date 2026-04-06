// Package main 实现 SOCKS5 代理服务器的核心服务模块。
// 负责监听客户端连接、处理认证握手、路由命令请求，
// 并协调 TCP/UDP 代理转发。
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config 服务器配置结构体，包含所有可配置的参数。
type Config struct {
	ReadSpeedLimit  int64 // 全局上传速度限制（字节/秒），0 表示不限速
	WriteSpeedLimit int64 // 全局下载速度限制（字节/秒），0 表示不限速

	ListenAddr string // 监听地址，格式为 "IP:Port"

	Auth Authenticator // 认证器接口，定义用户认证方式

	MaxWorkers int // 最大工作协程数，0 表示不限制

	MaxConnPerIP int // 单个 IP 允许的最大并发连接数

	EnableUserManagement bool // 是否启用用户管理功能

	HandshakeTimeout time.Duration // 握手超时时间

	TCPKeepAlivePeriod time.Duration // TCP Keepalive 周期

	TCPNoDelay bool // 是否禁用 Nagle 算法（降低延迟）

	RecvBufferPool *BufferPool // 接收缓冲区池

	SendBufferPool *BufferPool // 发送缓冲区池
}

// DefaultConfig 返回默认的服务器配置。
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:         "0.0.0.0:1080",
		Auth:               &NoAuth{},
		MaxWorkers:         0,
		MaxConnPerIP:       65535, // 端口最多 65535
		HandshakeTimeout:   10 * time.Second,
		TCPKeepAlivePeriod: 15 * time.Second,
		TCPNoDelay:         true,
		RecvBufferPool:     NewBufferPool(2 * 1024 * 1024),
		SendBufferPool:     NewBufferPool(2 * 1024 * 1024),
	}
}

// Server SOCKS5 服务器核心结构体。
// 管理监听器、工作池、连接管理器、统计信息等组件。
type Server struct {
	config      *Config      // 服务器配置
	listener    net.Listener // TCP 监听器
	pool        *WorkerPool  // 工作协程池
	connManager *ConnManager // 连接管理器（per-IP 限制）
	stats       *Stats       // 统计信息
	bufferPool  *BufferPool  // 缓冲区池

	mu      sync.RWMutex       // 保留锁
	running int32              // 运行状态标志（原子操作）
	wg      sync.WaitGroup     // 等待组，用于优雅关闭
	ctx     context.Context    // 上下文，用于取消操作
	cancel  context.CancelFunc // 取消函数

	zeroBuf []byte // 零值缓冲区（保留）

	connUserMap map[string]string // 连接地址 -> 用户名映射
	connUserMu  sync.RWMutex      // 映射的读写锁
}

// NewServer 创建一个新的 SOCKS5 服务器实例。
//
// 参数:
//   - config: 服务器配置，nil 则使用默认配置
//
// 返回:
//   - *Server: 初始化后的服务器实例
func NewServer(config *Config) *Server {
	if config == nil {
		config = DefaultConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	recvBufferPool := config.RecvBufferPool
	if recvBufferPool == nil {
		recvBufferPool = NewBufferPool(32 * 1024)
	}

	return &Server{
		config:      config,
		pool:        NewWorkerPool(config.MaxWorkers),
		connManager: NewConnManager(config.MaxConnPerIP),
		stats:       NewStats(),
		bufferPool:  recvBufferPool,
		ctx:         ctx,
		cancel:      cancel,
		zeroBuf:     make([]byte, 512),
		connUserMap: make(map[string]string),
	}
}

// Start 启动 SOCKS5 服务器，开始监听并接受客户端连接。
// 该方法是阻塞的，会在单独的 goroutine 中运行。
//
// 返回:
//   - error: 启动错误
func (s *Server) Start() error {
	// 原子检查并设置运行状态
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

	if tcpListener, ok := listener.(*net.TCPListener); ok {
		_ = tcpListener.SetDeadline(time.Time{})
	}

	log.Printf("SOCKS5 服务器已启动在 %s (GOMAXPROCS=%d)", s.config.ListenAddr, runtime.GOMAXPROCS(0))

	// 启动统计报告协程（每 30 秒输出一次）
	go s.statsReporter()

	// 如果启用用户管理，启动数据持久化协程（每 10 秒保存一次）
	if s.config.EnableUserManagement {
		go s.userDataPersister()
	}

	// 主循环：接受客户端连接
	for atomic.LoadInt32(&s.running) == 1 {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return nil // 正常关闭
			default:
				log.Printf("接受连接错误：%v", err)
				continue
			}
		}

		// 优化 TCP 连接参数
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			if s.config.TCPNoDelay {
				tcpConn.SetNoDelay(true) // 禁用 Nagle 算法，降低延迟
			}
			if s.config.TCPKeepAlivePeriod > 0 {
				tcpConn.SetKeepAlive(true)
				tcpConn.SetKeepAlivePeriod(s.config.TCPKeepAlivePeriod)
			}
			tcpConn.SetReadBuffer(16 * 1024 * 1024)  // 16MB 接收缓冲区
			tcpConn.SetWriteBuffer(16 * 1024 * 1024) // 16MB 发送缓冲区
			_ = tcpConn
		}

		// 检查 IP 连接数限制
		clientIP := getClientIP(conn)
		if !s.connManager.AddConn(clientIP) {
			log.Printf("IP 连接数超限：%s", clientIP)
			conn.Close()
			continue
		}

		s.wg.Add(1)
		s.stats.AddConnection()

		// 提交到工作池处理连接
		s.pool.Submit(func() {
			defer func() {
				s.connManager.RemoveConn(clientIP)
				s.stats.RemoveConnection()
				s.wg.Done()
			}()
			s.handleConnection(conn)
		})
	}

	return nil
}

// Stop 停止服务器，关闭监听器并等待所有连接处理完成。
func (s *Server) Stop() error {
	if !atomic.CompareAndSwapInt32(&s.running, 1, 0) {
		return fmt.Errorf("服务器未运行")
	}

	s.cancel() // 取消上下文

	if s.listener != nil {
		s.listener.Close()
	}

	s.pool.Stop() // 停止工作池
	s.wg.Wait()   // 等待所有连接处理完成

	log.Println("SOCKS5 服务器已停止")
	return nil
}

// IsRunning 检查服务器是否正在运行。
func (s *Server) IsRunning() bool {
	return atomic.LoadInt32(&s.running) == 1
}

// handleConnection 处理单个客户端连接的完整生命周期。
// 包括认证、请求处理和资源清理。
func (s *Server) handleConnection(conn net.Conn) {
	defer func() {
		// 清理连接-用户映射
		s.connUserMu.Lock()
		delete(s.connUserMap, conn.RemoteAddr().String())
		s.connUserMu.Unlock()
		conn.Close()
	}()

	// 从缓冲池获取缓冲区
	buf := s.bufferPool.Get()
	defer s.bufferPool.Put(buf)

	// 设置握手超时
	conn.SetDeadline(time.Now().Add(s.config.HandshakeTimeout))

	// 处理认证握手
	if err := s.handleAuth(conn); err != nil {
		log.Printf("认证失败来自 %s：%v", conn.RemoteAddr(), err)
		s.stats.AddFailedConnection()
		return
	}

	// 处理 SOCKS5 请求
	if err := s.handleRequest(conn); err != nil {
		// DNS 错误和连接错误不计入失败统计
		if !isDNSError(err) && !isConnectionError(err) {
			s.stats.AddFailedConnection()
		}
		return
	}
}

// handleAuth 处理 SOCKS5 认证握手流程。
// 读取客户端支持的认证方法，选择合适的方法并响应。
func (s *Server) handleAuth(conn net.Conn) error {
	req, err := ReadAuthRequest(conn)
	if err != nil {
		return fmt.Errorf("读取认证请求：%w", err)
	}

	serverMethods := []byte{s.config.Auth.Method()}
	selectedMethod := SelectAuthMethod(req.Methods, serverMethods)

	if err := WriteAuthResponse(conn, selectedMethod); err != nil {
		return fmt.Errorf("写入认证响应：%w", err)
	}

	if selectedMethod == AuthNoAccept {
		return ErrInvalidAuthMethod
	}

	// 如果选择密码认证，处理密码认证流程
	if selectedMethod == AuthPassword {
		if err := s.handlePasswordAuth(conn); err != nil {
			return err
		}
	}

	return nil
}

// handlePasswordAuth 处理用户名/密码认证流程。
// 验证凭据后检查用户的连接数和 IP 限制。
func (s *Server) handlePasswordAuth(conn net.Conn) error {
	req, err := ReadPasswordAuthRequest(conn)
	if err != nil {
		return fmt.Errorf("读取密码认证：%w", err)
	}

	// 验证用户名和密码
	if !s.config.Auth.Authenticate(req.Uname, req.Passwd) {
		WritePasswordAuthResponse(conn, 0x01) // 认证失败
		return ErrAuthFailed
	}

	// 如果启用用户管理，检查连接限制
	if s.config.EnableUserManagement {
		if auth, ok := s.config.Auth.(*PasswordAuth); ok {
			clientIP := getClientIP(conn)

			// 检查 IP 连接数限制
			if !auth.CheckUserIPLimit(req.Uname, clientIP) {
				log.Printf("用户 %s IP 连接数超限（当前 IP：%s，已连接 IP 数：%d）",
					req.Uname, clientIP, auth.GetUserIPCount(req.Uname))
				WritePasswordAuthResponse(conn, 0x01)
				return fmt.Errorf("用户 IP 连接数超限")
			}

			// 检查总连接数限制
			if !auth.CheckUserConnectionLimit(req.Uname) {
				log.Printf("用户 %s 连接数超限（当前：%d）", req.Uname, auth.GetUserConnectionCount(req.Uname))
				WritePasswordAuthResponse(conn, 0x01)
				return fmt.Errorf("用户连接数超限")
			}

			// 记录连接
			auth.IncrementUserConnection(req.Uname)
			auth.AddUserIP(req.Uname, clientIP)
			s.connUserMu.Lock()
			s.connUserMap[conn.RemoteAddr().String()] = req.Uname
			s.connUserMu.Unlock()
		}
	}

	// 认证成功
	if err := WritePasswordAuthResponse(conn, 0x00); err != nil {
		return fmt.Errorf("写入密码认证响应：%w", err)
	}

	return nil
}

// handleRequest 处理 SOCKS5 命令请求。
// 根据命令类型路由到不同的处理器（CONNECT/BIND/UDP ASSOCIATE）。
func (s *Server) handleRequest(conn net.Conn) error {
	req, err := ReadRequest(conn)
	if err != nil {
		return fmt.Errorf("读取请求：%w", err)
	}

	// 清除超时，进入数据传输阶段
	conn.SetDeadline(time.Time{})

	switch req.Cmd {
	case CmdConnect:
		return s.handleConnect(conn, req)
	case CmdBind:
		return s.handleBind(conn, req)
	case CmdUDPAssociate:
		return s.handleUDPAssociate(conn, req)
	default:
		WriteResponse(conn, ReplyCmdNotSupported, AddrTypeIPv4, "0.0.0.0", 0)
		return ErrInvalidCommand
	}
}

// handleConnect 处理 CONNECT 命令，建立 TCP 隧道。
func (s *Server) handleConnect(conn net.Conn, req *Request) error {
	proxy := NewTCPProxy(conn, s)
	proxy.SetBufferPool(s.bufferPool)

	// 设置用户名以便流量统计
	if s.config.EnableUserManagement {
		if auth, ok := s.config.Auth.(*PasswordAuth); ok {
			s.connUserMu.RLock()
			username, exists := s.connUserMap[conn.RemoteAddr().String()]
			s.connUserMu.RUnlock()

			if !exists {
				clientIP := getClientIP(conn)
				username, exists = auth.FindUserByIP(clientIP)
			}

			if exists {
				proxy.SetUsername(username)
			}
		}
	}

	return proxy.HandleConnect(req.DstAddr, req.DstPort)
}

// handleBind 处理 BIND 命令（当前不支持）。
func (s *Server) handleBind(conn net.Conn, req *Request) error {
	WriteResponse(conn, ReplyCmdNotSupported, AddrTypeIPv4, "0.0.0.0", 0)
	return fmt.Errorf("不支持 BIND 命令")
}

// handleUDPAssociate 处理 UDP ASSOCIATE 命令，建立 UDP 关联。
func (s *Server) handleUDPAssociate(conn net.Conn, req *Request) error {
	udpAssoc := NewUDPAssociation(conn, s)
	s.stats.AddUDPAssociation()
	defer s.stats.RemoveUDPAssociation()

	// 设置用户名以便流量统计
	if s.config.EnableUserManagement {
		if auth, ok := s.config.Auth.(*PasswordAuth); ok {
			s.connUserMu.RLock()
			username, exists := s.connUserMap[conn.RemoteAddr().String()]
			s.connUserMu.RUnlock()

			if !exists {
				clientIP := getClientIP(conn)
				username, exists = auth.FindUserByIP(clientIP)
			}

			if exists {
				udpAssoc.SetUsername(username)
			}
		}
	}

	return udpAssoc.HandleUDPAssociate()
}

// statsReporter 定期输出服务器统计信息（每 30 秒）。
func (s *Server) statsReporter() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Println(s.stats.String())
		case <-s.ctx.Done():
			return
		}
	}
}

// GetStats 获取服务器统计信息。
func (s *Server) GetStats() *Stats {
	return s.stats
}

// getClientIP 从连接中提取客户端 IP 地址。
func getClientIP(conn net.Conn) string {
	addr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if ok {
		return addr.IP.String()
	}
	return conn.RemoteAddr().String()
}

// isDNSError 判断错误是否为 DNS 解析错误。
func isDNSError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "lookup") ||
		strings.Contains(errStr, "DNS")
}

// isConnectionError 判断错误是否为网络连接错误。
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "i/o timeout") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connect:")
}

// copyWithBuffer 使用指定缓冲区复制数据。
func copyWithBuffer(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	return io.CopyBuffer(dst, src, buf)
}

// userDataPersister 定期将内存中的用户数据持久化到数据库（每 10 秒）。
func (s *Server) userDataPersister() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		select {
		case <-s.ctx.Done():
			return
		default:
			if auth, ok := s.config.Auth.(*PasswordAuth); ok {
				s.persistUsers(auth)
			}
		}
	}
}

// persistUsers 将内存中的用户数据快照保存到数据库。
// 使用快照机制避免长时间持有锁。
func (s *Server) persistUsers(auth *PasswordAuth) {
	auth.mu.RLock()
	type userSnapshot struct {
		username string
		user     *User
	}
	snapshots := make([]userSnapshot, 0, len(auth.users))

	// 创建用户数据快照（原子读取）
	for username, user := range auth.users {
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

	// 逐个保存用户数据
	for _, snapshot := range snapshots {
		username := snapshot.username
		userCopy := snapshot.user

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
