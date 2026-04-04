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

type Config struct {
	ReadSpeedLimit  int64
	WriteSpeedLimit int64

	ListenAddr string

	Auth Authenticator

	MaxWorkers int

	MaxConnPerIP int

	EnableUserManagement bool

	HandshakeTimeout time.Duration

	TCPKeepAlivePeriod time.Duration

	TCPNoDelay bool

	RecvBufferPool *BufferPool

	SendBufferPool *BufferPool
}

func DefaultConfig() *Config {
	return &Config{
		ListenAddr:         "0.0.0.0:1080",
		Auth:               &NoAuth{},
		MaxWorkers:         0,
		MaxConnPerIP:       65535, //端口最多65535
		HandshakeTimeout:   10 * time.Second,
		TCPKeepAlivePeriod: 15 * time.Second,
		TCPNoDelay:         true,
		RecvBufferPool:     NewBufferPool(2 * 1024 * 1024),
		SendBufferPool:     NewBufferPool(2 * 1024 * 1024),
	}
}

type Server struct {
	config      *Config
	listener    net.Listener
	pool        *WorkerPool
	connManager *ConnManager
	stats       *Stats
	bufferPool  *BufferPool

	mu      sync.RWMutex
	running int32
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc

	zeroBuf []byte

	connUserMap map[string]string
	connUserMu  sync.RWMutex
}

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

func (s *Server) Start() error {
	if !atomic.CompareAndSwapInt32(&s.running, 0, 1) {
		return fmt.Errorf("服务器已在运行中")
	}

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

	go s.statsReporter()

	if s.config.EnableUserManagement {
		go s.userDataPersister()
	}

	for atomic.LoadInt32(&s.running) == 1 {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return nil
			default:
				log.Printf("接受连接错误：%v", err)
				continue
			}
		}

		if tcpConn, ok := conn.(*net.TCPConn); ok {
			if s.config.TCPNoDelay {
				tcpConn.SetNoDelay(true)
			}
			if s.config.TCPKeepAlivePeriod > 0 {
				tcpConn.SetKeepAlive(true)
				tcpConn.SetKeepAlivePeriod(s.config.TCPKeepAlivePeriod)
			}
			tcpConn.SetReadBuffer(16 * 1024 * 1024)
			tcpConn.SetWriteBuffer(16 * 1024 * 1024)
			_ = tcpConn
		}

		clientIP := getClientIP(conn)
		if !s.connManager.AddConn(clientIP) {
			log.Printf("IP 连接数超限：%s", clientIP)
			conn.Close()
			continue
		}

		s.wg.Add(1)
		s.stats.AddConnection()

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

func (s *Server) Stop() error {
	if !atomic.CompareAndSwapInt32(&s.running, 1, 0) {
		return fmt.Errorf("服务器未运行")
	}

	s.cancel()

	if s.listener != nil {
		s.listener.Close()
	}

	s.pool.Stop()
	s.wg.Wait()

	log.Println("SOCKS5 服务器已停止")
	return nil
}

func (s *Server) IsRunning() bool {
	return atomic.LoadInt32(&s.running) == 1
}

func (s *Server) handleConnection(conn net.Conn) {
	defer func() {
		s.connUserMu.Lock()
		delete(s.connUserMap, conn.RemoteAddr().String())
		s.connUserMu.Unlock()
		conn.Close()
	}()

	buf := s.bufferPool.Get()
	defer s.bufferPool.Put(buf)

	conn.SetDeadline(time.Now().Add(s.config.HandshakeTimeout))

	if err := s.handleAuth(conn); err != nil {
		log.Printf("认证失败来自 %s：%v", conn.RemoteAddr(), err)
		s.stats.AddFailedConnection()
		return
	}

	if err := s.handleRequest(conn); err != nil {

		if !isDNSError(err) && !isConnectionError(err) {
			s.stats.AddFailedConnection()
		}
		return
	}
}

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

	if selectedMethod == AuthPassword {
		if err := s.handlePasswordAuth(conn); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) handlePasswordAuth(conn net.Conn) error {
	req, err := ReadPasswordAuthRequest(conn)
	if err != nil {
		return fmt.Errorf("读取密码认证：%w", err)
	}

	if !s.config.Auth.Authenticate(req.Uname, req.Passwd) {
		WritePasswordAuthResponse(conn, 0x01)
		return ErrAuthFailed
	}

	if s.config.EnableUserManagement {
		if auth, ok := s.config.Auth.(*PasswordAuth); ok {
			clientIP := getClientIP(conn)

			if !auth.CheckUserIPLimit(req.Uname, clientIP) {
				log.Printf("用户 %s IP 连接数超限（当前 IP：%s，已连接 IP 数：%d）",
					req.Uname, clientIP, auth.GetUserIPCount(req.Uname))
				WritePasswordAuthResponse(conn, 0x01)
				return fmt.Errorf("用户 IP 连接数超限")
			}

			if !auth.CheckUserConnectionLimit(req.Uname) {
				log.Printf("用户 %s 连接数超限（当前：%d）", req.Uname, auth.GetUserConnectionCount(req.Uname))
				WritePasswordAuthResponse(conn, 0x01)
				return fmt.Errorf("用户连接数超限")
			}

			auth.IncrementUserConnection(req.Uname)
			auth.AddUserIP(req.Uname, clientIP)
			s.connUserMu.Lock()
			s.connUserMap[conn.RemoteAddr().String()] = req.Uname
			s.connUserMu.Unlock()
		}
	}

	if err := WritePasswordAuthResponse(conn, 0x00); err != nil {
		return fmt.Errorf("写入密码认证响应：%w", err)
	}

	return nil
}

func (s *Server) handleRequest(conn net.Conn) error {
	req, err := ReadRequest(conn)
	if err != nil {
		return fmt.Errorf("读取请求：%w", err)
	}

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

func (s *Server) handleConnect(conn net.Conn, req *Request) error {
	proxy := NewTCPProxy(conn, s)
	proxy.SetBufferPool(s.bufferPool)

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

func (s *Server) handleBind(conn net.Conn, req *Request) error {
	WriteResponse(conn, ReplyCmdNotSupported, AddrTypeIPv4, "0.0.0.0", 0)
	return fmt.Errorf("不支持 BIND 命令")
}

func (s *Server) handleUDPAssociate(conn net.Conn, req *Request) error {
	udpAssoc := NewUDPAssociation(conn, s)
	s.stats.AddUDPAssociation()
	defer s.stats.RemoveUDPAssociation()

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

func (s *Server) GetStats() *Stats {
	return s.stats
}

func getClientIP(conn net.Conn) string {
	addr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if ok {
		return addr.IP.String()
	}
	return conn.RemoteAddr().String()
}

func isDNSError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "lookup") ||
		strings.Contains(errStr, "DNS")
}

func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "i/o timeout") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connect:")
}

func copyWithBuffer(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	return io.CopyBuffer(dst, src, buf)
}

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

func (s *Server) persistUsers(auth *PasswordAuth) {
	auth.mu.RLock()
	type userSnapshot struct {
		username string
		user     *User
	}
	snapshots := make([]userSnapshot, 0, len(auth.users))

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
