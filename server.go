// Package main 实现 SOCKS5 代理服务器的核心服务模块。
// 负责监听客户端连接、处理认证握手、路由命令请求，
// 并协调 TCP/UDP 代理转发。
package main

// 导入标准库和第三方包
import (
	"context" // 上下文控制包，用于优雅关闭和超时控制
	"fmt"     // 格式化输出包，提供字符串格式化和错误包装
	"io"      // IO 接口包，定义 Reader/Writer 等基础接口
	"log"     // 日志包，用于输出运行状态和错误信息
	"net"     // 网络包，提供 TCP/UDP 网络连接功能
	"runtime" // 运行时包，获取 CPU 核心数等系统信息
	"runtime/debug"
	"strings"     // 字符串处理包，提供字符串搜索和匹配功能
	"sync"        // 同步包，提供互斥锁、等待组等同步原语
	"sync/atomic" // 原子操作包，提供无锁的并发安全操作
	"time"        // 时间包，提供超时控制和定时任务功能
)

// Config 服务器配置结构体，包含所有可配置的参数。
// 该结构体定义了 SOCKS5 服务器的行为特征，包括监听地址、认证方式、
// 并发控制、网络优化等各个方面。
type Config struct {
	ListenAddr string // SOCKS5 服务监听地址，格式为 "IP:Port"，例如 "0.0.0.0:1080" 表示监听所有网卡

	Auth Authenticator // 认证器接口，定义用户认证方式（PasswordAuth 或 NoAuth），决定是否需要用户名密码

	MaxWorkers int // 最大工作协程数，0 表示不限制并发数量，由 Go runtime 自动调度 goroutine

	MaxConnPerIP int // 单个 IP 地址允许的最大并发连接数，防止恶意用户占用过多资源

	EnableUserManagement bool // 是否启用用户管理功能，true 时要求用户名/密码认证并记录流量统计

	HandshakeTimeout time.Duration // SOCKS5 握手超时时间，超过此时间未完成握手则断开连接，防止慢速攻击

	TCPKeepAlivePeriod time.Duration // TCP Keepalive 心跳检测周期，用于检测死连接并及时释放资源

	TCPNoDelay bool // 是否禁用 Nagle 算法，true 可降低延迟但可能增加小包数量，适合实时性要求高的场景

	RecvBufferPool *BufferPool // 接收缓冲区池，用于复用内存减少 GC 压力，提升高并发性能

	SendBufferPool *BufferPool // 发送缓冲区池，用于复用内存减少 GC 压力，与接收缓冲池独立以避免竞争
}

// DefaultConfig 返回默认的服务器配置。
// 针对高吞吐场景优化，使用合理的缓冲区和并发策略。
// 默认配置适合大多数生产环境使用。
//
// 返回:
//   - *Config: 初始化后的默认配置实例
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:         "0.0.0.0:1080",           // 默认监听所有网卡的 1080 端口
		Auth:               &NoAuth{},                // 默认不使用认证（生产环境建议改为 PasswordAuth）
		MaxWorkers:         1000,                     // 最大工作协程数限制为1000，避免无限创建goroutine导致内存溢出
		MaxConnPerIP:       65535,                    // 单 IP 最大连接数（端口上限），实际上不会达到这个值
		HandshakeTimeout:   10 * time.Second,         // 握手超时时间设置为 10 秒，平衡安全性和用户体验
		TCPKeepAlivePeriod: 15 * time.Second,         // TCP Keepalive 周期设置为 15 秒，及时检测死连接
		TCPNoDelay:         true,                     // 禁用 Nagle 算法，降低延迟，提升实时性
		RecvBufferPool:     NewBufferPool(32 * 1024), // 32KB 接收缓冲区池，平衡性能与内存占用
		SendBufferPool:     NewBufferPool(32 * 1024), // 32KB 发送缓冲区池，与接收缓冲池大小一致
	}
}

// Server SOCKS5 服务器核心结构体。
// 管理监听器、工作池、连接管理器、统计信息等组件。
// 是 SOCKS5 代理服务的核心控制器，负责整个生命周期管理。
type Server struct {
	config      *Config      // 服务器配置指针，包含监听地址、认证方式等所有配置参数
	listener    net.Listener // TCP 监听器对象，用于接受来自客户端的新连接请求
	pool        *WorkerPool  // 工作协程池管理器，限制并发处理的连接数量，防止资源耗尽
	connManager *ConnManager // 连接管理器，实现单 IP 最大连接数限制，防止单个客户端滥用
	stats       *Stats       // 统计信息收集器，记录总上传/下载流量、当前连接数等指标
	bufferPool  *BufferPool  // 缓冲区池管理器，复用内存缓冲区以减少 GC 压力和内存分配开销

	mu      sync.RWMutex       // 读写锁（保留字段，当前未直接使用，主要用于未来扩展）
	running int32              // 运行状态标志，使用 atomic 操作确保线程安全：0=停止，1=运行中
	wg      sync.WaitGroup     // 等待组，用于优雅关闭时等待所有正在处理的连接协程结束
	ctx     context.Context    // 上下文对象，用于取消操作和传递请求范围的值，支持优雅关闭
	cancel  context.CancelFunc // 取消函数，调用后触发 ctx.Done() 信号，通知所有协程退出

	zeroBuf []byte // 零值缓冲区（保留字段，当前未使用，预留用于特殊场景）

	connUserMap map[string]string // 连接地址到用户名的映射表，key 为远程地址字符串，value 为用户名，用于追踪哪个连接属于哪个用户
	connUserMu  sync.RWMutex      // connUserMap 的读写锁，保证并发访问映射表时的线程安全
}

// NewServer 创建一个新的 SOCKS5 服务器实例。
// 初始化服务器的所有组件，包括工作池、连接管理器、统计信息等。
//
// 参数:
//   - config: 服务器配置指针，nil 则使用默认配置
//
// 返回:
//   - *Server: 初始化后的服务器实例指针
func NewServer(config *Config) *Server {
	// 如果传入的配置为 nil，则使用默认配置
	if config == nil {
		config = DefaultConfig()
	}

	// 创建可取消的上下文，用于后续的优雅关闭
	ctx, cancel := context.WithCancel(context.Background())

	// 获取配置中的接收缓冲区池
	recvBufferPool := config.RecvBufferPool
	// 如果配置中没有设置接收缓冲区池，则创建一个默认的 32KB 缓冲区池
	if recvBufferPool == nil {
		recvBufferPool = NewBufferPool(32 * 1024)
	}

	// 创建并返回 Server 实例，初始化所有成员变量
	return &Server{
		config:      config,                              // 保存配置引用
		pool:        NewWorkerPool(config.MaxWorkers),    // 创建工作协程池，根据配置的最大工作数
		connManager: NewConnManager(config.MaxConnPerIP), // 创建连接管理器，设置单 IP 最大连接数
		stats:       NewStats(),                          // 创建统计信息收集器
		bufferPool:  recvBufferPool,                      // 设置缓冲区池
		ctx:         ctx,                                 // 保存上下文对象
		cancel:      cancel,                              // 保存取消函数
		zeroBuf:     make([]byte, 512),                   // 初始化 512 字节的零值缓冲区
		connUserMap: make(map[string]string),             // 初始化连接-用户映射表
	}
}

// Start 启动 SOCKS5 服务器，开始监听并接受客户端连接。
// 该方法是阻塞的，会在单独的 goroutine 中运行。
// 启动后会持续接受新连接，直到调用 Stop() 方法或发生致命错误。
//
// 返回:
//   - error: 启动错误，如端口被占用等；正常关闭返回 nil
func (s *Server) Start() error {
	// 使用原子操作检查并设置运行状态，防止重复启动
	// CompareAndSwapInt32 确保只有一个协程能成功将 running 从 0 改为 1
	if !atomic.CompareAndSwapInt32(&s.running, 0, 1) {
		return fmt.Errorf("服务器已在运行中") // 如果已经在运行，返回错误
	}

	// 创建 TCP 监听器，开始监听指定地址
	listener, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		// 如果监听失败，恢复运行状态为 0
		atomic.StoreInt32(&s.running, 0)
		// 返回包装后的错误，包含原始错误信息
		return fmt.Errorf("监听失败：%w", err)
	}
	// 保存监听器引用，供后续使用和关闭
	s.listener = listener

	// 尝试将监听器转换为 TCPListener 类型以设置更多选项
	if tcpListener, ok := listener.(*net.TCPListener); ok {
		// 清除监听器的 deadline，确保不会因为超时而意外关闭
		_ = tcpListener.SetDeadline(time.Time{})
	}

	// 输出服务器已启动的日志，包含监听地址和 GOMAXPROCS 值
	log.Printf("SOCKS5 服务器已启动在 %s (GOMAXPROCS=%d)", s.config.ListenAddr, runtime.GOMAXPROCS(0))

	// 启动统计报告协程，每 30 秒输出一次服务器运行状态
	go s.statsReporter()

	// 如果启用了用户管理功能，启动数据持久化协程和配额重置协程
	if s.config.EnableUserManagement {
		// 每 10 秒将内存中的用户数据保存到数据库
		go s.userDataPersister()
		// 每 60 秒检查并重置过期的配额
		go s.quotaResetChecker()
	}

	// 主循环：持续接受客户端连接，直到服务器停止
	for atomic.LoadInt32(&s.running) == 1 {
		// 接受新的客户端连接，这是一个阻塞调用
		conn, err := listener.Accept()
		if err != nil {
			// 如果接受连接出错，检查是否是正常关闭
			select {
			case <-s.ctx.Done():
				// 如果上下文已取消，说明是正常关闭，返回 nil
				return nil
			default:
				// 否则记录错误日志并继续接受下一个连接
				log.Printf("接受连接错误：%v", err)
				continue
			}
		}

		// 优化 TCP 连接参数，提升吞吐量和降低延迟
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			// 如果配置了禁用 Nagle 算法，则设置为 true 以降低延迟
			if s.config.TCPNoDelay {
				tcpConn.SetNoDelay(true) // 禁用 Nagle 算法，数据包立即发送，不等待累积
			}
			// 如果配置了 TCP Keepalive 周期，则启用 keepalive 并设置周期
			if s.config.TCPKeepAlivePeriod > 0 {
				tcpConn.SetKeepAlive(true)                              // 启用 TCP Keepalive
				tcpConn.SetKeepAlivePeriod(s.config.TCPKeepAlivePeriod) // 设置 Keepalive 检测周期
			}
			// 使用系统默认的 TCP 缓冲区大小，由操作系统自动调优
			_ = tcpConn
		}

		// 从连接中提取客户端 IP 地址
		clientIP := getClientIP(conn)
		// 检查 IP 连接数是否超过限制
		if !s.connManager.AddConn(clientIP) {
			// 如果超过限制，记录日志并关闭连接
			log.Printf("IP 连接数超限：%s", clientIP)
			conn.Close()
			continue // 跳过本次循环，继续接受下一个连接
		}

		// 增加等待组计数，表示有一个新的连接需要处理
		s.wg.Add(1)
		// 增加连接统计计数
		s.stats.AddConnection()

		// 提交连接处理任务到工作池
		s.pool.Submit(func() {
			// 使用 defer 确保无论处理成功与否都会执行清理操作
			defer func() {
				s.connManager.RemoveConn(clientIP) // 从连接管理器中移除该 IP 的连接记录
				s.stats.RemoveConnection()         // 减少活跃连接计数
				s.wg.Done()                        // 减少等待组计数，表示一个连接处理完成
			}()
			// 调用连接处理函数，处理整个 SOCKS5 协议流程
			s.handleConnection(conn)
		})
	}

	// 当循环退出时（running 变为 0），返回 nil 表示正常停止
	return nil
}

// Stop 停止服务器，关闭监听器并等待所有连接处理完成。
// 该方法会优雅地关闭服务器，确保正在处理的连接能够完成。
//
// 返回:
//   - error: 停止错误，如服务器未运行等
func (s *Server) Stop() error {
	// 使用原子操作检查并设置运行状态，防止重复停止
	if !atomic.CompareAndSwapInt32(&s.running, 1, 0) {
		return fmt.Errorf("服务器未运行") // 如果服务器未在运行，返回错误
	}

	// 调用取消函数，触发 ctx.Done() 信号
	s.cancel()

	// 如果监听器存在，则关闭它
	if s.listener != nil {
		s.listener.Close()
	}

	// 停止工作池，不再接受新的任务
	s.pool.Stop()
	// 等待所有正在处理的连接协程结束
	s.wg.Wait()

	// 输出服务器已停止的日志
	log.Println("SOCKS5 服务器已停止")
	// 返回 nil 表示成功停止
	return nil
}

// IsRunning 检查服务器是否正在运行。
// 使用原子操作读取 running 标志，确保线程安全。
//
// 返回:
//   - bool: true 表示服务器正在运行，false 表示已停止
func (s *Server) IsRunning() bool {
	// 原子加载 running 标志并判断是否为 1
	return atomic.LoadInt32(&s.running) == 1
}

// handleConnection 处理单个客户端连接的完整生命周期。
// 包括认证、请求处理和资源清理。
// 该函数在工作协程中执行，不会阻塞主循环。
//
// 参数:
//   - conn: 客户端的网络连接对象
func (s *Server) handleConnection(conn net.Conn) {
	// 使用 defer 确保连接处理完成后执行清理操作
	defer func() {
		// 加锁保护连接-用户映射表的删除操作
		s.connUserMu.Lock()
		// 从映射表中删除该连接的记录
		delete(s.connUserMap, conn.RemoteAddr().String())
		// 解锁
		s.connUserMu.Unlock()
		// 关闭网络连接，释放资源
		conn.Close()
	}()

	// 从缓冲池中获取一个缓冲区，用于后续的读写操作
	buf := s.bufferPool.Get()
	// 使用 defer 确保函数返回时将缓冲区归还到池中
	defer s.bufferPool.Put(buf)

	// 设置握手阶段的超时时间，防止客户端长时间不发送数据
	conn.SetDeadline(time.Now().Add(s.config.HandshakeTimeout))

	// 处理认证握手流程
	if err := s.handleAuth(conn); err != nil {
		// 如果认证失败，记录日志
		log.Printf("认证失败来自 %s：%v", conn.RemoteAddr(), err)
		// 增加失败连接计数
		s.stats.AddFailedConnection()
		// 返回，结束连接处理
		return
	}

	// 处理 SOCKS5 命令请求（CONNECT/BIND/UDP ASSOCIATE）
	if err := s.handleRequest(conn); err != nil {
		// 如果是 DNS 错误或连接错误，不计入失败统计（这些是目标服务器的问题）
		if !isDNSError(err) && !isConnectionError(err) {
			// 其他类型的错误计入失败统计
			s.stats.AddFailedConnection()
		}
		// 返回，结束连接处理
		return
	}
}

// handleAuth 处理 SOCKS5 认证握手流程。
// 读取客户端支持的认证方法，选择合适的方法并响应。
//
// 参数:
//   - conn: 客户端的网络连接对象
//
// 返回:
//   - error: 认证过程中的错误
func (s *Server) handleAuth(conn net.Conn) error {
	// 从连接中读取认证请求
	req, err := ReadAuthRequest(conn)
	if err != nil {
		// 如果读取失败，返回包装后的错误
		return fmt.Errorf("读取认证请求：%w", err)
	}

	// 获取服务器支持的认证方法列表（通常只有一个）
	serverMethods := []byte{s.config.Auth.Method()}
	// 从客户端支持的方法和服务端支持的方法中选择一个共同支持的方法
	selectedMethod := SelectAuthMethod(req.Methods, serverMethods)

	// 向客户端发送选定的认证方法
	if err := WriteAuthResponse(conn, selectedMethod); err != nil {
		// 如果写入响应失败，返回错误
		return fmt.Errorf("写入认证响应：%w", err)
	}

	// 如果没有可接受的认证方法，返回错误
	if selectedMethod == AuthNoAccept {
		return ErrInvalidAuthMethod
	}

	// 如果选择的是密码认证方法，则需要进一步处理密码认证流程
	if selectedMethod == AuthPassword {
		// 调用密码认证处理函数
		if err := s.handlePasswordAuth(conn); err != nil {
			// 如果密码认证失败，返回错误
			return err
		}
	}

	// 认证成功或无需认证，返回 nil
	return nil
}

// handlePasswordAuth 处理用户名/密码认证流程。
// 验证凭据后检查用户的连接数和 IP 限制。
//
// 参数:
//   - conn: 客户端的网络连接对象
//
// 返回:
//   - error: 密码认证过程中的错误
func (s *Server) handlePasswordAuth(conn net.Conn) error {
	// 从连接中读取密码认证请求（包含用户名和密码）
	req, err := ReadPasswordAuthRequest(conn)
	if err != nil {
		// 如果读取失败，返回包装后的错误
		return fmt.Errorf("读取密码认证：%w", err)
	}

	// 调用认证器的 Authenticate 方法验证用户名和密码
	if !s.config.Auth.Authenticate(req.Uname, req.Passwd) {
		// 如果认证失败，向客户端发送失败响应（状态码 0x01）
		WritePasswordAuthResponse(conn, 0x01)
		// 返回认证失败错误
		return ErrAuthFailed
	}

	// 如果使用密码认证，需要进行额外的连接限制检查
	// 直接检查认证器类型，而不是依赖 EnableUserManagement 配置
	if auth, ok := s.config.Auth.(*PasswordAuth); ok {
		// 获取客户端的 IP 地址
		clientIP := getClientIP(conn)

		// 检查用户流量配额是否已用尽
		if auth.CheckQuotaExceeded(req.Uname) {
			// 如果配额已用尽，记录日志
			log.Printf("用户 %s 流量配额已用尽，拒绝连接", req.Uname)
			// 向客户端发送认证失败响应
			WritePasswordAuthResponse(conn, 0x01)
			// 返回错误
			return fmt.Errorf("用户流量配额已用尽")
		}

		// 检查该用户的 IP 连接数是否超过限制
		if !auth.CheckUserIPLimit(req.Uname, clientIP) {
			// 如果超过限制，记录日志
			log.Printf("用户 %s IP 连接数超限（当前 IP：%s，已连接 IP 数：%d）", req.Uname, clientIP, auth.GetUserIPCount(req.Uname))
			// 向客户端发送认证失败响应
			WritePasswordAuthResponse(conn, 0x01)
			// 返回错误
			return fmt.Errorf("用户 IP 连接数超限")
		}

		// 检查该用户的总连接数是否超过限制
		if !auth.CheckUserConnectionLimit(req.Uname) {
			// 如果超过限制，记录日志
			log.Printf("用户 %s 连接数超限（当前：%d）", req.Uname, auth.GetUserConnectionCount(req.Uname))
			// 向客户端发送认证失败响应
			WritePasswordAuthResponse(conn, 0x01)
			// 返回错误
			return fmt.Errorf("用户连接数超限")
		}

		// 通过所有限制检查，增加用户的连接计数
		auth.IncrementUserConnection(req.Uname)
		// 将该 IP 添加到用户的已连接 IP 列表中
		auth.AddUserIP(req.Uname, clientIP)
		// 加锁保护连接-用户映射表的写入操作
		s.connUserMu.Lock()
		// 在映射表中记录该连接对应的用户名
		s.connUserMap[conn.RemoteAddr().String()] = req.Uname
		// 解锁
		s.connUserMu.Unlock()
	}

	// 认证成功，向客户端发送成功响应（状态码 0x00）
	if err := WritePasswordAuthResponse(conn, 0x00); err != nil {
		// 如果写入响应失败，返回错误
		return fmt.Errorf("写入密码认证响应：%w", err)
	}

	// 返回 nil 表示认证成功
	return nil
}

// handleRequest 处理 SOCKS5 命令请求。
// 根据命令类型路由到不同的处理器（CONNECT/BIND/UDP ASSOCIATE）。
//
// 参数:
//   - conn: 客户端的网络连接对象
//
// 返回:
//   - error: 请求处理过程中的错误
func (s *Server) handleRequest(conn net.Conn) error {
	// 从连接中读取 SOCKS5 命令请求
	req, err := ReadRequest(conn)
	if err != nil {
		// 如果读取失败，返回包装后的错误
		return fmt.Errorf("读取请求：%w", err)
	}

	// 清除之前设置的超时，进入数据传输阶段（不再限制时间）
	conn.SetDeadline(time.Time{})

	// 根据命令类型进行不同的处理
	switch req.Cmd {
	case CmdConnect:
		// CONNECT 命令：建立 TCP 隧道
		return s.handleConnect(conn, req)
	case CmdBind:
		// BIND 命令：绑定端口（当前不支持）
		return s.handleBind(conn, req)
	case CmdUDPAssociate:
		// UDP ASSOCIATE 命令：建立 UDP 关联
		return s.handleUDPAssociate(conn, req)
	default:
		// 不支持的命令类型，向客户端发送错误响应
		WriteResponse(conn, ReplyCmdNotSupported, AddrTypeIPv4, "0.0.0.0", 0)
		// 返回无效命令错误
		return ErrInvalidCommand
	}
}

// handleConnect 处理 CONNECT 命令，建立 TCP 隧道。
// 这是最常用的 SOCKS5 命令，用于代理 TCP 连接。
//
// 参数:
//   - conn: 客户端的网络连接对象
//   - req: 解析后的 SOCKS5 请求结构
//
// 返回:
//   - error: 连接处理过程中的错误
func (s *Server) handleConnect(conn net.Conn, req *Request) error {
	// 创建 TCP 代理实例
	proxy := NewTCPProxy(conn, s)
	// 设置代理使用的缓冲区池
	proxy.SetBufferPool(s.bufferPool)

	// 如果当前使用密码认证，需要设置用户名以便流量统计和配额检查
	// 直接检查认证器类型，而不是依赖 EnableUserManagement 配置
	if auth, ok := s.config.Auth.(*PasswordAuth); ok {
		// 加读锁保护连接-用户映射表的读取
		s.connUserMu.RLock()
		// 从映射表中查找该连接对应的用户名
		connKey := conn.RemoteAddr().String()
		username, exists := s.connUserMap[connKey]
		// 解锁
		s.connUserMu.RUnlock()

		// 如果在映射表中没有找到用户名
		if !exists {
			// 获取客户端 IP 地址
			clientIP := getClientIP(conn)
			// 尝试通过 IP 地址在认证器中查找用户
			username, exists = auth.FindUserByIP(clientIP)
		}

		// 如果找到了用户名，设置到代理中并检查配额
		if exists {
			// 检查用户流量配额是否已用尽
			if auth.CheckQuotaExceeded(username) {
				// 如果配额已用尽，记录日志
				log.Printf("用户 %s 流量配额已用尽，拒绝 TCP 连接", username)
				// 向客户端发送错误响应
				WriteResponse(conn, ReplyGeneralFailure, AddrTypeIPv4, "0.0.0.0", 0)
				// 返回错误
				return fmt.Errorf("用户流量配额已用尽")
			}
			proxy.SetUsername(username)
		}
	}

	// 调用代理的 HandleConnect 方法，建立到目标地址的 TCP 连接并开始转发
	return proxy.HandleConnect(req.DstAddr, req.DstPort)
}

// handleBind 处理 BIND 命令（当前不支持）。
// BIND 命令用于 FTP 等需要服务端主动连接客户端的场景。
//
// 参数:
//   - conn: 客户端的网络连接对象
//   - req: 解析后的 SOCKS5 请求结构
//
// 返回:
//   - error: 始终返回不支持的错误
func (s *Server) handleBind(conn net.Conn, req *Request) error {
	// 向客户端发送命令不支持的响应
	WriteResponse(conn, ReplyCmdNotSupported, AddrTypeIPv4, "0.0.0.0", 0)
	// 返回错误信息
	return fmt.Errorf("不支持 BIND 命令")
}

// handleUDPAssociate 处理 UDP ASSOCIATE 命令，建立 UDP 关联。
// 用于代理 UDP 数据包，常用于 DNS 查询等场景。
//
// 参数:
//   - conn: 客户端的 TCP 控制连接
//   - req: 解析后的 SOCKS5 请求结构
//
// 返回:
//   - error: UDP 关联处理过程中的错误
func (s *Server) handleUDPAssociate(conn net.Conn, req *Request) error {
	// 创建 UDP 关联实例
	udpAssoc := NewUDPAssociation(conn, s)
	// 增加 UDP 关联统计计数
	s.stats.AddUDPAssociation()
	// 使用 defer 确保函数返回时减少 UDP 关联计数
	defer s.stats.RemoveUDPAssociation()

	// 如果当前使用密码认证，需要设置用户名以便流量统计和配额检查
	// 直接检查认证器类型，而不是依赖 EnableUserManagement 配置
	if auth, ok := s.config.Auth.(*PasswordAuth); ok {
		// 加读锁保护连接-用户映射表的读取
		s.connUserMu.RLock()
		// 从映射表中查找该连接对应的用户名
		username, exists := s.connUserMap[conn.RemoteAddr().String()]
		// 解锁
		s.connUserMu.RUnlock()

		// 如果在映射表中没有找到用户名
		if !exists {
			// 获取客户端 IP 地址
			clientIP := getClientIP(conn)
			// 尝试通过 IP 地址在认证器中查找用户
			username, exists = auth.FindUserByIP(clientIP)
		}

		// 如果找到了用户名，设置到 UDP 关联中并检查配额
		if exists {
			// 检查用户流量配额是否已用尽
			if auth.CheckQuotaExceeded(username) {
				// 如果配额已用尽，记录日志
				log.Printf("用户 %s 流量配额已用尽，拒绝 UDP 连接", username)
				// 向客户端发送错误响应
				WriteResponse(conn, ReplyGeneralFailure, AddrTypeIPv4, "0.0.0.0", 0)
				// 返回错误
				return fmt.Errorf("用户流量配额已用尽")
			}
			udpAssoc.SetUsername(username)
		}
	}

	// 调用 UDP 关联的 HandleUDPAssociate 方法，开始处理 UDP 数据转发
	return udpAssoc.HandleUDPAssociate()
}

// statsReporter 定期输出服务器统计信息（每 30 秒）。
// 该协程在后台运行，直到服务器停止。
func (s *Server) statsReporter() {
	// 创建一个 30 秒间隔的定时器
	ticker := time.NewTicker(30 * time.Second)
	// 使用 defer 确保函数返回时停止定时器，释放资源
	defer ticker.Stop()

	// 无限循环，定期输出统计信息
	for {
		// 使用 select 同时监听定时器事件和上下文取消信号
		select {
		case <-ticker.C:
			// 定时器触发，输出当前统计信息
			log.Println(s.stats.String())

			// 输出 Go runtime 内存统计信息
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			log.Printf("[内存] Alloc=%.2fMB, TotalAlloc=%.2fMB, Sys=%.2fMB, NumGC=%d",
				float64(m.Alloc)/1024/1024,
				float64(m.TotalAlloc)/1024/1024,
				float64(m.Sys)/1024/1024,
				m.NumGC)

			// 如果 Sys 远大于 Alloc，尝试释放内存给 OS
			if m.Sys > m.Alloc*2 && m.Sys > 100*1024*1024 {
				runtime.GC()
				debug.FreeOSMemory()
				log.Println("[内存] 已尝试释放未使用的内存给操作系统")
			}
		case <-s.ctx.Done():
			// 上下文已取消，退出循环
			return
		}
	}
}

// GetStats 获取服务器统计信息。
// 返回统计信息对象的指针，调用者可以读取当前的统计数据。
//
// 返回:
//   - *Stats: 统计信息对象指针
func (s *Server) GetStats() *Stats {
	// 直接返回 stats 字段
	return s.stats
}

// getClientIP 从连接中提取客户端 IP 地址。
// 优先使用 TCPAddr 类型的 IP，如果失败则使用 RemoteAddr 的字符串表示。
//
// 参数:
//   - conn: 网络连接对象
//
// 返回:
//   - string: 客户端 IP 地址字符串
func getClientIP(conn net.Conn) string {
	// 尝试将远程地址转换为 TCPAddr 类型
	addr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if ok {
		// 如果转换成功，返回 IP 地址的字符串表示
		return addr.IP.String()
	}
	// 如果转换失败，返回 RemoteAddr 的完整字符串表示
	return conn.RemoteAddr().String()
}

// isDNSError 判断错误是否为 DNS 解析错误。
// DNS 错误通常是由于目标主机名无法解析导致的，不应计入连接失败统计。
//
// 参数:
//   - err: 待判断的错误对象
//
// 返回:
//   - bool: true 表示是 DNS 错误，false 表示不是
func isDNSError(err error) bool {
	// 如果错误为 nil，直接返回 false
	if err == nil {
		return false
	}
	// 获取错误的字符串表示
	errStr := err.Error()
	// 检查错误信息中是否包含 DNS 相关的关键词
	return strings.Contains(errStr, "no such host") || // "no such host" 表示主机不存在
		strings.Contains(errStr, "lookup") || // "lookup" 表示 DNS 查询
		strings.Contains(errStr, "DNS") // "DNS" 直接包含 DNS 关键词
}

// isConnectionError 判断错误是否为网络连接错误。
// 连接错误通常是由于网络问题或目标服务器不可达导致的，不应计入认证失败统计。
//
// 参数:
//   - err: 待判断的错误对象
//
// 返回:
//   - bool: true 表示是连接错误，false 表示不是
func isConnectionError(err error) bool {
	// 如果错误为 nil，直接返回 false
	if err == nil {
		return false
	}
	// 获取错误的字符串表示
	errStr := err.Error()
	// 检查错误信息中是否包含连接相关的关键词
	return strings.Contains(errStr, "i/o timeout") || // "i/o timeout" 表示 I/O 超时
		strings.Contains(errStr, "connection refused") || // "connection refused" 表示连接被拒绝
		strings.Contains(errStr, "connect:") // "connect:" 表示连接过程中的错误
}

// copyWithBuffer 使用指定缓冲区复制数据。
// 这是一个辅助函数，封装 io.CopyBuffer 调用。
//
// 参数:
//   - dst: 数据写入的目标
//   - src: 数据来源的读取器
//   - buf: 用于复制的缓冲区
//
// 返回:
//   - int64: 复制的字节数
//   - error: 复制过程中的错误
func copyWithBuffer(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	// 调用标准库的 io.CopyBuffer 函数进行数据复制
	return io.CopyBuffer(dst, src, buf)
}

// userDataPersister 定期将内存中的用户数据持久化到数据库（每 5 分钟）。
// 该协程在后台运行，确保用户数据不会因服务器重启而丢失。
func (s *Server) userDataPersister() {
	// 创建一个 5 分钟间隔的定时器
	ticker := time.NewTicker(5 * time.Minute)
	// 使用 defer 确保函数返回时停止定时器，释放资源
	defer ticker.Stop()

	// 使用 range 遍历定时器事件
	for range ticker.C {
		// 使用 select 监听上下文取消信号
		select {
		case <-s.ctx.Done():
			// 上下文已取消，退出函数
			return
		default:
			// 尝试将认证器转换为 PasswordAuth 类型
			if auth, ok := s.config.Auth.(*PasswordAuth); ok {
				// 调用 persistUsers 方法保存用户数据
				s.persistUsers(auth)
			}
		}
	}
}

// persistUsers 将内存中的用户数据快照保存到数据库。
// 使用快照机制避免长时间持有锁，减少对并发性能的影响。
//
// 参数:
//   - auth: 密码认证器实例
func (s *Server) persistUsers(auth *PasswordAuth) {
	// 加读锁保护用户数据的读取操作
	auth.mu.RLock()
	// 定义用户快照结构体，用于临时存储用户数据
	type userSnapshot struct {
		username string // 用户名
		user     *User  // 用户数据指针
	}
	// 创建快照切片，预分配容量以减少内存分配
	snapshots := make([]userSnapshot, 0, len(auth.users))

	// 遍历所有用户，创建数据快照
	for username, user := range auth.users {
		// 创建用户数据的副本，避免并发修改问题
		snapshot := &User{
			Username:         user.Username,                         // 用户名
			Password:         user.Password,                         // 密码哈希
			MaxConnections:   user.MaxConnections,                   // 最大连接数
			MaxIPConnections: user.MaxIPConnections,                 // 单 IP 最大连接数
			Enabled:          user.Enabled,                          // 是否启用
			UploadTotal:      atomic.LoadInt64(&user.UploadTotal),   // 原子读取累计上传流量
			DownloadTotal:    atomic.LoadInt64(&user.DownloadTotal), // 原子读取累计下载流量
			CreateTime:       user.CreateTime,                       // 创建时间
			LastActivity:     atomic.LoadInt64(&user.LastActivity),  // 原子读取最后活动时间
			QuotaPeriod:      user.QuotaPeriod,                      // 配额周期
			QuotaBytes:       user.QuotaBytes,                       // 配额总量
			QuotaUsed:        atomic.LoadInt64(&user.QuotaUsed),     // 原子读取已用配额
			QuotaResetTime:   user.QuotaResetTime,                   // 配额重置时间
			QuotaStartTime:   user.QuotaStartTime,                   // 配额开始时间
			QuotaEndTime:     user.QuotaEndTime,                     // 配额结束时间
		}
		// 将快照添加到切片中
		snapshots = append(snapshots, userSnapshot{username: username, user: snapshot})
	}
	// 解锁，允许其他协程继续访问用户数据
	auth.mu.RUnlock()

	// 检查数据库管理器是否已初始化
	if dbManager == nil {
		// 如果未初始化，记录警告日志并返回
		log.Printf("警告：数据库管理器未初始化，无法持久化用户数据")
		return
	}

	// 初始化保存成功的计数器
	savedCount := 0
	// 初始化保存失败的计数器
	failedCount := 0

	// 遍历所有用户快照，逐个保存到数据库
	for _, snapshot := range snapshots {
		// 获取用户名
		username := snapshot.username
		// 获取用户数据副本
		userCopy := snapshot.user

		// 调用数据库管理器的 SaveUser 方法保存用户数据
		if err := dbManager.SaveUser(userCopy); err != nil {
			// 如果保存失败，记录错误日志
			log.Printf("持久化用户 [%s] 失败：%v", username, err)
			// 增加失败计数
			failedCount++
		} else {
			// 如果保存成功且用户有使用配额，记录详细信息
			if userCopy.QuotaUsed > 0 {
				log.Printf("持久化用户 [%s] 成功 (配额：%.2f MB / %.2f MB)", username, float64(userCopy.QuotaUsed)/1024/1024, float64(userCopy.QuotaBytes)/1024/1024)
			}

			// 增加成功计数
			savedCount++
		}
	}

	// 函数结束，用户数据已持久化到数据库
}

// quotaResetChecker 定期检查并重置所有用户的过期配额。
// 每 60 秒执行一次，确保配额能够自动重置。
func (s *Server) quotaResetChecker() {
	// 创建一个 60 秒间隔的定时器
	ticker := time.NewTicker(60 * time.Second)
	// 使用 defer 确保函数返回时停止定时器，释放资源
	defer ticker.Stop()

	// 无限循环，定期检查配额
	for {
		// 使用 select 同时监听定时器事件和上下文取消信号
		select {
		case <-ticker.C:
			// 定时器触发，检查配额
			if auth, ok := s.config.Auth.(*PasswordAuth); ok {
				// 获取所有用户列表
				users := auth.ListUsers()
				// 遍历所有用户，检查并重置配额
				for _, user := range users {
					auth.CheckQuotaAndReset(user.Username)
				}
			}
		case <-s.ctx.Done():
			// 上下文已取消，退出循环
			return
		}
	}
}
