// =============================================================================
// 文件名：proxy.go
// 描述：TCP/UDP 代理转发模块
// 功能：
//   - TCP 代理：双向数据转发、限速控制、流量统计
//   - UDP 代理：连接池复用、批处理
// 性能优化：
//   - 零拷贝转发（io.CopyBuffer）
//   - 多级缓冲池（8KB/128KB/2MB）
//   - 批量统计更新（减少原子操作）
//   - UDP 连接池（复用到相同目标的连接）
// =============================================================================

package main

import (
	"fmt"         // 格式化输出
	"io"          // IO 操作
	"log"         // 日志记录
	"net"         // 网络操作
	"strconv"     // 字符串处理
	"sync"        // 同步原语
	"sync/atomic" // 原子操作
	"time"        // 时间处理
)

// =============================================================================
// 缓冲池全局变量
// =============================================================================

// tcpBufferPool 用于复用 TCP 缓冲区，减少内存分配开销
var tcpBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 256*1024) // 256KB 缓冲区（万兆优化，平衡延迟和吞吐）
	},
}

// udpBufferPool 用于复用 UDP 缓冲区，减少内存分配开销
var udpBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 65535) // 64KB 缓冲区（支持 UDP 最大包大小，游戏优化）
	},
}

// TCPProxy TCP 代理连接结构体，负责在客户端和目标服务器之间转发数据（极致性能优化版）
type TCPProxy struct {
	// 32 位系统兼容性：int64 字段必须放在开头以确保 8 字节对齐
	readSpeedLimit  int64 // 读取速度限制（字节/秒）
	writeSpeedLimit int64 // 写入速度限制（字节/秒）
	pendingUpload   int64 // 待上传统计（批量更新减少原子操作）
	pendingDownload int64 // 待下载统计
	batchSize       int64 // 批量更新阈值
	// 其他字段
	clientConn net.Conn    // 客户端连接
	remoteConn net.Conn    // 远程服务器连接
	server     *Server     // 所属的服务器实例
	bufferPool *BufferPool // 缓冲区池
	closeOnce  sync.Once   // 确保只关闭一次
	closed     int32       // 关闭标志（原子操作）
	// 用户管理相关
	username string // 当前用户的用户名（如果已认证）
	// 性能优化：预计算标志位，避免运行时重复检查
	needStats            bool          // 是否需要统计
	needUserTraffic      bool          // 是否需要记录用户流量
	needReadLimit        bool          // 是否需要读取限速
	needWriteLimit       bool          // 是否需要写入限速
	authCache            *PasswordAuth // 认证器缓存
	usernameQuotaChecked bool          // 是否已检查配额
}

// NewTCPProxy 创建并初始化新的 TCP 代理实例（万兆极致优化版）
func NewTCPProxy(clientConn net.Conn, server *Server) *TCPProxy {
	proxy := &TCPProxy{
		clientConn: clientConn,
		server:     server,
		// 初始化批量统计参数（万兆优化）
		batchSize: 256 * 1024, // 256KB 批量更新阈值（更大的批次，减少原子操作频率）
	}
	// 从服务器配置继承限速设置
	if server != nil && server.config != nil {
		proxy.readSpeedLimit = server.config.ReadSpeedLimit
		proxy.writeSpeedLimit = server.config.WriteSpeedLimit
		// 预检查统计需求（性能优化）
		proxy.needStats = server.stats != nil
		proxy.needUserTraffic = server.config.EnableUserManagement
		// 预计算限速标志，避免运行时重复判断
		proxy.needReadLimit = proxy.readSpeedLimit > 0
		proxy.needWriteLimit = proxy.writeSpeedLimit > 0
		if proxy.needUserTraffic {
			if auth, ok := server.config.Auth.(*PasswordAuth); ok {
				proxy.authCache = auth
			} else {
				proxy.needUserTraffic = false
			}
		}
	}
	return proxy
}

// SetUsername 设置用户名（认证成功后调用）
func (p *TCPProxy) SetUsername(username string) {
	p.username = username
	// 如果启用了多用户管理，从认证器获取用户的限速配置
	if p.server != nil && p.server.config != nil && p.server.config.EnableUserManagement {
		if auth, ok := p.server.config.Auth.(*PasswordAuth); ok {
			if user, exists := auth.GetUser(username); exists {
				// 使用用户特定的限速设置（如果设置了）
				if user.ReadSpeedLimit > 0 {
					p.readSpeedLimit = user.ReadSpeedLimit
				}
				if user.WriteSpeedLimit > 0 {
					p.writeSpeedLimit = user.WriteSpeedLimit
				}
				// 重要：更新限速标志位，确保限速功能生效
				p.needReadLimit = p.readSpeedLimit > 0
				p.needWriteLimit = p.writeSpeedLimit > 0
			}
			// 检查用户是否超出流量配额
			if auth.CheckQuotaExceeded(username) {
				log.Printf("用户 [%s] 流量配额已用尽，拒绝连接", username)
				// 关闭连接
				p.clientConn.Close()
				return
			}
		}
	}
}

// SetBufferPool 设置缓冲区池，用于减少数据传输时的内存分配
func (p *TCPProxy) SetBufferPool(pool *BufferPool) {
	p.bufferPool = pool
}

// HandleConnect 处理 CONNECT 命令：建立到目标服务器的 TCP 连接并开始转发数据（优化版）
func (p *TCPProxy) HandleConnect(dstAddr string, dstPort uint16) error {
	// 拼接远程地址字符串，正确处理 IPv6 格式
	remoteAddr := net.JoinHostPort(dstAddr, fmt.Sprintf("%d", dstPort))
	// 建立到目标服务器的连接，超时 10 秒
	remoteConn, err := net.DialTimeout("tcp", remoteAddr, 10*time.Second)
	if err != nil {
		return err
	}
	p.remoteConn = remoteConn

	// 万兆优化：优化远程连接的 TCP 参数（16MB 缓冲区实现万兆吞吐）
	if tcpConn, ok := remoteConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)                     // 禁用 Nagle 算法
		tcpConn.SetKeepAlive(true)                   // 启用 Keepalive
		tcpConn.SetKeepAlivePeriod(10 * time.Second) // 5 秒心跳（更快检测）
		// 万兆优化：16MB 缓冲区
		tcpConn.SetReadBuffer(16 * 1024 * 1024)  // 16MB 读缓冲区（10Gbps 必需）
		tcpConn.SetWriteBuffer(16 * 1024 * 1024) // 16MB 写缓冲区
	}

	// 获取本地地址用于响应客户端
	localAddr := remoteConn.LocalAddr().(*net.TCPAddr)

	// 根据 IP 类型确定地址类型
	var addrType byte
	ip := localAddr.IP
	if ip4 := ip.To4(); ip4 != nil {
		addrType = AddrTypeIPv4 // IPv4 地址
	} else if ip16 := ip.To16(); ip16 != nil {
		addrType = AddrTypeIPv6 // IPv6 地址
	} else {
		addrType = AddrTypeDomain // 域名
	}

	// 发送成功响应给客户端，包含代理服务器的监听地址
	if err := WriteResponse(p.clientConn, ReplySuccess, addrType, localAddr.IP.String(), uint16(localAddr.Port)); err != nil {
		return err
	}

	// 开始双向数据转发
	p.startRelay()
	return nil
}

// startRelay 启动双向数据转发协程
func (p *TCPProxy) startRelay() {
	var wg sync.WaitGroup
	wg.Add(2)

	// 客户端 -> 远程服务器方向的数据转发
	go func() {
		defer wg.Done()
		defer p.Close()
		p.copyWithStats(p.remoteConn, p.clientConn, true) // upload=true
	}()

	// 远程服务器 -> 客户端方向的数据转发
	go func() {
		defer wg.Done()
		defer p.Close()
		p.copyWithStats(p.clientConn, p.remoteConn, false) // upload=false
	}()

	wg.Wait() // 等待两个方向都完成
}

// copyWithStats 带统计信息的数据复制（极致性能优化版）
func (p *TCPProxy) copyWithStats(dst, src net.Conn, upload bool) {
	// 从池中获取缓冲区（bufferPool 应该总是存在）
	buf := p.bufferPool.Get()
	defer p.bufferPool.Put(buf)

	// 极致性能优化：预计算所有标志位（零开销路径判断）
	speedLimit := p.writeSpeedLimit
	if upload {
		speedLimit = p.readSpeedLimit
	}
	needSpeedLimit := speedLimit > 0

	// 缓存常用变量到局部变量，减少字段访问开销（性能优化）
	var (
		stats           = p.server.stats
		needStats       = p.needStats
		needUserTraffic = p.needUserTraffic
		auth            = p.authCache
		username        = p.username
	)

	// 重要修复：如果启用了用户流量管理，必须进入完整路径以进行配额检查
	// 这是关键的功能完整性保证，不能因为性能优化而跳过配额检查
	if needUserTraffic && auth != nil && username != "" {
		// 强制进入完整路径，确保配额检查生效
		needStats = true // 需要统计才能记录用户流量
	}

	// 千兆优化：快速路径（无统计无限速无配额 - 极致性能）
	if !needStats && !needUserTraffic && !needSpeedLimit {
		p.copyFast(dst, src, buf)
		return
	}

	// 千兆优化：仅统计路径（无限速无配额 - 高性能）
	if needStats && !needUserTraffic && !needSpeedLimit {
		p.copyWithStatsOnly(dst, src, buf, upload, stats)
		return
	}

	// 万兆优化：完整路径（带统计 + 用户流量 + 限速 - 功能完整但性能优化）
	// 实时统计优化：更小的阈值和超时刷新，确保小流量也能及时统计
	const batchThreshold int64 = 256 * 1024     // 256KB 批量更新阈值（更大的批次，减少原子操作）
	const flushThreshold int64 = 32 * 1024      // 32KB 刷新阈值（平衡实时性和性能）
	const flushTimeout = 100 * time.Millisecond // 100ms 超时刷新（平衡响应性和 CPU 开销）
	localUpload := int64(0)
	localDownload := int64(0)
	quotaCheckCounter := 0
	lastQuotaCheck := time.Now()
	lastFlush := time.Now()

	// 设置读超时：300 秒（5 分钟）无数据自动断开
	// 防止客户端不关闭连接导致 goroutine 永久阻塞
	readTimeout := 300 * time.Second

	for {
		// 设置读超时，避免永久阻塞
		src.SetReadDeadline(time.Now().Add(readTimeout))

		n, err := src.Read(buf)
		if n > 0 {
			// 写入数据到目标（零拷贝优化）
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return
			}

			// 万兆优化：本地累积统计（双阈值 + 超时刷新，确保小流量也能及时统计）
			if needStats {
				now := time.Now()
				if upload {
					localUpload += int64(n)
					// 三条件任一满足即提交：达到 batchThreshold、达到 flushThreshold 且超时、或超时 200ms
					if localUpload >= batchThreshold ||
						(localUpload >= flushThreshold && now.Sub(lastFlush) > flushTimeout) ||
						(localUpload > 0 && now.Sub(lastFlush) > 200*time.Millisecond) {
						atomic.AddInt64(&stats.TotalUpload, localUpload)
						localUpload = 0
						lastFlush = now
					}
				} else {
					localDownload += int64(n)
					if localDownload >= batchThreshold ||
						(localDownload >= flushThreshold && now.Sub(lastFlush) > flushTimeout) ||
						(localDownload > 0 && now.Sub(lastFlush) > 200*time.Millisecond) {
						atomic.AddInt64(&stats.TotalDownload, localDownload)
						localDownload = 0
						lastFlush = now
					}
				}
			}

			// 记录用户流量（仅在需要时）
			if needUserTraffic && auth != nil && username != "" {
				if upload {
					p.pendingUpload += int64(n)
					auth.AddUserTraffic(username, int64(n), 0)
				} else {
					p.pendingDownload += int64(n)
					auth.AddUserTraffic(username, 0, int64(n))
				}

				// 批量将用户流量持久化到数据库（减少数据库写入频率）
				if dbManager != nil {
					// 每 1MB 记录一次或每 10 秒记录一次
					const trafficLogThreshold = 1 * 1024 * 1024 // 1MB
					if upload {
						if p.pendingUpload >= trafficLogThreshold {
							dbManager.LogTraffic(username, p.pendingUpload, 0)
							p.pendingUpload = 0
						}
					} else {
						if p.pendingDownload >= trafficLogThreshold {
							dbManager.LogTraffic(username, 0, p.pendingDownload)
							p.pendingDownload = 0
						}
					}
				}

				// 配额检查优化：时间 + 计数双重检查（确保及时性）
				quotaCheckCounter++
				now := time.Now()
				// 每 100 次检查 1 次，或每 100ms 检查 1 次（取先到者）
				if quotaCheckCounter >= 100 || now.Sub(lastQuotaCheck) > 100*time.Millisecond {
					quotaCheckCounter = 0
					lastQuotaCheck = now
					if auth.CheckQuotaExceeded(username) {
						log.Printf("用户 [%s] 流量配额已用尽 (%.2f MB / %.2f MB)，终止连接",
							username,
							float64(auth.GetUserQuotaUsed(username))/1024/1024,
							float64(auth.GetUserQuotaTotal(username))/1024/1024)
						return
					}
				}
			}

			// 限速处理（仅在需要时，使用整数运算避免浮点开销）
			if needSpeedLimit && n > 0 {
				sleepNs := int64(n) * int64(time.Second) / speedLimit
				if sleepNs > 0 {
					time.Sleep(time.Duration(sleepNs))
				}
			}
		}
		if err != nil {

			if needStats && (localUpload > 0 || localDownload > 0) {
				if localUpload > 0 {
					atomic.AddInt64(&stats.TotalUpload, localUpload)
				}
				if localDownload > 0 {
					atomic.AddInt64(&stats.TotalDownload, localDownload)
				}
			}
			return
		}
	}
}

// copyFast 快速数据复制（无统计无限速的优化路径 - 极致性能）
// 万兆优化：使用 io.CopyBuffer 实现零拷贝，利用操作系统优化
func (p *TCPProxy) copyFast(dst io.Writer, src io.Reader, buf []byte) {
	// 尝试使用零拷贝传输
	if tcpDst, ok := dst.(*net.TCPConn); ok {
		if tcpSrc, ok := src.(*net.TCPConn); ok {
			if err := p.copyWithSplice(tcpDst, tcpSrc); err == nil {
				return
			}
		}
	}
	// 回退到标准复制
	_, err := io.CopyBuffer(dst, src, buf)
	_ = err // 忽略错误，由上层处理
}

// copyWithSplice 尝试使用零拷贝传输
func (p *TCPProxy) copyWithSplice(dst, src *net.TCPConn) error {
	// 使用更大的缓冲区提高传输效率
	buf := make([]byte, 128*1024) // 128KB 缓冲区
	_, err := io.CopyBuffer(dst, src, buf)
	return err
}

// copyWithStatsOnly 仅统计路径（无限速无配额 - 高性能优化）
// 万兆优化：平衡实时性和性能，使用双阈值策略
func (p *TCPProxy) copyWithStatsOnly(dst io.Writer, src io.Reader, buf []byte, upload bool, stats *Stats) {
	// 实时统计优化：更小的阈值和超时刷新，确保小流量也能及时统计
	const batchThreshold int64 = 100 * 1024    // 100KB 批量更新
	const flushThreshold int64 = 10 * 1024     // 10KB 刷新阈值
	const flushTimeout = 50 * time.Millisecond // 50ms 超时刷新
	localUpload := int64(0)
	localDownload := int64(0)
	lastFlush := time.Now()

	// 设置读超时：300 秒（5 分钟）无数据自动断开
	var srcConn net.Conn
	if conn, ok := src.(net.Conn); ok {
		srcConn = conn
	}

	for {
		// 每次读取前都设置超时，确保超时有效
		if srcConn != nil {
			srcConn.SetReadDeadline(time.Now().Add(300 * time.Second))
		}

		n, err := src.Read(buf)
		if n > 0 {
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return
			}

			// 实时统计优化：双阈值 + 超时刷新
			now := time.Now()
			if upload {
				localUpload += int64(n)
				if localUpload >= batchThreshold ||
					(localUpload >= flushThreshold && now.Sub(lastFlush) > flushTimeout) ||
					(localUpload > 0 && now.Sub(lastFlush) > 200*time.Millisecond) {
					atomic.AddInt64(&stats.TotalUpload, localUpload)
					localUpload = 0
					lastFlush = now
				}
			} else {
				localDownload += int64(n)
				if localDownload >= batchThreshold ||
					(localDownload >= flushThreshold && now.Sub(lastFlush) > flushTimeout) ||
					(localDownload > 0 && now.Sub(lastFlush) > 200*time.Millisecond) {
					atomic.AddInt64(&stats.TotalDownload, localDownload)
					localDownload = 0
					lastFlush = now
				}
			}
		}
		if err != nil {
			// 刷新未提交的统计
			if localUpload > 0 {
				atomic.AddInt64(&stats.TotalUpload, localUpload)
			}
			if localDownload > 0 {
				atomic.AddInt64(&stats.TotalDownload, localDownload)
			}
			return
		}
	}
}

// Close 关闭代理连接，确保只关闭一次
func (p *TCPProxy) Close() {
	p.closeOnce.Do(func() {
		atomic.StoreInt32(&p.closed, 1) // 设置关闭标志
		if p.clientConn != nil {
			p.clientConn.Close()
		}
		if p.remoteConn != nil {
			p.remoteConn.Close()
		}
		// 注意：wg.Done() 不应在这里调用，因为 TCPProxy 的 startRelay() 中的 goroutine
		// 已经在 defer 中调用了 wg.Done()。这里重复调用会导致 panic。
		// 如果启用了多用户管理，减少用户连接数和 IP 记录
		if p.username != "" && p.server != nil && p.server.config != nil && p.server.config.EnableUserManagement {
			if auth, ok := p.server.config.Auth.(*PasswordAuth); ok {
				auth.DecrementUserConnection(p.username)
				// 获取客户端 IP 并移除
				if p.clientConn != nil {
					clientIP := p.clientConn.RemoteAddr().String()
					auth.RemoveUserIP(p.username, clientIP)
				}
				// 刷新未提交的用户流量到数据库（使用原子操作读取，避免竞态条件）
				if dbManager != nil {
					pendingUpload := atomic.LoadInt64(&p.pendingUpload)
					pendingDownload := atomic.LoadInt64(&p.pendingDownload)
					if pendingUpload > 0 || pendingDownload > 0 {
						dbManager.LogTraffic(p.username, pendingUpload, pendingDownload)
					}
				}
			}
		}
	})
}

// IsClosed 检查代理是否已关闭
func (p *TCPProxy) IsClosed() bool {
	return atomic.LoadInt32(&p.closed) == 1
}

// UDPAssociation UDP 关联结构体，处理 UDP 代理转发
type UDPAssociation struct {
	clientAddr    *net.UDPAddr            // 客户端 UDP 地址
	clientConn    net.Conn                // 控制连接（TCP）
	udpListener   *net.UDPConn            // UDP 监听器
	server        *Server                 // 所属服务器实例
	closeOnce     sync.Once               // 确保只关闭一次
	closed        int32                   // 关闭标志
	clientMap     map[string]*net.UDPAddr // 记录多个客户端地址
	clientMapMu   sync.RWMutex            // 保护 clientMap 的锁
	remoteConns   map[string]*net.UDPConn // 复用到相同目标的连接（按客户端隔离）
	remoteConnsMu sync.RWMutex            // 保护 remoteConns 的锁
	// 限速相关
	readSpeedLimit  int64 // 读取速度限制（字节/秒）
	writeSpeedLimit int64 // 写入速度限制（字节/秒）
	// 用户管理相关
	username string // 当前用户的用户名（如果已认证）
}

// NewUDPAssociation 创建并初始化新的 UDP 关联实例
func NewUDPAssociation(clientConn net.Conn, server *Server) *UDPAssociation {
	udpAssoc := &UDPAssociation{
		clientConn:  clientConn,
		server:      server,
		clientMap:   make(map[string]*net.UDPAddr),
		remoteConns: make(map[string]*net.UDPConn),
	}
	// 从服务器配置继承限速设置
	if server != nil && server.config != nil {
		udpAssoc.readSpeedLimit = server.config.ReadSpeedLimit
		udpAssoc.writeSpeedLimit = server.config.WriteSpeedLimit
	}
	return udpAssoc
}

// SetUsername 设置用户名（认证成功后调用）
func (u *UDPAssociation) SetUsername(username string) {
	u.username = username
	// 如果启用了多用户管理，从认证器获取用户的限速配置
	if u.server != nil && u.server.config != nil && u.server.config.EnableUserManagement {
		if auth, ok := u.server.config.Auth.(*PasswordAuth); ok {
			if user, exists := auth.GetUser(username); exists {
				// 使用用户特定的限速设置（如果设置了）
				if user.ReadSpeedLimit > 0 {
					u.readSpeedLimit = user.ReadSpeedLimit
				}
				if user.WriteSpeedLimit > 0 {
					u.writeSpeedLimit = user.WriteSpeedLimit
				}
			}
		}
	}
}

// HandleUDPAssociate 处理 UDP ASSOCIATE 命令：创建 UDP 监听并转发数据
func (u *UDPAssociation) HandleUDPAssociate() error {
	// 重要修复：检查 clientConn 是否为 nil
	u.clientMapMu.RLock()
	controlConn := u.clientConn
	u.clientMapMu.RUnlock()

	if controlConn == nil {
		return fmt.Errorf("clientConn is nil")
	}

	// 获取控制连接的本地地址
	controlLocalAddr := controlConn.LocalAddr().(*net.TCPAddr)

	// 创建 UDP 监听器，使用与控制连接相同的 IP 地址
	udpAddr := &net.UDPAddr{IP: controlLocalAddr.IP, Port: 0} // Port=0 表示系统自动分配
	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	u.udpListener = udpListener

	// 获取监听地址（系统分配的端口）
	localAddr := udpListener.LocalAddr().(*net.UDPAddr)

	// 发送成功响应给客户端，告知 UDP 代理监听的地址和端口
	var addrType byte
	ip := controlLocalAddr.IP
	if ip4 := ip.To4(); ip4 != nil {
		addrType = AddrTypeIPv4
	} else if ip16 := ip.To16(); ip16 != nil {
		addrType = AddrTypeIPv6
	} else {
		addrType = AddrTypeDomain
	}

	if err := WriteResponse(u.clientConn, ReplySuccess, addrType, controlLocalAddr.IP.String(), uint16(localAddr.Port)); err != nil {
		udpListener.Close()
		return err
	}

	// 启动 goroutine 处理 UDP 数据转发
	go u.handleUDPData()

	// 等待控制连接关闭
	u.waitForClose()

	return nil
}

// handleUDPData 处理 UDP 数据转发：接收客户端 UDP 包并转发到目标服务器
func (u *UDPAssociation) handleUDPData() {
	for !u.IsClosed() {
		// ✅ 重要修复：每次循环都重新获取缓冲区，避免数据覆盖导致丢包
		buf := udpBufferPool.Get().([]byte)

		u.clientMapMu.RLock()
		listener := u.udpListener
		u.clientMapMu.RUnlock()

		if listener == nil {
			// udpListener 已关闭，归还缓冲区后退出循环
			udpBufferPool.Put(buf)
			return
		}

		n, clientAddr, err := listener.ReadFromUDP(buf)
		if err != nil {
			udpBufferPool.Put(buf)
			if u.IsClosed() {
				return // 已关闭则退出
			}
			// 网络错误，关闭连接
			log.Printf("UDP 读取错误：%v", err)
			u.Close()
			return
		}

		// 记录客户端地址，用于后续响应
		clientKey := clientAddr.String()
		u.clientMapMu.Lock()
		if u.clientMap != nil {
			u.clientMap[clientKey] = clientAddr
		}
		u.clientMapMu.Unlock()

		// 解析 UDP 请求头部（前 10 字节为头部）
		if n < 10 {
			udpBufferPool.Put(buf)
			continue // 数据太短，无效包
		}

		header, err := ParseUDPHeader(buf[:n])
		if err != nil {
			udpBufferPool.Put(buf)
			continue // 解析失败，丢弃
		}

		// 检查 RSV 和 FRAG：不支持分片
		if header.Rsv != 0 || header.Frag != 0 {
			udpBufferPool.Put(buf)
			continue // 不支持的分片包
		}

		// ✅ 重要修复：启动 goroutine 转发到远程服务器，让 forwardToRemoteWithPool 负责归还缓冲区
		go func() {
			defer udpBufferPool.Put(buf) // 在 goroutine 结束时归还缓冲区
			u.forwardToRemoteWithPool(header, clientKey)
		}()
	}
}

// forwardToRemoteWithPool 使用连接池转发到远程服务器（严格参考 socks51）
func (u *UDPAssociation) forwardToRemoteWithPool(header *UDPHeader, clientKey string) {
	// 解析目标服务器地址
	dstAddr := net.JoinHostPort(header.DstAddr, fmt.Sprintf("%d", header.DstPort))

	// ✅ 重要修复：按 dstAddr 复用连接（不按 clientKey 隔离）
	u.remoteConnsMu.RLock()
	remoteConn, exists := u.remoteConns[dstAddr]
	u.remoteConnsMu.RUnlock()

	// 如果不存在或连接已关闭，创建新连接并放入池中
	if !exists || remoteConn == nil {
		u.remoteConnsMu.Lock()
		// 双重检查
		if u.remoteConns != nil {
			if remoteConn, exists = u.remoteConns[dstAddr]; !exists || remoteConn == nil {
				conn, err := net.Dial("udp", dstAddr)
				if err != nil {
					u.remoteConnsMu.Unlock()
					log.Printf("[UDP] 建立到远程服务器 [%s] 的连接失败：%v", dstAddr, err)
					return
				}
				// 游戏优化：设置 UDP 连接缓冲区为 256kb
				if udpConn, ok := conn.(*net.UDPConn); ok {
					udpConn.SetReadBuffer(256 * 1024)
					udpConn.SetWriteBuffer(256 * 1024)
					remoteConn = udpConn
				} else {
					remoteConn = conn.(*net.UDPConn)
				}
				u.remoteConns[dstAddr] = remoteConn
				log.Printf("[UDP] ✅ 新建连接 [%s] -> [%s]", clientKey, dstAddr)
			}
		} else {
			u.remoteConnsMu.Unlock()
			return
		}
		u.remoteConnsMu.Unlock()
	}

	// ✅ 重要修复：发送数据到远程服务器（快速失败，无重试）
	if remoteConn == nil {
		return
	}
	_, err := remoteConn.Write(header.Data)
	if err != nil {
		// 快速失败：仅记录错误，不重试
		log.Printf("[UDP] ⚠️ 发送失败 [%s]: %v", dstAddr, err)
		return
	}

	// 更新统计
	if u.server != nil && u.server.stats != nil {
		u.server.stats.AddUpload(int64(len(header.Data)))
	}

	// ✅ 重要修复：在同一 goroutine 中持续接收响应并转发给客户端
	responseBuf := udpBufferPool.Get().([]byte)
	defer udpBufferPool.Put(responseBuf)

	for !u.IsClosed() {
		remoteConn.SetReadDeadline(time.Now().Add(30 * time.Second))

		n, err := remoteConn.Read(responseBuf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 超时但未关闭，继续等待
				continue
			}
			// 读取错误，退出循环
			return
		}

		// 获取客户端地址
		u.clientMapMu.RLock()
		clientAddr, exists := u.clientMap[clientKey]
		u.clientMapMu.RUnlock()

		if !exists {
			return
		}

		// 构建响应 UDP 头部
		respData, err := BuildUDPHeader(header.AddrType, header.DstAddr, header.DstPort, responseBuf[:n])
		if err != nil {
			return
		}

		// 发送回客户端
		u.udpListener.WriteToUDP(respData, clientAddr)

		// 更新统计
		if u.server != nil && u.server.stats != nil {
			u.server.stats.AddDownload(int64(n))
		}
	}
}

// waitForClose 等待控制连接关闭：阻塞读取直到 TCP 控制连接断开
func (u *UDPAssociation) waitForClose() {
	// 循环读取控制连接，直到它关闭
	buf := make([]byte, 1)

	for {
		// 重要修复：检查 clientConn 是否为 nil（避免并发关闭导致的空指针）
		u.clientMapMu.RLock()
		conn := u.clientConn
		u.clientMapMu.RUnlock()

		if conn == nil {
			// clientConn 已关闭，立即关闭 UDP 关联
			u.Close()
			return
		}

		// 阻塞读取控制连接，直到它关闭
		conn.SetReadDeadline(time.Time{}) // 取消超时设置，永久阻塞
		_, err := conn.Read(buf)
		if err != nil {
			// 连接关闭或错误，立即关闭 UDP 关联
			u.Close()
			return
		}
	}
}

// Close 关闭 UDP 关联，释放所有资源
func (u *UDPAssociation) Close() {
	u.closeOnce.Do(func() {
		atomic.StoreInt32(&u.closed, 1) // 设置关闭标志

		// 先关闭 UDP 监听器，停止接收新数据包
		if u.udpListener != nil {
			u.udpListener.Close() // 关闭 UDP 监听器
			u.udpListener = nil   // 释放引用
		}

		// 关闭控制连接
		if u.clientConn != nil {
			u.clientConn.Close() // 关闭控制连接
			u.clientConn = nil   // 释放引用
		}

		// 关闭所有复用的远程连接并释放 map
		u.remoteConnsMu.Lock()
		if u.remoteConns != nil {
			for _, conn := range u.remoteConns {
				if conn != nil {
					conn.Close() // 关闭每个 UDP 连接
				}
			}
			u.remoteConns = nil
		}
		u.remoteConnsMu.Unlock()

		// 清理客户端地址映射
		u.clientMapMu.Lock()
		u.clientMap = nil
		u.clientMapMu.Unlock()

		// 如果启用了多用户管理，减少用户连接数
		if u.username != "" && u.server != nil && u.server.config != nil && u.server.config.EnableUserManagement {
			if auth, ok := u.server.config.Auth.(*PasswordAuth); ok {
				auth.DecrementUserConnection(u.username)
			}
		}
	})
}

// IsClosed 检查 UDP 关联是否已关闭
func (u *UDPAssociation) IsClosed() bool {
	return atomic.LoadInt32(&u.closed) == 1
}

// parsePort 将字符串端口转换为 uint16
func parsePort(portStr string) uint16 {
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(port)
}

// copyData 在两个连接之间复制数据（备用函数）
// 参数 dst: 目标连接；src: 源连接；done: 完成信号通道
func copyData(dst, src net.Conn, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	io.Copy(dst, src)
}
