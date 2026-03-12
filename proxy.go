package main

import (
	"fmt"         // 格式化输出
	"io"          // IO 操作
	"log"         // 日志记录
	"net"         // 网络操作
	"sync"        // 同步原语
	"sync/atomic" // 原子操作
	"time"        // 时间处理
)

// udpBufferPool 用于复用 UDP 缓冲区，减少内存分配开销
var udpBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 65535) // 64KB 缓冲区，足够容纳最大 UDP 包
	},
}

// TCPProxy TCP 代理连接结构体，负责在客户端和目标服务器之间转发数据（极致性能优化版）
type TCPProxy struct {
	clientConn net.Conn    // 客户端连接
	remoteConn net.Conn    // 远程服务器连接
	server     *Server     // 所属的服务器实例
	bufferPool *BufferPool // 缓冲区池
	closeOnce  sync.Once   // 确保只关闭一次
	closed     int32       // 关闭标志（原子操作）
	// 限速相关
	readSpeedLimit  int64 // 读取速度限制（字节/秒）
	writeSpeedLimit int64 // 写入速度限制（字节/秒）
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

// NewTCPProxy 创建并初始化新的 TCP 代理实例（极致性能优化版）
func NewTCPProxy(clientConn net.Conn, server *Server) *TCPProxy {
	proxy := &TCPProxy{
		clientConn: clientConn,
		server:     server,
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

	// 优化远程连接的 TCP 参数以提高性能
	if tcpConn, ok := remoteConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)                     // 禁用 Nagle 算法，减少延迟
		tcpConn.SetKeepAlive(true)                   // 启用 Keepalive
		tcpConn.SetKeepAlivePeriod(30 * time.Second) // 30 秒心跳
		// 设置更大的缓冲区以提高吞吐量
		tcpConn.SetReadBuffer(64 * 1024)  // 64KB 读缓冲区
		tcpConn.SetWriteBuffer(64 * 1024) // 64KB 写缓冲区
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

	// 使用预计算的标志位（在 NewTCPProxy 中已计算好）
	speedLimit := p.writeSpeedLimit
	if upload {
		speedLimit = p.readSpeedLimit
	}
	needSpeedLimit := speedLimit > 0 && (upload && p.needReadLimit || !upload && p.needWriteLimit)

	// 缓存常用变量到局部变量，减少字段访问开销
	var (
		stats           = p.server.stats
		needStats       = p.needStats
		needUserTraffic = p.needUserTraffic
		auth            = p.authCache
		username        = p.username
	)

	// 快速路径：如果什么都不需要记录，使用简化循环
	if !needStats && !needUserTraffic && !needSpeedLimit {
		p.copyFast(dst, src, buf)
		return
	}

	// 完整路径：带统计和限速
	for {
		n, err := src.Read(buf)
		if n > 0 {
			// 写入数据到目标
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return
			}

			// 更新统计信息（内联优化，避免函数调用）
			if needStats {
				if upload {
					atomic.AddInt64(&stats.TotalUpload, int64(n))
				} else {
					atomic.AddInt64(&stats.TotalDownload, int64(n))
				}
			}

			// 记录用户流量（仅在需要时）
			if needUserTraffic && auth != nil && username != "" {
				if upload {
					auth.AddUserTraffic(username, int64(n), 0)
				} else {
					auth.AddUserTraffic(username, 0, int64(n))
				}

				// 配额检查（仅在首次或定期检查）
				if !p.usernameQuotaChecked && auth.CheckQuotaExceeded(username) {
					log.Printf("用户 [%s] 流量配额已用尽，终止连接", username)
					return
				}
				p.usernameQuotaChecked = true
			}

			// 限速处理（使用整数运算避免浮点开销）
			if needSpeedLimit && n > 0 {
				sleepNs := int64(n) * int64(time.Second) / speedLimit
				if sleepNs > 0 {
					time.Sleep(time.Duration(sleepNs))
				}
			}
		}
		if err != nil {
			return
		}
	}
}

// copyFast 快速数据复制（无统计无限速的优化路径）
func (p *TCPProxy) copyFast(dst io.Writer, src io.Reader, buf []byte) {
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}
		}
		if err != nil {
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
	lastActivity  int64                   // 最后活动时间（Unix 时间戳）- 必须在开头以确保 8 字节对齐
	clientAddr    *net.UDPAddr            // 客户端 UDP 地址
	clientConn    net.Conn                // 控制连接（TCP）
	udpListener   *net.UDPConn            // UDP 监听器
	server        *Server                 // 所属服务器实例
	closeOnce     sync.Once               // 确保只关闭一次
	closed        int32                   // 关闭标志
	timeout       time.Duration           // 超时时间
	clientMap     map[string]*net.UDPAddr // 记录多个客户端地址
	clientMapMu   sync.RWMutex            // 保护 clientMap 的锁
	remoteConns   map[string]*net.UDPConn // 复用到相同目标的连接
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
		clientConn:   clientConn,
		server:       server,
		timeout:      5 * time.Minute, // 默认 5 分钟超时
		lastActivity: time.Now().Unix(),
		clientMap:    make(map[string]*net.UDPAddr),
		remoteConns:  make(map[string]*net.UDPConn),
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
	// 获取控制连接的本地地址
	controlLocalAddr := u.clientConn.LocalAddr().(*net.TCPAddr)

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
	buf := udpBufferPool.Get().([]byte) // 从池中获取缓冲区
	defer udpBufferPool.Put(buf)        // 确保归还

	for !u.IsClosed() {
		// 设置读取超时，用于检测空闲
		u.udpListener.SetReadDeadline(time.Now().Add(u.timeout))

		n, clientAddr, err := u.udpListener.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 检查是否真正超时
				if time.Now().Unix()-atomic.LoadInt64(&u.lastActivity) > int64(u.timeout.Seconds()) {
					u.Close()
					return
				}
				continue // 超时时继续循环
			}
			if u.IsClosed() {
				return // 已关闭则退出
			}
			continue // 其他错误也继续
		}

		// 更新最后活动时间
		atomic.StoreInt64(&u.lastActivity, time.Now().Unix())

		// 记录客户端地址，用于后续响应
		clientKey := clientAddr.String()
		u.clientMapMu.Lock()
		if u.clientMap != nil {
			u.clientMap[clientKey] = clientAddr
		}
		u.clientMapMu.Unlock()

		// 解析 UDP 请求头部（前 10 字节为头部）
		if n < 10 {
			continue // 数据太短，无效包
		}

		header, err := ParseUDPHeader(buf[:n])
		if err != nil {
			continue // 解析失败，丢弃
		}

		// 检查 RSV 和 FRAG：不支持分片
		if header.Rsv != 0 || header.Frag != 0 {
			continue // 不支持的分片包
		}

		// 启动 goroutine 转发到远程服务器（复用连接）
		go u.forwardToRemoteWithPool(header, clientKey)
	}
}

// forwardToRemoteWithPool 使用连接池转发 UDP 数据到远程服务器
func (u *UDPAssociation) forwardToRemoteWithPool(header *UDPHeader, clientKey string) {
	// 解析目标服务器地址，正确处理 IPv6 格式
	dstAddr := net.JoinHostPort(header.DstAddr, fmt.Sprintf("%d", header.DstPort))

	// 尝试从连接池获取到该目标的现有连接
	u.remoteConnsMu.RLock()
	remoteConn, exists := u.remoteConns[dstAddr]
	u.remoteConnsMu.RUnlock()

	// 如果不存在，创建新连接并放入池中
	if !exists {
		u.remoteConnsMu.Lock()
		// 双重检查避免竞态条件
		if u.remoteConns != nil { // 检查 map 是否已被关闭
			if remoteConn, exists = u.remoteConns[dstAddr]; !exists {
				conn, err := net.Dial("udp", dstAddr) // 建立 UDP 连接
				if err != nil {
					u.remoteConnsMu.Unlock()
					return
				}
				remoteConn = conn.(*net.UDPConn)
				u.remoteConns[dstAddr] = remoteConn // 存入池中
			}
		}
		u.remoteConnsMu.Unlock()
	}

	// 发送数据到远程服务器
	_, err := remoteConn.Write(header.Data)
	if err != nil {
		return
	}

	// 更新上传统计
	if u.server != nil && u.server.stats != nil {
		u.server.stats.AddUpload(int64(len(header.Data)))
	}

	// UDP 上传限速
	if u.writeSpeedLimit > 0 {
		sleepDuration := time.Duration(float64(len(header.Data)) / float64(u.writeSpeedLimit) * float64(time.Second))
		if sleepDuration > 0 {
			time.Sleep(sleepDuration)
		}
	}

	// 准备接收响应
	responseBuf := udpBufferPool.Get().([]byte)
	defer udpBufferPool.Put(responseBuf)

	// 持续接收来自远程服务器的响应并转发给客户端
	for !u.IsClosed() {
		remoteConn.SetReadDeadline(time.Now().Add(30 * time.Second)) // 30 秒超时

		n, err := remoteConn.Read(responseBuf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 超时但未关闭，继续等待
				continue
			}
			return // 其他错误退出
		}

		// 获取对应的客户端地址
		u.clientMapMu.RLock()
		if u.clientMap == nil {
			u.clientMapMu.RUnlock()
			return // 已关闭则退出
		}
		clientAddr, exists := u.clientMap[clientKey]
		u.clientMapMu.RUnlock()

		if !exists {
			return // 客户端不存在则退出
		}

		// 构建响应 UDP 头部（使用原始请求的目标地址作为源地址）
		respData, err := BuildUDPHeader(header.AddrType, header.DstAddr, header.DstPort, responseBuf[:n])
		if err != nil {
			return
		}

		// 发送回客户端
		u.udpListener.WriteToUDP(respData, clientAddr)

		// 更新下载统计
		if u.server != nil && u.server.stats != nil {
			u.server.stats.AddDownload(int64(n))
		}

		// UDP 下载限速
		if u.readSpeedLimit > 0 {
			sleepDuration := time.Duration(float64(n) / float64(u.readSpeedLimit) * float64(time.Second))
			if sleepDuration > 0 {
				time.Sleep(sleepDuration)
			}
		}

		// 更新活动时间
		atomic.StoreInt64(&u.lastActivity, time.Now().Unix())
	}
}

// waitForClose 等待控制连接关闭：阻塞读取直到 TCP 控制连接断开
func (u *UDPAssociation) waitForClose() {
	// 循环读取控制连接，直到它关闭或超时
	buf := make([]byte, 1)
	for {
		u.clientConn.SetReadDeadline(time.Now().Add(u.timeout))
		_, err := u.clientConn.Read(buf)
		if err != nil {
			// 连接关闭或超时，需要清理 UDP 关联
			u.Close()
			return
		}
	}
}

// Close 关闭 UDP 关联，释放所有资源
func (u *UDPAssociation) Close() {
	u.closeOnce.Do(func() {
		atomic.StoreInt32(&u.closed, 1) // 设置关闭标志
		if u.udpListener != nil {
			u.udpListener.Close() // 关闭 UDP 监听器
		}
		if u.clientConn != nil {
			u.clientConn.Close() // 关闭控制连接
		}
		// 关闭所有复用的远程连接
		u.remoteConnsMu.Lock()
		for _, conn := range u.remoteConns {
			conn.Close()
		}
		u.remoteConns = nil
		u.remoteConnsMu.Unlock()
		// 清理客户端地址映射
		u.clientMapMu.Lock()
		u.clientMap = nil
		u.clientMapMu.Unlock()
		// 注意：不在这里调用 wg.Done()，因为 UDPAssociation 没有对应的 wg.Add(1)
		// UDP 关联的生命周期由 handleUDPData() 和 waitForClose() 管理
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

// copyData 在两个连接之间复制数据（备用函数）
func copyData(dst, src net.Conn, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	io.Copy(dst, src)
}
