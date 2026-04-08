// Package main 实现 SOCKS5 代理服务器的 TCP/UDP 数据转发功能。
// 包括 TCP 代理（支持速度限制、流量统计、用户配额）和 UDP 代理（低延迟转发）。
package main

import (
	"fmt"         // 导入格式化包，用于字符串格式化和地址拼接
	"io"          // 导入输入输出包，提供 CopyBuffer 等数据复制工具
	"log"         // 导入日志包，用于记录运行日志和错误信息
	"net"         // 导入网络包，提供 TCP/UDP 连接和网络地址操作
	"strconv"     // 导入字符串转换包，用于端口号字符串与整数的转换
	"sync"        // 导入同步包，提供 WaitGroup、Once 等同步原语
	"sync/atomic" // 导入原子操作包，提供无锁的线程安全整数操作
	"time"        // 导入时间包，用于超时控制和时间计算
)

// tcpBufferPool TCP 代理使用的缓冲区池，每个缓冲区 64KB。
// 使用 sync.Pool 实现内存复用，减少 GC 压力和内存分配开销。
// sync.Pool 会在 GC 时自动清理未使用的对象，无需手动管理生命周期。
var tcpBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 64*1024) // 每次创建新的 64KB 字节切片（从256KB优化到64KB）
	},
}

// udpBufferPool UDP 代理使用的缓冲区池，每个缓冲区 64KB（UDP 最大数据包大小）。
// UDP 协议规定最大数据包大小为 65535 字节（包括头部），因此缓冲区设置为 65535 字节。
// 使用 sync.Pool 实现内存复用，减少高频 UDP 转发时的内存分配压力。
var udpBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 65535) // 每次创建新的 65535 字节（64KB-1）切片
	},
}

// TCPProxy TCP 代理结构体，负责客户端与远程服务器之间的数据转发。
// 支持流量统计、用户配额检查、批量持久化等高级功能。
// 采用优化策略：根据配置动态选择快速路径或完整功能路径，提升性能。
type TCPProxy struct {
	// === 流量统计 ===
	// 用于累积待持久化的流量数据，减少数据库写入频率
	pendingUpload   int64 // 待持久化的上传流量累积值（字节）
	pendingDownload int64 // 待持久化的下载流量累积值（字节）
	batchSize       int64 // 批量持久化的阈值（字节），达到此值后触发数据库更新

	// === 网络连接 ===
	// 代理涉及的两个端点连接
	clientConn net.Conn // 客户端 TCP 连接，接收客户端请求并返回响应
	remoteConn net.Conn // 远程服务器 TCP 连接，转发客户端请求到目标服务器

	// === 服务器引用 ===
	// 对父级服务器实例的引用，用于访问全局配置和统计
	server     *Server     // 服务器实例指针，用于访问配置、统计等资源
	bufferPool *BufferPool // 缓冲区池指针，用于获取和归还数据缓冲区

	// === 并发控制 ===
	// 确保资源正确释放，防止重复关闭导致的 panic
	closeOnce sync.Once // sync.Once 确保 Close() 方法只执行一次，防止重复关闭
	closed    int32     // 关闭标志位，使用 atomic 操作：0=开启状态，1=已关闭状态

	// === 用户信息 ===
	// 关联的用户身份和认证信息，用于流量统计和配额管理
	username             string        // 用户名，用于流量统计、配额检查和连接计数
	authCache            *PasswordAuth // 认证器缓存指针，避免每次操作都重新查找认证器
	usernameQuotaChecked bool          // 配额检查优化标记，记录是否已进行过配额检查

	// === 功能开关 ===
	// 根据配置动态启用的功能标志，用于优化运行时性能
	needStats       bool // 是否需要统计总流量，由 server.stats != nil 决定
	needUserTraffic bool // 是否需要记录用户级别流量，由启用用户管理决定
}

// NewTCPProxy 创建一个新的 TCP 代理实例。
// 初始化代理的基本配置，包括客户端连接、服务器引用、缓冲区大小和功能开关。
//
// 参数:
//   - clientConn: 客户端 TCP 连接，已建立并完成 SOCKS5 握手
//   - server: 服务器实例指针，用于访问全局配置和统计信息
//
// 返回:
//   - *TCPProxy: 初始化完成的 TCP 代理实例，可立即用于数据转发
func NewTCPProxy(clientConn net.Conn, server *Server) *TCPProxy {
	// 创建 TCPProxy 结构体并初始化基本字段
	proxy := &TCPProxy{
		clientConn: clientConn, // 保存客户端连接引用
		server:     server,     // 保存服务器实例引用
		batchSize:  256 * 1024, // 设置批量持久化阈值为 256KB
	}
	// 检查服务器实例和配置是否有效
	if server != nil && server.config != nil {
		// 根据统计模块是否存在决定是否需要流量统计
		proxy.needStats = server.stats != nil
		// 注意：needUserTraffic 不再在这里设置，而是在 copyWithStats 中动态检查
		// 这样可以支持运行时切换认证方式
	}
	return proxy // 返回初始化完成的代理实例
}

// SetUsername 设置 TCP 代理的用户名，并应用用户级别的配置。
// 包括配额检查等。
//
// 参数:
//   - username: 已通过认证的用户名
func (p *TCPProxy) SetUsername(username string) {
	p.username = username // 保存用户名到代理实例
	// 如果认证器缓存存在，检查配额
	if p.authCache != nil {
		// 检查用户流量配额是否已用尽，如果超限则拒绝连接
		if p.authCache.CheckQuotaExceeded(username) {
			log.Printf("用户 [%s] 流量配额已用尽，拒绝连接", username) // 记录日志
			p.clientConn.Close()                         // 关闭客户端连接，拒绝服务
			return                                       // 提前返回，不继续处理
		}
	}
}

// SetBufferPool 设置缓冲区池，用于内存复用。
// 缓冲区池由外部管理，通过此方法注入到代理实例中。
//
// 参数:
//   - pool: 外部创建的 BufferPool 实例指针
func (p *TCPProxy) SetBufferPool(pool *BufferPool) {
	p.bufferPool = pool // 保存缓冲区池引用
}

// HandleConnect 处理 SOCKS5 CONNECT 命令，建立到目标服务器的 TCP 连接。
// 连接成功后，向客户端发送成功响应，然后启动双向数据中继。
// 这是 TCP 代理的核心功能，实现客户端与目标服务器之间的透明转发。
//
// 参数:
//   - dstAddr: 目标地址字符串（IPv4/IPv6/域名）
//   - dstPort: 目标端口号（0-65535）
//
// 返回:
//   - error: 连接建立过程中的错误，如 DNS 解析失败、连接超时等
func (p *TCPProxy) HandleConnect(dstAddr string, dstPort uint16) error {
	// 拼接完整的网络地址字符串（格式：IP:Port 或 域名:Port）
	remoteAddr := net.JoinHostPort(dstAddr, fmt.Sprintf("%d", dstPort))
	// 尝试建立到目标服务器的 TCP 连接，设置 10 秒超时防止长时间阻塞
	remoteConn, err := net.DialTimeout("tcp", remoteAddr, 10*time.Second)
	if err != nil {
		return err // 连接失败，返回错误由调用者处理并响应客户端
	}
	p.remoteConn = remoteConn // 保存远程连接引用到代理实例

	// 如果连接是 TCP 类型，优化连接参数以提升性能和实时性
	if tcpConn, ok := remoteConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)                     // 禁用 Nagle 算法，减少小数据包延迟，适合实时应用
		tcpConn.SetKeepAlive(true)                   // 启用 TCP Keepalive 机制，自动检测死连接
		tcpConn.SetKeepAlivePeriod(10 * time.Second) // 设置 Keepalive 探测间隔为 10 秒
		// 使用系统默认的 TCP 缓冲区大小，由操作系统自动调优
	}

	// 获取本地分配的地址信息，用于构建响应告知客户端实际绑定的地址
	localAddr := remoteConn.LocalAddr().(*net.TCPAddr)

	// 根据 IP 地址类型确定响应中的地址类型字段值
	var addrType byte
	ip := localAddr.IP
	if ip4 := ip.To4(); ip4 != nil {
		addrType = AddrTypeIPv4 // 可转换为 IPv4，使用 IPv4 类型标识
	} else if ip16 := ip.To16(); ip16 != nil {
		addrType = AddrTypeIPv6 // 可转换为 IPv6，使用 IPv6 类型标识
	} else {
		addrType = AddrTypeDomain // 其他情况（理论上不会发生），使用域名类型
	}

	// 向客户端发送成功响应，包含服务器实际绑定的地址和端口
	if err := WriteResponse(p.clientConn, ReplySuccess, addrType, localAddr.IP.String(), uint16(localAddr.Port)); err != nil {
		return err // 响应写入失败，返回错误
	}

	// 启动双向数据中继，开始实际的数据转发
	p.startRelay()
	return nil // 成功启动中继，返回 nil
}

// startRelay 启动双向数据中继。
// 创建两个独立的 goroutine 分别处理上传和下载方向的数据转发。
// 使用 sync.WaitGroup 等待两个方向都完成后才返回，确保资源正确清理。
// 任一方向关闭时，会触发整个代理的关闭（通过 defer p.Close()），确保连接状态一致。
func (p *TCPProxy) startRelay() {
	var wg sync.WaitGroup // 创建等待组，用于同步两个方向的完成状态
	wg.Add(2)             // 添加两个待完成的任务计数（上传方向和下载方向）

	// 启动上传方向的 goroutine：数据从远程服务器流向客户端
	go func() {
		defer wg.Done()                                   // 任务完成时递减等待组计数
		defer p.Close()                                   // 任一方向结束时关闭整个代理，确保资源释放
		p.copyWithStats(p.remoteConn, p.clientConn, true) // 执行带统计的数据复制，upload=true 表示上传方向
	}()

	// 启动下载方向的 goroutine：数据从客户端流向远程服务器
	go func() {
		defer wg.Done()                                    // 任务完成时递减等待组计数
		defer p.Close()                                    // 任一方向结束时关闭整个代理，确保资源释放
		p.copyWithStats(p.clientConn, p.remoteConn, false) // 执行带统计的数据复制，upload=false 表示下载方向
	}()

	wg.Wait() // 阻塞等待，直到两个方向的 goroutine 都完成
}

// copyWithStats 带统计和限速的数据复制函数。
// 根据配置决定是否启用流量统计、用户流量记录、速度限制等功能。
// 采用多种优化策略：
// 1. 如果无需任何额外功能，使用快速复制路径（copyFast）
// 2. 如果只需统计，使用简化统计路径（copyWithStatsOnly）
// 3. 如果需要完整功能，使用完整路径（包括批量持久化、配额检查等）
//
// 参数:
//   - dst: 目标连接，数据写入到此连接
//   - src: 源连接，数据从此连接读取
//   - upload: 是否为上传方向（true=远程->客户端，false=客户端->远程）
func (p *TCPProxy) copyWithStats(dst, src net.Conn, upload bool) {
	// 从缓冲区池获取一个缓冲区，函数返回时归还
	buf := p.bufferPool.Get()
	defer p.bufferPool.Put(buf) // 确保缓冲区被归还到池中

	// 将常用变量提取到局部变量，减少结构体字段访问开销
	var (
		stats = p.server.stats // 服务器统计指针
	)

	// 动态检查当前的认证方式和用户名
	// 这样可以在运行时切换认证方式后立即生效
	var needUserTraffic bool
	var auth *PasswordAuth
	var username string

	if p.server != nil && p.server.config != nil {
		// 尝试将认证器转换为 PasswordAuth
		if a, ok := p.server.config.Auth.(*PasswordAuth); ok {
			auth = a
			username = p.username
			needUserTraffic = (auth != nil && username != "")
		}
	}

	// 如果需要用户流量记录，则强制启用统计功能
	needStats := p.needStats
	if needUserTraffic {
		needStats = true
	}

	// 优化路径1：如果无需任何额外功能，使用最快的复制方式
	if !needStats && !needUserTraffic {
		p.copyFast(dst, src, buf)
		return
	}

	// 优化路径2：如果只需要统计，使用简化的统计复制
	if needStats && !needUserTraffic {
		p.copyWithStatsOnly(dst, src, buf, upload, stats)
		return
	}

	// 完整路径：需要所有功能（统计+用户流量）
	//log.Printf("[DEBUG] 使用完整统计路径（包含用户流量）")
	// 定义批量持久化的阈值和超时参数
	const batchThreshold int64 = 512 * 1024     // 批量提交阈值：512KB
	const flushThreshold int64 = 64 * 1024      // 刷新阈值：64KB
	const flushTimeout = 200 * time.Millisecond // 刷新超时：200ms
	const dbFlushInterval = 5 * time.Minute     // 数据库持久化间隔：5分钟

	// 初始化本地累积计数器
	localUpload := int64(0)   // 本地累积的上传流量
	localDownload := int64(0) // 本地累积的下载流量
	dbUpload := int64(0)      // 待持久化到数据库的上传流量
	dbDownload := int64(0)    // 待持久化到数据库的下载流量

	// 配额检查相关变量
	quotaCheckCounter := 0       // 配额检查计数器
	lastQuotaCheck := time.Now() // 上次配额检查时间
	lastFlush := time.Now()      // 上次刷新统计的时间
	lastDbFlush := time.Now()    // 上次数据库持久化的时间

	readTimeout := 300 * time.Second // 读取超时：300秒（5分钟）

	// 主循环：持续读取和转发数据
	for {
		// 设置读取超时，防止连接挂起
		src.SetReadDeadline(time.Now().Add(readTimeout))

		// 从源连接读取数据到缓冲区
		n, err := src.Read(buf)
		if n > 0 {
			// 如果有数据可读，写入目标连接
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return // 写入失败，退出循环
			}

			// 如果需要统计，累积流量数据
			if needStats {
				now := time.Now() // 获取当前时间
				if upload {
					// 上传方向：累加到本地计数器
					localUpload += int64(n)
					// 检查是否达到批量提交条件
					if localUpload >= batchThreshold ||
						(localUpload >= flushThreshold && now.Sub(lastFlush) > flushTimeout) ||
						(localUpload > 0 && now.Sub(lastFlush) > 200*time.Millisecond) {
						// 原子累加到全局统计
						atomic.AddInt64(&stats.TotalUpload, localUpload)
						dbUpload += localUpload // 累积待持久化数据
						localUpload = 0         // 重置本地计数器
						lastFlush = now         // 更新刷新时间
					}
				} else {
					// 下载方向：累加到本地计数器
					localDownload += int64(n)
					// 检查是否达到批量提交条件
					if localDownload >= batchThreshold ||
						(localDownload >= flushThreshold && now.Sub(lastFlush) > flushTimeout) ||
						(localDownload > 0 && now.Sub(lastFlush) > 200*time.Millisecond) {
						// 原子累加到全局统计
						atomic.AddInt64(&stats.TotalDownload, localDownload)
						dbDownload += localDownload // 累积待持久化数据
						localDownload = 0           // 重置本地计数器
						lastFlush = now             // 更新刷新时间
					}
				}
			}

			// 如果需要用户流量记录，更新用户统计数据
			if needUserTraffic && auth != nil && username != "" {
				if upload {
					p.pendingUpload += int64(n)                // 累加待持久化上传流量
					auth.AddUserTraffic(username, int64(n), 0) // 记录用户上传流量
				} else {
					p.pendingDownload += int64(n)              // 累加待持久化下载流量
					auth.AddUserTraffic(username, 0, int64(n)) // 记录用户下载流量
				}

				// 定期执行配额检查，避免每次都检查影响性能
				quotaCheckCounter++
				now := time.Now()
				// 每 200 次传输或 200ms 检查一次配额
				if quotaCheckCounter >= 200 || now.Sub(lastQuotaCheck) > 200*time.Millisecond {
					quotaCheckCounter = 0 // 重置计数器
					lastQuotaCheck = now  // 更新检查时间
					// 检查配额是否超限
					if auth.CheckQuotaExceeded(username) {
						log.Printf("用户 [%s] 流量配额已用尽 (%.2f MB / %.2f MB)，终止连接",
							username,
							float64(auth.GetUserQuotaUsed(username))/1024/1024,
							float64(auth.GetUserQuotaTotal(username))/1024/1024)
						// 立即关闭连接，确保小流量无法继续通过
						p.Close()
						return // 配额超限，终止连接
					}
				}
				// 定期将内存中的流量数据持久化到数据库
				if now.Sub(lastDbFlush) > dbFlushInterval {
					if user, exists := auth.GetUser(username); exists {
						quotaUsed := atomic.LoadInt64(&user.QuotaUsed)
						uploadTotal := atomic.LoadInt64(&user.UploadTotal)
						downloadTotal := atomic.LoadInt64(&user.DownloadTotal)

						// 检查 dbManager 是否已初始化
						if dbManager != nil {
							if err := dbManager.UpdateUserQuotaUsed(
								username,
								quotaUsed,
								uploadTotal,
								downloadTotal,
							); err != nil {
								log.Printf("保存用户 [%s] 流量数据失败: %v", username, err)
							}
						}
					}
					lastDbFlush = now // 更新数据库持久化时间
				}
			}
		}
		// 检查读取错误
		if err != nil {
			// 退出前刷新剩余的统计数据
			if needStats && (localUpload > 0 || localDownload > 0) {
				if localUpload > 0 {
					atomic.AddInt64(&stats.TotalUpload, localUpload)
				}
				if localDownload > 0 {
					atomic.AddInt64(&stats.TotalDownload, localDownload)
				}
			}
			return // 读取错误或 EOF，退出循环
		}
	}

}

// copyFast 快速数据复制函数，不带任何统计和限速功能。
// 优先尝试使用 TCP splice（零拷贝），如果不支持则回退到普通复制。
//
// 参数:
//   - dst: 目标写入器
//   - src: 源读取器
//   - buf: 预分配的缓冲区
func (p *TCPProxy) copyFast(dst io.Writer, src io.Reader, buf []byte) {
	// 尝试使用 TCP 连接的零拷贝特性（如果两端都是 TCP 连接）
	if tcpDst, ok := dst.(*net.TCPConn); ok {
		if tcpSrc, ok := src.(*net.TCPConn); ok {
			// 尝试使用 splice 方式进行零拷贝传输
			if err := p.copyWithSplice(tcpDst, tcpSrc); err == nil {
				return // splice 成功，直接返回
			}
			// splice 失败，回退到普通复制
		}
	}
	// 使用标准库的 CopyBuffer 进行数据复制
	_, err := io.CopyBuffer(dst, src, buf)
	_ = err // 忽略错误，由调用者处理
}

// copyWithSplice 使用 TCP splice 进行零拷贝数据传输。
// 目前实现仍使用 CopyBuffer，预留未来优化空间。
//
// 参数:
//   - dst: 目标 TCP 连接
//   - src: 源 TCP 连接
//
// 返回:
//   - error: 复制过程中的错误
func (p *TCPProxy) copyWithSplice(dst, src *net.TCPConn) error {
	buf := make([]byte, 128*1024) // 分配 128KB 缓冲区
	_, err := io.CopyBuffer(dst, src, buf)
	return err
}

// copyWithStatsOnly 仅带统计的数据复制函数，不含用户流量和限速功能。
// 用于只需要全局流量统计的场景，比完整路径更高效。
//
// 参数:
//   - dst: 目标写入器
//   - src: 源读取器
//   - buf: 预分配的缓冲区
//   - upload: 是否为上传方向
//   - stats: 服务器统计指针
func (p *TCPProxy) copyWithStatsOnly(dst io.Writer, src io.Reader, buf []byte, upload bool, stats *Stats) {
	// 定义批量提交的阈值和超时参数（比完整路径更激进，因为只涉及内存操作）
	const batchThreshold int64 = 100 * 1024    // 批量提交阈值：100KB
	const flushThreshold int64 = 10 * 1024     // 刷新阈值：10KB
	const flushTimeout = 50 * time.Millisecond // 刷新超时：50ms

	// 初始化本地累积计数器
	localUpload := int64(0)   // 本地累积的上传流量
	localDownload := int64(0) // 本地累积的下载流量
	lastFlush := time.Now()   // 上次刷新时间

	// 尝试将源转换为 net.Conn 以设置超时
	var srcConn net.Conn
	if conn, ok := src.(net.Conn); ok {
		srcConn = conn
	}

	// 主循环：持续读取和转发数据
	for {
		// 设置读取超时（如果源是网络连接）
		if srcConn != nil {
			srcConn.SetReadDeadline(time.Now().Add(300 * time.Second))
		}

		// 从源读取数据
		n, err := src.Read(buf)
		if n > 0 {
			// 写入目标
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return // 写入失败，退出
			}

			// 累积流量统计
			now := time.Now()
			if upload {
				localUpload += int64(n)
				// 检查是否达到刷新条件
				if localUpload >= batchThreshold ||
					(localUpload >= flushThreshold && now.Sub(lastFlush) > flushTimeout) ||
					(localUpload > 0 && now.Sub(lastFlush) > 200*time.Millisecond) {
					atomic.AddInt64(&stats.TotalUpload, localUpload)
					localUpload = 0 // 重置计数器
					lastFlush = now // 更新时间
				}
			} else {
				localDownload += int64(n)
				// 检查是否达到刷新条件
				if localDownload >= batchThreshold ||
					(localDownload >= flushThreshold && now.Sub(lastFlush) > flushTimeout) ||
					(localDownload > 0 && now.Sub(lastFlush) > 200*time.Millisecond) {
					atomic.AddInt64(&stats.TotalDownload, localDownload)
					localDownload = 0 // 重置计数器
					lastFlush = now   // 更新时间
				}
			}
		}
		// 检查读取错误
		if err != nil {
			// 退出前刷新剩余统计
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

// Close 关闭 TCP 代理，释放所有相关资源。
// 使用 sync.Once 确保只执行一次，防止重复关闭导致的 panic。
// 关闭时会更新用户连接计数、清理 IP 记录、持久化最终流量数据。
func (p *TCPProxy) Close() {
	p.closeOnce.Do(func() { // 确保只执行一次
		// 设置关闭标志
		atomic.StoreInt32(&p.closed, 1)

		// 关闭客户端连接
		if p.clientConn != nil {
			p.clientConn.Close()
			p.clientConn = nil // 置为 nil，释放引用
		}
		// 关闭远程服务器连接
		if p.remoteConn != nil {
			p.remoteConn.Close()
			p.remoteConn = nil // 置为 nil，释放引用
		}

		// 如果有关联的用户，更新用户状态
		if p.username != "" && p.authCache != nil {
			// 减少用户连接计数
			p.authCache.DecrementUserConnection(p.username)
			// 移除用户的 IP 记录
			if p.clientConn != nil {
				clientIP := p.clientConn.RemoteAddr().String()
				p.authCache.RemoveUserIP(p.username, clientIP)
			}
			// 连接关闭时保存最终的流量数据到数据库
			if user, exists := p.authCache.GetUser(p.username); exists {
				if err := dbManager.UpdateUserQuotaUsed(
					p.username,
					atomic.LoadInt64(&user.QuotaUsed),
					atomic.LoadInt64(&user.UploadTotal),
					atomic.LoadInt64(&user.DownloadTotal),
				); err != nil {
					log.Printf("保存用户 [%s] 最终流量数据失败: %v", p.username, err)
				}
			}
		}
	})
}

// IsClosed 检查 TCP 代理是否已关闭。
//
// 返回:
//   - bool: true 表示已关闭，false 表示仍在运行
func (p *TCPProxy) IsClosed() bool {
	return atomic.LoadInt32(&p.closed) == 1
}

// UDPAssociation UDP 代理关联结构体，负责 UDP 数据包的转发。
// 用于 SOCKS5 UDP ASSOCIATE 命令，实现游戏等低延迟应用的 UDP 转发。
// 注意：UDP 不限速、不检查配额，确保最低延迟。
type UDPAssociation struct {
	// === 网络连接 ===
	clientAddr  *net.UDPAddr // 客户端 UDP 地址（保留字段，当前未直接使用）
	clientConn  net.Conn     // 客户端 TCP 控制连接（用于接收关闭信号）
	udpListener *net.UDPConn // UDP 监听器，接收和发送 UDP 数据包

	// === 服务器引用 ===
	server *Server // 服务器实例引用，用于访问统计和配置

	// === 并发控制 ===
	closeOnce sync.Once // sync.Once 确保 Close() 只执行一次
	closed    int32     // 关闭标志，atomic 操作：0=开启，1=已关闭

	// === 客户端映射 ===
	// 维护客户端地址到 UDP 地址的映射，支持多客户端场景
	clientMap   map[string]*net.UDPAddr // 客户端地址映射表：key=地址字符串, value=UDP地址
	clientMapMu sync.RWMutex            // clientMap 的读写锁

	// === 远程连接池 ===
	// 维护到不同目标服务器的 UDP 连接池，避免重复建立连接
	remoteConns   map[string]*net.UDPConn // 远程服务器连接池：key=目标地址, value=UDP连接
	remoteConnsMu sync.RWMutex            // remoteConns 的读写锁

	// === 用户信息 ===
	username string // 用户名，用于流量统计（但不限速、不检查配额）
}

// NewUDPAssociation 创建一个新的 UDP 代理关联实例。
// 初始化客户端映射表和远程连接池。
//
// 参数:
//   - clientConn: 客户端 TCP 控制连接
//   - server: 服务器实例引用
//
// 返回:
//   - *UDPAssociation: 初始化后的 UDP 关联实例
func NewUDPAssociation(clientConn net.Conn, server *Server) *UDPAssociation {
	udpAssoc := &UDPAssociation{
		clientConn:  clientConn,
		server:      server,
		clientMap:   make(map[string]*net.UDPAddr), // 初始化客户端地址映射表
		remoteConns: make(map[string]*net.UDPConn), // 初始化远程服务器连接池
	}
	return udpAssoc
}

// SetUsername 设置 UDP 关联的用户名，用于流量统计。
// 注意：UDP 不限速、不检查配额，仅记录流量数据以确保最低延迟。
//
// 参数:
//   - username: 已通过认证的用户名
func (u *UDPAssociation) SetUsername(username string) {
	u.username = username
}

// HandleUDPAssociate 处理 SOCKS5 UDP ASSOCIATE 命令。
// 创建 UDP 监听器，向客户端返回绑定的地址和端口，
// 然后启动 UDP 数据转发协程并等待控制连接关闭。
//
// 返回:
//   - error: 处理过程中的错误，如 UDP 监听器创建失败
func (u *UDPAssociation) HandleUDPAssociate() error {
	// 安全地获取客户端控制连接
	u.clientMapMu.RLock()
	controlConn := u.clientConn
	u.clientMapMu.RUnlock()

	// 检查控制连接是否有效
	if controlConn == nil {
		return fmt.Errorf("clientConn is nil") // 控制连接为空，返回错误
	}

	// 获取控制连接的本地地址，用于确定 UDP 监听器的绑定 IP
	controlLocalAddr := controlConn.LocalAddr().(*net.TCPAddr)

	// 创建 UDP 监听器，Port=0 表示由系统自动分配可用端口
	udpAddr := &net.UDPAddr{IP: controlLocalAddr.IP, Port: 0}
	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err // UDP 监听器创建失败，返回错误
	}
	u.udpListener = udpListener // 保存 UDP 监听器引用

	// 获取 UDP 监听器的实际本地地址（包含系统分配的端口）
	localAddr := udpListener.LocalAddr().(*net.UDPAddr)

	// 确定地址类型（IPv4/IPv6/域名）
	var addrType byte
	ip := controlLocalAddr.IP
	if ip4 := ip.To4(); ip4 != nil {
		addrType = AddrTypeIPv4 // IPv4 地址
	} else if ip16 := ip.To16(); ip16 != nil {
		addrType = AddrTypeIPv6 // IPv6 地址
	} else {
		addrType = AddrTypeDomain // 其他情况
	}

	// 向客户端发送成功响应，包含 UDP 监听器的地址和端口
	if err := WriteResponse(u.clientConn, ReplySuccess, addrType, controlLocalAddr.IP.String(), uint16(localAddr.Port)); err != nil {
		udpListener.Close() // 响应失败，关闭监听器
		return err          // 返回错误
	}

	// 启动 UDP 数据转发协程，处理实际的 UDP 数据包
	go u.handleUDPData()

	// 启动定期清理协程，防止内存泄漏
	go u.cleanupIdleClients()

	// 等待控制连接关闭（TCP 连接），此调用会阻塞
	u.waitForClose()

	return nil
}

// handleUDPData 处理 UDP 数据包的接收和转发。
// 循环从 UDP 监听器读取数据包，解析 SOCKS5 UDP 头部，然后转发到目标服务器。
// 每个数据包的处理都在独立的 goroutine 中进行，以实现并发处理。
func (u *UDPAssociation) handleUDPData() {
	// 主循环：持续接收 UDP 数据包
	for !u.IsClosed() {
		// 从 UDP 缓冲区池获取缓冲区
		buf := udpBufferPool.Get().([]byte)

		// 安全地获取 UDP 监听器
		u.clientMapMu.RLock()
		listener := u.udpListener
		u.clientMapMu.RUnlock()

		// 检查监听器是否有效
		if listener == nil {
			udpBufferPool.Put(buf) // 归还缓冲区
			return                 // 监听器无效，退出
		}

		// 从 UDP 监听器读取数据包
		n, clientAddr, err := listener.ReadFromUDP(buf)
		if err != nil {
			udpBufferPool.Put(buf) // 归还缓冲区
			if u.IsClosed() {
				return // 代理已关闭，正常退出
			}
			log.Printf("UDP 读取错误：%v", err) // 记录错误日志
			u.Close()                      // 关闭代理
			return
		}

		// 生成客户端唯一标识 key
		clientKey := clientAddr.String()
		// 将客户端地址添加到映射表中（如果已存在则更新）
		u.clientMapMu.Lock()
		if u.clientMap != nil {
			u.clientMap[clientKey] = clientAddr
		}
		u.clientMapMu.Unlock()

		// 检查数据包长度是否足够解析头部（最小 10 字节）
		if n < 10 {
			udpBufferPool.Put(buf) // 数据包太短，丢弃并归还缓冲区
			continue
		}

		// 解析 SOCKS5 UDP 头部
		header, err := ParseUDPHeader(buf[:n])
		if err != nil {
			udpBufferPool.Put(buf) // 解析失败，丢弃并归还缓冲区
			continue
		}

		// 检查保留字段和分片字段（当前实现不支持分片）
		if header.Rsv != 0 || header.Frag != 0 {
			udpBufferPool.Put(buf) // 不支持的字段，丢弃并归还缓冲区
			continue
		}

		// 异步转发到远程服务器（不阻塞主循环）
		go func() {
			defer udpBufferPool.Put(buf) // 确保缓冲区被归还
			u.forwardToRemote(header, clientKey)
		}()
	}
}

// forwardToRemote 将 UDP 数据包转发到远程服务器。
// 使用连接池复用远程连接，并为每个新连接启动后台响应读取 goroutine。
//
// 参数:
//   - header: 解析后的 UDP 头部，包含目标地址和数据
//   - clientKey: 客户端的唯一标识 key
func (u *UDPAssociation) forwardToRemote(header *UDPHeader, clientKey string) {
	// 拼接目标地址字符串
	dstAddr := net.JoinHostPort(header.DstAddr, fmt.Sprintf("%d", header.DstPort))

	// 从连接池中查找已有的远程连接
	u.remoteConnsMu.RLock()
	remoteConn, exists := u.remoteConns[dstAddr]
	u.remoteConnsMu.RUnlock()

	// 如果连接不存在或为空，创建新连接并启动后台读取 goroutine
	if !exists || remoteConn == nil {
		u.remoteConnsMu.Lock()
		if u.remoteConns != nil {
			// 双重检查，防止竞态条件
			if remoteConn, exists = u.remoteConns[dstAddr]; !exists || remoteConn == nil {
				// 建立到目标服务器的 UDP 连接
				conn, err := net.Dial("udp", dstAddr)
				if err != nil {
					u.remoteConnsMu.Unlock()
					return // 连接失败，返回
				}
				// 优化 UDP 连接参数
				if udpConn, ok := conn.(*net.UDPConn); ok {
					udpConn.SetReadBuffer(256 * 1024)  // 设置 256KB 接收缓冲区
					udpConn.SetWriteBuffer(256 * 1024) // 设置 256KB 发送缓冲区
					remoteConn = udpConn
				} else {
					remoteConn = conn.(*net.UDPConn)
				}
				// 将新连接存入连接池
				u.remoteConns[dstAddr] = remoteConn

				// 为新连接启动后台响应读取 goroutine
				go u.readFromRemoteAndRespond(remoteConn, dstAddr, clientKey, header.AddrType, header.DstAddr, header.DstPort)
			}
		} else {
			u.remoteConnsMu.Unlock()
			return // 连接池已被清理，返回
		}
		u.remoteConnsMu.Unlock()
	}

	// 检查连接是否有效
	if remoteConn == nil {
		return
	}

	// 发送数据到远程服务器
	_, err := remoteConn.Write(header.Data)
	if err != nil {
		return // 发送失败，快速失败
	}

	// 统计上传流量
	uploadSize := int64(len(header.Data))
	if u.server != nil && u.server.stats != nil {
		u.server.stats.AddUpload(uploadSize)
	}

	// 用户流量统计（UDP 不限速、不检查配额，仅记录）
	if u.username != "" && u.server != nil && u.server.config != nil {
		if auth, ok := u.server.config.Auth.(*PasswordAuth); ok {
			auth.AddUserTraffic(u.username, uploadSize, 0)
		}
	}
}

// readFromRemoteAndRespond 从远程服务器读取响应并返回给客户端。
// 此函数在独立的 goroutine 中运行，持续监听指定连接的响应。
//
// 参数:
//   - remoteConn: 远程 UDP 连接
//   - dstAddr: 目标地址字符串
//   - clientKey: 客户端的唯一标识 key
//   - addrType: 地址类型（IPv4/IPv6/Domain）
//   - dstAddrStr: 目标地址字符串
//   - dstPort: 目标端口
func (u *UDPAssociation) readFromRemoteAndRespond(remoteConn *net.UDPConn, dstAddr string, clientKey string, addrType byte, dstAddrStr string, dstPort uint16) {
	// 从缓冲区池获取响应缓冲区
	responseBuf := udpBufferPool.Get().([]byte)
	defer func() {
		udpBufferPool.Put(responseBuf) // 确保归还缓冲区
		// 连接关闭时从连接池中移除
		u.remoteConnsMu.Lock()
		delete(u.remoteConns, dstAddr)
		u.remoteConnsMu.Unlock()
		// 关闭远程连接
		if remoteConn != nil {
			remoteConn.Close()
		}
	}()

	// 持续读取响应（直到连接关闭或代理关闭）
	for !u.IsClosed() {
		// 设置短超时（100ms），避免长时间阻塞
		remoteConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

		// 读取响应数据
		n, err := remoteConn.Read(responseBuf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // 超时是正常的，继续等待
			}
			// 其他错误，退出循环
			break
		}

		// 成功读取到数据，查找对应的客户端地址
		u.clientMapMu.RLock()
		clientAddr, exists := u.clientMap[clientKey]
		u.clientMapMu.RUnlock()

		if !exists {
			break // 客户端不存在，退出
		}

		// 构建 SOCKS5 UDP 响应头部
		respData, err := BuildUDPHeader(addrType, dstAddrStr, dstPort, responseBuf[:n])
		if err != nil {
			break // 构建失败，退出
		}

		// 发送响应给客户端
		_, writeErr := u.udpListener.WriteToUDP(respData, clientAddr)
		if writeErr != nil {
			break // 发送失败，退出
		}

		// 统计下载流量
		downloadSize := int64(n)
		if u.server != nil && u.server.stats != nil {
			u.server.stats.AddDownload(downloadSize)
		}

		// 用户流量统计
		if u.username != "" && u.server != nil && u.server.config != nil {
			if auth, ok := u.server.config.Auth.(*PasswordAuth); ok {
				auth.AddUserTraffic(u.username, 0, downloadSize)
			}
		}
	}
}

// cleanupIdleClients 定期清理空闲的客户端和远程连接，防止内存泄漏。
// 每 10 秒执行一次，检查并清理无效资源。
func (u *UDPAssociation) cleanupIdleClients() {
	ticker := time.NewTicker(10 * time.Second) // 创建 10 秒间隔的定时器
	defer ticker.Stop()                        // 确保函数返回时停止定时器

	for {
		select {
		case <-ticker.C:
			if u.IsClosed() {
				return // 代理已关闭，退出
			}

			// 清理 clientMap：如果超过 1000 个客户端，清空所有（极端情况保护）
			u.clientMapMu.Lock()
			clientCount := len(u.clientMap)
			if clientCount > 1000 {
				log.Printf("[UDP警告] clientMap 过大 (%d)，强制清空", clientCount)
				u.clientMap = make(map[string]*net.UDPAddr)
			}
			u.clientMapMu.Unlock()

			// 清理 remoteConns：检查连接是否仍然有效
			u.remoteConnsMu.Lock()
			connCount := len(u.remoteConns)
			cleanedCount := 0
			for dstAddr, conn := range u.remoteConns {
				if conn == nil {
					delete(u.remoteConns, dstAddr)
					cleanedCount++
					continue
				}

				// 尝试发送一个空包检测连接是否有效
				// 如果失败，说明连接已断开，需要删除
				_, err := conn.Write([]byte{})
				if err != nil {
					conn.Close()
					delete(u.remoteConns, dstAddr)
					cleanedCount++
				}
			}
			u.remoteConnsMu.Unlock()

			// 输出统计信息用于调试
			if cleanedCount > 0 {
				log.Printf("[UDP清理] clients=%d, remoteConns=%d, cleaned=%d",
					clientCount, connCount, cleanedCount)
			}
		case <-time.After(1 * time.Second):
			// 每秒检查一次是否关闭，确保快速退出
			if u.IsClosed() {
				return
			}
		}
	}
}

// waitForClose 等待控制连接关闭。
// 通过读取 TCP 控制连接来检测客户端何时断开，从而清理 UDP 资源。
func (u *UDPAssociation) waitForClose() {
	buf := make([]byte, 1) // 分配 1 字节缓冲区用于检测关闭

	// 无限循环，直到检测到连接关闭
	for {
		// 安全地获取控制连接
		u.clientMapMu.RLock()
		conn := u.clientConn
		u.clientMapMu.RUnlock()

		// 检查连接是否有效
		if conn == nil {
			u.Close() // 连接为空，关闭代理
			return
		}

		// 清除读取超时，使 Read 阻塞等待
		conn.SetReadDeadline(time.Time{})
		// 尝试读取数据，客户端断开时会返回错误
		_, err := conn.Read(buf)
		if err != nil {
			u.Close() // 检测到断开，关闭代理
			return
		}
	}
}

// Close 关闭 UDP 代理关联，释放所有相关资源。
// 使用 sync.Once 确保只执行一次，防止重复关闭。
// 关闭时会清理 UDP 监听器、控制连接、远程连接池和客户端映射。
func (u *UDPAssociation) Close() {
	u.closeOnce.Do(func() { // 确保只执行一次
		// 设置关闭标志（这会让所有后台 goroutine 检测到并退出）
		atomic.StoreInt32(&u.closed, 1)

		// 关闭 UDP 监听器（这会使得 handleUDPData 中的 ReadFromUDP 返回错误并退出）
		if u.udpListener != nil {
			u.udpListener.Close()
			u.udpListener = nil
		}

		// 关闭客户端控制连接
		if u.clientConn != nil {
			u.clientConn.Close()
			u.clientConn = nil
		}

		// 关闭所有远程服务器连接（这会使得 readFromRemoteAndRespond 中的 Read 返回错误并退出）
		u.remoteConnsMu.Lock()
		if u.remoteConns != nil {
			for addr, conn := range u.remoteConns {
				if conn != nil {
					conn.Close() // 关闭每个远程连接
				}
				delete(u.remoteConns, addr) // 立即删除条目
			}
			u.remoteConns = nil // 清空映射，释放内存
		}
		u.remoteConnsMu.Unlock()

		// 清空客户端映射
		u.clientMapMu.Lock()
		if u.clientMap != nil {
			u.clientMap = nil // 清空映射，释放内存
		}
		u.clientMapMu.Unlock()

		// 如果有关联的用户，更新用户状态
		if u.username != "" && u.server != nil && u.server.config != nil && u.server.config.EnableUserManagement {
			if auth, ok := u.server.config.Auth.(*PasswordAuth); ok {
				auth.DecrementUserConnection(u.username) // 减少用户连接计数
				// 连接关闭时保存最终的流量数据
				if user, exists := auth.GetUser(u.username); exists {
					if err := dbManager.UpdateUserQuotaUsed(
						u.username,
						atomic.LoadInt64(&user.QuotaUsed),
						atomic.LoadInt64(&user.UploadTotal),
						atomic.LoadInt64(&user.DownloadTotal),
					); err != nil {
						//log.Printf("保存用户 [%s] UDP最终流量数据失败: %v", u.username, err)
					}
				}
			}
		}
	})
}

// IsClosed 检查 UDP 代理是否已关闭。
//
// 返回:
//   - bool: true 表示已关闭，false 表示仍在运行
func (u *UDPAssociation) IsClosed() bool {
	return atomic.LoadInt32(&u.closed) == 1
}

// parsePort 将端口字符串解析为 uint16 端口号。
// 用于从字符串格式的端口号转换为数值格式。
//
// 参数:
//   - portStr: 端口号字符串（如 "8080"）
//
// 返回:
//   - uint16: 解析后的端口号，解析失败返回 0
func parsePort(portStr string) uint16 {
	// 使用 strconv 解析字符串为 16 位无符号整数
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0 // 解析失败，返回 0
	}
	return uint16(port) // 转换为 uint16 并返回
}

// copyData 简单的数据复制辅助函数。
// 从 src 复制到 dst，完成后向 done 通道发送信号。
//
// 参数:
//   - dst: 目标连接
//   - src: 源连接
//   - done: 完成信号通道
func copyData(dst, src net.Conn, done chan<- struct{}) {
	defer func() { done <- struct{}{} }() // 确保完成后发送信号
	io.Copy(dst, src)                     // 执行数据复制
}
