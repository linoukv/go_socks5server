// Package main 实现 SOCKS5 代理服务器的资源池管理模块。
// 包括工作协程池（WorkerPool）、缓冲区池（BufferPool）、多级缓冲池（MultiBufferPool）
// 和连接管理器（ConnManager），用于高效复用资源并控制并发。
package main

import (
	"context"     // 导入上下文包，用于任务的取消和超时控制
	"sync"        // 导入同步包，提供 WaitGroup、Pool 等同步原语
	"sync/atomic" // 导入原子操作包，提供无锁的线程安全整数操作
)

// WorkerPool 工作协程池，用于控制和复用 goroutine。
// 当配置了最大工作协程数时，通过信号量（chan struct{}）限制并发数量；
// 否则为无限制模式，每个任务启动一个新的 goroutine。
// 使用 context.Context 实现优雅关闭，支持取消所有待处理任务。
type WorkerPool struct {
	submitted int64              // 已提交的任务计数，使用 atomic 操作确保线程安全
	workers   int                // 最大工作协程数，0 表示不限制并发数量
	semaphore chan struct{}      // 信号量通道，容量为 workers，用于限制并发 goroutine 数量
	wg        sync.WaitGroup     // 等待组，用于跟踪所有正在执行的任务，支持优雅关闭
	ctx       context.Context    // 上下文，用于传递取消信号给所有任务
	cancel    context.CancelFunc // 取消函数，调用后所有基于此上下文的操作都会收到取消信号
}

// NewWorkerPool 创建一个新的工作协程池。
// 根据 workers 参数决定是否启用并发限制。
//
// 参数:
//   - workers: 最大工作协程数，0 表示不限制并发数量，正整数表示最大并发数
//
// 返回:
//   - *WorkerPool: 初始化完成的工作池实例，可立即用于提交任务
func NewWorkerPool(workers int) *WorkerPool {
	// 创建可取消的上下文，用于后续的优雅关闭
	ctx, cancel := context.WithCancel(context.Background())

	// 创建工作池结构体
	pool := &WorkerPool{
		workers: workers, // 保存最大工作协程数
		ctx:     ctx,     // 保存上下文
		cancel:  cancel,  // 保存取消函数
	}

	// 仅在有并发限制时创建信号量通道
	if workers > 0 {
		// 创建容量为 workers 的缓冲通道，作为信号量使用
		pool.semaphore = make(chan struct{}, workers)
	}

	return pool // 返回初始化完成的工作池
}

// Submit 向工作池提交一个任务函数。
// 如果工作池已停止（上下文已取消），则拒绝提交新任务。
// 在有限制模式下，如果信号量已满且上下文未取消，会阻塞直到有可用槽位。
//
// 参数:
//   - task: 要执行的任务函数，无参数无返回值
//
// 返回:
//   - bool: 提交是否成功，false 表示工作池已停止或上下文已取消
func (p *WorkerPool) Submit(task func()) bool {
	// 检查工作池是否已停止（上下文是否已被取消）
	if p.ctx.Err() != nil {
		return false // 上下文已取消，拒绝提交新任务
	}

	// 有限制模式：使用信号量控制并发 goroutine 数量
	if p.workers > 0 {
		select {
		case p.semaphore <- struct{}{}:
			// 成功获取信号量槽位，可以启动新协程
			p.wg.Add(1)                      // 增加等待组计数
			atomic.AddInt64(&p.submitted, 1) // 原子增加已提交任务计数

			// 启动新的 goroutine 执行任务
			go func() {
				defer func() {
					<-p.semaphore // 任务完成后释放信号量槽位
					p.wg.Done()   // 减少等待组计数
				}()
				task() // 执行用户提交的任务函数
			}()
			return true // 提交成功

		case <-p.ctx.Done():
			// 上下文已取消，拒绝提交
			return false
		}
	} else {
		// 无限制模式：直接启动新协程，不限制并发数量
		p.wg.Add(1)                      // 增加等待组计数
		atomic.AddInt64(&p.submitted, 1) // 原子增加已提交任务计数

		// 启动新的 goroutine 执行任务
		go func() {
			defer p.wg.Done() // 任务完成后减少等待组计数
			task()            // 执行用户提交的任务函数
		}()
		return true // 提交成功
	}
}

// Stop 停止工作池，等待所有正在执行的任务完成。
// 首先取消上下文，拒绝新的任务提交；
// 然后等待所有已提交的任务执行完毕。
// 此方法应在程序退出前调用，确保资源正确清理。
func (p *WorkerPool) Stop() {
	p.cancel()  // 取消上下文，阻止新任务提交
	p.wg.Wait() // 等待所有正在执行的任务完成
}

// BufferPool 缓冲区池，基于 sync.Pool 实现字节切片的高效复用。
// 通过预分配和回收机制减少内存分配次数和 GC 压力。
// 适用于需要频繁分配和释放固定大小缓冲区的场景。
type BufferPool struct {
	allocated int64     // 已分配的缓冲区总数量，使用 atomic 操作追踪
	pool      sync.Pool // 底层对象池，由 Go 运行时管理生命周期
	size      int       // 每个缓冲区的固定大小（字节）
	preAlloc  int       // 预分配的缓冲区数量配置值
}

// MultiBufferPool 多级缓冲区池，根据请求大小自动选择合适的池。
// 分为小（8KB）、中（128KB）、大（2MB）三级，优化不同场景下的内存使用效率。
// 小池用于控制消息等小数据，中池用于普通数据传输，大池用于高速大数据传输。
type MultiBufferPool struct {
	smallPool  *BufferPool // 小缓冲区池：8KB，用于控制消息、认证数据等小数据包
	mediumPool *BufferPool // 中缓冲区池：128KB，用于普通 HTTP/TCP 数据传输
	largePool  *BufferPool // 大缓冲区池：2MB，用于文件传输、视频流等大数据传输
}

// NewMultiBufferPool 创建一个新的多级缓冲区池。
// 自动初始化小、中、大三级缓冲池，每级池都会预分配 200 个缓冲区。
//
// 返回:
//   - *MultiBufferPool: 初始化完成的多级缓冲池实例
func NewMultiBufferPool() *MultiBufferPool {
	return &MultiBufferPool{
		smallPool:  NewBufferPool(8 * 1024),        // 创建 8KB 小缓冲池
		mediumPool: NewBufferPool(128 * 1024),      // 创建 128KB 中缓冲池
		largePool:  NewBufferPool(2 * 1024 * 1024), // 创建 2MB 大缓冲池
	}
}

// GetBuffer 根据所需大小从合适的缓冲池中获取缓冲区。
// 自动选择能容纳请求大小的最小缓冲区，以优化内存使用效率。
// 选择策略：<=8KB 用小池，<=128KB 用中池，>128KB 用大池。
//
// 参数:
//   - needSize: 需要的缓冲区大小（字节）
//
// 返回:
//   - []byte: 分配的字节切片，大小为所选池的固定大小
//   - *BufferPool: 提供该缓冲区的池实例指针，用于后续通过 Put() 归还
func (m *MultiBufferPool) GetBuffer(needSize int) ([]byte, *BufferPool) {
	if needSize <= 8*1024 {
		// 小数据：从 8KB 池中获取
		buf := m.smallPool.Get()
		return buf, m.smallPool
	} else if needSize <= 128*1024 {
		// 中等数据：从 128KB 池中获取
		buf := m.mediumPool.Get()
		return buf, m.mediumPool
	} else {
		// 大数据：从 2MB 池中获取
		buf := m.largePool.Get()
		return buf, m.largePool
	}
}

// NewBufferPool 创建一个新的缓冲区池。
// 自动预分配 200 个缓冲区以减少初始阶段的内存分配，提升高并发性能。
// 如果指定的 size 小于 8KB，会自动提升到 8KB 以确保最小缓冲区大小。
//
// 参数:
//   - size: 每个缓冲区的大小（字节），最小为 8KB（8192 字节）
//
// 返回:
//   - *BufferPool: 初始化完成的缓冲池实例，已预分配 200 个缓冲区
func NewBufferPool(size int) *BufferPool {
	// 确保最小缓冲区大小为 8KB，避免过小缓冲区影响性能
	if size < 8*1024 {
		size = 8 * 1024 // 提升到最小值 8KB
	}

	// 创建 BufferPool 结构体
	pool := &BufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				// 当池中没有可用缓冲区时，创建新的指定大小的字节切片
				return make([]byte, size)
			},
		},
		size:      size, // 保存缓冲区大小
		preAlloc:  0,    // 预分配数量配置（当前未直接使用）
		allocated: 0,    // 已分配计数器
	}

	// 预分配 50 个缓冲区，减少运行时的内存分配，提升高并发性能
	// 预分配的缓冲区会被放入 sync.Pool 中，供后续 Get() 快速获取
	pool.preAllocate(50)

	return pool // 返回初始化完成的缓冲池
}

// preAllocate 预分配指定数量的缓冲区并放入池中。
// 在初始化时调用，避免运行时频繁分配内存导致的性能抖动。
// 预分配的缓冲区会立即被放入 sync.Pool 中，可供 Get() 直接获取。
//
// 参数:
//   - count: 预分配的缓冲区数量
func (p *BufferPool) preAllocate(count int) {
	// 循环创建指定数量的缓冲区
	for i := 0; i < count; i++ {
		buf := make([]byte, p.size)      // 创建指定大小的字节切片
		p.pool.Put(buf)                  // 放入对象池
		atomic.AddInt64(&p.allocated, 1) // 原子增加已分配计数
	}
}

// SetPreAlloc 设置预分配数量配置（当前实现仅在未分配时触发预分配）。
// 此方法主要用于动态调整预分配策略，但实际预分配只在 allocated==0 时执行。
//
// 参数:
//   - count: 期望的预分配数量
func (p *BufferPool) SetPreAlloc(count int) {
	p.preAlloc = count // 保存配置值

	// 仅在尚未分配任何缓冲区时进行预分配
	if p.allocated == 0 {
		p.preAllocate(count) // 执行预分配
	}
}

// Get 从池中获取一个缓冲区。
// 如果池中有空闲缓冲区，直接返回；否则调用 New 函数创建新的缓冲区。
// 返回的字节切片长度为 size，容量也为 size。
//
// 返回:
//   - []byte: 字节切片，大小为创建池时指定的 size
func (p *BufferPool) Get() []byte {
	// 从 sync.Pool 获取对象，类型断言为字节切片
	return p.pool.Get().([]byte)
}

// Put 将缓冲区归还到池中以便复用。
// 仅当缓冲区容量足够时才回收，并清零内容以确保数据安全。
// 对于大于 128KB 的大缓冲区，跳过清零以提升性能。
//
// 参数:
//   - buf: 要归还的字节切片
func (p *BufferPool) Put(buf []byte) {
	// 仅回收容量足够的缓冲区，防止过小缓冲区被错误回收
	if cap(buf) >= p.size {
		buf = buf[:cap(buf)] // 恢复到完整容量，确保下次使用时有足够空间

		// 对于较小的缓冲区（<=128KB），清零内容以防止数据泄露
		// 大缓冲区跳过清零以提升性能，因为大缓冲区通常用于内部传输
		if p.size <= 128*1024 {
			// 逐字节清零，确保敏感数据不被泄露
			for i := range buf {
				buf[i] = 0
			}
		}

		// 将清零后的缓冲区放回对象池
		p.pool.Put(buf)
	}
	// 如果容量不足，丢弃该缓冲区（由 GC 回收）
}

// ConnManager 连接管理器，跟踪和管理每个 IP 地址的活跃连接数。
// 使用 sync.Map 实现高并发下的线程安全访问，无需额外加锁。
// 支持单 IP 最大连接数限制，超过限制的 IP 将被拒绝新连接。
type ConnManager struct {
	mu           sync.RWMutex // 保留字段（当前未使用，sync.Map 自身已线程安全）
	conns        sync.Map     // IP 地址 -> 连接计数指针的映射，key 为 IP 字符串，value 为 *int32
	maxConnPerIP int          // 单个 IP 允许的最大连接数，0 表示不限制
}

// ShardedConnManager 分片连接管理器，使用 32 个分片减少锁竞争。
// 适用于高并发场景，每个分片独立管理一部分 IP 的连接计数。
// 通过哈希算法将 IP 均匀分布到 32 个分片中，降低热点 IP 的影响。
type ShardedConnManager struct {
	shards     [32]*ConnManager // 32 个独立的连接管理器分片
	shardCount int              // 分片数量，固定为 32
}

// NewShardedConnManager 创建一个新的分片连接管理器。
// 初始化 32 个独立的分片，每个分片有相同的最大连接数限制。
//
// 参数:
//   - maxConnPerIP: 单个 IP 允许的最大连接数，0 表示不限制
//
// 返回:
//   - *ShardedConnManager: 初始化完成的分片连接管理器
func NewShardedConnManager(maxConnPerIP int) *ShardedConnManager {
	sm := &ShardedConnManager{
		shardCount: 32, // 固定 32 个分片
	}
	// 初始化每个分片
	for i := 0; i < sm.shardCount; i++ {
		sm.shards[i] = NewConnManager(maxConnPerIP) // 创建独立的 ConnManager 实例
	}
	return sm
}

// getShard 根据 IP 地址计算对应的分片索引。
// 使用简单的多项式滚动哈希算法将 IP 均匀分布到 32 个分片中。
// 相同 IP 始终映射到同一个分片，保证数据一致性。
//
// 参数:
//   - ip: IP 地址字符串（如 "192.168.1.1"）
//
// 返回:
//   - *ConnManager: 对应的分片实例指针
func (sm *ShardedConnManager) getShard(ip string) *ConnManager {
	hash := 0 // 初始化哈希值
	// 遍历 IP 字符串的每个字符，计算哈希值
	for _, c := range ip {
		hash = hash*31 + int(c) // 乘以质数 31 并加上字符值
		if hash < 0 {
			hash = -hash // 处理溢出导致的负数
		}
	}
	// 对分片数量取模，得到分片索引（0-31）
	return sm.shards[hash%sm.shardCount]
}

// AddConn 向指定分片添加一个连接（增加 IP 的连接计数）。
// 委托给对应的分片处理，实现负载均衡。
//
// 参数:
//   - ip: 客户端 IP 地址
//
// 返回:
//   - bool: 是否成功添加，false 表示超过限制
func (sm *ShardedConnManager) AddConn(ip string) bool {
	return sm.getShard(ip).AddConn(ip) // 委托给对应分片
}

// RemoveConn 从指定分片移除一个连接（减少 IP 的连接计数）。
// 委托给对应的分片处理。
//
// 参数:
//   - ip: 客户端 IP 地址
func (sm *ShardedConnManager) RemoveConn(ip string) {
	sm.getShard(ip).RemoveConn(ip) // 委托给对应分片
}

// GetConnCount 获取指定 IP 在当前分片中的连接数。
// 委托给对应的分片处理。
//
// 参数:
//   - ip: 客户端 IP 地址
//
// 返回:
//   - int: 当前连接数
func (sm *ShardedConnManager) GetConnCount(ip string) int {
	return sm.getShard(ip).GetConnCount(ip) // 委托给对应分片
}

// NewConnManager 创建一个新的连接管理器。
// 使用 sync.Map 存储 IP 到连接计数的映射，支持高并发访问。
//
// 参数:
//   - maxConnPerIP: 单个 IP 允许的最大连接数，0 表示不限制
//
// 返回:
//   - *ConnManager: 初始化完成的连接管理器
func NewConnManager(maxConnPerIP int) *ConnManager {
	return &ConnManager{
		conns:        sync.Map{},   // 初始化空的 sync.Map
		maxConnPerIP: maxConnPerIP, // 保存最大连接数限制
	}
}

// AddConn 添加一个来自指定 IP 的连接。
// 使用原子操作（CAS 循环）确保高并发下的线程安全。
// 如果当前连接数已达到上限，则拒绝新连接。
//
// 参数:
//   - ip: 客户端 IP 地址
//
// 返回:
//   - bool: 是否成功添加，false 表示超过限制
func (m *ConnManager) AddConn(ip string) bool {
	// 如果没有限制（maxConnPerIP <= 0），始终允许连接
	if m.maxConnPerIP <= 0 {
		return true
	}

	// 获取或创建该 IP 的计数器指针
	// LoadOrStore: 如果 key 存在则加载，否则存储新值并返回
	val, _ := m.conns.LoadOrStore(ip, new(int32))
	countPtr := val.(*int32) // 类型断言为 int32 指针

	// 使用 CAS（Compare-And-Swap）循环原子地增加计数
	for {
		current := atomic.LoadInt32(countPtr) // 原子加载当前计数
		// 检查是否超过限制
		if current >= int32(m.maxConnPerIP) {
			return false // 已达上限，拒绝新连接
		}
		// 尝试原子地将计数从 current 增加到 current+1
		if atomic.CompareAndSwapInt32(countPtr, current, current+1) {
			return true // CAS 成功，连接添加成功
		}
		// CAS 失败（有其他 goroutine 修改了计数），重试
	}
}

// RemoveConn 移除一个来自指定 IP 的连接。
// 使用原子操作（CAS 循环）确保高并发下的线程安全。
// 当计数降为 0 时，从映射中删除该 IP 的条目以释放内存。
//
// 参数:
//   - ip: 客户端 IP 地址
func (m *ConnManager) RemoveConn(ip string) {
	// 如果没有限制，无需操作
	if m.maxConnPerIP <= 0 {
		return
	}

	// 加载该 IP 的计数器
	val, exists := m.conns.Load(ip)
	if !exists {
		return // IP 不存在，无需操作
	}
	countPtr := val.(*int32) // 类型断言为 int32 指针

	// 使用 CAS 循环原子地减少计数
	for {
		current := atomic.LoadInt32(countPtr) // 原子加载当前计数
		// 防止下溢：如果计数已为 0 或更小
		if current <= 0 {
			m.conns.Delete(ip) // 删除该 IP 的条目
			return
		}
		// 尝试原子地将计数从 current 减少到 current-1
		if atomic.CompareAndSwapInt32(countPtr, current, current-1) {
			// 如果计数归零，删除条目以释放内存
			if current-1 <= 0 {
				m.conns.Delete(ip)
			}
			return // CAS 成功，操作完成
		}
		// CAS 失败（有其他 goroutine 修改了计数），重试
	}
}

// GetConnCount 获取指定 IP 的当前连接数。
// 使用原子加载确保读取到最新的值。
//
// 参数:
//   - ip: 客户端 IP 地址
//
// 返回:
//   - int: 当前活跃连接数，0 表示无连接或 IP 不存在
func (m *ConnManager) GetConnCount(ip string) int {
	// 从 sync.Map 中加载该 IP 的计数器
	val, exists := m.conns.Load(ip)
	if !exists {
		return 0 // IP 不存在，返回 0
	}
	// 原子加载计数值并转换为 int
	return int(atomic.LoadInt32(val.(*int32)))
}
