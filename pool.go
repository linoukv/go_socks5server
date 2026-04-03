// =============================================================================
// 文件名：pool.go
// 描述：工作协程池和缓冲池管理模块
// 功能：
//   - WorkerPool: 限制并发数量，避免资源耗尽
//   - BufferPool: 字节缓冲区复用，减少 GC 压力
//   - MultiBufferPool: 多级缓冲池（小/中/大）
//   - ConnManager: IP 连接数管理（防单 IP 占用过多资源）
//   - ShardedConnManager: 分片连接管理器（超高并发优化）
// 性能优化：万兆网络优化版（无锁设计、原子操作、预分配策略）
// =============================================================================

package main

import (
	"context"     // 上下文控制包（用于优雅取消）
	"sync"        // 同步原语包（WaitGroup、Mutex、Pool）
	"sync/atomic" // 原子操作包（无锁并发计数）
)

// =============================================================================
// WorkerPool - 工作协程池
//
// 用途：管理和调度工作 goroutine，控制并发数量
// 两种模式：
//  1. 有限制模式 (workers > 0): 使用信号量通道控制最大并发数
//  2. 无限制模式 (workers = 0): 依赖 GOMAXPROCS 自动调度（推荐，性能最佳）
//
// 内存对齐优化：
// - int64 字段 (submitted) 必须放在结构体开头（8 字节对齐要求）
// - 避免在 32 位系统上发生 panic
// =============================================================================
type WorkerPool struct {
	// --- 统计字段（原子操作）---
	// 已提交任务总数：从创建至今提交的任务数（只增不减）
	// 注意：必须放在结构体开头以保证 8 字节对齐（32 位系统要求）
	submitted int64

	// --- 配置字段 ---
	// 最大并发工作数：0 表示无限制，由 GOMAXPROCS 自动决定
	workers int

	// --- 并发控制 ---
	// 信号量通道：仅在 workers>0 时使用，控制最大并发数
	// 缓冲容量 = workers，每个元素代表一个并发许可
	semaphore chan struct{}

	// 等待组：等待所有正在执行的任务完成（用于优雅关闭）
	wg sync.WaitGroup

	// 上下文：传递取消信号给所有工作 goroutine
	ctx context.Context
	// 取消函数：触发上下文取消
	cancel context.CancelFunc
}

// NewWorkerPool 创建新的工作协程池（万兆优化版）
//
// 参数 workers: 最大并发工作数
//   - > 0: 使用信号量限制并发数
//   - = 0: 无限制模式，依赖 GOMAXPROCS 自动调度（推荐，性能最佳）
//
// 返回：*WorkerPool - 初始化后的工作池对象
//
// 工作流程：
// 1. 创建可取消的上下文（用于优雅关闭）
// 2. 根据 workers 参数决定是否创建信号量通道
// 3. 返回工作池实例
func NewWorkerPool(workers int) *WorkerPool {
	// 创建可取消的上下文
	// context.Background() 是根上下文，WithCancel 创建其子上下文
	ctx, cancel := context.WithCancel(context.Background())

	pool := &WorkerPool{
		workers: workers, // 保存配置的 worker 数量
		ctx:     ctx,     // 保存上下文
		cancel:  cancel,  // 保存取消函数
	}

	// 万兆优化：根据配置选择工作模式
	if workers > 0 {
		// === 有限制模式 ===
		// 创建缓冲通道作为信号量
		// 容量 = workers，表示最多允许 workers 个 goroutine 同时执行
		pool.semaphore = make(chan struct{}, workers)
	} else {
		// === 无限制模式（推荐）===
		// 不创建信号量，完全依赖 Go 运行时调度
		// GOMAXPROCS 会自动决定最优的并行 goroutine 数量
		// 这是性能最佳的模式，适合超高并发场景（50 万 + 连接）
	}

	return pool
}

// Submit 提交任务到工作池，返回是否提交成功
//
// 参数 task: 要执行的函数（闭包）
// 返回：bool - true=提交成功，false=提交失败（池已停止或上下文已取消）
//
// 两种执行路径：
// 1. 有限制模式 (workers > 0):
//   - 尝试获取信号量（向通道发送空结构体）
//   - 如果通道已满，阻塞等待
//   - 获取成功后启动 goroutine 执行任务
//   - 执行完成后释放信号量
//
// 2. 无限制模式 (workers = 0):
//   - 直接启动 goroutine 执行任务
//   - 无需等待信号量，性能最优
//
// 并发安全：
// - 使用原子操作更新 submitted 计数
// - 使用 select 避免阻塞
func (p *WorkerPool) Submit(task func()) bool {
	// === 快速路径：检查上下文是否已取消 ===
	// 无锁检查，立即返回失败
	if p.ctx.Err() != nil {
		return false // 上下文已取消，拒绝提交
	}

	if p.workers > 0 {
		// === 有限制模式：使用信号量控制并发 ===
		select {
		case p.semaphore <- struct{}{}:
			// 成功获取信号量（通道有空位）

			// 增加等待组计数（必须在启动 goroutine 前调用）
			p.wg.Add(1)

			// 原子增加已提交任务数（统计用）
			atomic.AddInt64(&p.submitted, 1)

			// 启动 goroutine 执行任务
			go func() {
				defer func() {
					<-p.semaphore // 释放信号量（从通道读取一个元素）
					p.wg.Done()   // 减少等待组计数
				}()
				task() // 执行用户任务
			}()
			return true

		case <-p.ctx.Done():
			// 等待信号量过程中被取消
			return false
		}
	} else {
		// === 无限制模式：直接启动 goroutine ===

		// 增加等待组计数
		p.wg.Add(1)

		// 原子增加已提交任务数
		atomic.AddInt64(&p.submitted, 1)

		// 启动 goroutine
		go func() {
			defer p.wg.Done() // 任务完成后减少等待组
			task()            // 执行用户任务
		}()
		return true
	}
}

// Stop 停止工作池，取消所有待处理的任务
//
// 工作流程：
// 1. 调用 cancel() 取消上下文
//   - 所有正在等待信号量的 Submit 会立即返回 false
//   - ctx.Err() 检查会失败，阻止新任务提交
//
// 2. 调用 wg.Wait() 等待所有任务完成
//   - 阻塞直到所有已启动的 goroutine 执行完毕
//
// 注意：
// - Stop 是阻塞调用，会等待所有任务完成
// - 已经启动的 goroutine 会继续执行完成
// - 不会强制终止正在运行的任务
func (p *WorkerPool) Stop() {
	p.cancel()  // 第一步：取消上下文（阻止新任务）
	p.wg.Wait() // 第二步：等待所有任务完成（优雅关闭）
}

// =============================================================================
// BufferPool - 字节缓冲区池
//
// 用途：复用字节切片，减少内存分配和 GC 压力
// 原理：使用 sync.Pool 对象池模式
//
// 内存对齐优化：
// - int64 字段 (allocated) 必须放在结构体开头（8 字节对齐要求）
// - 避免在 32 位系统上发生 panic
//
// 预分配策略：
// - 启动时预分配 100 个缓冲区
// - 减少运行时的内存分配开销
// - 提升性能（特别是高并发场景）
// =============================================================================
type BufferPool struct {
	// --- 统计字段（原子操作）---
	// 已分配缓冲区数量：从池中取出的总次数（只增不减）
	// 注意：必须放在结构体开头以保证 8 字节对齐
	allocated int64

	// --- 核心组件 ---
	// 底层对象池：Go 标准库提供的 sync.Pool
	// 特性：
	// - 自动回收：GC 时会清空池中对象
	// - 并发安全：多 goroutine 访问无需加锁
	// - 懒加载：池为空时调用 New 函数创建
	pool sync.Pool

	// --- 配置字段 ---
	// 缓冲区大小：每个切片的容量（字节）
	// 示例：8KB, 128KB, 2MB
	size int

	// 预分配数量：启动时预先创建的缓冲区数量
	// 默认值：100（可根据性能需求调整）
	preAlloc int
}

// =============================================================================
// MultiBufferPool - 多级缓冲池管理器
//
// 用途：根据所需大小自动选择合适的缓冲池
// 分级策略：
//   - 小缓冲池：8KB（用于控制数据、小响应）
//   - 中缓冲池：128KB（用于普通数据传输）
//   - 大缓冲池：2MB（用于大数据传输、高吞吐场景）
//
// 优势：
// - 避免小数据使用大缓冲区的浪费
// - 避免大数据频繁分配小缓冲区的开销
// - 提高内存利用率
// =============================================================================
type MultiBufferPool struct {
	smallPool  *BufferPool // 小缓冲区池：8KB
	mediumPool *BufferPool // 中缓冲区池：128KB
	largePool  *BufferPool // 大缓冲区池：2MB
}

// NewMultiBufferPool 创建多级缓冲池（万兆优化版）
//
// 返回：*MultiBufferPool - 包含三个缓冲池的管理器
//
// 分级策略：
// - smallPool: 8KB (8 * 1024 字节) - 用于控制数据、小响应包
// - mediumPool: 128KB (128 * 1024 字节) - 用于普通数据传输
// - largePool: 2MB (2 * 1024 * 1024 字节) - 用于大数据传输、高吞吐场景
//
// 使用示例：
//
//	multiPool := NewMultiBufferPool()
//	buf, pool := multiPool.GetBuffer(50 * 1024) // 需要 50KB，返回中缓冲区
//	defer pool.Put(buf) // 使用完归还
func NewMultiBufferPool() *MultiBufferPool {
	return &MultiBufferPool{
		smallPool:  NewBufferPool(8 * 1024),        // 8KB 小缓冲池
		mediumPool: NewBufferPool(128 * 1024),      // 128KB 中缓冲池
		largePool:  NewBufferPool(2 * 1024 * 1024), // 2MB 大缓冲池
	}
}

// GetBuffer 根据所需大小获取合适的缓冲区
//
// 参数 needSize: 需要的缓冲区大小（字节）
// 返回：([]byte, *BufferPool) - 缓冲区和对应的缓冲池对象
//
// 选择策略：
// - needSize <= 8KB:  使用小缓冲池（8KB）
// - needSize <= 128KB: 使用中缓冲池（128KB）
// - needSize > 128KB:  使用大缓冲池（2MB）
//
// 注意：
// - 返回的缓冲区长度 = 容量 = 缓冲池大小
// - 使用后必须调用对应缓冲池的 Put() 方法归还
// - 第二个返回值用于方便归还操作
func (m *MultiBufferPool) GetBuffer(needSize int) ([]byte, *BufferPool) {
	if needSize <= 8*1024 {
		// 小数据：使用 8KB 缓冲池
		buf := m.smallPool.Get()
		return buf, m.smallPool
	} else if needSize <= 128*1024 {
		// 中等数据：使用 128KB 缓冲池
		buf := m.mediumPool.Get()
		return buf, m.mediumPool
	} else {
		// 大数据：使用 2MB 缓冲池
		buf := m.largePool.Get()
		return buf, m.largePool
	}
}

// NewBufferPool 创建指定大小的缓冲区池（万兆极致优化版）
//
// 参数 size: 每个缓冲区的大小（字节）
// 返回：*BufferPool - 初始化后的缓冲池对象
//
// 特性：
// 1. 最小大小限制：如果 size < 8KB，自动调整为 8KB
// 2. 预分配策略：启动时预分配 100 个缓冲区
// 3. 懒加载：池为空时自动创建新缓冲区
// 4. 并发安全：sync.Pool 自动处理并发访问
//
// 性能优化：
// - 预分配减少运行时内存分配开销
// - sync.Pool 自动复用对象，减少 GC 压力
// - 适合高并发场景（每秒数万次分配）
func NewBufferPool(size int) *BufferPool {
	// 确保最小大小为 8KB
	// 过小的缓冲区没有实际意义，反而增加管理开销
	if size < 8*1024 {
		size = 8 * 1024 // 最小 8KB
	}

	pool := &BufferPool{
		// 初始化 sync.Pool
		// New 函数在池为空时自动调用，创建新缓冲区
		pool: sync.Pool{
			New: func() interface{} {
				// 创建指定大小的字节切片
				// make([]byte, size) 返回长度和容量都为 size 的切片
				return make([]byte, size)
			},
		},
		// 保存配置参数
		size:      size, // 缓冲区大小
		preAlloc:  0,    // 预分配数量（稍后设置）
		allocated: 0,    // 已分配计数初始为 0
	}

	// 万兆优化：预分配 100 个缓冲区
	// 目的：减少启动初期的内存分配开销
	// 代价：增加启动时的内存占用（100 * size 字节）
	// 适用场景：高并发、频繁分配的场景
	pool.preAllocate(100)

	return pool
}

// preAllocate 预分配缓冲区（性能优化）
//
// 参数 count: 要预分配的缓冲区数量
//
// 工作原理：
// 1. 循环创建指定数量的缓冲区
// 2. 调用 pool.Put() 放入对象池
// 3. 原子增加 allocated 计数
//
// 性能考虑：
// - 优点：减少运行时内存分配，提升性能
// - 缺点：增加启动时间和内存占用
// - 适用：高并发、频繁分配的场景
func (p *BufferPool) preAllocate(count int) {
	for i := 0; i < count; i++ {
		// 创建新的缓冲区
		buf := make([]byte, p.size)

		// 放入对象池（等待被复用）
		p.pool.Put(buf)

		// 原子增加已分配计数
		atomic.AddInt64(&p.allocated, 1)
	}
}

// SetPreAlloc 设置预分配数量（在启动时调用）
//
// 参数 count: 要预分配的缓冲区数量
//
// 用途：允许外部调用者自定义预分配数量
// 调用时机：应该在创建缓冲池后立即调用
//
// 注意：
// - 如果已经执行过预分配（allocated > 0），则不会重复执行
// - 这是为了防止多次调用导致重复分配
func (p *BufferPool) SetPreAlloc(count int) {
	p.preAlloc = count // 保存配置

	// 如果还未预分配，立即执行
	if p.allocated == 0 {
		p.preAllocate(count)
	}
}

// Get 从池中获取一个缓冲区
//
// 返回：[]byte - 字节切片（长度和容量都等于 size）
//
// 工作原理：
// 1. 尝试从 sync.Pool 获取空闲缓冲区
// 2. 如果池为空，调用 New 函数创建新缓冲区
// 3. 返回获取到的缓冲区
//
// 并发安全：sync.Pool 自动处理并发访问
//
// 使用示例：
//
//	buf := bufferPool.Get()
//	defer bufferPool.Put(buf) // 使用后归还
func (p *BufferPool) Get() []byte {
	// 从 sync.Pool 获取对象
	// Get() 返回 interface{}，需要类型断言为 []byte
	return p.pool.Get().([]byte)
}

// Put 将缓冲区归还到池中，以便复用（万兆优化版：智能回收）
//
// 参数 buf: 要归还的字节切片
//
// 智能回收策略：
// 1. 容量检查：只回收容量 >= size 的缓冲区
//   - 使用 cap 而不是 len（切片可能被缩小但底层数组不变）
//   - 防止小缓冲区污染大缓冲池
//
// 2. 重置长度：buf = buf[:cap(buf)]
//   - 恢复为完整大小，确保下次使用时是正确的
//   - 保持容量不变，充分利用底层数组
//
// 3. 数据清零（安全考虑）：
//   - 小型缓冲区（<=128KB）：全部清零
//     目的：防止敏感数据泄露（如密码、密钥）
//   - 大型缓冲区（>128KB）：跳过清零
//     目的：减少 CPU 开销，提升性能
//
// 4. 不符合条件的处理：
//   - 直接丢弃，不归还到池中
//   - Go 的 GC 会自动回收这些内存
//
// 并发安全：sync.Pool 自动处理并发访问
func (p *BufferPool) Put(buf []byte) {
	// 智能回收：只回收容量足够的缓冲区
	if cap(buf) >= p.size {
		// 重置长度为容量（充分利用底层数组）
		buf = buf[:cap(buf)]

		// 数据清零（安全考虑，防止数据泄露）
		// 性能优化：仅对小型缓冲区清零，大型缓冲区跳过以减少 CPU 开销
		if p.size <= 128*1024 {
			// 小型缓冲区：逐字节清零
			for i := range buf {
				buf[i] = 0
			}
		}
		// 大型缓冲区：跳过清零，直接归还

		// 归还到对象池
		p.pool.Put(buf)
	}
	// 不符合条件的缓冲区会被 GC 自动回收，无需额外处理
}

// ConnManager 连接管理器，使用 sync.Map 优化并发性能（万兆极致优化版）
// 使用分片 map 减少锁竞争，适合超高并发场景
type ConnManager struct {
	mu           sync.RWMutex // 读写锁（实际未使用）
	conns        sync.Map     // IP -> 连接数 (*int32 原子计数)
	maxConnPerIP int          // 每个 IP 的最大连接数限制
}

// ShardedConnManager 分片连接管理器（万兆极致性能版）
// 使用 32 个分片 map 减少锁竞争，适合 50 万 + 并发连接
type ShardedConnManager struct {
	shards     [32]*ConnManager // 32 个分片
	shardCount int              // 分片数量
}

// NewShardedConnManager 创建分片连接管理器（万兆优化）
func NewShardedConnManager(maxConnPerIP int) *ShardedConnManager {
	sm := &ShardedConnManager{
		shardCount: 32,
	}
	for i := 0; i < sm.shardCount; i++ {
		sm.shards[i] = NewConnManager(maxConnPerIP)
	}
	return sm
}

// getShard 根据 IP 获取对应的分片（使用 hash 取模）
func (sm *ShardedConnManager) getShard(ip string) *ConnManager {
	hash := 0
	for _, c := range ip {
		hash = hash*31 + int(c)
		if hash < 0 {
			hash = -hash
		}
	}
	return sm.shards[hash%sm.shardCount]
}

// AddConn 添加连接（分片版本）
func (sm *ShardedConnManager) AddConn(ip string) bool {
	return sm.getShard(ip).AddConn(ip)
}

// RemoveConn 移除连接（分片版本）
func (sm *ShardedConnManager) RemoveConn(ip string) {
	sm.getShard(ip).RemoveConn(ip)
}

// GetConnCount 获取连接数（分片版本）
func (sm *ShardedConnManager) GetConnCount(ip string) int {
	return sm.getShard(ip).GetConnCount(ip)
}

// NewConnManager 创建连接管理器
func NewConnManager(maxConnPerIP int) *ConnManager {
	return &ConnManager{
		conns:        sync.Map{},   // 初始化 sync.Map
		maxConnPerIP: maxConnPerIP, // 设置限制
	}
}

// AddConn 添加连接，如果超过限制则返回 false
func (m *ConnManager) AddConn(ip string) bool {
	// 如果限制为 0 或负数，表示无限制
	if m.maxConnPerIP <= 0 {
		return true
	}

	// 使用 atomic 操作避免全局锁
	// LoadOrStore: 如果存在则返回现有值，否则存储新值并返回
	val, _ := m.conns.LoadOrStore(ip, new(int32))
	countPtr := val.(*int32)

	// CAS 循环：尝试增加计数
	for {
		current := atomic.LoadInt32(countPtr)
		if current >= int32(m.maxConnPerIP) {
			return false // 已达到限制
		}
		// CompareAndSwap: 如果当前值等于 expected 则更新为 desired
		if atomic.CompareAndSwapInt32(countPtr, current, current+1) {
			return true // 成功增加
		}
		// 如果 CAS 失败，重试
	}
}

// RemoveConn 移除连接，减少对应 IP 的连接计数
func (m *ConnManager) RemoveConn(ip string) {
	// 如果无限制，直接返回
	if m.maxConnPerIP <= 0 {
		return
	}

	// 加载该 IP 的计数
	val, exists := m.conns.Load(ip)
	if !exists {
		return // 不存在则无需减少
	}
	countPtr := val.(*int32)

	// CAS 循环：尝试减少计数
	for {
		current := atomic.LoadInt32(countPtr)
		if current <= 0 {
			// 连接数为 0，删除该 IP 记录
			m.conns.Delete(ip)
			return
		}
		if atomic.CompareAndSwapInt32(countPtr, current, current-1) {
			return // 成功减少
		}
	}
}

// GetConnCount 获取指定 IP 的当前连接数
// 参数 ip: 要查询的 IP 地址
// 返回：该 IP 的当前连接数
func (m *ConnManager) GetConnCount(ip string) int {
	val, exists := m.conns.Load(ip)
	if !exists {
		return 0 // 不存在则返回 0
	}
	return int(atomic.LoadInt32(val.(*int32)))
}
