// Package main 实现 SOCKS5 代理服务器的资源池管理模块。
// 包括工作协程池（WorkerPool）、缓冲区池（BufferPool）、多级缓冲池（MultiBufferPool）
// 和连接管理器（ConnManager），用于高效复用资源并控制并发。
package main

import (
	"context"
	"sync"
	"sync/atomic"
)

// WorkerPool 工作协程池，用于控制和复用 goroutine。
// 当配置了最大工作协程数时，通过信号量限制并发数量；
// 否则为无限制模式，每个任务启动一个新的 goroutine。
type WorkerPool struct {
	submitted int64              // 已提交的任务计数（原子操作）
	workers   int                // 最大工作协程数，0 表示无限制
	semaphore chan struct{}      // 信号量通道，用于限制并发
	wg        sync.WaitGroup     // 等待组，用于优雅关闭
	ctx       context.Context    // 上下文，用于取消任务
	cancel    context.CancelFunc // 取消函数
}

// NewWorkerPool 创建一个新的工作协程池。
//
// 参数:
//   - workers: 最大工作协程数，0 表示不限制并发数量
//
// 返回:
//   - *WorkerPool: 初始化后的工作池实例
func NewWorkerPool(workers int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	pool := &WorkerPool{
		workers: workers,
		ctx:     ctx,
		cancel:  cancel,
	}

	// 仅在有并发限制时创建信号量通道
	if workers > 0 {
		pool.semaphore = make(chan struct{}, workers)
	}

	return pool
}

// Submit 向工作池提交一个任务函数。
// 如果工作池已停止或上下文已取消，则拒绝提交。
//
// 参数:
//   - task: 要执行的任务函数
//
// 返回:
//   - bool: 提交是否成功，false 表示工作池已停止
func (p *WorkerPool) Submit(task func()) bool {
	// 检查工作池是否已停止
	if p.ctx.Err() != nil {
		return false
	}

	// 有限制模式：使用信号量控制并发
	if p.workers > 0 {
		select {
		case p.semaphore <- struct{}{}:
			// 获取信号量，启动新协程执行任务
			p.wg.Add(1)
			atomic.AddInt64(&p.submitted, 1)

			go func() {
				defer func() {
					<-p.semaphore // 释放信号量
					p.wg.Done()
				}()
				task()
			}()
			return true

		case <-p.ctx.Done():
			// 上下文已取消，拒绝提交
			return false
		}
	} else {
		// 无限制模式：直接启动新协程
		p.wg.Add(1)
		atomic.AddInt64(&p.submitted, 1)

		go func() {
			defer p.wg.Done()
			task()
		}()
		return true
	}
}

// Stop 停止工作池，等待所有正在执行的任务完成。
// 调用后会取消上下文，拒绝新的任务提交，并等待现有任务结束。
func (p *WorkerPool) Stop() {
	p.cancel()
	p.wg.Wait()
}

// BufferPool 缓冲区池，基于 sync.Pool 实现字节切片的高效复用。
// 通过预分配和回收机制减少内存分配和 GC 压力。
type BufferPool struct {
	allocated int64     // 已分配的缓冲区数量（原子操作）
	pool      sync.Pool // 底层对象池
	size      int       // 每个缓冲区的大小（字节）
	preAlloc  int       // 预分配的缓冲区数量
}

// MultiBufferPool 多级缓冲区池，根据请求大小自动选择合适的池。
// 分为小（8KB）、中（128KB）、大（2MB）三级，优化不同场景下的内存使用。
type MultiBufferPool struct {
	smallPool  *BufferPool // 小缓冲区池：8KB，用于控制消息等小数据
	mediumPool *BufferPool // 中缓冲区池：128KB，用于普通数据传输
	largePool  *BufferPool // 大缓冲区池：2MB，用于高速数据传输
}

// NewMultiBufferPool 创建一个新的多级缓冲区池。
// 自动初始化小、中、大三级缓冲池。
//
// 返回:
//   - *MultiBufferPool: 初始化后的多级缓冲池实例
func NewMultiBufferPool() *MultiBufferPool {
	return &MultiBufferPool{
		smallPool:  NewBufferPool(8 * 1024),        // 8KB
		mediumPool: NewBufferPool(128 * 1024),      // 128KB
		largePool:  NewBufferPool(2 * 1024 * 1024), // 2MB
	}
}

// GetBuffer 根据所需大小从合适的缓冲池中获取缓冲区。
// 自动选择能容纳请求大小的最小缓冲区，以优化内存使用。
//
// 参数:
//   - needSize: 需要的缓冲区大小（字节）
//
// 返回:
//   - []byte: 分配的字节切片
//   - *BufferPool: 提供该缓冲区的池实例，用于后续归还
func (m *MultiBufferPool) GetBuffer(needSize int) ([]byte, *BufferPool) {
	if needSize <= 8*1024 {
		buf := m.smallPool.Get()
		return buf, m.smallPool
	} else if needSize <= 128*1024 {
		buf := m.mediumPool.Get()
		return buf, m.mediumPool
	} else {
		buf := m.largePool.Get()
		return buf, m.largePool
	}
}

// NewBufferPool 创建一个新的缓冲区池。
// 自动预分配 100 个缓冲区以减少初始阶段的内存分配。
//
// 参数:
//   - size: 每个缓冲区的大小（字节），最小为 8KB
//
// 返回:
//   - *BufferPool: 初始化后的缓冲池实例
func NewBufferPool(size int) *BufferPool {
	// 确保最小缓冲区大小
	if size < 8*1024 {
		size = 8 * 1024
	}

	pool := &BufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, size)
			},
		},
		size:      size,
		preAlloc:  0,
		allocated: 0,
	}

	// 预分配 100 个缓冲区，减少运行时的内存分配
	pool.preAllocate(100)

	return pool
}

// preAllocate 预分配指定数量的缓冲区并放入池中。
// 在初始化时调用，避免运行时频繁分配内存。
//
// 参数:
//   - count: 预分配的缓冲区数量
func (p *BufferPool) preAllocate(count int) {
	for i := 0; i < count; i++ {
		buf := make([]byte, p.size)
		p.pool.Put(buf)
		atomic.AddInt64(&p.allocated, 1)
	}
}

// SetPreAlloc 设置预分配数量（当前实现仅在未分配时触发预分配）。
//
// 参数:
//   - count: 期望的预分配数量
func (p *BufferPool) SetPreAlloc(count int) {
	p.preAlloc = count

	// 仅在尚未分配时进行预分配
	if p.allocated == 0 {
		p.preAllocate(count)
	}
}

// Get 从池中获取一个缓冲区。
// 如果池为空，会自动创建新的缓冲区。
//
// 返回:
//   - []byte: 字节切片，大小为创建池时指定的 size
func (p *BufferPool) Get() []byte {
	return p.pool.Get().([]byte)
}

// Put 将缓冲区归还到池中以便复用。
// 仅当缓冲区容量足够时才回收，并清零内容以确保安全。
//
// 参数:
//   - buf: 要归还的字节切片
func (p *BufferPool) Put(buf []byte) {
	// 仅回收容量足够的缓冲区
	if cap(buf) >= p.size {
		buf = buf[:cap(buf)] // 恢复到完整容量

		// 对于较小的缓冲区，清零内容以防止数据泄露
		// 大缓冲区跳过清零以提升性能
		if p.size <= 128*1024 {
			for i := range buf {
				buf[i] = 0
			}
		}

		p.pool.Put(buf)
	}
}

// ConnManager 连接管理器，跟踪和管理每个 IP 地址的活跃连接数。
// 使用 sync.Map 实现高并发下的线程安全访问。
type ConnManager struct {
	mu           sync.RWMutex // 保留字段（当前未使用）
	conns        sync.Map     // IP 地址 -> 连接计数的映射（原子 int32）
	maxConnPerIP int          // 单个 IP 允许的最大连接数，0 表示不限制
}

// ShardedConnManager 分片连接管理器，使用 32 个分片减少锁竞争。
// 适用于高并发场景，每个分片独立管理一部分 IP 的连接计数。
type ShardedConnManager struct {
	shards     [32]*ConnManager // 32 个独立的连接管理器分片
	shardCount int              // 分片数量，固定为 32
}

// NewShardedConnManager 创建一个新的分片连接管理器。
// 初始化 32 个独立的分片，每个分片有相同的最大连接数限制。
//
// 参数:
//   - maxConnPerIP: 单个 IP 允许的最大连接数
//
// 返回:
//   - *ShardedConnManager: 初始化后的分片连接管理器
func NewShardedConnManager(maxConnPerIP int) *ShardedConnManager {
	sm := &ShardedConnManager{
		shardCount: 32,
	}
	for i := 0; i < sm.shardCount; i++ {
		sm.shards[i] = NewConnManager(maxConnPerIP)
	}
	return sm
}

// getShard 根据 IP 地址计算对应的分片索引。
// 使用简单的哈希算法将 IP 均匀分布到 32 个分片中。
//
// 参数:
//   - ip: IP 地址字符串
//
// 返回:
//   - *ConnManager: 对应的分片实例
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

// AddConn 向指定分片添加一个连接（增加 IP 的连接计数）。
//
// 参数:
//   - ip: 客户端 IP 地址
//
// 返回:
//   - bool: 是否成功添加，false 表示超过限制
func (sm *ShardedConnManager) AddConn(ip string) bool {
	return sm.getShard(ip).AddConn(ip)
}

// RemoveConn 从指定分片移除一个连接（减少 IP 的连接计数）。
//
// 参数:
//   - ip: 客户端 IP 地址
func (sm *ShardedConnManager) RemoveConn(ip string) {
	sm.getShard(ip).RemoveConn(ip)
}

// GetConnCount 获取指定 IP 在当前分片中的连接数。
//
// 参数:
//   - ip: 客户端 IP 地址
//
// 返回:
//   - int: 当前连接数
func (sm *ShardedConnManager) GetConnCount(ip string) int {
	return sm.getShard(ip).GetConnCount(ip)
}

// NewConnManager 创建一个新的连接管理器。
//
// 参数:
//   - maxConnPerIP: 单个 IP 允许的最大连接数，0 表示不限制
//
// 返回:
//   - *ConnManager: 初始化后的连接管理器
func NewConnManager(maxConnPerIP int) *ConnManager {
	return &ConnManager{
		conns:        sync.Map{},
		maxConnPerIP: maxConnPerIP,
	}
}

// AddConn 添加一个来自指定 IP 的连接。
// 使用原子操作确保高并发下的线程安全。
// 如果当前连接数已达到上限，则拒绝新连接。
//
// 参数:
//   - ip: 客户端 IP 地址
//
// 返回:
//   - bool: 是否成功添加，false 表示超过限制
func (m *ConnManager) AddConn(ip string) bool {
	// 如果没有限制，始终允许
	if m.maxConnPerIP <= 0 {
		return true
	}

	// 获取或创建该 IP 的计数器指针
	val, _ := m.conns.LoadOrStore(ip, new(int32))
	countPtr := val.(*int32)

	// 使用 CAS 循环原子地增加计数
	for {
		current := atomic.LoadInt32(countPtr)
		// 检查是否超过限制
		if current >= int32(m.maxConnPerIP) {
			return false
		}
		// 尝试原子增加计数
		if atomic.CompareAndSwapInt32(countPtr, current, current+1) {
			return true
		}
		// CAS 失败，重试
	}
}

// RemoveConn 移除一个来自指定 IP 的连接。
// 当计数降为 0 时，从映射中删除该 IP 的条目以释放内存。
//
// 参数:
//   - ip: 客户端 IP 地址
func (m *ConnManager) RemoveConn(ip string) {
	// 如果没有限制，无需操作
	if m.maxConnPerIP <= 0 {
		return
	}

	val, exists := m.conns.Load(ip)
	if !exists {
		return
	}
	countPtr := val.(*int32)

	// 使用 CAS 循环原子地减少计数
	for {
		current := atomic.LoadInt32(countPtr)
		// 防止下溢
		if current <= 0 {
			m.conns.Delete(ip)
			return
		}
		// 尝试原子减少计数
		if atomic.CompareAndSwapInt32(countPtr, current, current-1) {
			// 如果计数归零，删除条目
			if current-1 <= 0 {
				m.conns.Delete(ip)
			}
			return
		}
		// CAS 失败，重试
	}
}

// GetConnCount 获取指定 IP 的当前连接数。
//
// 参数:
//   - ip: 客户端 IP 地址
//
// 返回:
//   - int: 当前活跃连接数
func (m *ConnManager) GetConnCount(ip string) int {
	val, exists := m.conns.Load(ip)
	if !exists {
		return 0
	}
	return int(atomic.LoadInt32(val.(*int32)))
}
