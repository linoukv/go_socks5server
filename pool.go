package main

import (
	"context"     // 上下文控制
	"sync"        // 同步原语
	"sync/atomic" // 原子操作
)

// WorkerPool 工作协程池，用于限制并发数量，避免资源耗尽（高性能优化版）
type WorkerPool struct {
	submitted int64              // 已提交任务数（原子操作，用于统计）- 必须放在开头保证 8 字节对齐
	workers   int                // 最大并发工作数
	semaphore chan struct{}      // 信号量通道，控制并发数
	wg        sync.WaitGroup     // 等待组，等待所有任务完成
	ctx       context.Context    // 上下文
	cancel    context.CancelFunc // 取消函数
}

// NewWorkerPool 创建新的工作协程池
// workers: 最大并发工作数，0 表示无限制
func NewWorkerPool(workers int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background()) // 创建可取消的上下文

	pool := &WorkerPool{
		workers: workers,
		ctx:     ctx,
		cancel:  cancel,
	}

	// 如果指定了 worker 数量，创建信号量通道
	if workers > 0 {
		pool.semaphore = make(chan struct{}, workers) // 缓冲通道作为信号量
	}

	return pool
}

// Submit 提交任务到工作池，返回是否提交成功（优化版）
func (p *WorkerPool) Submit(task func()) bool {
	// 快速路径：检查上下文是否已取消（无锁检查）
	if p.ctx.Err() != nil {
		return false
	}

	if p.workers > 0 {
		// 使用信号量限制并发数
		select {
		case p.semaphore <- struct{}{}: // 获取信号量
			p.wg.Add(1)
			atomic.AddInt64(&p.submitted, 1) // 统计提交数
			go func() {
				defer func() {
					<-p.semaphore // 释放信号量
					p.wg.Done()
				}()
				task()
			}()
			return true
		case <-p.ctx.Done(): // 等待过程中被取消
			return false
		}
	} else {
		// 无限制模式：直接启动 goroutine（优化版）
		p.wg.Add(1)
		atomic.AddInt64(&p.submitted, 1) // 统计提交数
		go func() {
			defer p.wg.Done()
			task()
		}()
		return true
	}
}

// Stop 停止工作池，取消所有待处理的任务
func (p *WorkerPool) Stop() {
	p.cancel()  // 取消上下文
	p.wg.Wait() // 等待所有正在执行的任务完成
}

// BufferPool 字节缓冲区池，减少 GC 压力，提高性能（极致优化版）
type BufferPool struct {
	pool sync.Pool // 底层 sync.Pool
	size int       // 缓冲区大小
}

// NewBufferPool 创建指定大小的缓冲区池（极致优化版）
func NewBufferPool(size int) *BufferPool {
	// 使用更大的默认缓冲区以提高吞吐量
	if size < 64*1024 {
		size = 64 * 1024 // 最小 64KB
	}
	return &BufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, size) // 创建指定大小的缓冲区
			},
		},
		size: size,
	}
}

// Get 从池中获取一个缓冲区，如果池为空则创建新的
func (p *BufferPool) Get() []byte {
	return p.pool.Get().([]byte)
}

// Put 将缓冲区归还到池中，以便复用（优化版：移除条件检查）
func (p *BufferPool) Put(buf []byte) {
	// 简化检查：只回收容量足够的缓冲区
	// len 检查可能会失败（因为可能被切片），但 cap 不会变
	if cap(buf) >= p.size {
		// 重新设置为完整大小，确保下次使用时是正确的
		buf = buf[:p.size]
		p.pool.Put(buf)
	}
	// 不符合条件的缓冲区会被 GC 自动回收，无需额外处理
}

// ConnManager 连接管理器，使用 sync.Map 优化并发性能
type ConnManager struct {
	mu           sync.RWMutex // 读写锁（实际未使用）
	conns        sync.Map     // IP -> 连接数 (*int32 原子计数)
	maxConnPerIP int          // 每个 IP 的最大连接数限制
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
func (m *ConnManager) GetConnCount(ip string) int {
	val, exists := m.conns.Load(ip)
	if !exists {
		return 0 // 不存在则返回 0
	}
	return int(atomic.LoadInt32(val.(*int32)))
}
