package main

import (
	"context"
	"sync"
	"sync/atomic"
)

type WorkerPool struct {
	submitted int64
	workers   int
	semaphore chan struct{}
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
}

func NewWorkerPool(workers int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	pool := &WorkerPool{
		workers: workers,
		ctx:     ctx,
		cancel:  cancel,
	}

	if workers > 0 {
		pool.semaphore = make(chan struct{}, workers)
	}

	return pool
}

func (p *WorkerPool) Submit(task func()) bool {
	if p.ctx.Err() != nil {
		return false
	}

	if p.workers > 0 {
		select {
		case p.semaphore <- struct{}{}:
			p.wg.Add(1)
			atomic.AddInt64(&p.submitted, 1)

			go func() {
				defer func() {
					<-p.semaphore
					p.wg.Done()
				}()
				task()
			}()
			return true

		case <-p.ctx.Done():
			return false
		}
	} else {
		p.wg.Add(1)
		atomic.AddInt64(&p.submitted, 1)

		go func() {
			defer p.wg.Done()
			task()
		}()
		return true
	}
}

func (p *WorkerPool) Stop() {
	p.cancel()
	p.wg.Wait()
}

type BufferPool struct {
	allocated int64
	pool      sync.Pool
	size      int
	preAlloc  int
}

type MultiBufferPool struct {
	smallPool  *BufferPool
	mediumPool *BufferPool
	largePool  *BufferPool
}

func NewMultiBufferPool() *MultiBufferPool {
	return &MultiBufferPool{
		smallPool:  NewBufferPool(8 * 1024),
		mediumPool: NewBufferPool(128 * 1024),
		largePool:  NewBufferPool(2 * 1024 * 1024),
	}
}

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

func NewBufferPool(size int) *BufferPool {
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

	pool.preAllocate(100)

	return pool
}

func (p *BufferPool) preAllocate(count int) {
	for i := 0; i < count; i++ {
		buf := make([]byte, p.size)
		p.pool.Put(buf)
		atomic.AddInt64(&p.allocated, 1)
	}
}

func (p *BufferPool) SetPreAlloc(count int) {
	p.preAlloc = count

	if p.allocated == 0 {
		p.preAllocate(count)
	}
}

func (p *BufferPool) Get() []byte {
	return p.pool.Get().([]byte)
}

func (p *BufferPool) Put(buf []byte) {
	if cap(buf) >= p.size {
		buf = buf[:cap(buf)]

		if p.size <= 128*1024 {
			for i := range buf {
				buf[i] = 0
			}
		}

		p.pool.Put(buf)
	}
}

type ConnManager struct {
	mu           sync.RWMutex
	conns        sync.Map
	maxConnPerIP int
}

type ShardedConnManager struct {
	shards     [32]*ConnManager
	shardCount int
}

func NewShardedConnManager(maxConnPerIP int) *ShardedConnManager {
	sm := &ShardedConnManager{
		shardCount: 32,
	}
	for i := 0; i < sm.shardCount; i++ {
		sm.shards[i] = NewConnManager(maxConnPerIP)
	}
	return sm
}

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

func (sm *ShardedConnManager) AddConn(ip string) bool {
	return sm.getShard(ip).AddConn(ip)
}

func (sm *ShardedConnManager) RemoveConn(ip string) {
	sm.getShard(ip).RemoveConn(ip)
}

func (sm *ShardedConnManager) GetConnCount(ip string) int {
	return sm.getShard(ip).GetConnCount(ip)
}

func NewConnManager(maxConnPerIP int) *ConnManager {
	return &ConnManager{
		conns:        sync.Map{},
		maxConnPerIP: maxConnPerIP,
	}
}

func (m *ConnManager) AddConn(ip string) bool {
	if m.maxConnPerIP <= 0 {
		return true
	}

	val, _ := m.conns.LoadOrStore(ip, new(int32))
	countPtr := val.(*int32)

	for {
		current := atomic.LoadInt32(countPtr)
		if current >= int32(m.maxConnPerIP) {
			return false
		}
		if atomic.CompareAndSwapInt32(countPtr, current, current+1) {
			return true
		}
	}
}

func (m *ConnManager) RemoveConn(ip string) {
	if m.maxConnPerIP <= 0 {
		return
	}

	val, exists := m.conns.Load(ip)
	if !exists {
		return
	}
	countPtr := val.(*int32)

	for {
		current := atomic.LoadInt32(countPtr)
		if current <= 0 {
			m.conns.Delete(ip)
			return
		}
		if atomic.CompareAndSwapInt32(countPtr, current, current-1) {
			return
		}
	}
}

func (m *ConnManager) GetConnCount(ip string) int {
	val, exists := m.conns.Load(ip)
	if !exists {
		return 0
	}
	return int(atomic.LoadInt32(val.(*int32)))
}
