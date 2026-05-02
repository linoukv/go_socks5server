package main

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// RateLimiter 基于令牌桶算法的高性能限速器
// 支持动态调整速率，零内存分配设计
type RateLimiter struct {
	// 使用原子操作存储令牌数量（单位：字节）
	// 正值表示可用令牌，负值表示欠费令牌
	tokens int64

	// 速率限制（字节/秒）
	rate int64

	// 桶容量（最大突发流量，字节）
	burst int64

	// 上次更新时间（纳秒时间戳）
	lastUpdate int64

	// 互斥锁，用于保护非原子操作
	mu sync.Mutex

	// 关闭标志
	closed int32
}

// NewRateLimiter 创建新的限速器
// rate: 每秒允许的速率（字节/秒），0 表示不限速
// burst: 桶容量（字节），决定突发流量能力
func NewRateLimiter(rate, burst int64) *RateLimiter {
	if burst <= 0 {
		burst = rate // 默认桶容量等于速率
	}

	return &RateLimiter{
		tokens:     burst, // 初始填满桶
		rate:       rate,
		burst:      burst,
		lastUpdate: time.Now().UnixNano(),
	}
}

// SetRate 动态调整限速速率
func (rl *RateLimiter) SetRate(rate int64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.rate = rate
}

// GetRate 获取当前限速速率
func (rl *RateLimiter) GetRate() int64 {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.rate
}

// SetBurst 动态调整桶容量
func (rl *RateLimiter) SetBurst(burst int64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.burst = burst
}

// Close 关闭限速器
func (rl *RateLimiter) Close() {
	atomic.StoreInt32(&rl.closed, 1)
}

// IsClosed 检查限速器是否已关闭
func (rl *RateLimiter) IsClosed() bool {
	return atomic.LoadInt32(&rl.closed) == 1
}

// WaitN 等待获取 n 个令牌
// 如果限速器已关闭或速率为 0，立即返回
// 返回 context 错误如果上下文被取消
func (rl *RateLimiter) WaitN(ctx context.Context, n int) error {
	// 检查是否已关闭
	if rl.IsClosed() {
		return nil
	}

	// 检查是否不限速
	rl.mu.Lock()
	rate := rl.rate
	rl.mu.Unlock()

	if rate <= 0 {
		return nil // 不限速，直接通过
	}

	// 尝试立即获取令牌
	if rl.tryAcquire(int64(n)) {
		return nil
	}

	// 需要等待，计算等待时间
	waitTime := rl.calculateWaitTime(int64(n))
	if waitTime <= 0 {
		return nil // 可以立即获取
	}

	// 使用定时器等待
	timer := time.NewTimer(waitTime)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		// 时间到了，再次尝试获取
		if rl.tryAcquire(int64(n)) {
			return nil
		}
		// 如果还是获取不到，使用循环等待而不是递归，避免栈溢出
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				if rl.tryAcquire(int64(n)) {
					return nil
				}
				// 短暂休眠后重试
				time.Sleep(time.Millisecond)
			}
		}
	}
}

// Wait 等待获取 1 个令牌
func (rl *RateLimiter) Wait(ctx context.Context) error {
	return rl.WaitN(ctx, 1)
}

// tryAcquire 尝试获取 n 个令牌，返回是否成功
// 使用原子操作，无锁设计
func (rl *RateLimiter) tryAcquire(n int64) bool {
	// 更新令牌数量
	rl.updateTokens()

	// 尝试原子操作获取令牌
	for {
		tokens := atomic.LoadInt64(&rl.tokens)
		if tokens < n {
			return false // 令牌不足
		}

		// CAS 操作尝试减少令牌
		if atomic.CompareAndSwapInt64(&rl.tokens, tokens, tokens-n) {
			return true
		}
		// CAS 失败，重试
	}
}

// updateTokens 根据时间更新令牌数量
func (rl *RateLimiter) updateTokens() {
	now := time.Now().UnixNano()

	// 获取上次更新时间
	last := atomic.LoadInt64(&rl.lastUpdate)

	// 计算时间差（纳秒）
	elapsed := now - last
	if elapsed <= 0 {
		return // 时间没有前进或倒退，不更新
	}

	// 先获取所有需要的值
	rl.mu.Lock()
	rate := rl.rate
	burst := rl.burst
	rl.mu.Unlock()

	if rate <= 0 {
		return // 不限速，不更新令牌
	}

	// 计算新增令牌数
	newTokens := (rate * elapsed) / 1e9
	if newTokens <= 0 {
		return // 时间太短，没有新令牌
	}

	// 尝试更新 lastUpdate，如果失败说明其他 goroutine 已经更新
	if !atomic.CompareAndSwapInt64(&rl.lastUpdate, last, now) {
		return
	}

	// 原子操作增加令牌，但不超过桶容量
	for {
		tokens := atomic.LoadInt64(&rl.tokens)
		total := tokens + newTokens
		if total > burst {
			total = burst // 不能超过桶容量
		}

		if atomic.CompareAndSwapInt64(&rl.tokens, tokens, total) {
			break
		}
	}
}

// calculateWaitTime 计算获取 n 个令牌需要等待的时间
func (rl *RateLimiter) calculateWaitTime(n int64) time.Duration {
	rl.updateTokens()

	tokens := atomic.LoadInt64(&rl.tokens)
	if tokens >= n {
		return 0 // 可以立即获取
	}

	// 计算需要等待的时间
	need := n - tokens

	rl.mu.Lock()
	rate := rl.rate
	rl.mu.Unlock()

	if rate <= 0 {
		return 0 // 不限速
	}

	// 等待时间 = 需要的令牌数 / 速率
	waitNs := (need * 1e9) / rate
	return time.Duration(waitNs) * time.Nanosecond
}

// ReserveN 预留 n 个令牌，返回等待时间（不实际等待）
func (rl *RateLimiter) ReserveN(n int64) time.Duration {
	return rl.calculateWaitTime(n)
}

// Tokens 获取当前可用令牌数（用于监控）
func (rl *RateLimiter) Tokens() int64 {
	rl.updateTokens()
	return atomic.LoadInt64(&rl.tokens)
}

// UserRateLimiter 用户级别的限速器管理
type UserRateLimiter struct {
	// 上传限速器
	uploadLimiter *RateLimiter

	// 下载限速器
	downloadLimiter *RateLimiter

	// 用户名
	username string

	// 互斥锁
	mu sync.RWMutex
}

// NewUserRateLimiter 创建用户限速器
func NewUserRateLimiter(username string, uploadRate, downloadRate int64) *UserRateLimiter {
	url := &UserRateLimiter{
		username: username,
	}

	// 创建上传限速器（如果速率 > 0）
	if uploadRate > 0 {
		url.uploadLimiter = NewRateLimiter(uploadRate, uploadRate*2)
	}

	// 创建下载限速器（如果速率 > 0）
	if downloadRate > 0 {
		url.downloadLimiter = NewRateLimiter(downloadRate, downloadRate*2)
	}

	return url
}

// SetUploadRate 设置上传限速
func (url *UserRateLimiter) SetUploadRate(rate int64) {
	url.mu.Lock()
	defer url.mu.Unlock()

	if url.uploadLimiter != nil {
		url.uploadLimiter.SetRate(rate)
		url.uploadLimiter.SetBurst(rate * 2)
	} else if rate > 0 {
		url.uploadLimiter = NewRateLimiter(rate, rate*2)
	}
}

// SetDownloadRate 设置下载限速
func (url *UserRateLimiter) SetDownloadRate(rate int64) {
	url.mu.Lock()
	defer url.mu.Unlock()

	if url.downloadLimiter != nil {
		url.downloadLimiter.SetRate(rate)
		url.downloadLimiter.SetBurst(rate * 2)
	} else if rate > 0 {
		url.downloadLimiter = NewRateLimiter(rate, rate*2)
	}
}

// WaitUpload 等待上传令牌
func (url *UserRateLimiter) WaitUpload(ctx context.Context, n int) error {
	url.mu.RLock()
	limiter := url.uploadLimiter
	url.mu.RUnlock()

	if limiter == nil {
		return nil // 不限速
	}
	return limiter.WaitN(ctx, n)
}

// WaitDownload 等待下载令牌
func (url *UserRateLimiter) WaitDownload(ctx context.Context, n int) error {
	url.mu.RLock()
	limiter := url.downloadLimiter
	url.mu.RUnlock()

	if limiter == nil {
		return nil // 不限速
	}
	return limiter.WaitN(ctx, n)
}

// Close 关闭用户限速器
func (url *UserRateLimiter) Close() {
	url.mu.Lock()
	defer url.mu.Unlock()

	if url.uploadLimiter != nil {
		url.uploadLimiter.Close()
		url.uploadLimiter = nil // 置为 nil 防止重复关闭
	}
	if url.downloadLimiter != nil {
		url.downloadLimiter.Close()
		url.downloadLimiter = nil // 置为 nil 防止重复关闭
	}
}

// RateLimiterManager 全局限速器管理器
type RateLimiterManager struct {
	// 用户限速器映射
	limiters map[string]*UserRateLimiter

	// 最后活动时间映射
	lastActivity map[string]int64

	// 互斥锁
	mu sync.RWMutex

	// 关闭通道
	closeChan chan struct{}

	// 等待组
	wg sync.WaitGroup
}

// NewRateLimiterManager 创建限速器管理器
func NewRateLimiterManager() *RateLimiterManager {
	rlm := &RateLimiterManager{
		limiters:     make(map[string]*UserRateLimiter),
		lastActivity: make(map[string]int64),
		closeChan:    make(chan struct{}),
	}

	// 启动定期清理协程
	rlm.wg.Add(1)
	go rlm.cleanupInactiveLimiters()

	return rlm
}

// GetOrCreateLimiter 获取或创建用户限速器
func (rlm *RateLimiterManager) GetOrCreateLimiter(username string, uploadRate, downloadRate int64) *UserRateLimiter {
	rlm.mu.RLock()
	limiter, exists := rlm.limiters[username]
	rlm.mu.RUnlock()

	if exists {
		// 更新限速配置
		limiter.SetUploadRate(uploadRate)
		limiter.SetDownloadRate(downloadRate)

		// 更新最后活动时间
		rlm.mu.Lock()
		rlm.lastActivity[username] = time.Now().Unix()
		rlm.mu.Unlock()

		return limiter
	}

	// 创建新的限速器
	rlm.mu.Lock()
	defer rlm.mu.Unlock()

	// 双重检查
	if limiter, exists = rlm.limiters[username]; exists {
		limiter.SetUploadRate(uploadRate)
		limiter.SetDownloadRate(downloadRate)
		rlm.lastActivity[username] = time.Now().Unix()
		return limiter
	}

	limiter = NewUserRateLimiter(username, uploadRate, downloadRate)
	rlm.limiters[username] = limiter
	rlm.lastActivity[username] = time.Now().Unix()
	return limiter
}

// GetLimiter 获取用户限速器（如果不存在返回 nil）
func (rlm *RateLimiterManager) GetLimiter(username string) *UserRateLimiter {
	rlm.mu.RLock()
	limiter := rlm.limiters[username]
	rlm.mu.RUnlock()

	if limiter != nil {
		// 更新最后活动时间
		rlm.mu.Lock()
		rlm.lastActivity[username] = time.Now().Unix()
		rlm.mu.Unlock()
	}

	return limiter
}

// RemoveLimiter 移除用户限速器
func (rlm *RateLimiterManager) RemoveLimiter(username string) {
	rlm.mu.Lock()
	defer rlm.mu.Unlock()

	if limiter, exists := rlm.limiters[username]; exists {
		limiter.Close()
		delete(rlm.limiters, username)
		delete(rlm.lastActivity, username)
	}
}

// UpdateLimiter 更新用户限速配置
func (rlm *RateLimiterManager) UpdateLimiter(username string, uploadRate, downloadRate int64) {
	rlm.mu.RLock()
	limiter, exists := rlm.limiters[username]
	rlm.mu.RUnlock()

	if exists {
		limiter.SetUploadRate(uploadRate)
		limiter.SetDownloadRate(downloadRate)

		// 更新最后活动时间
		rlm.mu.Lock()
		rlm.lastActivity[username] = time.Now().Unix()
		rlm.mu.Unlock()
	}
}

// Close 关闭所有限速器
func (rlm *RateLimiterManager) Close() {
	// 停止清理协程
	close(rlm.closeChan)
	rlm.wg.Wait()

	rlm.mu.Lock()
	defer rlm.mu.Unlock()

	for _, limiter := range rlm.limiters {
		limiter.Close()
	}
	rlm.limiters = make(map[string]*UserRateLimiter)
	rlm.lastActivity = make(map[string]int64)
}

// cleanupInactiveLimiters 定期清理不活跃的用户限速器
// 每 30 分钟运行一次，清理超过 1 小时未活动的用户限速器
func (rlm *RateLimiterManager) cleanupInactiveLimiters() {
	defer rlm.wg.Done()

	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rlm.cleanupLimiters()
		case <-rlm.closeChan:
			return
		}
	}
}

// cleanupLimiters 执行实际的限速器清理操作
func (rlm *RateLimiterManager) cleanupLimiters() {
	rlm.mu.Lock()
	defer rlm.mu.Unlock()

	now := time.Now().Unix()
	inactiveThreshold := now - 60*60 // 1 小时不活跃

	for username, lastActive := range rlm.lastActivity {
		if lastActive < inactiveThreshold {
			if limiter, exists := rlm.limiters[username]; exists {
				limiter.Close()
			}
			delete(rlm.limiters, username)
			delete(rlm.lastActivity, username)
		}
	}
}
