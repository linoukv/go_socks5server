// Package main 实现 SOCKS5 代理服务器的用户认证和授权模块。
// 提供基于用户名/密码的身份验证、用户管理、连接数限制、
// IP 连接限制、流量配额管理等功能。支持分片架构以提升并发性能。
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// 用户认证相关的常量定义
const (
	MinUsernameLen = 3                       // 用户名最小长度
	MaxUsernameLen = 32                      // 用户名最大长度
	MinPasswordLen = 8                       // 密码最小长度（用于 API 验证）
	MaxPasswordLen = 128                     // 密码最大长度
	MaxSpeedLimit  = 10 * 1024 * 1024 * 1024 // 最大速度限制（10 GB/s）
	MaxConnections = 100000                  // 最大连接数限制
)

// 用户名合法性正则表达式：仅允许字母、数字、下划线和短横线
var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// hashPassword 使用 bcrypt 算法对密码进行哈希加密。
// bcrypt 是一种安全的密码哈希函数，具有抗暴力破解能力。
//
// 参数:
//   - password: 明文密码
//
// 返回:
//   - string: bcrypt 哈希后的密文
//   - error: 哈希过程中的错误
func hashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("密码哈希失败：%w", err)
	}
	return string(hashed), nil
}

// checkPasswordHash 验证明文密码是否与 bcrypt 哈希值匹配。
// 使用恒定时间比较防止时序攻击。
//
// 参数:
//   - password: 明文密码
//   - hash: bcrypt 哈希值
//
// 返回:
//   - bool: 密码是否匹配
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// validateUsername 验证用户名的合法性。
// 检查长度范围和字符集限制。
//
// 参数:
//   - username: 待验证的用户名
//
// 返回:
//   - error: 验证错误，nil 表示通过
func validateUsername(username string) error {
	if len(username) < MinUsernameLen {
		return fmt.Errorf("用户名长度至少为 %d 位", MinUsernameLen)
	}

	if len(username) > MaxUsernameLen {
		return fmt.Errorf("用户名长度不能超过 %d 位", MaxUsernameLen)
	}

	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("用户名只能包含字母、数字、下划线和短横线")
	}

	return nil
}

// validatePassword 验证密码的强度和合法性。
// 要求密码同时包含字母和数字以提高安全性。
//
// 参数:
//   - password: 待验证的密码
//
// 返回:
//   - error: 验证错误，nil 表示通过
func validatePassword(password string) error {
	if len(password) < MinPasswordLen {
		return fmt.Errorf("密码长度至少为 %d 位", MinPasswordLen)
	}
	if len(password) > MaxPasswordLen {
		return fmt.Errorf("密码长度不能超过 %d 位", MaxPasswordLen)
	}

	hasLetter := false
	hasNumber := false
	for _, r := range password {
		if unicode.IsLetter(r) {
			hasLetter = true
		}
		if unicode.IsNumber(r) {
			hasNumber = true
		}
	}

	if !hasLetter || !hasNumber {
		return fmt.Errorf("密码必须同时包含字母和数字")
	}

	return nil
}

// validateSpeedLimit 验证速度限制参数的合法性。
//
// 参数:
//   - limit: 速度限制值（字节/秒）
//
// 返回:
//   - int64: 验证通过的速度限制
//   - error: 验证错误
func validateSpeedLimit(limit int64) (int64, error) {
	if limit < 0 {
		return 0, fmt.Errorf("速度限制不能为负数")
	}
	if limit > MaxSpeedLimit {
		return MaxSpeedLimit, fmt.Errorf("速度限制不能超过 %d GB/s", MaxSpeedLimit/1024/1024/1024)
	}
	return limit, nil
}

// validateMaxConnections 验证最大连接数参数的合法性。
//
// 参数:
//   - maxConn: 最大连接数
//
// 返回:
//   - int: 验证通过的连接数
//   - error: 验证错误
func validateMaxConnections(maxConn int) (int, error) {
	if maxConn < 0 {
		return 0, fmt.Errorf("最大连接数不能为负数")
	}
	if maxConn > MaxConnections {
		return MaxConnections, fmt.Errorf("最大连接数不能超过 %d", MaxConnections)
	}
	return maxConn, nil
}

// Authenticator 认证器接口，定义 SOCKS5 代理的认证行为。
// 所有认证方法都必须实现此接口。
type Authenticator interface {
	Authenticate(username, password string) bool // 验证用户名和密码
	Method() byte                                // 返回认证方法标识
}

// NoAuth 无认证模式实现，允许任何连接通过。
// 仅用于测试环境，生产环境不推荐使用。
type NoAuth struct{}

// Authenticate 无认证模式的认证逻辑，始终返回 true。
func (a *NoAuth) Authenticate(username, password string) bool {
	return true
}

// Method 返回无认证的方法标识。
func (a *NoAuth) Method() byte {
	return AuthNone
}

// User 用户数据结构，存储用户的配置和统计信息。
// 包含速度限制、连接限制、流量配额等字段。
// 注意：部分字段使用 atomic 操作以确保并发安全。
type User struct {
	ReadSpeedLimit  int64 `json:"read_speed_limit"`  // 上传速度限制（字节/秒），0 表示不限速
	WriteSpeedLimit int64 `json:"write_speed_limit"` // 下载速度限制（字节/秒），0 表示不限速
	UploadTotal     int64 `json:"upload_total"`      // 累计上传流量（字节），原子操作
	DownloadTotal   int64 `json:"download_total"`    // 累计下载流量（字节），原子操作
	CreateTime      int64 `json:"create_time"`       // 用户创建时间（Unix 时间戳）
	LastActivity    int64 `json:"last_activity"`     // 最后活动时间（Unix 时间戳），原子操作
	QuotaBytes      int64 `json:"quota_bytes"`       // 流量配额总量（字节）
	QuotaUsed       int64 `json:"quota_used"`        // 已用流量（字节），原子操作
	QuotaResetTime  int64 `json:"quota_reset_time"`  // 配额重置时间（Unix 时间戳）
	QuotaStartTime  int64 `json:"quota_start_time"`  // 配额周期开始时间
	QuotaEndTime    int64 `json:"quota_end_time"`    // 配额周期结束时间

	Username         string `json:"username"`           // 用户名
	Password         string `json:"password"`           // bcrypt 加密的密码
	MaxConnections   int    `json:"max_connections"`    // 最大并发连接数，0 表示不限制
	Enabled          bool   `json:"enabled"`            // 用户是否启用
	QuotaPeriod      string `json:"quota_period"`       // 配额周期：daily/weekly/monthly/custom
	MaxIPConnections int    `json:"max_ip_connections"` // 单 IP 最大连接数，0 表示不限制
}

// MarshalJSON 自定义 JSON 序列化，确保原子字段的值正确读取。
// 使用 atomic.Load 获取并发安全的字段值。
func (u *User) MarshalJSON() ([]byte, error) {
	type Alias User
	return json.Marshal(&struct {
		UploadTotal   int64 `json:"upload_total"`
		DownloadTotal int64 `json:"download_total"`
		QuotaUsed     int64 `json:"quota_used"`
		LastActivity  int64 `json:"last_activity"`
		*Alias
	}{
		UploadTotal:   atomic.LoadInt64(&u.UploadTotal),
		DownloadTotal: atomic.LoadInt64(&u.DownloadTotal),
		QuotaUsed:     atomic.LoadInt64(&u.QuotaUsed),
		LastActivity:  atomic.LoadInt64(&u.LastActivity),
		Alias:         (*Alias)(u),
	})
}

// PasswordAuth 基于密码的用户认证管理器。
// 维护用户映射、连接计数和 IP 追踪信息。
// 使用读写锁实现高并发的线程安全访问。
type PasswordAuth struct {
	mu              sync.RWMutex               // 用户数据的读写锁
	users           map[string]*User           // 用户名 -> 用户信息的映射
	userConnections map[string]int             // 用户名 -> 当前连接数的映射
	connMu          sync.RWMutex               // 连接计数的读写锁
	userIPs         map[string]map[string]bool // 用户名 -> IP 集合的映射
	ipMu            sync.RWMutex               // IP 映射的读写锁
}

// ShardedPasswordAuth 分片密码认证器，将用户分散到 16 个分片中。
// 通过减少锁竞争提升高并发场景下的性能。
type ShardedPasswordAuth struct {
	shards     [16]*PasswordAuth // 16 个独立的认证器分片
	shardCount int               // 分片数量，固定为 16
}

// NewShardedPasswordAuth 创建一个新的分片密码认证器。
// 自动初始化 16 个分片实例。
//
// 返回:
//   - *ShardedPasswordAuth: 分片认证器实例
func NewShardedPasswordAuth() *ShardedPasswordAuth {
	sa := &ShardedPasswordAuth{
		shardCount: 16,
	}
	for i := 0; i < sa.shardCount; i++ {
		sa.shards[i] = NewPasswordAuth()
	}
	return sa
}

// getShard 根据用户名计算对应的分片索引。
// 使用简单的哈希算法将用户名均匀分布到 16 个分片中。
//
// 参数:
//   - username: 用户名
//
// 返回:
//   - *PasswordAuth: 对应的分片实例
func (sa *ShardedPasswordAuth) getShard(username string) *PasswordAuth {
	hash := 0
	for _, c := range username {
		hash = hash*31 + int(c)
		if hash < 0 {
			hash = -hash
		}
	}
	return sa.shards[hash%sa.shardCount]
}

// AddUser 向分片认证器添加新用户。
// 委托给对应的分片处理。
func (sa *ShardedPasswordAuth) AddUser(username, password string) error {
	return sa.getShard(username).AddUser(username, password)
}

// GetUser 从分片认证器获取用户信息。
func (sa *ShardedPasswordAuth) GetUser(username string) (*User, bool) {
	return sa.getShard(username).GetUser(username)
}

// Authenticate 在分片认证器中验证用户凭据。
func (sa *ShardedPasswordAuth) Authenticate(username, password string) bool {
	return sa.getShard(username).Authenticate(username, password)
}

// NewPasswordAuth 创建一个新的密码认证器实例。
// 初始化用户映射、连接计数映射和 IP 追踪映射。
//
// 返回:
//   - *PasswordAuth: 初始化后的认证器实例
func NewPasswordAuth() *PasswordAuth {
	return &PasswordAuth{
		users:           make(map[string]*User),
		userConnections: make(map[string]int),
		userIPs:         make(map[string]map[string]bool),
	}
}

// AddUser 添加新用户到认证系统。
// 验证用户名和密码的合法性，使用 bcrypt 加密存储密码。
//
// 参数:
//   - username: 用户名
//   - password: 明文密码（将被加密存储）
//
// 返回:
//   - error: 创建错误信息
func (a *PasswordAuth) AddUser(username, password string) error {
	if err := validateUsername(username); err != nil {
		return fmt.Errorf("用户名验证失败：%w", err)
	}

	if err := validatePassword(password); err != nil {
		return fmt.Errorf("密码验证失败：%w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	hashedPassword, err := hashPassword(password)
	if err != nil {
		log.Printf("用户 [%s] 密码哈希失败：%v", username, err)
		return fmt.Errorf("密码加密失败：%w", err)
	}

	a.users[username] = &User{
		Username:        username,
		Password:        hashedPassword,
		ReadSpeedLimit:  0, // 默认不限速
		WriteSpeedLimit: 0,
		MaxConnections:  0, // 默认不限制连接数
		Enabled:         true,
		CreateTime:      time.Now().Unix(),
		LastActivity:    time.Now().Unix(),
	}

	log.Printf("用户 [%s] 创建成功", username)
	return nil
}

// RemoveUser 从认证系统中移除用户。
//
// 参数:
//   - username: 要删除的用户名
func (a *PasswordAuth) RemoveUser(username string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.users, username)
}

// UpdateUserPassword 更新用户的密码。
// 使用 bcrypt 重新加密新密码。
//
// 参数:
//   - username: 用户名
//   - newPassword: 新密码
//
// 返回:
//   - bool: 更新是否成功
func (a *PasswordAuth) UpdateUserPassword(username, newPassword string) bool {
	if a == nil {
		log.Printf("错误：PasswordAuth 为 nil")
		return false
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	user, exists := a.users[username]
	if !exists {
		return false
	}

	hashedPassword, err := hashPassword(newPassword)
	if err != nil {
		log.Printf("用户 [%s] 密码哈希失败：%v", username, err)
		return false
	}

	user.Password = hashedPassword
	log.Printf("用户 [%s] 密码已更新", username)
	return true
}

// Authenticate 验证用户的用户名和密码。
// 使用 bcrypt 比较密码哈希，同时检查用户是否被禁用。
// 对于不存在的用户，执行恒定时间的空密码比较以防止时序攻击。
//
// 参数:
//   - username: 用户名
//   - password: 明文密码
//
// 返回:
//   - bool: 认证是否成功
func (a *PasswordAuth) Authenticate(username, password string) bool {
	a.mu.RLock()
	user, exists := a.users[username]
	a.mu.RUnlock()

	if !exists || !user.Enabled {
		// 对空密码执行比较，防止时序攻击泄露用户是否存在
		_ = checkPasswordHash(password, "")
		return false
	}

	return checkPasswordHash(password, user.Password)
}

// Method 返回认证方法标识（SOCKS5 协议用）。
func (a *PasswordAuth) Method() byte {
	return AuthPassword
}

// SetUserSpeedLimit 设置用户的速度限制。
//
// 参数:
//   - username: 用户名
//   - readLimit: 上传速度限制（字节/秒）
//   - writeLimit: 下载速度限制（字节/秒）
//
// 返回:
//   - bool: 设置是否成功
func (a *PasswordAuth) SetUserSpeedLimit(username string, readLimit, writeLimit int64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, exists := a.users[username]
	if !exists {
		return false
	}

	user.ReadSpeedLimit = readLimit
	user.WriteSpeedLimit = writeLimit
	return true
}

// SetUserMaxConnections 设置用户的最大并发连接数。
//
// 参数:
//   - username: 用户名
//   - maxConn: 最大连接数，0 表示不限制
//
// 返回:
//   - bool: 设置是否成功
func (a *PasswordAuth) SetUserMaxConnections(username string, maxConn int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, exists := a.users[username]
	if !exists {
		return false
	}

	user.MaxConnections = maxConn
	return true
}

// EnableUser 启用或禁用用户账户。
//
// 参数:
//   - username: 用户名
//   - enabled: true 启用，false 禁用
//
// 返回:
//   - bool: 操作是否成功
func (a *PasswordAuth) EnableUser(username string, enabled bool) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, exists := a.users[username]
	if !exists {
		return false
	}

	user.Enabled = enabled
	return true
}

// GetUser 获取用户信息。
//
// 参数:
//   - username: 用户名
//
// 返回:
//   - *User: 用户信息指针
//   - bool: 用户是否存在
func (a *PasswordAuth) GetUser(username string) (*User, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	user, exists := a.users[username]
	if !exists {
		return nil, false
	}

	return user, true
}

// ListUsers 列出所有用户。
//
// 返回:
//   - []*User: 用户列表
func (a *PasswordAuth) ListUsers() []*User {
	a.mu.RLock()
	defer a.mu.RUnlock()

	users := make([]*User, 0, len(a.users))
	for _, user := range a.users {
		users = append(users, user)
	}
	return users
}

// IncrementUserConnection 增加用户的当前连接计数。
//
// 参数:
//   - username: 用户名
//
// 返回:
//   - int: 增加后的连接数
func (a *PasswordAuth) IncrementUserConnection(username string) int {
	a.connMu.Lock()
	defer a.connMu.Unlock()

	if a.userConnections == nil {
		a.userConnections = make(map[string]int)
	}
	a.userConnections[username]++
	return a.userConnections[username]
}

// DecrementUserConnection 减少用户的当前连接计数。
// 确保计数不会低于 0。
//
// 参数:
//   - username: 用户名
//
// 返回:
//   - int: 减少后的连接数
func (a *PasswordAuth) DecrementUserConnection(username string) int {
	a.connMu.Lock()
	defer a.connMu.Unlock()

	if a.userConnections != nil {
		a.userConnections[username]--
		if a.userConnections[username] <= 0 {
			a.userConnections[username] = 0
		}
		return a.userConnections[username]
	}
	return 0
}

// GetUserConnectionCount 获取用户的当前连接数。
func (a *PasswordAuth) GetUserConnectionCount(username string) int {
	a.connMu.RLock()
	defer a.connMu.RUnlock()

	if a.userConnections == nil {
		return 0
	}
	return a.userConnections[username]
}

// CheckUserConnectionLimit 检查用户是否达到连接数限制。
//
// 参数:
//   - username: 用户名
//
// 返回:
//   - bool: true 表示允许新连接，false 表示已达限制
func (a *PasswordAuth) CheckUserConnectionLimit(username string) bool {
	a.mu.RLock()
	user, exists := a.users[username]
	a.mu.RUnlock()

	// 用户不存在或无限制
	if !exists || user.MaxConnections <= 0 {
		return true
	}

	a.connMu.RLock()
	currentConns := 0
	if a.userConnections != nil {
		currentConns = a.userConnections[username]
	}
	a.connMu.RUnlock()

	return currentConns < user.MaxConnections
}

// AddUserIP 记录用户的 IP 地址。
// 用于追踪用户从哪些 IP 建立了连接。
//
// 参数:
//   - username: 用户名
//   - ip: IP 地址
func (a *PasswordAuth) AddUserIP(username, ip string) {
	a.ipMu.Lock()
	defer a.ipMu.Unlock()

	if a.userIPs == nil {
		a.userIPs = make(map[string]map[string]bool)
	}
	if a.userIPs[username] == nil {
		a.userIPs[username] = make(map[string]bool)
	}
	a.userIPs[username][ip] = true
}

// RemoveUserIP 移除用户的 IP 地址记录。
// 当用户断开连接时调用。
func (a *PasswordAuth) RemoveUserIP(username, ip string) {
	a.ipMu.Lock()
	defer a.ipMu.Unlock()

	if a.userIPs != nil && a.userIPs[username] != nil {
		delete(a.userIPs[username], ip)
		// 如果该用户没有其他 IP 了，清理整个条目
		if len(a.userIPs[username]) == 0 {
			delete(a.userIPs, username)
		}
	}
}

// GetUserIPCount 获取用户当前连接的不同 IP 数量。
func (a *PasswordAuth) GetUserIPCount(username string) int {
	a.ipMu.RLock()
	defer a.ipMu.RUnlock()

	if a.userIPs == nil || a.userIPs[username] == nil {
		return 0
	}
	return len(a.userIPs[username])
}

// CheckUserIPLimit 检查用户是否达到单 IP 连接数限制。
// 如果该 IP 已经连接过，允许再次连接；否则检查 IP 数量是否超限。
//
// 参数:
//   - username: 用户名
//   - ip: 待检查的 IP 地址
//
// 返回:
//   - bool: true 表示允许连接，false 表示超限
func (a *PasswordAuth) CheckUserIPLimit(username, ip string) bool {
	a.mu.RLock()
	user, exists := a.users[username]
	if !exists || user.MaxIPConnections <= 0 {
		a.mu.RUnlock()
		return true // 用户不存在或无限制
	}
	a.mu.RUnlock()

	a.ipMu.RLock()
	if a.userIPs == nil {
		a.ipMu.RUnlock()
		return true
	}
	ipSet := a.userIPs[username]
	if ipSet == nil {
		a.ipMu.RUnlock()
		return true
	}

	// 如果该 IP 已经连接过，允许
	if ipSet[ip] {
		a.ipMu.RUnlock()
		return true
	}

	currentIPs := len(ipSet)
	a.ipMu.RUnlock()

	// 检查不同 IP 的数量是否超过限制
	return currentIPs < user.MaxIPConnections
}

// GetUserIPs 获取用户当前连接的所有 IP 地址列表。
func (a *PasswordAuth) GetUserIPs(username string) []string {
	a.ipMu.RLock()
	defer a.ipMu.RUnlock()

	if a.userIPs == nil || a.userIPs[username] == nil {
		return []string{}
	}

	ips := make([]string, 0, len(a.userIPs[username]))
	for ip := range a.userIPs[username] {
		ips = append(ips, ip)
	}
	return ips
}

// FindUserByIP 根据 IP 地址查找对应的用户名。
// 用于在连接建立时确定用户身份。
//
// 参数:
//   - ip: IP 地址
//
// 返回:
//   - string: 用户名
//   - bool: 是否找到
func (a *PasswordAuth) FindUserByIP(ip string) (string, bool) {
	a.ipMu.RLock()
	defer a.ipMu.RUnlock()

	if a.userIPs == nil {
		return "", false
	}

	for username, ipSet := range a.userIPs {
		if ipSet[ip] {
			return username, true
		}
	}
	return "", false
}

// SetUserMaxIPConnections 设置用户允许的最大不同 IP 连接数。
//
// 参数:
//   - username: 用户名
//   - maxIP: 最大 IP 数
func (a *PasswordAuth) SetUserMaxIPConnections(username string, maxIP int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, exists := a.users[username]
	if !exists {
		return
	}

	user.MaxIPConnections = maxIP
	log.Printf("用户 [%s] 最大 IP 连接数已设置为：%d", username, maxIP)
}

// SelectAuthMethod 协商选择认证方法。
// 从客户端支持的方法和服务端支持的方法中找到第一个匹配项。
// 优先选择密码认证，其次是无认证。
//
// 参数:
//   - clientMethods: 客户端支持的认证方法列表
//   - serverMethods: 服务端支持的认证方法列表
//
// 返回:
//   - byte: 选定的认证方法，AuthNoAccept 表示无匹配
func SelectAuthMethod(clientMethods, serverMethods []byte) byte {
	// 优先尝试密码认证
	for _, cm := range clientMethods {
		if cm == AuthPassword {
			for _, sm := range serverMethods {
				if sm == AuthPassword {
					return AuthPassword
				}
			}
		}
	}

	// 其次尝试无认证
	for _, cm := range clientMethods {
		if cm == AuthNone {
			for _, sm := range serverMethods {
				if sm == AuthNone {
					return AuthNone
				}
			}
		}
	}

	return AuthNoAccept
}

func (a *PasswordAuth) SetUserQuota(username, period string, quotaBytes int64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, exists := a.users[username]
	if !exists {
		return false
	}

	user.QuotaPeriod = period
	user.QuotaBytes = quotaBytes

	if period == "custom" && quotaBytes > 0 {
		if user.QuotaStartTime > 0 && user.QuotaEndTime > 0 {
			user.QuotaResetTime = user.QuotaEndTime
			atomic.StoreInt64(&user.QuotaUsed, 0)
			log.Printf("用户 [%s] 配额已设置：%d MB，时间段：%s - %s",
				username,
				quotaBytes/1024/1024,
				time.Unix(user.QuotaStartTime, 0).Format("2006-01-02 15:04:05"),
				time.Unix(user.QuotaEndTime, 0).Format("2006-01-02 15:04:05"))
		} else {
			log.Printf("用户 [%s] 配额已设置：%d MB，等待设置时间段", username, quotaBytes/1024/1024)
		}
	}

	return true
}

func (a *PasswordAuth) calculateNextResetTime(period string) int64 {
	now := time.Now()
	switch period {
	case "daily":
		next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
		return next.Unix()
	case "weekly":
		daysUntilMonday := int(time.Monday - now.Weekday())
		if daysUntilMonday <= 0 {
			daysUntilMonday += 7
		}
		next := time.Date(now.Year(), now.Month(), now.Day()+daysUntilMonday, 0, 0, 0, 0, now.Location())
		return next.Unix()
	case "monthly":
		var next time.Time
		if now.Month() == time.December {
			next = time.Date(now.Year()+1, time.January, 1, 0, 0, 0, 0, now.Location())
		} else {
			next = time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, now.Location())
		}
		return next.Unix()
	default:
		return 0
	}
}

func (a *PasswordAuth) SetUserQuotaTimeRange(username string, startTime, endTime int64) bool {
	a.mu.RLock()
	user, exists := a.users[username]
	a.mu.RUnlock()

	if !exists {
		return false
	}

	isFirstTime := user.QuotaStartTime == 0 || user.QuotaEndTime == 0

	atomic.StoreInt64(&user.QuotaStartTime, startTime)
	atomic.StoreInt64(&user.QuotaEndTime, endTime)
	atomic.StoreInt64(&user.QuotaResetTime, endTime)

	if isFirstTime {
		atomic.StoreInt64(&user.QuotaUsed, 0)
	}

	log.Printf("用户 [%s] 自定义时间段配额已设置：%s - %s",
		username,
		time.Unix(startTime, 0).Format("2006-01-02 15:04:05"),
		time.Unix(endTime, 0).Format("2006-01-02 15:04:05"))

	return true
}

func (a *PasswordAuth) ClearUserQuota(username string) bool {
	a.mu.RLock()
	user, exists := a.users[username]
	a.mu.RUnlock()

	if !exists {
		return false
	}

	atomic.StoreInt64(&user.QuotaStartTime, 0)
	atomic.StoreInt64(&user.QuotaEndTime, 0)
	atomic.StoreInt64(&user.QuotaResetTime, 0)
	atomic.StoreInt64(&user.QuotaUsed, 0)

	user.QuotaPeriod = ""
	user.QuotaBytes = 0

	log.Printf("用户 [%s] 已设置为无限制", username)
	return true
}

func (a *PasswordAuth) CheckQuotaAndReset(username string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, exists := a.users[username]
	if !exists {
		return
	}

	if user.QuotaPeriod == "custom" && user.QuotaBytes > 0 {
		now := time.Now().Unix()

		if now > user.QuotaEndTime {
			quotaUsed := atomic.LoadInt64(&user.QuotaUsed)
			if quotaUsed > 0 {
				atomic.StoreInt64(&user.QuotaUsed, 0)
				log.Printf("用户 [%s] 自定义时间段配额已到期，流量已重置：%s - %s",
					username,
					time.Unix(user.QuotaStartTime, 0).Format("2006-01-02 15:04:05"),
					time.Unix(user.QuotaEndTime, 0).Format("2006-01-02 15:04:05"))
			}
		}
	}
}

func (a *PasswordAuth) AddUserTraffic(username string, upload, download int64) {
	a.mu.RLock()
	user, exists := a.users[username]
	a.mu.RUnlock()

	if !exists {
		return
	}

	atomic.AddInt64(&user.UploadTotal, upload)
	atomic.AddInt64(&user.DownloadTotal, download)

	if user.QuotaPeriod != "" {
		atomic.AddInt64(&user.QuotaUsed, upload+download)
	}

	atomic.StoreInt64(&user.LastActivity, time.Now().Unix())
}

func (a *PasswordAuth) CheckQuotaExceeded(username string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	user, exists := a.users[username]
	if !exists {
		return false
	}

	if user.QuotaPeriod == "" {
		return false
	}

	if user.QuotaPeriod == "custom" {
		now := time.Now().Unix()

		quotaStartTime := atomic.LoadInt64(&user.QuotaStartTime)
		quotaEndTime := atomic.LoadInt64(&user.QuotaEndTime)
		quotaUsed := atomic.LoadInt64(&user.QuotaUsed)

		if now < quotaStartTime {
			log.Printf("用户 [%s] 配额时间段未开始 (%s)，禁止连接",
				username, time.Unix(quotaStartTime, 0).Format("2006-01-02 15:04:05"))
			return true
		}

		if now > quotaEndTime {
			log.Printf("用户 [%s] 配额时间段已结束 (%s)，禁止连接",
				username, time.Unix(quotaEndTime, 0).Format("2006-01-02 15:04:05"))
			return true
		}

		if user.QuotaBytes > 0 && quotaUsed >= user.QuotaBytes {
			log.Printf("用户 [%s] 流量配额已用尽 (%.2f MB / %.2f MB)，禁止连接",
				username, float64(quotaUsed)/1024/1024, float64(user.QuotaBytes)/1024/1024)
			return true
		}

		return false
	}

	quotaUsed := atomic.LoadInt64(&user.QuotaUsed)
	if user.QuotaBytes > 0 && quotaUsed >= user.QuotaBytes {
		log.Printf("用户 [%s] 流量配额已用尽 (%.2f MB / %.2f MB)，禁止连接",
			username, float64(quotaUsed)/1024/1024, float64(user.QuotaBytes)/1024/1024)
		return true
	}

	return false
}

func (a *PasswordAuth) GetUserQuotaInfo(username string) (period string, total int64, used int64, resetTime int64, exists bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	user, exists := a.users[username]
	if !exists {
		return "", 0, 0, 0, false
	}

	return user.QuotaPeriod, user.QuotaBytes, atomic.LoadInt64(&user.QuotaUsed), user.QuotaResetTime, true
}

func (a *PasswordAuth) GetUserQuotaUsed(username string) int64 {
	a.mu.RLock()
	defer a.mu.RUnlock()

	user, exists := a.users[username]
	if !exists {
		return 0
	}
	return atomic.LoadInt64(&user.QuotaUsed)
}

func (a *PasswordAuth) GetUserQuotaTotal(username string) int64 {
	a.mu.RLock()
	defer a.mu.RUnlock()

	user, exists := a.users[username]
	if !exists {
		return 0
	}
	return user.QuotaBytes
}
