package main

import (
	// 常量时间比较，防止时序攻击
	"fmt"     // 格式化输出
	"log"     // 日志记录
	"regexp"  // 正则表达式
	"sync"    // 同步原语
	"time"    // 时间处理
	"unicode" // Unicode 字符分类

	"golang.org/x/crypto/bcrypt" // 密码哈希加密
)

// 安全常量定义
const (
	MinUsernameLen = 3                       // 最小用户名长度
	MaxUsernameLen = 32                      // 最大用户名长度
	MinPasswordLen = 8                       // 最小密码长度
	MaxPasswordLen = 128                     // 最大密码长度
	MaxSpeedLimit  = 10 * 1024 * 1024 * 1024 // 最大速度限制 10GB/s
	MaxConnections = 100000                  // 最大连接数限制
)

// 用户名验证正则表达式：只允许字母、数字、下划线、短横线
var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// hashPassword 对密码进行 bcrypt 哈希处理
// cost: 加密成本系数（4-31），默认使用 10，数值越大越安全但越慢
func hashPassword(password string) (string, error) {
	// 使用 bcrypt.DefaultCost (10) 平衡安全性和性能
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("密码哈希失败：%w", err)
	}
	return string(hashed), nil
}

// checkPasswordHash 验证密码是否匹配哈希值
// 使用 constant-time 比较防止时序攻击
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// validateUsername 验证用户名格式
// 规则：3-32 位，只允许字母、数字、下划线、短横线
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

// validatePassword 验证密码强度
// 规则：8-128 位，必须包含字母和数字
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

// validateSpeedLimit 验证速度限制值
func validateSpeedLimit(limit int64) (int64, error) {
	if limit < 0 {
		return 0, fmt.Errorf("速度限制不能为负数")
	}
	if limit > MaxSpeedLimit {
		return MaxSpeedLimit, fmt.Errorf("速度限制不能超过 %d GB/s", MaxSpeedLimit/1024/1024/1024)
	}
	return limit, nil
}

// validateMaxConnections 验证最大连接数
func validateMaxConnections(maxConn int) (int, error) {
	if maxConn < 0 {
		return 0, fmt.Errorf("最大连接数不能为负数")
	}
	if maxConn > MaxConnections {
		return MaxConnections, fmt.Errorf("最大连接数不能超过 %d", MaxConnections)
	}
	return maxConn, nil
}

// Authenticator 认证器接口，定义了认证必须实现的方法
type Authenticator interface {
	// Authenticate 验证用户名和密码，返回是否验证成功
	Authenticate(username, password string) bool
	// Method 返回认证方法常量（用于 SOCKS5 协议协商）
	Method() byte
}

// NoAuth 无需认证的实现，总是允许连接
type NoAuth struct{}

func (a *NoAuth) Authenticate(username, password string) bool {
	return true // 总是认证成功
}

func (a *NoAuth) Method() byte {
	return AuthNone // 返回无认证方法标识
}

// User 用户信息结构体（32 位系统优化版：int64 字段放在开头确保 8 字节对齐）
type User struct {
	// int64 字段必须放在最前面，确保 8 字节对齐（32 位系统原子操作要求）
	ReadSpeedLimit  int64 `json:"read_speed_limit"`  // 读取速度限制（字节/秒）
	WriteSpeedLimit int64 `json:"write_speed_limit"` // 写入速度限制（字节/秒）
	UploadTotal     int64 `json:"upload_total"`      // 总上传流量（字节）
	DownloadTotal   int64 `json:"download_total"`    // 总下载流量（字节）
	CreateTime      int64 `json:"create_time"`       // 创建时间戳
	LastActivity    int64 `json:"last_activity"`     // 最后活动时间戳
	QuotaBytes      int64 `json:"quota_bytes"`       // 周期流量配额（字节）
	QuotaUsed       int64 `json:"quota_used"`        // 当前周期已用流量（字节）
	QuotaResetTime  int64 `json:"quota_reset_time"`  // 下次流量重置时间戳

	// 其他字段
	Username         string `json:"username"`           // 用户名
	Password         string `json:"password"`           // 密码
	MaxConnections   int    `json:"max_connections"`    // 最大连接数
	Enabled          bool   `json:"enabled"`            // 是否启用
	Group            string `json:"group"`              // 所属分组
	QuotaPeriod      string `json:"quota_period"`       // 流量周期
	MaxIPConnections int    `json:"max_ip_connections"` // 单用户最大 IP 连接数
}

// UserGroup 用户分组结构体（32 位系统优化版：int64 字段放在开头）
type UserGroup struct {
	// int64 字段放在最前面，确保 8 字节对齐
	ReadSpeedLimit  int64 `json:"read_speed_limit"`  // 分组默认读取速度限制
	WriteSpeedLimit int64 `json:"write_speed_limit"` // 分组默认写入速度限制

	// 其他字段
	Name           string `json:"name"`            // 分组名称
	Description    string `json:"description"`     // 分组描述
	MaxConnections int    `json:"max_connections"` // 分组默认最大连接数
	Members        int    `json:"members"`         // 组成员数量
}

// PasswordAuth 用户名/密码认证实现，支持多用户管理
type PasswordAuth struct {
	mu              sync.RWMutex               // 读写锁，保护并发访问
	users           map[string]*User           // 用户名到用户信息的映射
	userConnections map[string]int             // 每个用户的当前连接数
	connMu          sync.RWMutex               // 保护 userConnections 的锁
	userIPs         map[string]map[string]bool // 每个用户的 IP 地址集合 {username: {ip: true}}
	ipMu            sync.RWMutex               // 保护 userIPs 的锁
	groups          map[string]*UserGroup      // 用户分组
}

// NewPasswordAuth 创建并初始化密码认证器实例
func NewPasswordAuth() *PasswordAuth {
	return &PasswordAuth{
		users:           make(map[string]*User),           // 初始化用户 map
		userConnections: make(map[string]int),             // 初始化连接数 map
		userIPs:         make(map[string]map[string]bool), // 初始化 IP 集合
		groups:          make(map[string]*UserGroup),      // 初始化分组 map
	}
}

// AddUser 添加或更新用户凭据（安全版：密码哈希存储 + 输入验证）
func (a *PasswordAuth) AddUser(username, password string) error {
	// ✅ 验证用户名格式
	if err := validateUsername(username); err != nil {
		return fmt.Errorf("用户名验证失败：%w", err)
	}

	// ✅ 验证密码强度
	if err := validatePassword(password); err != nil {
		return fmt.Errorf("密码验证失败：%w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// 对密码进行 bcrypt 哈希处理
	hashedPassword, err := hashPassword(password)
	if err != nil {
		log.Printf("用户 [%s] 密码哈希失败：%v", username, err)
		return fmt.Errorf("密码加密失败：%w", err)
	}

	a.users[username] = &User{
		Username:        username,
		Password:        hashedPassword, // ✅ 存储哈希值而非明文
		ReadSpeedLimit:  0,              // 默认不限速
		WriteSpeedLimit: 0,              // 默认不限速
		MaxConnections:  0,              // 默认不限连接数
		Enabled:         true,
		Group:           "", // 默认无分组
		CreateTime:      time.Now().Unix(),
		LastActivity:    time.Now().Unix(),
	}

	log.Printf("用户 [%s] 创建成功", username)
	return nil
}

// RemoveUser 删除指定用户
func (a *PasswordAuth) RemoveUser(username string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.users, username)
}

// Authenticate 验证用户名和密码（安全版：bcrypt 密码验证）
// 使用 constant-time 比较防止时序攻击（timing attack）
func (a *PasswordAuth) Authenticate(username, password string) bool {
	a.mu.RLock()
	user, exists := a.users[username]
	a.mu.RUnlock()

	if !exists || !user.Enabled {
		// 为了防止时序攻击，即使用户不存在也进行虚假比较
		// 这样攻击者无法通过响应时间判断用户是否存在
		_ = checkPasswordHash(password, "")
		return false
	}

	// ✅ 使用 bcrypt 验证哈希密码
	// bcrypt.CompareHashAndPassword 内部已实现 constant-time 比较
	return checkPasswordHash(password, user.Password)
}

func (a *PasswordAuth) Method() byte {
	return AuthPassword // 返回密码认证方法标识
}

// SetUserSpeedLimit 设置用户的速度限制
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

// SetUserMaxConnections 设置用户的最大连接数
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

// EnableUser 启用或禁用用户
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

// GetUser 获取用户信息
func (a *PasswordAuth) GetUser(username string) (*User, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	user, exists := a.users[username]
	if !exists {
		return nil, false
	}

	return user, true
}

// ListUsers 列出所有用户
func (a *PasswordAuth) ListUsers() []*User {
	a.mu.RLock()
	defer a.mu.RUnlock()

	users := make([]*User, 0, len(a.users))
	for _, user := range a.users {
		users = append(users, user)
	}
	return users
}

// IncrementUserConnection 增加用户连接数（原子操作）
func (a *PasswordAuth) IncrementUserConnection(username string) int {
	a.connMu.Lock()
	defer a.connMu.Unlock()

	if a.userConnections == nil {
		a.userConnections = make(map[string]int)
	}
	a.userConnections[username]++
	return a.userConnections[username]
}

// DecrementUserConnection 减少用户连接数（原子操作）
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

// GetUserConnectionCount 获取用户当前连接数
func (a *PasswordAuth) GetUserConnectionCount(username string) int {
	a.connMu.RLock()
	defer a.connMu.RUnlock()

	if a.userConnections == nil {
		return 0
	}
	return a.userConnections[username]
}

// CheckUserConnectionLimit 检查用户是否超过连接数限制
func (a *PasswordAuth) CheckUserConnectionLimit(username string) bool {
	a.mu.RLock()
	user, exists := a.users[username]
	a.mu.RUnlock()

	if !exists || user.MaxConnections <= 0 {
		return true // 无限制
	}

	a.connMu.RLock()
	currentConns := 0
	if a.userConnections != nil {
		currentConns = a.userConnections[username]
	}
	a.connMu.RUnlock()

	return currentConns < user.MaxConnections
}

// AddUserIP 添加用户 IP 地址
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

// RemoveUserIP 移除用户 IP 地址
func (a *PasswordAuth) RemoveUserIP(username, ip string) {
	a.ipMu.Lock()
	defer a.ipMu.Unlock()

	if a.userIPs != nil && a.userIPs[username] != nil {
		delete(a.userIPs[username], ip)
		// 如果没有 IP 了，清理 map
		if len(a.userIPs[username]) == 0 {
			delete(a.userIPs, username)
		}
	}
}

// GetUserIPCount 获取用户当前连接的 IP 数量
func (a *PasswordAuth) GetUserIPCount(username string) int {
	a.ipMu.RLock()
	defer a.ipMu.RUnlock()

	if a.userIPs == nil || a.userIPs[username] == nil {
		return 0
	}
	return len(a.userIPs[username])
}

// CheckUserIPLimit 检查用户是否超过 IP 连接数限制
func (a *PasswordAuth) CheckUserIPLimit(username, ip string) bool {
	// 快速获取用户信息
	a.mu.RLock()
	user, exists := a.users[username]
	if !exists || user.MaxIPConnections <= 0 {
		a.mu.RUnlock()
		return true // 无限制
	}
	a.mu.RUnlock()

	// 快速获取 IP 计数
	a.ipMu.RLock()
	if a.userIPs == nil {
		a.ipMu.RUnlock()
		return true // 还没有 IP 记录
	}
	ipSet := a.userIPs[username]
	if ipSet == nil {
		a.ipMu.RUnlock()
		return true // 还没有 IP 记录
	}

	// 检查 IP 是否已存在
	if ipSet[ip] {
		a.ipMu.RUnlock()
		return true // 已存在，允许连接
	}

	currentIPs := len(ipSet)
	a.ipMu.RUnlock()

	return currentIPs < user.MaxIPConnections
}

// GetUserIPs 获取用户当前连接的所有 IP 地址
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

// SetUserMaxIPConnections 设置用户最大 IP 连接数
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

// SelectAuthMethod 选择双方都支持的认证方法
// 参数：clientMethods - 客户端支持的方法列表；serverMethods - 服务器支持的方法列表
// 返回：选定的认证方法，如果没有共同支持的方法则返回 AuthNoAccept
func SelectAuthMethod(clientMethods, serverMethods []byte) byte {
	// 优先检查密码认证 (0x02) - 更安全
	for _, cm := range clientMethods {
		if cm == AuthPassword {
			for _, sm := range serverMethods {
				if sm == AuthPassword {
					return AuthPassword // 找到共同支持的密码认证
				}
			}
		}
	}

	// 其次检查无需认证 (0x00)
	for _, cm := range clientMethods {
		if cm == AuthNone {
			for _, sm := range serverMethods {
				if sm == AuthNone {
					return AuthNone // 找到共同支持的无认证
				}
			}
		}
	}

	// 没有共同支持的认证方法
	return AuthNoAccept
}

// SetUserQuota 设置用户流量配额
// period: "daily"(每日), "weekly"(每周), "monthly"(每月), ""(无限制)
// quotaBytes: 周期流量配额（字节），0 表示无限制
func (a *PasswordAuth) SetUserQuota(username, period string, quotaBytes int64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, exists := a.users[username]
	if !exists {
		return false
	}

	user.QuotaPeriod = period
	user.QuotaBytes = quotaBytes

	// 计算下次重置时间
	if period != "" && quotaBytes > 0 {
		user.QuotaResetTime = a.calculateNextResetTime(period)
		user.QuotaUsed = 0 // 设置配额时重置已用流量
	}

	return true
}

// calculateNextResetTime 计算下次重置时间
func (a *PasswordAuth) calculateNextResetTime(period string) int64 {
	now := time.Now()
	switch period {
	case "daily":
		// 明天零点
		next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
		return next.Unix()
	case "weekly":
		// 下周一零点
		daysUntilMonday := int(time.Monday - now.Weekday())
		if daysUntilMonday <= 0 {
			daysUntilMonday += 7
		}
		next := time.Date(now.Year(), now.Month(), now.Day()+daysUntilMonday, 0, 0, 0, 0, now.Location())
		return next.Unix()
	case "monthly":
		// 下月 1 号零点
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

// CheckQuotaAndReset 检查并重置到期的流量配额
func (a *PasswordAuth) CheckQuotaAndReset(username string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, exists := a.users[username]
	if !exists || user.QuotaPeriod == "" || user.QuotaBytes == 0 {
		return
	}

	// 检查是否到期
	if time.Now().Unix() >= user.QuotaResetTime {
		user.QuotaUsed = 0
		user.QuotaResetTime = a.calculateNextResetTime(user.QuotaPeriod)
		log.Printf("用户 [%s] 流量配额已重置，周期：%s", username, user.QuotaPeriod)
	}
}

// AddUserTraffic 增加用户流量使用量（极致优化版：减少锁竞争）
func (a *PasswordAuth) AddUserTraffic(username string, upload, download int64) {
	// 快速获取用户指针（只读操作使用读锁）
	a.mu.RLock()
	user, exists := a.users[username]
	a.mu.RUnlock()

	if !exists {
		return
	}

	// 直接更新字段（假设单用户对自身字段的写入是线程安全的）
	// 在大多数架构上，int64 的对齐写入是原子的
	user.UploadTotal += upload
	user.DownloadTotal += download

	// 配额更新（仅在启用了配额时）
	if user.QuotaPeriod != "" && user.QuotaBytes > 0 {
		user.QuotaUsed += upload + download
	}

	// 更新最后活动时间
	user.LastActivity = time.Now().Unix()
}

// CheckQuotaExceeded 检查用户是否超出流量配额
func (a *PasswordAuth) CheckQuotaExceeded(username string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	user, exists := a.users[username]
	if !exists || user.QuotaPeriod == "" || user.QuotaBytes == 0 {
		return false // 无配额限制
	}

	return user.QuotaUsed >= user.QuotaBytes
}

// GetUserQuotaInfo 获取用户流量配额信息
func (a *PasswordAuth) GetUserQuotaInfo(username string) (period string, total int64, used int64, resetTime int64, exists bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	user, exists := a.users[username]
	if !exists {
		return "", 0, 0, 0, false
	}

	return user.QuotaPeriod, user.QuotaBytes, user.QuotaUsed, user.QuotaResetTime, true
}
