// Package main 实现 SOCKS5 代理服务器的用户认证和授权模块。
// 提供基于用户名/密码的身份验证、用户管理、连接数限制、
// IP 连接限制、流量配额管理等功能。支持分片架构以提升并发性能。
package main

import (
	"encoding/json" // 导入 JSON 编码包，用于用户数据的序列化和反序列化
	"fmt"           // 导入格式化包，用于字符串格式化和错误信息包装
	"log"           // 导入日志包，用于记录系统运行日志和调试信息
	"regexp"        // 导入正则表达式包，用于验证用户名的字符合法性
	"sync"          // 导入同步包，提供互斥锁、读写锁等同步原语
	"sync/atomic"   // 导入原子操作包，提供无锁的线程安全整数操作
	"time"          // 导入时间包，用于时间戳获取和时间计算
	"unicode"       // 导入 Unicode 包，用于字符分类判断（字母、数字等）

	"golang.org/x/crypto/bcrypt" // 导入 bcrypt 加密包，用于密码的安全哈希和验证
)

// 用户认证相关的常量定义 - 用于限制用户输入和系统资源使用
const (
	MinUsernameLen = 3      // 用户名最小长度，防止过短的用户名缺乏辨识度
	MaxUsernameLen = 32     // 用户名最大长度，防止过长的用户名占用过多存储空间
	MinPasswordLen = 8      // 密码最小长度（用于 API 验证），确保密码具有基本的安全性
	MaxPasswordLen = 128    // 密码最大长度，防止超长密码导致哈希计算耗时过长
	MaxConnections = 100000 // 最大连接数限制，单个用户允许的最大并发连接数上限
)

// 用户名合法性正则表达式：仅允许字母、数字、下划线和短横线
// 正则说明：^ 表示字符串开头，[a-zA-Z0-9_-] 表示允许的字符集，+ 表示至少一个字符，$ 表示字符串结尾
// 此规则防止 SQL 注入、路径遍历等安全风险，同时保证用户名的可读性
var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// hashPassword 使用 bcrypt 算法对密码进行哈希加密。
// bcrypt 是一种自适应的密码哈希函数，通过调整计算成本因子来抵抗暴力破解和彩虹表攻击。
// bcrypt.DefaultCost 默认值为 10，表示进行 2^10 = 1024 轮迭代。
//
// 参数:
//   - password: 明文密码字符串，将被加密存储
//
// 返回:
//   - string: bcrypt 哈希后的密文字符串，格式为 $2a$cost$salt+hash
//   - error: 哈希过程中的错误，如内存不足或参数无效
func hashPassword(password string) (string, error) {
	// 调用 bcrypt 库生成密码哈希，使用默认成本因子（10）
	// bcrypt.GenerateFromPassword 会自动生成随机盐值并执行多轮哈希计算
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		// 哈希失败时，包装错误信息并返回，使用 %w 保留原始错误链
		return "", fmt.Errorf("密码哈希失败：%w", err)
	}
	// 将字节切片类型的哈希值转换为字符串并返回
	return string(hashed), nil
}

// checkPasswordHash 验证明文密码是否与 bcrypt 哈希值匹配。
// bcrypt.CompareHashAndPassword 内部使用恒定时间比较算法，防止通过计时攻击推断密码信息。
// 该函数会重新计算明文密码的哈希并与存储的哈希值进行比较。
//
// 参数:
//   - password: 待验证的明文密码字符串
//   - hash: 存储在数据库中的 bcrypt 哈希值
//
// 返回:
//   - bool: 密码是否匹配，true 表示验证成功，false 表示验证失败
func checkPasswordHash(password, hash string) bool {
	// 调用 bcrypt 库比较明文密码和哈希值
	// 如果密码匹配，返回 nil；否则返回错误
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	// 将错误检查结果转换为布尔值：无错误表示密码匹配
	return err == nil
}

// validateUsername 验证用户名的合法性。
// 检查长度范围（3-32 字符）和字符集限制（仅允许字母、数字、下划线、短横线）。
// 此函数在创建新用户或修改用户名时被调用，确保数据符合系统规范。
//
// 参数:
//   - username: 待验证的用户名字符串
//
// 返回:
//   - error: 验证错误信息，nil 表示验证通过
func validateUsername(username string) error {
	// 检查用户名长度是否小于最小允许值（3 字符）
	if len(username) < MinUsernameLen {
		return fmt.Errorf("用户名长度至少为 %d 位", MinUsernameLen) // 返回包含最小长度要求的错误信息
	}

	// 检查用户名长度是否超过最大允许值（32 字符）
	if len(username) > MaxUsernameLen {
		return fmt.Errorf("用户名长度不能超过 %d 位", MaxUsernameLen) // 返回包含最大长度限制的错误信息
	}

	// 使用正则表达式验证用户名字符集，只允许字母、数字、下划线和短横线
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("用户名只能包含字母、数字、下划线和短横线") // 返回字符集限制说明
	}

	return nil // 所有验证通过，返回 nil 表示合法
}

// validatePassword 验证密码的强度和合法性。
// 检查长度范围（8-128 字符）并要求密码同时包含字母和数字以提高安全性。
// 此规则防止用户使用过于简单的密码，增强账户安全性。
//
// 参数:
//   - password: 待验证的明文字符串
//
// 返回:
//   - error: 验证错误信息，nil 表示验证通过
func validatePassword(password string) error {
	// 检查密码长度是否小于最小允许值（8 字符）
	if len(password) < MinPasswordLen {
		return fmt.Errorf("密码长度至少为 %d 位", MinPasswordLen) // 返回包含最小长度要求的错误信息
	}
	// 检查密码长度是否超过最大允许值（128 字符）
	if len(password) > MaxPasswordLen {
		return fmt.Errorf("密码长度不能超过 %d 位", MaxPasswordLen) // 返回包含最大长度限制的错误信息
	}

	// 初始化标志变量，用于追踪密码中是否包含字母和数字
	hasLetter := false // 标记是否包含至少一个字母字符
	hasNumber := false // 标记是否包含至少一个数字字符

	// 遍历密码中的每个 Unicode 字符，检查其类型
	for _, r := range password {
		// 使用 unicode 包判断当前字符是否为字母（包括中英文等所有语言的字母）
		if unicode.IsLetter(r) {
			hasLetter = true // 发现字母，设置标志
		}
		// 使用 unicode 包判断当前字符是否为数字（包括各种语言的数字字符）
		if unicode.IsNumber(r) {
			hasNumber = true // 发现数字，设置标志
		}
	}

	// 检查密码是否同时包含字母和数字，缺一不可
	if !hasLetter || !hasNumber {
		return fmt.Errorf("密码必须同时包含字母和数字") // 返回密码复杂度要求说明
	}

	return nil // 所有验证通过，返回 nil 表示密码合法
}

// validateMaxConnections 验证最大连接数参数的合法性。
// 确保连接数在合理范围内（0 到 100000），防止资源耗尽。
//
// 参数:
//   - maxConn: 最大并发连接数，0 表示不限制
//
// 返回:
//   - int: 验证通过的连接数值（可能被修正为最大值）
//   - error: 验证错误，当值为负数或超过最大值时返回
func validateMaxConnections(maxConn int) (int, error) {
	// 检查连接数是否为负数，负数是无效的配置
	if maxConn < 0 {
		return 0, fmt.Errorf("最大连接数不能为负数") // 返回明确的错误信息
	}
	// 检查连接数是否超过系统允许的最大值（100000）
	if maxConn > MaxConnections {
		// 返回修正后的最大值和错误提示
		return MaxConnections, fmt.Errorf("最大连接数不能超过 %d", MaxConnections)
	}
	// 验证通过，返回原始的连接数值
	return maxConn, nil
}

// Authenticator 认证器接口，定义 SOCKS5 代理的认证行为。
// 所有认证方法（无认证、密码认证等）都必须实现此接口，以便服务器统一调用。
// 接口设计遵循 Go 语言的隐式接口实现原则。
type Authenticator interface {
	Authenticate(username, password string) bool // 验证用户名和密码，返回认证结果
	Method() byte                                // 返回认证方法标识，用于 SOCKS5 协议握手协商
}

// NoAuth 无认证模式实现，允许任何连接通过。
// 仅用于测试环境或开放代理场景，生产环境不推荐使用，因为缺乏身份验证机制。
type NoAuth struct{}

// Authenticate 无认证模式的认证逻辑，始终返回 true。
// 用于测试环境或开放代理场景，不进行任何身份验证，允许任意用户名和密码通过。
//
// 参数:
//   - username: 用户名（在此模式下被忽略，可以是任意值）
//   - password: 密码（在此模式下被忽略，可以是任意值）
//
// 返回:
//   - bool: 始终返回 true，表示认证成功
func (a *NoAuth) Authenticate(username, password string) bool {
	return true // 无条件返回成功，不进行任何验证
}

// Method 返回无认证的方法标识。
// SOCKS5 协议中，0x00 表示无需认证，客户端和服务器在握手阶段协商使用此方法。
//
// 返回:
//   - byte: AuthNone 常量值 (0x00)，表示无认证方法
func (a *NoAuth) Method() byte {
	return AuthNone // 返回预定义的无认证方法标识
}

// User 用户数据结构，存储用户的配置和统计信息。
// 包含连接限制、流量配额等字段，用于实现精细化的用户管理。
// 注意：部分字段（如 UploadTotal、DownloadTotal、QuotaUsed、LastActivity）使用 atomic 原子操作
// 以确保在高并发场景下的线程安全性，避免数据竞争。
type User struct {
	// === 流量统计（原子操作） ===
	// 这些字段在多个 goroutine 中同时更新，必须使用 atomic 包进行操作
	UploadTotal   int64 `json:"upload_total"`   // 累计上传流量（字节），通过 atomic.AddInt64 原子更新
	DownloadTotal int64 `json:"download_total"` // 累计下载流量（字节），通过 atomic.AddInt64 原子更新
	LastActivity  int64 `json:"last_activity"`  // 最后活动时间（Unix 时间戳），通过 atomic.StoreInt64 原子更新，用于检测僵尸账户

	// === 流量配额 ===
	// 控制用户在特定时间段内可以使用的总流量
	QuotaBytes     int64  `json:"quota_bytes"`      // 流量配额总量（字节），0 表示无配额限制
	QuotaUsed      int64  `json:"quota_used"`       // 已用流量（字节），通过 atomic.AddInt64 原子更新，与 QuotaBytes 比较判断是否超限
	QuotaPeriod    string `json:"quota_period"`     // 配额周期类型："daily"=每日重置, "weekly"=每周重置, "monthly"=每月重置, "custom"=自定义时间段, ""=无限制
	QuotaStartTime int64  `json:"quota_start_time"` // 自定义配额开始时间（Unix 时间戳），仅在 QuotaPeriod="custom" 时有效
	QuotaEndTime   int64  `json:"quota_end_time"`   // 自定义配额结束时间（Unix 时间戳），仅在 QuotaPeriod="custom" 时有效
	QuotaResetTime int64  `json:"quota_reset_time"` // 配额下次重置时间（Unix 时间戳），预留字段，用于周期性配额管理

	// === 基本信息 ===
	// 用户的身份标识和认证凭据
	Username string `json:"username"` // 用户名，唯一标识符，用于登录认证和数据库主键
	Password string `json:"password"` // bcrypt 加密后的密码哈希值，永不存储明文密码

	// === 连接限制 ===
	// 控制用户可以建立的并发连接数量
	MaxConnections   int `json:"max_connections"`    // 最大并发连接数，0 表示不限制，用于防止单个用户占用过多资源
	MaxIPConnections int `json:"max_ip_connections"` // 单 IP 最大连接数，0 表示不限制，用于防止同一 IP 建立过多连接

	// === 状态 ===
	// 用户的账户状态和时间信息
	Enabled    bool  `json:"enabled"`     // 用户是否启用，false 时拒绝所有认证请求，可用于临时禁用账户
	CreateTime int64 `json:"create_time"` // 用户创建时间（Unix 时间戳），用于审计和账户生命周期管理
}

// MarshalJSON 自定义 JSON 序列化方法，确保原子字段的值正确读取。
// 由于 UploadTotal、DownloadTotal、QuotaUsed、LastActivity 等字段使用 atomic 操作更新，
// 直接序列化可能读取到不一致的值。此方法通过 atomic.Load 获取线程安全的快照值。
// 这是 Go encoding/json 包的标准扩展方式，当结构体实现此方法时会自动调用。
func (u *User) MarshalJSON() ([]byte, error) {
	// 定义类型别名，避免递归调用 MarshalJSON
	type Alias User
	// 构造匿名结构体，将原子字段单独提取并使用 atomic.Load 读取
	return json.Marshal(&struct {
		UploadTotal   int64 `json:"upload_total"`   // 上传总量，通过原子加载获取
		DownloadTotal int64 `json:"download_total"` // 下载总量，通过原子加载获取
		QuotaUsed     int64 `json:"quota_used"`     // 已用配额，通过原子加载获取
		LastActivity  int64 `json:"last_activity"`  // 最后活动时间，通过原子加载获取
		*Alias              // 嵌入原始 User 结构的其他字段
	}{
		// 使用 atomic.LoadInt64 安全地读取原子字段的当前值
		UploadTotal:   atomic.LoadInt64(&u.UploadTotal),   // 原子加载上传总量
		DownloadTotal: atomic.LoadInt64(&u.DownloadTotal), // 原子加载下载总量
		QuotaUsed:     atomic.LoadInt64(&u.QuotaUsed),     // 原子加载已用配额
		LastActivity:  atomic.LoadInt64(&u.LastActivity),  // 原子加载最后活动时间
		Alias:         (*Alias)(u),                        // 类型转换，嵌入其他非原子字段
	})
}

// PasswordAuth 基于密码的用户认证管理器。
// 维护用户映射、连接计数和 IP 追踪信息，提供完整的用户管理功能。
// 使用读写锁（sync.RWMutex）实现高并发的线程安全访问：
// - 读操作（如认证检查）可以并发执行
// - 写操作（如添加/删除用户）独占访问
type PasswordAuth struct {
	mu              sync.RWMutex               // 用户数据映射的读写锁，保护 users 字段的并发访问
	users           map[string]*User           // 用户名到用户信息指针的映射，key 为用户名，value 为 User 结构体指针
	userConnections map[string]int             // 用户名到当前活跃连接数的映射，用于连接数限制检查
	connMu          sync.RWMutex               // 连接计数映射的读写锁，独立于用户数据锁以减少锁竞争
	userIPs         map[string]map[string]bool // 用户名到 IP 地址集合的嵌套映射，外层 key 为用户名，内层 key 为 IP 地址
	ipMu            sync.RWMutex               // IP 映射的读写锁，独立于其他锁以支持细粒度并发控制
}

// ShardedPasswordAuth 分片密码认证器，将用户分散到 16 个独立分片中。
// 通过减少锁竞争提升高并发场景下的性能，特别适用于多核 CPU 和大用户量场景。
// 每个分片拥有独立的锁和数据映射，不同分片之间可以完全并行处理。
type ShardedPasswordAuth struct {
	shards     [16]*PasswordAuth // 16 个独立的 PasswordAuth 分片实例，每个分片管理一部分用户
	shardCount int               // 分片数量，固定为 16，用于计算哈希取模
}

// NewShardedPasswordAuth 创建一个新的分片密码认证器。
// 自动初始化 16 个独立的 PasswordAuth 分片实例，每个分片都有自己的锁和数据映射。
//
// 返回:
//   - *ShardedPasswordAuth: 初始化完成的分片认证器实例，可立即使用
func NewShardedPasswordAuth() *ShardedPasswordAuth {
	// 创建分片认证器结构体，设置分片数量为 16
	sa := &ShardedPasswordAuth{
		shardCount: 16, // 固定 16 个分片，这是性能和内存占用的平衡点
	}
	// 循环初始化每个分片，调用 NewPasswordAuth 创建独立的 PasswordAuth 实例
	for i := 0; i < sa.shardCount; i++ {
		sa.shards[i] = NewPasswordAuth() // 为每个分片创建独立的认证器实例
	}
	return sa // 返回初始化完成的分片认证器
}

// getShard 根据用户名计算对应的分片索引，并返回该分片实例。
// 使用简单的字符串哈希算法将用户名均匀分布到 16 个分片中，确保负载均衡。
// 相同用户名始终映射到同一个分片，保证数据一致性。
//
// 参数:
//   - username: 用户名字符串，用于计算哈希值
//
// 返回:
//   - *PasswordAuth: 对应的分片实例指针，调用者可直接操作该分片
func (sa *ShardedPasswordAuth) getShard(username string) *PasswordAuth {
	hash := 0 // 初始化哈希值为 0
	// 遍历用户名的每个字符，使用多项式滚动哈希算法计算哈希值
	for _, c := range username {
		hash = hash*31 + int(c) // 乘以质数 31 并加上当前字符的 Unicode 值
		if hash < 0 {
			hash = -hash // 处理整数溢出导致的负数情况，确保哈希值为正
		}
	}
	// 对分片数量取模，得到分片索引（0-15），返回对应的分片实例
	return sa.shards[hash%sa.shardCount]
}

// AddUser 向分片认证器添加新用户。
// 根据用户名自动路由到对应的分片，由该分片处理用户添加逻辑。
//
// 参数:
//   - username: 新用户的用户名
//   - password: 新用户的明文密码
//
// 返回:
//   - error: 添加失败时的错误信息
func (sa *ShardedPasswordAuth) AddUser(username, password string) error {
	// 委托给对应的分片处理，getShard 根据用户名确定目标分片
	return sa.getShard(username).AddUser(username, password)
}

// GetUser 从分片认证器获取用户信息。
// 根据用户名自动路由到对应的分片进行查询。
//
// 参数:
//   - username: 要查询的用户名
//
// 返回:
//   - *User: 用户信息指针，nil 表示用户不存在
//   - bool: 用户是否存在
func (sa *ShardedPasswordAuth) GetUser(username string) (*User, bool) {
	// 委托给对应的分片处理
	return sa.getShard(username).GetUser(username)
}

// Authenticate 在分片认证器中验证用户凭据。
// 根据用户名自动路由到对应的分片进行认证。
//
// 参数:
//   - username: 待验证的用户名
//   - password: 待验证的明文密码
//
// 返回:
//   - bool: 认证是否成功
func (sa *ShardedPasswordAuth) Authenticate(username, password string) bool {
	// 委托给对应的分片处理
	return sa.getShard(username).Authenticate(username, password)
}

// NewPasswordAuth 创建一个新的密码认证器实例。
// 初始化用户映射、连接计数映射和 IP 追踪映射，所有映射初始为空。
// 此函数是 PasswordAuth 的标准构造函数。
//
// 返回:
//   - *PasswordAuth: 初始化完成的认证器实例，可立即用于用户管理
func NewPasswordAuth() *PasswordAuth {
	// 返回新创建的 PasswordAuth 结构体指针，所有映射使用 make 初始化
	return &PasswordAuth{
		users:           make(map[string]*User),           // 初始化用户信息映射，key 为用户名，value 为 User 指针
		userConnections: make(map[string]int),             // 初始化连接计数映射，key 为用户名，value 为当前连接数
		userIPs:         make(map[string]map[string]bool), // 初始化 IP 追踪映射，外层 key 为用户名，内层 key 为 IP 地址
	}
}

// AddUser 添加新用户到认证系统。
// 验证用户名和密码的合法性，使用 bcrypt 加密存储密码，设置默认配置值。
// 如果用户名已存在，将覆盖原有用户信息。
//
// 参数:
//   - username: 新用户的用户名，必须符合命名规范（3-32 字符，仅字母数字下划线短横线）
//   - password: 明文密码，将被 bcrypt 加密后存储（8-128 字符，必须包含字母和数字）
//
// 返回:
//   - error: 创建错误信息，包括验证失败、哈希失败等
func (a *PasswordAuth) AddUser(username, password string) error {
	// 验证用户名是否符合规范（长度、字符集）
	if err := validateUsername(username); err != nil {
		return fmt.Errorf("用户名验证失败：%w", err) // 包装验证错误并返回
	}

	// 验证密码是否符合强度要求（长度、复杂度）
	if err := validatePassword(password); err != nil {
		return fmt.Errorf("密码验证失败：%w", err) // 包装验证错误并返回
	}

	// 获取写锁，确保用户映射的修改是线程安全的
	a.mu.Lock()
	defer a.mu.Unlock() // 函数返回时自动释放锁

	// 使用 bcrypt 对密码进行哈希加密
	hashedPassword, err := hashPassword(password)
	if err != nil {
		// 记录日志并返回错误，哈希失败通常是由于系统资源不足
		log.Printf("用户 [%s] 密码哈希失败：%v", username, err)
		return fmt.Errorf("密码加密失败：%w", err)
	}

	// 创建新的 User 结构体，填充基本信息和默认配置
	a.users[username] = &User{
		Username:       username,          // 设置用户名
		Password:       hashedPassword,    // 设置加密后的密码哈希
		MaxConnections: 0,                 // 默认不限制并发连接数（0 表示无限制）
		Enabled:        true,              // 默认启用账户
		CreateTime:     time.Now().Unix(), // 记录当前时间戳作为创建时间
		LastActivity:   time.Now().Unix(), // 初始化最后活动时间为创建时间
	}

	// 记录成功日志，便于审计和调试
	log.Printf("用户 [%s] 创建成功", username)
	return nil // 返回 nil 表示操作成功
}

// RemoveUser 从认证系统中移除指定用户。
// 此操作不可逆，会永久删除用户及其所有配置信息。
//
// 参数:
//   - username: 要删除的用户名
func (a *PasswordAuth) RemoveUser(username string) {
	// 获取写锁，确保删除操作的线程安全
	a.mu.Lock()
	defer a.mu.Unlock() // 函数返回时自动释放锁
	// 从用户映射中删除指定用户，Go 的 delete 函数对不存在的 key 是安全的
	delete(a.users, username)
}

// UpdateUserPassword 更新用户的密码。
// 验证用户存在性，使用 bcrypt 重新加密新密码并替换旧密码。
//
// 参数:
//   - username: 要更新密码的用户名
//   - newPassword: 新的明文密码，将被加密后存储
//
// 返回:
//   - bool: 更新是否成功，false 表示用户不存在或哈希失败
func (a *PasswordAuth) UpdateUserPassword(username, newPassword string) bool {
	// 检查认证器实例是否为 nil，防止空指针异常
	if a == nil {
		log.Printf("错误：PasswordAuth 为 nil") // 记录严重错误日志
		return false                        // 返回失败
	}

	// 获取写锁，确保密码更新的线程安全
	a.mu.Lock()
	defer a.mu.Unlock() // 函数返回时自动释放锁

	// 从映射中查找用户
	user, exists := a.users[username]
	if !exists {
		return false // 用户不存在，返回失败
	}

	// 对新密码进行 bcrypt 哈希加密
	hashedPassword, err := hashPassword(newPassword)
	if err != nil {
		// 记录日志并返回失败，哈希失败通常是系统问题
		log.Printf("用户 [%s] 密码哈希失败：%v", username, err)
		return false
	}

	// 更新用户的密码字段为新哈希值
	user.Password = hashedPassword
	// 记录成功日志
	log.Printf("用户 [%s] 密码已更新", username)
	return true // 返回成功
}

// Authenticate 验证用户的用户名和密码。
// 使用 bcrypt 比较密码哈希，同时检查用户是否被禁用。
// 对于不存在的用户，执行恒定时间的空密码比较以防止时序攻击泄露用户是否存在。
// 这是一种安全措施，防止攻击者通过响应时间差异推断有效用户名。
//
// 参数:
//   - username: 待验证的用户名
//   - password: 待验证的明文密码
//
// 返回:
//   - bool: 认证是否成功，true 表示用户名和密码都正确且账户已启用
func (a *PasswordAuth) Authenticate(username, password string) bool {
	// 获取读锁，允许多个认证请求并发执行
	a.mu.RLock()
	// 从映射中查找用户
	user, exists := a.users[username]
	a.mu.RUnlock() // 立即释放读锁，减少锁持有时间

	// 检查用户是否存在且已启用
	if !exists || !user.Enabled {
		// 对空密码执行比较操作，消耗与真实认证相同的时间
		// 这防止攻击者通过响应时间差异判断用户名是否有效（时序攻击防护）
		_ = checkPasswordHash(password, "")
		return false // 用户不存在或被禁用，返回失败
	}

	// 用户存在且已启用，验证密码是否正确
	return checkPasswordHash(password, user.Password)
}

// Method 返回认证方法标识（SOCKS5 协议用）。
// 实现 Authenticator 接口，表明此认证器使用密码认证方式。
//
// 返回:
//   - byte: AuthPassword 常量值 (0x02)，表示用户名/密码认证
func (a *PasswordAuth) Method() byte {
	return AuthPassword // 返回预定义的密码认证方法标识
}

// SetUserMaxConnections 设置用户的最大并发连接数。
// 用于控制单个用户可以同时建立的连接数量，防止资源滥用。
//
// 参数:
//   - username: 要设置限制的用户名
//   - maxConn: 最大连接数，0 表示不限制
//
// 返回:
//   - bool: 设置是否成功，false 表示用户不存在
func (a *PasswordAuth) SetUserMaxConnections(username string, maxConn int) bool {
	// 获取写锁，确保配置修改的线程安全
	a.mu.Lock()
	defer a.mu.Unlock() // 函数返回时自动释放锁

	// 从映射中查找用户
	user, exists := a.users[username]
	if !exists {
		return false // 用户不存在，返回失败
	}

	// 更新用户的最大连接数配置
	user.MaxConnections = maxConn
	return true // 返回成功
}

// EnableUser 启用或禁用用户账户。
// 禁用的用户将无法通过认证，但配置信息保留在系统中。
//
// 参数:
//   - username: 要操作用户的用户名
//   - enabled: true 启用账户，false 禁用账户
//
// 返回:
//   - bool: 操作是否成功，false 表示用户不存在
func (a *PasswordAuth) EnableUser(username string, enabled bool) bool {
	// 获取写锁，确保状态修改的线程安全
	a.mu.Lock()
	defer a.mu.Unlock() // 函数返回时自动释放锁

	// 从映射中查找用户
	user, exists := a.users[username]
	if !exists {
		return false // 用户不存在，返回失败
	}

	// 更新用户的启用状态
	user.Enabled = enabled
	return true // 返回成功
}

// GetUser 获取指定用户的详细信息。
// 使用读锁允许多个查询并发执行。
//
// 参数:
//   - username: 要查询的用户名
//
// 返回:
//   - *User: 用户信息指针，nil 表示用户不存在
//   - bool: 用户是否存在
func (a *PasswordAuth) GetUser(username string) (*User, bool) {
	// 获取读锁，允许多个查询并发执行
	a.mu.RLock()
	defer a.mu.RUnlock() // 函数返回时自动释放读锁

	// 从映射中查找用户
	user, exists := a.users[username]
	if !exists {
		return nil, false // 用户不存在，返回 nil 和 false
	}

	return user, true // 返回用户指针和存在标志
}

// ListUsers 列出所有用户的信息。
// 返回用户列表的副本，调用者可以安全地遍历而不影响内部数据。
//
// 返回:
//   - []*User: 所有用户的指针切片，按映射迭代顺序排列
func (a *PasswordAuth) ListUsers() []*User {
	// 获取读锁，确保遍历期间数据不被修改
	a.mu.RLock()
	defer a.mu.RUnlock() // 函数返回时自动释放读锁

	// 预分配切片容量，避免动态扩容
	users := make([]*User, 0, len(a.users))
	// 遍历用户映射，将所有用户指针添加到切片中
	for _, user := range a.users {
		users = append(users, user) // 追加用户指针到切片
	}
	return users // 返回用户列表
}

// IncrementUserConnection 增加用户的当前连接计数。
// 当用户建立新连接时调用此函数，用于跟踪并发连接数。
//
// 参数:
//   - username: 要建立连接的用户名
//
// 返回:
//   - int: 增加后的连接数，表示用户当前的活跃连接总数
func (a *PasswordAuth) IncrementUserConnection(username string) int {
	// 获取连接计数的写锁，独立于用户数据锁以减少竞争
	a.connMu.Lock()
	defer a.connMu.Unlock() // 函数返回时自动释放锁

	// 检查映射是否已初始化，防止 nil 映射 panic
	if a.userConnections == nil {
		a.userConnections = make(map[string]int) // 惰性初始化映射
	}
	// 将用户的连接数加 1
	a.userConnections[username]++
	// 返回增加后的连接数
	return a.userConnections[username]
}

// DecrementUserConnection 减少用户的当前连接计数。
// 当用户断开连接时调用此函数，确保计数不会低于 0。
// 当连接数降为0时，自动清理该用户的IP记录以释放内存。
//
// 参数:
//   - username: 要断开连接的用户名
//
// 返回:
//   - int: 减少后的连接数，最小为 0
func (a *PasswordAuth) DecrementUserConnection(username string) int {
	// 获取连接计数的写锁
	a.connMu.Lock()

	// 检查映射是否已初始化
	currentConns := 0
	if a.userConnections != nil {
		// 将用户的连接数减 1
		a.userConnections[username]--
		// 确保计数不低于 0，防止异常情况导致负数
		if a.userConnections[username] <= 0 {
			delete(a.userConnections, username) // 删除连接数为0的用户
			currentConns = 0
		} else {
			currentConns = a.userConnections[username]
		}
	}
	a.connMu.Unlock() // 释放连接计数锁

	// 如果连接数降为0，清理该用户的IP记录
	if currentConns == 0 {
		a.ipMu.Lock()
		if a.userIPs != nil && a.userIPs[username] != nil {
			delete(a.userIPs, username) // 删除用户的IP记录
		}
		a.ipMu.Unlock()
	}

	return currentConns
}

// GetUserConnectionCount 获取用户的当前活跃连接数。
// 使用读锁允许多个查询并发执行。
//
// 参数:
//   - username: 要查询的用户名
//
// 返回:
//   - int: 当前活跃连接数，0 表示无连接或用户不存在
func (a *PasswordAuth) GetUserConnectionCount(username string) int {
	// 获取连接计数的读锁
	a.connMu.RLock()
	defer a.connMu.RUnlock() // 函数返回时自动释放读锁

	// 检查映射是否已初始化
	if a.userConnections == nil {
		return 0 // 映射未初始化，返回 0
	}
	// 返回用户的当前连接数，不存在的 key 返回零值 0
	return a.userConnections[username]
}

// CheckUserConnectionLimit 检查用户是否达到连接数限制。
// 如果用户未设置限制或当前连接数未达上限，则允许新连接。
//
// 参数:
//   - username: 要检查的用户名
//
// 返回:
//   - bool: true 表示允许新连接，false 表示已达限制应拒绝
func (a *PasswordAuth) CheckUserConnectionLimit(username string) bool {
	// 获取用户数据的读锁
	a.mu.RLock()
	// 查找用户信息
	user, exists := a.users[username]
	a.mu.RUnlock() // 立即释放锁

	// 如果用户不存在或没有限制（MaxConnections <= 0），始终允许连接
	if !exists || user.MaxConnections <= 0 {
		return true // 无限制，允许连接
	}

	// 获取连接计数的读锁，检查当前连接数
	a.connMu.RLock()
	currentConns := 0 // 初始化当前连接数
	if a.userConnections != nil {
		currentConns = a.userConnections[username] // 获取用户的当前连接数
	}
	a.connMu.RUnlock() // 释放连接计数锁

	// 比较当前连接数与最大限制，小于限制则允许
	return currentConns < user.MaxConnections
}

// AddUserIP 记录用户的 IP 地址。
// 用于追踪用户从哪些 IP 建立了连接，支持单 IP 连接数限制功能。
// 当用户建立新连接时调用此函数。
//
// 参数:
//   - username: 要建立连接的用户名
//   - ip: 客户端的 IP 地址字符串（如 "192.168.1.100"）
func (a *PasswordAuth) AddUserIP(username, ip string) {
	// 获取 IP 映射的写锁
	a.ipMu.Lock()
	defer a.ipMu.Unlock() // 函数返回时自动释放锁

	// 检查外层映射是否已初始化
	if a.userIPs == nil {
		a.userIPs = make(map[string]map[string]bool) // 惰性初始化外层映射
	}
	// 检查该用户的内层 IP 集合是否已存在
	if a.userIPs[username] == nil {
		a.userIPs[username] = make(map[string]bool) // 为该用户创建新的 IP 集合
	}
	// 将 IP 添加到用户的 IP 集合中，值为 true 表示存在
	a.userIPs[username][ip] = true
}

// RemoveUserIP 移除用户的 IP 地址记录。
// 当用户断开连接时调用此函数，清理不再使用的 IP 记录。
// 如果用户没有其他 IP 了，会清理整个条目以释放内存。
//
// 参数:
//   - username: 要断开连接的用户名
//   - ip: 客户端的 IP 地址字符串
func (a *PasswordAuth) RemoveUserIP(username, ip string) {
	// 获取 IP 映射的写锁
	a.ipMu.Lock()
	defer a.ipMu.Unlock() // 函数返回时自动释放锁

	// 检查映射是否已初始化且用户存在
	if a.userIPs != nil && a.userIPs[username] != nil {
		// 从用户的 IP 集合中删除指定 IP
		delete(a.userIPs[username], ip)
		// 如果该用户没有其他 IP 了，清理整个条目以释放内存
		if len(a.userIPs[username]) == 0 {
			delete(a.userIPs, username) // 删除用户的 IP 集合
		}
	}
}

// GetUserIPCount 获取用户当前连接的不同 IP 数量。
// 用于监控用户从多少个不同的 IP 地址建立了连接。
//
// 参数:
//   - username: 要查询的用户名
//
// 返回:
//   - int: 不同 IP 的数量，0 表示无记录或用户不存在
func (a *PasswordAuth) GetUserIPCount(username string) int {
	// 获取 IP 映射的读锁
	a.ipMu.RLock()
	defer a.ipMu.RUnlock() // 函数返回时自动释放读锁

	// 检查映射是否已初始化且用户存在
	if a.userIPs == nil || a.userIPs[username] == nil {
		return 0 // 无记录，返回 0
	}
	// 返回用户 IP 集合的大小，即不同 IP 的数量
	return len(a.userIPs[username])
}

// CheckUserIPLimit 检查用户是否达到单 IP 连接数限制。
// 如果该 IP 已经连接过，允许再次连接；否则检查不同 IP 的数量是否超限。
// 此功能用于防止用户从过多不同的 IP 地址建立连接。
//
// 参数:
//   - username: 要检查的用户名
//   - ip: 待检查的 IP 地址字符串
//
// 返回:
//   - bool: true 表示允许连接，false 表示 IP 数量超限应拒绝
func (a *PasswordAuth) CheckUserIPLimit(username, ip string) bool {
	// 获取用户数据的读锁，检查用户配置
	a.mu.RLock()
	user, exists := a.users[username]
	// 如果用户不存在或没有限制（MaxIPConnections <= 0），始终允许
	if !exists || user.MaxIPConnections <= 0 {
		a.mu.RUnlock()
		return true // 无限制，允许连接
	}
	a.mu.RUnlock() // 释放用户数据锁

	// 获取 IP 映射的读锁，检查 IP 数量
	a.ipMu.RLock()
	if a.userIPs == nil {
		a.ipMu.RUnlock()
		return true // 映射未初始化，允许连接
	}
	// 获取用户的 IP 集合
	ipSet := a.userIPs[username]
	if ipSet == nil {
		a.ipMu.RUnlock()
		return true // 用户无 IP 记录，允许连接
	}

	// 如果该 IP 已经连接过，允许再次连接（不重复计数）
	if ipSet[ip] {
		a.ipMu.RUnlock()
		return true // IP 已存在，允许连接
	}

	// 获取当前不同 IP 的数量
	currentIPs := len(ipSet)
	a.ipMu.RUnlock() // 释放 IP 映射锁

	// 检查不同 IP 的数量是否超过限制
	return currentIPs < user.MaxIPConnections
}

// GetUserIPs 获取用户当前连接的所有 IP 地址列表。
// 返回 IP 列表的副本，调用者可以安全遍历。
//
// 参数:
//   - username: 要查询的用户名
//
// 返回:
//   - []string: IP 地址字符串切片，空切片表示无记录
func (a *PasswordAuth) GetUserIPs(username string) []string {
	// 获取 IP 映射的读锁
	a.ipMu.RLock()
	defer a.ipMu.RUnlock() // 函数返回时自动释放读锁

	// 检查映射是否已初始化且用户存在
	if a.userIPs == nil || a.userIPs[username] == nil {
		return []string{} // 无记录，返回空切片
	}

	// 预分配切片容量，避免动态扩容
	ips := make([]string, 0, len(a.userIPs[username]))
	// 遍历用户的 IP 集合，将所有 IP 添加到切片中
	for ip := range a.userIPs[username] {
		ips = append(ips, ip) // 追加 IP 到切片
	}
	return ips // 返回 IP 列表
}

// FindUserByIP 根据 IP 地址查找对应的用户名。
// 用于在连接建立时确定用户身份，或进行 IP 相关的审计查询。
// 这是一个 O(n) 复杂度的操作，因为需要遍历所有用户的 IP 集合。
//
// 参数:
//   - ip: 要查找的 IP 地址字符串
//
// 返回:
//   - string: 对应的用户名，空字符串表示未找到
//   - bool: 是否找到匹配的用户
func (a *PasswordAuth) FindUserByIP(ip string) (string, bool) {
	// 获取 IP 映射的读锁
	a.ipMu.RLock()
	defer a.ipMu.RUnlock() // 函数返回时自动释放读锁

	// 检查映射是否已初始化
	if a.userIPs == nil {
		return "", false // 映射未初始化，返回未找到
	}

	// 遍历所有用户的 IP 集合
	for username, ipSet := range a.userIPs {
		// 检查该用户的 IP 集合中是否包含目标 IP
		if ipSet[ip] {
			return username, true // 找到匹配的用户，返回用户名和成功标志
		}
	}
	return "", false // 遍历完成未找到，返回空字符串和失败标志
}

// SetUserMaxIPConnections 设置用户允许的最大不同 IP 连接数。
// 用于控制用户可以从多少个不同的 IP 地址建立连接。
//
// 参数:
//   - username: 要设置限制的用户名
//   - maxIP: 最大不同 IP 数量，0 表示不限制
func (a *PasswordAuth) SetUserMaxIPConnections(username string, maxIP int) {
	// 获取用户数据的写锁
	a.mu.Lock()
	defer a.mu.Unlock() // 函数返回时自动释放锁

	// 从映射中查找用户
	user, exists := a.users[username]
	if !exists {
		return // 用户不存在，直接返回
	}

	// 更新用户的最大 IP 连接数配置
	user.MaxIPConnections = maxIP
	// 记录成功日志
	log.Printf("用户 [%s] 最大 IP 连接数已设置为：%d", username, maxIP)
}

// SelectAuthMethod 协商选择认证方法。
// 从客户端支持的方法列表和服务端支持的方法列表中找到第一个匹配项。
// 优先选择密码认证（更安全），其次是无认证（兼容性）。
// 如果没有任何匹配，返回 AuthNoAccept 表示拒绝连接。
//
// 参数:
//   - clientMethods: 客户端支持的认证方法字节切片
//   - serverMethods: 服务端支持的认证方法字节切片
//
// 返回:
//   - byte: 选定的认证方法，AuthNoAccept(0xFF) 表示无匹配应拒绝连接
func SelectAuthMethod(clientMethods, serverMethods []byte) byte {
	// 第一轮：优先尝试匹配密码认证方法（更安全）
	for _, cm := range clientMethods {
		// 检查客户端是否支持密码认证
		if cm == AuthPassword {
			// 遍历服务端支持的方法，查找密码认证
			for _, sm := range serverMethods {
				if sm == AuthPassword {
					return AuthPassword // 双方都支持密码认证，选择此方法
				}
			}
		}
	}

	// 第二轮：其次尝试匹配无认证方法（兼容性好）
	for _, cm := range clientMethods {
		// 检查客户端是否支持无认证
		if cm == AuthNone {
			// 遍历服务端支持的方法，查找无认证
			for _, sm := range serverMethods {
				if sm == AuthNone {
					return AuthNone // 双方都支持无认证，选择此方法
				}
			}
		}
	}

	// 没有任何匹配的方法，返回拒绝标志
	return AuthNoAccept
}

// SetUserQuota 设置用户的流量配额。
// 支持多种配额周期类型，包括自定义时间段、每日、每周、每月和无限制。
//
// 参数:
//   - username: 要设置配额的用户名
//   - period: 配额周期类型（"custom"=自定义时间段, "daily"=每日重置, "weekly"=每周重置, "monthly"=每月重置, "unlimited"=无限制）
//   - quotaBytes: 配额总量（字节），0 表示无配额
//
// 返回:
//   - bool: 设置是否成功，false 表示用户不存在
func (a *PasswordAuth) SetUserQuota(username, period string, quotaBytes int64) bool {
	// 获取用户数据的写锁
	a.mu.Lock()
	defer a.mu.Unlock() // 函数返回时自动释放锁

	// 从映射中查找用户
	user, exists := a.users[username]
	if !exists {
		return false // 用户不存在，返回失败
	}

	// 更新用户的配额周期和配额总量
	user.QuotaPeriod = period    // 设置配额周期类型
	user.QuotaBytes = quotaBytes // 设置配额总量

	// 处理不同类型的配额周期
	switch period {
	case "custom":
		// 自定义时间段配额
		if quotaBytes > 0 {
			// 检查是否已设置时间段的开始和结束时间
			if user.QuotaStartTime > 0 && user.QuotaEndTime > 0 {
				// 设置配额重置时间为结束时间
				user.QuotaResetTime = user.QuotaEndTime
				// 重置已用流量为 0，使用原子操作确保线程安全
				atomic.StoreInt64(&user.QuotaUsed, 0)
				// 记录成功日志，格式化显示时间段
				log.Printf("用户 [%s] 配额已设置：%d MB，时间段：%s - %s",
					username,
					quotaBytes/1024/1024, // 将字节转换为 MB 便于阅读
					time.Unix(user.QuotaStartTime, 0).Format("2006-01-02 15:04:05"), // 格式化开始时间
					time.Unix(user.QuotaEndTime, 0).Format("2006-01-02 15:04:05"))   // 格式化结束时间
			} else {
				// 时间段尚未设置，记录等待日志
				log.Printf("用户 [%s] 配额已设置：%d MB，等待设置时间段", username, quotaBytes/1024/1024)
			}
		}
	case "daily", "weekly", "monthly":
		// 周期性配额（每日、每周、每月）
		if quotaBytes > 0 {
			// 计算下次重置时间
			nextResetTime := a.calculateNextResetTime(period)
			if nextResetTime > 0 {
				// 设置配额重置时间
				user.QuotaResetTime = nextResetTime
				// 重置已用流量为 0
				atomic.StoreInt64(&user.QuotaUsed, 0)
				// 记录成功日志
				log.Printf("用户 [%s] 配额已设置：%d MB，周期：%s，下次重置：%s",
					username,
					quotaBytes/1024/1024,
					period,
					time.Unix(nextResetTime, 0).Format("2006-01-02 15:04:05"))
			}
		}
	case "unlimited":
		// 无限制配额
		// 重置所有配额相关字段
		atomic.StoreInt64(&user.QuotaUsed, 0)
		user.QuotaResetTime = 0
		user.QuotaStartTime = 0
		user.QuotaEndTime = 0
		log.Printf("用户 [%s] 已设置为无限制配额", username)
	}

	return true // 返回成功
}

// calculateNextResetTime 根据配额周期计算下次重置时间。
// 支持每日、每周、每月三种周期性配额重置策略。
//
// 参数:
//   - period: 配额周期类型（"daily"=每日, "weekly"=每周, "monthly"=每月）
//
// 返回:
//   - int64: 下次重置时间的 Unix 时间戳，0 表示不支持的周期类型
func (a *PasswordAuth) calculateNextResetTime(period string) int64 {
	now := time.Now() // 获取当前时间
	switch period {
	case "daily":
		// 每日重置：计算明天的零点时间
		next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
		return next.Unix() // 返回明天零点的 Unix 时间戳
	case "weekly":
		// 每周重置：计算下个周一的零点时间
		daysUntilMonday := int(time.Monday - now.Weekday()) // 计算距离下周一的天数
		if daysUntilMonday <= 0 {
			daysUntilMonday += 7 // 如果今天是周一或之后，需要加 7 天到下周
		}
		next := time.Date(now.Year(), now.Month(), now.Day()+daysUntilMonday, 0, 0, 0, 0, now.Location())
		return next.Unix() // 返回下周一零点的 Unix 时间戳
	case "monthly":
		// 每月重置：计算下月 1 号的零点时间
		var next time.Time
		if now.Month() == time.December {
			// 如果是 12 月，下月是明年的 1 月
			next = time.Date(now.Year()+1, time.January, 1, 0, 0, 0, 0, now.Location())
		} else {
			// 否则是下个月的 1 号
			next = time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, now.Location())
		}
		return next.Unix() // 返回下月 1 号零点的 Unix 时间戳
	default:
		return 0 // 不支持的周期类型，返回 0
	}
}

// SetUserQuotaTimeRange 设置用户的自定义配额时间段。
// 用于定义配额的生效时间范围，在此范围外用户无法使用服务。
//
// 参数:
//   - username: 要设置时间段的用户名
//   - startTime: 配额开始时间的 Unix 时间戳
//   - endTime: 配额结束时间的 Unix 时间戳
//
// 返回:
//   - bool: 设置是否成功，false 表示用户不存在
func (a *PasswordAuth) SetUserQuotaTimeRange(username string, startTime, endTime int64) bool {
	// 获取用户数据的读锁
	a.mu.RLock()
	user, exists := a.users[username]
	a.mu.RUnlock() // 立即释放锁

	if !exists {
		return false // 用户不存在，返回失败
	}

	// 判断是否是首次设置时间段（之前未设置过）
	isFirstTime := user.QuotaStartTime == 0 || user.QuotaEndTime == 0

	// 使用原子操作更新时间段字段，确保并发安全
	atomic.StoreInt64(&user.QuotaStartTime, startTime) // 设置开始时间
	atomic.StoreInt64(&user.QuotaEndTime, endTime)     // 设置结束时间
	atomic.StoreInt64(&user.QuotaResetTime, endTime)   // 设置重置时间为结束时间

	// 如果是首次设置，重置已用流量为 0
	if isFirstTime {
		atomic.StoreInt64(&user.QuotaUsed, 0)
	}

	// 记录成功日志，格式化显示时间段
	log.Printf("用户 [%s] 自定义时间段配额已设置：%s - %s",
		username,
		time.Unix(startTime, 0).Format("2006-01-02 15:04:05"), // 格式化开始时间
		time.Unix(endTime, 0).Format("2006-01-02 15:04:05"))   // 格式化结束时间

	return true // 返回成功
}

// ClearUserQuota 清除用户的所有配额限制，设置为无限制模式。
// 重置所有配额相关字段为零值或空值。
//
// 参数:
//   - username: 要清除配额的用户名
//
// 返回:
//   - bool: 清除是否成功，false 表示用户不存在
func (a *PasswordAuth) ClearUserQuota(username string) bool {
	// 获取用户数据的读锁
	a.mu.RLock()
	user, exists := a.users[username]
	a.mu.RUnlock() // 立即释放锁

	if !exists {
		return false // 用户不存在，返回失败
	}

	// 使用原子操作清零所有配额相关的时间字段
	atomic.StoreInt64(&user.QuotaStartTime, 0) // 清零开始时间
	atomic.StoreInt64(&user.QuotaEndTime, 0)   // 清零结束时间
	atomic.StoreInt64(&user.QuotaResetTime, 0) // 清零重置时间
	atomic.StoreInt64(&user.QuotaUsed, 0)      // 清零已用流量

	// 清零配额周期和配额总量（非原子字段，直接赋值）
	user.QuotaPeriod = "" // 清空配额周期，表示无限制
	user.QuotaBytes = 0   // 清零配额总量

	// 记录成功日志
	log.Printf("用户 [%s] 已设置为无限制", username)
	return true // 返回成功
}

// CheckQuotaAndReset 检查并重置过期的配额。
// 支持自定义时间段、每日、每周、每月配额的自动重置。
// 此函数应在定期任务中调用，以自动清理过期配额。
//
// 参数:
//   - username: 要检查的用户名
func (a *PasswordAuth) CheckQuotaAndReset(username string) {
	// 获取用户数据的写锁
	a.mu.Lock()
	defer a.mu.Unlock() // 函数返回时自动释放锁

	// 从映射中查找用户
	user, exists := a.users[username]
	if !exists {
		return // 用户不存在，直接返回
	}

	now := time.Now().Unix() // 获取当前 Unix 时间戳

	switch user.QuotaPeriod {
	case "custom":
		// 处理自定义时间段配额
		if user.QuotaBytes > 0 && user.QuotaEndTime > 0 {
			// 检查当前时间是否已超过配额结束时间
			if now > user.QuotaEndTime {
				// 原子加载已用流量
				quotaUsed := atomic.LoadInt64(&user.QuotaUsed)
				// 如果有已用流量，则重置
				if quotaUsed > 0 {
					atomic.StoreInt64(&user.QuotaUsed, 0) // 重置已用流量为 0
					// 记录重置日志，格式化显示时间段
					log.Printf("用户 [%s] 自定义时间段配额已到期，流量已重置：%s - %s",
						username,
						time.Unix(user.QuotaStartTime, 0).Format("2006-01-02 15:04:05"),
						time.Unix(user.QuotaEndTime, 0).Format("2006-01-02 15:04:05"))
				}
			}
		}
	case "daily", "weekly", "monthly":
		// 处理周期性配额
		if user.QuotaBytes > 0 && user.QuotaResetTime > 0 {
			// 检查当前时间是否已超过重置时间
			if now > user.QuotaResetTime {
				// 原子加载已用流量
				quotaUsed := atomic.LoadInt64(&user.QuotaUsed)
				// 如果有已用流量，则重置
				if quotaUsed > 0 {
					atomic.StoreInt64(&user.QuotaUsed, 0) // 重置已用流量为 0
					// 计算下一次重置时间
					nextResetTime := a.calculateNextResetTime(user.QuotaPeriod)
					if nextResetTime > 0 {
						user.QuotaResetTime = nextResetTime
						// 记录重置日志
						log.Printf("用户 [%s] %s 配额已重置，下次重置：%s",
							username,
							user.QuotaPeriod,
							time.Unix(nextResetTime, 0).Format("2006-01-02 15:04:05"))
					}
				}
			}
		}
	}
}

// AddUserTraffic 记录用户的流量使用情况。
// 同时更新上传总量、下载总量、配额使用量和最后活动时间。
// 所有统计字段都使用原子操作确保高并发下的数据一致性。
//
// 参数:
//   - username: 产生流量的用户名
//   - upload: 本次上传的字节数
//   - download: 本次下载的字节数
func (a *PasswordAuth) AddUserTraffic(username string, upload, download int64) {
	// 获取用户数据的读锁
	a.mu.RLock()
	user, exists := a.users[username]
	a.mu.RUnlock() // 立即释放锁

	if !exists {
		return // 用户不存在，直接返回
	}

	// 使用原子操作累加上载和下载总量
	atomic.AddInt64(&user.UploadTotal, upload)     // 累加上载总量
	atomic.AddInt64(&user.DownloadTotal, download) // 累加下载总量

	// 只有当用户设置了配额周期且不是无限时，才累加 QuotaUsed
	// unlimited 或空字符串表示无限制，不需要统计周期内已用流量
	if user.QuotaPeriod != "" && user.QuotaPeriod != "unlimited" {
		atomic.AddInt64(&user.QuotaUsed, upload+download) // 累加总流量到配额使用量
	}

	// 更新最后活动时间为当前时间，使用原子操作
	atomic.StoreInt64(&user.LastActivity, time.Now().Unix())
}

// CheckQuotaExceeded 检查用户是否超出流量配额或使用时间段限制。
// 支持自定义时间段、每日、每周、每月配额的检查。
//
// 参数:
//   - username: 要检查的用户名
//
// 返回:
//   - bool: true 表示配额已超限应拒绝连接，false 表示可以使用
func (a *PasswordAuth) CheckQuotaExceeded(username string) bool {
	// 获取用户数据的读锁
	a.mu.RLock()
	defer a.mu.RUnlock() // 函数返回时自动释放锁

	// 从映射中查找用户
	user, exists := a.users[username]
	if !exists {
		return false // 用户不存在，返回 false（不阻止）
	}

	// 如果用户没有启用配额管理，始终允许
	if user.QuotaPeriod == "" || user.QuotaPeriod == "unlimited" {
		return false // 无配额限制，允许使用
	}

	switch user.QuotaPeriod {
	case "custom":
		// 处理自定义时间段配额
		now := time.Now().Unix() // 获取当前 Unix 时间戳

		// 原子加载时间段和已用流量
		quotaStartTime := atomic.LoadInt64(&user.QuotaStartTime)
		quotaEndTime := atomic.LoadInt64(&user.QuotaEndTime)
		quotaUsed := atomic.LoadInt64(&user.QuotaUsed)

		// 检查当前时间是否在配额时间段之前
		if now < quotaStartTime {
			// 时间段尚未开始，拒绝连接
			log.Printf("用户 [%s] 配额时间段未开始 (%s)，禁止连接",
				username, time.Unix(quotaStartTime, 0).Format("2006-01-02 15:04:05"))
			return true // 返回 true 表示应拒绝
		}

		// 检查当前时间是否在配额时间段之后
		if now > quotaEndTime {
			// 时间段已结束，拒绝连接
			log.Printf("用户 [%s] 配额时间段已结束 (%s)，禁止连接",
				username, time.Unix(quotaEndTime, 0).Format("2006-01-02 15:04:05"))
			return true // 返回 true 表示应拒绝
		}

		// 检查流量配额是否已用尽
		if user.QuotaBytes > 0 && quotaUsed >= user.QuotaBytes {
			// 流量已用尽，拒绝连接
			log.Printf("用户 [%s] 流量配额已用尽 (%.2f MB / %.2f MB)，禁止连接",
				username, float64(quotaUsed)/1024/1024, float64(user.QuotaBytes)/1024/1024)
			return true // 返回 true 表示应拒绝
		}

	case "daily", "weekly", "monthly":
		// 处理周期性配额
		// 原子加载已用流量
		quotaUsed := atomic.LoadInt64(&user.QuotaUsed)
		// 检查流量配额是否已用尽
		if user.QuotaBytes > 0 && quotaUsed >= user.QuotaBytes {
			// 流量已用尽，拒绝连接
			log.Printf("用户 [%s] 流量配额已用尽 (%.2f MB / %.2f MB)，禁止连接",
				username, float64(quotaUsed)/1024/1024, float64(user.QuotaBytes)/1024/1024)
			return true // 返回 true 表示应拒绝
		}
	}

	return false // 配额未超限，允许使用
}

// GetUserQuotaInfo 获取用户的配额详细信息。
// 返回配额周期、总量、已用量和重置时间。
//
// 参数:
//   - username: 要查询的用户名
//
// 返回:
//   - period: 配额周期类型
//   - total: 配额总量（字节）
//   - used: 已用流量（字节）
//   - resetTime: 下次重置时间（Unix 时间戳）
//   - exists: 用户是否存在
func (a *PasswordAuth) GetUserQuotaInfo(username string) (period string, total int64, used int64, resetTime int64, exists bool) {
	// 获取用户数据的读锁
	a.mu.RLock()
	defer a.mu.RUnlock() // 函数返回时自动释放锁

	// 从映射中查找用户
	user, exists := a.users[username]
	if !exists {
		// 用户不存在，返回零值和 false
		return "", 0, 0, 0, false
	}

	// 返回配额信息，已用流量使用原子加载确保一致性
	return user.QuotaPeriod, user.QuotaBytes, atomic.LoadInt64(&user.QuotaUsed), user.QuotaResetTime, true
}

// GetUserQuotaUsed 获取用户已使用的配额流量。
//
// 参数:
//   - username: 要查询的用户名
//
// 返回:
//   - int64: 已用流量字节数，0 表示用户不存在或无配额
func (a *PasswordAuth) GetUserQuotaUsed(username string) int64 {
	// 获取用户数据的读锁
	a.mu.RLock()
	defer a.mu.RUnlock() // 函数返回时自动释放锁

	// 从映射中查找用户
	user, exists := a.users[username]
	if !exists {
		return 0 // 用户不存在，返回 0
	}
	// 原子加载并返回已用流量
	return atomic.LoadInt64(&user.QuotaUsed)
}

// GetUserQuotaTotal 获取用户的配额总量。
//
// 参数:
//   - username: 要查询的用户名
//
// 返回:
//   - int64: 配额总量字节数，0 表示用户不存在或无配额
func (a *PasswordAuth) GetUserQuotaTotal(username string) int64 {
	// 获取用户数据的读锁
	a.mu.RLock()
	defer a.mu.RUnlock() // 函数返回时自动释放锁

	// 从映射中查找用户
	user, exists := a.users[username]
	if !exists {
		return 0 // 用户不存在，返回 0
	}
	// 返回配额总量（非原子字段，直接读取）
	return user.QuotaBytes
}
