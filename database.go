// Package main 实现 SOCKS5 代理服务器的数据库管理模块。
// 使用 SQLite3 作为后端存储，提供用户数据持久化、流量日志记录、
// 连接日志、系统配置和 Web 管理员账户管理功能。
package main

import (
	"database/sql"  // 导入数据库 SQL 包，提供通用的数据库接口
	"encoding/json" // 导入 JSON 编码包，用于用户数据的序列化导出
	"fmt"           // 导入格式化包，用于字符串格式化和错误信息包装
	"log"           // 导入日志包，用于记录数据库操作日志
	"sync"          // 导入同步包，提供读写锁保护并发访问
	"sync/atomic"   // 导入原子操作包，提供无锁的线程安全整数操作
	"time"          // 导入时间包，用于时间戳获取和时间计算

	_ "github.com/mattn/go-sqlite3" // 导入 SQLite3 驱动，使用空白标识符仅执行初始化
)

// dbWriteTask 数据库写入任务，用于异步队列处理。
type dbWriteTask struct {
	execFunc func() error // 执行函数，包含具体的数据库写操作
	errChan  chan error   // 错误通道，用于返回执行结果
}

// DatabaseManager 数据库管理器，封装所有数据库操作。
// 使用 SQLite3 作为后端存储，提供用户数据持久化、流量日志记录、
// 连接日志、系统配置和 Web 管理员账户管理功能。
// 使用 sync.RWMutex 确保并发安全，支持多 goroutine 同时访问。
type DatabaseManager struct {
	db *sql.DB      // SQLite3 数据库连接实例，由 sql.Open 创建
	mu sync.RWMutex // 读写锁，保护 db 的并发访问，避免竞态条件

	// === 异步写入队列 ===
	writeQueue chan *dbWriteTask // 写入任务队列，用于串行化数据库写操作
	wg         sync.WaitGroup    // 等待组，用于优雅关闭时等待队列处理完成
	closed     int32             // 关闭标志，atomic 操作：0=运行中，1=已关闭
}

// NewDatabaseManager 创建并初始化数据库管理器。
// 自动打开数据库连接并创建所需的表结构。
// 如果数据库文件不存在，SQLite3 会自动创建。
//
// 参数:
//   - dbPath: SQLite3 数据库文件路径（如 "socks5.db"）
//
// 返回:
//   - *DatabaseManager: 数据库管理器实例
//   - error: 初始化错误，包括打开数据库失败、建表失败等
func NewDatabaseManager(dbPath string) (*DatabaseManager, error) {
	// 打开 SQLite3 数据库连接
	// 第一个参数是驱动名称，第二个参数是数据库文件路径
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败：%w", err) // 包装错误并返回
	}

	// 创建数据库管理器实例
	manager := &DatabaseManager{
		db:         db,                            // 保存数据库连接
		writeQueue: make(chan *dbWriteTask, 1000), // 创建容量为 1000 的写入队列
	}

	// 初始化数据库表结构
	if err := manager.initTables(); err != nil {
		return nil, fmt.Errorf("初始化数据库失败：%w", err) // 包装错误并返回
	}

	// 启动异步写入队列处理协程
	manager.wg.Add(1)
	go manager.processWriteQueue()

	return manager, nil // 返回初始化完成的管理器
}

// boolToInt 将布尔值转换为整数（用于 SQLite3 存储）。
// SQLite3 没有原生的 BOOLEAN 类型，使用 INTEGER 存储（0=false, 1=true）。
//
// 参数:
//   - b: 布尔值
//
// 返回:
//   - int: 1 表示 true，0 表示 false
func boolToInt(b bool) int {
	if b {
		return 1 // true 转换为 1
	}
	return 0 // false 转换为 0
}

// intToBool 将整数转换为布尔值（从 SQLite3 读取）。
// SQLite3 使用 INTEGER 存储 BOOLEAN，0=false，非 0=true。
//
// 参数:
//   - i: 整数值，通常从数据库查询结果中获取
//
// 返回:
//   - bool: 转换后的布尔值，0 为 false，其他值为 true
func intToBool(i int) bool {
	return i != 0 // 非零即为 true
}

// initTables 初始化数据库表结构。
// 创建所有必需的表（users、connection_logs、system_config、admin_users），
// 并添加必要的索引以优化查询性能。
// 使用 CREATE TABLE IF NOT EXISTS 确保重复调用时不会出错。
//
// 返回:
//   - error: 初始化过程中的错误，包括建表失败、创建索引失败等
func (m *DatabaseManager) initTables() error {
	log.Println("开始初始化/更新数据库表结构...") // 记录开始日志

	// 定义核心表结构的 SQL 语句
	schemas := []string{
		// users 表：存储 SOCKS5 用户信息
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,    -- 自增主键 ID
			username TEXT UNIQUE NOT NULL,           -- 用户名，唯一且不能为空
			password TEXT NOT NULL,                  -- bcrypt 加密的密码哈希，不能为空
			read_speed_limit INTEGER DEFAULT 0,      -- 上传速度限制（字节/秒），默认 0 表示不限速
			write_speed_limit INTEGER DEFAULT 0,     -- 下载速度限制（字节/秒），默认 0 表示不限速
			max_connections INTEGER DEFAULT 0,       -- 最大并发连接数，默认 0 表示不限制
			max_ip_connections INTEGER DEFAULT 0,    -- 单 IP 最大连接数，默认 0 表示不限制
			enabled BOOLEAN DEFAULT 1,               -- 是否启用，默认 1（启用）
			upload_total INTEGER DEFAULT 0,          -- 累计上传流量（字节），默认 0
			download_total INTEGER DEFAULT 0,        -- 累计下载流量（字节），默认 0
			create_time INTEGER NOT NULL,            -- 创建时间（Unix 时间戳），不能为空
			last_activity INTEGER NOT NULL,          -- 最后活动时间（Unix 时间戳），不能为空
			quota_period TEXT DEFAULT '',            -- 配额周期类型，默认空字符串表示无限制
			quota_bytes INTEGER DEFAULT 0,           -- 配额总量（字节），默认 0 表示无配额
			quota_used INTEGER DEFAULT 0,            -- 已用配额（字节），默认 0
			quota_reset_time INTEGER DEFAULT 0,      -- 配额重置时间（Unix 时间戳），默认 0
			quota_start_time INTEGER DEFAULT 0,      -- 配额开始时间（Unix 时间戳），默认 0
			quota_end_time INTEGER DEFAULT 0,        -- 配额结束时间（Unix 时间戳），默认 0
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- 记录创建时间，自动生成
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP  -- 记录更新时间，自动生成
		)`,

		// connection_logs 表：记录用户连接/断开事件
		`CREATE TABLE IF NOT EXISTS connection_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,    -- 自增主键 ID
			username TEXT NOT NULL,                  -- 用户名，不能为空
			client_ip TEXT,                          -- 客户端 IP 地址，可为空
			action TEXT,                             -- 动作类型：connect/disconnect
			log_time INTEGER NOT NULL                -- 日志时间（Unix 时间戳），不能为空
		)`,

		// system_config 表：存储系统配置键值对
		`CREATE TABLE IF NOT EXISTS system_config (
			key TEXT PRIMARY KEY,                    -- 配置键名，主键且唯一
			value TEXT NOT NULL,                     -- 配置值，不能为空
			description TEXT,                        -- 配置描述，可为空
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP -- 更新时间，自动生成
		)`,

		// admin_users 表：Web 管理界面的管理员账户
		`CREATE TABLE IF NOT EXISTS admin_users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,    -- 自增主键 ID
			username TEXT UNIQUE NOT NULL,           -- 管理员用户名，唯一且不能为空
			password_hash TEXT NOT NULL,             -- bcrypt 加密的密码哈希，不能为空
			enabled BOOLEAN DEFAULT 1,               -- 是否启用，默认 1（启用）
			create_time INTEGER NOT NULL,            -- 创建时间（Unix 时间戳），不能为空
			last_login INTEGER DEFAULT 0,            -- 最后登录时间，默认 0
			last_password_change INTEGER DEFAULT 0,  -- 最后密码修改时间，默认 0
			force_password_change BOOLEAN DEFAULT 0, -- 是否强制修改密码，默认 0（否）
			login_fail_count INTEGER DEFAULT 0,      -- 登录失败次数，默认 0
			last_login_fail_time INTEGER DEFAULT 0,  -- 最后登录失败时间，默认 0
			lock_until INTEGER DEFAULT 0,            -- 锁定截止时间，默认 0 表示未锁定
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- 记录创建时间，自动生成
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP  -- 记录更新时间，自动生成
		)`,
	}

	// 定义索引以优化查询性能
	indexes := []string{
		// 在 connection_logs 表的 username 字段上创建索引，加速按用户名查询
		`CREATE INDEX IF NOT EXISTS idx_connection_username ON connection_logs(username)`,
	}

	// 执行建表语句
	for _, schema := range schemas {
		if _, err := m.db.Exec(schema); err != nil {
			return fmt.Errorf("创建表失败：%w", err) // 建表失败，返回错误
		}
	}

	log.Println("数据库表结构创建完成") // 记录建表完成日志

	// 执行索引创建
	for _, index := range indexes {
		if _, err := m.db.Exec(index); err != nil {
			return fmt.Errorf("创建索引失败：%w", err) // 创建索引失败，返回错误
		}
	}

	log.Println("数据库索引创建完成") // 记录索引创建完成日志
	log.Println("数据库初始化完成")  // 记录整体初始化完成日志

	return nil // 初始化成功，返回 nil
}

// processWriteQueue 处理数据库写入队列。
// 从队列中取出任务并串行执行，避免并发写入导致的冲突。
// 此协程在后台运行，直到收到关闭信号。
func (m *DatabaseManager) processWriteQueue() {
	defer m.wg.Done() // 确保函数退出时递减等待组计数

	for task := range m.writeQueue { // 从队列中读取任务
		if task == nil {
			continue // 跳过空任务
		}

		// 执行写入操作
		err := task.execFunc()
		// 将错误返回给调用者（如果通道未关闭）
		select {
		case task.errChan <- err:
		default:
			// 通道已关闭或无人接收，忽略
		}
	}
}

// submitWriteTask 提交写入任务到队列，并等待执行结果。
// 如果队列已满或管理器已关闭，会返回错误。
//
// 参数:
//   - execFunc: 执行函数，包含具体的数据库写操作
//
// 返回:
//   - error: 执行错误或队列错误
func (m *DatabaseManager) submitWriteTask(execFunc func() error) error {
	// 检查是否已关闭
	if atomic.LoadInt32(&m.closed) == 1 {
		return fmt.Errorf("数据库管理器已关闭")
	}

	// 创建任务
	task := &dbWriteTask{
		execFunc: execFunc,
		errChan:  make(chan error, 1), // 缓冲通道，防止阻塞
	}

	// 提交到队列（非阻塞）
	select {
	case m.writeQueue <- task:
		// 成功提交
	case <-time.After(5 * time.Second):
		// 超时，队列可能已满
		return fmt.Errorf("数据库写入队列已满，超时 5 秒")
	}

	// 等待执行结果
	select {
	case err := <-task.errChan:
		return err
	case <-time.After(10 * time.Second):
		// 执行超时
		return fmt.Errorf("数据库写入执行超时 10 秒")
	}
}

// isDatabaseInitialized 检查数据库是否已初始化（是否存在 users 表）。
// 通过查询 sqlite_master 系统表判断，这是 SQLite3 的系统元数据表。
//
// 返回:
//   - bool: true=已初始化（users 表存在），false=未初始化
//   - error: 查询错误
func (m *DatabaseManager) isDatabaseInitialized() (bool, error) {
	// 查询 sqlite_master 表中名为 'users' 的表数量
	query := `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'`
	var count int
	// 执行查询并扫描结果
	err := m.db.QueryRow(query).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("查询数据库状态失败：%w", err)
	}
	return count > 0, nil // 如果计数大于 0，说明表存在
}

// Close 关闭数据库连接，释放资源。
// 在程序退出时调用，确保所有 pending 的数据都已持久化。
//
// 返回:
//   - error: 关闭过程中的错误
func (m *DatabaseManager) Close() error {
	// 设置关闭标志
	atomic.StoreInt32(&m.closed, 1)

	// 关闭写入队列通道，停止接收新任务
	close(m.writeQueue)

	// 等待队列处理协程退出
	m.wg.Wait()

	// 关闭数据库连接
	if m.db != nil {
		return m.db.Close()
	}
	return nil // 数据库连接为空，无需操作
}

// SaveAdminUser 保存或更新 Web 管理员账户。
// 如果用户已存在则更新密码和状态，否则插入新记录。
// 使用 UPSERT 逻辑确保幂等性。
//
// 参数:
//   - username: 管理员用户名
//   - passwordHash: bcrypt 加密的密码哈希
//   - enabled: 是否启用账户
func (m *DatabaseManager) SaveAdminUser(username, passwordHash string, enabled bool) error {
	// 获取写锁，确保数据库操作的线程安全
	m.mu.Lock()
	defer m.mu.Unlock() // 函数返回时自动释放锁

	var exists bool
	// 检查管理员是否已存在
	err := m.db.QueryRow("SELECT 1 FROM admin_users WHERE username = ?", username).Scan(&exists)
	if err == sql.ErrNoRows {
		// 新用户，插入记录
		_, err = m.db.Exec(`
			INSERT INTO admin_users (username, password_hash, enabled, create_time, last_password_change, force_password_change)
			VALUES (?, ?, ?, ?, ?, ?)
		`, username, passwordHash, enabled, time.Now().Unix(), time.Now().Unix(), false)
	} else if err != nil {
		return err // 查询出错，返回错误
	} else {
		// 已有用户，更新密码和状态
		_, err = m.db.Exec(`
			UPDATE admin_users 
			SET password_hash = ?, 
			    enabled = ?,
			    updated_at = CURRENT_TIMESTAMP,
			    last_password_change = CASE WHEN ? THEN ? ELSE last_password_change END,
			    force_password_change = false
			WHERE username = ?
		`, passwordHash, enabled, true, time.Now().Unix(), username)
	}
	return err // 返回执行结果
}

// LoadAdminUsers 从数据库加载所有管理员账户到 WebServer 内存中。
// 用于服务器启动时恢复管理员状态。
//
// 参数:
//   - ws: WebServer 实例指针，用于存储加载的管理员数据
//
// 返回:
//   - error: 加载过程中的错误
func (m *DatabaseManager) LoadAdminUsers(ws *WebServer) error {
	// 获取读锁，允许多个加载操作并发执行
	m.mu.RLock()
	defer m.mu.RUnlock() // 函数返回时自动释放读锁

	// 查询所有管理员账户
	rows, err := m.db.Query(`
		SELECT username, password_hash, enabled, create_time, last_login, last_password_change, 
		       force_password_change, login_fail_count, last_login_fail_time, lock_until
		FROM admin_users
	`)
	if err != nil {
		return fmt.Errorf("查询管理员失败：%w", err)
	}
	defer rows.Close() // 确保结果集被关闭

	count := 0 // 计数器，记录加载的管理员数量
	// 遍历查询结果
	for rows.Next() {
		var username, passwordHash string
		var enabled, forcePasswordChange bool
		var createTime, lastLogin, lastPasswordChange int64
		var loginFailCount int
		var lastLoginFailTime, lockUntil int64

		// 扫描一行数据到变量中
		if err := rows.Scan(&username, &passwordHash, &enabled, &createTime, &lastLogin, &lastPasswordChange,
			&forcePasswordChange, &loginFailCount, &lastLoginFailTime, &lockUntil); err != nil {
			return fmt.Errorf("扫描管理员数据失败：%w", err)
		}

		// 将管理员数据存入 WebServer 的内存映射中
		ws.adminMu.Lock()
		ws.adminUsers[username] = &AdminUser{
			Username:            username,
			PasswordHash:        passwordHash,
			Enabled:             enabled,
			CreateTime:          createTime,
			LastLogin:           lastLogin,
			LastPasswordChange:  lastPasswordChange,
			ForcePasswordChange: forcePasswordChange,
			LoginFailCount:      loginFailCount,
			LastLoginFailTime:   lastLoginFailTime,
			LockUntil:           lockUntil,
		}
		ws.adminMu.Unlock()

		count++ // 增加计数
	}

	// 记录加载日志
	if count > 0 {
		log.Printf("已从数据库加载 %d 个管理员（包含已禁用的）", count)
	}

	return rows.Err() // 返回遍历过程中的错误
}

// DeleteAdminUser 删除指定的管理员账户。
//
// 参数:
//   - username: 要删除的管理员用户名
//
// 返回:
//   - error: 删除操作错误
func (m *DatabaseManager) DeleteAdminUser(username string) error {
	// 获取写锁
	m.mu.Lock()
	defer m.mu.Unlock()

	// 执行删除操作
	_, err := m.db.Exec("DELETE FROM admin_users WHERE username = ?", username)
	return err
}

// UpdateUserQuotaUsed 仅更新用户的配额使用量和总流量（轻量级操作）。
// 用于定期将内存中的流量统计数据持久化到数据库，避免频繁全量保存。
// 此方法只更新流量相关字段，比 SaveUser 更高效。
// 使用异步写入队列，避免并发写入冲突。
//
// 参数:
//   - username: 用户名
//   - quotaUsed: 已使用的配额字节数
//   - uploadTotal: 累计上传流量
//   - downloadTotal: 累计下载流量
func (m *DatabaseManager) UpdateUserQuotaUsed(username string, quotaUsed, uploadTotal, downloadTotal int64) error {
	// 提交到异步队列
	return m.submitWriteTask(func() error {
		// 执行更新操作，只更新流量相关字段
		query := `UPDATE users SET quota_used = ?, upload_total = ?, download_total = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?`
		_, err := m.db.Exec(query, quotaUsed, uploadTotal, downloadTotal, username)
		return err
	})
}

// SaveUser 保存或更新 SOCKS5 用户信息到数据库。
// 使用 UPSERT 语法（ON CONFLICT DO UPDATE），如果用户已存在则更新字段。
// 此方法保存用户的所有字段，包括密码、限速、配额等完整信息。
// 使用异步写入队列，避免并发写入冲突。
//
// 参数:
//   - user: 用户信息结构体指针
func (m *DatabaseManager) SaveUser(user *User) error {
	// 提交到异步队列
	return m.submitWriteTask(func() error {
		// 定义 UPSERT 语句：插入新记录或在冲突时更新
		query := `
			INSERT INTO users (username, password,
				max_connections, max_ip_connections, enabled, upload_total, download_total, 
				create_time, last_activity, quota_period, quota_bytes, quota_used, quota_reset_time,
				quota_start_time, quota_end_time)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(username) DO UPDATE SET
				password = excluded.password,
				max_connections = excluded.max_connections,
				max_ip_connections = excluded.max_ip_connections,
				enabled = excluded.enabled,
				upload_total = excluded.upload_total,
				download_total = excluded.download_total,
				last_activity = excluded.last_activity,
				quota_period = excluded.quota_period,
				quota_bytes = excluded.quota_bytes,
				quota_used = excluded.quota_used,
				quota_reset_time = excluded.quota_reset_time,
				quota_start_time = excluded.quota_start_time,
				quota_end_time = excluded.quota_end_time,
				updated_at = CURRENT_TIMESTAMP
		`

		// 执行 UPSERT 操作，传入用户的所有字段
		_, err := m.db.Exec(query,
			user.Username,
			user.Password,
			user.MaxConnections,
			user.MaxIPConnections,
			user.Enabled,
			user.UploadTotal,
			user.DownloadTotal,
			user.CreateTime,
			user.LastActivity,
			user.QuotaPeriod,
			user.QuotaBytes,
			user.QuotaUsed,
			user.QuotaResetTime,
			user.QuotaStartTime,
			user.QuotaEndTime,
		)

		return err
	})
}

// GetUser 根据用户名获取用户信息。
//
// 参数:
//   - username: 用户名
//
// 返回:
//   - *User: 用户信息指针，nil 表示用户不存在
//   - error: 查询错误
func (m *DatabaseManager) GetUser(username string) (*User, error) {
	// 获取读锁
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 定义查询语句
	query := `
		SELECT username, password,
			max_connections, max_ip_connections, enabled, upload_total, download_total,
			create_time, last_activity, quota_period, quota_bytes, quota_used, quota_reset_time,
			quota_start_time, quota_end_time
		FROM users
		WHERE username = ?
	`

	// 创建用户结构体
	user := &User{}
	// 执行查询并扫描结果到结构体中
	err := m.db.QueryRow(query, username).Scan(
		&user.Username,
		&user.Password,
		&user.MaxConnections,
		&user.MaxIPConnections,
		&user.Enabled,
		&user.UploadTotal,
		&user.DownloadTotal,
		&user.CreateTime,
		&user.LastActivity,
		&user.QuotaPeriod,
		&user.QuotaBytes,
		&user.QuotaUsed,
		&user.QuotaResetTime,
		&user.QuotaStartTime,
		&user.QuotaEndTime,
	)

	if err == sql.ErrNoRows {
		return nil, nil // 用户不存在，返回 nil, nil
	}

	return user, err // 返回用户信息和可能的错误
}

// GetAllUsers 获取所有用户列表，按用户名排序。
//
// 返回:
//   - []*User: 用户列表
//   - error: 查询错误
func (m *DatabaseManager) GetAllUsers() ([]*User, error) {
	// 获取读锁
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 定义查询语句，按用户名排序
	query := `
		SELECT username, password,
			max_connections, max_ip_connections, enabled, upload_total, download_total,
			create_time, last_activity, quota_period, quota_bytes, quota_used, quota_reset_time,
			quota_start_time, quota_end_time
		FROM users
		ORDER BY username
	`

	// 执行查询
	rows, err := m.db.Query(query)
	if err != nil {
		log.Printf("[ERROR] GetAllUsers SQL 查询失败：%v", err)
		return nil, err
	}
	defer rows.Close() // 确保结果集被关闭

	var users []*User // 用户列表切片
	count := 0        // 计数器

	// 遍历查询结果
	for rows.Next() {
		user := &User{} // 创建新的用户结构体
		// 扫描一行数据
		err := rows.Scan(
			&user.Username,
			&user.Password,
			&user.MaxConnections,
			&user.MaxIPConnections,
			&user.Enabled,
			&user.UploadTotal,
			&user.DownloadTotal,
			&user.CreateTime,
			&user.LastActivity,
			&user.QuotaPeriod,
			&user.QuotaBytes,
			&user.QuotaUsed,
			&user.QuotaResetTime,
			&user.QuotaStartTime,
			&user.QuotaEndTime,
		)
		if err != nil {
			log.Printf("[ERROR] GetAllUsers Scan 失败：%v", err)
			return nil, err
		}
		users = append(users, user) // 添加到列表
		count++
	}

	// 检查遍历过程中是否有错误
	if err = rows.Err(); err != nil {
		log.Printf("[ERROR] GetAllUsers rows.Err: %v", err)
		return nil, err
	}

	return users, rows.Err() // 返回用户列表
}

// DeleteUser 删除指定的用户及其相关数据。
// 注意：此方法只删除 users 表中的记录，不会级联删除相关日志。
//
// 参数:
//   - username: 要删除的用户名
//
// 返回:
//   - error: 删除操作错误
func (m *DatabaseManager) DeleteUser(username string) error {
	// 获取写锁
	m.mu.Lock()
	defer m.mu.Unlock()

	// 执行删除操作
	_, err := m.db.Exec("DELETE FROM users WHERE username = ?", username)
	return err
}

// LoadAllUsersToAuth 从数据库加载所有用户到内存认证器中。
// 用于服务器启动时恢复用户状态，将数据库中的用户数据同步到内存中的 PasswordAuth。
//
// 参数:
//   - auth: PasswordAuth 实例指针，用于存储加载的用户数据
//
// 返回:
//   - error: 加载过程中的错误
func (m *DatabaseManager) LoadAllUsersToAuth(auth *PasswordAuth) error {

	// 从数据库获取所有用户
	users, err := m.GetAllUsers()
	if err != nil {
		log.Printf("[ERROR] GetAllUsers 失败：%v", err)
		return err
	}

	// 获取认证器的写锁
	auth.mu.Lock()
	defer auth.mu.Unlock()

	// 确保映射已初始化
	if auth.users == nil {
		auth.users = make(map[string]*User)
	}
	if auth.userConnections == nil {
		auth.userConnections = make(map[string]int)
	}
	if auth.userIPs == nil {
		auth.userIPs = make(map[string]map[string]bool)
	}

	// 将所有用户存入内存映射
	for _, user := range users {
		auth.users[user.Username] = user
	}

	return nil
}

// LogTraffic 记录用户流量日志（当前为空实现，保留接口）。
//
// 参数:
//   - username: 用户名
//   - upload: 上传流量
//   - download: 下载流量
//
// 返回:
//   - error: 始终返回 nil
func (m *DatabaseManager) LogTraffic(username string, upload, download int64) error {
	return nil // 空实现
}

// LogTotalTraffic 记录总流量日志。
// 如果上传和下载都为 0，则跳过记录。
//
// 参数:
//   - upload: 上传流量
//   - download: 下载流量
//
// 返回:
//   - error: 记录错误
func (m *DatabaseManager) LogTotalTraffic(upload, download int64) error {
	// 如果流量都为 0，跳过记录
	if upload == 0 && download == 0 {
		return nil
	}

	// 获取写锁
	m.mu.Lock()
	defer m.mu.Unlock()

	// 插入流量日志记录
	query := `
		INSERT INTO total_traffic_logs (upload, download, log_time)
		VALUES (?, ?, ?)
	`

	_, err := m.db.Exec(query, upload, download, time.Now().Unix())
	return err
}

// CleanOldTrafficLogs 清理旧的流量日志（当前为空实现，保留接口）。
//
// 参数:
//   - retentionDays: 保留天数
//
// 返回:
//   - error: 始终返回 nil
func (m *DatabaseManager) CleanOldTrafficLogs(retentionDays int) error {
	return nil // 空实现
}

// GetTrafficLogsCount 获取流量日志数量（当前为空实现，保留接口）。
//
// 返回:
//   - int64: 始终返回 0
//   - error: 始终返回 nil
func (m *DatabaseManager) GetTrafficLogsCount() (int64, error) {
	return 0, nil // 空实现
}

// GetTrafficStats 获取指定时间段内的流量统计（当前为空实现，保留接口）。
//
// 参数:
//   - username: 用户名
//   - startTime: 开始时间
//   - endTime: 结束时间
//
// 返回:
//   - totalUpload: 总上传流量
//   - totalDownload: 总下载流量
//   - error: 错误
func (m *DatabaseManager) GetTrafficStats(username string, startTime, endTime int64) (totalUpload, totalDownload int64, err error) {
	return 0, 0, nil // 空实现
}

// GetUserTrafficReport 获取用户流量报告（当前为空实现，保留接口）。
//
// 参数:
//   - username: 用户名
//   - days: 天数
//
// 返回:
//   - []map[string]interface{}: 空的报告列表
//   - error: 错误
func (m *DatabaseManager) GetUserTrafficReport(username string, days int) ([]map[string]interface{}, error) {
	return []map[string]interface{}{}, nil // 空实现
}

// LogConnection 记录用户连接/断开事件。
// 用于审计和追踪用户的连接历史。
//
// 参数:
//   - username: 用户名
//   - clientIP: 客户端 IP 地址
//   - action: 动作类型（"connect"=连接, "disconnect"=断开）
func (m *DatabaseManager) LogConnection(username, clientIP, action string) error {
	// 获取写锁
	m.mu.Lock()
	defer m.mu.Unlock()

	// 插入连接日志记录
	query := `
		INSERT INTO connection_logs (username, client_ip, action, log_time)
		VALUES (?, ?, ?, ?)
	`

	_, err := m.db.Exec(query, username, clientIP, action, time.Now().Unix())
	return err
}

// ExportUserData 导出指定用户的完整数据为 JSON 格式。
// 用于数据备份或迁移，导出的数据包含用户的所有配置和统计信息。
//
// 参数:
//   - username: 要导出的用户名
//
// 返回:
//   - string: JSON 格式的用户数据
//   - error: 导出错误
func (m *DatabaseManager) ExportUserData(username string) (string, error) {
	// 从数据库获取用户信息
	user, err := m.GetUser(username)
	if err != nil {
		return "", err
	}
	if user == nil {
		return "", fmt.Errorf("用户不存在") // 用户不存在，返回错误
	}

	// 将用户结构体序列化为 JSON
	data, err := json.Marshal(user)
	if err != nil {
		return "", err
	}

	return string(data), nil // 返回 JSON 字符串
}

// GetConfig 获取系统配置项的值。
//
// 参数:
//   - key: 配置键名
//
// 返回:
//   - string: 配置值，空字符串表示配置不存在
//   - error: 查询错误
func (m *DatabaseManager) GetConfig(key string) (string, error) {
	// 获取读锁
	m.mu.RLock()
	defer m.mu.RUnlock()

	var value string
	// 执行查询
	err := m.db.QueryRow("SELECT value FROM system_config WHERE key = ?", key).Scan(&value)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil // 配置不存在，返回空字符串
		}
		return "", err // 查询错误
	}
	return value, nil // 返回配置值
}

// GetIntConfig 获取整数类型的系统配置项。
// 内部调用 GetConfig 获取字符串值，然后解析为 int64。
//
// 参数:
//   - key: 配置键名
//
// 返回:
//   - int64: 配置值，0 表示配置不存在或解析失败
//   - error: 查询或解析错误
func (m *DatabaseManager) GetIntConfig(key string) (int64, error) {
	// 获取字符串配置值
	value, err := m.GetConfig(key)
	if err != nil || value == "" {
		return 0, err
	}

	var result int64
	// 解析字符串为整数
	_, err = fmt.Sscanf(value, "%d", &result)
	if err != nil {
		return 0, err
	}
	return result, nil
}

// GetInt64Config 获取 64 位整数类型的系统配置项。
// 与 GetIntConfig 功能相同，保留此方法以保持 API 一致性。
//
// 参数:
//   - key: 配置键名
//
// 返回:
//   - int64: 配置值，0 表示配置不存在或解析失败
//   - error: 查询或解析错误
func (m *DatabaseManager) GetInt64Config(key string) (int64, error) {
	// 获取字符串配置值
	value, err := m.GetConfig(key)
	if err != nil || value == "" {
		return 0, err
	}

	var result int64
	// 解析字符串为整数
	_, err = fmt.Sscanf(value, "%d", &result)
	if err != nil {
		return 0, err
	}
	return result, nil
}

// SetConfig 设置系统配置项。
// 如果配置已存在则更新值和时间戳，否则插入新记录。
//
// 参数:
//   - key: 配置键名
//   - value: 配置值
//   - description: 配置描述
func (m *DatabaseManager) SetConfig(key, value, description string) error {
	// 获取写锁
	m.mu.Lock()
	defer m.mu.Unlock()

	var exists bool
	// 检查配置是否已存在
	err := m.db.QueryRow("SELECT 1 FROM system_config WHERE key = ?", key).Scan(&exists)
	if err == sql.ErrNoRows {
		// 配置不存在，插入新记录
		_, err = m.db.Exec(
			"INSERT INTO system_config (key, value, description) VALUES (?, ?, ?)",
			key, value, description,
		)
	} else if err != nil {
		return err // 查询出错
	} else {
		// 配置已存在，更新值和更新时间
		_, err = m.db.Exec(
			"UPDATE system_config SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?",
			value, key,
		)
	}
	return err
}

// DeleteConfig 删除指定的系统配置项。
//
// 参数:
//   - key: 要删除的配置键名
//
// 返回:
//   - error: 删除操作错误
func (m *DatabaseManager) DeleteConfig(key string) error {
	// 获取写锁
	m.mu.Lock()
	defer m.mu.Unlock()

	// 执行删除操作
	_, err := m.db.Exec("DELETE FROM system_config WHERE key = ?", key)
	return err
}
