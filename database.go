package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3" // SQLite 驱动
)

// DatabaseManager 数据库管理器
type DatabaseManager struct {
	db *sql.DB
	mu sync.RWMutex
}

// NewDatabaseManager 创建数据库管理器
func NewDatabaseManager(dbPath string) (*DatabaseManager, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败：%w", err)
	}

	manager := &DatabaseManager{
		db: db,
	}

	// 初始化数据库表
	if err := manager.initTables(); err != nil {
		return nil, fmt.Errorf("初始化数据库失败：%w", err)
	}

	return manager, nil
}

// boolToInt 将布尔值转换为整数（SQLite 存储）
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// intToBool 将整数转换为布尔值
func intToBool(i int) bool {
	return i != 0
}

// initTables 初始化数据库表（支持增量创建新表）
func (m *DatabaseManager) initTables() error {
	log.Println("开始初始化/更新数据库表结构...")

	schemas := []string{
		// 用户表
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			read_speed_limit INTEGER DEFAULT 0,
			write_speed_limit INTEGER DEFAULT 0,
			max_connections INTEGER DEFAULT 0,
			max_ip_connections INTEGER DEFAULT 0,
			enabled BOOLEAN DEFAULT 1,
			upload_total INTEGER DEFAULT 0,
			download_total INTEGER DEFAULT 0,
			create_time INTEGER NOT NULL,
			last_activity INTEGER NOT NULL,
			quota_period TEXT DEFAULT '',
			quota_bytes INTEGER DEFAULT 0,
			quota_used INTEGER DEFAULT 0,
			quota_reset_time INTEGER DEFAULT 0,
			quota_start_time INTEGER DEFAULT 0,
			quota_end_time INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// 流量记录表（用于详细统计）
		`CREATE TABLE IF NOT EXISTS traffic_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL,
			upload INTEGER DEFAULT 0,
			download INTEGER DEFAULT 0,
			log_time INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// 连接日志表
		`CREATE TABLE IF NOT EXISTS connection_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL,
			client_ip TEXT,
			action TEXT, -- 'connect' or 'disconnect'
			log_time INTEGER NOT NULL
		)`,

		// 系统配置表
		`CREATE TABLE IF NOT EXISTS system_config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			description TEXT,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// 管理员表
		`CREATE TABLE IF NOT EXISTS admin_users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			enabled BOOLEAN DEFAULT 1,
			create_time INTEGER NOT NULL,
			last_login INTEGER DEFAULT 0,
			last_password_change INTEGER DEFAULT 0,
			force_password_change BOOLEAN DEFAULT 0,
			login_fail_count INTEGER DEFAULT 0,
			last_login_fail_time INTEGER DEFAULT 0,
			lock_until INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	// 创建索引
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_traffic_username ON traffic_logs(username)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_time ON traffic_logs(log_time)`,
		`CREATE INDEX IF NOT EXISTS idx_connection_username ON connection_logs(username)`,
	}

	// 执行创建表的 SQL
	for _, schema := range schemas {
		if _, err := m.db.Exec(schema); err != nil {
			return fmt.Errorf("创建表失败：%w", err)
		}
	}

	log.Println("数据库表结构创建完成")

	// 数据库迁移：为现有的 users 表添加 max_ip_connections 字段
	// 使用 ALTER TABLE ADD COLUMN IF NOT EXISTS 确保幂等性
	if _, err := m.db.Exec(`ALTER TABLE users ADD COLUMN max_ip_connections INTEGER DEFAULT 0`); err != nil {
		// 如果字段已存在，忽略错误
		// SQLite 没有直接的 IF NOT EXISTS 语法，需要捕获错误
		log.Printf("数据库迁移：max_ip_connections 字段可能已存在 - %v", err)
	}

	// 数据库迁移：为现有的 users 表添加 quota 相关字段
	quotaFields := []string{
		"quota_period TEXT DEFAULT ''",
		"quota_bytes INTEGER DEFAULT 0",
		"quota_used INTEGER DEFAULT 0",
		"quota_reset_time INTEGER DEFAULT 0",
		"quota_start_time INTEGER DEFAULT 0",
		"quota_end_time INTEGER DEFAULT 0",
	}
	for _, field := range quotaFields {
		fieldName := field[:strings.Index(field, " ")]
		query := fmt.Sprintf(`ALTER TABLE users ADD COLUMN %s`, field)
		if _, err := m.db.Exec(query); err != nil {
			log.Printf("数据库迁移：%s 字段可能已存在 - %v", fieldName, err)
		}
	}

	// 执行创建索引的 SQL
	for _, index := range indexes {
		if _, err := m.db.Exec(index); err != nil {
			return fmt.Errorf("创建索引失败：%w", err)
		}
	}

	log.Println("数据库索引创建完成")
	log.Println("数据库初始化完成")

	// 数据库迁移：确保 admin_users 表存在（即使数据库已初始化）
	if err := m.migrateAdminUsersTable(); err != nil {
		log.Printf("管理员表迁移失败：%v", err)
	} else {
		log.Println("管理员表已就绪")
	}

	return nil
}

// migrateAdminUsersTable 迁移管理员表（支持增量创建）
func (m *DatabaseManager) migrateAdminUsersTable() error {
	// 检查 admin_users 表是否存在
	var count int
	err := m.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='admin_users'`).Scan(&count)
	if err != nil {
		return fmt.Errorf("查询管理员表状态失败：%w", err)
	}

	// 如果表已存在，无需迁移
	if count > 0 {
		return nil
	}

	log.Println("正在创建管理员表 (admin_users)...")

	// 创建管理员表
	_, err = m.db.Exec(`
		CREATE TABLE IF NOT EXISTS admin_users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			enabled BOOLEAN DEFAULT 1,
			create_time INTEGER NOT NULL,
			last_login INTEGER DEFAULT 0,
			last_password_change INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("创建管理员表失败：%w", err)
	}

	// 创建索引
	_, err = m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_admin_username ON admin_users(username)`)
	if err != nil {
		return fmt.Errorf("创建管理员索引失败：%w", err)
	}

	// 插入默认管理员（如果表中为空）
	var adminCount int
	err = m.db.QueryRow(`SELECT COUNT(*) FROM admin_users`).Scan(&adminCount)
	if err == nil && adminCount == 0 {
		// 插入默认管理员 admin/password123，使用 bcrypt 哈希
		// 注意：这是 bcrypt 哈希值，对应密码 "password123"
		defaultPasswordHash := "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
		now := time.Now().Unix()
		_, err = m.db.Exec(`
			INSERT INTO admin_users (username, password_hash, enabled, create_time, last_password_change, force_password_change)
			VALUES (?, ?, 1, ?, ?, 1)
		`, "admin", defaultPasswordHash, now, now)
		if err != nil {
			return fmt.Errorf("插入默认管理员失败：%w", err)
		}
		log.Println("已插入默认管理员账户：admin / password123（首次登录请修改密码）")
	}

	return nil
}

// isDatabaseInitialized 检查数据库是否已初始化
func (m *DatabaseManager) isDatabaseInitialized() (bool, error) {
	// 查询 sqlite_master 表，检查是否存在 users 表
	query := `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'`
	var count int
	err := m.db.QueryRow(query).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("查询数据库状态失败：%w", err)
	}
	return count > 0, nil
}

// Close 关闭数据库连接
func (m *DatabaseManager) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}

// ========== 管理员 CRUD 操作 ==========

// SaveAdminUser 保存管理员用户（新增或更新）
func (m *DatabaseManager) SaveAdminUser(username, passwordHash string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 检查管理员是否已存在
	var exists bool
	err := m.db.QueryRow("SELECT 1 FROM admin_users WHERE username = ?", username).Scan(&exists)
	if err == sql.ErrNoRows {
		// 插入新管理员
		_, err = m.db.Exec(`
			INSERT INTO admin_users (username, password_hash, enabled, create_time, last_password_change, force_password_change)
			VALUES (?, ?, ?, ?, ?, ?)
		`, username, passwordHash, enabled, time.Now().Unix(), time.Now().Unix(), false)
	} else if err != nil {
		return err
	} else {
		// 更新现有管理员
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
	return err
}

// LoadAdminUsers 加载所有管理员用户到内存（包括禁用的）
func (m *DatabaseManager) LoadAdminUsers(ws *WebServer) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rows, err := m.db.Query(`
		SELECT username, password_hash, enabled, create_time, last_login, last_password_change, 
		       force_password_change, login_fail_count, last_login_fail_time, lock_until
		FROM admin_users
	`)
	if err != nil {
		return fmt.Errorf("查询管理员失败：%w", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var username, passwordHash string
		var enabled, forcePasswordChange bool
		var createTime, lastLogin, lastPasswordChange int64
		var loginFailCount int
		var lastLoginFailTime, lockUntil int64

		if err := rows.Scan(&username, &passwordHash, &enabled, &createTime, &lastLogin, &lastPasswordChange,
			&forcePasswordChange, &loginFailCount, &lastLoginFailTime, &lockUntil); err != nil {
			return fmt.Errorf("扫描管理员数据失败：%w", err)
		}

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

		count++
	}

	if count > 0 {
		log.Printf("已从数据库加载 %d 个管理员（包含已禁用的）", count)
	}

	return rows.Err()
}

// DeleteAdminUser 删除管理员用户
func (m *DatabaseManager) DeleteAdminUser(username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, err := m.db.Exec("DELETE FROM admin_users WHERE username = ?", username)
	return err
}

// ========== 用户 CRUD 操作 ==========

// SaveUser 保存用户到数据库
func (m *DatabaseManager) SaveUser(user *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	query := `
		INSERT INTO users (username, password, read_speed_limit, write_speed_limit, 
			max_connections, max_ip_connections, enabled, upload_total, download_total, 
			create_time, last_activity, quota_period, quota_bytes, quota_used, quota_reset_time,
			quota_start_time, quota_end_time)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
			password = excluded.password,
			read_speed_limit = excluded.read_speed_limit,
			write_speed_limit = excluded.write_speed_limit,
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

	_, err := m.db.Exec(query,
		user.Username,
		user.Password,
		user.ReadSpeedLimit,
		user.WriteSpeedLimit,
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
}

// GetUser 从数据库获取用户
func (m *DatabaseManager) GetUser(username string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	query := `
		SELECT username, password, read_speed_limit, write_speed_limit,
			max_connections, max_ip_connections, enabled, upload_total, download_total,
			create_time, last_activity, quota_period, quota_bytes, quota_used, quota_reset_time,
			quota_start_time, quota_end_time
		FROM users
		WHERE username = ?
	`

	user := &User{}
	err := m.db.QueryRow(query, username).Scan(
		&user.Username,
		&user.Password,
		&user.ReadSpeedLimit,
		&user.WriteSpeedLimit,
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
		return nil, nil
	}

	return user, err
}

// GetAllUsers 获取所有用户（完整字段版）
func (m *DatabaseManager) GetAllUsers() ([]*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	log.Printf("[DEBUG] GetAllUsers 开始执行 SQL 查询...")
	query := `
		SELECT username, password, read_speed_limit, write_speed_limit,
			max_connections, max_ip_connections, enabled, upload_total, download_total,
			create_time, last_activity, quota_period, quota_bytes, quota_used, quota_reset_time,
			quota_start_time, quota_end_time
		FROM users
		ORDER BY username
	`

	rows, err := m.db.Query(query)
	if err != nil {
		log.Printf("[ERROR] GetAllUsers SQL 查询失败：%v", err)
		return nil, err
	}
	defer rows.Close()

	var users []*User
	count := 0
	for rows.Next() {
		user := &User{}
		err := rows.Scan(
			&user.Username,
			&user.Password,
			&user.ReadSpeedLimit,
			&user.WriteSpeedLimit,
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
		users = append(users, user)
		count++
		log.Printf("[DEBUG] 扫描到用户 %d: %s", count, user.Username)
	}

	if err = rows.Err(); err != nil {
		log.Printf("[ERROR] GetAllUsers rows.Err: %v", err)
		return nil, err
	}

	log.Printf("[INFO] GetAllUsers 完成，共 %d 个用户", count)
	return users, rows.Err()
}

// DeleteUser 从数据库删除用户
func (m *DatabaseManager) DeleteUser(username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, err := m.db.Exec("DELETE FROM users WHERE username = ?", username)
	return err
}

// LoadAllUsersToAuth 从数据库加载所有用户到认证器
func (m *DatabaseManager) LoadAllUsersToAuth(auth *PasswordAuth) error {
	log.Printf("[INFO] 开始从数据库加载用户...")
	users, err := m.GetAllUsers()
	if err != nil {
		log.Printf("[ERROR] GetAllUsers 失败：%v", err)
		return err
	}
	log.Printf("[INFO] 从数据库查询到 %d 个用户", len(users))

	auth.mu.Lock()
	defer auth.mu.Unlock()

	// 确保 users map 已初始化
	if auth.users == nil {
		auth.users = make(map[string]*User)
	}
	// 确保 userConnections map 已初始化
	if auth.userConnections == nil {
		auth.userConnections = make(map[string]int)
	}
	// 确保 userIPs map 已初始化
	if auth.userIPs == nil {
		auth.userIPs = make(map[string]map[string]bool)
	}

	for i, user := range users {
		auth.users[user.Username] = user
		log.Printf("[DEBUG] 加载用户 %d: %s (配额：%d MB, 已用：%d MB)",
			i+1, user.Username, user.QuotaBytes/1024/1024, user.QuotaUsed/1024/1024)
	}

	log.Printf("[INFO] 完成加载 %d 个用户到认证器，当前认证器用户总数：%d", len(users), len(auth.users))
	return nil
}

// ========== 流量日志操作 ==========

// LogTraffic 记录流量日志
func (m *DatabaseManager) LogTraffic(username string, upload, download int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	query := `
		INSERT INTO traffic_logs (username, upload, download, log_time)
		VALUES (?, ?, ?, ?)
	`

	_, err := m.db.Exec(query, username, upload, download, time.Now().Unix())
	return err
}

// CleanOldTrafficLogs 清理旧的流量日志
// retentionDays: 保留天数，只保留最近 N 天的数据
func (m *DatabaseManager) CleanOldTrafficLogs(retentionDays int) error {
	// 检查数据库是否初始化
	if m == nil || m.db == nil {
		log.Printf("警告：数据库未初始化，跳过流量日志清理")
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if retentionDays <= 0 {
		return fmt.Errorf("保留天数必须大于 0")
	}

	// 计算保留的截止时间戳
	cutoffTime := time.Now().AddDate(0, 0, -retentionDays).Unix()

	query := `
		DELETE FROM traffic_logs
		WHERE log_time < ?
	`

	result, err := m.db.Exec(query, cutoffTime)
	if err != nil {
		return fmt.Errorf("清理流量日志失败：%w", err)
	}

	// 获取删除的行数
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("获取删除行数失败：%v", err)
	} else {
		log.Printf("清理流量日志：删除了 %d 条 %d 天前的记录", rowsAffected, retentionDays)
	}

	return nil
}

// GetTrafficLogsCount 获取流量日志总数
func (m *DatabaseManager) GetTrafficLogsCount() (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	query := `SELECT COUNT(*) FROM traffic_logs`
	var count int64
	err := m.db.QueryRow(query).Scan(&count)
	return count, err
}

// GetTrafficStats 获取流量统计
func (m *DatabaseManager) GetTrafficStats(username string, startTime, endTime int64) (totalUpload, totalDownload int64, err error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	query := `
		SELECT COALESCE(SUM(upload), 0), COALESCE(SUM(download), 0)
		FROM traffic_logs
		WHERE username = ? AND log_time BETWEEN ? AND ?
	`

	err = m.db.QueryRow(query, username, startTime, endTime).Scan(&totalUpload, &totalDownload)
	return
}

// GetUserTrafficReport 获取用户流量报告
func (m *DatabaseManager) GetUserTrafficReport(username string, days int) ([]map[string]interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 获取每天的流量统计
	query := `
		SELECT DATE(datetime(log_time, 'unixepoch')) as date,
			   SUM(upload) as upload,
			   SUM(download) as download
		FROM traffic_logs
		WHERE username = ? AND log_time >= strftime('%s', datetime('now', '-' || ? || ' days'))
		GROUP BY DATE(datetime(log_time, 'unixepoch'))
		ORDER BY date DESC
	`

	rows, err := m.db.Query(query, username, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reports []map[string]interface{}
	for rows.Next() {
		var date string
		var upload, download int64
		if err := rows.Scan(&date, &upload, &download); err != nil {
			return nil, err
		}
		reports = append(reports, map[string]interface{}{
			"date":     date,
			"upload":   upload,
			"download": download,
		})
	}

	return reports, rows.Err()
}

// LogConnection 记录连接日志
func (m *DatabaseManager) LogConnection(username, clientIP, action string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	query := `
		INSERT INTO connection_logs (username, client_ip, action, log_time)
		VALUES (?, ?, ?, ?)
	`

	_, err := m.db.Exec(query, username, clientIP, action, time.Now().Unix())
	return err
}

// ExportUserData 导出用户数据为 JSON
// 参数 username: 要导出的用户名
// 返回：JSON 格式的用户数据和可能的错误
func (m *DatabaseManager) ExportUserData(username string) (string, error) {
	user, err := m.GetUser(username)
	if err != nil {
		return "", err
	}
	if user == nil {
		return "", fmt.Errorf("用户不存在")
	}

	data, err := json.Marshal(user)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// GetConfig 获取系统配置项
func (m *DatabaseManager) GetConfig(key string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var value string
	err := m.db.QueryRow("SELECT value FROM system_config WHERE key = ?", key).Scan(&value)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil // 配置项不存在
		}
		return "", err
	}
	return value, nil
}

// GetIntConfig 获取整数类型配置项
func (m *DatabaseManager) GetIntConfig(key string) (int64, error) {
	value, err := m.GetConfig(key)
	if err != nil || value == "" {
		return 0, err
	}

	var result int64
	_, err = fmt.Sscanf(value, "%d", &result)
	if err != nil {
		return 0, err
	}
	return result, nil
}

// GetInt64Config 获取 int64 类型配置项
func (m *DatabaseManager) GetInt64Config(key string) (int64, error) {
	value, err := m.GetConfig(key)
	if err != nil || value == "" {
		return 0, err
	}

	var result int64
	_, err = fmt.Sscanf(value, "%d", &result)
	if err != nil {
		return 0, err
	}
	return result, nil
}

// SetConfig 设置系统配置项
func (m *DatabaseManager) SetConfig(key, value, description string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 检查配置项是否存在
	var exists bool
	err := m.db.QueryRow("SELECT 1 FROM system_config WHERE key = ?", key).Scan(&exists)
	if err == sql.ErrNoRows {
		// 插入新配置
		_, err = m.db.Exec(
			"INSERT INTO system_config (key, value, description) VALUES (?, ?, ?)",
			key, value, description,
		)
	} else if err != nil {
		return err
	} else {
		// 更新现有配置
		_, err = m.db.Exec(
			"UPDATE system_config SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?",
			value, key,
		)
	}
	return err
}

// DeleteConfig 删除系统配置项
func (m *DatabaseManager) DeleteConfig(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, err := m.db.Exec("DELETE FROM system_config WHERE key = ?", key)
	return err
}
