package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
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

// initTables 初始化数据库表
func (m *DatabaseManager) initTables() error {
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
			group_name TEXT DEFAULT '',
			upload_total INTEGER DEFAULT 0,
			download_total INTEGER DEFAULT 0,
			create_time INTEGER NOT NULL,
			last_activity INTEGER NOT NULL,
			quota_period TEXT DEFAULT '',
			quota_bytes INTEGER DEFAULT 0,
			quota_used INTEGER DEFAULT 0,
			quota_reset_time INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// 用户分组表
		`CREATE TABLE IF NOT EXISTS user_groups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			description TEXT,
			read_speed_limit INTEGER DEFAULT 0,
			write_speed_limit INTEGER DEFAULT 0,
			max_connections INTEGER DEFAULT 0,
			members INTEGER DEFAULT 0,
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
	}

	// 创建索引
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_traffic_username ON traffic_logs(username)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_time ON traffic_logs(log_time)`,
		`CREATE INDEX IF NOT EXISTS idx_connection_username ON connection_logs(username)`,
		`CREATE INDEX IF NOT EXISTS idx_users_group ON users(group_name)`,
	}

	// 执行创建表的 SQL
	for _, schema := range schemas {
		if _, err := m.db.Exec(schema); err != nil {
			return fmt.Errorf("创建表失败：%w", err)
		}
	}

	// 数据库迁移：为现有的 users 表添加 max_ip_connections 字段
	// 使用 ALTER TABLE ADD COLUMN IF NOT EXISTS 确保幂等性
	_, err := m.db.Exec(`ALTER TABLE users ADD COLUMN max_ip_connections INTEGER DEFAULT 0`)
	if err != nil {
		// 如果字段已存在，忽略错误
		// SQLite 没有直接的 IF NOT EXISTS 语法，需要捕获错误
		log.Printf("数据库迁移：max_ip_connections 字段可能已存在 - %v", err)
	}

	// 执行创建索引的 SQL
	for _, index := range indexes {
		if _, err := m.db.Exec(index); err != nil {
			return fmt.Errorf("创建索引失败：%w", err)
		}
	}

	return nil
}

// Close 关闭数据库连接
func (m *DatabaseManager) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}

// ========== 用户 CRUD 操作 ==========

// SaveUser 保存用户到数据库
func (m *DatabaseManager) SaveUser(user *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	query := `
		INSERT INTO users (username, password, read_speed_limit, write_speed_limit, 
			max_connections, max_ip_connections, enabled, group_name, upload_total, download_total, 
			create_time, last_activity, quota_period, quota_bytes, quota_used, quota_reset_time)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
			password = excluded.password,
			read_speed_limit = excluded.read_speed_limit,
			write_speed_limit = excluded.write_speed_limit,
			max_connections = excluded.max_connections,
			max_ip_connections = excluded.max_ip_connections,
			enabled = excluded.enabled,
			group_name = excluded.group_name,
			upload_total = excluded.upload_total,
			download_total = excluded.download_total,
			last_activity = excluded.last_activity,
			quota_period = excluded.quota_period,
			quota_bytes = excluded.quota_bytes,
			quota_used = excluded.quota_used,
			quota_reset_time = excluded.quota_reset_time,
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
		user.Group,
		user.UploadTotal,
		user.DownloadTotal,
		user.CreateTime,
		user.LastActivity,
		user.QuotaPeriod,
		user.QuotaBytes,
		user.QuotaUsed,
		user.QuotaResetTime,
	)

	return err
}

// GetUser 从数据库获取用户
func (m *DatabaseManager) GetUser(username string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	query := `
		SELECT username, password, read_speed_limit, write_speed_limit,
			max_connections, max_ip_connections, enabled, group_name, upload_total, download_total,
			create_time, last_activity, quota_period, quota_bytes, quota_used, quota_reset_time
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
		&user.Group,
		&user.UploadTotal,
		&user.DownloadTotal,
		&user.CreateTime,
		&user.LastActivity,
		&user.QuotaPeriod,
		&user.QuotaBytes,
		&user.QuotaUsed,
		&user.QuotaResetTime,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	return user, err
}

// GetAllUsers 获取所有用户
func (m *DatabaseManager) GetAllUsers() ([]*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	query := `
		SELECT username, password, read_speed_limit, write_speed_limit,
			max_connections, max_ip_connections, enabled, group_name, upload_total, download_total,
			create_time, last_activity
		FROM users
		ORDER BY username
	`

	rows, err := m.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
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
			&user.Group,
			&user.UploadTotal,
			&user.DownloadTotal,
			&user.CreateTime,
			&user.LastActivity,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

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
	users, err := m.GetAllUsers()
	if err != nil {
		return err
	}

	auth.mu.Lock()
	defer auth.mu.Unlock()

	for _, user := range users {
		auth.users[user.Username] = user
	}

	return nil
}

// ========== 分组 CRUD 操作 ==========

// SaveGroup 保存分组到数据库
func (m *DatabaseManager) SaveGroup(group *UserGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	query := `
		INSERT INTO user_groups (name, description, read_speed_limit, 
			write_speed_limit, max_connections, members)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			description = excluded.description,
			read_speed_limit = excluded.read_speed_limit,
			write_speed_limit = excluded.write_speed_limit,
			max_connections = excluded.max_connections,
			members = excluded.members,
			updated_at = CURRENT_TIMESTAMP
	`

	_, err := m.db.Exec(query,
		group.Name,
		group.Description,
		group.ReadSpeedLimit,
		group.WriteSpeedLimit,
		group.MaxConnections,
		group.Members,
	)

	return err
}

// GetGroup 从数据库获取分组
func (m *DatabaseManager) GetGroup(name string) (*UserGroup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	query := `
		SELECT name, description, read_speed_limit, write_speed_limit,
			max_connections, members
		FROM user_groups
		WHERE name = ?
	`

	group := &UserGroup{}
	err := m.db.QueryRow(query, name).Scan(
		&group.Name,
		&group.Description,
		&group.ReadSpeedLimit,
		&group.WriteSpeedLimit,
		&group.MaxConnections,
		&group.Members,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return group, nil
}

// GetAllGroups 获取所有分组
func (m *DatabaseManager) GetAllGroups() ([]*UserGroup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	query := `
		SELECT name, description, read_speed_limit, write_speed_limit,
			max_connections, members
		FROM user_groups
		ORDER BY name
	`

	rows, err := m.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []*UserGroup
	for rows.Next() {
		group := &UserGroup{}
		err := rows.Scan(
			&group.Name,
			&group.Description,
			&group.ReadSpeedLimit,
			&group.WriteSpeedLimit,
			&group.MaxConnections,
			&group.Members,
		)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}

	return groups, rows.Err()
}

// DeleteGroup 从数据库删除分组
func (m *DatabaseManager) DeleteGroup(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, err := m.db.Exec("DELETE FROM user_groups WHERE name = ?", name)
	return err
}

// LoadAllGroupsToAuth 从数据库加载所有分组到认证器
func (m *DatabaseManager) LoadAllGroupsToAuth(auth *PasswordAuth) error {
	groups, err := m.GetAllGroups()
	if err != nil {
		return err
	}

	auth.mu.Lock()
	defer auth.mu.Unlock()

	for _, group := range groups {
		auth.groups[group.Name] = group
	}

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
func (m *DatabaseManager) ExportUserData(username string) (string, error) {
	user, err := m.GetUser(username)
	if err != nil {
		return "", err
	}
	if user == nil {
		return "", fmt.Errorf("用户不存在")
	}

	data, err := json.MarshalIndent(map[string]interface{}{
		"user": user,
	}, "", "  ")

	return string(data), err
}
