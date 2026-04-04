package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type DatabaseManager struct {
	db *sql.DB
	mu sync.RWMutex
}

func NewDatabaseManager(dbPath string) (*DatabaseManager, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败：%w", err)
	}

	manager := &DatabaseManager{
		db: db,
	}

	if err := manager.initTables(); err != nil {
		return nil, fmt.Errorf("初始化数据库失败：%w", err)
	}

	return manager, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func intToBool(i int) bool {
	return i != 0
}

func (m *DatabaseManager) initTables() error {
	log.Println("开始初始化/更新数据库表结构...")

	schemas := []string{
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

		`CREATE TABLE IF NOT EXISTS traffic_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL,
			upload INTEGER DEFAULT 0,
			download INTEGER DEFAULT 0,
			log_time INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS connection_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL,
			client_ip TEXT,
			action TEXT,
			log_time INTEGER NOT NULL
		)`,

		`CREATE TABLE IF NOT EXISTS system_config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			description TEXT,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

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

	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_traffic_username ON traffic_logs(username)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_time ON traffic_logs(log_time)`,
		`CREATE INDEX IF NOT EXISTS idx_connection_username ON connection_logs(username)`,
	}

	for _, schema := range schemas {
		if _, err := m.db.Exec(schema); err != nil {
			return fmt.Errorf("创建表失败：%w", err)
		}
	}

	log.Println("数据库表结构创建完成")

	for _, index := range indexes {
		if _, err := m.db.Exec(index); err != nil {
			return fmt.Errorf("创建索引失败：%w", err)
		}
	}

	log.Println("数据库索引创建完成")
	log.Println("数据库初始化完成")

	return nil
}

func (m *DatabaseManager) isDatabaseInitialized() (bool, error) {
	query := `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'`
	var count int
	err := m.db.QueryRow(query).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("查询数据库状态失败：%w", err)
	}
	return count > 0, nil
}

func (m *DatabaseManager) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}

func (m *DatabaseManager) SaveAdminUser(username, passwordHash string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var exists bool
	err := m.db.QueryRow("SELECT 1 FROM admin_users WHERE username = ?", username).Scan(&exists)
	if err == sql.ErrNoRows {
		_, err = m.db.Exec(`
			INSERT INTO admin_users (username, password_hash, enabled, create_time, last_password_change, force_password_change)
			VALUES (?, ?, ?, ?, ?, ?)
		`, username, passwordHash, enabled, time.Now().Unix(), time.Now().Unix(), false)
	} else if err != nil {
		return err
	} else {
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

func (m *DatabaseManager) DeleteAdminUser(username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, err := m.db.Exec("DELETE FROM admin_users WHERE username = ?", username)
	return err
}

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

func (m *DatabaseManager) GetAllUsers() ([]*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

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

	}

	if err = rows.Err(); err != nil {
		log.Printf("[ERROR] GetAllUsers rows.Err: %v", err)
		return nil, err
	}

	return users, rows.Err()
}

func (m *DatabaseManager) DeleteUser(username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, err := m.db.Exec("DELETE FROM users WHERE username = ?", username)
	return err
}

func (m *DatabaseManager) LoadAllUsersToAuth(auth *PasswordAuth) error {

	users, err := m.GetAllUsers()
	if err != nil {
		log.Printf("[ERROR] GetAllUsers 失败：%v", err)
		return err
	}

	auth.mu.Lock()
	defer auth.mu.Unlock()

	if auth.users == nil {
		auth.users = make(map[string]*User)
	}
	if auth.userConnections == nil {
		auth.userConnections = make(map[string]int)
	}
	if auth.userIPs == nil {
		auth.userIPs = make(map[string]map[string]bool)
	}

	for _, user := range users {
		auth.users[user.Username] = user
	}

	return nil
}

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

func (m *DatabaseManager) LogTotalTraffic(upload, download int64) error {
	if upload == 0 && download == 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	query := `
		INSERT INTO total_traffic_logs (upload, download, log_time)
		VALUES (?, ?, ?)
	`

	_, err := m.db.Exec(query, upload, download, time.Now().Unix())
	return err
}

func (m *DatabaseManager) CleanOldTrafficLogs(retentionDays int) error {
	if m == nil || m.db == nil {
		log.Printf("警告：数据库未初始化，跳过流量日志清理")
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if retentionDays <= 0 {
		return fmt.Errorf("保留天数必须大于 0")
	}

	cutoffTime := time.Now().AddDate(0, 0, -retentionDays).Unix()

	query := `
		DELETE FROM traffic_logs
		WHERE log_time < ?
	`

	result, err := m.db.Exec(query, cutoffTime)
	if err != nil {
		return fmt.Errorf("清理流量日志失败：%w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("获取删除行数失败：%v", err)
	} else {
		log.Printf("清理流量日志：删除了 %d 条 %d 天前的记录", rowsAffected, retentionDays)
	}

	return nil
}

func (m *DatabaseManager) GetTrafficLogsCount() (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	query := `SELECT COUNT(*) FROM traffic_logs`
	var count int64
	err := m.db.QueryRow(query).Scan(&count)
	return count, err
}

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

func (m *DatabaseManager) GetUserTrafficReport(username string, days int) ([]map[string]interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

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

func (m *DatabaseManager) GetConfig(key string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var value string
	err := m.db.QueryRow("SELECT value FROM system_config WHERE key = ?", key).Scan(&value)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return value, nil
}

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

func (m *DatabaseManager) SetConfig(key, value, description string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var exists bool
	err := m.db.QueryRow("SELECT 1 FROM system_config WHERE key = ?", key).Scan(&exists)
	if err == sql.ErrNoRows {
		_, err = m.db.Exec(
			"INSERT INTO system_config (key, value, description) VALUES (?, ?, ?)",
			key, value, description,
		)
	} else if err != nil {
		return err
	} else {
		_, err = m.db.Exec(
			"UPDATE system_config SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?",
			value, key,
		)
	}
	return err
}

func (m *DatabaseManager) DeleteConfig(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, err := m.db.Exec("DELETE FROM system_config WHERE key = ?", key)
	return err
}
