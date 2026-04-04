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

const (
	MinUsernameLen = 3
	MaxUsernameLen = 32
	MinPasswordLen = 8
	MaxPasswordLen = 128
	MaxSpeedLimit  = 10 * 1024 * 1024 * 1024
	MaxConnections = 100000
)

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func hashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("密码哈希失败：%w", err)
	}
	return string(hashed), nil
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

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

func validateSpeedLimit(limit int64) (int64, error) {
	if limit < 0 {
		return 0, fmt.Errorf("速度限制不能为负数")
	}
	if limit > MaxSpeedLimit {
		return MaxSpeedLimit, fmt.Errorf("速度限制不能超过 %d GB/s", MaxSpeedLimit/1024/1024/1024)
	}
	return limit, nil
}

func validateMaxConnections(maxConn int) (int, error) {
	if maxConn < 0 {
		return 0, fmt.Errorf("最大连接数不能为负数")
	}
	if maxConn > MaxConnections {
		return MaxConnections, fmt.Errorf("最大连接数不能超过 %d", MaxConnections)
	}
	return maxConn, nil
}

type Authenticator interface {
	Authenticate(username, password string) bool
	Method() byte
}

type NoAuth struct{}

func (a *NoAuth) Authenticate(username, password string) bool {
	return true
}

func (a *NoAuth) Method() byte {
	return AuthNone
}

type User struct {
	ReadSpeedLimit  int64 `json:"read_speed_limit"`
	WriteSpeedLimit int64 `json:"write_speed_limit"`
	UploadTotal     int64 `json:"upload_total"`
	DownloadTotal   int64 `json:"download_total"`
	CreateTime      int64 `json:"create_time"`
	LastActivity    int64 `json:"last_activity"`
	QuotaBytes      int64 `json:"quota_bytes"`
	QuotaUsed       int64 `json:"quota_used"`
	QuotaResetTime  int64 `json:"quota_reset_time"`
	QuotaStartTime  int64 `json:"quota_start_time"`
	QuotaEndTime    int64 `json:"quota_end_time"`

	Username         string `json:"username"`
	Password         string `json:"password"`
	MaxConnections   int    `json:"max_connections"`
	Enabled          bool   `json:"enabled"`
	QuotaPeriod      string `json:"quota_period"`
	MaxIPConnections int    `json:"max_ip_connections"`
}

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

type PasswordAuth struct {
	mu              sync.RWMutex
	users           map[string]*User
	userConnections map[string]int
	connMu          sync.RWMutex
	userIPs         map[string]map[string]bool
	ipMu            sync.RWMutex
}

type ShardedPasswordAuth struct {
	shards     [16]*PasswordAuth
	shardCount int
}

func NewShardedPasswordAuth() *ShardedPasswordAuth {
	sa := &ShardedPasswordAuth{
		shardCount: 16,
	}
	for i := 0; i < sa.shardCount; i++ {
		sa.shards[i] = NewPasswordAuth()
	}
	return sa
}

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

func (sa *ShardedPasswordAuth) AddUser(username, password string) error {
	return sa.getShard(username).AddUser(username, password)
}

func (sa *ShardedPasswordAuth) GetUser(username string) (*User, bool) {
	return sa.getShard(username).GetUser(username)
}

func (sa *ShardedPasswordAuth) Authenticate(username, password string) bool {
	return sa.getShard(username).Authenticate(username, password)
}

func NewPasswordAuth() *PasswordAuth {
	return &PasswordAuth{
		users:           make(map[string]*User),
		userConnections: make(map[string]int),
		userIPs:         make(map[string]map[string]bool),
	}
}

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
		ReadSpeedLimit:  0,
		WriteSpeedLimit: 0,
		MaxConnections:  0,
		Enabled:         true,
		CreateTime:      time.Now().Unix(),
		LastActivity:    time.Now().Unix(),
	}

	log.Printf("用户 [%s] 创建成功", username)
	return nil
}

func (a *PasswordAuth) RemoveUser(username string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.users, username)
}

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

func (a *PasswordAuth) Authenticate(username, password string) bool {
	a.mu.RLock()
	user, exists := a.users[username]
	a.mu.RUnlock()

	if !exists || !user.Enabled {
		_ = checkPasswordHash(password, "")
		return false
	}

	return checkPasswordHash(password, user.Password)
}

func (a *PasswordAuth) Method() byte {
	return AuthPassword
}

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

func (a *PasswordAuth) GetUser(username string) (*User, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	user, exists := a.users[username]
	if !exists {
		return nil, false
	}

	return user, true
}

func (a *PasswordAuth) ListUsers() []*User {
	a.mu.RLock()
	defer a.mu.RUnlock()

	users := make([]*User, 0, len(a.users))
	for _, user := range a.users {
		users = append(users, user)
	}
	return users
}

func (a *PasswordAuth) IncrementUserConnection(username string) int {
	a.connMu.Lock()
	defer a.connMu.Unlock()

	if a.userConnections == nil {
		a.userConnections = make(map[string]int)
	}
	a.userConnections[username]++
	return a.userConnections[username]
}

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

func (a *PasswordAuth) GetUserConnectionCount(username string) int {
	a.connMu.RLock()
	defer a.connMu.RUnlock()

	if a.userConnections == nil {
		return 0
	}
	return a.userConnections[username]
}

func (a *PasswordAuth) CheckUserConnectionLimit(username string) bool {
	a.mu.RLock()
	user, exists := a.users[username]
	a.mu.RUnlock()

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

func (a *PasswordAuth) RemoveUserIP(username, ip string) {
	a.ipMu.Lock()
	defer a.ipMu.Unlock()

	if a.userIPs != nil && a.userIPs[username] != nil {
		delete(a.userIPs[username], ip)
		if len(a.userIPs[username]) == 0 {
			delete(a.userIPs, username)
		}
	}
}

func (a *PasswordAuth) GetUserIPCount(username string) int {
	a.ipMu.RLock()
	defer a.ipMu.RUnlock()

	if a.userIPs == nil || a.userIPs[username] == nil {
		return 0
	}
	return len(a.userIPs[username])
}

func (a *PasswordAuth) CheckUserIPLimit(username, ip string) bool {
	a.mu.RLock()
	user, exists := a.users[username]
	if !exists || user.MaxIPConnections <= 0 {
		a.mu.RUnlock()
		return true
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

	if ipSet[ip] {
		a.ipMu.RUnlock()
		return true
	}

	currentIPs := len(ipSet)
	a.ipMu.RUnlock()

	return currentIPs < user.MaxIPConnections
}

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

func SelectAuthMethod(clientMethods, serverMethods []byte) byte {
	for _, cm := range clientMethods {
		if cm == AuthPassword {
			for _, sm := range serverMethods {
				if sm == AuthPassword {
					return AuthPassword
				}
			}
		}
	}

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

	if user.QuotaPeriod != "" && user.QuotaBytes > 0 {
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
