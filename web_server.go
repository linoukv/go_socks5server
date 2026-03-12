package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate" // 限流库
)

// RateLimiter API 限流器（防止 DoS 攻击）
type RateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*rate.Limiter
	rate     rate.Limit // 请求速率：每秒请求数
	burst    int        // 突发容量
}

// NewRateLimiter 创建限流器
func NewRateLimiter(requestsPerSecond float64, burst int) *RateLimiter {
	return &RateLimiter{
		visitors: make(map[string]*rate.Limiter),
		rate:     rate.Limit(requestsPerSecond),
		burst:    burst,
	}
}

// getLimiter 获取或创建指定 IP 的限流器
func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.visitors[ip]
	if !exists {
		// 创建新的限流器
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.visitors[ip] = limiter
	}

	return limiter
}

// Allow 检查是否允许请求
func (rl *RateLimiter) Allow(ip string) bool {
	return rl.getLimiter(ip).Allow()
}

// Middleware 限流中间件
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr

		if !rl.Allow(ip) {
			log.Printf("限流触发：IP=%s", ip)
			http.Error(w, "请求过于频繁，请稍后再试", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// WebServer Web 管理服务器
type WebServer struct {
	auth   *PasswordAuth
	db     *DatabaseManager
	server *http.Server
}

// NewWebServer 创建 Web 管理服务器（安全版：添加限流保护 + nil 防护）
func NewWebServer(auth *PasswordAuth, db *DatabaseManager, listenAddr string) *WebServer {
	// ✅ 确保 auth 不为 nil，防止空指针解引用
	if auth == nil {
		log.Printf("警告：auth 为 nil，创建空的 PasswordAuth")
		auth = &PasswordAuth{
			users: make(map[string]*User),
		}
	}

	ws := &WebServer{
		auth: auth,
		db:   db,
	}

	mux := http.NewServeMux()

	// API 路由
	mux.HandleFunc("/api/users", ws.handleUsers)
	mux.HandleFunc("/api/groups", ws.handleGroups)
	mux.HandleFunc("/api/stats", ws.handleStats)
	mux.HandleFunc("/api/traffic", ws.handleTraffic)
	mux.HandleFunc("/api/dashboard", ws.handleDashboard)
	mux.HandleFunc("/api/user-quota", ws.handleUserQuota)

	// 静态文件服务
	fs := http.FileServer(http.Dir("static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// 首页
	mux.HandleFunc("/", ws.handleIndex)

	// ✅ 创建限流器：每秒 10 个请求，突发 20 个
	rateLimiter := NewRateLimiter(10.0, 20)

	ws.server = &http.Server{
		Addr:           listenAddr,
		Handler:        rateLimiter.Middleware(ws.corsMiddleware(mux)), // ✅ 应用限流中间件
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB 最大请求头
	}

	return ws
}

// sanitizeUsername 脱敏用户名（用于日志记录）
// 只显示首尾字符，中间用 * 替代
func sanitizeUsername(username string) string {
	if len(username) <= 2 {
		return "***"
	}
	return username[:1] + strings.Repeat("*", len(username)-2) + username[len(username)-1:]
}

// Start 启动 Web 服务器
func (ws *WebServer) Start() error {
	fmt.Printf("Web 管理界面已启动在 http://%s\n", ws.server.Addr)
	return ws.server.ListenAndServe()
}

// Stop 停止 Web 服务器
func (ws *WebServer) Stop() error {
	return ws.server.Close()
}

// CORS 中间件
func (ws *WebServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("CORS 中间件：[%s] %s %s", r.RemoteAddr, r.Method, r.URL.Path)

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			log.Printf("OPTIONS 预检请求，直接返回")
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// handleIndex 处理首页请求
func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// 读取静态 HTML 文件
	htmlData, err := ioutil.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "页面加载失败", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(htmlData)
}

// handleUsers 处理用户相关 API（安全版：添加 nil 检查）
func (ws *WebServer) handleUsers(w http.ResponseWriter, r *http.Request) {
	// ✅ 添加 nil 检查，防止空指针解引用
	if ws.auth == nil {
		log.Printf("错误：auth 为 nil")
		http.Error(w, "认证服务未初始化", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case "GET":
		// 获取所有用户
		users := ws.auth.ListUsers()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)

	case "POST":
		// 创建用户（已在函数开头检查过 ws.auth != nil）
		var data struct {
			Username         string `json:"username"`
			Password         string `json:"password"`
			Group            string `json:"group"`
			ReadLimit        int64  `json:"read_limit"`
			WriteLimit       int64  `json:"write_limit"`
			MaxConn          int    `json:"max_conn"`
			MaxIPConnections int    `json:"max_ip_connections"`
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "请求数据格式错误", http.StatusBadRequest)
			return
		}

		// ✅ 添加用户（带验证）
		if err := ws.auth.AddUser(data.Username, data.Password); err != nil {
			log.Printf("创建用户失败 [%s]: %v", data.Username, err)
			http.Error(w, fmt.Sprintf("用户创建失败：%v", err), http.StatusBadRequest)
			return
		}

		// 设置分组和限速
		if data.Group != "" {
			ws.auth.AddUserToGroup(data.Username, data.Group)
		}

		// ✅ 使用验证函数处理数值
		readLimit, _ := validateSpeedLimit(data.ReadLimit)
		writeLimit, _ := validateSpeedLimit(data.WriteLimit)
		if readLimit > 0 || writeLimit > 0 {
			ws.auth.SetUserSpeedLimit(data.Username, readLimit, writeLimit)
		}

		maxConn, _ := validateMaxConnections(data.MaxConn)
		ws.auth.SetUserMaxConnections(data.Username, maxConn)

		maxIPConn, _ := validateMaxConnections(data.MaxIPConnections)
		ws.auth.SetUserMaxIPConnections(data.Username, maxIPConn)

		log.Printf("用户 [%s] 创建成功：分组=%s, 限速=[R:%d/W:%d], 连接限制=%d",
			sanitizeUsername(data.Username), data.Group, readLimit, writeLimit, maxConn)

		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"status":"success","message":"用户创建成功"}`)

	case "PUT":
		// 更新用户
		username := r.URL.Query().Get("username")
		if username == "" {
			http.Error(w, "缺少用户名参数", http.StatusBadRequest)
			return
		}

		var data struct {
			Password         string `json:"password"`
			Group            string `json:"group"`
			ReadLimit        int64  `json:"read_limit"`
			WriteLimit       int64  `json:"write_limit"`
			MaxConn          int    `json:"max_conn"`
			MaxIPConnections int    `json:"max_ip_connections"`
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			log.Printf("解析用户数据失败：%v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		log.Printf("更新用户 [%s]: 分组=%s, 读限速=%d, 写限速=%d, 最大连接=%d",
			sanitizeUsername(username), data.Group, data.ReadLimit, data.WriteLimit, data.MaxConn)

		// 更新用户信息
		if user, exists := ws.auth.GetUser(username); exists {
			// 更新密码（如果提供了）
			if data.Password != "" {
				user.Password = data.Password
			}
			// 更新分组
			if data.Group != "" {
				ws.auth.AddUserToGroup(username, data.Group)
			} else if user.Group != "" {
				ws.auth.RemoveUserFromGroup(username)
			}
			// 更新限速（确保值有效）
			readLimit := data.ReadLimit
			if readLimit < 0 {
				readLimit = 0
			}
			writeLimit := data.WriteLimit
			if writeLimit < 0 {
				writeLimit = 0
			}
			ws.auth.SetUserSpeedLimit(username, readLimit, writeLimit)
			// 更新连接数限制（0 表示不限，也需要更新）
			maxConn := data.MaxConn
			if maxConn < 0 {
				maxConn = 0
			}
			ws.auth.SetUserMaxConnections(username, maxConn)
			// 更新 IP 连接数限制（0 表示不限，也需要更新）
			maxIPConn := data.MaxIPConnections
			if maxIPConn < 0 {
				maxIPConn = 0
			}
			ws.auth.SetUserMaxIPConnections(username, maxIPConn)

			log.Printf("用户 [%s] 更新成功，最大连接数：%d, 最大 IP 连接数：%d", username, data.MaxConn, data.MaxIPConnections)
			fmt.Fprintf(w, `{"status":"success","message":"用户已更新"}`)
		} else {
			log.Printf("用户 [%s] 不存在", username)
			http.Error(w, "用户不存在", http.StatusNotFound)
		}

		// 保存用户到数据库（包含配额信息）
		if ws.db != nil {
			if user, exists := ws.auth.GetUser(username); exists {
				ws.db.SaveUser(user)
			}
		}

	case "DELETE":
		// 删除用户
		username := r.URL.Query().Get("username")
		if username == "" {
			http.Error(w, "缺少用户名参数", http.StatusBadRequest)
			return
		}

		ws.auth.RemoveUser(username)
		fmt.Fprintf(w, `{"status":"success","message":"用户已删除"}`)
	}
}

// handleGroups 处理分组相关 API
func (ws *WebServer) handleGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		// 获取所有分组
		groups := ws.auth.ListGroups()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(groups)

	case "POST":
		// 创建分组
		var data struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			ReadLimit   int64  `json:"read_limit"`
			WriteLimit  int64  `json:"write_limit"`
			MaxConn     int    `json:"max_conn"`
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ws.auth.CreateGroup(data.Name, data.Description, data.ReadLimit, data.WriteLimit, data.MaxConn)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"status":"success","message":"分组创建成功"}`)

	case "DELETE":
		// 删除分组
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "缺少分组名参数", http.StatusBadRequest)
			return
		}

		ws.auth.RemoveGroup(name)
		fmt.Fprintf(w, `{"status":"success","message":"分组已删除"}`)

	case "PUT":
		// 更新分组
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "缺少分组名参数", http.StatusBadRequest)
			return
		}

		var data struct {
			Description string `json:"description"`
			ReadLimit   int64  `json:"read_limit"`
			WriteLimit  int64  `json:"write_limit"`
			MaxConn     int    `json:"max_conn"`
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			log.Printf("解析分组数据失败：%v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		log.Printf("更新分组 [%s]: 描述=%s, 读限速=%d, 写限速=%d, 最大连接=%d",
			name, data.Description, data.ReadLimit, data.WriteLimit, data.MaxConn)

		// 更新分组配置
		if ws.auth.UpdateGroup(name, data.Description, data.ReadLimit, data.WriteLimit, data.MaxConn) {
			// 应用分组设置到所有成员
			ws.auth.ApplyGroupSettings(name)
			log.Printf("分组 [%s] 更新成功", name)
			fmt.Fprintf(w, `{"status":"success","message":"分组已更新"}`)
		} else {
			log.Printf("分组 [%s] 不存在", name)
			http.Error(w, "分组不存在", http.StatusNotFound)
		}
	}
}

// handleStats 处理统计 API
func (ws *WebServer) handleStats(w http.ResponseWriter, r *http.Request) {
	// 获取所有统计信息
	users := ws.auth.ListUsers()
	totalUsers := len(users)
	activeUsers := 0
	totalUpload := int64(0)
	totalDownload := int64(0)

	for _, user := range users {
		if user.LastActivity > time.Now().Unix()-3600 {
			activeUsers++
		}
		totalUpload += user.UploadTotal
		totalDownload += user.DownloadTotal
	}

	data := map[string]interface{}{
		"total_users":    totalUsers,
		"active_users":   activeUsers,
		"total_upload":   totalUpload,
		"total_download": totalDownload,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// handleTraffic 处理流量 API
func (ws *WebServer) handleTraffic(w http.ResponseWriter, r *http.Request) {
	// TODO: 从数据库查询流量数据
	traffic := []map[string]interface{}{}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(traffic)
}

// handleDashboard 处理仪表板 API（安全版：添加 nil 检查）
func (ws *WebServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// ✅ 添加 nil 检查，防止空指针解引用
	if ws.auth == nil {
		log.Printf("错误：auth 为 nil")
		http.Error(w, "认证服务未初始化", http.StatusInternalServerError)
		return
	}

	users := ws.auth.ListUsers()
	totalUsers := len(users)
	activeUsers := 0
	totalUpload := int64(0)
	totalDownload := int64(0)

	for _, user := range users {
		if user.LastActivity > time.Now().Unix()-3600 {
			activeUsers++
		}
		totalUpload += user.UploadTotal
		totalDownload += user.DownloadTotal
	}

	data := map[string]interface{}{
		"total_users":    totalUsers,
		"active_users":   activeUsers,
		"total_upload":   totalUpload,
		"total_download": totalDownload,
		"timestamp":      time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// handleUserQuota 处理用户流量配额 API
func (ws *WebServer) handleUserQuota(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	switch r.Method {
	case "PUT":
		// 设置流量配额
		username := r.URL.Query().Get("username")
		if username == "" {
			http.Error(w, "缺少用户名参数", http.StatusBadRequest)
			return
		}

		var data struct {
			Period string `json:"period"`
			Quota  int64  `json:"quota"`
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			log.Printf("解析配额数据失败：%v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		log.Printf("设置用户 [%s] 流量配额：周期=%s, 配额=%d 字节", username, data.Period, data.Quota)

		if ws.auth.SetUserQuota(username, data.Period, data.Quota) {
			// ✅ 保存用户到数据库（添加 nil 检查）
			if ws.db != nil {
				if user, exists := ws.auth.GetUser(username); exists {
					ws.db.SaveUser(user)
				}
			}
			log.Printf("用户 [%s] 流量配额设置成功", username)
			fmt.Fprintf(w, `{"status":"success","message":"配额已设置"}`)
		} else {
			log.Printf("用户 [%s] 不存在", username)
			http.Error(w, "用户不存在", http.StatusNotFound)
		}

	case "GET":
		// 获取用户流量配额信息
		username := r.URL.Query().Get("username")
		if username == "" {
			http.Error(w, "缺少用户名参数", http.StatusBadRequest)
			return
		}

		period, total, used, resetTime, exists := ws.auth.GetUserQuotaInfo(username)
		if !exists {
			http.Error(w, "用户不存在", http.StatusNotFound)
			return
		}

		fmt.Fprintf(w, `{"period":"%s","total":%d,"used":%d,"reset_time":%d}`, period, total, used, resetTime)
	}
}
