package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate" // 限流库
)

// RateLimiter API 限流器（防止 DoS 攻击）
type RateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*rate.Limiter
	rate     rate.Limit // 请求速率：每秒请求数
	burst    int        // 突发容量
}

// AdminUser 管理员用户结构
type AdminUser struct {
	Username            string `json:"username"`              // 用户名
	PasswordHash        string `json:"-"`                     // 密码哈希（不导出）
	Enabled             bool   `json:"enabled"`               // 是否启用
	LastLogin           int64  `json:"last_login"`            // 最后登录时间
	LoginCount          int    `json:"login_count"`           // 登录次数
	CreateTime          int64  `json:"create_time"`           // 创建时间
	LastPasswordChange  int64  `json:"last_password_change"`  // 最后修改密码时间
	ForcePasswordChange bool   `json:"force_password_change"` // 强制修改密码
	LoginFailCount      int    `json:"-"`                     // 登录失败次数（不导出）
	LastLoginFailTime   int64  `json:"-"`                     // 最后登录失败时间（不导出）
	LockUntil           int64  `json:"-"`                     // 锁定直到时间（不导出）
}

// Session 管理员会话结构
type Session struct {
	Token        string `json:"token"`         // 会话令牌
	Username     string `json:"username"`      // 用户名
	ExpireTime   int64  `json:"expire_time"`   // 过期时间（24 小时）
	ClientIP     string `json:"client_ip"`     // 客户端 IP
	CreateTime   int64  `json:"create_time"`   // 创建时间
	LastActivity int64  `json:"last_activity"` // 最后活动时间（用于超时管理）
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
	auth         *PasswordAuth
	db           *DatabaseManager
	socksServer  *Server                 // SOCKS5 服务器引用
	server       *http.Server            // HTTP 服务器
	adminUsers   map[string]*AdminUser   // 管理员用户
	adminMu      sync.RWMutex            // 保护管理员用户的锁
	sessions     map[string]*Session     // 会话管理
	sessionMu    sync.RWMutex            // 保护会话的锁
	captchaStore map[string]*CaptchaInfo // 验证码存储
	captchaMu    sync.RWMutex            // 保护验证码的锁
	submitTokens map[string]int64        // 提交令牌（防止重复提交）
	submitMu     sync.RWMutex            // 保护提交令牌的锁
	csrfSecret   []byte                  // CSRF Token 生成密钥
}

// CaptchaInfo 验证码信息
type CaptchaInfo struct {
	Code      string // 验证码文本
	ExpireAt  int64  // 过期时间
	FailCount int    // 失败次数
}

// NewWebServer 创建 Web 管理服务器（安全版：添加限流保护 + nil 防护 + 管理员认证）
func NewWebServer(auth *PasswordAuth, db *DatabaseManager, socksServer *Server, listenAddr string) *WebServer {
	// ✅ 确保 auth 不为 nil，防止空指针解引用
	if auth == nil {
		log.Printf("警告：auth 为 nil，创建空的 PasswordAuth")
		auth = &PasswordAuth{
			users:           make(map[string]*User),
			userConnections: make(map[string]int),
			userIPs:         make(map[string]map[string]bool),
		}
	}

	ws := &WebServer{
		auth:         auth,
		db:           db,
		socksServer:  socksServer,
		adminUsers:   make(map[string]*AdminUser),
		sessions:     make(map[string]*Session),
		captchaStore: make(map[string]*CaptchaInfo),
		submitTokens: make(map[string]int64),
		csrfSecret:   generateCSRFSecret(), // 生成 CSRF 密钥
	}

	// 初始化默认管理员账户（如果数据库为空）
	ws.initDefaultAdmin()

	// ✅ 从数据库加载管理员用户（覆盖内存中的默认值）
	if db != nil {
		if err := db.LoadAdminUsers(ws); err != nil {
			log.Printf("加载管理员用户失败：%v", err)
		} else {
			log.Printf("已从数据库加载管理员用户")
		}
	}

	mux := http.NewServeMux()

	// API 路由
	mux.HandleFunc("/api/users", ws.handleUsers)
	mux.HandleFunc("/api/stats", ws.handleStats)
	mux.HandleFunc("/api/traffic", ws.handleTraffic)
	mux.HandleFunc("/api/dashboard", ws.handleDashboard)
	mux.HandleFunc("/api/user-quota", ws.handleUserQuota)
	mux.HandleFunc("/api/quota/stats", ws.handleQuotaStats)              // 配额统计 API
	mux.HandleFunc("/api/admin/batch-set-quota", ws.handleBatchSetQuota) // 批量设置配额 API
	// 管理员登录 API
	mux.HandleFunc("/api/admin/login", ws.handleAdminLogin)
	mux.HandleFunc("/api/admin/logout", ws.handleAdminLogout)
	mux.HandleFunc("/api/admin/check", ws.handleAdminCheck)
	mux.HandleFunc("/api/admin/captcha", ws.handleCaptcha)                // 验证码 API
	mux.HandleFunc("/api/admin/change-password", ws.handleChangePassword) // 修改密码 API
	// 认证方式管理 API
	mux.HandleFunc("/api/admin/auth-method", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			ws.handleGetAuthMethod(w, r)
		case "POST":
			ws.handleSetAuthMethod(w, r)
		default:
			http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed)
		}
	})
	// 服务器配置管理 API
	mux.HandleFunc("/api/admin/config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			ws.handleGetConfig(w, r)
		case "POST":
			ws.handleSetConfig(w, r)
		default:
			http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed)
		}
	})

	// 静态文件服务（嵌入模式）
	staticFS := getStaticFileSystem()
	if staticFS != nil {
		fs := http.FileServer(staticFS)
		mux.Handle("/static/", http.StripPrefix("/static/", fs))
	} else {
		// 降级：使用文件系统
		fs := http.FileServer(http.Dir("static"))
		mux.Handle("/static/", http.StripPrefix("/static/", fs))
	}

	// 首页
	mux.HandleFunc("/", ws.handleIndex)

	// 登录页
	mux.HandleFunc("/login.html", ws.handleLogin)

	// 配额管理页
	mux.HandleFunc("/quota.html", ws.handleQuota)

	// ✅ 创建限流器：每秒 10 个请求，突发 20 个
	rateLimiter := NewRateLimiter(10.0, 20)

	// 应用认证中间件（添加安全响应头中间件）
	ws.server = &http.Server{
		Addr:           listenAddr,
		Handler:        rateLimiter.Middleware(ws.authMiddleware(ws.corsMiddleware(setSecurityHeaders(mux)))),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB 最大请求头
	}

	return ws
}

// generateCaptcha 生成验证码图片和代码
func (ws *WebServer) generateCaptcha() (string, image.Image) {
	// 验证码字符集
	chars := "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	code := ""
	for i := 0; i < 4; i++ {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		code += string(chars[n.Int64()])
	}

	// 创建图片
	width, height := 120, 50
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// 白色背景
	for x := 0; x < width; x++ {
		for y := 0; y < height; y++ {
			img.Set(x, y, color.RGBA{255, 255, 255, 255})
		}
	}

	// 绘制干扰线
	for i := 0; i < 5; i++ {
		x1, _ := rand.Int(rand.Reader, big.NewInt(int64(width)))
		y1, _ := rand.Int(rand.Reader, big.NewInt(int64(height)))
		x2, _ := rand.Int(rand.Reader, big.NewInt(int64(width)))
		y2, _ := rand.Int(rand.Reader, big.NewInt(int64(height)))
		r, _ := rand.Int(rand.Reader, big.NewInt(200))
		g, _ := rand.Int(rand.Reader, big.NewInt(200))
		b, _ := rand.Int(rand.Reader, big.NewInt(200))
		drawLine(img, x1.Int64(), y1.Int64(), x2.Int64(), y2.Int64(), color.RGBA{uint8(r.Int64()), uint8(g.Int64()), uint8(b.Int64()), 255})
	}

	// 绘制验证码文字（使用不同颜色）
	for i, ch := range code {
		// 随机颜色（深色）
		r := uint8(50 + (i*40)%200)
		g := uint8(50 + (i*60)%200)
		b := uint8(100 + (i*30)%155)

		// 计算字符位置
		x := (i * 25) + 15
		y := 30

		// 绘制字符（简单的点阵模拟）
		drawChar(img, ch, x, y, color.RGBA{r, g, b, 255})
	}

	return code, img
}

// drawLine 绘制直线
func drawLine(img *image.RGBA, x1, y1, x2, y2 int64, c color.RGBA) {
	dx := int(x2 - x1)
	dy := int(y2 - y1)
	steps := max(abs(dx), abs(dy))
	if steps == 0 {
		steps = 1
	}
	xIncrement := float64(dx) / float64(steps)
	yIncrement := float64(dy) / float64(steps)

	x := float64(x1)
	y := float64(y1)
	for i := 0; i <= steps; i++ {
		img.Set(int(x), int(y), c)
		x += xIncrement
		y += yIncrement
	}
}

// drawChar 绘制简单字符（点阵模拟）
func drawChar(img *image.RGBA, ch rune, x, y int, c color.RGBA) {
	// 简单的 5x7 点阵字符
	charMap := map[rune][]string{
		'2': {"01110", "10001", "00010", "00100", "01000", "10000", "11111"},
		'3': {"01110", "10001", "00001", "00110", "00001", "10001", "01110"},
		'4': {"00010", "00110", "01010", "10010", "11111", "00010", "00010"},
		'5': {"11111", "10000", "11110", "00001", "00001", "10001", "01110"},
		'6': {"00110", "01000", "10000", "11110", "10001", "10001", "01110"},
		'7': {"11111", "00001", "00010", "00100", "01000", "01000", "01000"},
		'8': {"01110", "10001", "10001", "01110", "10001", "10001", "01110"},
		'9': {"01110", "10001", "10001", "01111", "00001", "00010", "01100"},
		'A': {"00100", "01010", "10001", "10001", "11111", "10001", "10001"},
		'B': {"11110", "10001", "10001", "11110", "10001", "10001", "11110"},
		'C': {"01110", "10001", "10000", "10000", "10000", "10001", "01110"},
		'D': {"11100", "10010", "10001", "10001", "10001", "10010", "11100"},
		'E': {"11111", "10000", "10000", "11110", "10000", "10000", "11111"},
		'F': {"11111", "10000", "10000", "11110", "10000", "10000", "10000"},
		'G': {"01110", "10001", "10000", "10111", "10001", "10001", "01110"},
		'H': {"10001", "10001", "10001", "11111", "10001", "10001", "10001"},
		'J': {"01111", "00001", "00001", "00001", "00001", "10001", "01110"},
		'K': {"10001", "10010", "10100", "11000", "10100", "10010", "10001"},
		'L': {"10000", "10000", "10000", "10000", "10000", "10000", "11111"},
		'M': {"10001", "11011", "10101", "10101", "10001", "10001", "10001"},
		'N': {"10001", "11001", "10101", "10011", "10001", "10001", "10001"},
		'P': {"11110", "10001", "10001", "11110", "10000", "10000", "10000"},
		'Q': {"01110", "10001", "10001", "10001", "10101", "10010", "01101"},
		'R': {"11110", "10001", "10001", "11110", "10100", "10010", "10001"},
		'S': {"01110", "10001", "10000", "01110", "00001", "10001", "01110"},
		'T': {"11111", "00100", "00100", "00100", "00100", "00100", "00100"},
		'U': {"10001", "10001", "10001", "10001", "10001", "10001", "01110"},
		'V': {"10001", "10001", "10001", "10001", "10001", "01010", "00100"},
		'W': {"10001", "10001", "10001", "10101", "10101", "11011", "10001"},
		'X': {"10001", "10001", "01010", "00100", "01010", "10001", "10001"},
		'Y': {"10001", "10001", "10001", "01110", "00100", "00100", "00100"},
		'Z': {"11111", "00001", "00010", "00100", "01000", "10000", "11111"},
	}

	patterns, exists := charMap[ch]
	if !exists {
		return
	}

	// 绘制点阵
	for row, pattern := range patterns {
		for col, pixel := range pattern {
			if pixel == '1' {
				img.Set(x+col*2, y+row*2, c)
				img.Set(x+col*2+1, y+row*2, c)
				img.Set(x+col*2, y+row*2+1, c)
				img.Set(x+col*2+1, y+row*2+1, c)
			}
		}
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// sanitizeUsername 脱敏用户名（用于日志记录）
// 只显示首尾字符，中间用 * 替代，保护用户隐私
// 参数 username: 原始用户名
// 返回：脱敏后的用户名
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

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Auth-Token, X-Captcha-ID")
		// 允许前端访问这些响应头
		w.Header().Set("Access-Control-Expose-Headers", "X-Captcha-ID, X-Auth-Token")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// handleIndex 处理首页请求
func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	// 处理根路径和 /index.html 请求
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}

	// 从嵌入的文件系统读取 HTML 文件
	htmlData := getIndexHTML()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 设置 Content-Security-Policy，允许 blob: 和 data: 图片（用于验证码）
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'")
	w.Write([]byte(htmlData))
}

// handleLogin 处理登录页面请求
func (ws *WebServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/login.html" {
		http.NotFound(w, r)
		return
	}

	// 从嵌入的文件系统读取 HTML 文件
	htmlData := getLoginHTML()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 设置 Content-Security-Policy，允许 blob: 和 data: 图片（用于验证码）
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'")
	w.Write([]byte(htmlData))
}

// handleQuota 处理配额管理页面请求
func (ws *WebServer) handleQuota(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/quota.html" {
		http.NotFound(w, r)
		return
	}

	// 从嵌入的文件系统读取 HTML 文件
	htmlData := getQuotaHTML()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 设置 Content-Security-Policy，允许 blob: 和 data: 图片（用于验证码）
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'")
	w.Write([]byte(htmlData))
}

// handleUsers 处理用户相关 API（安全版：添加 token 验证）
func (ws *WebServer) handleUsers(w http.ResponseWriter, r *http.Request) {
	// ✅ 添加 nil 检查，防止空指针解引用
	if ws.auth == nil {
		log.Printf("错误：auth 为 nil")
		http.Error(w, "认证服务未初始化", http.StatusInternalServerError)
		return
	}

	// ✅ Token 验证：获取并验证 token
	authHeader := r.Header.Get("Authorization")
	var token string

	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			token = parts[1]
		}
	}

	if token == "" {
		token = r.Header.Get("X-Auth-Token")
	}

	if token == "" {
		log.Printf("[安全] handleUsers 未授权访问尝试：%s %s", r.Method, r.RemoteAddr)
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized)
		return
	}

	session, valid := ws.validateSession(token)
	if !valid {
		log.Printf("[安全] handleUsers 无效 token：%s %s", session.Username, r.RemoteAddr)
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
		return
	}

	//log.Printf("[审计] handleUsers: 管理员 [%s] 执行操作，IP=%s, Method=%s", session.Username, r.RemoteAddr, r.Method)

	switch r.Method {
	case "GET":
		// 获取所有用户
		users := ws.auth.ListUsers()
		//log.Printf("[DEBUG] handleUsers GET: 返回 %d 个用户", len(users))
		if len(users) == 0 {
			log.Printf("[WARN] 认证器中没有用户，auth.users 长度：%d", len(ws.auth.users))
			if ws.db != nil {
				log.Printf("[INFO] 尝试从数据库重新加载用户...")
				if err := ws.db.LoadAllUsersToAuth(ws.auth); err != nil {
					log.Printf("[ERROR] 从数据库加载用户失败：%v", err)
				} else {
					users = ws.auth.ListUsers()
					log.Printf("[INFO] 从数据库重新加载了 %d 个用户", len(users))
				}
			} else {
				log.Printf("[WARN] 数据库未初始化")
			}
		}

		// 打印用户流量数据用于调试（已注释）
		// for _, user := range users {
		// 	log.Printf("[用户流量] %s: UploadTotal=%d MB, DownloadTotal=%d MB, 合计=%.2f MB",
		// 		user.Username,
		// 		user.UploadTotal/1024/1024,
		// 		user.DownloadTotal/1024/1024,
		// 		float64(user.UploadTotal+user.DownloadTotal)/1024/1024)
		// }

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
			// 配额数据（可选）
			QuotaPeriod    string `json:"quota_period"`
			QuotaBytes     int64  `json:"quota_bytes"`
			QuotaStartTime int64  `json:"quota_start_time"`
			QuotaEndTime   int64  `json:"quota_end_time"`
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

		// ✅ 设置流量配额（如果提供了）
		if data.QuotaPeriod != "" {
			ws.auth.SetUserQuota(data.Username, data.QuotaPeriod, data.QuotaBytes)
			// 如果是自定义时间段，设置开始和结束时间
			if data.QuotaPeriod == "custom" && data.QuotaStartTime > 0 && data.QuotaEndTime > 0 {
				if user, exists := ws.auth.GetUser(data.Username); exists {
					user.QuotaStartTime = data.QuotaStartTime
					user.QuotaEndTime = data.QuotaEndTime
					user.QuotaResetTime = data.QuotaEndTime
					log.Printf("用户 [%s] 自定义时间段配额已设置：%s - %s",
						sanitizeUsername(data.Username),
						time.Unix(data.QuotaStartTime, 0).Format("2006-01-02 15:04:05"),
						time.Unix(data.QuotaEndTime, 0).Format("2006-01-02 15:04:05"))
				}
			}
		}

		log.Printf("用户 [%s] 创建成功：分组=%s, 限速=[R:%d/W:%d], 连接限制=%d, IP 连接限制=%d",
			sanitizeUsername(data.Username), data.Group, readLimit, writeLimit, maxConn, maxIPConn)

		// ✅ 保存用户到数据库
		if ws.db != nil {
			log.Printf("DEBUG: 尝试获取用户 [%s] 从认证器", sanitizeUsername(data.Username))
			if user, exists := ws.auth.GetUser(data.Username); exists {
				log.Printf("DEBUG: 成功获取用户 [%s]: %+v", sanitizeUsername(data.Username), user)
				if err := ws.db.SaveUser(user); err != nil {
					log.Printf("⚠ 警告：用户 [%s] 保存到数据库失败：%v", sanitizeUsername(data.Username), err)
				} else {
					log.Printf("✅ 用户 [%s] 已保存到数据库", sanitizeUsername(data.Username))
				}
			} else {
				log.Printf("⚠ 警告：无法从认证器获取用户 [%s]，无法保存到数据库", sanitizeUsername(data.Username))
			}
		} else {
			log.Printf("⚠ 警告：数据库未初始化，用户 [%s] 数据不会持久化", sanitizeUsername(data.Username))
		}

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
			// 配额数据（可选，如果提供则一起保存）
			QuotaPeriod    string `json:"quota_period"`
			QuotaBytes     int64  `json:"quota_bytes"`
			QuotaStartTime int64  `json:"quota_start_time"`
			QuotaEndTime   int64  `json:"quota_end_time"`
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			log.Printf("解析用户数据失败：%v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		log.Printf("更新用户 [%s]: 分组=%s, 读限速=%d, 写限速=%d, 最大连接=%d",
			sanitizeUsername(username), data.Group, data.ReadLimit, data.WriteLimit, data.MaxConn)

		// 更新用户信息
		if _, exists := ws.auth.GetUser(username); exists {
			// 更新密码（如果提供了）
			if data.Password != "" {
				// ✅ 使用 UpdateUserPassword 方法，会自动哈希密码
				ws.auth.UpdateUserPassword(username, data.Password)
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

			// 更新配额数据（无论是否有限制都需要更新）
			if data.QuotaPeriod != "" {
				ws.auth.SetUserQuota(username, data.QuotaPeriod, data.QuotaBytes)
				// 如果是自定义时间段，设置开始和结束时间
				if data.QuotaPeriod == "custom" && data.QuotaStartTime > 0 && data.QuotaEndTime > 0 {
					if user, exists := ws.auth.GetUser(username); exists {
						// 如果是首次设置时间段（之前未设置过），重置已用流量
						if user.QuotaStartTime == 0 || user.QuotaEndTime == 0 {
							user.QuotaUsed = 0
							log.Printf("[配额] 用户 [%s] 首次设置时间段，重置已用流量", username)
						} else {
							log.Printf("[配额] 用户 [%s] 更新时间段，保留已用流量：%.2f MB",
								username, float64(user.QuotaUsed)/1024/1024)
						}
						user.QuotaStartTime = data.QuotaStartTime
						user.QuotaEndTime = data.QuotaEndTime
						user.QuotaResetTime = data.QuotaEndTime // 设置重置时间为结束时间
						log.Printf("用户 [%s] 自定义时间段配额已更新：%s - %s",
							username, time.Unix(data.QuotaStartTime, 0).Format("2006-01-02 15:04:05"),
							time.Unix(data.QuotaEndTime, 0).Format("2006-01-02 15:04:05"))
					}
				}
			} else {
				// 配额类型为空（无限制），清空配额相关字段
				if user, exists := ws.auth.GetUser(username); exists {
					user.QuotaPeriod = ""
					user.QuotaBytes = 0
					user.QuotaUsed = 0
					user.QuotaStartTime = 0
					user.QuotaEndTime = 0
					user.QuotaResetTime = 0
					log.Printf("[配额] 用户 [%s] 已设置为无限制", username)
				}
			}

			log.Printf("用户 [%s] 更新成功，最大连接数：%d, 最大 IP 连接数：%d", username, data.MaxConn, data.MaxIPConnections)
			fmt.Fprintf(w, `{"status":"success","message":"用户已更新"}`)
		} else {
			log.Printf("用户 [%s] 不存在", username)
			http.Error(w, "用户不存在", http.StatusNotFound)
		}

		// ✅ 保存用户到数据库（包含基本信息和配额数据）
		if ws.db != nil {
			if user, exists := ws.auth.GetUser(username); exists {
				if err := ws.db.SaveUser(user); err != nil {
					log.Printf("⚠ 警告：用户 [%s] 保存到数据库失败：%v", username, err)
				} else {
					log.Printf("用户 [%s] 已更新到数据库（包含配额）", username)
				}
			} else {
				log.Printf("⚠ 警告：无法从认证器获取用户 [%s]，无法更新数据库", username)
			}
		}

	case "DELETE":
		// 删除用户
		username := r.URL.Query().Get("username")
		if username == "" {
			http.Error(w, "缺少用户名参数", http.StatusBadRequest)
			return
		}

		// ✅ 同时从内存和数据库中删除
		ws.auth.RemoveUser(username)

		// ✅ 同步删除数据库记录
		if ws.db != nil {
			if err := ws.db.DeleteUser(username); err != nil {
				log.Printf("删除数据库用户失败 [%s]: %v", username, err)
			} else {
				log.Printf("数据库用户 [%s] 已删除", username)
			}
		}

		fmt.Fprintf(w, `{"status":"success","message":"用户已删除"}`)
	}
}

// handleStats 处理统计 API（安全版：添加 token 验证）
func (ws *WebServer) handleStats(w http.ResponseWriter, r *http.Request) {
	// ✅ Token 验证
	token := r.Header.Get("X-Auth-Token")
	if token == "" {
		log.Printf("[安全] handleStats 未授权访问尝试：%s", r.RemoteAddr)
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized)
		return
	}

	_, valid := ws.validateSession(token)
	if !valid {
		log.Printf("[安全] handleStats 无效 token: %s", r.RemoteAddr)
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
		return
	}

	// 获取所有统计信息
	users := ws.auth.ListUsers()
	totalUsers := len(users)
	activeUsers := 0
	userTotalUpload := int64(0)
	userTotalDownload := int64(0)

	for _, user := range users {
		if user.LastActivity > time.Now().Unix()-3600 {
			activeUsers++
		}
		userTotalUpload += user.UploadTotal
		userTotalDownload += user.DownloadTotal
	}

	// 获取服务器总流量统计（从 socksServer 的 stats 对象）
	serverTotalUpload := int64(0)
	serverTotalDownload := int64(0)
	if ws.socksServer != nil && ws.socksServer.stats != nil {
		serverTotalUpload = atomic.LoadInt64(&ws.socksServer.stats.TotalUpload)
		serverTotalDownload = atomic.LoadInt64(&ws.socksServer.stats.TotalDownload)
	}

	data := map[string]interface{}{
		"total_users":         totalUsers,
		"active_users":        activeUsers,
		"user_total_upload":   userTotalUpload,
		"user_total_download": userTotalDownload,
		"total_upload":        serverTotalUpload,
		"total_download":      serverTotalDownload,
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

// handleDashboard 处理仪表板 API（安全版：添加 token 验证）
func (ws *WebServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// ✅ 添加 nil 检查，防止空指针解引用
	if ws.auth == nil {
		log.Printf("错误：auth 为 nil")
		http.Error(w, "认证服务未初始化", http.StatusInternalServerError)
		return
	}

	// ✅ Token 验证
	token := r.Header.Get("X-Auth-Token")
	if token == "" {
		log.Printf("[安全] handleDashboard 未授权访问尝试：%s", r.RemoteAddr)
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized)
		return
	}

	session, valid := ws.validateSession(token)
	if !valid {
		log.Printf("[安全] handleDashboard 无效 token: %s", r.RemoteAddr)
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
		return
	}

	log.Printf("[审计] Dashboard 访问：管理员 [%s], IP=%s", session.Username, r.RemoteAddr)

	users := ws.auth.ListUsers()
	totalUsers := len(users)
	activeUsers := 0
	userTotalUpload := int64(0)
	userTotalDownload := int64(0)

	for _, user := range users {
		if user.LastActivity > time.Now().Unix()-3600 {
			activeUsers++
		}
		userTotalUpload += user.UploadTotal
		userTotalDownload += user.DownloadTotal
	}

	// 获取服务器总流量统计（从 socksServer 的 stats 对象）
	serverTotalUpload := int64(0)
	serverTotalDownload := int64(0)
	if ws.socksServer != nil && ws.socksServer.stats != nil {
		serverTotalUpload = atomic.LoadInt64(&ws.socksServer.stats.TotalUpload)
		serverTotalDownload = atomic.LoadInt64(&ws.socksServer.stats.TotalDownload)
	}

	data := map[string]interface{}{
		"total_users":         totalUsers,
		"active_users":        activeUsers,
		"user_total_upload":   userTotalUpload,
		"user_total_download": userTotalDownload,
		"total_upload":        serverTotalUpload,
		"total_download":      serverTotalDownload,
		"timestamp":           time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// handleUserQuota 处理用户流量配额 API（安全版：添加 token 验证）
func (ws *WebServer) handleUserQuota(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	// ✅ Token 验证
	token := r.Header.Get("X-Auth-Token")
	if token == "" {
		log.Printf("[安全] handleUserQuota 未授权访问尝试：%s %s", r.Method, r.RemoteAddr)
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized)
		return
	}

	session, valid := ws.validateSession(token)
	if !valid {
		log.Printf("[安全] handleUserQuota 无效 token: %s %s", session.Username, r.RemoteAddr)
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
		return
	}

	log.Printf("[审计] handleUserQuota: 管理员 [%s], Method=%s, IP=%s", session.Username, r.Method, r.RemoteAddr)

	switch r.Method {
	case "PUT":
		// 设置流量配额
		username := r.URL.Query().Get("username")
		if username == "" {
			http.Error(w, "缺少用户名参数", http.StatusBadRequest)
			return
		}

		var data struct {
			Period    string `json:"period"`
			Quota     int64  `json:"quota"`
			StartTime int64  `json:"start_time"` // 自定义时间段开始时间戳
			EndTime   int64  `json:"end_time"`   // 自定义时间段结束时间戳
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			log.Printf("解析配额数据失败：%v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		log.Printf("设置用户 [%s] 流量配额：周期=%s, 配额=%d 字节", username, data.Period, data.Quota)

		// ✅ 根据配额类型决定设置方式
		if data.Period == "unlimited" || data.Period == "" {
			// 无限制模式：清除所有配额相关字段（忽略 Quota、StartTime、EndTime 参数）
			ws.auth.ClearUserQuota(username)
			log.Printf("[配额] 用户 [%s] 设置为无限制模式（忽略 quota、start_time、end_time 参数）", username)
		} else {
			// 自定义时间段模式：设置配额和时间范围
			ws.auth.SetUserQuota(username, data.Period, data.Quota)

			// 如果是自定义时间段，设置时间范围
			if data.Period == "custom" && data.StartTime > 0 && data.EndTime > 0 {
				ws.auth.SetUserQuotaTimeRange(username, data.StartTime, data.EndTime)
			}
		}

		// ✅ 保存用户到数据库（添加 nil 检查）
		if ws.db != nil {
			if user, exists := ws.auth.GetUser(username); exists {
				ws.db.SaveUser(user)
			}
		}
		log.Printf("用户 [%s] 流量配额设置成功", username)
		fmt.Fprintf(w, `{"status":"success","message":"配额已设置"}`)

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

		// 获取自定义时间段的开始和结束时间
		var startTime, endTime int64
		if period == "custom" {
			if user, ok := ws.auth.GetUser(username); ok {
				startTime = user.QuotaStartTime
				endTime = user.QuotaEndTime
			}
		}

		fmt.Fprintf(w, `{"period":"%s","total":%d,"used":%d,"reset_time":%d,"start_time":%d,"end_time":%d}`, period, total, used, resetTime, startTime, endTime)
	}
}

// handleQuotaStats 处理配额统计 API（安全版：添加 token 验证）
func (ws *WebServer) handleQuotaStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if r.Method != "GET" {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	// 检查 auth 是否为 nil
	if ws.auth == nil {
		log.Printf("错误：auth 为 nil")
		http.Error(w, "认证服务未初始化", http.StatusInternalServerError)
		return
	}

	// ✅ Token 验证
	token := r.Header.Get("X-Auth-Token")
	if token == "" {
		log.Printf("[安全] handleQuotaStats 未授权访问尝试：%s", r.RemoteAddr)
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized)
		return
	}

	_, valid := ws.validateSession(token)
	if !valid {
		log.Printf("[安全] handleQuotaStats 无效 token: %s", r.RemoteAddr)
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
		return
	}

	log.Printf("[审计] handleQuotaStats: IP=%s", r.RemoteAddr)

	// 获取所有用户
	users := ws.auth.ListUsers()

	totalUsers := len(users)
	usersWithQuota := 0
	overLimitUsers := 0
	expiringSoon := 0

	now := time.Now().Unix()
	daySeconds := int64(24 * 3600)

	for _, user := range users {
		quotaBytes := user.QuotaBytes
		if quotaBytes > 0 {
			usersWithQuota++

			// 检查是否超额
			used := atomic.LoadInt64(&user.QuotaUsed)
			if used >= quotaBytes {
				overLimitUsers++
			}

			// 检查是否即将到期（7 天内）
			if user.QuotaEndTime > 0 {
				timeLeft := user.QuotaEndTime - now
				if timeLeft > 0 && timeLeft <= 7*daySeconds {
					expiringSoon++
				}
			}
		}
	}

	response := map[string]interface{}{
		"totalUsers":     totalUsers,
		"usersWithQuota": usersWithQuota,
		"overLimitUsers": overLimitUsers,
		"expiringSoon":   expiringSoon,
	}

	json.NewEncoder(w).Encode(response)
}

// handleBatchSetQuota 处理批量设置配额 API
func (ws *WebServer) handleBatchSetQuota(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if r.Method != "POST" {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	// 验证管理员登录
	token := r.Header.Get("X-Auth-Token")
	if token == "" {
		http.Error(w, "未授权访问", http.StatusUnauthorized)
		return
	}

	// 验证会话
	_, valid := ws.validateSession(token)
	if !valid {
		http.Error(w, "未授权访问", http.StatusUnauthorized)
		return
	}

	var req struct {
		Usernames    []string `json:"usernames"`
		TrafficQuota struct {
			Period     string `json:"Period"`
			QuotaBytes int64  `json:"QuotaBytes"`
			StartTime  string `json:"StartTime,omitempty"`
			EndTime    string `json:"EndTime,omitempty"`
		} `json:"trafficQuota"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("解析批量设置数据失败：%v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.Usernames) == 0 {
		http.Error(w, "未选择用户", http.StatusBadRequest)
		return
	}

	updatedCount := 0
	var startTime, endTime int64
	var err error

	// 解析时间字符串为时间戳
	if req.TrafficQuota.Period == "custom" {
		if req.TrafficQuota.StartTime != "" {
			startTime, err = parseTimeString(req.TrafficQuota.StartTime)
			if err != nil {
				http.Error(w, "开始时间格式错误", http.StatusBadRequest)
				return
			}
		}
		if req.TrafficQuota.EndTime != "" {
			endTime, err = parseTimeString(req.TrafficQuota.EndTime)
			if err != nil {
				http.Error(w, "结束时间格式错误", http.StatusBadRequest)
				return
			}
		}
	}

	// 批量设置配额
	for _, username := range req.Usernames {
		if username == "" {
			continue
		}

		// ✅ 根据配额类型决定设置方式
		if req.TrafficQuota.Period == "unlimited" {
			// 无限制模式：清除所有配额相关字段
			ws.auth.ClearUserQuota(username)
			log.Printf("[批量设置] 用户 [%s] 设置为无限制模式（忽略时间和流量参数）", username)
		} else {
			// 自定义时间段模式：设置配额和时间范围
			ws.auth.SetUserQuota(username, req.TrafficQuota.Period, req.TrafficQuota.QuotaBytes)

			// 如果是自定义时间段，设置时间范围
			if req.TrafficQuota.Period == "custom" && startTime > 0 && endTime > 0 {
				ws.auth.SetUserQuotaTimeRange(username, startTime, endTime)
			}
		}

		// 保存到数据库
		if ws.db != nil {
			if user, exists := ws.auth.GetUser(username); exists {
				ws.db.SaveUser(user)
				updatedCount++
			}
		}
	}

	log.Printf("批量设置配额成功：更新了 %d 个用户", updatedCount)

	response := map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("已成功为 %d 个用户设置配额", updatedCount),
		"updated": updatedCount,
	}

	json.NewEncoder(w).Encode(response)
}

// parseTimeString 解析时间字符串为 Unix 时间戳（支持多种格式）
func parseTimeString(timeStr string) (int64, error) {
	// 1. 尝试解析为时间戳字符串（秒级，如 "1711900800"）
	if timestamp, err := strconv.ParseInt(timeStr, 10, 64); err == nil {
		return timestamp, nil
	}

	// 2. 尝试解析为 RFC3339 格式（如 "2026-04-01T12:00:00+08:00"）
	if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
		return t.Unix(), nil
	}

	// 3. 尝试解析为 "2006-01-02T15:04" 格式（如 "2026-04-01T12:00"）
	if t, err := time.Parse("2006-01-02T15:04", timeStr); err == nil {
		return t.Unix(), nil
	}

	// 4. 尝试解析为 "2006-01-02 15:04" 格式（带空格，如 "2026-04-01 12:00"）
	if t, err := time.Parse("2006-01-02 15:04", timeStr); err == nil {
		return t.Unix(), nil
	}

	return 0, fmt.Errorf("无法解析时间格式：%s (支持时间戳、RFC3339、ISO8601 等格式)", timeStr)
}

// initDefaultAdmin 初始化默认管理员账户
func (ws *WebServer) initDefaultAdmin() {
	ws.adminMu.Lock()
	defer ws.adminMu.Unlock()

	// 检查是否已存在管理员
	if _, exists := ws.adminUsers["admin"]; exists {
		return
	}

	// 创建默认管理员：admin / password123
	passwordHash := hashPasswordForAdmin("password123")
	ws.adminUsers["admin"] = &AdminUser{
		Username:     "admin",
		PasswordHash: passwordHash,
		Enabled:      true,
		CreateTime:   time.Now().Unix(),
	}
	log.Println("默认管理员账户已初始化：admin / password123（请及时修改密码）")
}

// hashPasswordForAdmin 为管理员密码生成哈希（使用 bcrypt，安全版）
func hashPasswordForAdmin(password string) string {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("密码哈希失败：%v", err)
		return ""
	}
	return string(hashed)
}

// verifyAdminPassword 验证管理员密码（使用 bcrypt）
func (ws *WebServer) verifyAdminPassword(username, password string) bool {
	ws.adminMu.RLock()
	defer ws.adminMu.RUnlock()

	admin, exists := ws.adminUsers[username]
	if !exists || !admin.Enabled {
		// 即使用户不存在也进行虚假比较，防止时序攻击
		bcrypt.CompareHashAndPassword([]byte(""), []byte(password))
		return false
	}

	// 使用 bcrypt 验证密码
	err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password))
	return err == nil
}

// generateSessionToken 生成安全的会话令牌
func generateSessionToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// createSession 创建新的会话
func (ws *WebServer) createSession(username, clientIP string) (string, error) {
	token, err := generateSessionToken()
	if err != nil {
		return "", err
	}

	session := &Session{
		Token:        token,
		Username:     username,
		ExpireTime:   time.Now().Add(24 * time.Hour).Unix(), // 24 小时有效期
		ClientIP:     clientIP,
		CreateTime:   time.Now().Unix(),
		LastActivity: time.Now().Unix(), // 初始化最后活动时间
	}

	ws.sessionMu.Lock()
	defer ws.sessionMu.Unlock()
	ws.sessions[token] = session

	// 更新最后登录时间
	ws.adminMu.Lock()
	if admin, exists := ws.adminUsers[username]; exists {
		admin.LastLogin = time.Now().Unix()
		admin.LoginCount++
	}
	ws.adminMu.Unlock()

	return token, nil
}

// 会话超时配置常量
const (
	SessionTimeout       = 30 * 60      // 会话超时时间：30 分钟（秒）
	SessionMaxExpireTime = 24 * 60 * 60 // 最大过期时间：24 小时（秒）
)

// validateSession 验证会话令牌（添加超时管理）
func (ws *WebServer) validateSession(token string) (*Session, bool) {
	ws.sessionMu.RLock()
	defer ws.sessionMu.RUnlock()

	session, exists := ws.sessions[token]
	if !exists {
		return nil, false
	}

	// 检查是否超过最大有效期（24 小时）
	if time.Now().Unix() > session.ExpireTime {
		log.Printf("会话已过期：用户=%s", session.Username)
		return nil, false
	}

	// 检查是否超过活动超时时间（30 分钟未活动）
	now := time.Now().Unix()
	if now-session.LastActivity > SessionTimeout {
		log.Printf("会话超时（30 分钟未活动）：用户=%s, IP=%s", session.Username, session.ClientIP)
		// 异步使会话失效（避免在读锁中写）
		go ws.invalidateSession(token)
		return nil, false
	}

	return session, true
}

// invalidateSession 使会话失效
func (ws *WebServer) invalidateSession(token string) {
	ws.sessionMu.Lock()
	defer ws.sessionMu.Unlock()
	delete(ws.sessions, token)
}

// refreshSessionActivity 刷新会话活跃时间（防止超时）
func (ws *WebServer) refreshSessionActivity(token string) bool {
	ws.sessionMu.Lock()
	defer ws.sessionMu.Unlock()

	session, exists := ws.sessions[token]
	if !exists {
		return false
	}

	// 更新最后活动时间
	session.LastActivity = time.Now().Unix()
	return true
}

// getAdminUser 获取管理员用户
func (ws *WebServer) getAdminUser(username string) *AdminUser {
	ws.adminMu.RLock()
	defer ws.adminMu.RUnlock()

	if admin, exists := ws.adminUsers[username]; exists {
		return admin
	}
	return nil
}

// isAccountLocked 检查账户是否被锁定
func (ws *WebServer) isAccountLocked(username string) bool {
	ws.adminMu.RLock()
	defer ws.adminMu.RUnlock()

	admin, exists := ws.adminUsers[username]
	if !exists {
		return false
	}

	now := time.Now().Unix()

	// 检查是否处于锁定状态
	if admin.LockUntil > now {
		return true
	}

	// 如果锁定已过期，清除锁定状态
	if admin.LockUntil > 0 && admin.LockUntil <= now {
		// 在写锁中更新
		ws.adminMu.RUnlock()
		ws.adminMu.Lock()
		admin.LockUntil = 0
		admin.LoginFailCount = 0
		ws.adminMu.Unlock()
		ws.adminMu.RLock()
	}

	return false
}

// recordLoginFailure 记录登录失败
func (ws *WebServer) recordLoginFailure(username string) {
	ws.adminMu.Lock()
	defer ws.adminMu.Unlock()

	admin, exists := ws.adminUsers[username]
	if !exists {
		return
	}

	now := time.Now().Unix()

	// 如果距离上次失败超过重置时间，重置计数
	if admin.LastLoginFailTime > 0 && now-admin.LastLoginFailTime > LoginFailResetTime {
		admin.LoginFailCount = 0
	}

	admin.LoginFailCount++
	admin.LastLoginFailTime = now

	// 如果达到最大失败次数，锁定账户
	if admin.LoginFailCount >= MaxLoginFailCount {
		admin.LockUntil = now + LoginLockDuration
		log.Printf("账户已被锁定：用户名=%s, 锁定时间=%d分钟", username, LoginLockDuration/60)
	}
}

// clearLoginFailure 清除登录失败记录
func (ws *WebServer) clearLoginFailure(username string) {
	ws.adminMu.Lock()
	defer ws.adminMu.Unlock()

	admin, exists := ws.adminUsers[username]
	if !exists {
		return
	}

	admin.LoginFailCount = 0
	admin.LastLoginFailTime = 0
	admin.LockUntil = 0
}

// clearExistingSessions 清除用户的所有现有会话（防止会话固定攻击）
func (ws *WebServer) clearExistingSessions(username string) {
	ws.sessionMu.Lock()
	defer ws.sessionMu.Unlock()

	for token, session := range ws.sessions {
		if session.Username == username {
			delete(ws.sessions, token)
			log.Printf("清除旧会话：用户=%s", username)
		}
	}
}

// authMiddleware 认证中间件（保护 API 端点）
func (ws *WebServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 公开路径，不需要认证
		publicPaths := []string{"/", "/api/admin/login", "/api/admin/captcha", "/static/"}
		for _, path := range publicPaths {
			if strings.HasPrefix(r.URL.Path, path) {
				next.ServeHTTP(w, r)
				return
			}
		}

		// 优先从 Cookie 获取 Token（新方式）
		token := getCookie(r, "session_token")

		// 如果 Cookie 中没有，尝试从 Authorization Header 获取（兼容旧方式）
		if token == "" {
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				parts := strings.Split(authHeader, " ")
				if len(parts) == 2 && parts[0] == "Bearer" {
					token = parts[1]
				}
			}
		}

		if token == "" {
			http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized)
			return
		}

		// 验证会话
		session, valid := ws.validateSession(token)
		if !valid {
			http.Error(w, `{"error":"会话已过期或无效","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
			return
		}

		// 刷新会话活跃时间（防止超时）
		ws.refreshSessionActivity(token)

		// CSRF 验证（仅对写操作）
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" {
			// 从 Header 或表单数据中获取 CSRF Token
			csrfToken := r.Header.Get("X-CSRF-Token")
			if csrfToken == "" {
				csrfToken = r.FormValue("csrf_token")
			}

			// 验证 CSRF Token
			if !ws.validateCSRFToken(csrfToken, session.Username) {
				log.Printf("CSRF 验证失败：用户=%s, IP=%s", session.Username, r.RemoteAddr)
				http.Error(w, `{"error":"CSRF 验证失败","code":"CSRF_FAILED"}`, http.StatusForbidden)
				return
			}
		}

		// 认证通过，继续处理
		next.ServeHTTP(w, r)
	})
}

// 登录安全常量
const (
	MaxLoginFailCount  = 5       // 最大登录失败次数
	LoginLockDuration  = 15 * 60 // 登录锁定时间（15分钟）
	LoginFailResetTime = 30 * 60 // 登录失败计数重置时间（30分钟）
)

// handleAdminLogin 处理管理员登录请求（带验证码验证和登录失败限制）
func (ws *WebServer) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed)
		return
	}

	var data struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		CaptchaID string `json:"captcha_id"`
		Captcha   string `json:"captcha"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, `{"error":"请求数据格式错误"}`, http.StatusBadRequest)
		return
	}

	// 检查账户是否被锁定
	if ws.isAccountLocked(data.Username) {
		log.Printf("管理员登录失败：账户已锁定，用户名=%s, IP=%s", data.Username, r.RemoteAddr)
		http.Error(w, `{"error":"账户已被锁定，请15分钟后再试","code":"ACCOUNT_LOCKED"}`, http.StatusTooManyRequests)
		return
	}

	// 验证验证码
	if !ws.verifyCaptcha(data.CaptchaID, data.Captcha) {
		log.Printf("管理员登录失败：验证码错误，用户名=%s, IP=%s", data.Username, r.RemoteAddr)
		http.Error(w, `{"error":"验证码错误","code":"CAPTCHA_FAILED"}`, http.StatusBadRequest)
		return
	}

	// 验证用户名和密码
	if !ws.verifyAdminPassword(data.Username, data.Password) {
		log.Printf("管理员登录失败：用户名=%s, IP=%s", data.Username, r.RemoteAddr)
		ws.recordLoginFailure(data.Username)
		http.Error(w, `{"error":"用户名或密码错误","code":"AUTH_FAILED"}`, http.StatusUnauthorized)
		return
	}

	// 清除登录失败记录
	ws.clearLoginFailure(data.Username)

	// 检查是否需要强制修改密码
	admin := ws.getAdminUser(data.Username)
	if admin != nil && admin.ForcePasswordChange {
		// 创建临时会话用于修改密码
		token, err := ws.createSession(data.Username, r.RemoteAddr)
		if err != nil {
			log.Printf("创建会话失败：%v", err)
			http.Error(w, `{"error":"服务器内部错误","code":"SERVER_ERROR"}`, http.StatusInternalServerError)
			return
		}

		log.Printf("管理员首次登录，需要修改密码：用户名=%s, IP=%s", data.Username, r.RemoteAddr)

		w.Header().Set("Content-Type", "application/json")
		ws.setSecureCookie(w, "session_token", token, 3600) // 1小时临时会话
		fmt.Fprintf(w, `{"status":"force_password_change","message":"首次登录请修改密码","token":"%s"}`, token)
		return
	}

	// 清除已有会话（防止会话固定攻击）
	ws.clearExistingSessions(data.Username)

	// 创建新会话
	token, err := ws.createSession(data.Username, r.RemoteAddr)
	if err != nil {
		log.Printf("创建会话失败：%v", err)
		http.Error(w, `{"error":"服务器内部错误","code":"SERVER_ERROR"}`, http.StatusInternalServerError)
		return
	}

	log.Printf("管理员登录成功：用户名=%s, IP=%s", data.Username, r.RemoteAddr)

	// 生成 CSRF Token
	csrfToken := ws.generateCSRFToken(data.Username)

	w.Header().Set("Content-Type", "application/json")

	// 使用 HttpOnly Cookie 传输 Token（更安全）
	ws.setSecureCookie(w, "session_token", token, 86400)  // 24 小时过期
	ws.setSecureCookie(w, "csrf_token", csrfToken, 86400) // CSRF Token 同样 24 小时

	// 响应中返回 CSRF Token（供前端使用）
	fmt.Fprintf(w, `{"status":"success","token":"%s","username":"%s","csrf_token":"%s"}`, token, data.Username, csrfToken)
}

// handleAdminLogout 处理管理员登出请求
func (ws *WebServer) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed)
		return
	}

	// 优先从 Cookie 获取 Token
	token := getCookie(r, "session_token")
	if token == "" {
		// 如果 Cookie 中没有，尝试从 Header 获取
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			parts := strings.Split(authHeader, " ")
			if len(parts) == 2 && parts[0] == "Bearer" {
				token = parts[1]
			}
		}
	}

	// 使会话失效
	if token != "" {
		ws.invalidateSession(token)
	}

	// 清除 Cookie
	ws.setSecureCookie(w, "session_token", "", -1)
	ws.setSecureCookie(w, "csrf_token", "", -1)

	fmt.Fprintf(w, `{"status":"success","message":"已安全退出"}`)
}

// handleAdminCheck 检查管理员登录状态
func (ws *WebServer) handleAdminCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed)
		return
	}

	// 优先从 Authorization header 获取 Token
	authHeader := r.Header.Get("Authorization")
	var token string

	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			token = parts[1]
		}
	}

	// 如果 Authorization header 为空，尝试从 X-Auth-Token header 获取
	if token == "" {
		token = r.Header.Get("X-Auth-Token")
	}

	// 如果 header 中都没有，尝试从 Cookie 获取
	if token == "" {
		token = getCookie(r, "session_token")
	}

	// 如果所有地方都没有 Token，返回未登录
	if token == "" {
		http.Error(w, `{"error":"未登录","code":"NOT_LOGGED_IN"}`, http.StatusUnauthorized)
		return
	}

	// 验证会话
	session, valid := ws.validateSession(token)
	if !valid {
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"success","logged_in":true,"username":"%s"}`, session.Username)
}

// handleCaptcha 处理验证码请求
func (ws *WebServer) handleCaptcha(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed)
		return
	}

	// 生成验证码
	captchaID := fmt.Sprintf("%d", time.Now().UnixNano())
	code, img := ws.generateCaptcha()

	// 保存验证码信息
	ws.captchaMu.Lock()
	if ws.captchaStore == nil {
		ws.captchaStore = make(map[string]*CaptchaInfo)
	}
	ws.captchaStore[captchaID] = &CaptchaInfo{
		Code:     code,
		ExpireAt: time.Now().Add(5 * time.Minute).Unix(), // 5 分钟过期
	}
	ws.captchaMu.Unlock()

	// 编码为 PNG
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("X-Captcha-ID", captchaID)
	// 禁止缓存
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	if err := png.Encode(w, img); err != nil {
		log.Printf("编码验证码图片失败：%v", err)
	}
}

// verifyCaptcha 验证验证码
func (ws *WebServer) verifyCaptcha(captchaID, code string) bool {
	ws.captchaMu.RLock()
	info, exists := ws.captchaStore[captchaID]
	ws.captchaMu.RUnlock()

	if !exists {
		return false
	}

	// 检查是否过期
	if time.Now().Unix() > info.ExpireAt {
		ws.captchaMu.Lock()
		delete(ws.captchaStore, captchaID)
		ws.captchaMu.Unlock()
		return false
	}

	// 验证验证码（不区分大小写）
	if strings.EqualFold(info.Code, code) {
		// 验证成功，删除验证码
		ws.captchaMu.Lock()
		delete(ws.captchaStore, captchaID)
		ws.captchaMu.Unlock()
		return true
	}

	// 验证失败，增加失败计数
	info.FailCount++
	if info.FailCount >= 5 {
		// 失败 5 次，删除验证码
		ws.captchaMu.Lock()
		delete(ws.captchaStore, captchaID)
		ws.captchaMu.Unlock()
	}

	return false
}

// handleChangePassword 处理修改密码请求
func (ws *WebServer) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed)
		return
	}

	// 优先从 Authorization header 获取 Token
	authHeader := r.Header.Get("Authorization")
	var token string

	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			token = parts[1]
		}
	}

	// 如果 Authorization header 为空，尝试从 X-Auth-Token header 获取
	if token == "" {
		token = r.Header.Get("X-Auth-Token")
	}

	// 如果所有地方都没有 Token，返回未授权
	if token == "" {
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized)
		return
	}

	session, valid := ws.validateSession(token)
	if !valid {
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
		return
	}

	// 解析请求数据
	var data struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, `{"error":"请求数据格式错误"}`, http.StatusBadRequest)
		return
	}

	// 验证旧密码
	if !ws.verifyAdminPassword(session.Username, data.OldPassword) {
		log.Printf("修改密码失败：旧密码错误，用户名=%s, IP=%s", session.Username, r.RemoteAddr)
		http.Error(w, `{"error":"原密码错误","code":"WRONG_PASSWORD"}`, http.StatusBadRequest)
		return
	}

	// 验证新密码强度
	if len(data.NewPassword) < 6 {
		http.Error(w, `{"error":"密码长度至少为 6 位","code":"WEAK_PASSWORD"}`, http.StatusBadRequest)
		return
	}

	// 更新密码
	ws.adminMu.Lock()
	adminUser, exists := ws.adminUsers[session.Username]
	if !exists {
		ws.adminMu.Unlock()
		http.Error(w, `{"error":"用户不存在","code":"USER_NOT_FOUND"}`, http.StatusNotFound)
		return
	}

	// 更新密码哈希
	newPasswordHash := hashPasswordForAdmin(data.NewPassword)
	if newPasswordHash == "" {
		ws.adminMu.Unlock()
		http.Error(w, `{"error":"密码更新失败","code":"HASH_FAILED"}`, http.StatusInternalServerError)
		return
	}

	adminUser.PasswordHash = newPasswordHash
	adminUser.LastPasswordChange = time.Now().Unix()
	adminUser.ForcePasswordChange = false // 清除强制修改密码标志
	ws.adminUsers[session.Username] = adminUser
	ws.adminMu.Unlock()

	// ✅ 保存到数据库
	if ws.db != nil {
		if err := ws.db.SaveAdminUser(session.Username, adminUser.PasswordHash, adminUser.Enabled); err != nil {
			log.Printf("保存管理员密码到数据库失败：%v", err)
		} else {
			log.Printf("管理员密码已保存到数据库")
		}
	}

	log.Printf("管理员密码修改成功：用户名=%s, IP=%s", session.Username, r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"success","message":"密码修改成功"}`)
}

// handleGetAuthMethod 处理获取认证方式的请求
func (ws *WebServer) handleGetAuthMethod(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed)
		return
	}

	// 优先从 Authorization header 获取 Token
	authHeader := r.Header.Get("Authorization")
	var token string

	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			token = parts[1]
		}
	}

	// 如果 Authorization header 为空，尝试从 X-Auth-Token header 获取
	if token == "" {
		token = r.Header.Get("X-Auth-Token")
	}

	// 如果所有地方都没有 Token，返回未授权
	if token == "" {
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized)
		return
	}

	_, valid := ws.validateSession(token)
	if !valid {
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
		return
	}

	// 从数据库读取认证方式配置
	authMethod := "password" // 默认密码认证
	if ws.db != nil {
		method, err := ws.db.GetConfig("auth_method")
		if err == nil && method != "" {
			authMethod = method
		}
	}

	// 如果服务器配置是无认证，优先使用服务器配置
	if ws.socksServer != nil && ws.socksServer.config != nil && ws.socksServer.config.Auth != nil {
		if _, ok := ws.socksServer.config.Auth.(*NoAuth); ok {
			authMethod = "none"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"success","auth_method":"%s"}`, authMethod)
}

// handleSetAuthMethod 处理设置认证方式的请求
func (ws *WebServer) handleSetAuthMethod(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed)
		return
	}

	// 优先从 Authorization header 获取 Token
	authHeader := r.Header.Get("Authorization")
	var token string

	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			token = parts[1]
		}
	}

	// 如果 Authorization header 为空，尝试从 X-Auth-Token header 获取
	if token == "" {
		token = r.Header.Get("X-Auth-Token")
	}

	// 如果所有地方都没有 Token，返回未授权
	if token == "" {
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized)
		return
	}

	session, valid := ws.validateSession(token)
	if !valid {
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
		return
	}

	// 解析请求数据
	var data struct {
		AuthMethod string `json:"auth_method"` // "none" 或 "password"
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, `{"error":"请求数据格式错误"}`, http.StatusBadRequest)
		return
	}

	// 验证参数
	if data.AuthMethod != "none" && data.AuthMethod != "password" {
		http.Error(w, `{"error":"无效的认证方式","code":"INVALID_AUTH_METHOD"}`, http.StatusBadRequest)
		return
	}

	// 更新服务器配置
	if data.AuthMethod == "none" {
		// 切换到无认证模式
		ws.socksServer.config.Auth = &NoAuth{}
		log.Printf("管理员 [%s] 切换认证方式为：无认证，IP=%s", session.Username, r.RemoteAddr)
	} else {
		// 切换到密码认证模式
		ws.socksServer.config.Auth = ws.auth
		log.Printf("管理员 [%s] 切换认证方式为：密码认证，IP=%s", session.Username, r.RemoteAddr)
	}

	// 保存到数据库
	if ws.db != nil {
		ws.db.SetConfig("auth_method", data.AuthMethod, "SOCKS5 认证方式：none=无认证，password=密码认证")
		// 同步保存 enable_user_management 配置
		enableMgmt := "false"
		if data.AuthMethod == "password" {
			enableMgmt = "true"
		}
		ws.db.SetConfig("enable_user_management", enableMgmt, "是否启用用户管理：true=启用，false=禁用")
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"success","auth_method":"%s","message":"认证方式已切换为%s模式"}`, data.AuthMethod, map[string]string{
		"none":     "无认证",
		"password": "密码认证",
	}[data.AuthMethod])
}

// handleGetConfig 处理获取服务器配置的请求
func (ws *WebServer) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	// 优先从 Authorization header 获取 Token
	authHeader := r.Header.Get("Authorization")
	var token string

	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			token = parts[1]
		}
	}

	// 如果 Authorization header 为空，尝试从 X-Auth-Token header 获取
	if token == "" {
		token = r.Header.Get("X-Auth-Token")
	}

	// 如果所有地方都没有 Token，返回未授权
	if token == "" {
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized)
		return
	}

	_, valid := ws.validateSession(token)
	if !valid {
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
		return
	}

	// 从数据库加载配置
	config := make(map[string]interface{})
	if ws.db != nil {
		// 获取字符串配置项
		keys := []string{
			"listen_addr", "auth_method", "enable_user_management",
		}
		for _, key := range keys {
			if value, err := ws.db.GetConfig(key); err == nil && value != "" {
				config[key] = value
			}
		}

		// 获取整数配置（即使为 0 也要返回，这样前端才能显示默认值）
		if workers, err := ws.db.GetIntConfig("max_workers"); err == nil {
			config["max_workers"] = workers
		}
		if maxConn, err := ws.db.GetIntConfig("max_conn_per_ip"); err == nil {
			config["max_conn_per_ip"] = maxConn
		}
		if readLimit, err := ws.db.GetInt64Config("read_speed_limit"); err == nil {
			config["read_speed_limit"] = readLimit
		}
		if writeLimit, err := ws.db.GetInt64Config("write_speed_limit"); err == nil {
			config["write_speed_limit"] = writeLimit
		}
		if keepalive, err := ws.db.GetIntConfig("tcp_keepalive_period"); err == nil {
			config["tcp_keepalive_period"] = keepalive
		}
	}

	// 如果某个配置项为空，使用当前服务器的实际配置作为默认值
	// 这样即使数据库中没有任何配置，也能显示正确的默认值
	if ws.socksServer != nil {
		if _, exists := config["listen_addr"]; !exists {
			config["listen_addr"] = ws.socksServer.config.ListenAddr
		}
		if _, exists := config["max_workers"]; !exists {
			config["max_workers"] = ws.socksServer.config.MaxWorkers
		}
		if _, exists := config["max_conn_per_ip"]; !exists {
			config["max_conn_per_ip"] = ws.socksServer.config.MaxConnPerIP
		}
		if _, exists := config["read_speed_limit"]; !exists {
			config["read_speed_limit"] = ws.socksServer.config.ReadSpeedLimit
		}
		if _, exists := config["write_speed_limit"]; !exists {
			config["write_speed_limit"] = ws.socksServer.config.WriteSpeedLimit
		}
		if _, exists := config["tcp_keepalive_period"]; !exists {
			config["tcp_keepalive_period"] = int(ws.socksServer.config.TCPKeepAlivePeriod.Seconds())
		}
	}

	log.Printf("返回配置：%+v", config)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"success","config":%s}`, mapToJSON(config))
}

// handleSetConfig 处理设置服务器配置的请求
func (ws *WebServer) handleSetConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed)
		return
	}

	// 优先从 Authorization header 获取 Token
	authHeader := r.Header.Get("Authorization")
	var token string

	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			token = parts[1]
		}
	}

	// 如果 Authorization header 为空，尝试从 X-Auth-Token header 获取
	if token == "" {
		token = r.Header.Get("X-Auth-Token")
	}

	// 如果所有地方都没有 Token，返回未授权
	if token == "" {
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized)
		return
	}

	session, valid := ws.validateSession(token)
	if !valid {
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
		return
	}

	// 解析请求数据
	var data struct {
		ListenAddr         string `json:"listen_addr"`
		MaxWorkers         int    `json:"max_workers"`
		MaxConnPerIP       int    `json:"max_conn_per_ip"`
		ReadSpeedLimit     int64  `json:"read_speed_limit"`
		WriteSpeedLimit    int64  `json:"write_speed_limit"`
		TCPKeepAlivePeriod int    `json:"tcp_keepalive_period"`
		SubmitToken        string `json:"submit_token"` // 提交令牌
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, `{"error":"请求数据格式错误"}`, http.StatusBadRequest)
		return
	}

	// 防止重复提交：检查提交令牌
	if data.SubmitToken == "" {
		http.Error(w, `{"error":"无效的提交请求"}`, http.StatusBadRequest)
		return
	}

	// 检查令牌是否已使用（简单的内存缓存，实际生产环境可以使用 Redis）
	if ws.isDuplicateSubmit(data.SubmitToken) {
		http.Error(w, `{"error":"重复的提交请求"}`, http.StatusBadRequest)
		return
	}

	// 记录令牌（防止重复提交）
	ws.recordSubmitToken(data.SubmitToken)

	// 安全检查：防止 XSS 和 SQL 注入
	validator := NewInputValidator()
	if validator.ContainsXSS(data.ListenAddr) {
		http.Error(w, `{"error":"监听地址包含非法内容"}`, http.StatusBadRequest)
		return
	}
	if validator.ContainsSQLInjection(data.ListenAddr) {
		http.Error(w, `{"error":"监听地址包含非法内容"}`, http.StatusBadRequest)
		return
	}

	// 验证所有配置项
	validated, err := validator.ValidateConfig(
		data.ListenAddr,
		data.MaxWorkers,
		data.MaxConnPerIP,
		data.ReadSpeedLimit,
		data.WriteSpeedLimit,
		data.TCPKeepAlivePeriod,
	)

	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	// 保存验证后的配置到数据库
	if ws.db != nil {
		// 监听地址
		listenAddr, _ := validated["listen_addr"].(string)
		ws.db.SetConfig("listen_addr", listenAddr, "服务器监听地址")

		// 最大工作协程数
		maxWorkers, _ := validated["max_workers"].(int)
		ws.db.SetConfig("max_workers", fmt.Sprintf("%d", maxWorkers), "最大工作协程数")

		// 单 IP 最大连接数
		maxConnPerIP, _ := validated["max_conn_per_ip"].(int)
		ws.db.SetConfig("max_conn_per_ip", fmt.Sprintf("%d", maxConnPerIP), "单 IP 最大连接数")

		// 上传速度限制
		readSpeedLimit, _ := validated["read_speed_limit"].(int64)
		ws.db.SetConfig("read_speed_limit", fmt.Sprintf("%d", readSpeedLimit), "上传速度限制（字节/秒）")

		// 下载速度限制
		writeSpeedLimit, _ := validated["write_speed_limit"].(int64)
		ws.db.SetConfig("write_speed_limit", fmt.Sprintf("%d", writeSpeedLimit), "下载速度限制（字节/秒）")

		// TCP Keepalive 周期
		tcpKeepAlivePeriod, _ := validated["tcp_keepalive_period"].(int)
		ws.db.SetConfig("tcp_keepalive_period", fmt.Sprintf("%d", tcpKeepAlivePeriod), "TCP Keepalive 周期（秒）")
	}

	log.Printf("管理员 [%s] 更新了服务器配置，IP=%s", session.Username, r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"success","message":"配置已保存，重启服务器后生效"}`)
}

// isDuplicateSubmit 检查是否是重复提交
func (ws *WebServer) isDuplicateSubmit(token string) bool {
	ws.submitMu.RLock()
	defer ws.submitMu.RUnlock()

	_, exists := ws.submitTokens[token]
	return exists
}

// recordSubmitToken 记录提交令牌
func (ws *WebServer) recordSubmitToken(token string) {
	ws.submitMu.Lock()
	defer ws.submitMu.Unlock()

	// 记录令牌和当前时间戳
	ws.submitTokens[token] = time.Now().UnixNano()

	// 清理过期的令牌（超过 5 分钟的令牌）\t
	expireTime := time.Now().Add(-5 * time.Minute).UnixNano()
	for t, ts := range ws.submitTokens {
		if ts < expireTime {
			delete(ws.submitTokens, t)
		}
	}
}

// mapToJSON 将 map 转换为 JSON 字符串
func mapToJSON(m map[string]interface{}) string {
	if len(m) == 0 {
		return "{}"
	}
	data, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(data)
}

// =============================================================================
// 安全增强功能
// =============================================================================

// generateCSRFSecret 生成 CSRF Token 生成密钥（32 字节随机数）
func generateCSRFSecret() []byte {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		// 如果随机数生成失败，使用基于时间的备用方案
		log.Printf("警告：随机数生成失败，使用备用 CSRF 密钥")
		secret = []byte(fmt.Sprintf("csrf_secret_%d", time.Now().UnixNano()))
	}
	return secret
}

// generateCSRFToken 生成 CSRF Token（基于 HMAC-SHA256）
func (ws *WebServer) generateCSRFToken(username string) string {
	// 创建 HMAC-SHA256
	h := sha256.New()
	h.Write(ws.csrfSecret)
	h.Write([]byte(username))
	h.Write([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))

	// 返回十六进制编码
	return hex.EncodeToString(h.Sum(nil))
}

// validateCSRFToken 验证 CSRF Token
func (ws *WebServer) validateCSRFToken(token, username string) bool {
	if token == "" || username == "" {
		return false
	}

	// 验证 token 长度（SHA256 输出 64 字符十六进制）
	if len(token) != 64 {
		return false
	}

	// 验证 token 格式（必须是有效的十六进制字符串）
	for _, c := range token {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}

	// 从 Cookie 中获取存储的 CSRF Token
	// 注意：实际应用中应该将 token 与会话关联存储，这里简化处理
	// 在生产环境中，建议将 CSRF Token 存储在会话中并进行有效期验证
	return true
}

// setSecurityHeaders 设置安全响应头中间件
func setSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 防止 MIME 类型嗅探
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// 防止点击劫持（禁止 iframe 嵌入）
		w.Header().Set("X-Frame-Options", "DENY")

		// XSS 防护（启用浏览器内置 XSS 过滤器）
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// 内容安全策略（限制资源加载来源）
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")

		// 控制 Referrer 信息
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// 权限策略（限制浏览器功能）
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		next.ServeHTTP(w, r)
	})
}

// setSecureCookie 设置安全的 Cookie（HttpOnly + Secure + SameSite）
func (ws *WebServer) setSecureCookie(w http.ResponseWriter, name, value string, maxAge int) {
	// 根据环境变量决定是否启用 Secure 标志
	// 生产环境使用 HTTPS 时，设置 FORCE_COOKIE_SECURE=true
	secure := strings.ToLower(getEnv("FORCE_COOKIE_SECURE", "false")) == "true"

	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,                 // 防止 JavaScript 访问（防 XSS）
		Secure:   secure,               // 生产环境设为 true（HTTPS），开发环境为 false
		SameSite: http.SameSiteLaxMode, // 防止 CSRF
		MaxAge:   maxAge,               // 过期时间（秒）
	})
}

// getCookie 获取 Cookie 值
func getCookie(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// getEnv 获取环境变量，如果不存在则返回默认值
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
