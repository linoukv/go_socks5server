// Package main 实现 SOCKS5 代理服务器的 Web 管理界面模块。
// 提供基于 HTTP 的用户管理、流量统计、配额设置、系统配置等功能，
// 包含会话管理、CSRF 防护、验证码、速率限制等安全机制。
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
	"golang.org/x/time/rate"
)

// RateLimiter 基于 IP 的速率限制器，防止 API 滥用。
// 使用 golang.org/x/time/rate 包实现令牌桶算法。
type RateLimiter struct {
	mu       sync.Mutex               // 保护 visitors map，确保并发安全
	visitors map[string]*rate.Limiter // IP -> 限流器映射，每个 IP 独立的限流器
	rate     rate.Limit               // 每秒允许的请求数（令牌生成速率）
	burst    int                      // 允许的最大突发请求数（令牌桶容量） 
}

// AdminUser Web 管理员用户结构体。
// 包含登录状态、失败计数、账户锁定等安全管理字段。
type AdminUser struct {
	Username            string `json:"username"`              // 管理员用户名
	PasswordHash        string `json:"-"`                     // bcrypt 加密的密码哈希（不暴露给前端）
	Enabled             bool   `json:"enabled"`               // 是否启用账户
	LastLogin           int64  `json:"last_login"`            // 最后登录时间（Unix 时间戳）
	LoginCount          int    `json:"login_count"`           // 累计登录次数
	CreateTime          int64  `json:"create_time"`           // 账户创建时间
	LastPasswordChange  int64  `json:"last_password_change"`  // 最后密码修改时间
	ForcePasswordChange bool   `json:"force_password_change"` // 是否强制修改密码（首次登录）
	LoginFailCount      int    `json:"-"`                     // 登录失败次数（内部使用，达到阈值后锁定账户）
	LastLoginFailTime   int64  `json:"-"`                     // 最后登录失败时间（内部使用，用于重置计数器）
	LockUntil           int64  `json:"-"`                     // 账户锁定截止时间（内部使用，Unix 时间戳）
}

// Session 管理员会话结构体。
// 用于跟踪已登录的管理员状态，支持空闲超时和绝对过期机制。
type Session struct {
	Token        string `json:"token"`         // 会话令牌（随机生成的 64 字符十六进制字符串）
	Username     string `json:"username"`      // 管理员用户名
	ExpireTime   int64  `json:"expire_time"`   // 会话绝对过期时间（24小时，从创建时计算）
	ClientIP     string `json:"client_ip"`     // 客户端 IP 地址（用于审计和安全检查）
	CreateTime   int64  `json:"create_time"`   // 会话创建时间（Unix 时间戳）
	LastActivity int64  `json:"last_activity"` // 最后活动时间（用于空闲超时检测，30分钟无活动则失效）
}

// NewRateLimiter 创建一个新的速率限制器。
//
// 参数:
//   - requestsPerSecond: 每秒允许的请求数
//   - burst: 允许的最大突发请求数
//
// 返回:
//   - *RateLimiter: 初始化后的限流器实例
func NewRateLimiter(requestsPerSecond float64, burst int) *RateLimiter {
	return &RateLimiter{
		visitors: make(map[string]*rate.Limiter),
		rate:     rate.Limit(requestsPerSecond),
		burst:    burst,
	}
}

// getLimiter 获取或创建指定 IP 的限流器。
// 使用互斥锁保证并发安全，每个 IP 有独立的限流器实例。
// 如果该 IP 首次访问，会创建一个新的令牌桶限流器。
func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.visitors[ip]
	if !exists {
		// 创建新的限流器：指定速率和突发容量
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.visitors[ip] = limiter
	}

	return limiter
}

// Allow 检查指定 IP 是否允许发起请求。
// 基于令牌桶算法，如果桶中有可用令牌则允许请求并消耗一个令牌。
// 返回 true 表示允许请求，false 表示请求被限流。
func (rl *RateLimiter) Allow(ip string) bool {
	return rl.getLimiter(ip).Allow()
}

// Middleware HTTP 中间件，自动应用速率限制。
// 拦截所有通过此中间件的请求，检查客户端 IP 的请求频率。
// 如果超过限制，返回 HTTP 429 (Too Many Requests) 错误。
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr // 获取客户端 IP 地址

		if !rl.Allow(ip) {
			log.Printf("限流触发：IP=%s", ip)
			http.Error(w, "请求过于频繁，请稍后再试", http.StatusTooManyRequests) // 429 状态码
			return
		}

		next.ServeHTTP(w, r) // 请求未超限，继续处理下一个处理器
	})
}

// WebServer Web 管理服务器结构体。
// 管理 HTTP 服务、会话、管理员用户、验证码等组件，是 Web 管理界面的核心。
type WebServer struct {
	auth         *PasswordAuth           // SOCKS5 认证器，管理代理用户的认证和限速
	db           *DatabaseManager        // 数据库管理器，负责用户数据和配置的持久化
	socksServer  *Server                 // SOCKS5 服务器实例，用于获取服务器统计信息
	server       *http.Server            // HTTP 服务器，处理 Web 请求
	adminUsers   map[string]*AdminUser   // 管理员用户映射（用户名 -> 用户信息）
	adminMu      sync.RWMutex            // 管理员数据的读写锁，支持并发读、独占写
	sessions     map[string]*Session     // 活跃会话映射（token -> 会话信息）
	sessionMu    sync.RWMutex            // 会话数据的读写锁
	captchaStore map[string]*CaptchaInfo // 验证码存储（captchaID -> 验证码信息），内存存储
	captchaMu    sync.RWMutex            // 验证码数据的读写锁
	submitTokens map[string]int64        // 提交令牌记录（防重复提交，token -> 时间戳）
	submitMu     sync.RWMutex            // 提交令牌的读写锁
	csrfSecret   []byte                  // CSRF 密钥，用于生成和验证 CSRF 令牌
}

// CaptchaInfo 验证码信息结构体。
// 用于存储生成的验证码及其状态，支持失败次数限制和过期机制。
type CaptchaInfo struct {
	Code      string // 验证码文本（4位字符，排除易混淆字符）
	ExpireAt  int64  // 过期时间（Unix 时间戳，默认5分钟有效期）
	FailCount int    // 验证失败次数（超过5次则自动销毁，防止暴力破解）
}

// NewWebServer 创建并初始化 Web 管理服务器。
// 完成管理员账户初始化、路由注册、中间件配置等工作。
//
// 参数:
//   - auth: SOCKS5 认证器，如果为 nil 则创建空实例
//   - db: 数据库管理器，用于持久化用户和配置
//   - socksServer: SOCKS5 服务器实例，用于获取统计数据
//   - listenAddr: Web 服务监听地址（例如 ":8080"）
//
// 返回:
//   - *WebServer: 初始化后的 Web 服务器实例
func NewWebServer(auth *PasswordAuth, db *DatabaseManager, socksServer *Server, listenAddr string) *WebServer {
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
		csrfSecret:   generateCSRFSecret(),
	}

	// 初始化默认管理员账户（admin / password123）
	// 首次启动时创建，后续从数据库加载
	ws.initDefaultAdmin()

	// 从数据库加载已保存的管理员用户
	if db != nil {
		if err := db.LoadAdminUsers(ws); err != nil {
			log.Printf("加载管理员用户失败：%v", err)
		} else {
			log.Printf("已从数据库加载管理员用户")
		}
	}

	// 注册 HTTP 路由
	mux := http.NewServeMux()

	// API 路由：用户管理
	mux.HandleFunc("/api/users", ws.handleUsers)         // 用户 CRUD 操作
	mux.HandleFunc("/api/stats", ws.handleStats)         // 统计信息
	mux.HandleFunc("/api/traffic", ws.handleTraffic)     // 流量日志
	mux.HandleFunc("/api/dashboard", ws.handleDashboard) // 仪表盘数据

	// API 路由：配额管理
	mux.HandleFunc("/api/user-quota", ws.handleUserQuota)                // 用户配额设置
	mux.HandleFunc("/api/quota/stats", ws.handleQuotaStats)              // 配额统计
	mux.HandleFunc("/api/admin/batch-set-quota", ws.handleBatchSetQuota) // 批量设置配额

	// API 路由：管理员认证
	mux.HandleFunc("/api/admin/login", ws.handleAdminLogin)               // 管理员登录
	mux.HandleFunc("/api/admin/logout", ws.handleAdminLogout)             // 管理员登出
	mux.HandleFunc("/api/admin/check", ws.handleAdminCheck)               // 检查登录状态
	mux.HandleFunc("/api/admin/captcha", ws.handleCaptcha)                // 生成验证码
	mux.HandleFunc("/api/admin/change-password", ws.handleChangePassword) // 修改密码

	// API 路由：系统配置
	mux.HandleFunc("/api/admin/auth-method", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			ws.handleGetAuthMethod(w, r) // 获取认证方式
		case "POST":
			ws.handleSetAuthMethod(w, r) // 设置认证方式
		default:
			http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/admin/config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			ws.handleGetConfig(w, r) // 获取服务器配置
		case "POST":
			ws.handleSetConfig(w, r) // 设置服务器配置
		default:
			http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed)
		}
	})

	// 静态文件服务
	// 优先使用嵌入的静态文件系统，如果不存在则使用本地 static 目录
	staticFS := getStaticFileSystem()
	if staticFS != nil {
		fs := http.FileServer(staticFS)
		mux.Handle("/static/", http.StripPrefix("/static/", fs))
	} else {
		fs := http.FileServer(http.Dir("static"))
		mux.Handle("/static/", http.StripPrefix("/static/", fs))
	}

	// 页面路由
	mux.HandleFunc("/", ws.handleIndex)           // 首页（管理界面）
	mux.HandleFunc("/login.html", ws.handleLogin) // 登录页面
	mux.HandleFunc("/quota.html", ws.handleQuota) // 配额管理页面

	// 创建速率限制器（每秒 10 请求，突发 20）
	// 用于防止 API 滥用和 DDoS 攻击
	rateLimiter := NewRateLimiter(10.0, 20)

	// 创建 HTTP 服务器，应用中间件链
	// 中间件执行顺序：安全头 -> CORS -> 认证 -> 速率限制
	ws.server = &http.Server{
		Addr:           listenAddr,
		Handler:        rateLimiter.Middleware(ws.authMiddleware(ws.corsMiddleware(setSecurityHeaders(mux)))),
		ReadTimeout:    10 * time.Second, // 读取超时：防止慢速连接攻击
		WriteTimeout:   10 * time.Second, // 写入超时：防止响应过慢
		MaxHeaderBytes: 1 << 20,          // 最大请求头大小：1MB
	}

	return ws
}

// generateCaptcha 生成 4 位随机验证码图片和文本。
// 使用排除易混淆字符的字符集（排除 0,O,1,I,l 等）。
// 生成的验证码图片包含干扰线，增加 OCR 识别难度。
//
// 返回:
//   - string: 验证码文本（4位大写字母和数字）
//   - image.Image: 验证码图片（PNG 格式，120x50 像素）
func (ws *WebServer) generateCaptcha() (string, image.Image) {
	chars := "23456789ABCDEFGHJKLMNPQRSTUVWXYZ" // 排除 0,O,1,I,l 等易混淆字符
	code := ""
	for i := 0; i < 4; i++ {
		// 使用加密安全的随机数生成器
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		code += string(chars[n.Int64()])
	}

	width, height := 120, 50 // 图片尺寸：宽120px，高50px
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// 填充白色背景
	for x := 0; x < width; x++ {
		for y := 0; y < height; y++ {
			img.Set(x, y, color.RGBA{255, 255, 255, 255})
		}
	}

	// 绘制干扰线（5条随机颜色的直线）
	// 干扰线用于增加自动化识别的难度
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

	// 绘制验证码字符（每个字符不同颜色）
	for i, ch := range code {
		r := uint8(50 + (i*40)%200)
		g := uint8(50 + (i*60)%200)
		b := uint8(100 + (i*30)%155)

		x := (i * 25) + 15 // 字符水平位置
		y := 30            // 字符垂直位置

		drawChar(img, ch, x, y, color.RGBA{r, g, b, 255})
	}

	return code, img
}

// drawLine 在图片上绘制一条直线（Bresenham 算法简化版）。
// 使用线性插值方法，在两点之间绘制连续像素点。
//
// 参数:
//   - img: 目标图片
//   - x1, y1: 起点坐标
//   - x2, y2: 终点坐标
//   - c: 线条颜色
func drawLine(img *image.RGBA, x1, y1, x2, y2 int64, c color.RGBA) {
	dx := int(x2 - x1)
	dy := int(y2 - y1)
	steps := max(abs(dx), abs(dy)) // 步数取 dx 和 dy 的最大值
	if steps == 0 {
		steps = 1
	}
	xIncrement := float64(dx) / float64(steps) // X 方向每步增量
	yIncrement := float64(dy) / float64(steps) // Y 方向每步增量

	x := float64(x1)
	y := float64(y1)
	for i := 0; i <= steps; i++ {
		img.Set(int(x), int(y), c) // 设置像素颜色
		x += xIncrement
		y += yIncrement
	}
}

// drawChar 在图片上绘制一个字符（使用点阵字体）。
// 每个字符由 7x5 的点阵图案表示，放大 2 倍绘制。
//
// 参数:
//   - img: 目标图片
//   - ch: 要绘制的字符
//   - x, y: 字符左上角坐标
//   - c: 字符颜色
func drawChar(img *image.RGBA, ch rune, x, y int, c color.RGBA) {
	charMap := map[rune][]string{
		// 数字 2-9 的点阵图案（7行5列）
		'2': {"01110", "10001", "00010", "00100", "01000", "10000", "11111"},
		'3': {"01110", "10001", "00001", "00110", "00001", "10001", "01110"},
		'4': {"00010", "00110", "01010", "10010", "11111", "00010", "00010"},
		'5': {"11111", "10000", "10000", "11110", "10000", "10000", "11111"},
		'6': {"00110", "01000", "10000", "11110", "10001", "10001", "01110"},
		'7': {"11111", "00001", "00010", "00100", "01000", "01000", "01000"},
		'8': {"01110", "10001", "10001", "01110", "10001", "10001", "01110"},
		'9': {"01110", "10001", "10001", "01111", "00001", "00010", "01100"},
		// 大写字母 A-Z 的点阵图案（排除易混淆的 I、O）
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
		return // 如果字符不在点阵表中，直接返回
	}

	// 遍历点阵图案，将 '1' 的位置绘制为指定颜色
	// 每个点放大 2x2 像素，使字符更清晰
	for row, pattern := range patterns {
		for col, pixel := range pattern {
			if pixel == '1' {
				// 绘制 2x2 像素块
				img.Set(x+col*2, y+row*2, c)
				img.Set(x+col*2+1, y+row*2, c)
				img.Set(x+col*2, y+row*2+1, c)
				img.Set(x+col*2+1, y+row*2+1, c)
			}
		}
	}
}

// max 返回两个整数中的较大值。
// 用于计算直线绘制的步数。
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// abs 返回整数的绝对值。
// 用于计算直线绘制的距离。
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// sanitizeUsername 脱敏用户名，用于日志输出。
// 保留首尾字符，中间用 * 替代，保护用户隐私。
// 例如："admin" -> "a**n", "ab" -> "***"
func sanitizeUsername(username string) string {
	if len(username) <= 2 {
		return "***" // 用户名太短，全部隐藏
	}
	return username[:1] + strings.Repeat("*", len(username)-2) + username[len(username)-1:]
}

// Start 启动 Web 服务器。
// 开始监听指定地址，处理 HTTP 请求。
// 如果端口被占用或权限不足，将返回错误。
func (ws *WebServer) Start() error {
	fmt.Printf("Web 管理界面已启动在 http://%s\n", ws.server.Addr)
	return ws.server.ListenAndServe()
}

// Stop 停止 Web 服务器。
// 关闭监听器，停止接受新连接，现有连接会被中断。
func (ws *WebServer) Stop() error {
	return ws.server.Close()
}

// corsMiddleware CORS 跨域中间件，允许前端跨域访问 API。
// 设置 Access-Control-Allow-* 响应头，支持跨域请求。
// 对于 OPTIONS 预检请求，直接返回 200 状态码。
func (ws *WebServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 允许所有来源访问（生产环境应限制具体域名）
		w.Header().Set("Access-Control-Allow-Origin", "*")
		// 允许的 HTTP 方法
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		// 允许的请求头
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Auth-Token, X-Captcha-ID")
		// 暴露的响应头（前端可以访问这些头）
		w.Header().Set("Access-Control-Expose-Headers", "X-Captcha-ID, X-Auth-Token")

		// 处理 OPTIONS 预检请求
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// handleIndex 处理首页请求。
// 返回管理界面的 HTML 页面，嵌入在二进制文件中。
func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	// 只处理根路径和 /index.html
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}

	htmlData := getIndexHTML()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 设置内容安全策略，限制资源加载来源
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'")
	w.Write([]byte(htmlData))
}

// handleLogin 处理登录页面请求。
// 返回管理员登录界面的 HTML 页面。
func (ws *WebServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/login.html" {
		http.NotFound(w, r)
		return
	}

	htmlData := getLoginHTML()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'")
	w.Write([]byte(htmlData))
}

// handleQuota 处理配额管理页面请求。
// 返回用户配额管理界面的 HTML 页面。
func (ws *WebServer) handleQuota(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/quota.html" {
		http.NotFound(w, r)
		return
	}

	htmlData := getQuotaHTML()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'")
	w.Write([]byte(htmlData))
}

// handleUsers 处理用户管理 API（GET/POST/PUT/DELETE）。
// 提供 SOCKS5 代理用户的 CRUD 操作，包括创建、查询、更新、删除用户。
// 所有操作都需要有效的管理员会话令牌。
func (ws *WebServer) handleUsers(w http.ResponseWriter, r *http.Request) {
	if ws.auth == nil {
		log.Printf("错误：auth 为 nil")
		http.Error(w, "认证服务未初始化", http.StatusInternalServerError)
		return
	}

	// 提取认证 Token（支持 Authorization 头和 X-Auth-Token 头）
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

	// 验证会话令牌的有效性
	session, valid := ws.validateSession(token)
	if !valid {
		log.Printf("[安全] handleUsers 无效 token：%s %s", session.Username, r.RemoteAddr)
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case "GET":
		// 获取用户列表
		users := ws.auth.ListUsers()
		if len(users) == 0 {
			// 如果内存中没有用户，尝试从数据库加载
			if ws.db != nil {
				if err := ws.db.LoadAllUsersToAuth(ws.auth); err != nil {
					log.Printf("从数据库加载用户失败：%v", err)
				} else {
					users = ws.auth.ListUsers()
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)

	case "POST":
		// 创建新用户
		var data struct {
			Username         string `json:"username"`
			Password         string `json:"password"`
			Group            string `json:"group"`
			ReadLimit        int64  `json:"read_limit"`         // 上传速度限制（字节/秒）
			WriteLimit       int64  `json:"write_limit"`        // 下载速度限制（字节/秒）
			MaxConn          int    `json:"max_conn"`           // 最大连接数
			MaxIPConnections int    `json:"max_ip_connections"` // 单IP最大连接数
			QuotaPeriod      string `json:"quota_period"`       // 配额周期（daily/weekly/monthly/custom/unlimited）
			QuotaBytes       int64  `json:"quota_bytes"`        // 配额大小（字节）
			QuotaStartTime   int64  `json:"quota_start_time"`   // 配额开始时间（自定义周期）
			QuotaEndTime     int64  `json:"quota_end_time"`     // 配额结束时间（自定义周期）
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "请求数据格式错误", http.StatusBadRequest)
			return
		}

		// 添加用户到认证系统
		if err := ws.auth.AddUser(data.Username, data.Password); err != nil {
			log.Printf("创建用户失败 [%s]: %v", data.Username, err)
			http.Error(w, fmt.Sprintf("用户创建失败：%v", err), http.StatusBadRequest)
			return
		}

		// 设置速度限制
		readLimit, _ := validateSpeedLimit(data.ReadLimit)
		writeLimit, _ := validateSpeedLimit(data.WriteLimit)
		if readLimit > 0 || writeLimit > 0 {
			ws.auth.SetUserSpeedLimit(data.Username, readLimit, writeLimit)
		}

		// 设置最大连接数
		maxConn, _ := validateMaxConnections(data.MaxConn)
		ws.auth.SetUserMaxConnections(data.Username, maxConn)

		// 设置单 IP 最大连接数
		maxIPConn, _ := validateMaxConnections(data.MaxIPConnections)
		ws.auth.SetUserMaxIPConnections(data.Username, maxIPConn)

		// 设置流量配额
		if data.QuotaPeriod != "" {
			ws.auth.SetUserQuota(data.Username, data.QuotaPeriod, data.QuotaBytes)
			// 如果是自定义时间段，设置起止时间
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

		if ws.db != nil {
			if user, exists := ws.auth.GetUser(data.Username); exists {
				if err := ws.db.SaveUser(user); err != nil {
					log.Printf("用户 [%s] 保存到数据库失败：%v", sanitizeUsername(data.Username), err)
				}
			}
		}

		w.WriteHeader(http.StatusCreated)

	case "PUT":
		// 更新用户信息
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
			QuotaPeriod      string `json:"quota_period"`
			QuotaBytes       int64  `json:"quota_bytes"`
			QuotaStartTime   int64  `json:"quota_start_time"`
			QuotaEndTime     int64  `json:"quota_end_time"`
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			log.Printf("解析用户数据失败：%v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		log.Printf("更新用户 [%s]: 分组=%s, 读限速=%d, 写限速=%d, 最大连接=%d",
			sanitizeUsername(username), data.Group, data.ReadLimit, data.WriteLimit, data.MaxConn)

		if _, exists := ws.auth.GetUser(username); exists {
			if data.Password != "" {
				ws.auth.UpdateUserPassword(username, data.Password)
			}
			readLimit := data.ReadLimit
			if readLimit < 0 {
				readLimit = 0
			}
			writeLimit := data.WriteLimit
			if writeLimit < 0 {
				writeLimit = 0
			}
			ws.auth.SetUserSpeedLimit(username, readLimit, writeLimit)
			maxConn := data.MaxConn
			if maxConn < 0 {
				maxConn = 0
			}
			ws.auth.SetUserMaxConnections(username, maxConn)
			maxIPConn := data.MaxIPConnections
			if maxIPConn < 0 {
				maxIPConn = 0
			}
			ws.auth.SetUserMaxIPConnections(username, maxIPConn)

			if data.QuotaPeriod != "" {
				ws.auth.SetUserQuota(username, data.QuotaPeriod, data.QuotaBytes)
				if data.QuotaPeriod == "custom" && data.QuotaStartTime > 0 && data.QuotaEndTime > 0 {
					if user, exists := ws.auth.GetUser(username); exists {
						if user.QuotaStartTime == 0 || user.QuotaEndTime == 0 {
							user.QuotaUsed = 0
						}
						user.QuotaStartTime = data.QuotaStartTime
						user.QuotaEndTime = data.QuotaEndTime
						user.QuotaResetTime = data.QuotaEndTime
					}
				}
			} else {
				if user, exists := ws.auth.GetUser(username); exists {
					user.QuotaPeriod = ""
					user.QuotaBytes = 0
					user.QuotaUsed = 0
					user.QuotaStartTime = 0
					user.QuotaEndTime = 0
					user.QuotaResetTime = 0
				}
			}

			fmt.Fprintf(w, `{"status":"success","message":"用户已更新"}`)
		} else {
			log.Printf("用户 [%s] 不存在", username)
			http.Error(w, "用户不存在", http.StatusNotFound)
		}

		if ws.db != nil {
			if user, exists := ws.auth.GetUser(username); exists {
				if err := ws.db.SaveUser(user); err != nil {
					log.Printf("用户 [%s] 保存到数据库失败：%v", username, err)
				}
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

		if ws.db != nil {
			if err := ws.db.DeleteUser(username); err != nil {
				log.Printf("删除数据库用户失败 [%s]: %v", username, err)
			}
		}

		fmt.Fprintf(w, `{"status":"success","message":"用户已删除"}`)
	}
}

// handleStats 处理统计信息 API。
func (ws *WebServer) handleStats(w http.ResponseWriter, r *http.Request) {
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

// handleTraffic 处理流量日志 API（当前返回空数组）。
func (ws *WebServer) handleTraffic(w http.ResponseWriter, r *http.Request) {
	traffic := []map[string]interface{}{}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(traffic)
}

// handleDashboard 处理仪表盘数据 API。
func (ws *WebServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if ws.auth == nil {
		log.Printf("错误：auth 为 nil")
		http.Error(w, "认证服务未初始化", http.StatusInternalServerError)
		return
	}

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

// handleUserQuota 处理用户配额设置 API（GET/PUT）。
func (ws *WebServer) handleUserQuota(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

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
		// 设置用户配额
		username := r.URL.Query().Get("username")
		if username == "" {
			http.Error(w, "缺少用户名参数", http.StatusBadRequest)
			return
		}

		var data struct {
			Period    string `json:"period"`
			Quota     int64  `json:"quota"`
			StartTime int64  `json:"start_time"`
			EndTime   int64  `json:"end_time"`
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			log.Printf("解析配额数据失败：%v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		log.Printf("设置用户 [%s] 流量配额：周期=%s, 配额=%d 字节", username, data.Period, data.Quota)

		if data.Period == "unlimited" || data.Period == "" {
			ws.auth.ClearUserQuota(username)
			log.Printf("[配额] 用户 [%s] 设置为无限制模式（忽略 quota、start_time、end_time 参数）", username)
		} else {
			ws.auth.SetUserQuota(username, data.Period, data.Quota)

			if data.Period == "custom" && data.StartTime > 0 && data.EndTime > 0 {
				ws.auth.SetUserQuotaTimeRange(username, data.StartTime, data.EndTime)
			}
		}

		if ws.db != nil {
			if user, exists := ws.auth.GetUser(username); exists {
				ws.db.SaveUser(user)
			}
		}
		log.Printf("用户 [%s] 流量配额设置成功", username)
		fmt.Fprintf(w, `{"status":"success","message":"配额已设置"}`)

	case "GET":
		// 获取用户配额信息
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

// handleQuotaStats 处理配额统计 API。
func (ws *WebServer) handleQuotaStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if r.Method != "GET" {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	if ws.auth == nil {
		log.Printf("错误：auth 为 nil")
		http.Error(w, "认证服务未初始化", http.StatusInternalServerError)
		return
	}

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

			used := atomic.LoadInt64(&user.QuotaUsed)
			if used >= quotaBytes {
				overLimitUsers++
			}

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

// handleBatchSetQuota 处理批量设置配额 API。
func (ws *WebServer) handleBatchSetQuota(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if r.Method != "POST" {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	token := r.Header.Get("X-Auth-Token")
	if token == "" {
		http.Error(w, "未授权访问", http.StatusUnauthorized)
		return
	}

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

	for _, username := range req.Usernames {
		if username == "" {
			continue
		}

		if req.TrafficQuota.Period == "unlimited" {
			ws.auth.ClearUserQuota(username)
		} else {
			ws.auth.SetUserQuota(username, req.TrafficQuota.Period, req.TrafficQuota.QuotaBytes)

			if req.TrafficQuota.Period == "custom" && startTime > 0 && endTime > 0 {
				ws.auth.SetUserQuotaTimeRange(username, startTime, endTime)
			}
		}

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

// parseTimeString 解析多种格式的时间字符串。
func parseTimeString(timeStr string) (int64, error) {
	if timestamp, err := strconv.ParseInt(timeStr, 10, 64); err == nil {
		return timestamp, nil
	}

	if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
		return t.Unix(), nil
	}

	if t, err := time.Parse("2006-01-02T15:04", timeStr); err == nil {
		return t.Unix(), nil
	}

	if t, err := time.Parse("2006-01-02 15:04", timeStr); err == nil {
		return t.Unix(), nil
	}

	return 0, fmt.Errorf("无法解析时间格式：%s (支持时间戳、RFC3339、ISO8601 等格式)", timeStr)
}

// initDefaultAdmin 初始化默认管理员账户（admin / password123）。
// 仅在首次启动且数据库中没有管理员时创建。
// 生产环境应及时修改默认密码。
func (ws *WebServer) initDefaultAdmin() {
	ws.adminMu.Lock()
	defer ws.adminMu.Unlock()

	// 如果已存在 admin 用户，则不重复创建
	if _, exists := ws.adminUsers["admin"]; exists {
		return
	}

	passwordHash := hashPasswordForAdmin("password123")
	ws.adminUsers["admin"] = &AdminUser{
		Username:     "admin",
		PasswordHash: passwordHash,
		Enabled:      true,
		CreateTime:   time.Now().Unix(),
	}
	log.Println("默认管理员账户已初始化：admin / password123（请及时修改密码）")
}

// hashPasswordForAdmin 使用 bcrypt 加密管理员密码。
// bcrypt 是一种安全的密码哈希算法，具有抗暴力破解能力。
//
// 参数:
//   - password: 明文密码
//
// 返回:
//   - string: bcrypt 哈希后的密码字符串
func hashPasswordForAdmin(password string) string {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("密码哈希失败：%v", err)
		return ""
	}
	return string(hashed)
}

// verifyAdminPassword 验证管理员密码。
// 使用 bcrypt 比较明文密码和哈希值。
// 即使用户不存在，也会执行一次哈希比较，防止时序攻击。
//
// 参数:
//   - username: 用户名
//   - password: 明文密码
//
// 返回:
//   - bool: 密码是否正确
func (ws *WebServer) verifyAdminPassword(username, password string) bool {
	ws.adminMu.RLock()
	defer ws.adminMu.RUnlock()

	admin, exists := ws.adminUsers[username]
	if !exists || !admin.Enabled {
		// 用户不存在或已禁用，执行一次空比较以防止时序攻击
		bcrypt.CompareHashAndPassword([]byte(""), []byte(password))
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password))
	return err == nil
}

// generateSessionToken 生成随机会话令牌（64 字符十六进制）。
// 使用加密安全的随机数生成器，确保令牌不可预测。
//
// 返回:
//   - string: 64 字符的十六进制字符串
//   - error: 随机数生成错误
func generateSessionToken() (string, error) {
	bytes := make([]byte, 32) // 32 字节 = 64 字符十六进制
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// createSession 创建新的管理员会话。
// 生成唯一的会话令牌，并记录会话信息。
// 同时更新管理员的登录统计信息。
//
// 参数:
//   - username: 管理员用户名
//   - clientIP: 客户端 IP 地址
//
// 返回:
//   - string: 会话令牌
//   - error: 创建错误
func (ws *WebServer) createSession(username, clientIP string) (string, error) {
	token, err := generateSessionToken()
	if err != nil {
		return "", err
	}

	// 创建会话对象，设置过期时间
	session := &Session{
		Token:        token,
		Username:     username,
		ExpireTime:   time.Now().Add(24 * time.Hour).Unix(), // 24小时后绝对过期
		ClientIP:     clientIP,
		CreateTime:   time.Now().Unix(),
		LastActivity: time.Now().Unix(),
	}

	// 保存会话到内存
	ws.sessionMu.Lock()
	defer ws.sessionMu.Unlock()
	ws.sessions[token] = session

	// 更新管理员登录统计
	ws.adminMu.Lock()
	if admin, exists := ws.adminUsers[username]; exists {
		admin.LastLogin = time.Now().Unix()
		admin.LoginCount++
	}
	ws.adminMu.Unlock()

	return token, nil
}

const (
	SessionTimeout       = 30 * 60      // 会话超时时间：30 分钟（无活动后失效）
	SessionMaxExpireTime = 24 * 60 * 60 // 会话最大有效期：24 小时（从创建时计算）
)

// validateSession 验证会话令牌的有效性。
// 检查会话是否存在、是否过期、是否超过空闲超时。
// 如果会话无效，返回 nil, false。
//
// 参数:
//   - token: 会话令牌
//
// 返回:
//   - *Session: 会话对象（如果有效）
//   - bool: 会话是否有效
func (ws *WebServer) validateSession(token string) (*Session, bool) {
	ws.sessionMu.RLock()
	defer ws.sessionMu.RUnlock()

	session, exists := ws.sessions[token]
	if !exists {
		return nil, false
	}

	// 检查是否超过最大有效期（绝对过期）
	if time.Now().Unix() > session.ExpireTime {
		log.Printf("会话已过期：用户=%s", session.Username)
		return nil, false
	}

	// 检查是否超过空闲超时（30分钟无活动）
	now := time.Now().Unix()
	if now-session.LastActivity > SessionTimeout {
		log.Printf("会话超时（30 分钟未活动）：用户=%s, IP=%s", session.Username, session.ClientIP)
		// 异步使会话失效，避免阻塞
		go ws.invalidateSession(token)
		return nil, false
	}

	return session, true
}

// invalidateSession 使会话失效。
// 从会话映射中删除指定的会话令牌。
//
// 参数:
//   - token: 要失效的会话令牌
func (ws *WebServer) invalidateSession(token string) {
	ws.sessionMu.Lock()
	defer ws.sessionMu.Unlock()
	delete(ws.sessions, token)
}

// refreshSessionActivity 刷新会话的最后活动时间。
// 用于延长会话的空闲超时时间，每次请求都会调用。
//
// 参数:
//   - token: 会话令牌
//
// 返回:
//   - bool: 是否成功刷新
func (ws *WebServer) refreshSessionActivity(token string) bool {
	ws.sessionMu.Lock()
	defer ws.sessionMu.Unlock()

	session, exists := ws.sessions[token]
	if !exists {
		return false
	}

	session.LastActivity = time.Now().Unix()
	return true
}

// getAdminUser 获取管理员用户信息。
func (ws *WebServer) getAdminUser(username string) *AdminUser {
	ws.adminMu.RLock()
	defer ws.adminMu.RUnlock()

	if admin, exists := ws.adminUsers[username]; exists {
		return admin
	}
	return nil
}

// isAccountLocked 检查管理员账户是否被锁定。
// 如果账户被锁定且锁定时间已过，自动解锁。
//
// 参数:
//   - username: 用户名
//
// 返回:
//   - bool: 账户是否被锁定
func (ws *WebServer) isAccountLocked(username string) bool {
	ws.adminMu.RLock()
	defer ws.adminMu.RUnlock()

	admin, exists := ws.adminUsers[username]
	if !exists {
		return false
	}

	now := time.Now().Unix()

	// 检查是否在锁定期内
	if admin.LockUntil > now {
		return true
	}

	// 如果锁定时间已过，自动解锁
	if admin.LockUntil > 0 && admin.LockUntil <= now {
		ws.adminMu.RUnlock()
		ws.adminMu.Lock()
		admin.LockUntil = 0
		admin.LoginFailCount = 0
		ws.adminMu.Unlock()
		ws.adminMu.RLock()
	}

	return false
}

// recordLoginFailure 记录登录失败，达到阈值后锁定账户。
// 防止暴力破解攻击，连续失败 MaxLoginFailCount 次后锁定账户 LoginLockDuration 时间。
//
// 参数:
//   - username: 用户名
func (ws *WebServer) recordLoginFailure(username string) {
	ws.adminMu.Lock()
	defer ws.adminMu.Unlock()

	admin, exists := ws.adminUsers[username]
	if !exists {
		return
	}

	now := time.Now().Unix()

	// 如果距离上次失败已超过重置时间，清零计数
	if admin.LastLoginFailTime > 0 && now-admin.LastLoginFailTime > LoginFailResetTime {
		admin.LoginFailCount = 0
	}

	admin.LoginFailCount++
	admin.LastLoginFailTime = now

	// 达到最大失败次数，锁定账户
	if admin.LoginFailCount >= MaxLoginFailCount {
		admin.LockUntil = now + LoginLockDuration
		log.Printf("账户已被锁定：用户名=%s, 锁定时间=%d分钟", username, LoginLockDuration/60)
	}
}

// clearLoginFailure 清除登录失败记录。
// 在成功登录后调用，重置失败计数和锁定状态。
//
// 参数:
//   - username: 用户名
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

// clearExistingSessions 清除指定用户的所有现有会话。
// 用于确保同一用户只有一个活跃会话，提高安全性。
//
// 参数:
//   - username: 用户名
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

// authMiddleware 认证中间件，保护需要登录的 API。
// 检查请求是否包含有效的会话令牌，对修改操作进行 CSRF 验证。
// 公开路径（如登录、验证码）无需认证。
func (ws *WebServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 公开路径，无需认证
		publicPaths := []string{"/", "/api/admin/login", "/api/admin/captcha", "/static/"}
		for _, path := range publicPaths {
			if strings.HasPrefix(r.URL.Path, path) {
				next.ServeHTTP(w, r)
				return
			}
		}

		// 从 Cookie 或 Header 提取 Token
		token := getCookie(r, "session_token")

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

		// 验证会话令牌
		session, valid := ws.validateSession(token)
		if !valid {
			http.Error(w, `{"error":"会话已过期或无效","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
			return
		}

		// 刷新会话活动时间，延长会话有效期
		ws.refreshSessionActivity(token)

		// 对修改操作进行 CSRF 验证（POST/PUT/DELETE）
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" {
			csrfToken := r.Header.Get("X-CSRF-Token")
			if csrfToken == "" {
				csrfToken = r.FormValue("csrf_token")
			}

			if !ws.validateCSRFToken(csrfToken, session.Username) {
				log.Printf("CSRF 验证失败：用户=%s, IP=%s", session.Username, r.RemoteAddr)
				http.Error(w, `{"error":"CSRF 验证失败","code":"CSRF_FAILED"}`, http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

const (
	MaxLoginFailCount  = 5       // 最大登录失败次数（超过后锁定账户）
	LoginLockDuration  = 15 * 60 // 账户锁定时长：15 分钟
	LoginFailResetTime = 30 * 60 // 失败计数重置时间：30 分钟（无失败后清零）
)

// handleAdminLogin 处理管理员登录 API。
// 验证用户名、密码、验证码，创建会话并返回令牌。
// 包含账户锁定、验证码验证、首次登录强制改密等安全机制。
func (ws *WebServer) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed)
		return
	}

	var data struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		CaptchaID string `json:"captcha_id"` // 验证码 ID
		Captcha   string `json:"captcha"`    // 用户输入的验证码
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

	// 验证验证码（防止自动化攻击）
	if !ws.verifyCaptcha(data.CaptchaID, data.Captcha) {
		log.Printf("管理员登录失败：验证码错误，用户名=%s, IP=%s", data.Username, r.RemoteAddr)
		http.Error(w, `{"error":"验证码错误","code":"CAPTCHA_FAILED"}`, http.StatusBadRequest)
		return
	}

	// 验证密码
	if !ws.verifyAdminPassword(data.Username, data.Password) {
		log.Printf("管理员登录失败：用户名=%s, IP=%s", data.Username, r.RemoteAddr)
		ws.recordLoginFailure(data.Username) // 记录失败次数
		http.Error(w, `{"error":"用户名或密码错误","code":"AUTH_FAILED"}`, http.StatusUnauthorized)
		return
	}

	// 登录成功，清除失败记录
	ws.clearLoginFailure(data.Username)

	admin := ws.getAdminUser(data.Username)
	if admin != nil && admin.ForcePasswordChange {
		// 首次登录，强制修改密码
		token, err := ws.createSession(data.Username, r.RemoteAddr)
		if err != nil {
			log.Printf("创建会话失败：%v", err)
			http.Error(w, `{"error":"服务器内部错误","code":"SERVER_ERROR"}`, http.StatusInternalServerError)
			return
		}

		log.Printf("管理员首次登录，需要修改密码：用户名=%s, IP=%s", data.Username, r.RemoteAddr)

		w.Header().Set("Content-Type", "application/json")
		ws.setSecureCookie(w, "session_token", token, 3600)
		fmt.Fprintf(w, `{"status":"force_password_change","message":"首次登录请修改密码","token":"%s"}`, token)
		return
	}

	// 清除旧会话（确保单点登录）
	ws.clearExistingSessions(data.Username)

	// 创建新会话
	token, err := ws.createSession(data.Username, r.RemoteAddr)
	if err != nil {
		log.Printf("创建会话失败：%v", err)
		http.Error(w, `{"error":"服务器内部错误","code":"SERVER_ERROR"}`, http.StatusInternalServerError)
		return
	}

	log.Printf("管理员登录成功：用户名=%s, IP=%s", data.Username, r.RemoteAddr)

	// 生成 CSRF 令牌
	csrfToken := ws.generateCSRFToken(data.Username)

	w.Header().Set("Content-Type", "application/json")

	// 设置安全的 Cookie
	ws.setSecureCookie(w, "session_token", token, 86400)  // 24小时
	ws.setSecureCookie(w, "csrf_token", csrfToken, 86400) // 24小时

	fmt.Fprintf(w, `{"status":"success","token":"%s","username":"%s","csrf_token":"%s"}`, token, data.Username, csrfToken)
}

// handleAdminLogout 处理管理员登出 API。
func (ws *WebServer) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed)
		return
	}

	token := getCookie(r, "session_token")
	if token == "" {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			parts := strings.Split(authHeader, " ")
			if len(parts) == 2 && parts[0] == "Bearer" {
				token = parts[1]
			}
		}
	}

	if token != "" {
		ws.invalidateSession(token)
	}

	ws.setSecureCookie(w, "session_token", "", -1)
	ws.setSecureCookie(w, "csrf_token", "", -1)

	fmt.Fprintf(w, `{"status":"success","message":"已安全退出"}`)
}

// handleAdminCheck 检查管理员登录状态。
func (ws *WebServer) handleAdminCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed)
		return
	}

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
		token = getCookie(r, "session_token")
	}

	if token == "" {
		http.Error(w, `{"error":"未登录","code":"NOT_LOGGED_IN"}`, http.StatusUnauthorized)
		return
	}

	session, valid := ws.validateSession(token)
	if !valid {
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"success","logged_in":true,"username":"%s"}`, session.Username)
}

// handleCaptcha 生成并返回验证码图片。
// 每次请求生成一个新的验证码，存储到内存中，有效期5分钟。
// 返回 PNG 格式的图片，并在响应头中包含验证码 ID。
func (ws *WebServer) handleCaptcha(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed)
		return
	}

	// 生成唯一的验证码 ID（基于时间戳）
	captchaID := fmt.Sprintf("%d", time.Now().UnixNano())
	code, img := ws.generateCaptcha()

	// 存储验证码信息到内存
	ws.captchaMu.Lock()
	if ws.captchaStore == nil {
		ws.captchaStore = make(map[string]*CaptchaInfo)
	}
	ws.captchaStore[captchaID] = &CaptchaInfo{
		Code:     code,
		ExpireAt: time.Now().Add(5 * time.Minute).Unix(), // 5分钟有效期
	}
	ws.captchaMu.Unlock()

	// 设置响应头
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("X-Captcha-ID", captchaID)                              // 返回验证码 ID，供前端提交时使用
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate") // 禁止缓存
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	if err := png.Encode(w, img); err != nil {
		log.Printf("编码验证码图片失败：%v", err)
	}
}

// verifyCaptcha 验证用户输入的验证码是否正确。
// 不区分大小写比较，验证成功后立即销毁验证码（一次性使用）。
// 失败次数超过5次也会销毁，防止暴力破解。
//
// 参数:
//   - captchaID: 验证码 ID
//   - code: 用户输入的验证码
//
// 返回:
//   - bool: 验证码是否正确
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

	// 不区分大小写比较
	if strings.EqualFold(info.Code, code) {
		// 验证成功，立即销毁验证码（一次性使用）
		ws.captchaMu.Lock()
		delete(ws.captchaStore, captchaID)
		ws.captchaMu.Unlock()
		return true
	}

	// 验证失败，增加失败计数
	info.FailCount++
	if info.FailCount >= 5 {
		// 失败次数过多，销毁验证码
		ws.captchaMu.Lock()
		delete(ws.captchaStore, captchaID)
		ws.captchaMu.Unlock()
	}

	return false
}

// handleChangePassword 处理修改管理员密码 API。
func (ws *WebServer) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed)
		return
	}

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
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized)
		return
	}

	session, valid := ws.validateSession(token)
	if !valid {
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
		return
	}

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

	// 检查新密码强度
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

	newPasswordHash := hashPasswordForAdmin(data.NewPassword)
	if newPasswordHash == "" {
		ws.adminMu.Unlock()
		http.Error(w, `{"error":"密码更新失败","code":"HASH_FAILED"}`, http.StatusInternalServerError)
		return
	}

	adminUser.PasswordHash = newPasswordHash
	adminUser.LastPasswordChange = time.Now().Unix()
	adminUser.ForcePasswordChange = false
	ws.adminUsers[session.Username] = adminUser
	ws.adminMu.Unlock()

	// 保存到数据库
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

// handleGetAuthMethod 获取当前认证方式。
func (ws *WebServer) handleGetAuthMethod(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed)
		return
	}

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
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized)
		return
	}

	_, valid := ws.validateSession(token)
	if !valid {
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
		return
	}

	authMethod := "password"
	if ws.db != nil {
		method, err := ws.db.GetConfig("auth_method")
		if err == nil && method != "" {
			authMethod = method
		}
	}

	if ws.socksServer != nil && ws.socksServer.config != nil && ws.socksServer.config.Auth != nil {
		if _, ok := ws.socksServer.config.Auth.(*NoAuth); ok {
			authMethod = "none"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"success","auth_method":"%s"}`, authMethod)
}

// handleSetAuthMethod 设置认证方式（none/password）。
func (ws *WebServer) handleSetAuthMethod(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed)
		return
	}

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
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized)
		return
	}

	session, valid := ws.validateSession(token)
	if !valid {
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
		return
	}

	var data struct {
		AuthMethod string `json:"auth_method"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, `{"error":"请求数据格式错误"}`, http.StatusBadRequest)
		return
	}

	if data.AuthMethod != "none" && data.AuthMethod != "password" {
		http.Error(w, `{"error":"无效的认证方式","code":"INVALID_AUTH_METHOD"}`, http.StatusBadRequest)
		return
	}

	if data.AuthMethod == "none" {
		ws.socksServer.config.Auth = &NoAuth{}
		log.Printf("管理员 [%s] 切换认证方式为：无认证，IP=%s", session.Username, r.RemoteAddr)
	} else {
		ws.socksServer.config.Auth = ws.auth
		log.Printf("管理员 [%s] 切换认证方式为：密码认证，IP=%s", session.Username, r.RemoteAddr)
	}

	if ws.db != nil {
		ws.db.SetConfig("auth_method", data.AuthMethod, "SOCKS5 认证方式：none=无认证，password=密码认证")
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

// handleGetConfig 获取服务器配置。
func (ws *WebServer) handleGetConfig(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized)
		return
	}

	_, valid := ws.validateSession(token)
	if !valid {
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
		return
	}

	config := make(map[string]interface{})
	if ws.db != nil {
		keys := []string{
			"listen_addr", "auth_method", "enable_user_management",
		}
		for _, key := range keys {
			if value, err := ws.db.GetConfig(key); err == nil && value != "" {
				config[key] = value
			}
		}

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

	// 从内存配置补充
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

// handleSetConfig 设置服务器配置。
func (ws *WebServer) handleSetConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed)
		return
	}

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
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized)
		return
	}

	session, valid := ws.validateSession(token)
	if !valid {
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
		return
	}

	var data struct {
		ListenAddr         string `json:"listen_addr"`
		MaxWorkers         int    `json:"max_workers"`
		MaxConnPerIP       int    `json:"max_conn_per_ip"`
		ReadSpeedLimit     int64  `json:"read_speed_limit"`
		WriteSpeedLimit    int64  `json:"write_speed_limit"`
		TCPKeepAlivePeriod int    `json:"tcp_keepalive_period"`
		SubmitToken        string `json:"submit_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, `{"error":"请求数据格式错误"}`, http.StatusBadRequest)
		return
	}

	// 防重复提交
	if data.SubmitToken == "" {
		http.Error(w, `{"error":"无效的提交请求"}`, http.StatusBadRequest)
		return
	}

	if ws.isDuplicateSubmit(data.SubmitToken) {
		http.Error(w, `{"error":"重复的提交请求"}`, http.StatusBadRequest)
		return
	}

	ws.recordSubmitToken(data.SubmitToken)

	// XSS 和 SQL 注入检测
	validator := NewInputValidator()
	if validator.ContainsXSS(data.ListenAddr) {
		http.Error(w, `{"error":"监听地址包含非法内容"}`, http.StatusBadRequest)
		return
	}
	if validator.ContainsSQLInjection(data.ListenAddr) {
		http.Error(w, `{"error":"监听地址包含非法内容"}`, http.StatusBadRequest)
		return
	}

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

	// 保存到数据库
	if ws.db != nil {
		listenAddr, _ := validated["listen_addr"].(string)
		ws.db.SetConfig("listen_addr", listenAddr, "服务器监听地址")

		maxWorkers, _ := validated["max_workers"].(int)
		ws.db.SetConfig("max_workers", fmt.Sprintf("%d", maxWorkers), "最大工作协程数")

		maxConnPerIP, _ := validated["max_conn_per_ip"].(int)
		ws.db.SetConfig("max_conn_per_ip", fmt.Sprintf("%d", maxConnPerIP), "单 IP 最大连接数")

		readSpeedLimit, _ := validated["read_speed_limit"].(int64)
		ws.db.SetConfig("read_speed_limit", fmt.Sprintf("%d", readSpeedLimit), "上传速度限制（字节/秒）")

		writeSpeedLimit, _ := validated["write_speed_limit"].(int64)
		ws.db.SetConfig("write_speed_limit", fmt.Sprintf("%d", writeSpeedLimit), "下载速度限制（字节/秒）")

		tcpKeepAlivePeriod, _ := validated["tcp_keepalive_period"].(int)
		ws.db.SetConfig("tcp_keepalive_period", fmt.Sprintf("%d", tcpKeepAlivePeriod), "TCP Keepalive 周期（秒）")
	}

	log.Printf("管理员 [%s] 更新了服务器配置，IP=%s", session.Username, r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"success","message":"配置已保存，重启服务器后生效"}`)
}

// isDuplicateSubmit 检查是否为重复提交。
// 通过检查提交令牌是否已存在来判断。
//
// 参数:
//   - token: 提交令牌
//
// 返回:
//   - bool: 是否为重复提交
func (ws *WebServer) isDuplicateSubmit(token string) bool {
	ws.submitMu.RLock()
	defer ws.submitMu.RUnlock()

	_, exists := ws.submitTokens[token]
	return exists
}

// recordSubmitToken 记录提交令牌，用于防重复提交。
// 将令牌和时间戳存储到内存中，并清理过期的令牌（5分钟前）。
//
// 参数:
//   - token: 提交令牌
func (ws *WebServer) recordSubmitToken(token string) {
	ws.submitMu.Lock()
	defer ws.submitMu.Unlock()

	// 记录当前提交令牌
	ws.submitTokens[token] = time.Now().UnixNano()

	// 清理过期的令牌（5分钟前）
	expireTime := time.Now().Add(-5 * time.Minute).UnixNano()
	for t, ts := range ws.submitTokens {
		if ts < expireTime {
			delete(ws.submitTokens, t)
		}
	}
}

// mapToJSON 将 map 转换为 JSON 字符串。
// 用于将配置数据序列化为 JSON 格式返回给前端。
// 如果转换失败，返回空对象 {}。
//
// 参数:
//   - m: 要转换的 map
//
// 返回:
//   - string: JSON 字符串
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

// generateCSRFSecret 生成随机的 CSRF 密钥。
// 在服务器启动时调用一次，用于生成和验证 CSRF 令牌。
// 如果随机数生成失败，使用备用方案（基于时间戳）。
//
// 返回:
//   - []byte: 32字节的 CSRF 密钥
func generateCSRFSecret() []byte {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Printf("警告：随机数生成失败，使用备用 CSRF 密钥")
		// 备用方案：使用时间戳（安全性较低，但能保证功能）
		secret = []byte(fmt.Sprintf("csrf_secret_%d", time.Now().UnixNano()))
	}
	return secret
}

// generateCSRFToken 生成 CSRF 令牌。
// 基于 CSRF 密钥、用户名和时间戳生成唯一的令牌。
// 用于防止跨站请求伪造攻击。
//
// 参数:
//   - username: 管理员用户名
//
// 返回:
//   - string: 64字符的十六进制 CSRF 令牌
func (ws *WebServer) generateCSRFToken(username string) string {
	h := sha256.New()
	h.Write(ws.csrfSecret)                                    // CSRF 密钥
	h.Write([]byte(username))                                 // 用户名
	h.Write([]byte(fmt.Sprintf("%d", time.Now().UnixNano()))) // 时间戳（增加随机性）

	return hex.EncodeToString(h.Sum(nil))
}

// validateCSRFToken 验证 CSRF 令牌的格式有效性。
// 检查令牌是否为空、长度是否正确、是否只包含十六进制字符。
// 注意：此函数只验证格式，不验证令牌的真实性（真实性由生成逻辑保证）。
//
// 参数:
//   - token: CSRF 令牌
//   - username: 管理员用户名（保留参数，便于未来扩展）
//
// 返回:
//   - bool: 令牌格式是否有效
func (ws *WebServer) validateCSRFToken(token, username string) bool {
	if token == "" || username == "" {
		return false
	}

	// CSRF 令牌应该是 64 字符的十六进制字符串（SHA-256 哈希）
	if len(token) != 64 {
		return false
	}

	// 检查是否只包含合法的十六进制字符
	for _, c := range token {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}

	return true
}

// setSecurityHeaders 设置安全相关的 HTTP 响应头。
// 包括 XSS 防护、点击劫持防护、MIME 类型嗅探防护等。
// 这是一个中间件函数，包裹在其他处理器外部。
func setSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff") // 禁止 MIME 类型嗅探
		w.Header().Set("X-Frame-Options", "DENY")           // 禁止 iframe 嵌入（防点击劫持）
		w.Header().Set("X-XSS-Protection", "1; mode=block") // 启用浏览器 XSS 过滤器
		// 内容安全策略：限制资源加载来源
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")             // 引用策略
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()") // 权限策略

		next.ServeHTTP(w, r)
	})
}

// setSecureCookie 设置安全的 HTTP Cookie。
// 配置 HttpOnly、Secure、SameSite 等属性，增强安全性。
//
// 参数:
//   - w: HTTP 响应写入器
//   - name: Cookie 名称
//   - value: Cookie 值
//   - maxAge: 最大存活时间（秒），负数表示删除 Cookie
func (ws *WebServer) setSecureCookie(w http.ResponseWriter, name, value string, maxAge int) {
	// 是否强制使用 Secure 标志（仅 HTTPS）
	secure := strings.ToLower(getEnv("FORCE_COOKIE_SECURE", "false")) == "true"

	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,                 // 禁止 JavaScript 访问，防止 XSS 窃取
		Secure:   secure,               // 仅通过 HTTPS 传输（可通过环境变量强制）
		SameSite: http.SameSiteLaxMode, // 防止 CSRF 攻击
		MaxAge:   maxAge,
	})
}

// getCookie 从请求中获取指定名称的 Cookie 值。
// 如果 Cookie 不存在，返回空字符串。
//
// 参数:
//   - r: HTTP 请求
//   - name: Cookie 名称
//
// 返回:
//   - string: Cookie 值
func getCookie(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// getEnv 获取环境变量，如果未设置则返回默认值。
// 用于配置可选的行为，如强制 Cookie Secure 标志。
//
// 参数:
//   - key: 环境变量名
//   - defaultValue: 默认值
//
// 返回:
//   - string: 环境变量值或默认值
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
