// Package main 实现 SOCKS5 代理服务器的 Web 管理界面模块。
// 提供基于 HTTP 的用户管理、流量统计、配额设置、系统配置等功能，
// 包含会话管理、CSRF 防护、验证码、速率限制等安全机制。
package main

import (
	"crypto/rand"   // 加密安全的随机数生成器，用于生成会话令牌、验证码等
	"crypto/sha256" // SHA-256 哈希算法，用于生成 CSRF 令牌
	"encoding/hex"  // 十六进制编码解码，将字节转换为十六进制字符串
	"encoding/json" // JSON 数据编解码，处理 API 请求和响应
	"fmt"           // 格式化输入输出，用于字符串格式化和打印
	"image"         // 图像处理基础接口，用于创建和操作图片
	"image/color"   // 颜色模型，定义颜色的表示方式
	"image/png"     // PNG 图像编解码，用于生成验证码图片
	"log"           // 日志记录，输出程序运行信息和错误
	"math/big"      // 大整数运算，用于生成安全的随机数
	"net/http"      // HTTP 客户端和服务器实现，处理 Web 请求
	"os"            // 操作系统功能，获取环境变量等
	"strconv"       // 字符串和基本类型转换，如字符串转整数
	"strings"       // 字符串操作函数，如分割、比较、前缀判断
	"sync"          // 同步原语，提供互斥锁和读写锁
	"sync/atomic"   // 原子操作，提供线程安全的整数操作
	"time"          // 时间相关功能，处理时间戳和定时器

	"golang.org/x/crypto/bcrypt" // bcrypt 密码哈希算法，安全地存储密码
	"golang.org/x/time/rate"     // 速率限制器，基于令牌桶算法实现限流
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
	// 创建并返回一个新的速率限制器实例
	return &RateLimiter{
		visitors: make(map[string]*rate.Limiter), // 初始化空的访客映射表
		rate:     rate.Limit(requestsPerSecond),  // 设置令牌生成速率（每秒允许的请求数）
		burst:    burst,                          // 设置令牌桶容量（允许的最大突发请求数）
	}
}

// getLimiter 获取或创建指定 IP 的限流器。
// 使用互斥锁保证并发安全，每个 IP 有独立的限流器实例。
// 如果该 IP 首次访问，会创建一个新的令牌桶限流器。
func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()         // 获取互斥锁，保证并发安全
	defer rl.mu.Unlock() // 函数返回时释放锁

	limiter, exists := rl.visitors[ip] // 查找该 IP 是否已有限流器
	if !exists {                       // 如果该 IP 首次访问，不存在限流器
		// 创建新的限流器：指定速率和突发容量
		limiter = rate.NewLimiter(rl.rate, rl.burst) // 创建令牌桶限流器实例
		rl.visitors[ip] = limiter                    // 将新限流器存入映射表
	}

	return limiter // 返回该 IP 对应的限流器
}

// Allow 检查指定 IP 是否允许发起请求。
// 基于令牌桶算法，如果桶中有可用令牌则允许请求并消耗一个令牌。
// 返回 true 表示允许请求，false 表示请求被限流。
func (rl *RateLimiter) Allow(ip string) bool {
	// 获取该 IP 的限流器并检查是否允许请求
	return rl.getLimiter(ip).Allow() // 调用令牌桶的 Allow 方法，返回是否有可用令牌
}

// Middleware HTTP 中间件，自动应用速率限制。
// 拦截所有通过此中间件的请求，检查客户端 IP 的请求频率。
// 如果超过限制，返回 HTTP 429 (Too Many Requests) 错误。
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	// 返回一个 HTTP 处理器函数，包装原始处理器并应用速率限制
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr // 获取客户端 IP 地址（包含端口号）

		if !rl.Allow(ip) { // 检查该 IP 是否允许发起请求
			log.Printf("限流触发：IP=%s", ip)                              // 记录限流日志
			http.Error(w, "请求过于频繁，请稍后再试", http.StatusTooManyRequests) // 返回 HTTP 429 错误
			return                                                    // 终止请求处理
		}

		next.ServeHTTP(w, r) // 请求未超限，继续调用下一个处理器
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
	// 检查认证器是否为空，如果为空则创建空实例
	if auth == nil {
		log.Printf("警告：auth 为 nil，创建空的 PasswordAuth") // 记录警告日志
		auth = &PasswordAuth{
			users:           make(map[string]*User),           // 初始化用户映射表
			userConnections: make(map[string]int),             // 初始化用户连接数映射表
			userIPs:         make(map[string]map[string]bool), // 初始化用户 IP 映射表
		}
	}

	// 创建 WebServer 实例并初始化所有字段
	ws := &WebServer{
		auth:         auth,                          // SOCKS5 认证器
		db:           db,                            // 数据库管理器
		socksServer:  socksServer,                   // SOCKS5 服务器实例
		adminUsers:   make(map[string]*AdminUser),   // 初始化管理员用户映射表
		sessions:     make(map[string]*Session),     // 初始化会话映射表
		captchaStore: make(map[string]*CaptchaInfo), // 初始化验证码存储映射表
		submitTokens: make(map[string]int64),        // 初始化提交令牌映射表
		csrfSecret:   generateCSRFSecret(),          // 生成 CSRF 密钥
	}

	// 初始化默认管理员账户（admin / password123）
	// 首次启动时创建，后续从数据库加载
	ws.initDefaultAdmin()

	// 从数据库加载已保存的管理员用户
	if db != nil { // 检查数据库管理器是否可用
		if err := db.LoadAdminUsers(ws); err != nil { // 尝试加载管理员用户
			log.Printf("加载管理员用户失败：%v", err) // 记录错误日志
		} else {
			log.Printf("已从数据库加载管理员用户") // 记录成功日志
		}
	}

	// 注册 HTTP 路由
	mux := http.NewServeMux() // 创建新的 HTTP 多路复用器

	// API 路由：用户管理
	mux.HandleFunc("/api/users", ws.handleUsers)         // 用户 CRUD 操作（增删改查）
	mux.HandleFunc("/api/stats", ws.handleStats)         // 统计信息接口
	mux.HandleFunc("/api/traffic", ws.handleTraffic)     // 流量日志接口
	mux.HandleFunc("/api/dashboard", ws.handleDashboard) // 仪表盘数据接口

	// API 路由：配额管理
	mux.HandleFunc("/api/user-quota", ws.handleUserQuota)                // 用户配额设置接口
	mux.HandleFunc("/api/quota/stats", ws.handleQuotaStats)              // 配额统计接口
	mux.HandleFunc("/api/admin/batch-set-quota", ws.handleBatchSetQuota) // 批量设置配额接口

	// API 路由：管理员认证
	mux.HandleFunc("/api/admin/login", ws.handleAdminLogin)               // 管理员登录接口
	mux.HandleFunc("/api/admin/logout", ws.handleAdminLogout)             // 管理员登出接口
	mux.HandleFunc("/api/admin/check", ws.handleAdminCheck)               // 检查登录状态接口
	mux.HandleFunc("/api/admin/captcha", ws.handleCaptcha)                // 生成验证码接口
	mux.HandleFunc("/api/admin/change-password", ws.handleChangePassword) // 修改密码接口

	// API 路由：系统配置
	// 根据 HTTP 方法分发到不同的处理函数
	mux.HandleFunc("/api/admin/auth-method", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method { // 根据请求方法进行分支处理
		case "GET":
			ws.handleGetAuthMethod(w, r) // 获取当前认证方式
		case "POST":
			ws.handleSetAuthMethod(w, r) // 设置新的认证方式
		default:
			http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed) // 返回 405 错误
		}
	})
	// 配置管理路由，支持 GET 和 POST 方法
	mux.HandleFunc("/api/admin/config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method { // 根据请求方法进行分支处理
		case "GET":
			ws.handleGetConfig(w, r) // 获取服务器配置
		case "POST":
			ws.handleSetConfig(w, r) // 设置服务器配置
		default:
			http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed) // 返回 405 错误
		}
	})

	// 静态文件服务
	// 优先使用嵌入的静态文件系统，如果不存在则使用本地 static 目录
	staticFS := getStaticFileSystem() // 获取静态文件系统
	if staticFS != nil {              // 如果嵌入的文件系统存在
		fs := http.FileServer(staticFS)                          // 创建文件服务器
		mux.Handle("/static/", http.StripPrefix("/static/", fs)) // 注册静态文件路由，去除前缀
	} else { // 否则使用本地文件系统
		fs := http.FileServer(http.Dir("static"))                // 创建本地目录的文件服务器
		mux.Handle("/static/", http.StripPrefix("/static/", fs)) // 注册静态文件路由，去除前缀
	}

	// 页面路由
	mux.HandleFunc("/", ws.handleIndex)           // 首页（管理界面主页面）
	mux.HandleFunc("/login.html", ws.handleLogin) // 登录页面
	mux.HandleFunc("/quota.html", ws.handleQuota) // 配额管理页面

	// 创建速率限制器（每秒 10 请求，突发 20）
	// 用于防止 API 滥用和 DDoS 攻击
	rateLimiter := NewRateLimiter(10.0, 20) // 创建限流器，每秒允许 10 个请求，突发容量 20

	// 创建 HTTP 服务器，应用中间件链
	// 中间件执行顺序：安全头 -> CORS -> 认证 -> 速率限制
	ws.server = &http.Server{
		Addr:           listenAddr,                                                                            // 监听地址（如 ":8080"）
		Handler:        rateLimiter.Middleware(ws.authMiddleware(ws.corsMiddleware(setSecurityHeaders(mux)))), // 中间件链：安全头、CORS、认证、限流
		ReadTimeout:    10 * time.Second,                                                                      // 读取超时：防止慢速连接攻击（Slowloris）
		WriteTimeout:   10 * time.Second,                                                                      // 写入超时：防止响应过慢导致资源占用
		MaxHeaderBytes: 1 << 20,                                                                               // 最大请求头大小：1MB（1 << 20 = 1048576 字节）
	}

	// 启动定期清理任务
	go ws.cleanupExpiredSessions() // 每5分钟清理过期会话
	go ws.cleanupExpiredCaptchas() // 每10分钟清理过期验证码
	go ws.cleanupSubmitTokens()    // 每小时清理提交令牌

	return ws // 返回初始化完成的 WebServer 实例
}

// generateCaptcha 生成 4 位随机验证码图片和文本。
// 使用排除易混淆字符的字符集（排除 0,O,1,I,l 等）。
// 生成的验证码图片包含干扰线，增加 OCR 识别难度。
//
// 返回:
//   - string: 验证码文本（4位大写字母和数字）
//   - image.Image: 验证码图片（PNG 格式，120x50 像素）
func (ws *WebServer) generateCaptcha() (string, image.Image) {
	chars := "23456789ABCDEFGHJKLMNPQRSTUVWXYZ" // 定义验证码字符集，排除 0,O,1,I,l 等易混淆字符
	code := ""                                  // 初始化验证码字符串
	for i := 0; i < 4; i++ {                    // 循环 4 次，生成 4 位验证码
		// 使用加密安全的随机数生成器
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars)))) // 生成 [0, len(chars)) 范围内的随机数
		code += string(chars[n.Int64()])                             // 从字符集中取出对应字符并追加到验证码
	}

	width, height := 120, 50                              // 设置图片尺寸：宽 120 像素，高 50 像素
	img := image.NewRGBA(image.Rect(0, 0, width, height)) // 创建 RGBA 格式的图片对象

	// 填充白色背景
	for x := 0; x < width; x++ { // 遍历所有 X 坐标
		for y := 0; y < height; y++ { // 遍历所有 Y 坐标
			img.Set(x, y, color.RGBA{255, 255, 255, 255}) // 设置每个像素为白色（R=255, G=255, B=255, A=255）
		}
	}

	// 绘制干扰线（5条随机颜色的直线）
	// 干扰线用于增加自动化识别的难度
	for i := 0; i < 5; i++ { // 循环 5 次，绘制 5 条干扰线
		x1, _ := rand.Int(rand.Reader, big.NewInt(int64(width)))  // 生成起点 X 坐标（0 到 width-1）
		y1, _ := rand.Int(rand.Reader, big.NewInt(int64(height))) // 生成起点 Y 坐标（0 到 height-1）
		x2, _ := rand.Int(rand.Reader, big.NewInt(int64(width)))  // 生成终点 X 坐标
		y2, _ := rand.Int(rand.Reader, big.NewInt(int64(height))) // 生成终点 Y 坐标
		r, _ := rand.Int(rand.Reader, big.NewInt(200))            // 生成红色分量（0-199）
		g, _ := rand.Int(rand.Reader, big.NewInt(200))            // 生成绿色分量（0-199）
		b, _ := rand.Int(rand.Reader, big.NewInt(200))            // 生成蓝色分量（0-199）
		// 调用 drawLine 绘制一条随机颜色的直线
		drawLine(img, x1.Int64(), y1.Int64(), x2.Int64(), y2.Int64(), color.RGBA{uint8(r.Int64()), uint8(g.Int64()), uint8(b.Int64()), 255})
	}

	// 绘制验证码字符（每个字符不同颜色）
	for i, ch := range code { // 遍历验证码中的每个字符
		r := uint8(50 + (i*40)%200)  // 计算红色分量，基于字符位置产生变化
		g := uint8(50 + (i*60)%200)  // 计算绿色分量，基于字符位置产生变化
		b := uint8(100 + (i*30)%155) // 计算蓝色分量，基于字符位置产生变化

		x := (i * 25) + 15 // 计算字符的水平位置（每个字符间隔 25 像素，起始偏移 15）
		y := 30            // 设置字符的垂直位置（固定为 30）

		drawChar(img, ch, x, y, color.RGBA{r, g, b, 255}) // 调用 drawChar 绘制单个字符
	}

	return code, img // 返回验证码文本和生成的图片
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
	dx := int(x2 - x1)             // 计算 X 方向的距离
	dy := int(y2 - y1)             // 计算 Y 方向的距离
	steps := max(abs(dx), abs(dy)) // 步数取 dx 和 dy 的绝对值的最大值，确保线条连续
	if steps == 0 {                // 如果起点和终点重合
		steps = 1 // 至少走一步，绘制一个像素点
	}
	xIncrement := float64(dx) / float64(steps) // 计算 X 方向每步的增量（浮点数）
	yIncrement := float64(dy) / float64(steps) // 计算 Y 方向每步的增量（浮点数）

	x := float64(x1)              // 初始化当前 X 坐标为浮点数
	y := float64(y1)              // 初始化当前 Y 坐标为浮点数
	for i := 0; i <= steps; i++ { // 从 0 到 steps 循环，逐步绘制像素
		img.Set(int(x), int(y), c) // 将浮点坐标转换为整数，设置该像素的颜色
		x += xIncrement            // X 坐标增加一个步长
		y += yIncrement            // Y 坐标增加一个步长
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
	// 定义字符点阵映射表，每个字符由 7 行 5 列的点阵图案表示
	charMap := map[rune][]string{
		// 数字 2-9 的点阵图案（7行5列），'1' 表示绘制像素，'0' 表示空白
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

	patterns, exists := charMap[ch] // 从映射表中查找字符对应的点阵图案
	if !exists {                    // 如果字符不在点阵表中
		return // 直接返回，不绘制任何内容
	}

	// 遍历点阵图案，将 '1' 的位置绘制为指定颜色
	// 每个点放大 2x2 像素，使字符更清晰
	for row, pattern := range patterns { // 遍历每一行点阵图案
		for col, pixel := range pattern { // 遍历该行中的每个像素点
			if pixel == '1' { // 如果该位置需要绘制（值为 '1'）
				// 绘制 2x2 像素块，放大字符以提高可读性
				img.Set(x+col*2, y+row*2, c)     // 绘制左上角像素
				img.Set(x+col*2+1, y+row*2, c)   // 绘制右上角像素
				img.Set(x+col*2, y+row*2+1, c)   // 绘制左下角像素
				img.Set(x+col*2+1, y+row*2+1, c) // 绘制右下角像素
			}
		}
	}
}

// max 返回两个整数中的较大值。
// 用于计算直线绘制的步数，确保线条连续。
func max(a, b int) int {
	if a > b { // 如果 a 大于 b
		return a // 返回 a
	}
	return b // 否则返回 b
}

// abs 返回整数的绝对值。
// 用于计算直线绘制的距离，处理负数情况。
func abs(x int) int {
	if x < 0 { // 如果 x 是负数
		return -x // 返回其相反数（正数）
	}
	return x // 如果 x 是非负数，直接返回
}

// sanitizeUsername 脱敏用户名，用于日志输出。
// 保留首尾字符，中间用 * 替代，保护用户隐私。
// 例如："admin" -> "a**n", "ab" -> "***"
func sanitizeUsername(username string) string {
	if len(username) <= 2 { // 如果用户名长度小于等于 2 个字符
		return "***" // 全部隐藏，返回三个星号
	}
	// 拼接：首字符 + 中间星号 + 尾字符
	return username[:1] + strings.Repeat("*", len(username)-2) + username[len(username)-1:]
}

// Start 启动 Web 服务器。
// 开始监听指定地址，处理 HTTP 请求。
// 如果端口被占用或权限不足，将返回错误。
func (ws *WebServer) Start() error {
	fmt.Printf("Web 管理界面已启动在 http://%s\n", ws.server.Addr) // 打印服务器启动信息
	return ws.server.ListenAndServe()                      // 开始监听并接受 HTTP 连接
}

// Stop 停止 Web 服务器。
// 关闭监听器，停止接受新连接，现有连接会被中断。
func (ws *WebServer) Stop() error {
	return ws.server.Close() // 关闭 HTTP 服务器，终止所有连接
}

// cleanupExpiredSessions 定期清理过期的会话。
// 每5分钟执行一次，检查所有会话的过期时间和空闲超时。
func (ws *WebServer) cleanupExpiredSessions() {
	ticker := time.NewTicker(5 * time.Minute) // 创建5分钟间隔的定时器
	defer ticker.Stop()                       // 确保函数返回时停止定时器

	for range ticker.C { // 循环等待定时器触发
		ws.sessionMu.Lock() // 获取会话映射的写锁

		now := time.Now().Unix()                  // 获取当前时间戳
		count := 0                                // 记录清理的会话数量
		for token, session := range ws.sessions { // 遍历所有会话
			// 检查会话是否过期（绝对过期或空闲超时30分钟）
			if now > session.ExpireTime || now-session.LastActivity > 1800 {
				delete(ws.sessions, token) // 删除过期会话
				count++                    // 增加计数
			}
		}

		ws.sessionMu.Unlock() // 释放锁

		if count > 0 {
			log.Printf("已清理 %d 个过期会话", count) // 记录清理日志
		}
	}
}

// cleanupExpiredCaptchas 定期清理过期的验证码。
// 每10分钟执行一次，检查验证码的过期时间和失败次数。
func (ws *WebServer) cleanupExpiredCaptchas() {
	ticker := time.NewTicker(10 * time.Minute) // 创建10分钟间隔的定时器
	defer ticker.Stop()                        // 确保函数返回时停止定时器

	for range ticker.C { // 循环等待定时器触发
		ws.captchaMu.Lock() // 获取验证码映射的写锁

		now := time.Now().Unix()                   // 获取当前时间戳
		count := 0                                 // 记录清理的验证码数量
		for id, captcha := range ws.captchaStore { // 遍历所有验证码
			// 检查验证码是否过期或失败次数超过5次
			if now > captcha.ExpireAt || captcha.FailCount >= 5 {
				delete(ws.captchaStore, id) // 删除过期或失败的验证码
				count++                     // 增加计数
			}
		}

		ws.captchaMu.Unlock() // 释放锁

		if count > 0 {
			log.Printf("已清理 %d 个过期验证码", count) // 记录清理日志
		}
	}
}

// cleanupSubmitTokens 定期清理过期的提交令牌。
// 每小时执行一次，清理超过1小时的令牌。
func (ws *WebServer) cleanupSubmitTokens() {
	ticker := time.NewTicker(1 * time.Hour) // 创建1小时间隔的定时器
	defer ticker.Stop()                     // 确保函数返回时停止定时器

	for range ticker.C { // 循环等待定时器触发
		ws.submitMu.Lock() // 获取提交令牌映射的写锁

		now := time.Now().Unix()                        // 获取当前时间戳
		count := 0                                      // 记录清理的令牌数量
		for token, timestamp := range ws.submitTokens { // 遍历所有令牌
			// 检查令牌是否超过1小时
			if now-timestamp > 3600 {
				delete(ws.submitTokens, token) // 删除过期令牌
				count++                        // 增加计数
			}
		}

		ws.submitMu.Unlock() // 释放锁

		if count > 0 {
			log.Printf("已清理 %d 个过期提交令牌", count) // 记录清理日志
		}
	}
}

// corsMiddleware CORS 跨域中间件，允许前端跨域访问 API。
// 设置 Access-Control-Allow-* 响应头，支持跨域请求。
// 对于 OPTIONS 预检请求，直接返回 200 状态码。
func (ws *WebServer) corsMiddleware(next http.Handler) http.Handler {
	// 返回一个 HTTP 处理器函数，包装原始处理器并添加 CORS 响应头
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 允许所有来源访问（生产环境应限制具体域名）
		w.Header().Set("Access-Control-Allow-Origin", "*")
		// 允许的 HTTP 方法：GET、POST、PUT、DELETE、OPTIONS
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		// 允许的请求头：Content-Type、自定义认证头和验证码头
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Auth-Token, X-Captcha-ID")
		// 暴露的响应头（前端 JavaScript 可以访问这些头）
		w.Header().Set("Access-Control-Expose-Headers", "X-Captcha-ID, X-Auth-Token")

		// 处理 OPTIONS 预检请求（浏览器在跨域请求前发送的检查请求）
		if r.Method == "OPTIONS" { // 如果是 OPTIONS 方法
			w.WriteHeader(http.StatusOK) // 返回 200 OK 状态码
			return                       // 终止请求处理，不调用下一个处理器
		}

		next.ServeHTTP(w, r) // 非预检请求，继续调用下一个处理器
	})
}

// handleIndex 处理首页请求。
// 返回 SOCKS5 管理界面的主页面 HTML。
//
// 参数:
//   - w: HTTP 响应写入器
//   - r: HTTP 请求对象
func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	// 只处理根路径和 /index.html，其他路径返回 404
	if r.URL.Path != "/" && r.URL.Path != "/index.html" { // 检查请求路径是否为首页
		http.NotFound(w, r) // 返回 404 Not Found 错误
		return              // 终止处理
	}

	htmlData := getIndexHTML() // 获取首页 HTML 内容（从嵌入资源或函数生成）

	w.Header().Set("Content-Type", "text/html; charset=utf-8") // 设置响应内容类型为 HTML，编码为 UTF-8
	// 设置内容安全策略（CSP），限制资源加载来源，防止 XSS 攻击
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'")
	w.Write([]byte(htmlData)) // 将 HTML 内容写入响应体
}

// handleLogin 处理登录页面请求。
// 返回管理员登录界面的 HTML 页面，包含验证码功能。
//
// 参数:
//   - w: HTTP 响应写入器
//   - r: HTTP 请求对象
func (ws *WebServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/login.html" { // 检查请求路径是否为登录页
		http.NotFound(w, r) // 如果不是，返回 404 错误
		return              // 终止处理
	}

	htmlData := getLoginHTML() // 获取登录页 HTML 内容

	w.Header().Set("Content-Type", "text/html; charset=utf-8") // 设置响应内容类型为 HTML
	// 设置内容安全策略，与首页相同
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'")
	w.Write([]byte(htmlData)) // 将 HTML 内容写入响应体
}

// handleQuota 处理配额管理页面请求。
// 返回用户配额管理界面的 HTML 页面。
func (ws *WebServer) handleQuota(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/quota.html" { // 检查请求路径是否为配额管理页
		http.NotFound(w, r) // 如果不是，返回 404 错误
		return              // 终止处理
	}

	htmlData := getQuotaHTML() // 获取配额管理页 HTML 内容

	w.Header().Set("Content-Type", "text/html; charset=utf-8") // 设置响应内容类型为 HTML
	// 设置内容安全策略，与首页相同
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'")
	w.Write([]byte(htmlData)) // 将 HTML 内容写入响应体
}

// handleUsers 处理用户管理 API（GET/POST/PUT/DELETE）。
// 提供 SOCKS5 代理用户的 CRUD 操作，包括创建、查询、更新、删除用户。
// 所有操作都需要有效的管理员会话令牌。
func (ws *WebServer) handleUsers(w http.ResponseWriter, r *http.Request) {
	if ws.auth == nil { // 检查认证器是否已初始化
		log.Printf("错误：auth 为 nil")                               // 记录错误日志
		http.Error(w, "认证服务未初始化", http.StatusInternalServerError) // 返回 500 服务器错误
		return                                                    // 终止处理
	}

	// 提取认证 Token（支持 Authorization 头和 X-Auth-Token 头）
	authHeader := r.Header.Get("Authorization") // 从请求头获取 Authorization 字段
	var token string                            // 声明 token 变量

	if authHeader != "" { // 如果 Authorization 头存在
		parts := strings.Split(authHeader, " ")      // 按空格分割头部值
		if len(parts) == 2 && parts[0] == "Bearer" { // 检查格式是否为 "Bearer <token>"
			token = parts[1] // 提取 token 部分
		}
	}

	if token == "" { // 如果 Authorization 头中没有 token
		token = r.Header.Get("X-Auth-Token") // 尝试从自定义头 X-Auth-Token 获取
	}

	if token == "" { // 如果仍然没有 token
		log.Printf("[安全] handleUsers 未授权访问尝试：%s %s", r.Method, r.RemoteAddr)              // 记录安全警告日志
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized) // 返回 401 未授权错误
		return                                                                            // 终止处理
	}

	// 验证会话令牌的有效性
	session, valid := ws.validateSession(token) // 调用会话验证函数
	if !valid {                                 // 如果会话无效
		log.Printf("[安全] handleUsers 无效 token：%s %s", session.Username, r.RemoteAddr)        // 记录安全警告
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized) // 返回 401 错误
		return                                                                               // 终止处理
	}

	switch r.Method { // 根据 HTTP 请求方法进行分支处理
	case "GET": // GET 请求：获取用户列表
		// 获取用户列表
		users := ws.auth.ListUsers() // 从认证器获取所有用户
		if len(users) == 0 {         // 如果内存中没有用户
			// 如果内存中没有用户，尝试从数据库加载
			if ws.db != nil { // 检查数据库管理器是否可用
				if err := ws.db.LoadAllUsersToAuth(ws.auth); err != nil { // 尝试从数据库加载用户
					log.Printf("从数据库加载用户失败：%v", err) // 记录错误日志
				} else {
					users = ws.auth.ListUsers() // 加载成功后重新获取用户列表
				}
			}
		}

		w.Header().Set("Content-Type", "application/json") // 设置响应内容类型为 JSON
		json.NewEncoder(w).Encode(users)                   // 将用户列表编码为 JSON 并写入响应

	case "POST": // POST 请求：创建新用户
		// 创建新用户
		var data struct { // 定义请求数据结构体
			Username         string `json:"username"`           // 用户名
			Password         string `json:"password"`           // 密码
			Group            string `json:"group"`              // 用户组
			MaxConn          int    `json:"max_conn"`           // 最大连接数
			MaxIPConnections int    `json:"max_ip_connections"` // 单IP最大连接数
			QuotaPeriod      string `json:"quota_period"`       // 配额周期（daily/weekly/monthly/custom/unlimited）
			QuotaBytes       int64  `json:"quota_bytes"`        // 配额大小（字节）
			QuotaStartTime   int64  `json:"quota_start_time"`   // 配额开始时间（自定义周期）
			QuotaEndTime     int64  `json:"quota_end_time"`     // 配额结束时间（自定义周期）
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil { // 解析请求体中的 JSON 数据
			http.Error(w, "请求数据格式错误", http.StatusBadRequest) // 如果解析失败，返回 400 错误
			return                                           // 终止处理
		}

		// 添加用户到认证系统
		if err := ws.auth.AddUser(data.Username, data.Password); err != nil { // 尝试添加用户
			log.Printf("创建用户失败 [%s]: %v", data.Username, err)                   // 记录错误日志
			http.Error(w, fmt.Sprintf("用户创建失败：%v", err), http.StatusBadRequest) // 返回 400 错误
			return                                                              // 终止处理
		}

		// 设置最大连接数
		maxConn, _ := validateMaxConnections(data.MaxConn)    // 验证并获取最大连接数
		ws.auth.SetUserMaxConnections(data.Username, maxConn) // 设置用户最大连接数

		// 设置单 IP 最大连接数
		maxIPConn, _ := validateMaxConnections(data.MaxIPConnections) // 验证并获取单 IP 最大连接数
		ws.auth.SetUserMaxIPConnections(data.Username, maxIPConn)     // 设置用户单 IP 最大连接数

		// 设置流量配额
		if data.QuotaPeriod != "" { // 如果指定了配额周期
			ws.auth.SetUserQuota(data.Username, data.QuotaPeriod, data.QuotaBytes) // 设置用户配额
			// 如果是自定义时间段，设置起止时间
			if data.QuotaPeriod == "custom" && data.QuotaStartTime > 0 && data.QuotaEndTime > 0 { // 检查是否为自定义周期且时间有效
				if user, exists := ws.auth.GetUser(data.Username); exists { // 获取用户对象
					user.QuotaStartTime = data.QuotaStartTime // 设置配额开始时间
					user.QuotaEndTime = data.QuotaEndTime     // 设置配额结束时间
					user.QuotaResetTime = data.QuotaEndTime   // 设置配额重置时间为结束时间
					log.Printf("用户 [%s] 自定义时间段配额已设置：%s - %s", // 记录日志
						sanitizeUsername(data.Username),
						time.Unix(data.QuotaStartTime, 0).Format("2006-01-02 15:04:05"), // 格式化开始时间
						time.Unix(data.QuotaEndTime, 0).Format("2006-01-02 15:04:05"))   // 格式化结束时间
				}
			}
		}

		// 记录用户创建成功日志
		log.Printf("用户 [%s] 创建成功：分组=%s, 连接限制=%d, IP 连接限制=%d",
			sanitizeUsername(data.Username), data.Group, maxConn, maxIPConn)

		if ws.db != nil { // 如果数据库可用
			if user, exists := ws.auth.GetUser(data.Username); exists { // 获取刚创建的用户
				if err := ws.db.SaveUser(user); err != nil { // 保存到数据库
					log.Printf("用户 [%s] 保存到数据库失败：%v", sanitizeUsername(data.Username), err) // 记录保存失败日志
				}
			}
		}

		w.WriteHeader(http.StatusCreated) // 返回 201 Created 状态码

	case "PUT": // PUT 请求：更新用户信息
		// 更新用户信息
		username := r.URL.Query().Get("username") // 从 URL 查询参数获取用户名
		if username == "" {                       // 如果用户名为空
			http.Error(w, "缺少用户名参数", http.StatusBadRequest) // 返回 400 错误
			return                                          // 终止处理
		}

		var data struct { // 定义请求数据结构体
			Password         string `json:"password"`           // 新密码（可选）
			Group            string `json:"group"`              // 用户组
			MaxConn          int    `json:"max_conn"`           // 最大连接数
			MaxIPConnections int    `json:"max_ip_connections"` // 单IP最大连接数
			QuotaPeriod      string `json:"quota_period"`       // 配额周期
			QuotaBytes       int64  `json:"quota_bytes"`        // 配额大小
			QuotaStartTime   int64  `json:"quota_start_time"`   // 配额开始时间
			QuotaEndTime     int64  `json:"quota_end_time"`     // 配额结束时间
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil { // 解析请求体中的 JSON 数据
			log.Printf("解析用户数据失败：%v", err)                    // 记录解析错误
			http.Error(w, err.Error(), http.StatusBadRequest) // 返回 400 错误
			return                                            // 终止处理
		}

		// 记录更新操作日志
		log.Printf("更新用户 [%s]: 分组=%s, 最大连接=%d",
			sanitizeUsername(username), data.Group, data.MaxConn)

		if _, exists := ws.auth.GetUser(username); exists { // 检查用户是否存在
			if data.Password != "" { // 如果提供了新密码
				ws.auth.UpdateUserPassword(username, data.Password) // 更新用户密码
			}
			maxConn := data.MaxConn // 获取最大连接数
			if maxConn < 0 {        // 如果值为负数
				maxConn = 0 // 重置为 0（无限制）
			}
			ws.auth.SetUserMaxConnections(username, maxConn) // 设置用户最大连接数
			maxIPConn := data.MaxIPConnections               // 获取单 IP 最大连接数
			if maxIPConn < 0 {                               // 如果值为负数
				maxIPConn = 0 // 重置为 0（无限制）
			}
			ws.auth.SetUserMaxIPConnections(username, maxIPConn) // 设置用户单 IP 最大连接数

			if data.QuotaPeriod != "" { // 如果指定了配额周期
				ws.auth.SetUserQuota(username, data.QuotaPeriod, data.QuotaBytes)                     // 设置用户配额
				if data.QuotaPeriod == "custom" && data.QuotaStartTime > 0 && data.QuotaEndTime > 0 { // 如果是自定义周期
					if user, exists := ws.auth.GetUser(username); exists { // 获取用户对象
						if user.QuotaStartTime == 0 || user.QuotaEndTime == 0 { // 如果之前没有设置过时间
							user.QuotaUsed = 0 // 重置已用流量
						}
						user.QuotaStartTime = data.QuotaStartTime // 设置配额开始时间
						user.QuotaEndTime = data.QuotaEndTime     // 设置配额结束时间
						user.QuotaResetTime = data.QuotaEndTime   // 设置配额重置时间
					}
				}
			} else { // 如果没有指定配额周期
				if user, exists := ws.auth.GetUser(username); exists { // 获取用户对象
					user.QuotaPeriod = ""   // 清空配额周期
					user.QuotaBytes = 0     // 清空配额大小
					user.QuotaUsed = 0      // 清空已用流量
					user.QuotaStartTime = 0 // 清空开始时间
					user.QuotaEndTime = 0   // 清空结束时间
					user.QuotaResetTime = 0 // 清空重置时间
				}
			}

			fmt.Fprintf(w, `{"status":"success","message":"用户已更新"}`) // 返回成功响应
		} else { // 如果用户不存在
			log.Printf("用户 [%s] 不存在", username)         // 记录错误日志
			http.Error(w, "用户不存在", http.StatusNotFound) // 返回 404 错误
		}

		if ws.db != nil { // 如果数据库可用
			if user, exists := ws.auth.GetUser(username); exists { // 获取更新后的用户
				if err := ws.db.SaveUser(user); err != nil { // 保存到数据库
					log.Printf("用户 [%s] 保存到数据库失败：%v", username, err) // 记录保存失败日志
				}
			}
		}

	case "DELETE": // DELETE 请求：删除用户
		// 删除用户
		username := r.URL.Query().Get("username") // 从 URL 查询参数获取用户名
		if username == "" {                       // 如果用户名为空
			http.Error(w, "缺少用户名参数", http.StatusBadRequest) // 返回 400 错误
			return                                          // 终止处理
		}

		ws.auth.RemoveUser(username) // 从认证器中移除用户

		if ws.db != nil { // 如果数据库可用
			if err := ws.db.DeleteUser(username); err != nil { // 从数据库中删除用户
				log.Printf("删除数据库用户失败 [%s]: %v", username, err) // 记录删除失败日志
			}
		}

		fmt.Fprintf(w, `{"status":"success","message":"用户已删除"}`) // 返回成功响应
	}
}

// handleStats 处理统计信息 API。
// 返回服务器运行状态、连接数、流量等统计数据。
// 需要有效的管理员会话 Token 才能访问。
//
// 参数:
//   - w: HTTP 响应写入器
//   - r: HTTP 请求对象
func (ws *WebServer) handleStats(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Auth-Token") // 从请求头获取认证令牌
	if token == "" {                      // 如果令牌为空
		log.Printf("[安全] handleStats 未授权访问尝试：%s", r.RemoteAddr)                           // 记录安全警告
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized) // 返回 401 错误
		return                                                                            // 终止处理
	}

	_, valid := ws.validateSession(token) // 验证会话令牌
	if !valid {                           // 如果会话无效
		log.Printf("[安全] handleStats 无效 token: %s", r.RemoteAddr)                            // 记录安全警告
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized) // 返回 401 错误
		return                                                                               // 终止处理
	}

	users := ws.auth.ListUsers()  // 获取所有用户列表
	totalUsers := len(users)      // 计算用户总数
	activeUsers := 0              // 初始化活跃用户计数器
	userTotalUpload := int64(0)   // 初始化用户上传总量
	userTotalDownload := int64(0) // 初始化用户下载总量

	for _, user := range users { // 遍历所有用户
		if user.LastActivity > time.Now().Unix()-3600 { // 如果最后活动时间在 1 小时内
			activeUsers++ // 计为活跃用户
		}
		userTotalUpload += user.UploadTotal     // 累加用户上传总量
		userTotalDownload += user.DownloadTotal // 累加用户下载总量
	}

	serverTotalUpload := int64(0)                             // 初始化服务器上传总量
	serverTotalDownload := int64(0)                           // 初始化服务器下载总量
	if ws.socksServer != nil && ws.socksServer.stats != nil { // 检查 SOCKS 服务器和统计对象是否存在
		serverTotalUpload = atomic.LoadInt64(&ws.socksServer.stats.TotalUpload)     // 原子读取服务器上传总量
		serverTotalDownload = atomic.LoadInt64(&ws.socksServer.stats.TotalDownload) // 原子读取服务器下载总量
	}

	// 构建响应数据映射
	data := map[string]interface{}{
		"total_users":         totalUsers,          // 用户总数
		"active_users":        activeUsers,         // 活跃用户数
		"user_total_upload":   userTotalUpload,     // 用户上传总量
		"user_total_download": userTotalDownload,   // 用户下载总量
		"total_upload":        serverTotalUpload,   // 服务器上传总量
		"total_download":      serverTotalDownload, // 服务器下载总量
	}

	w.Header().Set("Content-Type", "application/json") // 设置响应内容类型为 JSON
	json.NewEncoder(w).Encode(data)                    // 将统计数据编码为 JSON 并写入响应
}

// handleTraffic 处理流量日志 API（当前返回空数组）。
func (ws *WebServer) handleTraffic(w http.ResponseWriter, r *http.Request) {
	traffic := []map[string]interface{}{} // 初始化空的流量日志数组

	w.Header().Set("Content-Type", "application/json") // 设置响应内容类型为 JSON
	json.NewEncoder(w).Encode(traffic)                 // 返回空数组
}

// handleDashboard 处理仪表盘数据 API。
// 返回包含用户统计和服务器统计的综合数据，用于前端仪表盘展示。
func (ws *WebServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if ws.auth == nil { // 检查认证器是否已初始化
		log.Printf("错误：auth 为 nil")                               // 记录错误日志
		http.Error(w, "认证服务未初始化", http.StatusInternalServerError) // 返回 500 错误
		return                                                    // 终止处理
	}

	token := r.Header.Get("X-Auth-Token") // 从请求头获取认证令牌
	if token == "" {                      // 如果令牌为空
		log.Printf("[安全] handleDashboard 未授权访问尝试：%s", r.RemoteAddr)                       // 记录安全警告
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized) // 返回 401 错误
		return                                                                            // 终止处理
	}

	session, valid := ws.validateSession(token) // 验证会话令牌
	if !valid {                                 // 如果会话无效
		log.Printf("[安全] handleDashboard 无效 token: %s", r.RemoteAddr)                        // 记录安全警告
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized) // 返回 401 错误
		return                                                                               // 终止处理
	}

	// 记录审计日志
	log.Printf("[审计] Dashboard 访问：管理员 [%s], IP=%s", session.Username, r.RemoteAddr)

	users := ws.auth.ListUsers()  // 获取所有用户列表
	totalUsers := len(users)      // 计算用户总数
	activeUsers := 0              // 初始化活跃用户计数器
	userTotalUpload := int64(0)   // 初始化用户上传总量
	userTotalDownload := int64(0) // 初始化用户下载总量

	for _, user := range users { // 遍历所有用户
		if user.LastActivity > time.Now().Unix()-3600 { // 如果最后活动时间在 1 小时内
			activeUsers++ // 计为活跃用户
		}
		userTotalUpload += user.UploadTotal     // 累加用户上传总量
		userTotalDownload += user.DownloadTotal // 累加用户下载总量
	}

	serverTotalUpload := int64(0)                             // 初始化服务器上传总量
	serverTotalDownload := int64(0)                           // 初始化服务器下载总量
	if ws.socksServer != nil && ws.socksServer.stats != nil { // 检查 SOCKS 服务器和统计对象是否存在
		serverTotalUpload = atomic.LoadInt64(&ws.socksServer.stats.TotalUpload)     // 原子读取服务器上传总量
		serverTotalDownload = atomic.LoadInt64(&ws.socksServer.stats.TotalDownload) // 原子读取服务器下载总量
	}

	// 构建响应数据映射
	data := map[string]interface{}{
		"total_users":         totalUsers,          // 用户总数
		"active_users":        activeUsers,         // 活跃用户数
		"user_total_upload":   userTotalUpload,     // 用户上传总量
		"user_total_download": userTotalDownload,   // 用户下载总量
		"total_upload":        serverTotalUpload,   // 服务器上传总量
		"total_download":      serverTotalDownload, // 服务器下载总量
		"timestamp":           time.Now().Unix(),   // 当前时间戳
	}

	w.Header().Set("Content-Type", "application/json") // 设置响应内容类型为 JSON
	json.NewEncoder(w).Encode(data)                    // 将仪表盘数据编码为 JSON 并写入响应
}

// handleUserQuota 处理用户配额设置 API（GET/PUT）。
// GET: 获取指定用户的配额信息
// PUT: 设置指定用户的流量配额
func (ws *WebServer) handleUserQuota(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8") // 设置响应内容类型为 JSON

	token := r.Header.Get("X-Auth-Token") // 从请求头获取认证令牌
	if token == "" {                      // 如果令牌为空
		log.Printf("[安全] handleUserQuota 未授权访问尝试：%s %s", r.Method, r.RemoteAddr)          // 记录安全警告
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized) // 返回 401 错误
		return                                                                            // 终止处理
	}

	session, valid := ws.validateSession(token) // 验证会话令牌
	if !valid {                                 // 如果会话无效
		log.Printf("[安全] handleUserQuota 无效 token: %s %s", session.Username, r.RemoteAddr)   // 记录安全警告
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized) // 返回 401 错误
		return                                                                               // 终止处理
	}

	// 记录审计日志，包含管理员用户名、请求方法和 IP
	log.Printf("[审计] handleUserQuota: 管理员 [%s], Method=%s, IP=%s", session.Username, r.Method, r.RemoteAddr)

	switch r.Method { // 根据 HTTP 请求方法进行分支处理
	case "PUT": // PUT 请求：设置用户配额
		// 设置用户配额
		username := r.URL.Query().Get("username") // 从 URL 查询参数获取用户名
		if username == "" {                       // 如果用户名为空
			http.Error(w, "缺少用户名参数", http.StatusBadRequest) // 返回 400 错误
			return                                          // 终止处理
		}

		var data struct { // 定义请求数据结构体
			Period    string `json:"period"`     // 配额周期（daily/weekly/monthly/custom/unlimited）
			Quota     int64  `json:"quota"`      // 配额大小（字节）
			StartTime int64  `json:"start_time"` // 配额开始时间（自定义周期使用）
			EndTime   int64  `json:"end_time"`   // 配额结束时间（自定义周期使用）
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil { // 解析请求体中的 JSON 数据
			log.Printf("解析配额数据失败：%v", err)                    // 记录解析错误
			http.Error(w, err.Error(), http.StatusBadRequest) // 返回 400 错误
			return                                            // 终止处理
		}

		// 记录配额设置操作日志
		log.Printf("设置用户 [%s] 流量配额：周期=%s, 配额=%d 字节", username, data.Period, data.Quota)

		if data.Period == "unlimited" || data.Period == "" { // 如果设置为无限制或周期为空
			ws.auth.ClearUserQuota(username)                                               // 清除用户配额限制
			log.Printf("[配额] 用户 [%s] 设置为无限制模式（忽略 quota、start_time、end_time 参数）", username) // 记录日志
		} else { // 否则设置有限配额
			ws.auth.SetUserQuota(username, data.Period, data.Quota) // 设置用户配额

			if data.Period == "custom" && data.StartTime > 0 && data.EndTime > 0 { // 如果是自定义周期且时间有效
				ws.auth.SetUserQuotaTimeRange(username, data.StartTime, data.EndTime) // 设置配额时间范围
			}
		}

		if ws.db != nil { // 如果数据库可用
			if user, exists := ws.auth.GetUser(username); exists { // 获取用户对象
				ws.db.SaveUser(user) // 保存用户信息到数据库
			}
		}
		log.Printf("用户 [%s] 流量配额设置成功", username)                 // 记录成功日志
		fmt.Fprintf(w, `{"status":"success","message":"配额已设置"}`) // 返回成功响应

	case "GET": // GET 请求：获取用户配额信息
		// 获取用户配额信息
		username := r.URL.Query().Get("username") // 从 URL 查询参数获取用户名
		if username == "" {                       // 如果用户名为空
			http.Error(w, "缺少用户名参数", http.StatusBadRequest) // 返回 400 错误
			return                                          // 终止处理
		}

		// 获取用户配额详细信息
		period, total, used, resetTime, exists := ws.auth.GetUserQuotaInfo(username)
		if !exists { // 如果用户不存在
			http.Error(w, "用户不存在", http.StatusNotFound) // 返回 404 错误
			return                                      // 终止处理
		}

		var startTime, endTime int64 // 声明开始和结束时间变量
		if period == "custom" {      // 如果是自定义周期
			if user, ok := ws.auth.GetUser(username); ok { // 获取用户对象
				startTime = user.QuotaStartTime // 获取配额开始时间
				endTime = user.QuotaEndTime     // 获取配额结束时间
			}
		}

		// 返回配额信息的 JSON 响应
		fmt.Fprintf(w, `{"period":"%s","total":%d,"used":%d,"reset_time":%d,"start_time":%d,"end_time":%d}`, period, total, used, resetTime, startTime, endTime)
	}
}

// handleQuotaStats 处理配额统计 API。
// 返回配额相关的统计数据，包括总用户数、有配额的用户数、超限用户数、即将过期数等。
func (ws *WebServer) handleQuotaStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8") // 设置响应内容类型为 JSON

	if r.Method != "GET" { // 只允许 GET 请求
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed) // 返回 405 错误
		return                                              // 终止处理
	}

	if ws.auth == nil { // 检查认证器是否已初始化
		log.Printf("错误：auth 为 nil")                               // 记录错误日志
		http.Error(w, "认证服务未初始化", http.StatusInternalServerError) // 返回 500 错误
		return                                                    // 终止处理
	}

	token := r.Header.Get("X-Auth-Token") // 从请求头获取认证令牌
	if token == "" {                      // 如果令牌为空
		log.Printf("[安全] handleQuotaStats 未授权访问尝试：%s", r.RemoteAddr)                      // 记录安全警告
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized) // 返回 401 错误
		return                                                                            // 终止处理
	}

	_, valid := ws.validateSession(token) // 验证会话令牌
	if !valid {                           // 如果会话无效
		log.Printf("[安全] handleQuotaStats 无效 token: %s", r.RemoteAddr)                       // 记录安全警告
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized) // 返回 401 错误
		return                                                                               // 终止处理
	}

	// 记录审计日志
	log.Printf("[审计] handleQuotaStats: IP=%s", r.RemoteAddr)

	users := ws.auth.ListUsers() // 获取所有用户列表

	totalUsers := len(users) // 计算用户总数
	usersWithQuota := 0      // 初始化有配额的用户计数器
	overLimitUsers := 0      // 初始化超限用户计数器
	expiringSoon := 0        // 初始化即将过期计数器

	now := time.Now().Unix()       // 获取当前时间戳
	daySeconds := int64(24 * 3600) // 计算一天的秒数（86400 秒）

	for _, user := range users { // 遍历所有用户
		quotaBytes := user.QuotaBytes // 获取用户的配额大小
		if quotaBytes > 0 {           // 如果用户设置了配额（大于 0）
			usersWithQuota++ // 有配额的用户数加 1

			used := atomic.LoadInt64(&user.QuotaUsed) // 原子读取用户已用流量
			if used >= quotaBytes {                   // 如果已用流量超过或等于配额
				overLimitUsers++ // 超限用户数加 1
			}

			if user.QuotaEndTime > 0 { // 如果设置了配额结束时间
				timeLeft := user.QuotaEndTime - now           // 计算剩余时间（秒）
				if timeLeft > 0 && timeLeft <= 7*daySeconds { // 如果剩余时间在 7 天内且大于 0
					expiringSoon++ // 即将过期计数器加 1
				}
			}
		}
	}

	// 构建响应数据映射
	response := map[string]interface{}{
		"totalUsers":     totalUsers,     // 用户总数
		"usersWithQuota": usersWithQuota, // 有配额的用户数
		"overLimitUsers": overLimitUsers, // 超限用户数
		"expiringSoon":   expiringSoon,   // 即将过期用户数
	}

	json.NewEncoder(w).Encode(response) // 将统计数据编码为 JSON 并写入响应
}

// handleBatchSetQuota 处理批量设置配额 API。
// 允许管理员一次性为多个用户设置相同的流量配额。
func (ws *WebServer) handleBatchSetQuota(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8") // 设置响应内容类型为 JSON

	if r.Method != "POST" { // 只允许 POST 请求
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed) // 返回 405 错误
		return                                              // 终止处理
	}

	token := r.Header.Get("X-Auth-Token") // 从请求头获取认证令牌
	if token == "" {                      // 如果令牌为空
		http.Error(w, "未授权访问", http.StatusUnauthorized) // 返回 401 错误
		return                                          // 终止处理
	}

	_, valid := ws.validateSession(token) // 验证会话令牌
	if !valid {                           // 如果会话无效
		http.Error(w, "未授权访问", http.StatusUnauthorized) // 返回 401 错误
		return                                          // 终止处理
	}

	// 定义请求数据结构体
	var req struct {
		Usernames    []string `json:"usernames"` // 要设置配额的用户名列表
		TrafficQuota struct { // 流量配额配置
			Period     string `json:"Period"`              // 配额周期
			QuotaBytes int64  `json:"QuotaBytes"`          // 配额大小（字节）
			StartTime  string `json:"StartTime,omitempty"` // 开始时间（自定义周期使用，omitempty 表示可选）
			EndTime    string `json:"EndTime,omitempty"`   // 结束时间（自定义周期使用，omitempty 表示可选）
		} `json:"trafficQuota"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil { // 解析请求体中的 JSON 数据
		log.Printf("解析批量设置数据失败：%v", err)                  // 记录解析错误
		http.Error(w, err.Error(), http.StatusBadRequest) // 返回 400 错误
		return                                            // 终止处理
	}

	if len(req.Usernames) == 0 { // 如果用户名列表为空
		http.Error(w, "未选择用户", http.StatusBadRequest) // 返回 400 错误
		return                                        // 终止处理
	}

	updatedCount := 0            // 初始化成功更新的用户计数器
	var startTime, endTime int64 // 声明开始和结束时间变量
	var err error                // 声明错误变量

	if req.TrafficQuota.Period == "custom" { // 如果是自定义周期
		if req.TrafficQuota.StartTime != "" { // 如果提供了开始时间字符串
			startTime, err = parseTimeString(req.TrafficQuota.StartTime) // 解析开始时间字符串
			if err != nil {                                              // 如果解析失败
				http.Error(w, "开始时间格式错误", http.StatusBadRequest) // 返回 400 错误
				return                                           // 终止处理
			}
		}
		if req.TrafficQuota.EndTime != "" { // 如果提供了结束时间字符串
			endTime, err = parseTimeString(req.TrafficQuota.EndTime) // 解析结束时间字符串
			if err != nil {                                          // 如果解析失败
				http.Error(w, "结束时间格式错误", http.StatusBadRequest) // 返回 400 错误
				return                                           // 终止处理
			}
		}
	}

	for _, username := range req.Usernames { // 遍历所有用户名
		if username == "" { // 如果用户名为空
			continue // 跳过空用户名
		}

		if req.TrafficQuota.Period == "unlimited" { // 如果设置为无限制
			ws.auth.ClearUserQuota(username) // 清除用户配额
		} else { // 否则设置有限配额
			ws.auth.SetUserQuota(username, req.TrafficQuota.Period, req.TrafficQuota.QuotaBytes) // 设置用户配额

			if req.TrafficQuota.Period == "custom" && startTime > 0 && endTime > 0 { // 如果是自定义周期且时间有效
				ws.auth.SetUserQuotaTimeRange(username, startTime, endTime) // 设置配额时间范围
			}
		}

		if ws.db != nil { // 如果数据库可用
			if user, exists := ws.auth.GetUser(username); exists { // 获取用户对象
				ws.db.SaveUser(user) // 保存用户信息到数据库
				updatedCount++       // 成功更新计数加 1
			}
		}
	}

	// 记录批量操作日志
	log.Printf("批量设置配额成功：更新了 %d 个用户", updatedCount)

	// 构建响应数据映射
	response := map[string]interface{}{
		"success": true,                                         // 操作成功标志
		"message": fmt.Sprintf("已成功为 %d 个用户设置配额", updatedCount), // 成功消息
		"updated": updatedCount,                                 // 实际更新的用户数
	}

	json.NewEncoder(w).Encode(response) // 将响应数据编码为 JSON 并写入响应
}

// parseTimeString 解析多种格式的时间字符串。
// 支持 Unix 时间戳、RFC3339 格式、ISO8601 格式等多种常见时间表示方式。
//
// 参数:
//   - timeStr: 时间字符串
//
// 返回:
//   - int64: Unix 时间戳（秒）
//   - error: 解析错误，如果所有格式都失败则返回错误
func parseTimeString(timeStr string) (int64, error) {
	// 尝试解析为 Unix 时间戳（整数）
	if timestamp, err := strconv.ParseInt(timeStr, 10, 64); err == nil { // 尝试将字符串解析为 64 位整数
		return timestamp, nil // 如果成功，直接返回时间戳
	}

	// 尝试解析为 RFC3339 格式（如 "2006-01-02T15:04:05Z07:00"）
	if t, err := time.Parse(time.RFC3339, timeStr); err == nil { // 尝试 RFC3339 格式
		return t.Unix(), nil // 如果成功，转换为 Unix 时间戳并返回
	}

	// 尝试解析为 "2006-01-02T15:04" 格式（不含秒和时区）
	if t, err := time.Parse("2006-01-02T15:04", timeStr); err == nil { // 尝试 ISO8601 简化格式
		return t.Unix(), nil // 如果成功，转换为 Unix 时间戳并返回
	}

	// 尝试解析为 "2006-01-02 15:04" 格式（空格分隔，不含秒）
	if t, err := time.Parse("2006-01-02 15:04", timeStr); err == nil { // 尝试常见日期时间格式
		return t.Unix(), nil // 如果成功，转换为 Unix 时间戳并返回
	}

	// 所有格式都失败，返回错误
	return 0, fmt.Errorf("无法解析时间格式：%s (支持时间戳、RFC3339、ISO8601 等格式)", timeStr)
}

// initDefaultAdmin 初始化默认管理员账户（admin / password123）。
// 仅在首次启动且数据库中没有管理员时创建。
// 生产环境应及时修改默认密码。
func (ws *WebServer) initDefaultAdmin() {
	ws.adminMu.Lock()         // 获取管理员数据的写锁
	defer ws.adminMu.Unlock() // 函数返回时释放锁

	// 如果已存在 admin 用户，则不重复创建
	if _, exists := ws.adminUsers["admin"]; exists { // 检查 admin 用户是否已存在
		return // 如果已存在，直接返回
	}

	passwordHash := hashPasswordForAdmin("password123") // 对默认密码进行 bcrypt 哈希
	ws.adminUsers["admin"] = &AdminUser{                // 创建默认管理员用户
		Username:     "admin",           // 用户名
		PasswordHash: passwordHash,      // 哈希后的密码
		Enabled:      true,              // 启用账户
		CreateTime:   time.Now().Unix(), // 记录创建时间
	}
	log.Println("默认管理员账户已初始化：admin / password123（请及时修改密码）") // 记录初始化日志
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
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost) // 使用 bcrypt 默认成本因子生成密码哈希
	if err != nil {                                                                  // 如果哈希生成失败
		log.Printf("密码哈希失败：%v", err) // 记录错误日志
		return ""                    // 返回空字符串
	}
	return string(hashed) // 将字节切片转换为字符串并返回
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
	ws.adminMu.RLock()         // 获取管理员数据的读锁
	defer ws.adminMu.RUnlock() // 函数返回时释放锁

	admin, exists := ws.adminUsers[username] // 查找指定用户名的管理员
	if !exists || !admin.Enabled {           // 如果用户不存在或账户已禁用
		// 用户不存在或已禁用，执行一次空比较以防止时序攻击
		bcrypt.CompareHashAndPassword([]byte(""), []byte(password)) // 执行一次空的哈希比较，消耗相同时间
		return false                                                // 返回密码错误
	}

	err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password)) // 比较明文密码和存储的哈希值
	return err == nil                                                                  // 如果没有错误，说明密码正确
}

// generateSessionToken 生成随机会话令牌（64 字符十六进制）。
// 使用加密安全的随机数生成器，确保令牌不可预测。
//
// 返回:
//   - string: 64 字符的十六进制字符串
//   - error: 随机数生成错误
func generateSessionToken() (string, error) {
	bytes := make([]byte, 32)                   // 创建 32 字节的切片（32 字节 = 64 字符十六进制）
	if _, err := rand.Read(bytes); err != nil { // 使用加密安全的随机数生成器填充字节
		return "", err // 如果生成失败，返回错误
	}
	return hex.EncodeToString(bytes), nil // 将字节转换为十六进制字符串并返回
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
	token, err := generateSessionToken() // 生成随机会话令牌
	if err != nil {                      // 如果生成失败
		return "", err // 返回错误
	}

	// 创建会话对象，设置过期时间
	session := &Session{
		Token:        token,                                 // 会话令牌
		Username:     username,                              // 管理员用户名
		ExpireTime:   time.Now().Add(24 * time.Hour).Unix(), // 24小时后绝对过期时间
		ClientIP:     clientIP,                              // 客户端 IP 地址
		CreateTime:   time.Now().Unix(),                     // 会话创建时间
		LastActivity: time.Now().Unix(),                     // 最后活动时间（初始为创建时间）
	}

	// 保存会话到内存
	ws.sessionMu.Lock()          // 获取会话数据的写锁
	defer ws.sessionMu.Unlock()  // 函数返回时释放锁
	ws.sessions[token] = session // 将会话存入映射表

	// 更新管理员登录统计
	ws.adminMu.Lock()                                     // 获取管理员数据的写锁
	if admin, exists := ws.adminUsers[username]; exists { // 查找管理员
		admin.LastLogin = time.Now().Unix() // 更新最后登录时间
		admin.LoginCount++                  // 登录次数加 1
	}
	ws.adminMu.Unlock() // 释放管理员数据锁

	return token, nil // 返回会话令牌
}

const (
	SessionTimeout       = 30 * 60      // 会话超时时间：30 分钟（1800 秒，无活动后失效）
	SessionMaxExpireTime = 24 * 60 * 60 // 会话最大有效期：24 小时（86400 秒，从创建时计算）
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
	ws.sessionMu.RLock()         // 获取会话数据的读锁
	defer ws.sessionMu.RUnlock() // 函数返回时释放锁

	session, exists := ws.sessions[token] // 查找指定令牌的会话
	if !exists {                          // 如果会话不存在
		return nil, false // 返回无效
	}

	// 检查是否超过最大有效期（绝对过期）
	if time.Now().Unix() > session.ExpireTime { // 如果当前时间超过会话过期时间
		log.Printf("会话已过期：用户=%s", session.Username) // 记录过期日志
		return nil, false                           // 返回无效
	}

	// 检查是否超过空闲超时（30分钟无活动）
	now := time.Now().Unix()                       // 获取当前时间戳
	if now-session.LastActivity > SessionTimeout { // 如果距离最后活动时间超过 30 分钟
		log.Printf("会话超时（30 分钟未活动）：用户=%s, IP=%s", session.Username, session.ClientIP) // 记录超时日志
		// 异步使会话失效，避免阻塞
		go ws.invalidateSession(token) // 启动协程异步删除会话
		return nil, false              // 返回无效
	}

	return session, true // 会话有效，返回会话对象和 true
}

// invalidateSession 使会话失效。
// 从会话映射中删除指定的会话令牌。
//
// 参数:
//   - token: 要失效的会话令牌
func (ws *WebServer) invalidateSession(token string) {
	ws.sessionMu.Lock()         // 获取会话数据的写锁
	defer ws.sessionMu.Unlock() // 函数返回时释放锁
	delete(ws.sessions, token)  // 从映射表中删除会话
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
	ws.sessionMu.Lock()         // 获取会话数据的写锁
	defer ws.sessionMu.Unlock() // 函数返回时释放锁

	session, exists := ws.sessions[token] // 查找指定令牌的会话
	if !exists {                          // 如果会话不存在
		return false // 返回失败
	}

	session.LastActivity = time.Now().Unix() // 更新最后活动时间为当前时间
	return true                              // 返回成功
}

// getAdminUser 获取管理员用户信息。
// 根据用户名查找并返回管理员对象，如果不存在则返回 nil。
func (ws *WebServer) getAdminUser(username string) *AdminUser {
	ws.adminMu.RLock()         // 获取管理员数据的读锁
	defer ws.adminMu.RUnlock() // 函数返回时释放锁

	if admin, exists := ws.adminUsers[username]; exists { // 查找指定用户名的管理员
		return admin // 如果存在，返回管理员对象
	}
	return nil // 如果不存在，返回 nil
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
	ws.adminMu.RLock()         // 获取管理员数据的读锁
	defer ws.adminMu.RUnlock() // 函数返回时释放锁

	admin, exists := ws.adminUsers[username] // 查找指定用户名的管理员
	if !exists {                             // 如果用户不存在
		return false // 返回未锁定
	}

	now := time.Now().Unix() // 获取当前时间戳

	// 检查是否在锁定期内
	if admin.LockUntil > now { // 如果锁定截止时间大于当前时间
		return true // 账户仍被锁定
	}

	// 如果锁定时间已过，自动解锁
	if admin.LockUntil > 0 && admin.LockUntil <= now { // 如果曾设置过锁定时间且已过期
		ws.adminMu.RUnlock()     // 先释放读锁
		ws.adminMu.Lock()        // 获取写锁（需要修改数据）
		admin.LockUntil = 0      // 清除锁定截止时间
		admin.LoginFailCount = 0 // 重置登录失败计数
		ws.adminMu.Unlock()      // 释放写锁
		ws.adminMu.RLock()       // 重新获取读锁（保持函数退出时的 defer 一致性）
	}

	return false // 账户未被锁定
}

// recordLoginFailure 记录登录失败，达到阈值后锁定账户。
// 防止暴力破解攻击，连续失败 MaxLoginFailCount 次后锁定账户 LoginLockDuration 时间。
//
// 参数:
//   - username: 用户名
func (ws *WebServer) recordLoginFailure(username string) {
	ws.adminMu.Lock()         // 获取管理员数据的写锁
	defer ws.adminMu.Unlock() // 函数返回时释放锁

	admin, exists := ws.adminUsers[username] // 查找指定用户名的管理员
	if !exists {                             // 如果用户不存在
		return // 直接返回
	}

	now := time.Now().Unix() // 获取当前时间戳

	// 如果距离上次失败已超过重置时间，清零计数
	if admin.LastLoginFailTime > 0 && now-admin.LastLoginFailTime > LoginFailResetTime { // 检查是否需要重置计数器
		admin.LoginFailCount = 0 // 重置失败计数
	}

	admin.LoginFailCount++        // 失败计数加 1
	admin.LastLoginFailTime = now // 更新最后失败时间

	// 达到最大失败次数，锁定账户
	if admin.LoginFailCount >= MaxLoginFailCount { // 如果失败次数达到阈值（5次）
		admin.LockUntil = now + LoginLockDuration                              // 设置锁定截止时间（当前时间 + 15分钟）
		log.Printf("账户已被锁定：用户名=%s, 锁定时间=%d分钟", username, LoginLockDuration/60) // 记录锁定日志
	}
}

// clearLoginFailure 清除登录失败记录。
// 在成功登录后调用，重置失败计数和锁定状态。
//
// 参数:
//   - username: 用户名
func (ws *WebServer) clearLoginFailure(username string) {
	ws.adminMu.Lock()         // 获取管理员数据的写锁
	defer ws.adminMu.Unlock() // 函数返回时释放锁

	admin, exists := ws.adminUsers[username] // 查找指定用户名的管理员
	if !exists {                             // 如果用户不存在
		return // 直接返回
	}

	admin.LoginFailCount = 0    // 重置失败计数
	admin.LastLoginFailTime = 0 // 清除最后失败时间
	admin.LockUntil = 0         // 清除锁定截止时间
}

// clearExistingSessions 清除指定用户的所有现有会话。
// 用于确保同一用户只有一个活跃会话，提高安全性。
//
// 参数:
//   - username: 用户名
func (ws *WebServer) clearExistingSessions(username string) {
	ws.sessionMu.Lock()         // 获取会话数据的写锁
	defer ws.sessionMu.Unlock() // 函数返回时释放锁

	for token, session := range ws.sessions { // 遍历所有会话
		if session.Username == username { // 如果会话属于指定用户
			delete(ws.sessions, token)          // 删除该会话
			log.Printf("清除旧会话：用户=%s", username) // 记录日志
		}
	}
}

// authMiddleware 认证中间件，保护需要登录的 API。
// 检查请求是否包含有效的会话令牌，对修改操作进行 CSRF 验证。
// 公开路径（如登录、验证码）无需认证。
func (ws *WebServer) authMiddleware(next http.Handler) http.Handler {
	// 返回一个 HTTP 处理器函数，包装原始处理器并应用认证检查
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 公开路径，无需认证
		publicPaths := []string{"/", "/api/admin/login", "/api/admin/captcha", "/static/"} // 定义不需要认证的路径列表
		for _, path := range publicPaths {                                                 // 遍历公开路径
			if strings.HasPrefix(r.URL.Path, path) { // 如果请求路径以公开路径开头
				next.ServeHTTP(w, r) // 直接调用下一个处理器，跳过认证
				return               // 终止处理
			}
		}

		// 从 Cookie 或 Header 提取 Token
		token := getCookie(r, "session_token") // 首先尝试从 Cookie 获取会话令牌

		if token == "" { // 如果 Cookie 中没有令牌
			authHeader := r.Header.Get("Authorization") // 尝试从 Authorization 头获取
			if authHeader != "" {                       // 如果 Authorization 头存在
				parts := strings.Split(authHeader, " ")      // 按空格分割头部值
				if len(parts) == 2 && parts[0] == "Bearer" { // 检查格式是否为 "Bearer <token>"
					token = parts[1] // 提取 token 部分
				}
			}
		}

		if token == "" { // 如果仍然没有令牌
			http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized) // 返回 401 错误
			return                                                                            // 终止处理
		}

		// 验证会话令牌
		session, valid := ws.validateSession(token) // 调用会话验证函数
		if !valid {                                 // 如果会话无效
			http.Error(w, `{"error":"会话已过期或无效","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized) // 返回 401 错误
			return                                                                                  // 终止处理
		}

		// 刷新会话活动时间，延长会话有效期
		ws.refreshSessionActivity(token) // 更新最后活动时间，防止会话因空闲而超时

		// 对修改操作进行 CSRF 验证（POST/PUT/DELETE）
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" { // 如果是修改类请求
			csrfToken := r.Header.Get("X-CSRF-Token") // 首先从请求头获取 CSRF 令牌
			if csrfToken == "" {                      // 如果请求头中没有
				csrfToken = r.FormValue("csrf_token") // 尝试从表单数据获取
			}

			if !ws.validateCSRFToken(csrfToken, session.Username) { // 验证 CSRF 令牌
				log.Printf("CSRF 验证失败：用户=%s, IP=%s", session.Username, r.RemoteAddr)              // 记录安全警告
				http.Error(w, `{"error":"CSRF 验证失败","code":"CSRF_FAILED"}`, http.StatusForbidden) // 返回 403 禁止访问
				return                                                                            // 终止处理
			}
		}

		next.ServeHTTP(w, r) // 所有检查通过，调用下一个处理器
	})
}

const (
	MaxLoginFailCount  = 5       // 最大登录失败次数（超过 5 次后锁定账户）
	LoginLockDuration  = 15 * 60 // 账户锁定时长：15 分钟（900 秒）
	LoginFailResetTime = 30 * 60 // 失败计数重置时间：30 分钟（1800 秒，无失败后清零）
)

// handleAdminLogin 处理管理员登录 API。
// 验证用户名、密码、验证码，创建会话并返回令牌。
// 包含账户锁定、验证码验证、首次登录强制改密等安全机制。
func (ws *WebServer) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" { // 只允许 POST 请求
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed) // 返回 405 错误
		return                                                          // 终止处理
	}

	// 定义登录请求数据结构体
	var data struct {
		Username  string `json:"username"`   // 管理员用户名
		Password  string `json:"password"`   // 管理员密码
		CaptchaID string `json:"captcha_id"` // 验证码 ID（前端从获取验证码接口获得）
		Captcha   string `json:"captcha"`    // 用户输入的验证码
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil { // 解析请求体中的 JSON 数据
		http.Error(w, `{"error":"请求数据格式错误"}`, http.StatusBadRequest) // 如果解析失败，返回 400 错误
		return                                                       // 终止处理
	}

	// 检查账户是否被锁定
	if ws.isAccountLocked(data.Username) { // 调用账户锁定检查函数
		log.Printf("管理员登录失败：账户已锁定，用户名=%s, IP=%s", data.Username, r.RemoteAddr)                           // 记录锁定日志
		http.Error(w, `{"error":"账户已被锁定，请15分钟后再试","code":"ACCOUNT_LOCKED"}`, http.StatusTooManyRequests) // 返回 429 错误
		return                                                                                           // 终止处理
	}

	// 验证验证码（防止自动化攻击）
	if !ws.verifyCaptcha(data.CaptchaID, data.Captcha) { // 调用验证码验证函数
		log.Printf("管理员登录失败：验证码错误，用户名=%s, IP=%s", data.Username, r.RemoteAddr)            // 记录验证码错误日志
		http.Error(w, `{"error":"验证码错误","code":"CAPTCHA_FAILED"}`, http.StatusBadRequest) // 返回 400 错误
		return                                                                            // 终止处理
	}

	// 验证密码
	if !ws.verifyAdminPassword(data.Username, data.Password) { // 调用密码验证函数
		log.Printf("管理员登录失败：用户名=%s, IP=%s", data.Username, r.RemoteAddr)                    // 记录登录失败日志
		ws.recordLoginFailure(data.Username)                                                // 记录失败次数，可能触发账户锁定
		http.Error(w, `{"error":"用户名或密码错误","code":"AUTH_FAILED"}`, http.StatusUnauthorized) // 返回 401 错误（不区分用户名或密码错误，防止枚举）
		return                                                                              // 终止处理
	}

	// 登录成功，清除失败记录
	ws.clearLoginFailure(data.Username) // 重置登录失败计数和锁定状态

	admin := ws.getAdminUser(data.Username)        // 获取管理员用户信息
	if admin != nil && admin.ForcePasswordChange { // 如果设置了强制修改密码标志（首次登录）
		// 首次登录，强制修改密码
		token, err := ws.createSession(data.Username, r.RemoteAddr) // 创建会话
		if err != nil {                                             // 如果创建失败
			log.Printf("创建会话失败：%v", err)                                                               // 记录错误日志
			http.Error(w, `{"error":"服务器内部错误","code":"SERVER_ERROR"}`, http.StatusInternalServerError) // 返回 500 错误
			return                                                                                     // 终止处理
		}

		log.Printf("管理员首次登录，需要修改密码：用户名=%s, IP=%s", data.Username, r.RemoteAddr) // 记录首次登录日志

		w.Header().Set("Content-Type", "application/json")                                             // 设置响应内容类型为 JSON
		ws.setSecureCookie(w, "session_token", token, 3600)                                            // 设置会话 Cookie（1小时有效期）
		fmt.Fprintf(w, `{"status":"force_password_change","message":"首次登录请修改密码","token":"%s"}`, token) // 返回强制改密响应
		return                                                                                         // 终止处理
	}

	// 清除旧会话（确保单点登录）
	ws.clearExistingSessions(data.Username) // 删除该用户的所有现有会话

	// 创建新会话
	token, err := ws.createSession(data.Username, r.RemoteAddr) // 创建新的会话
	if err != nil {                                             // 如果创建失败
		log.Printf("创建会话失败：%v", err)                                                               // 记录错误日志
		http.Error(w, `{"error":"服务器内部错误","code":"SERVER_ERROR"}`, http.StatusInternalServerError) // 返回 500 错误
		return                                                                                     // 终止处理
	}

	log.Printf("管理员登录成功：用户名=%s, IP=%s", data.Username, r.RemoteAddr) // 记录登录成功日志

	// 生成 CSRF 令牌
	csrfToken := ws.generateCSRFToken(data.Username) // 基于用户名和密钥生成 CSRF 令牌

	w.Header().Set("Content-Type", "application/json") // 设置响应内容类型为 JSON

	// 设置安全的 Cookie
	ws.setSecureCookie(w, "session_token", token, 86400)  // 设置会话 Cookie（24小时 = 86400秒）
	ws.setSecureCookie(w, "csrf_token", csrfToken, 86400) // 设置 CSRF Cookie（24小时 = 86400秒）

	// 返回登录成功响应，包含令牌、用户名和 CSRF 令牌
	fmt.Fprintf(w, `{"status":"success","token":"%s","username":"%s","csrf_token":"%s"}`, token, data.Username, csrfToken)
}

// handleAdminLogout 处理管理员登出 API。
// 使当前会话失效，清除 Cookie，实现安全退出。
func (ws *WebServer) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" { // 只允许 POST 请求
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed) // 返回 405 错误
		return                                                          // 终止处理
	}

	// 从 Cookie 或 Header 获取会话令牌
	token := getCookie(r, "session_token") // 首先尝试从 Cookie 获取
	if token == "" {                       // 如果 Cookie 中没有
		authHeader := r.Header.Get("Authorization") // 尝试从 Authorization 头获取
		if authHeader != "" {                       // 如果 Authorization 头存在
			parts := strings.Split(authHeader, " ")      // 按空格分割
			if len(parts) == 2 && parts[0] == "Bearer" { // 检查格式
				token = parts[1] // 提取令牌
			}
		}
	}

	if token != "" { // 如果获取到令牌
		ws.invalidateSession(token) // 使会话失效（从内存中删除）
	}

	// 删除 Cookie（设置 MaxAge 为 -1 表示立即过期）
	ws.setSecureCookie(w, "session_token", "", -1) // 删除会话 Cookie
	ws.setSecureCookie(w, "csrf_token", "", -1)    // 删除 CSRF Cookie

	fmt.Fprintf(w, `{"status":"success","message":"已安全退出"}`) // 返回成功响应
}

// handleAdminCheck 检查管理员登录状态。
// 用于前端页面加载时检查用户是否已登录。
func (ws *WebServer) handleAdminCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" { // 只允许 GET 请求
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed) // 返回 405 错误
		return                                                          // 终止处理
	}

	// 从多个来源尝试获取令牌
	authHeader := r.Header.Get("Authorization") // 首先尝试 Authorization 头
	var token string                            // 声明令牌变量

	if authHeader != "" { // 如果 Authorization 头存在
		parts := strings.Split(authHeader, " ")      // 按空格分割
		if len(parts) == 2 && parts[0] == "Bearer" { // 检查格式
			token = parts[1] // 提取令牌
		}
	}

	if token == "" { // 如果 Authorization 头中没有
		token = r.Header.Get("X-Auth-Token") // 尝试 X-Auth-Token 头
	}

	if token == "" { // 如果仍然没有
		token = getCookie(r, "session_token") // 尝试从 Cookie 获取
	}

	if token == "" { // 如果所有方式都没有获取到令牌
		http.Error(w, `{"error":"未登录","code":"NOT_LOGGED_IN"}`, http.StatusUnauthorized) // 返回 401 错误
		return                                                                           // 终止处理
	}

	session, valid := ws.validateSession(token) // 验证会话令牌
	if !valid {                                 // 如果会话无效
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized) // 返回 401 错误
		return                                                                               // 终止处理
	}

	w.Header().Set("Content-Type", "application/json")                                        // 设置响应内容类型为 JSON
	fmt.Fprintf(w, `{"status":"success","logged_in":true,"username":"%s"}`, session.Username) // 返回登录状态和用户名
}

// handleCaptcha 生成并返回验证码图片。
// 每次请求生成一个新的验证码，存储到内存中，有效期5分钟。
// 返回 PNG 格式的图片，并在响应头中包含验证码 ID。
func (ws *WebServer) handleCaptcha(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" { // 只允许 GET 请求
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed) // 返回 405 错误
		return                                                          // 终止处理
	}

	// 生成唯一的验证码 ID（基于纳秒级时间戳）
	captchaID := fmt.Sprintf("%d", time.Now().UnixNano()) // 使用当前时间的纳秒戳作为唯一 ID
	code, img := ws.generateCaptcha()                     // 生成验证码文本和图片

	// 存储验证码信息到内存
	ws.captchaMu.Lock()         // 获取验证码存储的写锁
	if ws.captchaStore == nil { // 如果存储映射未初始化
		ws.captchaStore = make(map[string]*CaptchaInfo) // 初始化映射
	}
	ws.captchaStore[captchaID] = &CaptchaInfo{
		Code:     code,                                   // 验证码文本
		ExpireAt: time.Now().Add(5 * time.Minute).Unix(), // 设置过期时间为 5 分钟后
	}
	ws.captchaMu.Unlock() // 释放写锁

	// 设置响应头
	w.Header().Set("Content-Type", "image/png")                            // 设置内容类型为 PNG 图片
	w.Header().Set("X-Captcha-ID", captchaID)                              // 在响应头中返回验证码 ID，供前端提交时使用
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate") // 禁止浏览器缓存验证码图片
	w.Header().Set("Pragma", "no-cache")                                   // HTTP/1.0 兼容的无缓存指令
	w.Header().Set("Expires", "0")                                         // 设置过期时间为过去，确保不缓存
	if err := png.Encode(w, img); err != nil {                             // 将图片编码为 PNG 格式并写入响应
		log.Printf("编码验证码图片失败：%v", err) // 如果编码失败，记录错误日志
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
	ws.captchaMu.RLock()                       // 获取验证码存储的读锁
	info, exists := ws.captchaStore[captchaID] // 查找指定 ID 的验证码
	ws.captchaMu.RUnlock()                     // 释放读锁

	if !exists { // 如果验证码不存在
		return false // 返回验证失败
	}

	// 检查是否过期
	if time.Now().Unix() > info.ExpireAt { // 如果当前时间超过过期时间
		ws.captchaMu.Lock()                // 获取写锁
		delete(ws.captchaStore, captchaID) // 删除过期的验证码
		ws.captchaMu.Unlock()              // 释放写锁
		return false                       // 返回验证失败
	}

	// 不区分大小写比较
	if strings.EqualFold(info.Code, code) { // 使用不区分大小写的字符串比较
		// 验证成功，立即销毁验证码（一次性使用）
		ws.captchaMu.Lock()                // 获取写锁
		delete(ws.captchaStore, captchaID) // 删除已使用的验证码
		ws.captchaMu.Unlock()              // 释放写锁
		return true                        // 返回验证成功
	}

	// 验证失败，增加失败计数
	info.FailCount++         // 失败次数加 1
	if info.FailCount >= 5 { // 如果失败次数达到 5 次
		// 失败次数过多，销毁验证码
		ws.captchaMu.Lock()                // 获取写锁
		delete(ws.captchaStore, captchaID) // 删除验证码
		ws.captchaMu.Unlock()              // 释放写锁
	}

	return false // 返回验证失败
}

// handleChangePassword 处理修改管理员密码 API。
// 验证旧密码，检查新密码强度，更新密码并保存到数据库。
func (ws *WebServer) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" { // 只允许 POST 请求
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed) // 返回 405 错误
		return                                                          // 终止处理
	}

	// 从多个来源获取认证令牌
	authHeader := r.Header.Get("Authorization") // 首先尝试 Authorization 头
	var token string                            // 声明令牌变量

	if authHeader != "" { // 如果 Authorization 头存在
		parts := strings.Split(authHeader, " ")      // 按空格分割
		if len(parts) == 2 && parts[0] == "Bearer" { // 检查格式
			token = parts[1] // 提取令牌
		}
	}

	if token == "" { // 如果 Authorization 头中没有
		token = r.Header.Get("X-Auth-Token") // 尝试 X-Auth-Token 头
	}

	if token == "" { // 如果仍然没有令牌
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized) // 返回 401 错误
		return                                                                            // 终止处理
	}

	session, valid := ws.validateSession(token) // 验证会话令牌
	if !valid {                                 // 如果会话无效
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized) // 返回 401 错误
		return                                                                               // 终止处理
	}

	// 定义请求数据结构体
	var data struct {
		OldPassword string `json:"old_password"` // 旧密码
		NewPassword string `json:"new_password"` // 新密码
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil { // 解析请求体中的 JSON 数据
		http.Error(w, `{"error":"请求数据格式错误"}`, http.StatusBadRequest) // 如果解析失败，返回 400 错误
		return                                                       // 终止处理
	}

	// 验证旧密码
	if !ws.verifyAdminPassword(session.Username, data.OldPassword) { // 验证用户输入的旧密码是否正确
		log.Printf("修改密码失败：旧密码错误，用户名=%s, IP=%s", session.Username, r.RemoteAddr)          // 记录错误日志
		http.Error(w, `{"error":"原密码错误","code":"WRONG_PASSWORD"}`, http.StatusBadRequest) // 返回 400 错误
		return                                                                            // 终止处理
	}

	// 检查新密码强度
	if len(data.NewPassword) < 6 { // 如果新密码长度小于 6 位
		http.Error(w, `{"error":"密码长度至少为 6 位","code":"WEAK_PASSWORD"}`, http.StatusBadRequest) // 返回 400 错误
		return                                                                                 // 终止处理
	}

	// 更新密码
	ws.adminMu.Lock()                                    // 获取管理员数据的写锁
	adminUser, exists := ws.adminUsers[session.Username] // 查找当前登录的管理员
	if !exists {                                         // 如果用户不存在（异常情况）
		ws.adminMu.Unlock()                                                             // 释放锁
		http.Error(w, `{"error":"用户不存在","code":"USER_NOT_FOUND"}`, http.StatusNotFound) // 返回 404 错误
		return                                                                          // 终止处理
	}

	newPasswordHash := hashPasswordForAdmin(data.NewPassword) // 对新密码进行 bcrypt 哈希
	if newPasswordHash == "" {                                // 如果哈希生成失败
		ws.adminMu.Unlock()                                                                      // 释放锁
		http.Error(w, `{"error":"密码更新失败","code":"HASH_FAILED"}`, http.StatusInternalServerError) // 返回 500 错误
		return                                                                                   // 终止处理
	}

	adminUser.PasswordHash = newPasswordHash         // 更新密码哈希
	adminUser.LastPasswordChange = time.Now().Unix() // 记录密码修改时间
	adminUser.ForcePasswordChange = false            // 清除强制改密标志
	ws.adminUsers[session.Username] = adminUser      // 保存更新后的用户信息
	ws.adminMu.Unlock()                              // 释放写锁

	// 保存到数据库
	if ws.db != nil { // 如果数据库可用
		if err := ws.db.SaveAdminUser(session.Username, adminUser.PasswordHash, adminUser.Enabled); err != nil { // 尝试保存
			log.Printf("保存管理员密码到数据库失败：%v", err) // 记录保存失败日志
		} else {
			log.Printf("管理员密码已保存到数据库") // 记录成功日志
		}
	}

	log.Printf("管理员密码修改成功：用户名=%s, IP=%s", session.Username, r.RemoteAddr) // 记录成功日志

	w.Header().Set("Content-Type", "application/json")        // 设置响应内容类型为 JSON
	fmt.Fprintf(w, `{"status":"success","message":"密码修改成功"}`) // 返回成功响应
}

// handleGetAuthMethod 获取当前认证方式。
// 返回 "none"（无认证）或 "password"（密码认证）。
func (ws *WebServer) handleGetAuthMethod(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" { // 只允许 GET 请求
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed) // 返回 405 错误
		return                                                          // 终止处理
	}

	// 从多个来源获取认证令牌
	authHeader := r.Header.Get("Authorization") // 首先尝试 Authorization 头
	var token string                            // 声明令牌变量

	if authHeader != "" { // 如果 Authorization 头存在
		parts := strings.Split(authHeader, " ")      // 按空格分割
		if len(parts) == 2 && parts[0] == "Bearer" { // 检查格式
			token = parts[1] // 提取令牌
		}
	}

	if token == "" { // 如果 Authorization 头中没有
		token = r.Header.Get("X-Auth-Token") // 尝试 X-Auth-Token 头
	}

	if token == "" { // 如果仍然没有令牌
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized) // 返回 401 错误
		return                                                                            // 终止处理
	}

	_, valid := ws.validateSession(token) // 验证会话令牌
	if !valid {                           // 如果会话无效
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized) // 返回 401 错误
		return                                                                               // 终止处理
	}

	authMethod := "password" // 默认认证方式为密码认证
	if ws.db != nil {        // 如果数据库可用
		method, err := ws.db.GetConfig("auth_method") // 从数据库获取配置的认证方式
		if err == nil && method != "" {               // 如果获取成功且不为空
			authMethod = method // 使用数据库中的配置
		}
	}

	// 检查 SOCKS 服务器的实际认证配置
	if ws.socksServer != nil && ws.socksServer.config != nil && ws.socksServer.config.Auth != nil { // 检查服务器配置
		if _, ok := ws.socksServer.config.Auth.(*NoAuth); ok { // 如果认证器是 NoAuth 类型
			authMethod = "none" // 设置为无认证
		}
	}

	w.Header().Set("Content-Type", "application/json")                    // 设置响应内容类型为 JSON
	fmt.Fprintf(w, `{"status":"success","auth_method":"%s"}`, authMethod) // 返回认证方式
}

// handleSetAuthMethod 设置认证方式（none/password）。
// 允许管理员在运行时切换 SOCKS5 服务器的认证模式。
func (ws *WebServer) handleSetAuthMethod(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" { // 只允许 POST 请求
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed) // 返回 405 错误
		return                                                          // 终止处理
	}

	// 从多个来源获取认证令牌
	authHeader := r.Header.Get("Authorization") // 首先尝试 Authorization 头
	var token string                            // 声明令牌变量

	if authHeader != "" { // 如果 Authorization 头存在
		parts := strings.Split(authHeader, " ")      // 按空格分割
		if len(parts) == 2 && parts[0] == "Bearer" { // 检查格式
			token = parts[1] // 提取令牌
		}
	}

	if token == "" { // 如果 Authorization 头中没有
		token = r.Header.Get("X-Auth-Token") // 尝试 X-Auth-Token 头
	}

	if token == "" { // 如果仍然没有令牌
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized) // 返回 401 错误
		return                                                                            // 终止处理
	}

	session, valid := ws.validateSession(token) // 验证会话令牌
	if !valid {                                 // 如果会话无效
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized) // 返回 401 错误
		return                                                                               // 终止处理
	}

	// 定义请求数据结构体
	var data struct {
		AuthMethod string `json:"auth_method"` // 要设置的认证方式
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil { // 解析请求体中的 JSON 数据
		http.Error(w, `{"error":"请求数据格式错误"}`, http.StatusBadRequest) // 如果解析失败，返回 400 错误
		return                                                       // 终止处理
	}

	if data.AuthMethod != "none" && data.AuthMethod != "password" { // 验证认证方式是否有效
		http.Error(w, `{"error":"无效的认证方式","code":"INVALID_AUTH_METHOD"}`, http.StatusBadRequest) // 返回 400 错误
		return                                                                                   // 终止处理
	}

	if data.AuthMethod == "none" { // 如果设置为无认证
		// 创建新的 NoAuth 实例
		noAuth := &NoAuth{}
		// 同时更新 WebServer 和 SOCKS5 服务器的认证器
		ws.auth = nil // WebServer 不再需要 PasswordAuth
		ws.socksServer.config.Auth = noAuth
		log.Printf("管理员 [%s] 切换认证方式为：无认证，IP=%s", session.Username, r.RemoteAddr)
	} else { // 如果设置为密码认证
		// 检查 ws.auth 是否为 nil，如果是则创建新的 PasswordAuth
		if ws.auth == nil {
			ws.auth = NewPasswordAuth()
		}

		// 从数据库加载用户数据（如果数据库可用）
		if ws.db != nil {
			if err := ws.db.LoadAllUsersToAuth(ws.auth); err != nil {
				log.Printf("加载用户数据失败：%v", err)
			} else {
				log.Printf("已从数据库加载 %d 个用户到内存", len(ws.auth.users))
			}
		}

		// 同时更新 WebServer 和 SOCKS5 服务器的认证器
		ws.socksServer.config.Auth = ws.auth
		log.Printf("管理员 [%s] 切换认证方式为：密码认证，IP=%s", session.Username, r.RemoteAddr)
	}

	if ws.db != nil { // 如果数据库可用
		ws.db.SetConfig("auth_method", data.AuthMethod, "SOCKS5 认证方式：none=无认证，password=密码认证") // 保存认证方式配置
		enableMgmt := "false"                                                                 // 默认禁用用户管理
		if data.AuthMethod == "password" {                                                    // 如果是密码认证
			enableMgmt = "true" // 启用用户管理
		}
		ws.db.SetConfig("enable_user_management", enableMgmt, "是否启用用户管理：true=启用，false=禁用") // 保存用户管理配置
	}

	w.Header().Set("Content-Type", "application/json") // 设置响应内容类型为 JSON
	// 返回成功响应，包含认证方式和中文描述
	fmt.Fprintf(w, `{"status":"success","auth_method":"%s","message":"认证方式已切换为%s模式"}`, data.AuthMethod, map[string]string{
		"none":     "无认证",  // 无认证模式的中文描述
		"password": "密码认证", // 密码认证模式的中文描述
	}[data.AuthMethod])
}

// handleGetConfig 获取服务器配置。
// 从数据库和内存配置中读取当前的服务器配置参数。
func (ws *WebServer) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	// 从多个来源获取认证令牌
	authHeader := r.Header.Get("Authorization") // 首先尝试 Authorization 头
	var token string                            // 声明令牌变量

	if authHeader != "" { // 如果 Authorization 头存在
		parts := strings.Split(authHeader, " ")      // 按空格分割
		if len(parts) == 2 && parts[0] == "Bearer" { // 检查格式
			token = parts[1] // 提取令牌
		}
	}

	if token == "" { // 如果 Authorization 头中没有
		token = r.Header.Get("X-Auth-Token") // 尝试 X-Auth-Token 头
	}

	if token == "" { // 如果仍然没有令牌
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized) // 返回 401 错误
		return                                                                            // 终止处理
	}

	_, valid := ws.validateSession(token) // 验证会话令牌
	if !valid {                           // 如果会话无效
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized) // 返回 401 错误
		return                                                                               // 终止处理
	}

	config := make(map[string]interface{}) // 创建配置映射
	if ws.db != nil {                      // 如果数据库可用
		keys := []string{ // 定义要获取的配置键列表
			"listen_addr", "auth_method", "enable_user_management", // 监听地址、认证方式、用户管理开关
		}
		for _, key := range keys { // 遍历所有配置键
			if value, err := ws.db.GetConfig(key); err == nil && value != "" { // 尝试获取配置值
				config[key] = value // 如果获取成功且不为空，存入映射
			}
		}

		// 获取整数类型的配置项
		if workers, err := ws.db.GetIntConfig("max_workers"); err == nil { // 获取最大工作协程数
			config["max_workers"] = workers // 存入映射
		}
		if maxConn, err := ws.db.GetIntConfig("max_conn_per_ip"); err == nil { // 获取单 IP 最大连接数
			config["max_conn_per_ip"] = maxConn // 存入映射
		}
		if keepalive, err := ws.db.GetIntConfig("tcp_keepalive_period"); err == nil { // 获取 TCP Keepalive 周期
			config["tcp_keepalive_period"] = keepalive // 存入映射
		}
	}

	// 从内存配置补充（如果数据库中没有配置，则使用内存中的默认值）
	if ws.socksServer != nil { // 如果 SOCKS 服务器存在
		if _, exists := config["listen_addr"]; !exists { // 如果 listen_addr 未从数据库获取
			config["listen_addr"] = ws.socksServer.config.ListenAddr // 使用内存中的监听地址
		}
		if _, exists := config["max_workers"]; !exists { // 如果 max_workers 未从数据库获取
			config["max_workers"] = ws.socksServer.config.MaxWorkers // 使用内存中的最大工作协程数
		}
		if _, exists := config["max_conn_per_ip"]; !exists { // 如果 max_conn_per_ip 未从数据库获取
			config["max_conn_per_ip"] = ws.socksServer.config.MaxConnPerIP // 使用内存中的单 IP 最大连接数
		}
		if _, exists := config["tcp_keepalive_period"]; !exists { // 如果 tcp_keepalive_period 未从数据库获取
			config["tcp_keepalive_period"] = int(ws.socksServer.config.TCPKeepAlivePeriod.Seconds()) // 将 Duration 转换为秒
		}
	}

	log.Printf("返回配置：%+v", config) // 记录返回的配置信息（调试用）

	w.Header().Set("Content-Type", "application/json")                    // 设置响应内容类型为 JSON
	fmt.Fprintf(w, `{"status":"success","config":%s}`, mapToJSON(config)) // 返回配置数据
}

// handleSetConfig 设置服务器配置。
// 允许管理员修改服务器监听地址、工作协程数、连接限制等参数。
func (ws *WebServer) handleSetConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" { // 只允许 POST 请求
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed) // 返回 405 错误
		return                                                          // 终止处理
	}

	// 从多个来源获取认证令牌
	authHeader := r.Header.Get("Authorization") // 首先尝试 Authorization 头
	var token string                            // 声明令牌变量

	if authHeader != "" { // 如果 Authorization 头存在
		parts := strings.Split(authHeader, " ")      // 按空格分割
		if len(parts) == 2 && parts[0] == "Bearer" { // 检查格式
			token = parts[1] // 提取令牌
		}
	}

	if token == "" { // 如果 Authorization 头中没有
		token = r.Header.Get("X-Auth-Token") // 尝试 X-Auth-Token 头
	}

	if token == "" { // 如果仍然没有令牌
		http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized) // 返回 401 错误
		return                                                                            // 终止处理
	}

	session, valid := ws.validateSession(token) // 验证会话令牌
	if !valid {                                 // 如果会话无效
		http.Error(w, `{"error":"会话已过期","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized) // 返回 401 错误
		return                                                                               // 终止处理
	}

	// 定义请求数据结构体
	var data struct {
		ListenAddr         string `json:"listen_addr"`          // 服务器监听地址
		MaxWorkers         int    `json:"max_workers"`          // 最大工作协程数
		MaxConnPerIP       int    `json:"max_conn_per_ip"`      // 单 IP 最大连接数
		TCPKeepAlivePeriod int    `json:"tcp_keepalive_period"` // TCP Keepalive 周期（秒）
		SubmitToken        string `json:"submit_token"`         // 提交令牌（防重复提交）
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil { // 解析请求体中的 JSON 数据
		http.Error(w, `{"error":"请求数据格式错误"}`, http.StatusBadRequest) // 如果解析失败，返回 400 错误
		return                                                       // 终止处理
	}

	// 防重复提交
	if data.SubmitToken == "" { // 如果提交令牌为空
		http.Error(w, `{"error":"无效的提交请求"}`, http.StatusBadRequest) // 返回 400 错误
		return                                                      // 终止处理
	}

	if ws.isDuplicateSubmit(data.SubmitToken) { // 检查是否为重复提交
		http.Error(w, `{"error":"重复的提交请求"}`, http.StatusBadRequest) // 返回 400 错误
		return                                                      // 终止处理
	}

	ws.recordSubmitToken(data.SubmitToken) // 记录提交令牌

	// XSS 和 SQL 注入检测
	validator := NewInputValidator()            // 创建输入验证器
	if validator.ContainsXSS(data.ListenAddr) { // 检查监听地址是否包含 XSS 攻击代码
		http.Error(w, `{"error":"监听地址包含非法内容"}`, http.StatusBadRequest) // 返回 400 错误
		return                                                         // 终止处理
	}
	if validator.ContainsSQLInjection(data.ListenAddr) { // 检查监听地址是否包含 SQL 注入代码
		http.Error(w, `{"error":"监听地址包含非法内容"}`, http.StatusBadRequest) // 返回 400 错误
		return                                                         // 终止处理
	}

	// 验证配置参数的合法性
	validated, err := validator.ValidateConfig(
		data.ListenAddr,         // 监听地址
		data.MaxWorkers,         // 最大工作协程数
		data.MaxConnPerIP,       // 单 IP 最大连接数
		data.TCPKeepAlivePeriod, // TCP Keepalive 周期
	)

	if err != nil { // 如果验证失败
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest) // 返回 400 错误，包含具体错误信息
		return                                                                           // 终止处理
	}

	// 保存到数据库
	if ws.db != nil { // 如果数据库可用
		listenAddr, _ := validated["listen_addr"].(string)    // 提取监听地址
		ws.db.SetConfig("listen_addr", listenAddr, "服务器监听地址") // 保存监听地址配置

		maxWorkers, _ := validated["max_workers"].(int)                          // 提取最大工作协程数
		ws.db.SetConfig("max_workers", fmt.Sprintf("%d", maxWorkers), "最大工作协程数") // 保存工作协程数配置

		maxConnPerIP, _ := validated["max_conn_per_ip"].(int)                             // 提取单 IP 最大连接数
		ws.db.SetConfig("max_conn_per_ip", fmt.Sprintf("%d", maxConnPerIP), "单 IP 最大连接数") // 保存连接数配置

		tcpKeepAlivePeriod, _ := validated["tcp_keepalive_period"].(int)                                      // 提取 TCP Keepalive 周期
		ws.db.SetConfig("tcp_keepalive_period", fmt.Sprintf("%d", tcpKeepAlivePeriod), "TCP Keepalive 周期（秒）") // 保存 Keepalive 配置
	}

	log.Printf("管理员 [%s] 更新了服务器配置，IP=%s", session.Username, r.RemoteAddr) // 记录配置更新日志

	w.Header().Set("Content-Type", "application/json")                // 设置响应内容类型为 JSON
	fmt.Fprintf(w, `{"status":"success","message":"配置已保存，重启服务器后生效"}`) // 返回成功响应
}

// isDuplicateSubmit 检查是否为重复提交。
// 通过检查提交令牌是否已存在来判断。
//
// 参数:
//   - token: 提交令牌
//
// 返回:
//   - bool: 是否为重复提交（true=重复，false=非重复）
func (ws *WebServer) isDuplicateSubmit(token string) bool {
	ws.submitMu.RLock()         // 获取提交令牌映射的读锁
	defer ws.submitMu.RUnlock() // 函数返回时释放锁

	_, exists := ws.submitTokens[token] // 查找令牌是否存在
	return exists                       // 如果存在则返回 true（是重复提交）
}

// recordSubmitToken 记录提交令牌，用于防重复提交。
// 将令牌和时间戳存储到内存中，并清理过期的令牌（5分钟前）。
//
// 参数:
//   - token: 提交令牌
func (ws *WebServer) recordSubmitToken(token string) {
	ws.submitMu.Lock()         // 获取提交令牌映射的写锁
	defer ws.submitMu.Unlock() // 函数返回时释放锁

	// 记录当前提交令牌
	ws.submitTokens[token] = time.Now().UnixNano() // 存储令牌和当前时间戳（纳秒级）

	// 清理过期的令牌（5分钟前）
	expireTime := time.Now().Add(-5 * time.Minute).UnixNano() // 计算 5 分钟前的时间戳
	for t, ts := range ws.submitTokens {                      // 遍历所有存储的令牌
		if ts < expireTime { // 如果令牌的时间戳早于过期时间
			delete(ws.submitTokens, t) // 删除过期的令牌
		}
	}
}

// mapToJSON 将 map 转换为 JSON 字符串。
// 用于将配置数据序列化为 JSON 格式返回给前端。
// 如果转换失败，返回空对象 {}。
//
// 参数:
//   - m: 要转换的 map[string]interface{}
//
// 返回:
//   - string: JSON 字符串，如果转换失败则返回 "{}"
func mapToJSON(m map[string]interface{}) string {
	if len(m) == 0 { // 如果 map 为空
		return "{}" // 返回空对象 JSON
	}
	data, err := json.Marshal(m) // 将 map 序列化为 JSON 字节切片
	if err != nil {              // 如果序列化失败
		return "{}" // 返回空对象 JSON
	}
	return string(data) // 将字节切片转换为字符串并返回
}

// generateCSRFSecret 生成随机的 CSRF 密钥。
// 在服务器启动时调用一次，用于生成和验证 CSRF 令牌。
// 如果随机数生成失败，使用备用方案（基于时间戳）。
//
// 返回:
//   - []byte: 32字节的 CSRF 密钥
func generateCSRFSecret() []byte {
	secret := make([]byte, 32)                   // 创建 32 字节的切片
	if _, err := rand.Read(secret); err != nil { // 尝试使用加密安全的随机数生成器填充
		log.Printf("警告：随机数生成失败，使用备用 CSRF 密钥") // 记录警告日志
		// 备用方案：使用时间戳（安全性较低，但能保证功能）
		secret = []byte(fmt.Sprintf("csrf_secret_%d", time.Now().UnixNano())) // 基于纳秒时间戳生成密钥
	}
	return secret // 返回生成的 CSRF 密钥
}

// generateCSRFToken 生成 CSRF 令牌。
// 基于 CSRF 密钥、用户名和时间戳生成唯一的令牌。
// 用于防止跨站请求伪造攻击。
//
// 参数:
//   - username: 管理员用户名
//
// 返回:
//   - string: 64字符的十六进制 CSRF 令牌（SHA-256 哈希值）
func (ws *WebServer) generateCSRFToken(username string) string {
	h := sha256.New()                                         // 创建 SHA-256 哈希计算器
	h.Write(ws.csrfSecret)                                    // 写入 CSRF 密钥（秘密种子）
	h.Write([]byte(username))                                 // 写入用户名（绑定到特定用户）
	h.Write([]byte(fmt.Sprintf("%d", time.Now().UnixNano()))) // 写入时间戳（增加随机性，防止重放）

	return hex.EncodeToString(h.Sum(nil)) // 计算哈希并转换为十六进制字符串
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
	if token == "" || username == "" { // 如果令牌或用户名为空
		return false // 返回无效
	}

	// CSRF 令牌应该是 64 字符的十六进制字符串（SHA-256 哈希）
	if len(token) != 64 { // 检查长度是否为 64 字符
		return false // 长度不符，返回无效
	}

	// 检查是否只包含合法的十六进制字符（0-9, a-f, A-F）
	for _, c := range token { // 遍历令牌中的每个字符
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) { // 如果不是合法十六进制字符
			return false // 返回无效
		}
	}

	return true // 所有检查通过，返回有效
}

// setSecurityHeaders 设置安全相关的 HTTP 响应头。
// 包括 XSS 防护、点击劫持防护、MIME 类型嗅探防护等。
// 这是一个中间件函数，包裹在其他处理器外部。
func setSecurityHeaders(next http.Handler) http.Handler {
	// 返回一个 HTTP 处理器函数，包装原始处理器并添加安全响应头
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff") // 禁止浏览器进行 MIME 类型嗅探，防止 MIME 混淆攻击
		w.Header().Set("X-Frame-Options", "DENY")           // 禁止页面被嵌入到 iframe 中，防止点击劫持攻击
		w.Header().Set("X-XSS-Protection", "1; mode=block") // 启用浏览器的内置 XSS 过滤器，检测到 XSS 时阻止页面渲染
		// 内容安全策略（CSP）：限制资源加载来源，防止 XSS 和数据注入攻击
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")             // 引用策略：跨域时只发送来源信息，不发送完整 URL
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()") // 权限策略：禁用地理位置、麦克风、摄像头等敏感 API

		next.ServeHTTP(w, r) // 调用下一个处理器
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
	secure := strings.ToLower(getEnv("FORCE_COOKIE_SECURE", "false")) == "true" // 从环境变量读取是否强制 HTTPS

	http.SetCookie(w, &http.Cookie{
		Name:     name,                 // Cookie 名称
		Value:    value,                // Cookie 值
		Path:     "/",                  // Cookie 路径（整个网站可用）
		HttpOnly: true,                 // 禁止 JavaScript 访问，防止 XSS 窃取 Cookie
		Secure:   secure,               // 仅通过 HTTPS 传输（可通过环境变量 FORCE_COOKIE_SECURE 强制启用）
		SameSite: http.SameSiteLaxMode, // SameSite 策略：Lax 模式，防止 CSRF 攻击，允许顶级导航携带 Cookie
		MaxAge:   maxAge,               // 最大存活时间（秒），-1 表示立即过期（删除）
	})
}

// getCookie 从请求中获取指定名称的 Cookie 值。
// 如果 Cookie 不存在，返回空字符串。
//
// 参数:
//   - r: HTTP 请求对象
//   - name: Cookie 名称
//
// 返回:
//   - string: Cookie 值，如果不存在则返回空字符串
func getCookie(r *http.Request, name string) string {
	cookie, err := r.Cookie(name) // 尝试从请求中获取指定名称的 Cookie
	if err != nil {               // 如果 Cookie 不存在
		return "" // 返回空字符串
	}
	return cookie.Value // 返回 Cookie 的值
}

// getEnv 获取环境变量，如果未设置则返回默认值。
// 用于配置可选的行为，如强制 Cookie Secure 标志。
//
// 参数:
//   - key: 环境变量名
//   - defaultValue: 默认值（当环境变量未设置时使用）
//
// 返回:
//   - string: 环境变量的值，如果未设置则返回默认值
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key) // 从操作系统获取环境变量的值
	if value == "" {        // 如果环境变量未设置或为空
		return defaultValue // 返回默认值
	}
	return value // 返回环境变量的值
}
