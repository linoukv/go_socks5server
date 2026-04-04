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

type RateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*rate.Limiter
	rate     rate.Limit
	burst    int
}

type AdminUser struct {
	Username            string `json:"username"`
	PasswordHash        string `json:"-"`
	Enabled             bool   `json:"enabled"`
	LastLogin           int64  `json:"last_login"`
	LoginCount          int    `json:"login_count"`
	CreateTime          int64  `json:"create_time"`
	LastPasswordChange  int64  `json:"last_password_change"`
	ForcePasswordChange bool   `json:"force_password_change"`
	LoginFailCount      int    `json:"-"`
	LastLoginFailTime   int64  `json:"-"`
	LockUntil           int64  `json:"-"`
}

type Session struct {
	Token        string `json:"token"`
	Username     string `json:"username"`
	ExpireTime   int64  `json:"expire_time"`
	ClientIP     string `json:"client_ip"`
	CreateTime   int64  `json:"create_time"`
	LastActivity int64  `json:"last_activity"`
}

func NewRateLimiter(requestsPerSecond float64, burst int) *RateLimiter {
	return &RateLimiter{
		visitors: make(map[string]*rate.Limiter),
		rate:     rate.Limit(requestsPerSecond),
		burst:    burst,
	}
}

func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.visitors[ip]
	if !exists {
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.visitors[ip] = limiter
	}

	return limiter
}

func (rl *RateLimiter) Allow(ip string) bool {
	return rl.getLimiter(ip).Allow()
}

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

type WebServer struct {
	auth         *PasswordAuth
	db           *DatabaseManager
	socksServer  *Server
	server       *http.Server
	adminUsers   map[string]*AdminUser
	adminMu      sync.RWMutex
	sessions     map[string]*Session
	sessionMu    sync.RWMutex
	captchaStore map[string]*CaptchaInfo
	captchaMu    sync.RWMutex
	submitTokens map[string]int64
	submitMu     sync.RWMutex
	csrfSecret   []byte
}

type CaptchaInfo struct {
	Code      string
	ExpireAt  int64
	FailCount int
}

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

	ws.initDefaultAdmin()

	if db != nil {
		if err := db.LoadAdminUsers(ws); err != nil {
			log.Printf("加载管理员用户失败：%v", err)
		} else {
			log.Printf("已从数据库加载管理员用户")
		}
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/api/users", ws.handleUsers)
	mux.HandleFunc("/api/stats", ws.handleStats)
	mux.HandleFunc("/api/traffic", ws.handleTraffic)
	mux.HandleFunc("/api/dashboard", ws.handleDashboard)
	mux.HandleFunc("/api/user-quota", ws.handleUserQuota)
	mux.HandleFunc("/api/quota/stats", ws.handleQuotaStats)
	mux.HandleFunc("/api/admin/batch-set-quota", ws.handleBatchSetQuota)
	mux.HandleFunc("/api/admin/login", ws.handleAdminLogin)
	mux.HandleFunc("/api/admin/logout", ws.handleAdminLogout)
	mux.HandleFunc("/api/admin/check", ws.handleAdminCheck)
	mux.HandleFunc("/api/admin/captcha", ws.handleCaptcha)
	mux.HandleFunc("/api/admin/change-password", ws.handleChangePassword)
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

	staticFS := getStaticFileSystem()
	if staticFS != nil {
		fs := http.FileServer(staticFS)
		mux.Handle("/static/", http.StripPrefix("/static/", fs))
	} else {
		fs := http.FileServer(http.Dir("static"))
		mux.Handle("/static/", http.StripPrefix("/static/", fs))
	}

	mux.HandleFunc("/", ws.handleIndex)

	mux.HandleFunc("/login.html", ws.handleLogin)

	mux.HandleFunc("/quota.html", ws.handleQuota)

	rateLimiter := NewRateLimiter(10.0, 20)

	ws.server = &http.Server{
		Addr:           listenAddr,
		Handler:        rateLimiter.Middleware(ws.authMiddleware(ws.corsMiddleware(setSecurityHeaders(mux)))),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	return ws
}

func (ws *WebServer) generateCaptcha() (string, image.Image) {
	chars := "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	code := ""
	for i := 0; i < 4; i++ {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		code += string(chars[n.Int64()])
	}

	width, height := 120, 50
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	for x := 0; x < width; x++ {
		for y := 0; y < height; y++ {
			img.Set(x, y, color.RGBA{255, 255, 255, 255})
		}
	}

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

	for i, ch := range code {
		r := uint8(50 + (i*40)%200)
		g := uint8(50 + (i*60)%200)
		b := uint8(100 + (i*30)%155)

		x := (i * 25) + 15
		y := 30

		drawChar(img, ch, x, y, color.RGBA{r, g, b, 255})
	}

	return code, img
}

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

func drawChar(img *image.RGBA, ch rune, x, y int, c color.RGBA) {
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

func sanitizeUsername(username string) string {
	if len(username) <= 2 {
		return "***"
	}
	return username[:1] + strings.Repeat("*", len(username)-2) + username[len(username)-1:]
}

func (ws *WebServer) Start() error {
	fmt.Printf("Web 管理界面已启动在 http://%s\n", ws.server.Addr)
	return ws.server.ListenAndServe()
}

func (ws *WebServer) Stop() error {
	return ws.server.Close()
}

func (ws *WebServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Auth-Token, X-Captcha-ID")
		w.Header().Set("Access-Control-Expose-Headers", "X-Captcha-ID, X-Auth-Token")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}

	htmlData := getIndexHTML()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'")
	w.Write([]byte(htmlData))
}

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

func (ws *WebServer) handleUsers(w http.ResponseWriter, r *http.Request) {
	if ws.auth == nil {
		log.Printf("错误：auth 为 nil")
		http.Error(w, "认证服务未初始化", http.StatusInternalServerError)
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

	switch r.Method {
	case "GET":
		users := ws.auth.ListUsers()
		if len(users) == 0 {
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
		var data struct {
			Username         string `json:"username"`
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
			http.Error(w, "请求数据格式错误", http.StatusBadRequest)
			return
		}

		if err := ws.auth.AddUser(data.Username, data.Password); err != nil {
			log.Printf("创建用户失败 [%s]: %v", data.Username, err)
			http.Error(w, fmt.Sprintf("用户创建失败：%v", err), http.StatusBadRequest)
			return
		}

		readLimit, _ := validateSpeedLimit(data.ReadLimit)
		writeLimit, _ := validateSpeedLimit(data.WriteLimit)
		if readLimit > 0 || writeLimit > 0 {
			ws.auth.SetUserSpeedLimit(data.Username, readLimit, writeLimit)
		}

		maxConn, _ := validateMaxConnections(data.MaxConn)
		ws.auth.SetUserMaxConnections(data.Username, maxConn)

		maxIPConn, _ := validateMaxConnections(data.MaxIPConnections)
		ws.auth.SetUserMaxIPConnections(data.Username, maxIPConn)

		if data.QuotaPeriod != "" {
			ws.auth.SetUserQuota(data.Username, data.QuotaPeriod, data.QuotaBytes)
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

func (ws *WebServer) handleTraffic(w http.ResponseWriter, r *http.Request) {
	traffic := []map[string]interface{}{}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(traffic)
}

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

func (ws *WebServer) initDefaultAdmin() {
	ws.adminMu.Lock()
	defer ws.adminMu.Unlock()

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

func hashPasswordForAdmin(password string) string {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("密码哈希失败：%v", err)
		return ""
	}
	return string(hashed)
}

func (ws *WebServer) verifyAdminPassword(username, password string) bool {
	ws.adminMu.RLock()
	defer ws.adminMu.RUnlock()

	admin, exists := ws.adminUsers[username]
	if !exists || !admin.Enabled {
		bcrypt.CompareHashAndPassword([]byte(""), []byte(password))
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password))
	return err == nil
}

func generateSessionToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (ws *WebServer) createSession(username, clientIP string) (string, error) {
	token, err := generateSessionToken()
	if err != nil {
		return "", err
	}

	session := &Session{
		Token:        token,
		Username:     username,
		ExpireTime:   time.Now().Add(24 * time.Hour).Unix(),
		ClientIP:     clientIP,
		CreateTime:   time.Now().Unix(),
		LastActivity: time.Now().Unix(),
	}

	ws.sessionMu.Lock()
	defer ws.sessionMu.Unlock()
	ws.sessions[token] = session

	ws.adminMu.Lock()
	if admin, exists := ws.adminUsers[username]; exists {
		admin.LastLogin = time.Now().Unix()
		admin.LoginCount++
	}
	ws.adminMu.Unlock()

	return token, nil
}

const (
	SessionTimeout       = 30 * 60
	SessionMaxExpireTime = 24 * 60 * 60
)

func (ws *WebServer) validateSession(token string) (*Session, bool) {
	ws.sessionMu.RLock()
	defer ws.sessionMu.RUnlock()

	session, exists := ws.sessions[token]
	if !exists {
		return nil, false
	}

	if time.Now().Unix() > session.ExpireTime {
		log.Printf("会话已过期：用户=%s", session.Username)
		return nil, false
	}

	now := time.Now().Unix()
	if now-session.LastActivity > SessionTimeout {
		log.Printf("会话超时（30 分钟未活动）：用户=%s, IP=%s", session.Username, session.ClientIP)
		go ws.invalidateSession(token)
		return nil, false
	}

	return session, true
}

func (ws *WebServer) invalidateSession(token string) {
	ws.sessionMu.Lock()
	defer ws.sessionMu.Unlock()
	delete(ws.sessions, token)
}

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

func (ws *WebServer) getAdminUser(username string) *AdminUser {
	ws.adminMu.RLock()
	defer ws.adminMu.RUnlock()

	if admin, exists := ws.adminUsers[username]; exists {
		return admin
	}
	return nil
}

func (ws *WebServer) isAccountLocked(username string) bool {
	ws.adminMu.RLock()
	defer ws.adminMu.RUnlock()

	admin, exists := ws.adminUsers[username]
	if !exists {
		return false
	}

	now := time.Now().Unix()

	if admin.LockUntil > now {
		return true
	}

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

func (ws *WebServer) recordLoginFailure(username string) {
	ws.adminMu.Lock()
	defer ws.adminMu.Unlock()

	admin, exists := ws.adminUsers[username]
	if !exists {
		return
	}

	now := time.Now().Unix()

	if admin.LastLoginFailTime > 0 && now-admin.LastLoginFailTime > LoginFailResetTime {
		admin.LoginFailCount = 0
	}

	admin.LoginFailCount++
	admin.LastLoginFailTime = now

	if admin.LoginFailCount >= MaxLoginFailCount {
		admin.LockUntil = now + LoginLockDuration
		log.Printf("账户已被锁定：用户名=%s, 锁定时间=%d分钟", username, LoginLockDuration/60)
	}
}

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

func (ws *WebServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicPaths := []string{"/", "/api/admin/login", "/api/admin/captcha", "/static/"}
		for _, path := range publicPaths {
			if strings.HasPrefix(r.URL.Path, path) {
				next.ServeHTTP(w, r)
				return
			}
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

		if token == "" {
			http.Error(w, `{"error":"未授权访问","code":"UNAUTHORIZED"}`, http.StatusUnauthorized)
			return
		}

		session, valid := ws.validateSession(token)
		if !valid {
			http.Error(w, `{"error":"会话已过期或无效","code":"SESSION_EXPIRED"}`, http.StatusUnauthorized)
			return
		}

		ws.refreshSessionActivity(token)

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
	MaxLoginFailCount  = 5
	LoginLockDuration  = 15 * 60
	LoginFailResetTime = 30 * 60
)

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

	if ws.isAccountLocked(data.Username) {
		log.Printf("管理员登录失败：账户已锁定，用户名=%s, IP=%s", data.Username, r.RemoteAddr)
		http.Error(w, `{"error":"账户已被锁定，请15分钟后再试","code":"ACCOUNT_LOCKED"}`, http.StatusTooManyRequests)
		return
	}

	if !ws.verifyCaptcha(data.CaptchaID, data.Captcha) {
		log.Printf("管理员登录失败：验证码错误，用户名=%s, IP=%s", data.Username, r.RemoteAddr)
		http.Error(w, `{"error":"验证码错误","code":"CAPTCHA_FAILED"}`, http.StatusBadRequest)
		return
	}

	if !ws.verifyAdminPassword(data.Username, data.Password) {
		log.Printf("管理员登录失败：用户名=%s, IP=%s", data.Username, r.RemoteAddr)
		ws.recordLoginFailure(data.Username)
		http.Error(w, `{"error":"用户名或密码错误","code":"AUTH_FAILED"}`, http.StatusUnauthorized)
		return
	}

	ws.clearLoginFailure(data.Username)

	admin := ws.getAdminUser(data.Username)
	if admin != nil && admin.ForcePasswordChange {
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

	ws.clearExistingSessions(data.Username)

	token, err := ws.createSession(data.Username, r.RemoteAddr)
	if err != nil {
		log.Printf("创建会话失败：%v", err)
		http.Error(w, `{"error":"服务器内部错误","code":"SERVER_ERROR"}`, http.StatusInternalServerError)
		return
	}

	log.Printf("管理员登录成功：用户名=%s, IP=%s", data.Username, r.RemoteAddr)

	csrfToken := ws.generateCSRFToken(data.Username)

	w.Header().Set("Content-Type", "application/json")

	ws.setSecureCookie(w, "session_token", token, 86400)
	ws.setSecureCookie(w, "csrf_token", csrfToken, 86400)

	fmt.Fprintf(w, `{"status":"success","token":"%s","username":"%s","csrf_token":"%s"}`, token, data.Username, csrfToken)
}

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

func (ws *WebServer) handleCaptcha(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, `{"error":"方法不允许"}`, http.StatusMethodNotAllowed)
		return
	}

	captchaID := fmt.Sprintf("%d", time.Now().UnixNano())
	code, img := ws.generateCaptcha()

	ws.captchaMu.Lock()
	if ws.captchaStore == nil {
		ws.captchaStore = make(map[string]*CaptchaInfo)
	}
	ws.captchaStore[captchaID] = &CaptchaInfo{
		Code:     code,
		ExpireAt: time.Now().Add(5 * time.Minute).Unix(),
	}
	ws.captchaMu.Unlock()

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("X-Captcha-ID", captchaID)
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	if err := png.Encode(w, img); err != nil {
		log.Printf("编码验证码图片失败：%v", err)
	}
}

func (ws *WebServer) verifyCaptcha(captchaID, code string) bool {
	ws.captchaMu.RLock()
	info, exists := ws.captchaStore[captchaID]
	ws.captchaMu.RUnlock()

	if !exists {
		return false
	}

	if time.Now().Unix() > info.ExpireAt {
		ws.captchaMu.Lock()
		delete(ws.captchaStore, captchaID)
		ws.captchaMu.Unlock()
		return false
	}

	if strings.EqualFold(info.Code, code) {
		ws.captchaMu.Lock()
		delete(ws.captchaStore, captchaID)
		ws.captchaMu.Unlock()
		return true
	}

	info.FailCount++
	if info.FailCount >= 5 {
		ws.captchaMu.Lock()
		delete(ws.captchaStore, captchaID)
		ws.captchaMu.Unlock()
	}

	return false
}

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

	if !ws.verifyAdminPassword(session.Username, data.OldPassword) {
		log.Printf("修改密码失败：旧密码错误，用户名=%s, IP=%s", session.Username, r.RemoteAddr)
		http.Error(w, `{"error":"原密码错误","code":"WRONG_PASSWORD"}`, http.StatusBadRequest)
		return
	}

	if len(data.NewPassword) < 6 {
		http.Error(w, `{"error":"密码长度至少为 6 位","code":"WEAK_PASSWORD"}`, http.StatusBadRequest)
		return
	}

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

	if data.SubmitToken == "" {
		http.Error(w, `{"error":"无效的提交请求"}`, http.StatusBadRequest)
		return
	}

	if ws.isDuplicateSubmit(data.SubmitToken) {
		http.Error(w, `{"error":"重复的提交请求"}`, http.StatusBadRequest)
		return
	}

	ws.recordSubmitToken(data.SubmitToken)

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

func (ws *WebServer) isDuplicateSubmit(token string) bool {
	ws.submitMu.RLock()
	defer ws.submitMu.RUnlock()

	_, exists := ws.submitTokens[token]
	return exists
}

func (ws *WebServer) recordSubmitToken(token string) {
	ws.submitMu.Lock()
	defer ws.submitMu.Unlock()

	ws.submitTokens[token] = time.Now().UnixNano()

	expireTime := time.Now().Add(-5 * time.Minute).UnixNano()
	for t, ts := range ws.submitTokens {
		if ts < expireTime {
			delete(ws.submitTokens, t)
		}
	}
}

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

func generateCSRFSecret() []byte {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Printf("警告：随机数生成失败，使用备用 CSRF 密钥")
		secret = []byte(fmt.Sprintf("csrf_secret_%d", time.Now().UnixNano()))
	}
	return secret
}

func (ws *WebServer) generateCSRFToken(username string) string {
	h := sha256.New()
	h.Write(ws.csrfSecret)
	h.Write([]byte(username))
	h.Write([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))

	return hex.EncodeToString(h.Sum(nil))
}

func (ws *WebServer) validateCSRFToken(token, username string) bool {
	if token == "" || username == "" {
		return false
	}

	if len(token) != 64 {
		return false
	}

	for _, c := range token {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}

	return true
}

func setSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")

		w.Header().Set("X-Frame-Options", "DENY")

		w.Header().Set("X-XSS-Protection", "1; mode=block")

		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")

		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		next.ServeHTTP(w, r)
	})
}

func (ws *WebServer) setSecureCookie(w http.ResponseWriter, name, value string, maxAge int) {
	secure := strings.ToLower(getEnv("FORCE_COOKIE_SECURE", "false")) == "true"

	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

func getCookie(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
