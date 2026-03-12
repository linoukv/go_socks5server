package main

import (
	"flag"      // 命令行参数解析
	"fmt"       // 格式化输出
	"log"       // 日志记录
	"os"        // 操作系统功能
	"os/signal" // 信号处理
	"strings"   // 字符串处理
	"syscall"   // 系统调用
	"time"      // 时间处理
)

func main() {
	// 定义命令行参数
	var (
		listenAddr         = flag.String("l", "0.0.0.0:1080", "监听地址")         // 服务器监听地址，默认所有网卡 1080 端口
		username           = flag.String("u", "", "用户名（为空则不启用认证）")            // 认证用户名，空表示无认证
		password           = flag.String("p", "", "密码")                       // 认证密码
		workers            = flag.Int("w", 10000, "最大并发工作数")                  // 最大并发处理的 goroutine 数量
		maxConnIP          = flag.Int("c", 0, "每个 IP 最大连接数")                  // 限制单个 IP 的最大连接数，防止滥用
		udpTimeout         = flag.Int("t", 300, "UDP 关联超时（秒）")                // UDP 代理连接的超时时间
		readLimit          = flag.Int64("rl", 0, "读取速度限制（字节/秒），0 为不限速")       // 上传限速
		writeLimit         = flag.Int64("wl", 0, "写入速度限制（字节/秒），0 为不限速")       // 下载限速
		enableUserMgmt     = flag.Bool("user-mgmt", false, "启用多用户管理")         // 是否启用多用户管理
		userMaxConnections = flag.Int("umc", 0, "单用户最大连接数，0 为不限")             // 每个用户的最大连接数
		webAddr            = flag.String("web", ":8080", "Web 管理界面监听地址")      // Web 管理界面地址
		dbPath             = flag.String("db", "socks5.db", "SQLite 数据库文件路径") // 数据库路径
	)
	flag.Parse() // 解析命令行参数

	// 创建服务器配置对象
	config := &Config{
		ListenAddr:           *listenAddr,                              // 监听地址
		MaxWorkers:           *workers,                                 // 最大工作协程数
		MaxConnPerIP:         *maxConnIP,                               // 单 IP 最大连接数
		HandshakeTimeout:     10 * time.Second,                         // 握手超时时间 10 秒
		IdleTimeout:          300 * time.Second,                        // 空闲超时时间 300 秒
		UDPTimeout:           time.Duration(*udpTimeout) * time.Second, // UDP 超时时间
		ReadSpeedLimit:       *readLimit,                               // 上传限速
		WriteSpeedLimit:      *writeLimit,                              // 下载限速
		EnableUserManagement: *enableUserMgmt,                          // 是否启用多用户管理
	}

	// 配置认证方式：如果提供了用户名和密码则启用密码认证，否则使用无认证模式
	var auth *PasswordAuth
	if *username != "" && *password != "" {
		auth = NewPasswordAuth()           // 创建密码认证器
		auth.AddUser(*username, *password) // 添加用户

		// 如果启用了多用户管理，设置用户的连接数限制
		if *enableUserMgmt && *userMaxConnections > 0 {
			auth.SetUserMaxConnections(*username, *userMaxConnections)
			log.Printf("启用多用户管理，用户：%s，最大连接数：%d", *username, *userMaxConnections)
		}

		config.Auth = auth // 设置认证配置
		log.Printf("启用用户名/密码认证，用户名：%s", *username)
	} else {
		config.Auth = &NoAuth{} // 使用无认证
		log.Println("启用无认证模式（警告：不安全，仅用于测试）")
	}

	// 创建 SOCKS5 服务器实例
	server := NewServer(config)

	// 初始化数据库（如果指定了数据库路径）
	var db *DatabaseManager
	if *dbPath != "" {
		var err error
		db, err = NewDatabaseManager(*dbPath)
		if err != nil {
			log.Printf("数据库初始化失败：%v", err)
		} else {
			defer db.Close() // 确保程序退出时关闭数据库连接
			log.Println("SQLite 数据库已连接")
		}
	}

	// 启动 Web 管理界面
	var webServer *WebServer
	if *webAddr != "" {
		webServer = NewWebServer(auth, db, *webAddr)
		go func() {
			if err := webServer.Start(); err != nil {
				log.Printf("Web 服务错误：%v", err)
			}
		}()
		log.Printf("Web 管理界面已启动在 http://%s", *webAddr)
	}

	// 创建信号通道，用于接收系统信号（如 Ctrl+C）
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM) // 监听中断和终止信号

	// 在后台 goroutine 中启动服务器
	go func() {
		if err := server.Start(); err != nil {
			log.Fatalf("服务器错误：%v", err)
		}
	}()

	// 阻塞等待信号
	sig := <-sigCh
	log.Printf("收到信号：%v，正在关闭服务器...", sig)

	// 优雅关闭服务器
	if err := server.Stop(); err != nil {
		log.Printf("停止服务器出错：%v", err)
	}

	// 关闭 Web 服务器
	if webServer != nil {
		if err := webServer.Stop(); err != nil {
			log.Printf("停止 Web 服务器出错：%v", err)
		}
	}

	// 数据库连接已通过 defer 关闭
}

// parseUsers 解析用户列表字符串，格式：user1:pass1,user2:pass2
// 将多个用户信息解析为 map[用户名]密码 的形式
func parseUsers(usersStr string) map[string]string {
	users := make(map[string]string) // 创建用户映射表
	if usersStr == "" {
		return users // 空字符串返回空 map
	}

	// 按逗号分割多个用户
	pairs := strings.Split(usersStr, ",")
	for _, pair := range pairs {
		// 按冒号分割用户名和密码，SplitN 限制最多分割 2 部分
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) == 2 {
			// 去除前后空格后存入 map
			users[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return users
}

// printUsage 打印程序使用说明和示例
func printUsage() {
	fmt.Println(`SOCKS5 Server - 高性能 SOCKS5 代理服务器

用法:
  socks5-server [选项]

选项:
  -l string
        监听地址 (默认 "0.0.0.0:1080")
  -u string
        用户名（为空则不启用认证）
  -p string
        密码
  -w int
        最大并发工作数 (默认 10000)
  -c int
        每个 IP 最大连接数 (默认 100)
  -t int
        UDP 关联超时（秒）(默认 300)
  -rl int
        读取速度限制（字节/秒），0 为不限速 (默认 0)
  -wl int
        写入速度限制（字节/秒），0 为不限速 (默认 0)

示例:
  # 无认证模式（仅测试使用）
  socks5-server

  # 带认证模式
  socks5-server -u admin -p password

  # 自定义监听地址
  socks5-server -l 127.0.0.1:1080 -u admin -p password

  # 限制上传速度为 1MB/s，下载速度为 2MB/s
  socks5-server -rl 1048576 -wl 2097152

  # 组合使用：认证 + 限速
  socks5-server -u admin -p password -rl 524288 -wl 1048576`)
}
