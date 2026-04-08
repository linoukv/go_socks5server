// Package main SOCKS5 代理服务器的主程序入口。
// 负责初始化数据库、加载配置、启动 SOCKS5 服务和 Web 管理界面，
// 并处理优雅关闭信号。
package main

// 导入 log 包，提供日志记录功能
import (
	"log"
	// 导入 os 包，提供操作系统相关的功能
	"os"
	// 导入 os/signal 包，用于接收和处理系统信号
	"os/signal"
	// 导入 runtime 包，提供 Go 运行时相关信息和控制
	"runtime"
	// 导入 syscall 包，提供系统调用接口
	"syscall"
	// 导入 time 包，提供时间相关的测量和显示功能
	"time"
)

// dbManager 全局数据库管理器实例，供其他模块访问。
// 用于在 proxy.go 中持久化流量统计数据。
var dbManager *DatabaseManager

// main 程序入口函数，按顺序初始化各组件并启动服务。
// 执行流程：
// 1. 设置 CPU 核心数优化性能
// 2. 初始化 SQLite 数据库连接
// 3. 从数据库加载服务器配置
// 4. 创建 SOCKS5 服务器实例
// 5. 初始化用户认证系统
// 6. 启动 Web 管理界面（后台协程）
// 7. 启动 SOCKS5 代理服务（后台协程）
// 8. 等待终止信号并优雅关闭
func main() {
	// 获取当前系统的 CPU 核心数量
	numCPU := runtime.NumCPU()
	// 设置 Go 运行时使用的最大处理器核心数，以充分利用多核性能
	runtime.GOMAXPROCS(numCPU)
	// 记录 GOMAXPROCS 的设置值到日志
	log.Printf("GOMAXPROCS=%d", numCPU)

	// 从环境变量 SOCKS5_DB_PATH 获取数据库路径，如果未设置则使用默认值 "socks5.db"
	dbPath := getEnvOrDefault("SOCKS5_DB_PATH", "socks5.db")

	// 声明数据库管理器变量和错误变量
	var db *DatabaseManager
	var err error

	// 检查数据库路径是否非空，如果非空则尝试初始化数据库
	if dbPath != "" {
		// 创建新的数据库管理器实例
		db, err = NewDatabaseManager(dbPath)
		// 检查数据库初始化是否失败
		if err != nil {
			// 如果失败，记录错误日志并继续使用默认配置
			log.Printf("数据库初始化失败：%v，使用默认配置启动", err)
		} else {
			// 注册数据库关闭函数，确保程序退出时正确关闭数据库连接
			defer db.Close()
			// 记录数据库连接成功的日志
			log.Println("SQLite 数据库已连接")
			// 将数据库管理器赋值给全局变量，供其他模块使用
			dbManager = db
		}
	}

	// 从数据库加载服务器配置，如果数据库不存在则使用默认配置
	config := loadServerConfig(db)

	// 使用加载的配置创建新的 SOCKS5 服务器实例
	server := NewServer(config)

	// 声明认证器变量
	var auth *PasswordAuth
	// 检查配置中是否启用了用户管理功能
	if config.EnableUserManagement {
		// 创建新的密码认证器实例
		auth = NewPasswordAuth()
		// 将认证器赋值给配置的 Auth 字段
		config.Auth = auth

		// 检查数据库是否可用
		if db != nil {
			// 从数据库加载所有用户数据到认证器内存中
			if err := db.LoadAllUsersToAuth(auth); err != nil {
				// 如果加载失败，记录错误日志
				log.Printf("加载用户数据失败：%v", err)
			} else {
				// 如果加载成功，记录加载的用户数量
				log.Printf("已从数据库加载 %d 个用户到内存", len(auth.users))
			}
		}
	} else {
		// 如果未启用用户管理，使用无认证模式
		config.Auth = &NoAuth{}
		// 记录警告日志，提示无认证模式不安全
		log.Println("无认证模式（警告：不安全，仅用于测试）")
	}

	// 从环境变量获取 Web 管理界面的监听地址，默认为 ":8080"
	webAddr := getEnvOrDefault("SOCKS5_WEB_ADDR", ":8080")
	// 创建 Web 服务器实例，传入认证器、数据库、SOCKS5 服务器和监听地址
	webServer := NewWebServer(auth, db, server, webAddr)
	// 在后台 goroutine 中启动 Web 服务器
	go func() {
		// 启动 Web 服务器，如果出错则记录日志
		if err := webServer.Start(); err != nil {
			log.Printf("Web 服务错误：%v", err)
		}
	}()
	// 记录 Web 管理界面已启动的日志，包含监听地址
	log.Printf("Web 管理界面已启动在 http://%s", webAddr)
	// 记录服务器配置的摘要信息
	log.Printf("服务器配置：%+v", summarizeConfig(config))

	// 创建一个带缓冲的信号通道，用于接收系统信号
	sigCh := make(chan os.Signal, 1)
	// 注册信号通知，监听 SIGINT（Ctrl+C）和 SIGTERM（终止）信号
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// 在后台 goroutine 中启动 SOCKS5 服务器
	go func() {
		// 启动 SOCKS5 服务器，如果出错则记录致命错误并退出程序
		if err := server.Start(); err != nil {
			log.Fatalf("服务器错误：%v", err)
		}
	}()

	// 阻塞等待，直到接收到终止信号
	sig := <-sigCh
	// 记录收到信号的日志
	log.Printf("收到信号：%v，正在关闭服务器...", sig)

	// 优雅关闭 SOCKS5 服务器
	if err := server.Stop(); err != nil {
		// 如果关闭出错，记录错误日志
		log.Printf("停止服务器出错：%v", err)
	}

	// 检查 Web 服务器是否存在
	if webServer != nil {
		// 优雅关闭 Web 服务器
		if err := webServer.Stop(); err != nil {
			// 如果关闭出错，记录错误日志
			log.Printf("停止 Web 服务器出错：%v", err)
		}
	}
}

// loadServerConfig 从数据库加载服务器配置。
// 如果数据库不存在或没有配置记录，则使用默认配置。
//
// 参数:
//   - db: 数据库管理器实例
//
// 返回:
//   - *Config: 服务器配置
func loadServerConfig(db *DatabaseManager) *Config {
	// 获取默认配置作为基础配置
	config := DefaultConfig()

	// 检查数据库是否为空
	if db == nil {
		// 如果数据库不存在，记录日志并返回默认配置
		log.Println("数据库不存在，使用默认配置启动")
		return config
	}

	// 标记是否成功加载了任何配置项
	loaded := false

	// 尝试从数据库加载监听地址配置
	if addr, err := db.GetConfig("listen_addr"); err == nil && addr != "" {
		// 如果读取成功且非空，则更新配置中的监听地址
		config.ListenAddr = addr
		// 标记已加载配置
		loaded = true
	}

	// 尝试从数据库加载最大工作协程数配置
	if workers, err := db.GetIntConfig("max_workers"); err == nil && workers > 0 {
		// 如果读取成功且大于 0，则更新配置中的最大工作协程数
		config.MaxWorkers = int(workers)
		// 标记已加载配置
		loaded = true
	}

	// 尝试从数据库加载单 IP 最大连接数配置
	if maxConn, err := db.GetIntConfig("max_conn_per_ip"); err == nil && maxConn > 0 {
		// 如果读取成功且大于 0，则更新配置中的单 IP 最大连接数
		config.MaxConnPerIP = int(maxConn)
		// 标记已加载配置
		loaded = true
	}

	// 尝试从数据库加载 TCP Keepalive 周期配置
	if keepalive, err := db.GetIntConfig("tcp_keepalive_period"); err == nil && keepalive > 0 {
		// 如果读取成功且大于 0，则将秒转换为 Duration 类型并更新配置
		config.TCPKeepAlivePeriod = time.Duration(keepalive) * time.Second
		// 标记已加载配置
		loaded = true
	}

	// 尝试从数据库加载缓冲区池大小配置
	if bufferPool, err := db.GetIntConfig("buffer_pool_size"); err == nil && bufferPool > 0 {
		// 如果读取成功且大于 0，则创建新的接收和发送缓冲区池
		config.RecvBufferPool = NewBufferPool(int(bufferPool) * 1024)
		config.SendBufferPool = NewBufferPool(int(bufferPool) * 1024)
		// 标记已加载配置
		loaded = true
	}

	// 尝试从数据库加载用户管理开关配置
	if enableMgmt, err := db.GetConfig("enable_user_management"); err == nil && enableMgmt != "" {
		// 如果读取成功且非空，则根据字符串值设置布尔标志
		config.EnableUserManagement = (enableMgmt == "true" || enableMgmt == "1")
		// 标记已加载配置
		loaded = true
	}

	// 检查是否成功加载了任何配置
	if loaded {
		// 如果加载了配置，记录成功日志
		log.Println("已从数据库加载服务器配置")
	} else {
		// 如果没有加载到任何配置，记录使用默认配置的日志
		log.Println("数据库无配置记录，使用默认配置")
	}

	// 返回最终配置
	return config
}

// getEnvOrDefault 获取环境变量值，如果未设置则返回默认值。
//
// 参数:
//   - key: 环境变量名
//   - defaultValue: 默认值
//
// 返回:
//   - string: 环境变量值或默认值
func getEnvOrDefault(key, defaultValue string) string {
	// 尝试从环境变量中获取指定键的值
	if value := os.Getenv(key); value != "" {
		// 如果值非空，则返回该值
		return value
	}
	// 如果环境变量未设置或为空，则返回默认值
	return defaultValue
}

// summarizeConfig 将配置转换为可打印的映射格式。
// 用于日志输出时展示关键配置项。
func summarizeConfig(config *Config) map[string]interface{} {
	// 创建并返回一个包含关键配置项的映射
	return map[string]interface{}{
		// 监听地址
		"listen_addr": config.ListenAddr,
		// 最大工作协程数
		"max_workers": config.MaxWorkers,
		// 单 IP 最大连接数
		"max_conn_per_ip": config.MaxConnPerIP,
		// TCP Keepalive 周期（秒）
		"tcp_keepalive": config.TCPKeepAlivePeriod.Seconds(),
		// 是否启用用户管理
		"user_management": config.EnableUserManagement,
	}
}
