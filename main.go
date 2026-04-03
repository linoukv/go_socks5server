// =============================================================================
// 文件名：main.go
// 描述：SOCKS5 代理服务器 - 程序入口文件
// 功能：程序启动、初始化、配置加载、优雅关闭
// =============================================================================

package main

import (
	"log"       // 日志记录包
	"os"        // 操作系统接口包
	"os/signal" // 信号处理包
	"runtime"   // Go 运行时信息包
	"syscall"   // 系统调用包（用于接收系统信号）
	"time"      // 时间处理包
)

// dbManager 全局数据库管理器指针
// 用途：在服务器运行期间持久化用户数据和流量统计
// 注意：这是一个全局变量，在 userDataPersister 和 persistUsers 函数中使用
var dbManager *DatabaseManager

// main 程序主入口函数
// 执行流程：
// 1. 设置 CPU 核心数优化（GOMAXPROCS）
// 2. 初始化 SQLite 数据库
// 3. 从数据库加载服务器配置
// 4. 创建 SOCKS5 服务器实例
// 5. 配置认证方式（无认证/密码认证）
// 6. 启动 Web 管理界面
// 7. 启动 SOCKS5 服务器
// 8. 等待系统信号（SIGINT/SIGTERM）实现优雅关闭
func main() {
	// =========================================================================
	// 步骤 1: CPU 性能优化 - 设置 GOMAXPROCS 为物理 CPU 核心数
	// 目的：最大化利用多核 CPU，提升并发处理能力
	// 说明：Go 默认会根据系统情况设置，但显式设置可以确保最优性能
	// =========================================================================
	numCPU := runtime.NumCPU() // 获取逻辑 CPU 核心数
	runtime.GOMAXPROCS(numCPU) // 设置最大并行工作线程数
	log.Printf("万兆性能优化版 - GOMAXPROCS=%d (CPU 核心数)", numCPU)
	// =========================================================================
	// 步骤 2: 获取数据库路径（支持环境变量配置）
	// 优先级：SOCKS5_DB_PATH 环境变量 > 默认值 "socks5.db"
	// =========================================================================
	dbPath := getEnvOrDefault("SOCKS5_DB_PATH", "socks5.db")

	// =========================================================================
	// 步骤 3: 初始化 SQLite 数据库管理器
	// 如果数据库初始化失败，服务器仍可使用（但不支持持久化）
	// =========================================================================
	var db *DatabaseManager
	var err error

	if dbPath != "" {
		// 创建新的数据库管理器（会自动创建表结构）
		db, err = NewDatabaseManager(dbPath)
		if err != nil {
			// 数据库初始化失败时记录错误，但继续启动服务器
			log.Printf("数据库初始化失败：%v，使用默认配置启动", err)
		} else {
			defer db.Close() // 确保程序退出时关闭数据库连接
			log.Println("SQLite 数据库已连接")
			// 保存到全局变量，供后续持久化使用
			dbManager = db
		}
	}

	// =========================================================================
	// 步骤 4: 从数据库加载服务器配置
	// 如果数据库不存在或无配置记录，使用默认配置
	// =========================================================================
	config := loadServerConfig(db)

	// =========================================================================
	// 步骤 5: 创建 SOCKS5 服务器实例
	// 使用加载的配置初始化服务器对象
	// =========================================================================
	server := NewServer(config)

	// =========================================================================
	// 步骤 6: 配置认证方式
	// 根据配置启用用户管理（密码认证）或无认证模式
	// =========================================================================
	var auth *PasswordAuth
	if config.EnableUserManagement {
		// 启用密码认证模式
		auth = NewPasswordAuth() // 创建密码认证器
		config.Auth = auth       // 设置到服务器配置

		// 从数据库加载所有用户到内存中的认证器
		if db != nil {
			if err := db.LoadAllUsersToAuth(auth); err != nil {
				log.Printf("加载用户数据失败：%v", err)
			} else {
				log.Printf("已从数据库加载 %d 个用户到内存", len(auth.users))
			}
		}
	} else {
		// 无认证模式（警告：不安全，仅用于测试环境）
		config.Auth = &NoAuth{}
		log.Println("无认证模式（警告：不安全，仅用于测试）")
	}

	// =========================================================================
	// 步骤 7: 启动 Web 管理界面
	// Web 服务在独立 goroutine 中运行，不阻塞主程序
	// 必须启动，用于后续配置服务器和管理用户
	// =========================================================================
	webAddr := getEnvOrDefault("SOCKS5_WEB_ADDR", ":8080") // Web 监听地址
	webServer := NewWebServer(auth, db, server, webAddr)   // 创建 Web 服务器
	go func() {
		if err := webServer.Start(); err != nil {
			log.Printf("Web 服务错误：%v", err)
		}
	}()
	log.Printf("Web 管理界面已启动在 http://%s", webAddr)
	log.Printf("服务器配置：%+v", summarizeConfig(config)) // 打印配置摘要

	// =========================================================================
	// 步骤 7.1: 启动流量日志定时清理任务
	// 每天凌晨 2 点自动清理 1 天前的流量日志，避免数据库无限膨胀
	// =========================================================================
	go func() {
		// 等待系统启动完成
		time.Sleep(10 * time.Second)

		// 检查数据库是否初始化
		if db == nil {
			log.Println("数据库未初始化，跳过流量日志清理任务")
			return
		}

		// 首次启动时执行一次清理
		log.Println("启动流量日志清理...")
		if err := db.CleanOldTrafficLogs(1); err != nil {
			log.Printf("流量日志清理失败：%v", err)
		} else {
			// 显示当前日志数量
			if count, err := db.GetTrafficLogsCount(); err == nil {
				log.Printf("当前流量日志总数：%d 条", count)
			}
		}

		// 创建定时器：每天凌晨 2 点执行
		for {
			now := time.Now()
			next := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, now.Location())

			// 如果今天的 2 点已过，设置为明天 2 点
			if now.After(next) {
				next = next.Add(24 * time.Hour)
			}

			duration := next.Sub(now)
			log.Printf("下次流量日志清理时间：%s (等待 %v)", next.Format("2006-01-02 15:04:05"), duration.Round(time.Second))

			time.Sleep(duration)

			// 执行清理
			log.Println("执行定时流量日志清理...")
			if err := db.CleanOldTrafficLogs(30); err != nil {
				log.Printf("流量日志清理失败：%v", err)
			} else {
				// 显示当前日志数量
				if count, err := db.GetTrafficLogsCount(); err == nil {
					log.Printf("当前流量日志总数：%d 条", count)
				}
			}
		}
	}()
	log.Println("流量日志定时清理任务已启动（每天凌晨 2 点清理 30 天前的数据）")

	// =========================================================================
	// 步骤 8: 创建系统信号通道
	// 监听 SIGINT (Ctrl+C) 和 SIGTERM (终止信号)
	// =========================================================================
	sigCh := make(chan os.Signal, 1) // 带缓冲的信号通道
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// =========================================================================
	// 步骤 9: 在独立 goroutine 中启动 SOCKS5 服务器
	// 非阻塞启动，允许后续代码继续执行
	// =========================================================================
	go func() {
		if err := server.Start(); err != nil {
			log.Fatalf("服务器错误：%v", err) // 启动失败则直接退出
		}
	}()

	// =========================================================================
	// 步骤 10: 阻塞等待系统信号
	// 程序会在这里暂停，直到收到 SIGINT 或 SIGTERM 信号
	// =========================================================================
	sig := <-sigCh
	log.Printf("收到信号：%v，正在关闭服务器...", sig)

	// =========================================================================
	// 步骤 11: 优雅关闭服务器
	// 按顺序关闭 SOCKS5 服务器和 Web 服务器，确保资源正确释放
	// =========================================================================
	if err := server.Stop(); err != nil {
		log.Printf("停止服务器出错：%v", err)
	}

	if webServer != nil {
		if err := webServer.Stop(); err != nil {
			log.Printf("停止 Web 服务器出错：%v", err)
		}
	}
}

// loadServerConfig 从数据库加载服务器配置
func loadServerConfig(db *DatabaseManager) *Config {
	// 默认配置
	config := DefaultConfig()

	// 如果数据库不存在，返回默认配置
	if db == nil {
		log.Println("数据库不存在，使用默认配置启动")
		return config
	}

	// 尝试从数据库加载配置
	loaded := false

	// 加载监听地址
	if addr, err := db.GetConfig("listen_addr"); err == nil && addr != "" {
		config.ListenAddr = addr
		loaded = true
	}

	// 加载工作协程数
	if workers, err := db.GetIntConfig("max_workers"); err == nil && workers > 0 {
		config.MaxWorkers = int(workers)
		loaded = true
	}

	// 加载单 IP 最大连接数
	if maxConn, err := db.GetIntConfig("max_conn_per_ip"); err == nil && maxConn > 0 {
		config.MaxConnPerIP = int(maxConn)
		loaded = true
	}

	// 加载上传限速
	if readLimit, err := db.GetInt64Config("read_speed_limit"); err == nil && readLimit > 0 {
		config.ReadSpeedLimit = readLimit
		loaded = true
	}

	// 加载下载限速
	if writeLimit, err := db.GetInt64Config("write_speed_limit"); err == nil && writeLimit > 0 {
		config.WriteSpeedLimit = writeLimit
		loaded = true
	}

	// 加载 TCP Keepalive 周期
	if keepalive, err := db.GetIntConfig("tcp_keepalive_period"); err == nil && keepalive > 0 {
		config.TCPKeepAlivePeriod = time.Duration(keepalive) * time.Second
		loaded = true
	}

	// 加载缓冲池大小
	if bufferPool, err := db.GetIntConfig("buffer_pool_size"); err == nil && bufferPool > 0 {
		config.RecvBufferPool = NewBufferPool(int(bufferPool) * 1024)
		config.SendBufferPool = NewBufferPool(int(bufferPool) * 1024)
		loaded = true
	}

	// 加载是否启用多用户管理
	if enableMgmt, err := db.GetConfig("enable_user_management"); err == nil && enableMgmt != "" {
		config.EnableUserManagement = (enableMgmt == "true" || enableMgmt == "1")
		loaded = true
	}

	if loaded {
		log.Println("已从数据库加载服务器配置")
	} else {
		log.Println("数据库无配置记录，使用默认配置")
	}

	return config
}

// getEnvOrDefault 获取环境变量或返回默认值
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// summarizeConfig 返回配置摘要（用于日志）
func summarizeConfig(config *Config) map[string]interface{} {
	return map[string]interface{}{
		"listen_addr":       config.ListenAddr,
		"max_workers":       config.MaxWorkers,
		"max_conn_per_ip":   config.MaxConnPerIP,
		"read_speed_limit":  config.ReadSpeedLimit,
		"write_speed_limit": config.WriteSpeedLimit,
		"tcp_keepalive":     config.TCPKeepAlivePeriod.Seconds(),
		"user_management":   config.EnableUserManagement,
	}
}
