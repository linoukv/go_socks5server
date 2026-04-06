// Package main SOCKS5 代理服务器的主程序入口。
// 负责初始化数据库、加载配置、启动 SOCKS5 服务和 Web 管理界面，
// 并处理优雅关闭信号。
package main

import (
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

// dbManager 全局数据库管理器实例，供其他模块访问。
var dbManager *DatabaseManager

// main 程序入口函数，按顺序初始化各组件并启动服务。
func main() {
	// 设置最大 CPU 核心数
	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)
	log.Printf("GOMAXPROCS=%d", numCPU)

	// 从环境变量获取数据库路径，默认为 socks5.db
	dbPath := getEnvOrDefault("SOCKS5_DB_PATH", "socks5.db")

	var db *DatabaseManager
	var err error

	// 初始化数据库连接
	if dbPath != "" {
		db, err = NewDatabaseManager(dbPath)
		if err != nil {
			log.Printf("数据库初始化失败：%v，使用默认配置启动", err)
		} else {
			defer db.Close()
			log.Println("SQLite 数据库已连接")
			dbManager = db // 设置为全局实例
		}
	}

	// 从数据库加载服务器配置
	config := loadServerConfig(db)

	// 创建 SOCKS5 服务器实例
	server := NewServer(config)

	// 初始化认证器
	var auth *PasswordAuth
	if config.EnableUserManagement {
		auth = NewPasswordAuth()
		config.Auth = auth

		// 从数据库加载用户数据到内存
		if db != nil {
			if err := db.LoadAllUsersToAuth(auth); err != nil {
				log.Printf("加载用户数据失败：%v", err)
			} else {
				log.Printf("已从数据库加载 %d 个用户到内存", len(auth.users))
			}
		}
	} else {
		config.Auth = &NoAuth{}
		log.Println("无认证模式（警告：不安全，仅用于测试）")
	}

	// 启动 Web 管理界面
	webAddr := getEnvOrDefault("SOCKS5_WEB_ADDR", ":8080")
	webServer := NewWebServer(auth, db, server, webAddr)
	go func() {
		if err := webServer.Start(); err != nil {
			log.Printf("Web 服务错误：%v", err)
		}
	}()
	log.Printf("Web 管理界面已启动在 http://%s", webAddr)
	log.Printf("服务器配置：%+v", summarizeConfig(config))

	// 启动流量日志定时清理任务（每天凌晨 2 点清理 1 天前的数据）
	go func() {
		time.Sleep(10 * time.Second) // 等待 10 秒让系统稳定

		if db == nil {
			log.Println("数据库未初始化，跳过流量日志清理任务")
			return
		}

		log.Println("启动流量日志清理...")
		if err := db.CleanOldTrafficLogs(1); err != nil {
			log.Printf("流量日志清理失败：%v", err)
		} else {
			if count, err := db.GetTrafficLogsCount(); err == nil {
				log.Printf("当前流量日志总数：%d 条", count)
			}
		}

		// 循环执行定时清理
		for {
			now := time.Now()
			// 计算下一个凌晨 2 点的时间
			next := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, now.Location())

			if now.After(next) {
				next = next.Add(24 * time.Hour) // 如果已过 2 点，则设为明天
			}

			duration := next.Sub(now)
			log.Printf("下次流量日志清理时间：%s (等待 %v)", next.Format("2006-01-02 15:04:05"), duration.Round(time.Second))

			time.Sleep(duration)

			log.Println("执行定时流量日志清理...")
			if err := db.CleanOldTrafficLogs(1); err != nil {
				log.Printf("流量日志清理失败：%v", err)
			} else {
				if count, err := db.GetTrafficLogsCount(); err == nil {
					log.Printf("当前流量日志总数：%d 条", count)
				}
			}
		}
	}()
	log.Println("流量日志定时清理任务已启动（每天凌晨 2 点清理 30 天前的数据）")

	// 设置信号处理，支持优雅关闭
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// 在后台启动 SOCKS5 服务器
	go func() {
		if err := server.Start(); err != nil {
			log.Fatalf("服务器错误：%v", err)
		}
	}()

	// 等待终止信号
	sig := <-sigCh
	log.Printf("收到信号：%v，正在关闭服务器...", sig)

	// 优雅关闭服务
	if err := server.Stop(); err != nil {
		log.Printf("停止服务器出错：%v", err)
	}

	if webServer != nil {
		if err := webServer.Stop(); err != nil {
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
	config := DefaultConfig()

	if db == nil {
		log.Println("数据库不存在，使用默认配置启动")
		return config
	}

	loaded := false

	// 加载监听地址
	if addr, err := db.GetConfig("listen_addr"); err == nil && addr != "" {
		config.ListenAddr = addr
		loaded = true
	}

	// 加载最大工作协程数
	if workers, err := db.GetIntConfig("max_workers"); err == nil && workers > 0 {
		config.MaxWorkers = int(workers)
		loaded = true
	}

	// 加载单 IP 最大连接数
	if maxConn, err := db.GetIntConfig("max_conn_per_ip"); err == nil && maxConn > 0 {
		config.MaxConnPerIP = int(maxConn)
		loaded = true
	}

	// 加载上传速度限制
	if readLimit, err := db.GetInt64Config("read_speed_limit"); err == nil && readLimit > 0 {
		config.ReadSpeedLimit = readLimit
		loaded = true
	}

	// 加载下载速度限制
	if writeLimit, err := db.GetInt64Config("write_speed_limit"); err == nil && writeLimit > 0 {
		config.WriteSpeedLimit = writeLimit
		loaded = true
	}

	// 加载 TCP Keepalive 周期
	if keepalive, err := db.GetIntConfig("tcp_keepalive_period"); err == nil && keepalive > 0 {
		config.TCPKeepAlivePeriod = time.Duration(keepalive) * time.Second
		loaded = true
	}

	// 加载缓冲区池大小
	if bufferPool, err := db.GetIntConfig("buffer_pool_size"); err == nil && bufferPool > 0 {
		config.RecvBufferPool = NewBufferPool(int(bufferPool) * 1024)
		config.SendBufferPool = NewBufferPool(int(bufferPool) * 1024)
		loaded = true
	}

	// 加载用户管理开关
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

// getEnvOrDefault 获取环境变量值，如果未设置则返回默认值。
//
// 参数:
//   - key: 环境变量名
//   - defaultValue: 默认值
//
// 返回:
//   - string: 环境变量值或默认值
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// summarizeConfig 将配置转换为可打印的映射格式。
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
