package main

import (
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

var dbManager *DatabaseManager

func main() {
	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)
	log.Printf("GOMAXPROCS=%d", numCPU)

	dbPath := getEnvOrDefault("SOCKS5_DB_PATH", "socks5.db")

	var db *DatabaseManager
	var err error

	if dbPath != "" {
		db, err = NewDatabaseManager(dbPath)
		if err != nil {
			log.Printf("数据库初始化失败：%v，使用默认配置启动", err)
		} else {
			defer db.Close()
			log.Println("SQLite 数据库已连接")
			dbManager = db
		}
	}

	config := loadServerConfig(db)

	server := NewServer(config)

	var auth *PasswordAuth
	if config.EnableUserManagement {
		auth = NewPasswordAuth()
		config.Auth = auth

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

	webAddr := getEnvOrDefault("SOCKS5_WEB_ADDR", ":8080")
	webServer := NewWebServer(auth, db, server, webAddr)
	go func() {
		if err := webServer.Start(); err != nil {
			log.Printf("Web 服务错误：%v", err)
		}
	}()
	log.Printf("Web 管理界面已启动在 http://%s", webAddr)
	log.Printf("服务器配置：%+v", summarizeConfig(config))

	go func() {
		time.Sleep(10 * time.Second)

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

		for {
			now := time.Now()
			next := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, now.Location())

			if now.After(next) {
				next = next.Add(24 * time.Hour)
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

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := server.Start(); err != nil {
			log.Fatalf("服务器错误：%v", err)
		}
	}()

	sig := <-sigCh
	log.Printf("收到信号：%v，正在关闭服务器...", sig)

	if err := server.Stop(); err != nil {
		log.Printf("停止服务器出错：%v", err)
	}

	if webServer != nil {
		if err := webServer.Stop(); err != nil {
			log.Printf("停止 Web 服务器出错：%v", err)
		}
	}
}

func loadServerConfig(db *DatabaseManager) *Config {
	config := DefaultConfig()

	if db == nil {
		log.Println("数据库不存在，使用默认配置启动")
		return config
	}

	loaded := false

	if addr, err := db.GetConfig("listen_addr"); err == nil && addr != "" {
		config.ListenAddr = addr
		loaded = true
	}

	if workers, err := db.GetIntConfig("max_workers"); err == nil && workers > 0 {
		config.MaxWorkers = int(workers)
		loaded = true
	}

	if maxConn, err := db.GetIntConfig("max_conn_per_ip"); err == nil && maxConn > 0 {
		config.MaxConnPerIP = int(maxConn)
		loaded = true
	}

	if readLimit, err := db.GetInt64Config("read_speed_limit"); err == nil && readLimit > 0 {
		config.ReadSpeedLimit = readLimit
		loaded = true
	}

	if writeLimit, err := db.GetInt64Config("write_speed_limit"); err == nil && writeLimit > 0 {
		config.WriteSpeedLimit = writeLimit
		loaded = true
	}

	if keepalive, err := db.GetIntConfig("tcp_keepalive_period"); err == nil && keepalive > 0 {
		config.TCPKeepAlivePeriod = time.Duration(keepalive) * time.Second
		loaded = true
	}

	if bufferPool, err := db.GetIntConfig("buffer_pool_size"); err == nil && bufferPool > 0 {
		config.RecvBufferPool = NewBufferPool(int(bufferPool) * 1024)
		config.SendBufferPool = NewBufferPool(int(bufferPool) * 1024)
		loaded = true
	}

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

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

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
