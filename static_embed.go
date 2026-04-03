// =============================================================================
// 文件名：static_embed.go
// 描述：嵌入静态资源文件到可执行文件中
// 功能：使用 Go 1.16+ 的 embed 特性，将前端静态文件（HTML/CSS/JS）打包到二进制中
// 优势：
//   - 无需单独部署静态文件
//   - 防止文件丢失或被篡改
//   - 简化部署流程（单个二进制文件即可运行）
// =============================================================================

package main

import (
	"embed"    // Go embed 包（编译时嵌入文件）
	"io/fs"    // 文件系统接口包
	"net/http" // HTTP 文件服务包
)

// =============================================================================
// embeddedFiles - 嵌入的文件系统对象
//
// go:embed 指令说明：
// - 语法：//go:embed <模式>
// - 作用：编译时将匹配的文件嵌入到变量中
// - 支持的模式：
//   - static/* - 嵌入 static 目录下的所有文件
//   - *.txt    - 嵌入所有 txt 文件
//   - a/b/c    - 嵌入特定路径的文件
//
// 嵌入后的访问方式：
// - embeddedFiles.ReadFile("static/index.html") - 读取文件内容
// - fs.Sub(embeddedFiles, "static") - 获取子目录的文件系统
// =============================================================================
//
//go:embed static/*
var embeddedFiles embed.FS

// =============================================================================
// getStaticFileSystem 返回嵌入的静态文件系统
//
// 用途：为 HTTP 服务器提供静态文件服务
// 参数：无
// 返回：http.FileSystem - 实现 http.FileSystem 接口的对象
//
// 工作原理：
// 1. 使用 fs.Sub 获取 static 子目录的文件系统视图
// 2. 使用 http.FS 将其转换为 http.FileSystem 接口
// 3. 传递给 http.FileServer 处理静态文件请求
//
// 使用示例：
//
//	fs := getStaticFileSystem()
//	if fs != nil {
//	    mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(fs)))
//	}
//
// =============================================================================
func getStaticFileSystem() http.FileSystem {
	// 从嵌入的文件系统中提取 static 子目录
	// fs.Sub 返回一个只包含指定目录的文件系统视图
	subFS, err := fs.Sub(embeddedFiles, "static")
	if err != nil {
		// 如果提取失败（目录不存在），返回 nil
		return nil
	}
	// 将 fs.FS 转换为 http.FileSystem 接口
	// http.FS 是适配器，使得 fs.FS 可以实现 http.FileSystem 接口
	return http.FS(subFS)
}

// =============================================================================
// getIndexHTML 返回嵌入的 index.html 文件内容
//
// 用途：在首页路由（/）时返回 HTML 页面
// 参数：无
// 返回：string - HTML 文件内容（UTF-8 编码）
//
// 错误处理：
// - 如果文件不存在或读取失败，返回友好的错误提示页面
// - 避免直接暴露错误信息给用户
//
// 使用示例：
//
//	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
//	    w.Header().Set("Content-Type", "text/html; charset=utf-8")
//	    w.Write([]byte(getIndexHTML()))
//	})
//
// =============================================================================
func getIndexHTML() string {
	// 从嵌入文件系统中读取 index.html 文件
	// ReadFile 返回 []byte 和 error
	data, err := embeddedFiles.ReadFile("static/index.html")
	if err != nil {
		// 读取失败时返回友好的错误提示页面
		// 而不是暴露内部错误信息
		return "<html><body>页面加载失败</body></html>"
	}
	// 将字节数组转换为字符串返回
	return string(data)
}

// =============================================================================
// getAppJS 返回嵌入的 app.js 文件内容
//
// 用途：为前端 JavaScript 代码提供 HTTP 服务
// 参数：无
// 返回：string - JavaScript 文件内容
//
// 注意：
// - 如果文件不存在，返回空字符串（由调用方处理）
// - JS 文件通常较大，但不需要错误处理（已在构建时验证）
//
// 使用示例：
//
//	// 在 web_server.go 的路由中
//	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
//	    w.Header().Set("Content-Type", "application/javascript")
//	    w.Write([]byte(getAppJS()))
//	})
//
// =============================================================================
func getAppJS() string {
	// 从嵌入文件系统中读取 app.js 文件
	data, err := embeddedFiles.ReadFile("static/app.js")
	if err != nil {
		// 读取失败返回空字符串
		// 前端会收到空的 JS 响应（浏览器控制台会报错）
		return ""
	}
	return string(data)
}

// =============================================================================
// getLoginHTML 返回嵌入的 login.html 文件内容
//
// 用途：为管理员登录页面提供 HTTP 服务
// 参数：无
// 返回：string - HTML 文件内容
//
// 注意：
// - 如果文件不存在，返回空字符串（由调用方处理）
//
// 使用示例：
//
//	// 在 web_server.go 的路由中
//	mux.HandleFunc("/login.html", func(w http.ResponseWriter, r *http.Request) {
//	    w.Header().Set("Content-Type", "text/html; charset=utf-8")
//	    w.Write([]byte(getLoginHTML()))
//	})
//
// =============================================================================
func getLoginHTML() string {
	// 从嵌入文件系统中读取 login.html 文件
	data, err := embeddedFiles.ReadFile("static/login.html")
	if err != nil {
		// 读取失败返回空字符串
		return ""
	}
	return string(data)
}

// =============================================================================
// getQuotaHTML 返回嵌入的 quota.html 文件内容
//
// 用途：为配额管理页面提供 HTTP 服务
// 参数：无
// 返回：string - HTML 文件内容
//
// 注意：
// - 如果文件不存在，返回空字符串（由调用方处理）
//
// 使用示例：
//
//	// 在 web_server.go 的路由中
//	mux.HandleFunc("/quota.html", func(w http.ResponseWriter, r *http.Request) {
//	    w.Header().Set("Content-Type", "text/html; charset=utf-8")
//	    w.Write([]byte(getQuotaHTML()))
//	})
//
// =============================================================================
func getQuotaHTML() string {
	// 从嵌入文件系统中读取 quota.html 文件
	data, err := embeddedFiles.ReadFile("static/quota.html")
	if err != nil {
		// 读取失败返回空字符串
		return ""
	}
	return string(data)
}
