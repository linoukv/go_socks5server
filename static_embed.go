// Package main 实现 SOCKS5 代理服务器的静态资源嵌入模块。
// 使用 Go 1.16+ 的 embed 功能将前端静态文件（HTML、CSS、JS）编译到二进制文件中，
// 实现单文件部署，无需额外分发静态资源目录。
package main

// 导入 embed 包，提供编译时嵌入文件的功能
import (
	"embed"
	// 导入 io/fs 包，提供文件系统相关的接口和操作
	"io/fs"
	// 导入 net/http 包，提供 HTTP 服务器和客户端功能
	"net/http"
)

// embeddedFiles 嵌入的文件系统变量，包含 static 目录下的所有文件。
// 通过 //go:embed 指令在编译时自动打包静态资源。
//
// 声明一个 embed.FS 类型的变量，用于存储嵌入的静态文件系统
//
//go:embed static/*
var embeddedFiles embed.FS

// getStaticFileSystem 获取嵌入的静态文件系统，用于 HTTP 文件服务。
// 将 embed.FS 转换为 http.FileSystem 接口，供 http.FileServer 使用。
//
// 返回:
//   - http.FileSystem: 可用于 HTTP 服务的文件系统接口，错误时返回 nil
func getStaticFileSystem() http.FileSystem {
	// 从嵌入的文件系统中提取 "static" 子目录，创建一个新的文件系统视图
	subFS, err := fs.Sub(embeddedFiles, "static")
	// 检查提取子目录是否出错
	if err != nil {
		// 如果出错，返回 nil 表示无法获取文件系统
		return nil
	}
	// 将 fs.FS 转换为 http.FileSystem 类型并返回，使其可以被 HTTP 服务器使用
	return http.FS(subFS)
}

// getIndexHTML 读取并返回 index.html 页面的内容。
// 用于 Web 管理界面的主页面展示。
//
// 返回:
//   - string: HTML 页面内容，读取失败时返回错误提示页面
func getIndexHTML() string {
	// 从嵌入的文件系统中读取 "static/index.html" 文件的内容
	data, err := embeddedFiles.ReadFile("static/index.html")
	// 检查读取文件是否出错
	if err != nil {
		// 如果读取失败，返回一个简单的错误提示 HTML 页面
		return "<html><body>页面加载失败</body></html>"
	}
	// 将读取的字节切片转换为字符串并返回
	return string(data)
}

// getAppJS 读取并返回 app.js 前端应用脚本的内容。
// 用于 Web 管理界面的 JavaScript 逻辑。
//
// 返回:
//   - string: JavaScript 代码内容，读取失败时返回空字符串
func getAppJS() string {
	// 从嵌入的文件系统中读取 "static/app.js" 文件的内容
	data, err := embeddedFiles.ReadFile("static/app.js")
	// 检查读取文件是否出错
	if err != nil {
		// 如果读取失败，返回空字符串
		return ""
	}
	// 将读取的字节切片转换为字符串并返回
	return string(data)
}

// getLoginHTML 读取并返回 login.html 登录页面的内容。
// 用于用户认证界面。
//
// 返回:
//   - string: 登录页面 HTML 内容，读取失败时返回空字符串
func getLoginHTML() string {
	// 从嵌入的文件系统中读取 "static/login.html" 文件的内容
	data, err := embeddedFiles.ReadFile("static/login.html")
	// 检查读取文件是否出错
	if err != nil {
		// 如果读取失败，返回空字符串
		return ""
	}
	// 将读取的字节切片转换为字符串并返回
	return string(data)
}

// getQuotaHTML 读取并返回 quota.html 配额管理页面的内容。
// 用于流量配额管理界面（当前未使用）。
//
// 返回:
//   - string: 配额页面 HTML 内容，读取失败时返回空字符串
func getQuotaHTML() string {
	// 从嵌入的文件系统中读取 "static/quota.html" 文件的内容
	data, err := embeddedFiles.ReadFile("static/quota.html")
	// 检查读取文件是否出错
	if err != nil {
		// 如果读取失败，返回空字符串
		return ""
	}
	// 将读取的字节切片转换为字符串并返回
	return string(data)
}
