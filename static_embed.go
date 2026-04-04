package main

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static/*
var embeddedFiles embed.FS

func getStaticFileSystem() http.FileSystem {
	subFS, err := fs.Sub(embeddedFiles, "static")
	if err != nil {
		return nil
	}
	return http.FS(subFS)
}

func getIndexHTML() string {
	data, err := embeddedFiles.ReadFile("static/index.html")
	if err != nil {
		return "<html><body>页面加载失败</body></html>"
	}
	return string(data)
}

func getAppJS() string {
	data, err := embeddedFiles.ReadFile("static/app.js")
	if err != nil {
		return ""
	}
	return string(data)
}

func getLoginHTML() string {
	data, err := embeddedFiles.ReadFile("static/login.html")
	if err != nil {
		return ""
	}
	return string(data)
}

func getQuotaHTML() string {
	data, err := embeddedFiles.ReadFile("static/quota.html")
	if err != nil {
		return ""
	}
	return string(data)
}
