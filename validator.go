package main

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// InputValidator 输入验证器
type InputValidator struct{}

// NewInputValidator 创建输入验证器
func NewInputValidator() *InputValidator {
	return &InputValidator{}
}

// ValidateListenAddr 验证监听地址
// 格式：IP:PORT 或 :PORT
// 例如：0.0.0.0:1080, :8080
func (v *InputValidator) ValidateListenAddr(addr string) (string, error) {
	addr = strings.TrimSpace(addr)

	// 空值检查
	if addr == "" {
		return "0.0.0.0:1080", nil // 使用默认值
	}

	// 长度检查
	if len(addr) > 64 {
		return "", fmt.Errorf("监听地址过长，最大长度为 64 字符")
	}

	// 检查是否包含非法字符（只允许数字、点、冒号）
	matched, _ := regexp.MatchString(`^[0-9.:]+$`, addr)
	if !matched {
		return "", fmt.Errorf("监听地址包含非法字符，只允许数字、点和冒号")
	}

	// 解析地址
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("监听地址格式错误：%v", err)
	}

	// 验证端口
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return "", fmt.Errorf("端口号必须是数字")
	}
	if portNum < 1 || portNum > 65535 {
		return "", fmt.Errorf("端口号必须在 1-65535 之间")
	}

	// 验证 IP（如果有）
	if host != "" {
		ip := net.ParseIP(host)
		if ip == nil {
			return "", fmt.Errorf("IP 地址格式错误")
		}
	}

	return addr, nil
}

// ValidatePositiveInt 验证正整数（允许 0）
func (v *InputValidator) ValidatePositiveInt(value int, fieldName string, minVal, maxVal int) (int, error) {
	if value < 0 {
		return 0, fmt.Errorf("%s不能为负数", fieldName)
	}

	if value > maxVal {
		return 0, fmt.Errorf("%s过大，最大值为 %d", fieldName, maxVal)
	}

	// 0 是允许的，表示使用默认值或不限速
	if value == 0 {
		return 0, nil
	}

	if value < minVal && minVal > 0 {
		return 0, fmt.Errorf("%s过小，最小值为 %d", fieldName, minVal)
	}

	return value, nil
}

// ValidatePositiveInt64 验证正整数 64 位（允许 0）
func (v *InputValidator) ValidatePositiveInt64(value int64, fieldName string, minVal, maxVal int64) (int64, error) {
	if value < 0 {
		return 0, fmt.Errorf("%s不能为负数", fieldName)
	}

	if value > maxVal {
		return 0, fmt.Errorf("%s过大，最大值为 %d", fieldName, maxVal)
	}

	// 0 是允许的，表示使用默认值或不限速
	if value == 0 {
		return 0, nil
	}

	if value < minVal && minVal > 0 {
		return 0, fmt.Errorf("%s过小，最小值为 %d", fieldName, minVal)
	}

	return value, nil
}

// ValidateMaxWorkers 验证最大工作协程数
func (v *InputValidator) ValidateMaxWorkers(value int) (int, error) {
	return v.ValidatePositiveInt(value, "最大工作协程数", 0, 10000)
}

// ValidateMaxConnPerIP 验证单 IP 最大连接数
func (v *InputValidator) ValidateMaxConnPerIP(value int) (int, error) {
	return v.ValidatePositiveInt(value, "单 IP 最大连接数", 0, 1000000)
}

// ValidateSpeedLimit 验证速度限制（字节/秒）
func (v *InputValidator) ValidateSpeedLimit(value int64, fieldName string) (int64, error) {
	return v.ValidatePositiveInt64(value, fieldName, 0, 10*1024*1024*1024) // 最大 10GB/s
}

// ValidateTimeout 验证超时时间（秒）
func (v *InputValidator) ValidateTimeout(value int, fieldName string) (int, error) {
	return v.ValidatePositiveInt(value, fieldName, 1, 86400) // 最大 24 小时
}

// ValidateKeepAlive 验证 Keepalive 周期（秒）
func (v *InputValidator) ValidateKeepAlive(value int) (int, error) {
	return v.ValidatePositiveInt(value, "TCP Keepalive 周期", 0, 3600)
}

// ValidateUsername 验证用户名
func (v *InputValidator) ValidateUsername(username string) (string, error) {
	username = strings.TrimSpace(username)

	if username == "" {
		return "", fmt.Errorf("用户名不能为空")
	}

	if len(username) < 3 {
		return "", fmt.Errorf("用户名长度至少为 3 个字符")
	}

	if len(username) > 32 {
		return "", fmt.Errorf("用户名长度不能超过 32 个字符")
	}

	// 只允许字母、数字、下划线和短横线（与 auth.go 保持一致）
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, username)
	if !matched {
		return "", fmt.Errorf("用户名只能包含字母、数字、下划线和短横线")
	}

	return username, nil
}

// ValidatePassword 验证密码
func (v *InputValidator) ValidatePassword(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("密码不能为空")
	}

	if len(password) < 6 {
		return "", fmt.Errorf("密码长度至少为 6 个字符")
	}

	if len(password) > 64 {
		return "", fmt.Errorf("密码长度不能超过 64 个字符")
	}

	// 检查是否包含非法字符
	if strings.ContainsAny(password, "<>'\"&\\") {
		return "", fmt.Errorf("密码包含非法字符")
	}

	return password, nil
}

// ValidateGroupName 验证组名
func (v *InputValidator) ValidateGroupName(name string) (string, error) {
	name = strings.TrimSpace(name)

	if name == "" {
		return "", fmt.Errorf("组名不能为空")
	}

	if len(name) < 2 {
		return "", fmt.Errorf("组名长度至少为 2 个字符")
	}

	if len(name) > 64 {
		return "", fmt.Errorf("组名长度不能超过 64 个字符")
	}

	// 只允许字母、数字、中文、下划线、中划线
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_\u4e00-\u9fa5-]+$`, name)
	if !matched {
		return "", fmt.Errorf("组名只能包含字母、数字、中文、下划线和中划线")
	}

	return name, nil
}

// ValidateGroupDescription 验证组描述
func (v *InputValidator) ValidateGroupDescription(desc string) (string, error) {
	desc = strings.TrimSpace(desc)

	if len(desc) > 256 {
		return "", fmt.Errorf("描述长度不能超过 256 个字符")
	}

	// 检查是否包含非法字符
	if strings.ContainsAny(desc, "<>'\"&\\") {
		return "", fmt.Errorf("描述包含非法字符")
	}

	return desc, nil
}

// SanitizeString 清理字符串（去除首尾空格和特殊字符）
func (v *InputValidator) SanitizeString(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "<", "")
	s = strings.ReplaceAll(s, ">", "")
	s = strings.ReplaceAll(s, "'", "")
	s = strings.ReplaceAll(s, "\"", "")
	s = strings.ReplaceAll(s, "\\", "")
	return s
}

// ContainsXSS 检查是否包含 XSS 攻击特征
func (v *InputValidator) ContainsXSS(s string) bool {
	xssPatterns := []string{
		"<script", "</script>",
		"javascript:", "onerror=", "onload=",
		"onclick=", "onmouseover=", "onfocus=",
		"alert(", "confirm(", "prompt(",
		"document.cookie", "localStorage",
	}

	lower := strings.ToLower(s)
	for _, pattern := range xssPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// ContainsSQLInjection 检查是否包含 SQL 注入特征
func (v *InputValidator) ContainsSQLInjection(s string) bool {
	sqlPatterns := []string{
		"--", ";--", "/*", "*/",
		" UNION ", " SELECT ", " INSERT ",
		" UPDATE ", " DELETE ", " DROP ",
		" OR 1=1 ", " OR '1'='1",
	}

	lower := strings.ToUpper(s)
	for _, pattern := range sqlPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// ValidateConfig 验证配置数据
func (v *InputValidator) ValidateConfig(listenAddr string, maxWorkers, maxConnPerIP int, readSpeedLimit, writeSpeedLimit int64, tcpKeepAlive int) (map[string]interface{}, error) {
	errors := make(map[string]interface{})
	validated := make(map[string]interface{})

	// 验证监听地址
	if addr, err := v.ValidateListenAddr(listenAddr); err != nil {
		errors["listen_addr"] = err.Error()
	} else {
		validated["listen_addr"] = addr
	}

	// 验证最大工作协程数
	if val, err := v.ValidateMaxWorkers(maxWorkers); err != nil {
		errors["max_workers"] = err.Error()
	} else {
		validated["max_workers"] = val
	}

	// 验证单 IP 最大连接数
	if val, err := v.ValidateMaxConnPerIP(maxConnPerIP); err != nil {
		errors["max_conn_per_ip"] = err.Error()
	} else {
		validated["max_conn_per_ip"] = val
	}

	// 验证上传速度限制
	if val, err := v.ValidateSpeedLimit(readSpeedLimit, "上传速度限制"); err != nil {
		errors["read_speed_limit"] = err.Error()
	} else {
		validated["read_speed_limit"] = val
	}

	// 验证下载速度限制
	if val, err := v.ValidateSpeedLimit(writeSpeedLimit, "下载速度限制"); err != nil {
		errors["write_speed_limit"] = err.Error()
	} else {
		validated["write_speed_limit"] = val
	}

	// 验证 TCP Keepalive 周期
	if val, err := v.ValidateKeepAlive(tcpKeepAlive); err != nil {
		errors["tcp_keepalive_period"] = err.Error()
	} else {
		validated["tcp_keepalive_period"] = val
	}

	if len(errors) > 0 {
		return nil, fmt.Errorf("输入验证失败")
	}

	return validated, nil
}
