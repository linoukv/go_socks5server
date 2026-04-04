package main

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

type InputValidator struct{}

func NewInputValidator() *InputValidator {
	return &InputValidator{}
}

func (v *InputValidator) ValidateListenAddr(addr string) (string, error) {
	addr = strings.TrimSpace(addr)

	if addr == "" {
		return "0.0.0.0:1080", nil
	}

	if len(addr) > 64 {
		return "", fmt.Errorf("监听地址过长，最大长度为 64 字符")
	}

	matched, _ := regexp.MatchString(`^[0-9.:]+$`, addr)
	if !matched {
		return "", fmt.Errorf("监听地址包含非法字符，只允许数字、点和冒号")
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("监听地址格式错误：%v", err)
	}

	portNum, err := strconv.Atoi(port)
	if err != nil {
		return "", fmt.Errorf("端口号必须是数字")
	}
	if portNum < 1 || portNum > 65535 {
		return "", fmt.Errorf("端口号必须在 1-65535 之间")
	}

	if host != "" {
		ip := net.ParseIP(host)
		if ip == nil {
			return "", fmt.Errorf("IP 地址格式错误")
		}
	}

	return addr, nil
}

func (v *InputValidator) ValidatePositiveInt(value int, fieldName string, minVal, maxVal int) (int, error) {
	if value < 0 {
		return 0, fmt.Errorf("%s不能为负数", fieldName)
	}

	if value > maxVal {
		return 0, fmt.Errorf("%s过大，最大值为 %d", fieldName, maxVal)
	}

	if value == 0 {
		return 0, nil
	}

	if value < minVal && minVal > 0 {
		return 0, fmt.Errorf("%s过小，最小值为 %d", fieldName, minVal)
	}

	return value, nil
}

func (v *InputValidator) ValidatePositiveInt64(value int64, fieldName string, minVal, maxVal int64) (int64, error) {
	if value < 0 {
		return 0, fmt.Errorf("%s不能为负数", fieldName)
	}

	if value > maxVal {
		return 0, fmt.Errorf("%s过大，最大值为 %d", fieldName, maxVal)
	}

	if value == 0 {
		return 0, nil
	}

	if value < minVal && minVal > 0 {
		return 0, fmt.Errorf("%s过小，最小值为 %d", fieldName, minVal)
	}

	return value, nil
}

func (v *InputValidator) ValidateMaxWorkers(value int) (int, error) {
	return v.ValidatePositiveInt(value, "最大工作协程数", 0, 10000)
}

func (v *InputValidator) ValidateMaxConnPerIP(value int) (int, error) {
	return v.ValidatePositiveInt(value, "单 IP 最大连接数", 0, 1000000)
}

func (v *InputValidator) ValidateSpeedLimit(value int64, fieldName string) (int64, error) {
	return v.ValidatePositiveInt64(value, fieldName, 0, 10*1024*1024*1024)
}

func (v *InputValidator) ValidateTimeout(value int, fieldName string) (int, error) {
	return v.ValidatePositiveInt(value, fieldName, 1, 86400)
}

func (v *InputValidator) ValidateKeepAlive(value int) (int, error) {
	return v.ValidatePositiveInt(value, "TCP Keepalive 周期", 0, 3600)
}

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

	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, username)
	if !matched {
		return "", fmt.Errorf("用户名只能包含字母、数字、下划线和短横线")
	}

	return username, nil
}

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

	if strings.ContainsAny(password, "<>'\"&\\") {
		return "", fmt.Errorf("密码包含非法字符")
	}

	return password, nil
}

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

	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_\u4e00-\u9fa5-]+$`, name)
	if !matched {
		return "", fmt.Errorf("组名只能包含字母、数字、中文、下划线和中划线")
	}

	return name, nil
}

func (v *InputValidator) ValidateGroupDescription(desc string) (string, error) {
	desc = strings.TrimSpace(desc)

	if len(desc) > 256 {
		return "", fmt.Errorf("描述长度不能超过 256 个字符")
	}

	if strings.ContainsAny(desc, "<>'\"&\\") {
		return "", fmt.Errorf("描述包含非法字符")
	}

	return desc, nil
}

func (v *InputValidator) SanitizeString(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "<", "")
	s = strings.ReplaceAll(s, ">", "")
	s = strings.ReplaceAll(s, "'", "")
	s = strings.ReplaceAll(s, "\"", "")
	s = strings.ReplaceAll(s, "\\", "")
	return s
}

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

func (v *InputValidator) ValidateConfig(listenAddr string, maxWorkers, maxConnPerIP int, readSpeedLimit, writeSpeedLimit int64, tcpKeepAlive int) (map[string]interface{}, error) {
	errors := make(map[string]interface{})
	validated := make(map[string]interface{})

	if addr, err := v.ValidateListenAddr(listenAddr); err != nil {
		errors["listen_addr"] = err.Error()
	} else {
		validated["listen_addr"] = addr
	}

	if val, err := v.ValidateMaxWorkers(maxWorkers); err != nil {
		errors["max_workers"] = err.Error()
	} else {
		validated["max_workers"] = val
	}

	if val, err := v.ValidateMaxConnPerIP(maxConnPerIP); err != nil {
		errors["max_conn_per_ip"] = err.Error()
	} else {
		validated["max_conn_per_ip"] = val
	}

	if val, err := v.ValidateSpeedLimit(readSpeedLimit, "上传速度限制"); err != nil {
		errors["read_speed_limit"] = err.Error()
	} else {
		validated["read_speed_limit"] = val
	}

	if val, err := v.ValidateSpeedLimit(writeSpeedLimit, "下载速度限制"); err != nil {
		errors["write_speed_limit"] = err.Error()
	} else {
		validated["write_speed_limit"] = val
	}

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
