// Package main 实现 SOCKS5 代理服务器的输入验证模块。
// 提供对用户输入的安全检查，包括 XSS 攻击检测、SQL 注入防护、
// 以及配置参数的范围验证，确保系统安全运行。
package main

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// InputValidator 输入验证器，提供各类输入数据的验证和清理功能。
// 用于 Web 管理界面的表单验证和 API 参数校验。
type InputValidator struct{}

// NewInputValidator 创建一个新的输入验证器实例。
//
// 返回:
//   - *InputValidator: 初始化后的验证器实例
func NewInputValidator() *InputValidator {
	return &InputValidator{}
}

// ValidateListenAddr 验证服务器监听地址的合法性。
// 支持格式：IP:Port（如 0.0.0.0:1080）或 :Port（如 :1080）。
//
// 参数:
//   - addr: 待验证的监听地址字符串
//
// 返回:
//   - string: 验证通过的地址
//   - error: 验证错误信息
func (v *InputValidator) ValidateListenAddr(addr string) (string, error) {
	addr = strings.TrimSpace(addr)

	// 空地址使用默认值
	if addr == "" {
		return "0.0.0.0:1080", nil
	}

	// 限制地址长度防止溢出
	if len(addr) > 64 {
		return "", fmt.Errorf("监听地址过长，最大长度为 64 字符")
	}

	// 仅允许数字、点和冒号（IPv4 地址格式）
	matched, _ := regexp.MatchString(`^[0-9.:]+$`, addr)
	if !matched {
		return "", fmt.Errorf("监听地址包含非法字符，只允许数字、点和冒号")
	}

	// 解析主机和端口
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("监听地址格式错误：%v", err)
	}

	// 验证端口号
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return "", fmt.Errorf("端口号必须是数字")
	}
	if portNum < 1 || portNum > 65535 {
		return "", fmt.Errorf("端口号必须在 1-65535 之间")
	}

	// 如果指定了主机地址，验证 IP 格式
	if host != "" {
		ip := net.ParseIP(host)
		if ip == nil {
			return "", fmt.Errorf("IP 地址格式错误")
		}
	}

	return addr, nil
}

// ValidatePositiveInt 验证正整数参数的范围。
// 通用验证函数，用于检查配置参数是否在允许范围内。
//
// 参数:
//   - value: 待验证的整数值
//   - fieldName: 字段名称，用于错误提示
//   - minVal: 最小允许值（0 表示不检查最小值）
//   - maxVal: 最大允许值
//
// 返回:
//   - int: 验证通过的值
//   - error: 验证错误信息
func (v *InputValidator) ValidatePositiveInt(value int, fieldName string, minVal, maxVal int) (int, error) {
	// 不允许负数
	if value < 0 {
		return 0, fmt.Errorf("%s不能为负数", fieldName)
	}

	// 检查最大值
	if value > maxVal {
		return 0, fmt.Errorf("%s过大，最大值为 %d", fieldName, maxVal)
	}

	// 0 表示禁用/无限制
	if value == 0 {
		return 0, nil
	}

	// 检查最小值
	if value < minVal && minVal > 0 {
		return 0, fmt.Errorf("%s过小，最小值为 %d", fieldName, minVal)
	}

	return value, nil
}

// ValidatePositiveInt64 验证 64 位正整数参数的范围。
// 用于大数值参数如速度限制（字节/秒）的验证。
//
// 参数:
//   - value: 待验证的 64 位整数值
//   - fieldName: 字段名称，用于错误提示
//   - minVal: 最小允许值（0 表示不检查最小值）
//   - maxVal: 最大允许值
//
// 返回:
//   - int64: 验证通过的值
//   - error: 验证错误信息
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

// ValidateMaxWorkers 验证最大工作协程数参数。
// 允许范围：0-10000（0 表示无限制）。
//
// 参数:
//   - value: 工作协程数
//
// 返回:
//   - int: 验证通过的值
//   - error: 验证错误信息
func (v *InputValidator) ValidateMaxWorkers(value int) (int, error) {
	return v.ValidatePositiveInt(value, "最大工作协程数", 0, 10000)
}

// ValidateMaxConnPerIP 验证单 IP 最大连接数参数。
// 允许范围：0-1000000（0 表示无限制）。
//
// 参数:
//   - value: 最大连接数
//
// 返回:
//   - int: 验证通过的值
//   - error: 验证错误信息
func (v *InputValidator) ValidateMaxConnPerIP(value int) (int, error) {
	return v.ValidatePositiveInt(value, "单 IP 最大连接数", 0, 1000000)
}

// ValidateSpeedLimit 验证速度限制参数（字节/秒）。
// 允许范围：0-10GB/s（0 表示不限速）。
//
// 参数:
//   - value: 速度限制值
//   - fieldName: 字段名称（上传/下载）
//
// 返回:
//   - int64: 验证通过的值
//   - error: 验证错误信息
func (v *InputValidator) ValidateSpeedLimit(value int64, fieldName string) (int64, error) {
	return v.ValidatePositiveInt64(value, fieldName, 0, 10*1024*1024*1024)
}

// ValidateTimeout 验证超时参数（秒）。
// 允许范围：1-86400（1 秒到 24 小时）。
//
// 参数:
//   - value: 超时值（秒）
//   - fieldName: 字段名称
//
// 返回:
//   - int: 验证通过的值
//   - error: 验证错误信息
func (v *InputValidator) ValidateTimeout(value int, fieldName string) (int, error) {
	return v.ValidatePositiveInt(value, fieldName, 1, 86400)
}

// ValidateKeepAlive 验证 TCP Keepalive 周期参数（秒）。
// 允许范围：0-3600（0 表示禁用，最大 1 小时）。
//
// 参数:
//   - value: Keepalive 周期（秒）
//
// 返回:
//   - int: 验证通过的值
//   - error: 验证错误信息
func (v *InputValidator) ValidateKeepAlive(value int) (int, error) {
	return v.ValidatePositiveInt(value, "TCP Keepalive 周期", 0, 3600)
}

// ValidateUsername 验证用户名的合法性。
// 要求：3-32 个字符，仅允许字母、数字、下划线和短横线。
//
// 参数:
//   - username: 待验证的用户名
//
// 返回:
//   - string: 去除空格后的用户名
//   - error: 验证错误信息
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

	// 仅允许安全字符，防止注入攻击
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, username)
	if !matched {
		return "", fmt.Errorf("用户名只能包含字母、数字、下划线和短横线")
	}

	return username, nil
}

// ValidatePassword 验证密码的合法性。
// 要求：6-64 个字符，不包含特殊 HTML/SQL 字符。
//
// 参数:
//   - password: 待验证的密码
//
// 返回:
//   - string: 验证通过的密码
//   - error: 验证错误信息
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

	// 禁止可能引起安全问题的特殊字符
	if strings.ContainsAny(password, "<>'\"&\\") {
		return "", fmt.Errorf("密码包含非法字符")
	}

	return password, nil
}

// ValidateGroupName 验证用户组名的合法性。
// 支持中文、字母、数字、下划线和中划线。
//
// 参数:
//   - name: 待验证的组名
//
// 返回:
//   - string: 去除空格后的组名
//   - error: 验证错误信息
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

	// 允许中文 Unicode 范围 \u4e00-\u9fa5
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_\u4e00-\u9fa5-]+$`, name)
	if !matched {
		return "", fmt.Errorf("组名只能包含字母、数字、中文、下划线和中划线")
	}

	return name, nil
}

// ValidateGroupDescription 验证组描述的合法性。
// 最大长度 256 字符，禁止特殊 HTML/SQL 字符。
//
// 参数:
//   - desc: 待验证的描述文本
//
// 返回:
//   - string: 去除空格后的描述
//   - error: 验证错误信息
func (v *InputValidator) ValidateGroupDescription(desc string) (string, error) {
	desc = strings.TrimSpace(desc)

	if len(desc) > 256 {
		return "", fmt.Errorf("描述长度不能超过 256 个字符")
	}

	// 禁止可能引起 XSS 或 SQL 注入的字符
	if strings.ContainsAny(desc, "<>'\"&\\") {
		return "", fmt.Errorf("描述包含非法字符")
	}

	return desc, nil
}

// SanitizeString 清理字符串中的危险字符。
// 移除 HTML 标签和特殊符号，用于防止 XSS 攻击。
//
// 参数:
//   - s: 待清理的字符串
//
// 返回:
//   - string: 清理后的安全字符串
func (v *InputValidator) SanitizeString(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "<", "")
	s = strings.ReplaceAll(s, ">", "")
	s = strings.ReplaceAll(s, "'", "")
	s = strings.ReplaceAll(s, "\"", "")
	s = strings.ReplaceAll(s, "\\", "")
	return s
}

// ContainsXSS 检测字符串是否包含 XSS 攻击特征。
// 检查常见的 JavaScript 注入模式和 DOM 操作关键字。
//
// 参数:
//   - s: 待检测的字符串
//
// 返回:
//   - bool: true 表示检测到 XSS 特征
func (v *InputValidator) ContainsXSS(s string) bool {
	xssPatterns := []string{
		"<script", "</script>", // Script 标签
		"javascript:", "onerror=", "onload=", // 事件处理器
		"onclick=", "onmouseover=", "onfocus=", // 更多事件
		"alert(", "confirm(", "prompt(", // 弹窗函数
		"document.cookie", "localStorage", // DOM 访问
	}

	lower := strings.ToLower(s)
	for _, pattern := range xssPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// ContainsSQLInjection 检测字符串是否包含 SQL 注入特征。
// 检查常见的 SQL 关键字和注释符号。
//
// 参数:
//   - s: 待检测的字符串
//
// 返回:
//   - bool: true 表示检测到 SQL 注入特征
func (v *InputValidator) ContainsSQLInjection(s string) bool {
	sqlPatterns := []string{
		"--", ";--", "/*", "*/", // SQL 注释
		" UNION ", " SELECT ", " INSERT ", // 查询操作
		" UPDATE ", " DELETE ", " DROP ", // 修改操作
		" OR 1=1 ", " OR '1'='1", // 条件绕过
	}

	lower := strings.ToUpper(s)
	for _, pattern := range sqlPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// ValidateConfig 验证服务器配置参数的完整性。
// 一次性验证所有配置项，返回验证通过的配置映射和错误详情。
//
// 参数:
//   - listenAddr: 监听地址
//   - maxWorkers: 最大工作协程数
//   - maxConnPerIP: 单 IP 最大连接数
//   - readSpeedLimit: 上传速度限制（字节/秒）
//   - writeSpeedLimit: 下载速度限制（字节/秒）
//   - tcpKeepAlive: TCP Keepalive 周期（秒）
//
// 返回:
//   - map[string]interface{}: 验证通过的配置映射
//   - error: 验证错误，包含所有失败字段的详情
func (v *InputValidator) ValidateConfig(listenAddr string, maxWorkers, maxConnPerIP int, readSpeedLimit, writeSpeedLimit int64, tcpKeepAlive int) (map[string]interface{}, error) {
	errors := make(map[string]interface{})
	validated := make(map[string]interface{})

	// 验证监听地址
	if addr, err := v.ValidateListenAddr(listenAddr); err != nil {
		errors["listen_addr"] = err.Error()
	} else {
		validated["listen_addr"] = addr
	}

	// 验证工作协程数
	if val, err := v.ValidateMaxWorkers(maxWorkers); err != nil {
		errors["max_workers"] = err.Error()
	} else {
		validated["max_workers"] = val
	}

	// 验证每 IP 连接数
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

	// 验证 Keepalive 周期
	if val, err := v.ValidateKeepAlive(tcpKeepAlive); err != nil {
		errors["tcp_keepalive_period"] = err.Error()
	} else {
		validated["tcp_keepalive_period"] = val
	}

	// 如果有验证失败的字段，返回错误
	if len(errors) > 0 {
		return nil, fmt.Errorf("输入验证失败")
	}

	return validated, nil
}
