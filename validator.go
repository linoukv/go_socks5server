// Package main 实现 SOCKS5 代理服务器的输入验证模块。
// 提供对用户输入的安全检查，包括 XSS 攻击检测、SQL 注入防护、
// 以及配置参数的范围验证，确保系统安全运行。
package main

// 导入 fmt 包，提供格式化输入输出的功能
import (
	"fmt"
	// 导入 net 包，提供网络 I/O 和地址解析功能
	"net"
	// 导入 regexp 包，提供正则表达式匹配功能
	"regexp"
	// 导入 strconv 包，提供字符串与基本数据类型之间的转换
	"strconv"
	// 导入 strings 包，提供字符串操作和处理功能
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
	// 创建并返回一个新的 InputValidator 结构体指针
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
	// 去除地址字符串两端的空白字符
	addr = strings.TrimSpace(addr)

	// 检查地址是否为空
	if addr == "" {
		// 如果为空，返回默认监听地址
		return "0.0.0.0:1080", nil
	}

	// 检查地址长度是否超过限制（64 字符）
	if len(addr) > 64 {
		// 如果过长，返回错误
		return "", fmt.Errorf("监听地址过长，最大长度为 64 字符")
	}

	// 使用正则表达式检查地址是否只包含合法字符（数字、点、冒号）
	matched, _ := regexp.MatchString(`^[0-9.:]+$`, addr)
	// 如果包含非法字符
	if !matched {
		// 返回错误信息
		return "", fmt.Errorf("监听地址包含非法字符，只允许数字、点和冒号")
	}

	// 使用 net.SplitHostPort 解析主机和端口部分
	host, port, err := net.SplitHostPort(addr)
	// 检查解析是否出错
	if err != nil {
		// 如果出错，返回格式错误信息
		return "", fmt.Errorf("监听地址格式错误：%v", err)
	}

	// 将端口字符串转换为整数
	portNum, err := strconv.Atoi(port)
	// 检查转换是否出错
	if err != nil {
		// 如果出错，返回端口必须是数字的错误
		return "", fmt.Errorf("端口号必须是数字")
	}
	// 检查端口号是否在有效范围内（1-65535）
	if portNum < 1 || portNum > 65535 {
		// 如果超出范围，返回错误
		return "", fmt.Errorf("端口号必须在 1-65535 之间")
	}

	// 检查是否指定了主机地址（非空）
	if host != "" {
		// 尝试解析主机部分为 IP 地址
		ip := net.ParseIP(host)
		// 如果解析失败（ip 为 nil）
		if ip == nil {
			// 返回 IP 地址格式错误
			return "", fmt.Errorf("IP 地址格式错误")
		}
	}

	// 所有验证通过，返回原始地址
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
	// 检查值是否为负数
	if value < 0 {
		// 如果是负数，返回错误
		return 0, fmt.Errorf("%s不能为负数", fieldName)
	}

	// 检查值是否超过最大值
	if value > maxVal {
		// 如果超过最大值，返回错误
		return 0, fmt.Errorf("%s过大，最大值为 %d", fieldName, maxVal)
	}

	// 检查值是否为 0（表示禁用或无限制）
	if value == 0 {
		// 如果为 0，直接返回 0 表示合法
		return 0, nil
	}

	// 检查值是否小于最小值（且最小值大于 0，表示需要检查最小值）
	if value < minVal && minVal > 0 {
		// 如果小于最小值，返回错误
		return 0, fmt.Errorf("%s过小，最小值为 %d", fieldName, minVal)
	}

	// 所有验证通过，返回原值
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
	// 检查值是否为负数
	if value < 0 {
		// 如果是负数，返回错误
		return 0, fmt.Errorf("%s不能为负数", fieldName)
	}

	// 检查值是否超过最大值
	if value > maxVal {
		// 如果超过最大值，返回错误
		return 0, fmt.Errorf("%s过大，最大值为 %d", fieldName, maxVal)
	}

	// 检查值是否为 0（表示禁用或无限制）
	if value == 0 {
		// 如果为 0，直接返回 0 表示合法
		return 0, nil
	}

	// 检查值是否小于最小值（且最小值大于 0，表示需要检查最小值）
	if value < minVal && minVal > 0 {
		// 如果小于最小值，返回错误
		return 0, fmt.Errorf("%s过小，最小值为 %d", fieldName, minVal)
	}

	// 所有验证通过，返回原值
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
	// 调用通用正整数验证函数，设置范围为 0-10000
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
	// 调用通用正整数验证函数，设置范围为 0-1000000
	return v.ValidatePositiveInt(value, "单 IP 最大连接数", 0, 1000000)
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
	// 调用通用正整数验证函数，设置范围为 1-86400 秒
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
	// 调用通用正整数验证函数，设置范围为 0-3600 秒
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
	// 去除用户名字符串两端的空白字符
	username = strings.TrimSpace(username)

	// 检查用户名是否为空
	if username == "" {
		// 如果为空，返回错误
		return "", fmt.Errorf("用户名不能为空")
	}

	// 检查用户名长度是否小于最小要求（3 字符）
	if len(username) < 3 {
		// 如果过短，返回错误
		return "", fmt.Errorf("用户名长度至少为 3 个字符")
	}

	// 检查用户名长度是否超过最大限制（32 字符）
	if len(username) > 32 {
		// 如果过长，返回错误
		return "", fmt.Errorf("用户名长度不能超过 32 个字符")
	}

	// 使用正则表达式检查用户名是否只包含安全字符（字母、数字、下划线、短横线）
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, username)
	// 如果包含非法字符
	if !matched {
		// 返回错误信息，防止注入攻击
		return "", fmt.Errorf("用户名只能包含字母、数字、下划线和短横线")
	}

	// 所有验证通过，返回处理后的用户名
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
	// 检查密码是否为空
	if password == "" {
		// 如果为空，返回错误
		return "", fmt.Errorf("密码不能为空")
	}

	// 检查密码长度是否小于最小要求（6 字符）
	if len(password) < 6 {
		// 如果过短，返回错误
		return "", fmt.Errorf("密码长度至少为 6 个字符")
	}

	// 检查密码长度是否超过最大限制（64 字符）
	if len(password) > 64 {
		// 如果过长，返回错误
		return "", fmt.Errorf("密码长度不能超过 64 个字符")
	}

	// 检查密码是否包含可能引起安全问题的特殊字符（<>'"&\）
	if strings.ContainsAny(password, "<>'\"&\\") {
		// 如果包含非法字符，返回错误
		return "", fmt.Errorf("密码包含非法字符")
	}

	// 所有验证通过，返回原密码
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
	// 去除组名字符串两端的空白字符
	name = strings.TrimSpace(name)

	// 检查组名是否为空
	if name == "" {
		// 如果为空，返回错误
		return "", fmt.Errorf("组名不能为空")
	}

	// 检查组名长度是否小于最小要求（2 字符）
	if len(name) < 2 {
		// 如果过短，返回错误
		return "", fmt.Errorf("组名长度至少为 2 个字符")
	}

	// 检查组名长度是否超过最大限制（64 字符）
	if len(name) > 64 {
		// 如果过长，返回错误
		return "", fmt.Errorf("组名长度不能超过 64 个字符")
	}

	// 使用正则表达式检查组名是否只包含合法字符（字母、数字、中文 Unicode、下划线、中划线）
	// \u4e00-\u9fa5 是中文汉字的 Unicode 范围
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_\u4e00-\u9fa5-]+$`, name)
	// 如果包含非法字符
	if !matched {
		// 返回错误信息
		return "", fmt.Errorf("组名只能包含字母、数字、中文、下划线和中划线")
	}

	// 所有验证通过，返回处理后的组名
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
	// 去除描述字符串两端的空白字符
	desc = strings.TrimSpace(desc)

	// 检查描述长度是否超过最大限制（256 字符）
	if len(desc) > 256 {
		// 如果过长，返回错误
		return "", fmt.Errorf("描述长度不能超过 256 个字符")
	}

	// 检查描述是否包含可能引起 XSS 或 SQL 注入的特殊字符（<>'"&\）
	if strings.ContainsAny(desc, "<>'\"&\\") {
		// 如果包含非法字符，返回错误
		return "", fmt.Errorf("描述包含非法字符")
	}

	// 所有验证通过，返回处理后的描述
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
	// 去除字符串两端的空白字符
	s = strings.TrimSpace(s)
	// 移除所有左尖括号（HTML 标签开始）
	s = strings.ReplaceAll(s, "<", "")
	// 移除所有右尖括号（HTML 标签结束）
	s = strings.ReplaceAll(s, ">", "")
	// 移除所有单引号（防止 SQL 注入）
	s = strings.ReplaceAll(s, "'", "")
	// 移除所有双引号（防止注入攻击）
	s = strings.ReplaceAll(s, "\"", "")
	// 移除所有反斜杠（防止转义攻击）
	s = strings.ReplaceAll(s, "\\", "")
	// 返回清理后的安全字符串
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
	// 定义常见的 XSS 攻击模式列表
	xssPatterns := []string{
		// Script 标签及其闭合标签
		"<script", "</script>",
		// JavaScript 协议和常见事件处理器
		"javascript:", "onerror=", "onload=",
		// 更多的事件处理器
		"onclick=", "onmouseover=", "onfocus=",
		// 常见的弹窗函数
		"alert(", "confirm(", "prompt(",
		// DOM 访问和存储操作
		"document.cookie", "localStorage",
	}

	// 将输入字符串转换为小写，以便进行不区分大小写的匹配
	lower := strings.ToLower(s)
	// 遍历所有 XSS 模式
	for _, pattern := range xssPatterns {
		// 检查当前模式是否存在于输入字符串中
		if strings.Contains(lower, pattern) {
			// 如果找到匹配的模式，返回 true 表示检测到 XSS
			return true
		}
	}
	// 遍历完所有模式都未找到匹配，返回 false 表示未检测到 XSS
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
	// 定义常见的 SQL 注入模式列表
	sqlPatterns := []string{
		// SQL 注释符号
		"--", ";--", "/*", "*/",
		// SQL 查询操作关键字
		" UNION ", " SELECT ", " INSERT ",
		// SQL 修改操作关键字
		" UPDATE ", " DELETE ", " DROP ",
		// SQL 条件绕过技巧
		" OR 1=1 ", " OR '1'='1",
	}

	// 将输入字符串转换为大写，以便进行不区分大小写的匹配
	lower := strings.ToUpper(s)
	// 遍历所有 SQL 注入模式
	for _, pattern := range sqlPatterns {
		// 检查当前模式是否存在于输入字符串中
		if strings.Contains(lower, pattern) {
			// 如果找到匹配的模式，返回 true 表示检测到 SQL 注入
			return true
		}
	}
	// 遍历完所有模式都未找到匹配，返回 false 表示未检测到 SQL 注入
	return false
}

// ValidateConfig 验证服务器配置参数的完整性。
// 一次性验证所有配置项，返回验证通过的配置映射和错误详情。
//
// 参数:
//   - listenAddr: 监听地址
//   - maxWorkers: 最大工作协程数
//   - maxConnPerIP: 单 IP 最大连接数
//   - tcpKeepAlive: TCP Keepalive 周期（秒）
//
// 返回:
//   - map[string]interface{}: 验证通过的配置映射
//   - error: 验证错误，包含所有失败字段的详情
func (v *InputValidator) ValidateConfig(listenAddr string, maxWorkers, maxConnPerIP int, tcpKeepAlive int) (map[string]interface{}, error) {
	// 创建一个映射用于存储验证失败的字段和错误信息
	errors := make(map[string]interface{})
	// 创建一个映射用于存储验证通过的字段和值
	validated := make(map[string]interface{})

	// 验证监听地址
	if addr, err := v.ValidateListenAddr(listenAddr); err != nil {
		// 如果验证失败，将错误信息存入 errors 映射
		errors["listen_addr"] = err.Error()
	} else {
		// 如果验证通过，将值存入 validated 映射
		validated["listen_addr"] = addr
	}

	// 验证最大工作协程数
	if val, err := v.ValidateMaxWorkers(maxWorkers); err != nil {
		// 如果验证失败，将错误信息存入 errors 映射
		errors["max_workers"] = err.Error()
	} else {
		// 如果验证通过，将值存入 validated 映射
		validated["max_workers"] = val
	}

	// 验证单 IP 最大连接数
	if val, err := v.ValidateMaxConnPerIP(maxConnPerIP); err != nil {
		// 如果验证失败，将错误信息存入 errors 映射
		errors["max_conn_per_ip"] = err.Error()
	} else {
		// 如果验证通过，将值存入 validated 映射
		validated["max_conn_per_ip"] = val
	}

	// 验证 TCP Keepalive 周期
	if val, err := v.ValidateKeepAlive(tcpKeepAlive); err != nil {
		// 如果验证失败，将错误信息存入 errors 映射
		errors["tcp_keepalive_period"] = err.Error()
	} else {
		// 如果验证通过，将值存入 validated 映射
		validated["tcp_keepalive_period"] = val
	}

	// 检查是否有验证失败的字段
	if len(errors) > 0 {
		// 如果有错误，返回 nil 和通用的验证失败错误
		return nil, fmt.Errorf("输入验证失败")
	}

	// 所有验证通过，返回验证通过的配置映射和 nil 错误
	return validated, nil
}
