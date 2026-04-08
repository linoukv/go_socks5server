// Package main 实现 SOCKS5 代理服务器的核心协议处理模块。
// 该模块定义了 SOCKS5 协议的常量、数据结构和编解码函数，
// 包括认证握手、命令请求/响应、UDP 关联等完整协议支持。
package main

import (
	"encoding/binary" // 导入二进制编码包，用于大端序/小端序的数据读写操作
	"errors"          // 导入错误处理包，用于创建和返回标准错误对象
	"fmt"             // 导入格式化包，用于字符串格式化和错误信息包装
	"io"              // 导入输入输出包，提供 Reader/Writer 接口和 ReadFull 等工具函数
	"net"             // 导入网络包，提供 IP 地址解析和网络地址操作功能
)

// SOCKS5 协议版本标识
const (
	Version = 0x05 // SOCKS5 协议版本号，所有 SOCKS5 消息的第一个字节必须为此值

	// SOCKS5 认证方法常量 - 客户端在握手时声明支持的认证方式
	AuthNone     = 0x00 // 无需认证：允许任何客户端连接，不进行身份验证
	AuthGSSAPI   = 0x01 // GSSAPI 认证：基于 Kerberos 的通用安全服务 API（当前未实现）
	AuthPassword = 0x02 // 用户名/密码认证：RFC 1929 定义的标准用户名密码验证方式
	AuthNoAccept = 0xFF // 无可接受的认证方法：服务器返回此值表示拒绝所有客户端提议的认证方式

	// SOCKS5 命令类型常量 - 客户端请求执行的操作类型
	CmdConnect      = 0x01 // CONNECT 命令：请求代理服务器建立到目标服务器的 TCP 连接（最常用）
	CmdBind         = 0x02 // BIND 命令：请求代理服务器监听端口等待入站连接（当前未实现）
	CmdUDPAssociate = 0x03 // UDP ASSOCIATE 命令：请求建立 UDP 中继关联，用于转发 UDP 数据包

	// SOCKS5 地址类型常量 - 标识目标地址的格式类型
	AddrTypeIPv4   = 0x01 // IPv4 地址：后续跟随 4 字节的 IPv4 地址
	AddrTypeDomain = 0x03 // 域名地址：后续跟随 1 字节长度 + 域名字节串
	AddrTypeIPv6   = 0x04 // IPv6 地址：后续跟随 16 字节的 IPv6 地址

	// SOCKS5 响应码常量 - 服务器返回给客户端的操作结果状态
	ReplySuccess            = 0x00 // 成功：请求操作已成功完成
	ReplyGeneralFailure     = 0x01 // 一般性失败：发生了未指定的通用错误
	ReplyNotAllowed         = 0x02 // 不允许的规则：规则集禁止此连接请求
	ReplyNetworkUnreachable = 0x03 // 网络不可达：无法到达目标网络
	ReplyHostUnreachable    = 0x04 // 主机不可达：无法到达目标主机
	ReplyConnectionRefused  = 0x05 // 连接被拒绝：目标主机主动拒绝了连接
	ReplyTTLExpired         = 0x06 // TTL 过期：数据包的生存时间已耗尽
	ReplyCmdNotSupported    = 0x07 // 不支持的命令：服务器不支持客户端请求的命令类型
	ReplyAddrNotSupported   = 0x08 // 不支持的地址类型：服务器不支持请求中的地址类型
)

// SOCKS5 协议相关错误定义 - 用于标识协议处理过程中的各类错误
var (
	ErrInvalidVersion    = errors.New("SOCKS 版本无效") // 客户端使用的 SOCKS 版本不是 5，只支持 SOCKS5 协议
	ErrInvalidAuthMethod = errors.New("无可接受的认证方法")  // 服务器不支持客户端提供的任何认证方法，握手协商失败
	ErrAuthFailed        = errors.New("认证失败")       // 用户名或密码认证失败，凭据不匹配或账户被禁用
	ErrInvalidCommand    = errors.New("无效的命令")      // 客户端发送了不支持的 SOCKS 命令（如 BIND）
	ErrInvalidAddrType   = errors.New("无效的地址类型")    // 地址类型不是 IPv4(0x01)、域名(0x03) 或 IPv6(0x04)
)

// AuthRequest 表示 SOCKS5 认证请求结构。
// 客户端在握手阶段发送此结构，声明支持的认证方法列表。
// 协议格式：VER(1字节) + NMETHODS(1字节) + METHODS(NMETHODS字节)
type AuthRequest struct {
	Version  byte   // SOCKS 版本号，必须为 0x05，用于标识使用 SOCKS5 协议
	NMethods byte   // 支持的认证方法数量，取值范围 1-255，表示 Methods 数组的长度
	Methods  []byte // 支持的认证方法列表，每个字节代表一种认证方式（如 0x00=无认证, 0x02=密码认证）
}

// AuthResponse 表示 SOCKS5 认证响应结构。
// 服务器选择一个可接受的认证方法并返回给客户端。
// 协议格式：VER(1字节) + METHOD(1字节)
type AuthResponse struct {
	Version byte // SOCKS 版本号，固定为 0x05，与请求中的版本号保持一致
	Method  byte // 选定的认证方法，从客户端支持的方法中选择一个服务器也支持的方法
}

// PasswordAuthRequest 表示 SOCKS5 用户名/密码认证请求结构。
// 当选择密码认证方法后，客户端发送此结构进行身份验证。
// 协议格式：VER(1字节) + ULEN(1字节) + UNAME(ULEN字节) + PLEN(1字节) + PASSWD(PLEN字节)
type PasswordAuthRequest struct {
	Version byte   // 密码认证子协议版本，必须为 0x01，遵循 RFC 1929 规范
	Ulen    byte   // 用户名长度，取值范围 1-255，表示用户名字节串的长度
	Uname   string // 用户名字符串，由 Ulen 指定的字节数转换而来，用于身份识别
	Plen    byte   // 密码长度，取值范围 1-255，表示密码字节串的长度
	Passwd  string // 密码字符串，由 Plen 指定的字节数转换而来，用于身份验证
}

// PasswordAuthResponse 表示 SOCKS5 用户名/密码认证响应结构。
// 协议格式：VER(1字节) + STATUS(1字节)
type PasswordAuthResponse struct {
	Version byte // 密码认证子协议版本，固定为 0x01，与请求中的子协议版本对应
	Status  byte // 认证状态：0x00 表示认证成功，0x01 表示认证失败（用户名或密码错误）
}

// Request 表示 SOCKS5 命令请求结构。
// 认证完成后，客户端发送此结构指定要执行的操作（CONNECT/BIND/UDP ASSOCIATE）。
// 协议格式：VER(1) + CMD(1) + RSV(1) + ATYPE(1) + DST.ADDR(变长) + DST.PORT(2)
type Request struct {
	Version  byte   // SOCKS 版本号，必须为 0x05，确保使用正确的协议版本
	Cmd      byte   // 命令类型：0x01=CONNECT(TCP连接), 0x02=BIND(端口绑定), 0x03=UDP ASSOCIATE(UDP关联)
	Rsv      byte   // 保留字段，根据协议规范必须为 0x00，用于未来扩展
	AddrType byte   // 目标地址类型：0x01=IPv4(4字节), 0x03=域名(1字节长度+域名), 0x04=IPv6(16字节)
	DstAddr  string // 目标地址字符串，根据 AddrType 解析为 IPv4/域名/IPv6 的可读形式
	DstPort  uint16 // 目标端口号，2 字节大端序整数，范围 0-65535
}

// Response 表示 SOCKS5 命令响应结构。
// 服务器处理完客户端请求后返回此结构。
// 协议格式：VER(1) + REP(1) + RSV(1) + ATYPE(1) + BND.ADDR(变长) + BND.PORT(2)
type Response struct {
	Version  byte   // SOCKS 版本号，固定为 0x05，与请求中的版本号保持一致
	Rep      byte   // 响应码：0x00=成功, 0x01=一般失败, 0x02=不允许, 0x03-0x08=各类错误
	Rsv      byte   // 保留字段，固定为 0x00，遵循协议规范要求
	AddrType byte   // 绑定地址类型：0x01=IPv4, 0x03=域名, 0x04=IPv6，指示 BndAddr 的格式
	BndAddr  string // 绑定地址字符串，服务器为此次连接分配的实际地址（通常是服务器本地地址）
	BndPort  uint16 // 绑定端口号，2 字节大端序整数，服务器为此次连接分配的实际端口
}

// UDPHeader 表示 SOCKS5 UDP 数据报头部结构。
// UDP 关联建立后，每个 UDP 数据报都包含此头部，用于标识数据包的目标地址。
// 协议格式：RSV(2) + FRAG(1) + ATYPE(1) + DST.ADDR(变长) + DST.PORT(2) + DATA(变长)
type UDPHeader struct {
	Rsv      uint16 // 保留字段，必须为 0x0000，两个字节均为零，用于未来协议扩展
	Frag     byte   // 分片编号，当前实现不支持分片，必须为 0x00；非零值表示数据包被分片
	AddrType byte   // 目标地址类型：0x01=IPv4, 0x03=域名, 0x04=IPv6，决定后续地址字段的解析方式
	DstAddr  string // 目标地址字符串，UDP 数据包最终要发送到的目标主机地址
	DstPort  uint16 // 目标端口号，2 字节大端序整数，UDP 数据包要发送到的目标端口
	Data     []byte // 实际的 UDP 载荷数据，去除 SOCKS5 头部后的原始 UDP 数据内容
}

// 协议解析常量定义 - 用于限制解析过程中的资源分配，防止内存溢出攻击
const (
	MaxAuthMethods = 128 // 最大支持的认证方法数量，防止客户端发送超大方法列表导致服务器内存耗尽
	MaxDomainLen   = 255 // 域名最大长度，遵循 DNS 规范中单标签域名的最大长度限制（RFC 1035）
)

// ReadAuthRequest 从读取器中解析 SOCKS5 认证请求。
// 该函数读取客户端发送的握手数据，验证版本号并提取支持的认证方法列表。
// 这是 SOCKS5 协议握手的第一个步骤，用于协商认证方式。
//
// 参数:
//   - r: io.Reader 接口，通常是 TCP 连接，从中读取客户端发送的原始字节流
//
// 返回:
//   - *AuthRequest: 解析后的认证请求结构，包含版本号和认证方法列表
//   - error: 解析错误，包括版本无效、读取失败、方法数量异常等
func ReadAuthRequest(r io.Reader) (*AuthRequest, error) {
	req := &AuthRequest{} // 创建空的认证请求结构体，用于存储解析结果

	// 读取 SOCKS 版本号（1 字节），使用大端序读取
	if err := binary.Read(r, binary.BigEndian, &req.Version); err != nil {
		return nil, err // 读取失败，返回底层 I/O 错误
	}

	// 验证版本号必须为 SOCKS5（0x05），确保协议兼容性
	if req.Version != Version {
		return nil, ErrInvalidVersion // 版本不匹配，返回预定义的错误
	}

	// 读取认证方法数量（1 字节），表示客户端支持多少种认证方式
	if err := binary.Read(r, binary.BigEndian, &req.NMethods); err != nil {
		return nil, err // 读取失败，返回底层 I/O 错误
	}

	// 验证方法数量在合理范围内：不能为 0（至少一种方法），不能超过最大值（防止内存攻击）
	if req.NMethods == 0 || req.NMethods > MaxAuthMethods {
		return nil, fmt.Errorf("认证方法数量异常：%d", req.NMethods) // 返回格式化的错误信息
	}

	// 根据方法数量分配字节切片，准备读取认证方法列表
	req.Methods = make([]byte, req.NMethods)
	// 使用 ReadFull 确保读取完整的 NMethods 个字节，避免部分读取
	if _, err := io.ReadFull(r, req.Methods); err != nil {
		return nil, err // 读取不完整或失败，返回错误
	}

	return req, nil // 解析成功，返回填充好的认证请求结构
}

// WriteAuthResponse 向写入器发送 SOCKS5 认证响应。
// 服务器选择一个可接受的认证方法并通知客户端。
// 这是握手阶段的第二个步骤，服务器告知客户端将使用哪种认证方式。
//
// 参数:
//   - w: io.Writer 接口，通常是 TCP 连接，用于向客户端发送响应数据
//   - method: 选定的认证方法，可选值：AuthNone(0x00)=无认证, AuthPassword(0x02)=密码认证, AuthNoAccept(0xFF)=拒绝
//
// 返回:
//   - error: 写入错误，如果网络传输失败则返回底层 I/O 错误
func WriteAuthResponse(w io.Writer, method byte) error {
	// 构造认证响应结构体，设置版本号为 SOCKS5，方法为协商结果
	resp := &AuthResponse{
		Version: Version, // 版本号固定为 0x05
		Method:  method,  // 使用协商确定的认证方法
	}
	// 使用大端序将响应结构序列化并写入连接
	return binary.Write(w, binary.BigEndian, resp)
}

// ReadPasswordAuthRequest 从读取器中解析 SOCKS5 用户名/密码认证请求。
// 当客户端选择密码认证方法后，调用此函数读取认证凭据。
// 遵循 RFC 1929 规范，格式为：VER(1) + ULEN(1) + UNAME(ULEN) + PLEN(1) + PASSWD(PLEN)
//
// 参数:
//   - r: io.Reader 接口，通常是 TCP 连接，从中读取客户端发送的认证凭据
//
// 返回:
//   - *PasswordAuthRequest: 解析后的认证请求，包含解码后的用户名和密码字符串
//   - error: 解析错误，包括版本无效、长度超出限制、读取失败等
func ReadPasswordAuthRequest(r io.Reader) (*PasswordAuthRequest, error) {
	req := &PasswordAuthRequest{} // 创建空的密码认证请求结构体

	// 读取密码认证子协议版本（1 字节），应为 0x01
	if err := binary.Read(r, binary.BigEndian, &req.Version); err != nil {
		return nil, err // 读取失败，返回底层 I/O 错误
	}

	// 验证子协议版本必须为 0x01，确保符合 RFC 1929 规范
	if req.Version != 0x01 {
		return nil, errors.New("无效的密码认证版本") // 版本不匹配，返回明确错误
	}

	// 读取用户名长度（1 字节），表示后续用户名的字节数
	if err := binary.Read(r, binary.BigEndian, &req.Ulen); err != nil {
		return nil, err // 读取失败，返回底层 I/O 错误
	}

	// 验证用户名长度合法性：不能为空（0），也不能超过系统定义的最大长度
	if req.Ulen == 0 || req.Ulen > MaxUsernameLen {
		return nil, fmt.Errorf("用户名长度无效：%d", req.Ulen) // 返回包含实际长度的错误信息
	}

	// 根据用户名长度分配字节切片，准备读取用户名数据
	unameBytes := make([]byte, req.Ulen)
	// 使用 ReadFull 确保完整读取所有用户名字节
	if _, err := io.ReadFull(r, unameBytes); err != nil {
		return nil, err // 读取不完整或失败，返回错误
	}
	// 将字节切片转换为 Go 字符串，存储到结构体中
	req.Uname = string(unameBytes)

	// 读取密码长度（1 字节），表示后续密码的字节数
	if err := binary.Read(r, binary.BigEndian, &req.Plen); err != nil {
		return nil, err // 读取失败，返回底层 I/O 错误
	}

	// 验证密码长度合法性：不能为空（0），也不能超过系统定义的最大长度
	if req.Plen == 0 || req.Plen > MaxPasswordLen {
		return nil, fmt.Errorf("密码长度无效：%d", req.Plen) // 返回包含实际长度的错误信息
	}

	// 根据密码长度分配字节切片，准备读取密码数据
	passwdBytes := make([]byte, req.Plen)
	// 使用 ReadFull 确保完整读取所有密码字节
	if _, err := io.ReadFull(r, passwdBytes); err != nil {
		return nil, err // 读取不完整或失败，返回错误
	}
	// 将字节切片转换为 Go 字符串，存储到结构体中
	req.Passwd = string(passwdBytes)

	return req, nil // 解析成功，返回包含用户名和密码的认证请求结构
}

// WritePasswordAuthResponse 向写入器发送 SOCKS5 密码认证响应。
// 服务器验证完用户名和密码后，调用此函数通知客户端认证结果。
//
// 参数:
//   - w: io.Writer 接口，通常是 TCP 连接，用于向客户端发送响应
//   - status: 认证状态字节，0x00 表示认证成功，0x01 表示认证失败
//
// 返回:
//   - error: 写入错误，如果网络传输失败则返回底层 I/O 错误
func WritePasswordAuthResponse(w io.Writer, status byte) error {
	// 构造密码认证响应结构体，版本固定为 0x01，状态由参数指定
	resp := &PasswordAuthResponse{
		Version: 0x01,   // 密码认证子协议版本，固定为 0x01
		Status:  status, // 认证结果：0x00=成功, 0x01=失败
	}
	// 使用大端序将响应结构序列化并写入连接（2 字节）
	return binary.Write(w, binary.BigEndian, resp)
}

// ReadRequest 从读取器中解析 SOCKS5 命令请求。
// 认证完成后，客户端发送此请求指定要执行的操作和目标地址。
// 支持三种地址类型：IPv4（4字节）、域名（1字节长度+域名）、IPv6（16字节）。
// 协议格式：VER(1) + CMD(1) + RSV(1) + ATYPE(1) + DST.ADDR(变长) + DST.PORT(2)
//
// 参数:
//   - r: io.Reader 接口，通常是 TCP 连接，从中读取客户端发送的命令请求
//
// 返回:
//   - *Request: 解析后的命令请求结构，包含命令类型、目标地址和端口
//   - error: 解析错误，包括版本无效、地址类型不支持、读取失败等
func ReadRequest(r io.Reader) (*Request, error) {
	req := &Request{} // 创建空的命令请求结构体，用于存储解析结果

	// 读取 SOCKS 版本号（1 字节），必须为 0x05
	if err := binary.Read(r, binary.BigEndian, &req.Version); err != nil {
		return nil, err // 读取失败，返回底层 I/O 错误
	}

	// 验证版本号是否为 SOCKS5，确保协议兼容性
	if req.Version != Version {
		return nil, ErrInvalidVersion // 版本不匹配，返回预定义错误
	}

	// 读取命令类型（1 字节），指示客户端希望执行的操作
	if err := binary.Read(r, binary.BigEndian, &req.Cmd); err != nil {
		return nil, err // 读取失败，返回底层 I/O 错误
	}

	// 读取保留字段（1 字节），根据协议规范应为 0x00
	if err := binary.Read(r, binary.BigEndian, &req.Rsv); err != nil {
		return nil, err // 读取失败，返回底层 I/O 错误
	}

	// 读取地址类型（1 字节），决定后续地址字段的解析方式
	if err := binary.Read(r, binary.BigEndian, &req.AddrType); err != nil {
		return nil, err // 读取失败，返回底层 I/O 错误
	}

	// 根据地址类型分支解析目标地址，不同地址类型的编码格式不同
	switch req.AddrType {
	case AddrTypeIPv4:
		// IPv4 地址类型：读取 4 字节的 IPv4 地址
		addrBytes := make([]byte, 4) // 分配 4 字节空间存储 IPv4 地址
		if _, err := io.ReadFull(r, addrBytes); err != nil {
			return nil, err // 读取不完整，返回错误
		}
		// 将 4 字节转换为 net.IP 类型，再转为可读的点分十进制字符串（如 "192.168.1.1"）
		req.DstAddr = net.IP(addrBytes).String()

	case AddrTypeDomain:
		// 域名地址类型：先读取 1 字节长度，再读取对应长度的域名字节串
		var domainLen byte // 声明变量存储域名长度
		if err := binary.Read(r, binary.BigEndian, &domainLen); err != nil {
			return nil, err // 读取长度失败，返回错误
		}
		// 根据域名长度分配字节切片
		domainBytes := make([]byte, domainLen)
		if _, err := io.ReadFull(r, domainBytes); err != nil {
			return nil, err // 读取域名数据不完整，返回错误
		}
		// 将字节切片转换为 Go 字符串，存储域名（如 "example.com"）
		req.DstAddr = string(domainBytes)

	case AddrTypeIPv6:
		// IPv6 地址类型：读取 16 字节的 IPv6 地址
		addrBytes := make([]byte, 16) // 分配 16 字节空间存储 IPv6 地址
		if _, err := io.ReadFull(r, addrBytes); err != nil {
			return nil, err // 读取不完整，返回错误
		}
		// 将 16 字节转换为 net.IP 类型，再转为可读的冒号分隔字符串（如 "2001:db8::1"）
		req.DstAddr = net.IP(addrBytes).String()

	default:
		// 未知的地址类型，返回错误
		return nil, ErrInvalidAddrType // 地址类型不是 IPv4/域名/IPv6 中的任何一种
	}

	// 读取目标端口号（2 字节，大端序），范围 0-65535
	if err := binary.Read(r, binary.BigEndian, &req.DstPort); err != nil {
		return nil, err // 读取失败，返回底层 I/O 错误
	}

	return req, nil // 解析成功，返回完整的命令请求结构
}

// WriteResponse 向写入器发送 SOCKS5 命令响应。
// 服务器处理完客户端请求后，返回操作结果和绑定的地址信息。
// 协议格式：VER(1) + REP(1) + RSV(1) + ATYPE(1) + BND.ADDR(变长) + BND.PORT(2)
//
// 参数:
//   - w: io.Writer 接口，通常是 TCP 连接，用于向客户端发送响应数据
//   - rep: 响应码，指示操作结果（ReplySuccess=成功, ReplyGeneralFailure=失败等）
//   - addrType: 绑定地址类型，决定 BND.ADDR 字段的编码格式（IPv4/域名/IPv6）
//   - bndAddr: 绑定地址字符串，服务器为此次连接分配的实际地址
//   - bndPort: 绑定端口号，服务器为此次连接分配的实际端口
//
// 返回:
//   - error: 写入错误，包括网络传输失败、地址格式无效等
func WriteResponse(w io.Writer, rep byte, addrType byte, bndAddr string, bndPort uint16) error {
	// 构造响应结构体，填充所有响应字段
	resp := &Response{
		Version:  Version,  // 版本号固定为 0x05
		Rep:      rep,      // 响应码，由调用者指定
		Rsv:      0x00,     // 保留字段，固定为 0x00
		AddrType: addrType, // 地址类型，决定后续地址字段的编码方式
		BndAddr:  bndAddr,  // 绑定地址，服务器实际分配的地址
		BndPort:  bndPort,  // 绑定端口，服务器实际分配的端口
	}

	// 依次写入响应的固定头部字段（前 4 个字节）
	if err := binary.Write(w, binary.BigEndian, resp.Version); err != nil {
		return err // 写入版本号失败，返回错误
	}
	if err := binary.Write(w, binary.BigEndian, resp.Rep); err != nil {
		return err // 写入响应码失败，返回错误
	}
	if err := binary.Write(w, binary.BigEndian, resp.Rsv); err != nil {
		return err // 写入保留字段失败，返回错误
	}
	if err := binary.Write(w, binary.BigEndian, resp.AddrType); err != nil {
		return err // 写入地址类型失败，返回错误
	}

	// 根据地址类型分支写入绑定地址，不同地址类型的编码格式不同
	switch addrType {
	case AddrTypeIPv4:
		// IPv4 地址类型：将地址字符串解析为 4 字节并写入
		ip := net.ParseIP(bndAddr).To4() // 解析 IP 并转换为 4 字节格式
		if ip == nil {
			return fmt.Errorf("无效的 IPv4 地址：%s", bndAddr) // 解析失败，返回错误
		}
		if _, err := w.Write(ip); err != nil {
			return err // 写入 4 字节 IPv4 地址失败，返回错误
		}

	case AddrTypeDomain:
		// 域名地址类型：先写入 1 字节长度，再写入域名字节串
		domainLen := byte(len(bndAddr)) // 计算域名长度并转换为字节
		if err := binary.Write(w, binary.BigEndian, domainLen); err != nil {
			return err // 写入域名长度失败，返回错误
		}
		if _, err := w.Write([]byte(bndAddr)); err != nil {
			return err // 写入域名字节串失败，返回错误
		}

	case AddrTypeIPv6:
		// IPv6 地址类型：将地址字符串解析为 16 字节并写入
		ip := net.ParseIP(bndAddr).To16() // 解析 IP 并转换为 16 字节格式
		if ip == nil {
			return fmt.Errorf("无效的 IPv6 地址：%s", bndAddr) // 解析失败，返回错误
		}
		if _, err := w.Write(ip); err != nil {
			return err // 写入 16 字节 IPv6 地址失败，返回错误
		}
	}

	// 写入绑定端口号（2 字节，大端序）
	return binary.Write(w, binary.BigEndian, resp.BndPort)
}

// ParseUDPHeader 从字节切片中解析 SOCKS5 UDP 数据报头部。
// UDP 关联建立后，每个接收到的 UDP 数据报都以此格式封装。
// 协议格式：RSV(2) + FRAG(1) + ATYPE(1) + DST.ADDR(变长) + DST.PORT(2) + DATA(变长)
//
// 参数:
//   - data: UDP 数据报的原始字节切片，包含完整的 SOCKS5 UDP 头部和载荷
//
// 返回:
//   - *UDPHeader: 解析后的 UDP 头部结构，包含目标地址、端口和载荷数据
//   - error: 解析错误，包括数据太短、地址类型无效、长度不足等
func ParseUDPHeader(data []byte) (*UDPHeader, error) {
	// UDP 头部最小长度检查：RSV(2字节) + FRAG(1字节) + ATYPE(1字节) + 最小地址(4字节IPv4) + PORT(2字节) = 10 字节
	if len(data) < 10 {
		return nil, errors.New("UDP 头部太短") // 数据长度不足，无法构成有效的 UDP 头部
	}

	header := &UDPHeader{} // 创建空的 UDP 头部结构体

	// 解析固定长度的头部字段（前 4 个字节）
	header.Rsv = binary.BigEndian.Uint16(data[0:2]) // 读取 2 字节保留字段，大端序解析
	header.Frag = data[2]                           // 读取 1 字节分片编号，当前实现中应为 0x00
	header.AddrType = data[3]                       // 读取 1 字节地址类型，决定后续地址字段的解析方式

	offset := 4 // 初始化解析偏移量为 4，表示已处理完前 4 个字节的固定头部

	// 根据地址类型分支解析目标地址，不同地址类型的编码格式和长度不同
	switch header.AddrType {
	case AddrTypeIPv4:
		// IPv4 地址类型：需要额外 4 字节存储 IPv4 地址
		if len(data) < offset+4 {
			return nil, errors.New("UDP 头部包含无效的 IPv4 地址") // 数据长度不足 4 字节，返回错误
		}
		// 从当前偏移量读取 4 字节，转换为 net.IP 并转为点分十进制字符串
		header.DstAddr = net.IP(data[offset : offset+4]).String()
		offset += 4 // 偏移量增加 4，跳过已解析的 IPv4 地址

	case AddrTypeDomain:
		// 域名地址类型：先读取 1 字节长度，再读取对应长度的域名字节串
		if len(data) < offset+1 {
			return nil, errors.New("UDP 头部包含无效的域名") // 数据长度不足，无法读取域名长度字节
		}
		domainLen := int(data[offset]) // 读取 1 字节域名长度，转换为 int 类型
		offset++                       // 偏移量增加 1，跳过长度字节
		if len(data) < offset+domainLen {
			return nil, errors.New("UDP 头部包含无效的域名长度") // 剩余数据不足以容纳域名，返回错误
		}
		// 从当前偏移量读取 domainLen 字节，转换为 Go 字符串
		header.DstAddr = string(data[offset : offset+domainLen])
		offset += domainLen // 偏移量增加域名长度，跳过已解析的域名数据

	case AddrTypeIPv6:
		// IPv6 地址类型：需要额外 16 字节存储 IPv6 地址
		if len(data) < offset+16 {
			return nil, errors.New("UDP 头部包含无效的 IPv6 地址") // 数据长度不足 16 字节，返回错误
		}
		// 从当前偏移量读取 16 字节，转换为 net.IP 并转为冒号分隔字符串
		header.DstAddr = net.IP(data[offset : offset+16]).String()
		offset += 16 // 偏移量增加 16，跳过已解析的 IPv6 地址

	default:
		// 未知的地址类型，返回预定义错误
		return nil, ErrInvalidAddrType // 地址类型不是 IPv4/域名/IPv6 中的任何一种
	}

	// 解析目标端口号（2 字节，大端序），紧跟在地址字段之后
	if len(data) < offset+2 {
		return nil, errors.New("UDP 头部包含无效的端口") // 剩余数据不足 2 字节，无法读取端口号
	}
	// 从当前偏移量读取 2 字节，大端序解析为 uint16 端口号
	header.DstPort = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2 // 偏移量增加 2，跳过已解析的端口号

	// 剩余部分为 UDP 载荷数据，即实际的 UDP 数据包内容
	header.Data = data[offset:] // 截取从当前偏移量到末尾的所有字节作为载荷

	return header, nil // 解析成功，返回完整的 UDP 头部结构
}

// BuildUDPHeader 构建 SOCKS5 UDP 数据报头部字节切片。
// 用于将客户端的 UDP 数据封装成 SOCKS5 UDP 格式发送给远程服务器。
// 协议格式：RSV(2) + FRAG(1) + ATYPE(1) + DST.ADDR(变长) + DST.PORT(2) + DATA(变长)
//
// 参数:
//   - addrType: 地址类型，决定地址字段的编码格式（AddrTypeIPv4/AddrTypeDomain/AddrTypeIPv6）
//   - dstAddr: 目标地址字符串，可以是 IPv4、域名或 IPv6 地址
//   - dstPort: 目标端口号，2 字节无符号整数，范围 0-65535
//   - data: UDP 载荷数据，即要转发的原始 UDP 数据包内容
//
// 返回:
//   - []byte: 完整的 UDP 数据报字节切片，包含 SOCKS5 头部和原始载荷
//   - error: 构建错误，包括地址格式无效、地址类型不支持等
func BuildUDPHeader(addrType byte, dstAddr string, dstPort uint16, data []byte) ([]byte, error) {
	// 预分配容量为 1024 字节的字节切片，初始长度为 0
	// 预分配可以减少 append 操作时的内存重新分配次数，提升性能
	buf := make([]byte, 0, 1024)

	// 写入保留字段（2 字节），固定为 0x0000，遵循协议规范
	buf = append(buf, 0x00, 0x00)
	// 写入分片编号（1 字节），固定为 0x00，表示当前实现不支持分片功能
	buf = append(buf, 0x00)
	// 写入地址类型（1 字节），指示后续地址字段的编码格式
	buf = append(buf, addrType)

	// 根据地址类型分支写入目标地址，不同地址类型的编码方式不同
	switch addrType {
	case AddrTypeIPv4:
		// IPv4 地址类型：将地址字符串解析为 4 字节并追加到缓冲区
		ip := net.ParseIP(dstAddr).To4() // 解析 IP 字符串并转换为 4 字节格式
		if ip == nil {
			return nil, fmt.Errorf("无效的 IPv4 地址：%s", dstAddr) // 解析失败，返回错误
		}
		buf = append(buf, ip...) // 将 4 字节 IPv4 地址追加到缓冲区

	case AddrTypeDomain:
		// 域名地址类型：先追加 1 字节长度，再追加域名字节串
		buf = append(buf, byte(len(dstAddr))) // 追加域名长度（1 字节）
		buf = append(buf, []byte(dstAddr)...) // 追加域名的 UTF-8 字节串

	case AddrTypeIPv6:
		// IPv6 地址类型：将地址字符串解析为 16 字节并追加到缓冲区
		ip := net.ParseIP(dstAddr).To16() // 解析 IP 字符串并转换为 16 字节格式
		if ip == nil {
			return nil, fmt.Errorf("无效的 IPv6 地址：%s", dstAddr) // 解析失败，返回错误
		}
		buf = append(buf, ip...) // 将 16 字节 IPv6 地址追加到缓冲区

	default:
		// 未知的地址类型，返回预定义错误
		return nil, ErrInvalidAddrType // 地址类型不是 IPv4/域名/IPv6 中的任何一种
	}

	// 写入目标端口号（2 字节，大端序）
	portBytes := make([]byte, 2)                   // 分配 2 字节空间存储端口号
	binary.BigEndian.PutUint16(portBytes, dstPort) // 将 uint16 端口号以大端序写入字节切片
	buf = append(buf, portBytes...)                // 将 2 字节端口号追加到缓冲区

	// 追加 UDP 载荷数据，即原始的 UDP 数据包内容
	buf = append(buf, data...) // 将载荷数据追加到缓冲区末尾

	return buf, nil // 构建成功，返回完整的 SOCKS5 UDP 数据报字节切片
}
