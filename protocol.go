// Package main 实现 SOCKS5 代理服务器的核心协议处理模块。
// 该模块定义了 SOCKS5 协议的常量、数据结构和编解码函数，
// 包括认证握手、命令请求/响应、UDP 关联等完整协议支持。
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// SOCKS5 协议版本标识
const (
	Version = 0x05 // SOCKS5 协议版本号

	// SOCKS5 认证方法常量
	AuthNone     = 0x00 // 无需认证
	AuthGSSAPI   = 0x01 // GSSAPI 认证（未实现）
	AuthPassword = 0x02 // 用户名/密码认证
	AuthNoAccept = 0xFF // 无可接受的认证方法

	// SOCKS5 命令类型常量
	CmdConnect      = 0x01 // CONNECT 命令：建立 TCP 连接
	CmdBind         = 0x02 // BIND 命令：绑定端口（未实现）
	CmdUDPAssociate = 0x03 // UDP ASSOCIATE 命令：建立 UDP 关联

	// SOCKS5 地址类型常量
	AddrTypeIPv4   = 0x01 // IPv4 地址
	AddrTypeDomain = 0x03 // 域名地址
	AddrTypeIPv6   = 0x04 // IPv6 地址

	// SOCKS5 响应码常量
	ReplySuccess            = 0x00 // 成功
	ReplyGeneralFailure     = 0x01 // 一般性失败
	ReplyNotAllowed         = 0x02 // 不允许的规则
	ReplyNetworkUnreachable = 0x03 // 网络不可达
	ReplyHostUnreachable    = 0x04 // 主机不可达
	ReplyConnectionRefused  = 0x05 // 连接被拒绝
	ReplyTTLExpired         = 0x06 // TTL 过期
	ReplyCmdNotSupported    = 0x07 // 不支持的命令
	ReplyAddrNotSupported   = 0x08 // 不支持的地址类型
)

// SOCKS5 协议相关错误定义
var (
	ErrInvalidVersion    = errors.New("SOCKS 版本无效") // 客户端使用的 SOCKS 版本不是 5
	ErrInvalidAuthMethod = errors.New("无可接受的认证方法")  // 服务器不支持客户端提供的任何认证方法
	ErrAuthFailed        = errors.New("认证失败")       // 用户名或密码认证失败
	ErrInvalidCommand    = errors.New("无效的命令")      // 客户端发送了不支持的 SOCKS 命令
	ErrInvalidAddrType   = errors.New("无效的地址类型")    // 地址类型不是 IPv4、域名或 IPv6
)

// AuthRequest 表示 SOCKS5 认证请求结构。
// 客户端在握手阶段发送此结构，声明支持的认证方法列表。
type AuthRequest struct {
	Version  byte   // SOCKS 版本号，必须为 0x05
	NMethods byte   // 支持的认证方法数量
	Methods  []byte // 支持的认证方法列表
}

// AuthResponse 表示 SOCKS5 认证响应结构。
// 服务器选择一个可接受的认证方法并返回给客户端。
type AuthResponse struct {
	Version byte // SOCKS 版本号，固定为 0x05
	Method  byte // 选定的认证方法
}

// PasswordAuthRequest 表示 SOCKS5 用户名/密码认证请求结构。
// 当选择密码认证方法后，客户端发送此结构进行身份验证。
type PasswordAuthRequest struct {
	Version byte   // 密码认证子协议版本，必须为 0x01
	Ulen    byte   // 用户名长度
	Uname   string // 用户名字符串
	Plen    byte   // 密码长度
	Passwd  string // 密码字符串
}

// PasswordAuthResponse 表示 SOCKS5 用户名/密码认证响应结构。
type PasswordAuthResponse struct {
	Version byte // 密码认证子协议版本，固定为 0x01
	Status  byte // 认证状态：0x00 成功，0x01 失败
}

// Request 表示 SOCKS5 命令请求结构。
// 认证完成后，客户端发送此结构指定要执行的操作（CONNECT/BIND/UDP ASSOCIATE）。
type Request struct {
	Version  byte   // SOCKS 版本号，必须为 0x05
	Cmd      byte   // 命令类型：CONNECT/BIND/UDP ASSOCIATE
	Rsv      byte   // 保留字段，必须为 0x00
	AddrType byte   // 目标地址类型：IPv4/域名/IPv6
	DstAddr  string // 目标地址（IP 或域名）
	DstPort  uint16 // 目标端口号
}

// Response 表示 SOCKS5 命令响应结构。
// 服务器处理完客户端请求后返回此结构。
type Response struct {
	Version  byte   // SOCKS 版本号，固定为 0x05
	Rep      byte   // 响应码：成功/失败原因
	Rsv      byte   // 保留字段，固定为 0x00
	AddrType byte   // 绑定地址类型
	BndAddr  string // 绑定地址（服务器分配的地址）
	BndPort  uint16 // 绑定端口号
}

// UDPHeader 表示 SOCKS5 UDP 数据报头部结构。
// UDP 关联建立后，每个 UDP 数据报都包含此头部。
type UDPHeader struct {
	Rsv      uint16 // 保留字段，必须为 0x0000
	Frag     byte   // 分片编号，当前实现不支持分片，必须为 0x00
	AddrType byte   // 目标地址类型
	DstAddr  string // 目标地址
	DstPort  uint16 // 目标端口号
	Data     []byte // 实际的 UDP 载荷数据
}

// 协议解析常量定义
const (
	MaxAuthMethods = 128 // 最大支持的认证方法数量，防止恶意请求占用过多内存
	MaxDomainLen   = 255 // 域名最大长度（DNS 规范限制）
)

// ReadAuthRequest 从读取器中解析 SOCKS5 认证请求。
// 该函数读取客户端发送的握手数据，验证版本号并提取支持的认证方法列表。
//
// 参数:
//   - r: io.Reader 接口，通常是 TCP 连接
//
// 返回:
//   - *AuthRequest: 解析后的认证请求结构
//   - error: 解析错误，包括版本无效、读取失败等
func ReadAuthRequest(r io.Reader) (*AuthRequest, error) {
	req := &AuthRequest{}

	// 读取 SOCKS 版本号
	if err := binary.Read(r, binary.BigEndian, &req.Version); err != nil {
		return nil, err
	}

	// 验证版本号必须为 SOCKS5
	if req.Version != Version {
		return nil, ErrInvalidVersion
	}

	// 读取认证方法数量
	if err := binary.Read(r, binary.BigEndian, &req.NMethods); err != nil {
		return nil, err
	}

	// 验证方法数量在合理范围内
	if req.NMethods == 0 || req.NMethods > MaxAuthMethods {
		return nil, fmt.Errorf("认证方法数量异常：%d", req.NMethods)
	}

	// 读取认证方法列表
	req.Methods = make([]byte, req.NMethods)
	if _, err := io.ReadFull(r, req.Methods); err != nil {
		return nil, err
	}

	return req, nil
}

// WriteAuthResponse 向写入器发送 SOCKS5 认证响应。
// 服务器选择一个可接受的认证方法并通知客户端。
//
// 参数:
//   - w: io.Writer 接口，通常是 TCP 连接
//   - method: 选定的认证方法（AuthNone/AuthPassword/AuthNoAccept）
//
// 返回:
//   - error: 写入错误
func WriteAuthResponse(w io.Writer, method byte) error {
	resp := &AuthResponse{
		Version: Version,
		Method:  method,
	}
	return binary.Write(w, binary.BigEndian, resp)
}

// ReadPasswordAuthRequest 从读取器中解析 SOCKS5 用户名/密码认证请求。
// 当客户端选择密码认证方法后，调用此函数读取认证凭据。
//
// 参数:
//   - r: io.Reader 接口，通常是 TCP 连接
//
// 返回:
//   - *PasswordAuthRequest: 解析后的认证请求，包含用户名和密码
//   - error: 解析错误，包括版本无效、长度异常等
func ReadPasswordAuthRequest(r io.Reader) (*PasswordAuthRequest, error) {
	req := &PasswordAuthRequest{}

	// 读取密码认证子协议版本
	if err := binary.Read(r, binary.BigEndian, &req.Version); err != nil {
		return nil, err
	}

	// 验证子协议版本必须为 0x01
	if req.Version != 0x01 {
		return nil, errors.New("无效的密码认证版本")
	}

	// 读取用户名长度
	if err := binary.Read(r, binary.BigEndian, &req.Ulen); err != nil {
		return nil, err
	}

	// 验证用户名长度合法性
	if req.Ulen == 0 || req.Ulen > MaxUsernameLen {
		return nil, fmt.Errorf("用户名长度无效：%d", req.Ulen)
	}

	// 读取用户名字节并转换为字符串
	unameBytes := make([]byte, req.Ulen)
	if _, err := io.ReadFull(r, unameBytes); err != nil {
		return nil, err
	}
	req.Uname = string(unameBytes)

	// 读取密码长度
	if err := binary.Read(r, binary.BigEndian, &req.Plen); err != nil {
		return nil, err
	}

	// 验证密码长度合法性
	if req.Plen == 0 || req.Plen > MaxPasswordLen {
		return nil, fmt.Errorf("密码长度无效：%d", req.Plen)
	}

	// 读取密码字节并转换为字符串
	passwdBytes := make([]byte, req.Plen)
	if _, err := io.ReadFull(r, passwdBytes); err != nil {
		return nil, err
	}
	req.Passwd = string(passwdBytes)

	return req, nil
}

// WritePasswordAuthResponse 向写入器发送 SOCKS5 密码认证响应。
//
// 参数:
//   - w: io.Writer 接口，通常是 TCP 连接
//   - status: 认证状态，0x00 表示成功，0x01 表示失败
//
// 返回:
//   - error: 写入错误
func WritePasswordAuthResponse(w io.Writer, status byte) error {
	resp := &PasswordAuthResponse{
		Version: 0x01,
		Status:  status,
	}
	return binary.Write(w, binary.BigEndian, resp)
}

// ReadRequest 从读取器中解析 SOCKS5 命令请求。
// 认证完成后，客户端发送此请求指定要执行的操作和目标地址。
// 支持三种地址类型：IPv4、域名、IPv6。
//
// 参数:
//   - r: io.Reader 接口，通常是 TCP 连接
//
// 返回:
//   - *Request: 解析后的命令请求结构
//   - error: 解析错误，包括版本无效、地址类型不支持等
func ReadRequest(r io.Reader) (*Request, error) {
	req := &Request{}

	// 读取 SOCKS 版本号
	if err := binary.Read(r, binary.BigEndian, &req.Version); err != nil {
		return nil, err
	}

	// 验证版本号
	if req.Version != Version {
		return nil, ErrInvalidVersion
	}

	// 读取命令类型
	if err := binary.Read(r, binary.BigEndian, &req.Cmd); err != nil {
		return nil, err
	}

	// 读取保留字段（应为 0x00）
	if err := binary.Read(r, binary.BigEndian, &req.Rsv); err != nil {
		return nil, err
	}

	// 读取地址类型
	if err := binary.Read(r, binary.BigEndian, &req.AddrType); err != nil {
		return nil, err
	}

	// 根据地址类型解析目标地址
	switch req.AddrType {
	case AddrTypeIPv4:
		// IPv4 地址：4 字节
		addrBytes := make([]byte, 4)
		if _, err := io.ReadFull(r, addrBytes); err != nil {
			return nil, err
		}
		req.DstAddr = net.IP(addrBytes).String()

	case AddrTypeDomain:
		// 域名：1 字节长度 + 域名字节
		var domainLen byte
		if err := binary.Read(r, binary.BigEndian, &domainLen); err != nil {
			return nil, err
		}
		domainBytes := make([]byte, domainLen)
		if _, err := io.ReadFull(r, domainBytes); err != nil {
			return nil, err
		}
		req.DstAddr = string(domainBytes)

	case AddrTypeIPv6:
		// IPv6 地址：16 字节
		addrBytes := make([]byte, 16)
		if _, err := io.ReadFull(r, addrBytes); err != nil {
			return nil, err
		}
		req.DstAddr = net.IP(addrBytes).String()

	default:
		return nil, ErrInvalidAddrType
	}

	// 读取目标端口号（2 字节，大端序）
	if err := binary.Read(r, binary.BigEndian, &req.DstPort); err != nil {
		return nil, err
	}

	return req, nil
}

// WriteResponse 向写入器发送 SOCKS5 命令响应。
// 服务器处理完客户端请求后，返回操作结果和绑定的地址信息。
//
// 参数:
//   - w: io.Writer 接口，通常是 TCP 连接
//   - rep: 响应码（ReplySuccess/ReplyGeneralFailure 等）
//   - addrType: 绑定地址类型
//   - bndAddr: 绑定地址字符串
//   - bndPort: 绑定端口号
//
// 返回:
//   - error: 写入错误
func WriteResponse(w io.Writer, rep byte, addrType byte, bndAddr string, bndPort uint16) error {
	resp := &Response{
		Version:  Version,
		Rep:      rep,
		Rsv:      0x00,
		AddrType: addrType,
		BndAddr:  bndAddr,
		BndPort:  bndPort,
	}

	// 依次写入响应头字段
	if err := binary.Write(w, binary.BigEndian, resp.Version); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, resp.Rep); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, resp.Rsv); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, resp.AddrType); err != nil {
		return err
	}

	// 根据地址类型写入绑定地址
	switch addrType {
	case AddrTypeIPv4:
		ip := net.ParseIP(bndAddr).To4()
		if ip == nil {
			return fmt.Errorf("无效的 IPv4 地址：%s", bndAddr)
		}
		if _, err := w.Write(ip); err != nil {
			return err
		}

	case AddrTypeDomain:
		domainLen := byte(len(bndAddr))
		if err := binary.Write(w, binary.BigEndian, domainLen); err != nil {
			return err
		}
		if _, err := w.Write([]byte(bndAddr)); err != nil {
			return err
		}

	case AddrTypeIPv6:
		ip := net.ParseIP(bndAddr).To16()
		if ip == nil {
			return fmt.Errorf("无效的 IPv6 地址：%s", bndAddr)
		}
		if _, err := w.Write(ip); err != nil {
			return err
		}
	}

	// 写入绑定端口号
	return binary.Write(w, binary.BigEndian, resp.BndPort)
}

// ParseUDPHeader 从字节切片中解析 SOCKS5 UDP 数据报头部。
// UDP 关联建立后，每个接收到的 UDP 数据报都以此格式封装。
//
// 参数:
//   - data: UDP 数据报的原始字节
//
// 返回:
//   - *UDPHeader: 解析后的 UDP 头部结构
//   - error: 解析错误，包括数据太短、地址类型无效等
func ParseUDPHeader(data []byte) (*UDPHeader, error) {
	// UDP 头部最小长度：Rsv(2) + Frag(1) + AddrType(1) + Addr(4最小) + Port(2) = 10 字节
	if len(data) < 10 {
		return nil, errors.New("UDP 头部太短")
	}

	header := &UDPHeader{}

	// 解析固定头部字段
	header.Rsv = binary.BigEndian.Uint16(data[0:2]) // 保留字段
	header.Frag = data[2]                           // 分片编号
	header.AddrType = data[3]                       // 地址类型

	offset := 4 // 当前解析偏移量

	// 根据地址类型解析目标地址
	switch header.AddrType {
	case AddrTypeIPv4:
		if len(data) < offset+4 {
			return nil, errors.New("UDP 头部包含无效的 IPv4 地址")
		}
		header.DstAddr = net.IP(data[offset : offset+4]).String()
		offset += 4

	case AddrTypeDomain:
		if len(data) < offset+1 {
			return nil, errors.New("UDP 头部包含无效的域名")
		}
		domainLen := int(data[offset])
		offset++
		if len(data) < offset+domainLen {
			return nil, errors.New("UDP 头部包含无效的域名长度")
		}
		header.DstAddr = string(data[offset : offset+domainLen])
		offset += domainLen

	case AddrTypeIPv6:
		if len(data) < offset+16 {
			return nil, errors.New("UDP 头部包含无效的 IPv6 地址")
		}
		header.DstAddr = net.IP(data[offset : offset+16]).String()
		offset += 16

	default:
		return nil, ErrInvalidAddrType
	}

	// 解析目标端口号
	if len(data) < offset+2 {
		return nil, errors.New("UDP 头部包含无效的端口")
	}
	header.DstPort = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 剩余部分为 UDP 载荷数据
	header.Data = data[offset:]

	return header, nil
}

// BuildUDPHeader 构建 SOCKS5 UDP 数据报头部字节切片。
// 用于将客户端的 UDP 数据封装成 SOCKS5 UDP 格式发送给远程服务器。
//
// 参数:
//   - addrType: 地址类型（IPv4/域名/IPv6）
//   - dstAddr: 目标地址字符串
//   - dstPort: 目标端口号
//   - data: UDP 载荷数据
//
// 返回:
//   - []byte: 完整的 UDP 数据报（头部 + 载荷）
//   - error: 构建错误，包括地址格式无效等
func BuildUDPHeader(addrType byte, dstAddr string, dstPort uint16, data []byte) ([]byte, error) {
	buf := make([]byte, 0, 1024)

	// 写入保留字段（2 字节，值为 0x0000）
	buf = append(buf, 0x00, 0x00)
	// 写入分片编号（1 字节，值为 0x00，表示不分片）
	buf = append(buf, 0x00)
	// 写入地址类型
	buf = append(buf, addrType)

	// 根据地址类型写入目标地址
	switch addrType {
	case AddrTypeIPv4:
		ip := net.ParseIP(dstAddr).To4()
		if ip == nil {
			return nil, fmt.Errorf("无效的 IPv4 地址：%s", dstAddr)
		}
		buf = append(buf, ip...)

	case AddrTypeDomain:
		buf = append(buf, byte(len(dstAddr)))
		buf = append(buf, []byte(dstAddr)...)

	case AddrTypeIPv6:
		ip := net.ParseIP(dstAddr).To16()
		if ip == nil {
			return nil, fmt.Errorf("无效的 IPv6 地址：%s", dstAddr)
		}
		buf = append(buf, ip...)

	default:
		return nil, ErrInvalidAddrType
	}

	// 写入目标端口号（大端序）
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, dstPort)
	buf = append(buf, portBytes...)

	// 追加 UDP 载荷数据
	buf = append(buf, data...)

	return buf, nil
}
