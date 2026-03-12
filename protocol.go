package main

import (
	"encoding/binary" // 二进制编解码
	"errors"          // 错误处理
	"fmt"             // 格式化输出
	"io"              // IO 操作
	"net"             // 网络操作
)

// SOCKS5 协议常量定义
const (
	// 版本号：SOCKS5 固定为 0x05
	Version = 0x05

	// 认证方法
	AuthNone     = 0x00 // 无需认证
	AuthGSSAPI   = 0x01 // GSSAPI（一般不使用）
	AuthPassword = 0x02 // 用户名/密码认证
	AuthNoAccept = 0xFF // 无可接受的方法

	// 命令类型
	CmdConnect      = 0x01 // TCP 连接命令
	CmdBind         = 0x02 // TCP 绑定命令（较少使用）
	CmdUDPAssociate = 0x03 // UDP 关联命令

	// 地址类型
	AddrTypeIPv4   = 0x01 // IPv4 地址（4 字节）
	AddrTypeDomain = 0x03 // 域名（变长）
	AddrTypeIPv6   = 0x04 // IPv6 地址（16 字节）

	// 回复码
	ReplySuccess            = 0x00 // 成功
	ReplyGeneralFailure     = 0x01 // 通用错误
	ReplyNotAllowed         = 0x02 // 连接不允许
	ReplyNetworkUnreachable = 0x03 // 网络不可达
	ReplyHostUnreachable    = 0x04 // 主机不可达
	ReplyConnectionRefused  = 0x05 // 连接被拒绝
	ReplyTTLExpired         = 0x06 // TTL 过期
	ReplyCmdNotSupported    = 0x07 // 命令不支持
	ReplyAddrNotSupported   = 0x08 // 地址类型不支持
)

// 错误定义
var (
	ErrInvalidVersion    = errors.New("SOCKS 版本无效") // SOCKS 版本错误
	ErrInvalidAuthMethod = errors.New("无可接受的认证方法")  // 无可接受的认证方法
	ErrAuthFailed        = errors.New("认证失败")       // 认证失败
	ErrInvalidCommand    = errors.New("无效的命令")      // 无效命令
	ErrInvalidAddrType   = errors.New("无效的地址类型")    // 无效地址类型
)

// AuthRequest 认证请求结构体
// 格式：+----+----------+----------+
//
//	|VER | NMETHODS | METHODS  |
//	+----+----------+----------+
//	| 1  |    1     | 1 to 255 |
//	+----+----------+----------+
type AuthRequest struct {
	Version  byte   // SOCKS 版本号（应为 0x05）
	NMethods byte   // 支持的认证方法数量
	Methods  []byte // 支持的认证方法列表
}

// AuthResponse 认证响应结构体
// 格式：+----+--------+
//
//	|VER | METHOD |
//	+----+--------+
//	| 1  |   1    |
//	+----+--------+
type AuthResponse struct {
	Version byte // SOCKS 版本号
	Method  byte // 选定的认证方法
}

// PasswordAuthRequest 用户名密码认证请求结构体
// 格式：+----+------+----------+------+----------+
//
//	|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
//	+----+------+----------+------+----------+
//	| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
//	+----+------+----------+------+----------+
type PasswordAuthRequest struct {
	Version byte   // SOCKS 版本号（应为 0x01）
	Ulen    byte   // 用户名长度
	Uname   string // 用户名
	Plen    byte   // 密码长度
	Passwd  string // 密码
}

// PasswordAuthResponse 用户名密码认证响应结构体
// 格式：+----+--------+
//
//	|VER | STATUS |
//	+----+--------+
//	| 1  |   1    |
//	+----+--------+
type PasswordAuthResponse struct {
	Version byte // 版本号（应为 0x01）
	Status  byte // 认证状态：0x00 成功，0x01 失败
}

// Request SOCKS5 请求结构体
// 格式：+----+-----+-------+------+----------+----------+
//
//	|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//	+----+-----+-------+------+----------+----------+
//	| 1  |  1  | X'00' |  1   | Variable |    2     |
//	+----+-----+-------+------+----------+----------+
type Request struct {
	Version  byte   // SOCKS 版本号
	Cmd      byte   // 命令类型（CONNECT/BIND/UDP ASSOCIATE）
	Rsv      byte   // 保留字节，固定为 0x00
	AddrType byte   // 目标地址类型
	DstAddr  string // 目标地址
	DstPort  uint16 // 目标端口
}

// Response SOCKS5 响应结构体
// 格式：+----+-----+-------+------+----------+----------+
//
//	|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//	+----+-----+-------+------+----------+----------+
//	| 1  |  1  | X'00' |  1   | Variable |    2     |
//	+----+-----+-------+------+----------+----------+
type Response struct {
	Version  byte   // SOCKS 版本号
	Rep      byte   // 回复码
	Rsv      byte   // 保留字节
	AddrType byte   // 绑定地址类型
	BndAddr  string // 绑定地址
	BndPort  uint16 // 绑定端口
}

// UDPHeader UDP 转发头部结构体
// 格式：+----+------+------+----------+----------+----------+
//
//	|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+----+------+------+----------+----------+----------+
//	| 2  |  1   |  1   | Variable |    2     | Variable |
//	+----+------+------+----------+----------+----------+
type UDPHeader struct {
	Rsv      uint16 // 保留字节，固定为 0x0000
	Frag     byte   // 分片标志：0x00 表示不分片
	AddrType byte   // 目标地址类型
	DstAddr  string // 目标地址
	DstPort  uint16 // 目标端口
	Data     []byte // 实际数据
}

// 安全常量定义（防止 DoS 攻击）
const (
	MaxAuthMethods = 128 // 最大认证方法数（SOCKS5 最多 255，实际远小于此）
	// MaxUsernameLen 和 MaxPasswordLen 在 auth.go 中已定义
	MaxDomainLen = 255 // 域名最大长度
)

// ReadAuthRequest 读取并解析客户端的认证请求（安全版：添加 DoS 防护）
func ReadAuthRequest(r io.Reader) (*AuthRequest, error) {
	req := &AuthRequest{}

	// 读取版本号（第一个字节）
	if err := binary.Read(r, binary.BigEndian, &req.Version); err != nil {
		return nil, err
	}

	// 验证版本是否为 SOCKS5
	if req.Version != Version {
		return nil, ErrInvalidVersion
	}

	// 读取方法数量（第二个字节）
	if err := binary.Read(r, binary.BigEndian, &req.NMethods); err != nil {
		return nil, err
	}

	// ✅ 添加最大值检查，防止内存耗尽 DoS 攻击
	if req.NMethods == 0 || req.NMethods > MaxAuthMethods {
		return nil, fmt.Errorf("认证方法数量异常：%d", req.NMethods)
	}

	// 读取方法列表（后续 NMETHODS 个字节）
	req.Methods = make([]byte, req.NMethods)
	if _, err := io.ReadFull(r, req.Methods); err != nil {
		return nil, err
	}

	return req, nil
}

// WriteAuthResponse 向客户端写入认证响应
func WriteAuthResponse(w io.Writer, method byte) error {
	resp := &AuthResponse{
		Version: Version,
		Method:  method,
	}
	return binary.Write(w, binary.BigEndian, resp) // 使用大端序写入
}

// ReadPasswordAuthRequest 读取并解析客户端的密码认证请求（安全版：添加长度验证）
func ReadPasswordAuthRequest(r io.Reader) (*PasswordAuthRequest, error) {
	req := &PasswordAuthRequest{}

	// 读取版本号（应为 0x01）
	if err := binary.Read(r, binary.BigEndian, &req.Version); err != nil {
		return nil, err
	}

	// 验证版本
	if req.Version != 0x01 {
		return nil, errors.New("无效的密码认证版本")
	}

	// 读取用户名长度
	if err := binary.Read(r, binary.BigEndian, &req.Ulen); err != nil {
		return nil, err
	}

	// ✅ 验证用户名长度范围
	if req.Ulen == 0 || req.Ulen > MaxUsernameLen {
		return nil, fmt.Errorf("用户名长度无效：%d", req.Ulen)
	}

	// 读取用户名（ULEN 个字节）
	unameBytes := make([]byte, req.Ulen)
	if _, err := io.ReadFull(r, unameBytes); err != nil {
		return nil, err
	}
	req.Uname = string(unameBytes)

	// 读取密码长度
	if err := binary.Read(r, binary.BigEndian, &req.Plen); err != nil {
		return nil, err
	}

	// ✅ 验证密码长度范围
	if req.Plen == 0 || req.Plen > MaxPasswordLen {
		return nil, fmt.Errorf("密码长度无效：%d", req.Plen)
	}

	// 读取密码（PLEN 个字节）
	passwdBytes := make([]byte, req.Plen)
	if _, err := io.ReadFull(r, passwdBytes); err != nil {
		return nil, err
	}
	req.Passwd = string(passwdBytes)

	return req, nil
}

// WritePasswordAuthResponse 向客户端写入密码认证响应
func WritePasswordAuthResponse(w io.Writer, status byte) error {
	resp := &PasswordAuthResponse{
		Version: 0x01,
		Status:  status,
	}
	return binary.Write(w, binary.BigEndian, resp)
}

// ReadRequest 读取并解析客户端的 SOCKS5 请求
func ReadRequest(r io.Reader) (*Request, error) {
	req := &Request{}

	// 读取版本号
	if err := binary.Read(r, binary.BigEndian, &req.Version); err != nil {
		return nil, err
	}

	// 验证是否为 SOCKS5
	if req.Version != Version {
		return nil, ErrInvalidVersion
	}

	// 读取命令类型
	if err := binary.Read(r, binary.BigEndian, &req.Cmd); err != nil {
		return nil, err
	}

	// 读取保留字节
	if err := binary.Read(r, binary.BigEndian, &req.Rsv); err != nil {
		return nil, err
	}

	// 读取地址类型
	if err := binary.Read(r, binary.BigEndian, &req.AddrType); err != nil {
		return nil, err
	}

	// 根据地址类型读取目标地址
	switch req.AddrType {
	case AddrTypeIPv4:
		// IPv4：4 字节
		addrBytes := make([]byte, 4)
		if _, err := io.ReadFull(r, addrBytes); err != nil {
			return nil, err
		}
		req.DstAddr = net.IP(addrBytes).String()

	case AddrTypeDomain:
		// 域名：第一个字节是长度，后续是域名
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
		// IPv6：16 字节
		addrBytes := make([]byte, 16)
		if _, err := io.ReadFull(r, addrBytes); err != nil {
			return nil, err
		}
		req.DstAddr = net.IP(addrBytes).String()

	default:
		return nil, ErrInvalidAddrType
	}

	// 读取目标端口（2 字节，大端序）
	if err := binary.Read(r, binary.BigEndian, &req.DstPort); err != nil {
		return nil, err
	}

	return req, nil
}

// WriteResponse 向客户端写入 SOCKS5 响应
func WriteResponse(w io.Writer, rep byte, addrType byte, bndAddr string, bndPort uint16) error {
	resp := &Response{
		Version:  Version,  // SOCKS5 版本
		Rep:      rep,      // 回复码
		Rsv:      0x00,     // 保留字节
		AddrType: addrType, // 地址类型
		BndAddr:  bndAddr,  // 绑定地址
		BndPort:  bndPort,  // 绑定端口
	}

	// 依次写入响应头部的各个字段
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
		// IPv4：解析并写入 4 字节
		ip := net.ParseIP(bndAddr).To4()
		if ip == nil {
			return fmt.Errorf("无效的 IPv4 地址：%s", bndAddr)
		}
		if _, err := w.Write(ip); err != nil {
			return err
		}

	case AddrTypeDomain:
		// 域名：先写入长度字节，再写入域名
		domainLen := byte(len(bndAddr))
		if err := binary.Write(w, binary.BigEndian, domainLen); err != nil {
			return err
		}
		if _, err := w.Write([]byte(bndAddr)); err != nil {
			return err
		}

	case AddrTypeIPv6:
		// IPv6：解析并写入 16 字节
		ip := net.ParseIP(bndAddr).To16()
		if ip == nil {
			return fmt.Errorf("无效的 IPv6 地址：%s", bndAddr)
		}
		if _, err := w.Write(ip); err != nil {
			return err
		}
	}

	// 写入绑定端口（2 字节，大端序）
	return binary.Write(w, binary.BigEndian, resp.BndPort)
}

// ParseUDPHeader 解析 UDP 数据包头部
func ParseUDPHeader(data []byte) (*UDPHeader, error) {
	// UDP 头部至少需要 10 字节
	if len(data) < 10 {
		return nil, errors.New("UDP 头部太短")
	}

	header := &UDPHeader{}

	// RSV (2 bytes) - 保留字节
	header.Rsv = binary.BigEndian.Uint16(data[0:2])

	// FRAG (1 byte) - 分片标志
	header.Frag = data[2]

	// ATYP (1 byte) - 地址类型
	header.AddrType = data[3]

	offset := 4 // 已读取 4 字节

	// DST.ADDR - 根据地址类型解析目标地址
	switch header.AddrType {
	case AddrTypeIPv4:
		// IPv4：4 字节
		if len(data) < offset+4 {
			return nil, errors.New("UDP 头部包含无效的 IPv4 地址")
		}
		header.DstAddr = net.IP(data[offset : offset+4]).String()
		offset += 4

	case AddrTypeDomain:
		// 域名：第一个字节是长度
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
		// IPv6：16 字节
		if len(data) < offset+16 {
			return nil, errors.New("UDP 头部包含无效的 IPv6 地址")
		}
		header.DstAddr = net.IP(data[offset : offset+16]).String()
		offset += 16

	default:
		return nil, ErrInvalidAddrType
	}

	// DST.PORT (2 bytes) - 目标端口
	if len(data) < offset+2 {
		return nil, errors.New("UDP 头部包含无效的端口")
	}
	header.DstPort = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// DATA - 剩余的是数据部分
	header.Data = data[offset:]

	return header, nil
}

// BuildUDPHeader 构建 UDP 数据包头部
func BuildUDPHeader(addrType byte, dstAddr string, dstPort uint16, data []byte) ([]byte, error) {
	buf := make([]byte, 0, 1024) // 预分配容量的缓冲区

	// RSV (2 bytes) - 保留字节，固定为 0x0000
	buf = append(buf, 0x00, 0x00)

	// FRAG (1 byte) - 分片标志，0x00 表示不分片
	buf = append(buf, 0x00)

	// ATYP (1 byte) - 地址类型
	buf = append(buf, addrType)

	// DST.ADDR - 根据地址类型写入目标地址
	switch addrType {
	case AddrTypeIPv4:
		// IPv4：解析并追加 4 字节
		ip := net.ParseIP(dstAddr).To4()
		if ip == nil {
			return nil, fmt.Errorf("无效的 IPv4 地址：%s", dstAddr)
		}
		buf = append(buf, ip...)

	case AddrTypeDomain:
		// 域名：先追加长度字节，再追加域名
		buf = append(buf, byte(len(dstAddr)))
		buf = append(buf, []byte(dstAddr)...)

	case AddrTypeIPv6:
		// IPv6：解析并追加 16 字节
		ip := net.ParseIP(dstAddr).To16()
		if ip == nil {
			return nil, fmt.Errorf("无效的 IPv6 地址：%s", dstAddr)
		}
		buf = append(buf, ip...)

	default:
		return nil, ErrInvalidAddrType
	}

	// DST.PORT (2 bytes) - 目标端口，大端序
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, dstPort)
	buf = append(buf, portBytes...)

	// DATA - 追加实际数据
	buf = append(buf, data...)

	return buf, nil
}
