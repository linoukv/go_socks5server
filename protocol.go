package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	Version = 0x05

	AuthNone     = 0x00
	AuthGSSAPI   = 0x01
	AuthPassword = 0x02
	AuthNoAccept = 0xFF

	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUDPAssociate = 0x03

	AddrTypeIPv4   = 0x01
	AddrTypeDomain = 0x03
	AddrTypeIPv6   = 0x04

	ReplySuccess            = 0x00
	ReplyGeneralFailure     = 0x01
	ReplyNotAllowed         = 0x02
	ReplyNetworkUnreachable = 0x03
	ReplyHostUnreachable    = 0x04
	ReplyConnectionRefused  = 0x05
	ReplyTTLExpired         = 0x06
	ReplyCmdNotSupported    = 0x07
	ReplyAddrNotSupported   = 0x08
)

var (
	ErrInvalidVersion    = errors.New("SOCKS 版本无效")
	ErrInvalidAuthMethod = errors.New("无可接受的认证方法")
	ErrAuthFailed        = errors.New("认证失败")
	ErrInvalidCommand    = errors.New("无效的命令")
	ErrInvalidAddrType   = errors.New("无效的地址类型")
)

type AuthRequest struct {
	Version  byte
	NMethods byte
	Methods  []byte
}

type AuthResponse struct {
	Version byte
	Method  byte
}

type PasswordAuthRequest struct {
	Version byte
	Ulen    byte
	Uname   string
	Plen    byte
	Passwd  string
}

type PasswordAuthResponse struct {
	Version byte
	Status  byte
}

type Request struct {
	Version  byte
	Cmd      byte
	Rsv      byte
	AddrType byte
	DstAddr  string
	DstPort  uint16
}

type Response struct {
	Version  byte
	Rep      byte
	Rsv      byte
	AddrType byte
	BndAddr  string
	BndPort  uint16
}

type UDPHeader struct {
	Rsv      uint16
	Frag     byte
	AddrType byte
	DstAddr  string
	DstPort  uint16
	Data     []byte
}

const (
	MaxAuthMethods = 128
	MaxDomainLen   = 255
)

func ReadAuthRequest(r io.Reader) (*AuthRequest, error) {
	req := &AuthRequest{}

	if err := binary.Read(r, binary.BigEndian, &req.Version); err != nil {
		return nil, err
	}

	if req.Version != Version {
		return nil, ErrInvalidVersion
	}

	if err := binary.Read(r, binary.BigEndian, &req.NMethods); err != nil {
		return nil, err
	}

	if req.NMethods == 0 || req.NMethods > MaxAuthMethods {
		return nil, fmt.Errorf("认证方法数量异常：%d", req.NMethods)
	}

	req.Methods = make([]byte, req.NMethods)
	if _, err := io.ReadFull(r, req.Methods); err != nil {
		return nil, err
	}

	return req, nil
}

func WriteAuthResponse(w io.Writer, method byte) error {
	resp := &AuthResponse{
		Version: Version,
		Method:  method,
	}
	return binary.Write(w, binary.BigEndian, resp)
}

func ReadPasswordAuthRequest(r io.Reader) (*PasswordAuthRequest, error) {
	req := &PasswordAuthRequest{}

	if err := binary.Read(r, binary.BigEndian, &req.Version); err != nil {
		return nil, err
	}

	if req.Version != 0x01 {
		return nil, errors.New("无效的密码认证版本")
	}

	if err := binary.Read(r, binary.BigEndian, &req.Ulen); err != nil {
		return nil, err
	}

	if req.Ulen == 0 || req.Ulen > MaxUsernameLen {
		return nil, fmt.Errorf("用户名长度无效：%d", req.Ulen)
	}

	unameBytes := make([]byte, req.Ulen)
	if _, err := io.ReadFull(r, unameBytes); err != nil {
		return nil, err
	}
	req.Uname = string(unameBytes)

	if err := binary.Read(r, binary.BigEndian, &req.Plen); err != nil {
		return nil, err
	}

	if req.Plen == 0 || req.Plen > MaxPasswordLen {
		return nil, fmt.Errorf("密码长度无效：%d", req.Plen)
	}

	passwdBytes := make([]byte, req.Plen)
	if _, err := io.ReadFull(r, passwdBytes); err != nil {
		return nil, err
	}
	req.Passwd = string(passwdBytes)

	return req, nil
}

func WritePasswordAuthResponse(w io.Writer, status byte) error {
	resp := &PasswordAuthResponse{
		Version: 0x01,
		Status:  status,
	}
	return binary.Write(w, binary.BigEndian, resp)
}

func ReadRequest(r io.Reader) (*Request, error) {
	req := &Request{}

	if err := binary.Read(r, binary.BigEndian, &req.Version); err != nil {
		return nil, err
	}

	if req.Version != Version {
		return nil, ErrInvalidVersion
	}

	if err := binary.Read(r, binary.BigEndian, &req.Cmd); err != nil {
		return nil, err
	}

	if err := binary.Read(r, binary.BigEndian, &req.Rsv); err != nil {
		return nil, err
	}

	if err := binary.Read(r, binary.BigEndian, &req.AddrType); err != nil {
		return nil, err
	}

	switch req.AddrType {
	case AddrTypeIPv4:
		addrBytes := make([]byte, 4)
		if _, err := io.ReadFull(r, addrBytes); err != nil {
			return nil, err
		}
		req.DstAddr = net.IP(addrBytes).String()

	case AddrTypeDomain:
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
		addrBytes := make([]byte, 16)
		if _, err := io.ReadFull(r, addrBytes); err != nil {
			return nil, err
		}
		req.DstAddr = net.IP(addrBytes).String()

	default:
		return nil, ErrInvalidAddrType
	}

	if err := binary.Read(r, binary.BigEndian, &req.DstPort); err != nil {
		return nil, err
	}

	return req, nil
}

func WriteResponse(w io.Writer, rep byte, addrType byte, bndAddr string, bndPort uint16) error {
	resp := &Response{
		Version:  Version,
		Rep:      rep,
		Rsv:      0x00,
		AddrType: addrType,
		BndAddr:  bndAddr,
		BndPort:  bndPort,
	}

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

	return binary.Write(w, binary.BigEndian, resp.BndPort)
}

func ParseUDPHeader(data []byte) (*UDPHeader, error) {
	if len(data) < 10 {
		return nil, errors.New("UDP 头部太短")
	}

	header := &UDPHeader{}

	header.Rsv = binary.BigEndian.Uint16(data[0:2])
	header.Frag = data[2]
	header.AddrType = data[3]

	offset := 4

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

	if len(data) < offset+2 {
		return nil, errors.New("UDP 头部包含无效的端口")
	}
	header.DstPort = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	header.Data = data[offset:]

	return header, nil
}

func BuildUDPHeader(addrType byte, dstAddr string, dstPort uint16, data []byte) ([]byte, error) {
	buf := make([]byte, 0, 1024)

	buf = append(buf, 0x00, 0x00)
	buf = append(buf, 0x00)
	buf = append(buf, addrType)

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

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, dstPort)
	buf = append(buf, portBytes...)

	buf = append(buf, data...)

	return buf, nil
}
