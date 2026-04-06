package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var tcpBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 256*1024)
	},
}

var udpBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 65535)
	},
}

type TCPProxy struct {
	readSpeedLimit       int64
	writeSpeedLimit      int64
	pendingUpload        int64
	pendingDownload      int64
	batchSize            int64
	clientConn           net.Conn
	remoteConn           net.Conn
	server               *Server
	bufferPool           *BufferPool
	closeOnce            sync.Once
	closed               int32
	username             string
	needStats            bool
	needUserTraffic      bool
	needReadLimit        bool
	needWriteLimit       bool
	authCache            *PasswordAuth
	usernameQuotaChecked bool
}

func NewTCPProxy(clientConn net.Conn, server *Server) *TCPProxy {
	proxy := &TCPProxy{
		clientConn: clientConn,
		server:     server,
		batchSize:  256 * 1024,
	}
	if server != nil && server.config != nil {
		proxy.readSpeedLimit = server.config.ReadSpeedLimit
		proxy.writeSpeedLimit = server.config.WriteSpeedLimit
		proxy.needStats = server.stats != nil
		proxy.needReadLimit = proxy.readSpeedLimit > 0
		proxy.needWriteLimit = proxy.writeSpeedLimit > 0

		if auth, ok := server.config.Auth.(*PasswordAuth); ok {
			proxy.authCache = auth
			proxy.needUserTraffic = true
		} else {
			proxy.needUserTraffic = false
		}
	}
	return proxy
}

func (p *TCPProxy) SetUsername(username string) {
	p.username = username
	if p.authCache != nil {
		if user, exists := p.authCache.GetUser(username); exists {
			if user.ReadSpeedLimit > 0 {
				p.readSpeedLimit = user.ReadSpeedLimit
			}
			if user.WriteSpeedLimit > 0 {
				p.writeSpeedLimit = user.WriteSpeedLimit
			}
			p.needReadLimit = p.readSpeedLimit > 0
			p.needWriteLimit = p.writeSpeedLimit > 0
		}
		if p.authCache.CheckQuotaExceeded(username) {
			log.Printf("用户 [%s] 流量配额已用尽，拒绝连接", username)
			p.clientConn.Close()
			return
		}
	}
}

func (p *TCPProxy) SetBufferPool(pool *BufferPool) {
	p.bufferPool = pool
}

func (p *TCPProxy) HandleConnect(dstAddr string, dstPort uint16) error {
	remoteAddr := net.JoinHostPort(dstAddr, fmt.Sprintf("%d", dstPort))
	remoteConn, err := net.DialTimeout("tcp", remoteAddr, 10*time.Second)
	if err != nil {
		return err
	}
	p.remoteConn = remoteConn

	if tcpConn, ok := remoteConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(10 * time.Second)
		tcpConn.SetReadBuffer(16 * 1024 * 1024)
		tcpConn.SetWriteBuffer(16 * 1024 * 1024)
	}

	localAddr := remoteConn.LocalAddr().(*net.TCPAddr)

	var addrType byte
	ip := localAddr.IP
	if ip4 := ip.To4(); ip4 != nil {
		addrType = AddrTypeIPv4
	} else if ip16 := ip.To16(); ip16 != nil {
		addrType = AddrTypeIPv6
	} else {
		addrType = AddrTypeDomain
	}

	if err := WriteResponse(p.clientConn, ReplySuccess, addrType, localAddr.IP.String(), uint16(localAddr.Port)); err != nil {
		return err
	}

	p.startRelay()
	return nil
}

func (p *TCPProxy) startRelay() {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer p.Close()
		p.copyWithStats(p.remoteConn, p.clientConn, true)
	}()

	go func() {
		defer wg.Done()
		defer p.Close()
		p.copyWithStats(p.clientConn, p.remoteConn, false)
	}()

	wg.Wait()
}

func (p *TCPProxy) copyWithStats(dst, src net.Conn, upload bool) {
	buf := p.bufferPool.Get()
	defer p.bufferPool.Put(buf)

	speedLimit := p.writeSpeedLimit
	if upload {
		speedLimit = p.readSpeedLimit
	}
	needSpeedLimit := speedLimit > 0

	var (
		stats           = p.server.stats
		needStats       = p.needStats
		needUserTraffic = p.needUserTraffic
		auth            = p.authCache
		username        = p.username
	)

	if needUserTraffic && auth != nil && username != "" {
		needStats = true
	}

	if !needStats && !needUserTraffic && !needSpeedLimit {
		p.copyFast(dst, src, buf)
		return
	}

	if needStats && !needUserTraffic && !needSpeedLimit {
		p.copyWithStatsOnly(dst, src, buf, upload, stats)
		return
	}

	const batchThreshold int64 = 256 * 1024
	const flushThreshold int64 = 32 * 1024
	const flushTimeout = 100 * time.Millisecond
	const dbFlushInterval = 10 * time.Second
	localUpload := int64(0)
	localDownload := int64(0)
	dbUpload := int64(0)
	dbDownload := int64(0)
	quotaCheckCounter := 0
	lastQuotaCheck := time.Now()
	lastFlush := time.Now()
	lastDbFlush := time.Now()

	readTimeout := 300 * time.Second

	for {
		src.SetReadDeadline(time.Now().Add(readTimeout))

		n, err := src.Read(buf)
		if n > 0 {
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return
			}

			if needStats {
				now := time.Now()
				if upload {
					localUpload += int64(n)
					if localUpload >= batchThreshold ||
						(localUpload >= flushThreshold && now.Sub(lastFlush) > flushTimeout) ||
						(localUpload > 0 && now.Sub(lastFlush) > 200*time.Millisecond) {
						atomic.AddInt64(&stats.TotalUpload, localUpload)
						dbUpload += localUpload
						localUpload = 0
						lastFlush = now
					}
				} else {
					localDownload += int64(n)
					if localDownload >= batchThreshold ||
						(localDownload >= flushThreshold && now.Sub(lastFlush) > flushTimeout) ||
						(localDownload > 0 && now.Sub(lastFlush) > 200*time.Millisecond) {
						atomic.AddInt64(&stats.TotalDownload, localDownload)
						dbDownload += localDownload
						localDownload = 0
						lastFlush = now
					}
				}
			}

			if needUserTraffic && auth != nil && username != "" {
				if upload {
					p.pendingUpload += int64(n)
					auth.AddUserTraffic(username, int64(n), 0)
				} else {
					p.pendingDownload += int64(n)
					auth.AddUserTraffic(username, 0, int64(n))
				}

				quotaCheckCounter++
				now := time.Now()
				if quotaCheckCounter >= 100 || now.Sub(lastQuotaCheck) > 100*time.Millisecond {
					quotaCheckCounter = 0
					lastQuotaCheck = now
					if auth.CheckQuotaExceeded(username) {
						log.Printf("用户 [%s] 流量配额已用尽 (%.2f MB / %.2f MB)，终止连接",
							username,
							float64(auth.GetUserQuotaUsed(username))/1024/1024,
							float64(auth.GetUserQuotaTotal(username))/1024/1024)
						return
					}
				}
				// 定期将内存中的流量数据持久化到数据库
				if now.Sub(lastDbFlush) > dbFlushInterval {
					if user, exists := auth.GetUser(username); exists {
						if err := dbManager.UpdateUserQuotaUsed(
							username,
							atomic.LoadInt64(&user.QuotaUsed),
							atomic.LoadInt64(&user.UploadTotal),
							atomic.LoadInt64(&user.DownloadTotal),
						); err != nil {
							log.Printf("保存用户 [%s] 流量数据失败: %v", username, err)
						}
					}
					lastDbFlush = now
				}
			}

			if needSpeedLimit && n > 0 {
				sleepNs := int64(n) * int64(time.Second) / speedLimit
				if sleepNs > 0 {
					time.Sleep(time.Duration(sleepNs))
				}
			}
		}
		if err != nil {

			if needStats && (localUpload > 0 || localDownload > 0) {
				if localUpload > 0 {
					atomic.AddInt64(&stats.TotalUpload, localUpload)
				}
				if localDownload > 0 {
					atomic.AddInt64(&stats.TotalDownload, localDownload)
				}
			}
			return
		}
	}

}

func (p *TCPProxy) copyFast(dst io.Writer, src io.Reader, buf []byte) {
	if tcpDst, ok := dst.(*net.TCPConn); ok {
		if tcpSrc, ok := src.(*net.TCPConn); ok {
			if err := p.copyWithSplice(tcpDst, tcpSrc); err == nil {
				return
			}
		}
	}
	_, err := io.CopyBuffer(dst, src, buf)
	_ = err
}

func (p *TCPProxy) copyWithSplice(dst, src *net.TCPConn) error {
	buf := make([]byte, 128*1024)
	_, err := io.CopyBuffer(dst, src, buf)
	return err
}

func (p *TCPProxy) copyWithStatsOnly(dst io.Writer, src io.Reader, buf []byte, upload bool, stats *Stats) {
	const batchThreshold int64 = 100 * 1024
	const flushThreshold int64 = 10 * 1024
	const flushTimeout = 50 * time.Millisecond
	localUpload := int64(0)
	localDownload := int64(0)
	lastFlush := time.Now()

	var srcConn net.Conn
	if conn, ok := src.(net.Conn); ok {
		srcConn = conn
	}

	for {
		if srcConn != nil {
			srcConn.SetReadDeadline(time.Now().Add(300 * time.Second))
		}

		n, err := src.Read(buf)
		if n > 0 {
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return
			}

			now := time.Now()
			if upload {
				localUpload += int64(n)
				if localUpload >= batchThreshold ||
					(localUpload >= flushThreshold && now.Sub(lastFlush) > flushTimeout) ||
					(localUpload > 0 && now.Sub(lastFlush) > 200*time.Millisecond) {
					atomic.AddInt64(&stats.TotalUpload, localUpload)
					localUpload = 0
					lastFlush = now
				}
			} else {
				localDownload += int64(n)
				if localDownload >= batchThreshold ||
					(localDownload >= flushThreshold && now.Sub(lastFlush) > flushTimeout) ||
					(localDownload > 0 && now.Sub(lastFlush) > 200*time.Millisecond) {
					atomic.AddInt64(&stats.TotalDownload, localDownload)
					localDownload = 0
					lastFlush = now
				}
			}
		}
		if err != nil {
			if localUpload > 0 {
				atomic.AddInt64(&stats.TotalUpload, localUpload)
			}
			if localDownload > 0 {
				atomic.AddInt64(&stats.TotalDownload, localDownload)
			}
			return
		}
	}
}

func (p *TCPProxy) Close() {
	p.closeOnce.Do(func() {
		atomic.StoreInt32(&p.closed, 1)
		if p.clientConn != nil {
			p.clientConn.Close()
		}
		if p.remoteConn != nil {
			p.remoteConn.Close()
		}
		if p.username != "" && p.authCache != nil {
			p.authCache.DecrementUserConnection(p.username)
			if p.clientConn != nil {
				clientIP := p.clientConn.RemoteAddr().String()
				p.authCache.RemoveUserIP(p.username, clientIP)
			}
			// 连接关闭时保存最终的流量数据
			if user, exists := p.authCache.GetUser(p.username); exists {
				if err := dbManager.UpdateUserQuotaUsed(
					p.username,
					atomic.LoadInt64(&user.QuotaUsed),
					atomic.LoadInt64(&user.UploadTotal),
					atomic.LoadInt64(&user.DownloadTotal),
				); err != nil {
					log.Printf("保存用户 [%s] 最终流量数据失败: %v", p.username, err)
				}
			}
		}
	})
}

func (p *TCPProxy) IsClosed() bool {
	return atomic.LoadInt32(&p.closed) == 1
}

type UDPAssociation struct {
	clientAddr      *net.UDPAddr
	clientConn      net.Conn
	udpListener     *net.UDPConn
	server          *Server
	closeOnce       sync.Once
	closed          int32
	clientMap       map[string]*net.UDPAddr
	clientMapMu     sync.RWMutex
	remoteConns     map[string]*net.UDPConn
	remoteConnsMu   sync.RWMutex
	readSpeedLimit  int64
	writeSpeedLimit int64
	username        string
}

func NewUDPAssociation(clientConn net.Conn, server *Server) *UDPAssociation {
	udpAssoc := &UDPAssociation{
		clientConn:  clientConn,
		server:      server,
		clientMap:   make(map[string]*net.UDPAddr),
		remoteConns: make(map[string]*net.UDPConn),
	}
	if server != nil && server.config != nil {
		udpAssoc.readSpeedLimit = server.config.ReadSpeedLimit
		udpAssoc.writeSpeedLimit = server.config.WriteSpeedLimit
	}
	return udpAssoc
}

func (u *UDPAssociation) SetUsername(username string) {
	u.username = username
	if u.server != nil && u.server.config != nil && u.server.config.EnableUserManagement {
		if auth, ok := u.server.config.Auth.(*PasswordAuth); ok {
			if user, exists := auth.GetUser(username); exists {
				if user.ReadSpeedLimit > 0 {
					u.readSpeedLimit = user.ReadSpeedLimit
				}
				if user.WriteSpeedLimit > 0 {
					u.writeSpeedLimit = user.WriteSpeedLimit
				}
			}
		}
	}
}

func (u *UDPAssociation) HandleUDPAssociate() error {
	u.clientMapMu.RLock()
	controlConn := u.clientConn
	u.clientMapMu.RUnlock()

	if controlConn == nil {
		return fmt.Errorf("clientConn is nil")
	}

	controlLocalAddr := controlConn.LocalAddr().(*net.TCPAddr)

	udpAddr := &net.UDPAddr{IP: controlLocalAddr.IP, Port: 0}
	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	u.udpListener = udpListener

	localAddr := udpListener.LocalAddr().(*net.UDPAddr)

	var addrType byte
	ip := controlLocalAddr.IP
	if ip4 := ip.To4(); ip4 != nil {
		addrType = AddrTypeIPv4
	} else if ip16 := ip.To16(); ip16 != nil {
		addrType = AddrTypeIPv6
	} else {
		addrType = AddrTypeDomain
	}

	if err := WriteResponse(u.clientConn, ReplySuccess, addrType, controlLocalAddr.IP.String(), uint16(localAddr.Port)); err != nil {
		udpListener.Close()
		return err
	}

	go u.handleUDPData()

	u.waitForClose()

	return nil
}

func (u *UDPAssociation) handleUDPData() {
	for !u.IsClosed() {
		buf := udpBufferPool.Get().([]byte)

		u.clientMapMu.RLock()
		listener := u.udpListener
		u.clientMapMu.RUnlock()

		if listener == nil {
			udpBufferPool.Put(buf)
			return
		}

		n, clientAddr, err := listener.ReadFromUDP(buf)
		if err != nil {
			udpBufferPool.Put(buf)
			if u.IsClosed() {
				return
			}
			log.Printf("UDP 读取错误：%v", err)
			u.Close()
			return
		}

		clientKey := clientAddr.String()
		u.clientMapMu.Lock()
		if u.clientMap != nil {
			u.clientMap[clientKey] = clientAddr
		}
		u.clientMapMu.Unlock()

		if n < 10 {
			udpBufferPool.Put(buf)
			continue
		}

		header, err := ParseUDPHeader(buf[:n])
		if err != nil {
			udpBufferPool.Put(buf)
			continue
		}

		if header.Rsv != 0 || header.Frag != 0 {
			udpBufferPool.Put(buf)
			continue
		}

		go func() {
			defer udpBufferPool.Put(buf)
			u.forwardToRemoteWithPool(header, clientKey)
		}()
	}
}

func (u *UDPAssociation) forwardToRemoteWithPool(header *UDPHeader, clientKey string) {
	dstAddr := net.JoinHostPort(header.DstAddr, fmt.Sprintf("%d", header.DstPort))

	u.remoteConnsMu.RLock()
	remoteConn, exists := u.remoteConns[dstAddr]
	u.remoteConnsMu.RUnlock()

	if !exists || remoteConn == nil {
		u.remoteConnsMu.Lock()
		if u.remoteConns != nil {
			if remoteConn, exists = u.remoteConns[dstAddr]; !exists || remoteConn == nil {
				conn, err := net.Dial("udp", dstAddr)
				if err != nil {
					u.remoteConnsMu.Unlock()
					log.Printf("[UDP] 建立到远程服务器 [%s] 的连接失败：%v", dstAddr, err)
					return
				}
				if udpConn, ok := conn.(*net.UDPConn); ok {
					udpConn.SetReadBuffer(256 * 1024)
					udpConn.SetWriteBuffer(256 * 1024)
					remoteConn = udpConn
				} else {
					remoteConn = conn.(*net.UDPConn)
				}
				u.remoteConns[dstAddr] = remoteConn
				log.Printf("[UDP] 新建连接 [%s] -> [%s]", clientKey, dstAddr)
			}
		} else {
			u.remoteConnsMu.Unlock()
			return
		}
		u.remoteConnsMu.Unlock()
	}

	if remoteConn == nil {
		return
	}
	_, err := remoteConn.Write(header.Data)
	if err != nil {
		log.Printf("[UDP]  发送失败 [%s]: %v", dstAddr, err)
		return
	}

	uploadSize := int64(len(header.Data))
	if u.server != nil && u.server.stats != nil {
		u.server.stats.AddUpload(uploadSize)
	}

	// 用户流量统计
	if u.username != "" && u.server != nil && u.server.config != nil {
		if auth, ok := u.server.config.Auth.(*PasswordAuth); ok {
			auth.AddUserTraffic(u.username, uploadSize, 0)
		}
	}

	responseBuf := udpBufferPool.Get().([]byte)
	defer udpBufferPool.Put(responseBuf)

	for !u.IsClosed() {
		remoteConn.SetReadDeadline(time.Now().Add(30 * time.Second))

		n, err := remoteConn.Read(responseBuf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		u.clientMapMu.RLock()
		clientAddr, exists := u.clientMap[clientKey]
		u.clientMapMu.RUnlock()

		if !exists {
			return
		}

		respData, err := BuildUDPHeader(header.AddrType, header.DstAddr, header.DstPort, responseBuf[:n])
		if err != nil {
			return
		}

		u.udpListener.WriteToUDP(respData, clientAddr)

		downloadSize := int64(n)
		if u.server != nil && u.server.stats != nil {
			u.server.stats.AddDownload(downloadSize)
		}

		// 用户流量统计
		if u.username != "" && u.server != nil && u.server.config != nil {
			if auth, ok := u.server.config.Auth.(*PasswordAuth); ok {
				auth.AddUserTraffic(u.username, 0, downloadSize)
			}
		}
	}
}

func (u *UDPAssociation) waitForClose() {
	buf := make([]byte, 1)

	for {
		u.clientMapMu.RLock()
		conn := u.clientConn
		u.clientMapMu.RUnlock()

		if conn == nil {
			u.Close()
			return
		}

		conn.SetReadDeadline(time.Time{})
		_, err := conn.Read(buf)
		if err != nil {
			u.Close()
			return
		}
	}
}

func (u *UDPAssociation) Close() {
	u.closeOnce.Do(func() {
		atomic.StoreInt32(&u.closed, 1)

		if u.udpListener != nil {
			u.udpListener.Close()
			u.udpListener = nil
		}

		if u.clientConn != nil {
			u.clientConn.Close()
			u.clientConn = nil
		}

		u.remoteConnsMu.Lock()
		if u.remoteConns != nil {
			for _, conn := range u.remoteConns {
				if conn != nil {
					conn.Close()
				}
			}
			u.remoteConns = nil
		}
		u.remoteConnsMu.Unlock()

		u.clientMapMu.Lock()
		u.clientMap = nil
		u.clientMapMu.Unlock()

		if u.username != "" && u.server != nil && u.server.config != nil && u.server.config.EnableUserManagement {
			if auth, ok := u.server.config.Auth.(*PasswordAuth); ok {
				auth.DecrementUserConnection(u.username)
				// 连接关闭时保存最终的流量数据
				if user, exists := auth.GetUser(u.username); exists {
					if err := dbManager.UpdateUserQuotaUsed(
						u.username,
						atomic.LoadInt64(&user.QuotaUsed),
						atomic.LoadInt64(&user.UploadTotal),
						atomic.LoadInt64(&user.DownloadTotal),
					); err != nil {
						log.Printf("保存用户 [%s] UDP最终流量数据失败: %v", u.username, err)
					}
				}
			}
		}
	})
}

func (u *UDPAssociation) IsClosed() bool {
	return atomic.LoadInt32(&u.closed) == 1
}

func parsePort(portStr string) uint16 {
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(port)
}

func copyData(dst, src net.Conn, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	io.Copy(dst, src)
}
