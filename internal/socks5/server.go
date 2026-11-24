// Package socks5 implements a SOCKS5 proxy (RFC 1928) sharing the HTTP proxy's
// routing/dialer. CONNECT and UDP ASSOCIATE are supported; no-auth is the
// default method, matching a local trusted proxy.
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

type Server struct {
	dialer interface {
		DialTCP(ctx context.Context, host, port string) (net.Conn, error)
	}
	mu       sync.Mutex
	listener net.Listener
	conns    map[net.Conn]struct{}
}

func New(dialer interface {
	DialTCP(ctx context.Context, host, port string) (net.Conn, error)
}) *Server {
	return &Server{dialer: dialer, conns: map[net.Conn]struct{}{}}
}

func (s *Server) Listen(bind string, port int) (net.Addr, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(bind, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()
	go s.accept(ln)
	return ln.Addr(), nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	ln := s.listener
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	s.mu.Lock()
	for conn := range s.conns {
		_ = conn.Close()
	}
	s.mu.Unlock()
	return nil
}

func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

func (s *Server) accept(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		go func() {
			defer func() {
				_ = conn.Close()
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
			}()
			s.handle(conn)
		}()
	}
}

func (s *Server) handle(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil || header[0] != 5 {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	// No-auth (0x00) is sufficient for a loopback proxy.
	_, _ = conn.Write([]byte{5, 0})

	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return
	}
	if reqHeader[0] != 5 {
		return
	}
	cmd := reqHeader[1]
	host, port, err := readAddress(conn, reqHeader[3])
	if err != nil {
		reply(conn, 0x08, nil, 0)
		return
	}
	portStr := strconv.Itoa(port)

	if cmd == 3 { // UDP ASSOCIATE
		udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			reply(conn, 0x01, nil, 0)
			return
		}
		defer udp.Close()
		addr, port := udp.LocalAddr().(*net.UDPAddr).IP, udp.LocalAddr().(*net.UDPAddr).Port
		reply(conn, 0x00, addr, port)
		_ = conn.SetDeadline(time.Time{})
		go s.udpRelay(udp)
		_, _ = io.Copy(io.Discard, conn) // hold the TCP control connection
		return
	}
	if cmd != 1 {
		reply(conn, 0x07, nil, 0)
		return
	}

	target, err := s.dialer.DialTCP(context.Background(), host, portStr)
	if err != nil {
		reply(conn, 0x05, nil, 0)
		return
	}
	defer target.Close()
	if tcpAddr, ok := target.RemoteAddr().(*net.TCPAddr); ok {
		reply(conn, 0x00, tcpAddr.IP, tcpAddr.Port)
	} else {
		reply(conn, 0x00, net.IPv4zero, 0)
	}
	_ = conn.SetDeadline(time.Time{})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, conn)
		if c, ok := target.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, target)
		if c, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
	}()
	wg.Wait()
}

func readAddress(conn net.Conn, atyp byte) (string, int, error) {
	switch atyp {
	case 1:
		buf := make([]byte, 4+2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", 0, err
		}
		return net.IP(buf[:4]).String(), int(binary.BigEndian.Uint16(buf[4:])), nil
	case 3:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return "", 0, err
		}
		host := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, host); err != nil {
			return "", 0, err
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(conn, port); err != nil {
			return "", 0, err
		}
		return string(host), int(binary.BigEndian.Uint16(port)), nil
	case 4:
		buf := make([]byte, 16+2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", 0, err
		}
		return net.IP(buf[:16]).String(), int(binary.BigEndian.Uint16(buf[16:])), nil
	default:
		return "", 0, fmt.Errorf("unsupported address type %d", atyp)
	}
}

func reply(conn net.Conn, code byte, ip net.IP, port int) {
	buf := []byte{5, code, 0, 1}
	if ip == nil || ip.To4() == nil {
		buf = append(buf, net.IPv4zero.To4()...)
	} else {
		buf = append(buf, ip.To4()...)
	}
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(port))
	buf = append(buf, portBuf...)
	_, _ = conn.Write(buf)
}

// udpRelay forwards UDP datagrams for UDP ASSOCIATE clients. Sessions are
// keyed by source address and lazily dial to the requested target.
func (s *Server) udpRelay(udp *net.UDPConn) {
	type session struct {
		conn *net.UDPConn
		seen time.Time
	}
	sessions := map[string]*session{}
	defer func() {
		for _, sess := range sessions {
			_ = sess.conn.Close()
		}
	}()
	buf := make([]byte, 65535)
	for {
		n, src, err := udp.ReadFromUDP(buf)
		if err != nil || n < 10 {
			return
		}
		packet := buf[:n]
		if packet[0] != 0 || packet[2] != 0 {
			continue
		}
		host, port, err := readUDPAddress(packet[3:])
		if err != nil {
			continue
		}
		payload := packet[3+udpAddressLen(packet[3:]):]
		key := src.String() + "|" + host + ":" + strconv.Itoa(port)
		sess := sessions[key]
		if sess == nil || time.Since(sess.seen) > 2*time.Minute {
			remote, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
				continue
			}
			conn, err := net.DialUDP("udp", nil, remote)
			if err != nil {
				continue
			}
			sess = &session{conn: conn, seen: time.Now()}
			sessions[key] = sess
			go func(dst *net.UDPAddr, s *session) {
				back := make([]byte, 65535)
				for {
					m, _, err := s.conn.ReadFromUDP(back)
					if err != nil {
						return
					}
					resp := append([]byte{0, 0, 0, 1}, dst.IP.To4()...)
					pb := make([]byte, 2)
					binary.BigEndian.PutUint16(pb, uint16(dst.Port))
					resp = append(resp, pb...)
					resp = append(resp, back[:m]...)
					_, _ = udp.WriteToUDP(resp, dst)
				}
			}(src, sess)
		}
		sess.seen = time.Now()
		_, _ = sess.conn.Write(payload)
	}
}

func readUDPAddress(packet []byte) (string, int, error) {
	switch packet[0] {
	case 1:
		if len(packet) < 7 {
			return "", 0, errors.New("short ipv4")
		}
		return net.IP(packet[1:5]).String(), int(binary.BigEndian.Uint16(packet[5:7])), nil
	case 3:
		if len(packet) < 2 {
			return "", 0, errors.New("short domain")
		}
		n := int(packet[1])
		if len(packet) < 2+n+2 {
			return "", 0, errors.New("short domain packet")
		}
		return string(packet[2 : 2+n]), int(binary.BigEndian.Uint16(packet[2+n : 4+n])), nil
	case 4:
		if len(packet) < 19 {
			return "", 0, errors.New("short ipv6")
		}
		return net.IP(packet[1:17]).String(), int(binary.BigEndian.Uint16(packet[17:19])), nil
	default:
		return "", 0, fmt.Errorf("bad ATYP %d", packet[0])
	}
}

func udpAddressLen(packet []byte) int {
	switch packet[0] {
	case 1:
		return 7
	case 3:
		return 2 + int(packet[1]) + 2
	case 4:
		return 19
	}
	return 0
}
