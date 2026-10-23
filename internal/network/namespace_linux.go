//go:build linux

package network

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"time"
)

func inNamespace(name string, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := os.Open(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()))
	if err != nil {
		return err
	}
	defer original.Close()
	target, err := os.Open("/var/run/netns/" + name)
	if err != nil {
		return err
	}
	defer target.Close()
	if err = unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		return err
	}
	result := fn()
	if err = unix.Setns(int(original.Fd()), unix.CLONE_NEWNET); err != nil {
		panic("cannot restore original network namespace")
	}
	return result
}
func listenNamespaceDNS(name string) (net.PacketConn, error) {
	var listener net.PacketConn
	err := inNamespace(name, func() error { var e error; listener, e = net.ListenPacket("udp4", "127.0.0.1:53"); return e })
	return listener, err
}
func dialNamespaceIP(ctx context.Context, namespace, network, address string) (net.Conn, error) {
	return dialNamespaceMarkedIP(ctx, namespace, network, address, 0)
}

func dialNamespaceMarkedIP(ctx context.Context, namespace, network, address string, mark int) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("namespace dial requires resolved IP")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return nil, fmt.Errorf("invalid namespace destination port")
	}
	fd := -1
	err = inNamespace(namespace, func() error {
		family := unix.AF_INET
		if ip.Is6() {
			family = unix.AF_INET6
		}
		kind := unix.SOCK_STREAM
		if network == "udp" {
			kind = unix.SOCK_DGRAM
		}
		var e error
		fd, e = unix.Socket(family, kind|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		return e
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	if mark != 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, mark); err != nil {
			return nil, fmt.Errorf("mark trusted project socket: %w", err)
		}
	}
	var destination unix.Sockaddr
	if ip.Is6() {
		destination = &unix.SockaddrInet6{Port: p, Addr: ip.As16()}
	} else {
		destination = &unix.SockaddrInet4{Port: p, Addr: ip.As4()}
	}
	err = unix.Connect(fd, destination)
	if err != nil && !errors.Is(err, unix.EINPROGRESS) {
		return nil, err
	}
	deadline := time.Now().Add(10 * time.Second)
	for errors.Is(err, unix.EINPROGRESS) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("namespace connection timed out")
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		n, e := unix.Poll(poll, 100)
		if e != nil && e != unix.EINTR {
			return nil, e
		}
		if n > 0 {
			code, e := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
			if e != nil {
				return nil, e
			}
			if code != 0 {
				return nil, syscallError(code)
			}
			err = nil
		}
	}
	file := os.NewFile(uintptr(fd), "project-network-socket")
	fd = -1
	defer file.Close()
	return net.FileConn(file)
}
func syscallError(code int) error { return unix.Errno(code) }
