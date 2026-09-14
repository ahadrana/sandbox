//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"syscall"
	"time"
	"unsafe"

	"github.com/agent-sandbox/platform/runtime/guest-supervisor"
)

// Minimal vsock listener using raw syscalls (stdlib-only: syscall.Sockaddr's
// implementation method is unexported, so bind/connect go through
// RawSyscall). All sockets are NONBLOCKING with userspace poll loops: a
// blocking RawSyscall parks the goroutine in-kernel without entersyscall,
// which makes the Go runtime's async preemption (SIGURG) live-lock the
// blocking accept/read against the constant signal storm (observed under
// strace as an endless accept4 ERESTARTSYS loop that never completes).
// os.NewFile is avoided for the same reason (netpoller mishandles AF_VSOCK).

const (
	afVsock      = 40
	vmaddrCIDAny = 0xFFFFFFFF
	sockStream   = 1
	sockNonblock = 0o0004000
	sockCloexec  = 0o2000000
	eagain       = syscall.EAGAIN
)

type vsockListener struct{ fd int }

type vsockConn struct{ fd int }

func (c *vsockConn) Read(p []byte) (int, error) {
	for {
		n, err := syscall.Read(c.fd, p)
		if err == eagain {
			time.Sleep(time.Millisecond)
			continue
		}
		if err == syscall.EINTR {
			continue
		}
		if n == 0 && err == nil {
			return 0, io.EOF
		}
		return n, err
	}
}

// Write loops until all of p is written (framing depends on it).
func (c *vsockConn) Write(p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := syscall.Write(c.fd, p[total:])
		if err == eagain {
			time.Sleep(time.Millisecond)
			continue
		}
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func (c *vsockConn) Close() error { return syscall.Close(c.fd) }

// sockaddrVM packs struct sockaddr_vm { family u16; reserved u16; port u32;
// cid u32; flags u8; zero[3]; } into RawSockaddrAny, native endianness
// (little on all supported KVM targets here).
func sockaddrVM(port, cid uint32) *syscall.RawSockaddrAny {
	var raw syscall.RawSockaddrAny
	raw.Addr.Family = afVsock
	data := (*[14]byte)(unsafe.Pointer(&raw.Addr.Data))
	binary.LittleEndian.PutUint16(data[0:2], 0)
	binary.LittleEndian.PutUint32(data[2:6], port)
	binary.LittleEndian.PutUint32(data[6:10], cid)
	return &raw
}

// listenVsock binds AF_VSOCK on port and listens.
func listenVsock(port, cid uint32) (*vsockListener, error) {
	fd, err := syscall.Socket(afVsock, sockStream|sockNonblock|sockCloexec, 0)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_VSOCK): %w", err)
	}
	raw := sockaddrVM(port, cid)
	if _, _, errno := syscall.RawSyscall(syscall.SYS_BIND, uintptr(fd), uintptr(unsafe.Pointer(raw)), 16); errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind vsock: %v", errno)
	}
	if err := syscall.Listen(fd, 64); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("listen vsock: %w", err)
	}
	return &vsockListener{fd: fd}, nil
}

func (l *vsockListener) accept() (*vsockConn, error) {
	// Raw accept4: syscall.Accept parses the peer address and rejects
	// AF_VSOCK (EAFNOSUPPORT), dropping the connection.
	for {
		var raw syscall.RawSockaddrAny
		ln := uint32(16)
		fd, _, errno := syscall.RawSyscall6(syscall.SYS_ACCEPT4, uintptr(l.fd), uintptr(unsafe.Pointer(&raw)), uintptr(unsafe.Pointer(&ln)), sockNonblock|sockCloexec, 0, 0)
		if errno == eagain {
			time.Sleep(2 * time.Millisecond)
			continue
		}
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return nil, errno
		}
		return &vsockConn{fd: int(fd)}, nil
	}
}

// debugDial connects to cid:port and exchanges one health frame (debug tool).
func debugDial(cid, port uint32) error {
	fd, err := syscall.Socket(afVsock, sockStream|sockNonblock|sockCloexec, 0)
	if err != nil {
		return err
	}
	raw := sockaddrVM(port, cid)
	for {
		_, _, errno := syscall.RawSyscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(raw)), 16)
		if errno == syscall.EINPROGRESS || errno == eagain {
			time.Sleep(time.Millisecond)
			// poll completion via SO_ERROR would go here; vsock connect to a
			// live listener completes fast, so retry-connect is not valid —
			// fall through to a blocking wait using getsockopt.
			var soerr uint32
			sl := uint32(4)
			if _, _, e2 := syscall.RawSyscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), syscall.SOL_SOCKET, syscall.SO_ERROR, uintptr(unsafe.Pointer(&soerr)), uintptr(unsafe.Pointer(&sl)), 0); e2 != 0 {
				return fmt.Errorf("getsockopt: %v", e2)
			}
			if soerr == 0 {
				break
			}
			if syscall.Errno(soerr) == syscall.EINPROGRESS || syscall.Errno(soerr) == eagain {
				continue
			}
			return fmt.Errorf("connect: %v", syscall.Errno(soerr))
		}
		if errno != 0 {
			return fmt.Errorf("connect: %v", errno)
		}
		break
	}
	conn := &vsockConn{fd: fd}
	if err := supervisor.WriteFrame(conn, supervisor.Request{Op: supervisor.OpHealth}); err != nil {
		return err
	}
	var resp supervisor.Response
	if err := supervisor.ReadFrame(conn, &resp); err != nil {
		return err
	}
	fmt.Printf("debug dial: got response ok=%v err=%q\n", resp.OK, resp.Error)
	return nil
}
