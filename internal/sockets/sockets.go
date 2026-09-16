// Package sockets owns the DD-03 §5 socket layout of the access sidecar:
// one directory the sidecar creates (owner:0, 0711), trusted.sock
// (owner:0, 0660) and candidate.sock (owner:candidate, 0660). Every
// accepted connection is bound to the peer's kernel-reported credentials
// (SO_PEERCRED) and refuses ancillary data: a file descriptor delegated
// over either socket closes the connection, so neither a candidate nor a
// trusted client can hand the sidecar (or, through it, anyone) an open
// descriptor.
package sockets

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	TrustedName   = "trusted.sock"
	CandidateName = "candidate.sock"
)

// ErrFDDelegation marks a connection that carried ancillary data.
var ErrFDDelegation = errors.New("ancillary data (file descriptor delegation) is refused")

// Peer is the kernel-reported identity of a connected process.
type Peer struct {
	UID uint32
	GID uint32
	PID int32
}

// Conn is one accepted connection with its peer credentials. Read refuses
// ancillary data.
type Conn struct {
	*net.UnixConn
	Peer Peer
	oob  []byte
}

// Read receives with a control buffer so that a delegated descriptor is
// detected instead of silently installed: any control message closes the
// received descriptors and the connection.
func (c *Conn) Read(b []byte) (int, error) {
	n, oobn, flags, _, err := c.UnixConn.ReadMsgUnix(b, c.oob)
	if oobn > 0 || flags&unix.MSG_CTRUNC != 0 {
		closeReceived(c.oob[:oobn])
		_ = c.UnixConn.Close()
		return 0, ErrFDDelegation
	}
	return n, err
}

func closeReceived(oob []byte) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return
	}
	for i := range msgs {
		if msgs[i].Header.Level != unix.SOL_SOCKET || msgs[i].Header.Type != unix.SCM_RIGHTS {
			continue
		}
		fds, err := unix.ParseUnixRights(&msgs[i])
		if err != nil {
			continue
		}
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}
}

// Listener accepts on one socket and answers Conns carrying peer
// credentials. A peer whose UID is not the expected one is closed at
// accept: the file mode already keeps it out, this is the second check.
type Listener struct {
	*net.UnixListener
	Path        string
	ExpectedUID uint32
	rejected    func(Peer)
}

// Accept returns the next connection from the expected UID.
func (l *Listener) Accept() (net.Conn, error) {
	for {
		c, err := l.UnixListener.AcceptUnix()
		if err != nil {
			return nil, err
		}
		peer, err := peerOf(c)
		if err != nil || peer.UID != l.ExpectedUID {
			if l.rejected != nil {
				l.rejected(peer)
			}
			_ = c.Close()
			continue
		}
		return &Conn{UnixConn: c, Peer: peer, oob: make([]byte, 256)}, nil
	}
}

func peerOf(c *net.UnixConn) (Peer, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) { cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return Peer{}, err
	}
	if cerr != nil {
		return Peer{}, cerr
	}
	return Peer{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}, nil
}

// Layout is what Create established.
type Layout struct {
	Dir       string
	Trusted   *Listener
	Candidate *Listener
}

// Create makes the directory and both sockets with the DD-03 ownership and
// modes. It runs as the sidecar's own UID and needs no capability: the
// directory and the sockets are created by this process, their groups are
// set to groups this process is a member of (0 and the candidate's), and
// the modes are set explicitly. Every step verifies the result it
// produced, so an unexpected owner, group or mode refuses to serve rather
// than serving on a reachable socket.
func Create(dir string, trustedUID, candidateUID uint32, rejected func(Peer)) (*Layout, error) {
	self := uint32(os.Getuid())
	if err := os.MkdirAll(dir, 0o711); err != nil {
		return nil, fmt.Errorf("sockets: mkdir %s: %w", dir, err)
	}
	if err := own(dir, self, 0, 0o711|os.ModeDir, true); err != nil {
		return nil, err
	}
	for _, name := range []string{TrustedName, CandidateName} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("sockets: remove stale %s: %w", name, err)
		}
	}
	trusted, err := listen(filepath.Join(dir, TrustedName), self, 0, trustedUID, rejected)
	if err != nil {
		return nil, err
	}
	candidate, err := listen(filepath.Join(dir, CandidateName), self, candidateUID, candidateUID, rejected)
	if err != nil {
		_ = trusted.Close()
		return nil, err
	}
	return &Layout{Dir: dir, Trusted: trusted, Candidate: candidate}, nil
}

func listen(path string, owner, group, expectedUID uint32, rejected func(Peer)) (*Listener, error) {
	// A restrictive umask keeps the socket from being reachable between
	// bind and chmod.
	old := syscall.Umask(0o177)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, fmt.Errorf("sockets: listen %s: %w", path, err)
	}
	l.SetUnlinkOnClose(true)
	if err := own(path, owner, group, 0o660|os.ModeSocket, false); err != nil {
		_ = l.Close()
		return nil, err
	}
	return &Listener{UnixListener: l, Path: path, ExpectedUID: expectedUID, rejected: rejected}, nil
}

// own sets group and mode and verifies owner, group and mode afterwards.
func own(path string, owner, group uint32, mode os.FileMode, dir bool) error {
	if err := os.Chown(path, -1, int(group)); err != nil {
		return fmt.Errorf("sockets: chgrp %s to %d (the sidecar must be a member of that group): %w", path, group, err)
	}
	if err := os.Chmod(path, mode.Perm()); err != nil {
		return fmt.Errorf("sockets: chmod %s: %w", path, err)
	}
	return Verify(path, owner, group, mode, dir)
}

// Verify checks that a path has exactly the expected owner, group, mode and
// type.
func Verify(path string, owner, group uint32, mode os.FileMode, dir bool) error {
	st, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("sockets: stat %s: %w", path, err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("sockets: %s: no unix metadata", path)
	}
	if st.IsDir() != dir {
		return fmt.Errorf("sockets: %s: unexpected file type", path)
	}
	if !dir && st.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("sockets: %s is not a socket", path)
	}
	if sys.Uid != owner || sys.Gid != group {
		return fmt.Errorf("sockets: %s is owned by %d:%d, expected %d:%d", path, sys.Uid, sys.Gid, owner, group)
	}
	if st.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("sockets: %s has mode %o, expected %o", path, st.Mode().Perm(), mode.Perm())
	}
	return nil
}
