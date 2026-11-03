// Package sockets owns the DD-03 §5 socket layout of the access sidecar
// (DEC-045): two abstract-namespace Unix sockets bound inside the Pod,
// the trusted name and the candidate name, with no file, directory or
// mode behind them (an abstract name is scoped to the Pod's network
// namespace or sandbox, so another Pod cannot reach it, and it works the
// same under runc and gVisor). Every accepted connection is bound to the
// peer's kernel-reported credentials (SO_PEERCRED) and refuses ancillary
// data: a file descriptor delegated over either socket closes the
// connection, so neither a candidate nor a trusted client can hand the
// sidecar (or, through it, anyone) an open descriptor. The second binding
// of every request, the peer token, is the server package's.
package sockets

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrFDDelegation marks a connection that carried ancillary data.
var ErrFDDelegation = errors.New("ancillary data (file descriptor delegation) is refused")

// Peer is the kernel-reported identity of a connected process. The PID is
// 0 for a peer in another PID namespace (another container of the Pod)
// and is never a binding.
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
// accept: the first binding; the server's token check is the second.
type Listener struct {
	*net.UnixListener
	Name        string
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
	Trusted   *Listener
	Candidate *Listener
}

// Close closes both listeners.
func (l *Layout) Close() {
	if l.Trusted != nil {
		_ = l.Trusted.Close()
	}
	if l.Candidate != nil {
		_ = l.Candidate.Close()
	}
}

// IsAbstract reports whether name is an abstract-namespace socket name:
// a leading "@" (the NUL byte on the wire; Go's net package maps it).
func IsAbstract(name string) bool { return strings.HasPrefix(name, "@") && len(name) > 1 }

// Create binds the two abstract names. The sidecar is the Pod's native
// sidecar and binds before any client exists; a name already held
// (EADDRINUSE) refuses to serve rather than serving beside a squatter.
func Create(trustedName, candidateName string, trustedUID, candidateUID uint32, rejected func(Peer)) (*Layout, error) {
	trusted, err := listen(trustedName, trustedUID, rejected)
	if err != nil {
		return nil, err
	}
	candidate, err := listen(candidateName, candidateUID, rejected)
	if err != nil {
		_ = trusted.Close()
		return nil, err
	}
	return &Layout{Trusted: trusted, Candidate: candidate}, nil
}

func listen(name string, expectedUID uint32, rejected func(Peer)) (*Listener, error) {
	if !IsAbstract(name) {
		return nil, fmt.Errorf("sockets: %q is not an abstract socket name (a leading @)", name)
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: name, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("sockets: listen %s: %w", name, err)
	}
	return &Listener{UnixListener: l, Name: name, ExpectedUID: expectedUID, rejected: rejected}, nil
}
