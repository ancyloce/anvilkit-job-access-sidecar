package sockets

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// requireRoot gates the tests that forge credentials: claiming another PID
// or UID in SCM_CREDENTIALS needs CAP_SYS_ADMIN and CAP_SETUID. CI runs them
// under sudo with ANVILKIT_REQUIRE_ROOT_TESTS, which turns the skip into a
// failure.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		if os.Getenv("ANVILKIT_REQUIRE_ROOT_TESTS") != "" {
			t.Fatal("ANVILKIT_REQUIRE_ROOT_TESTS is set: forging peer credentials needs root")
		}
		t.Skip("forging peer credentials needs root")
	}
}

// forged is the identity a hostile peer claims: PID 1 and the candidate UID.
var forged = unix.UnixCredentials(&unix.Ucred{Pid: 1, Uid: 10001, Gid: 10001})

// TestForgedCredentialsTransferNoIdentity (SEC-03, PID transfer): a peer's
// identity is what the kernel reported at connect (SO_PEERCRED), never what
// the peer claims afterwards in SCM_CREDENTIALS. The test process is root
// and claims PID 1 and the candidate UID 10001.
func TestForgedCredentialsTransferNoIdentity(t *testing.T) {
	requireRoot(t)
	base := fmt.Sprintf("@anvilkit-sockets-test-%d-%d", os.Getpid(), time.Now().UnixNano())
	rejected := make(chan Peer, 4)
	layout, err := Create(base+"-trusted", base+"-candidate", 0, 10001, func(p Peer) { rejected <- p })
	require.NoError(t, err)
	t.Cleanup(layout.Close)
	accepted := make(chan *Conn, 4)
	for _, l := range []*Listener{layout.Trusted, layout.Candidate} {
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				accepted <- c.(*Conn)
			}
		}()
	}
	dial := func(name string) *net.UnixConn {
		t.Helper()
		c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: name, Net: "unix"})
		require.NoError(t, err)
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	payload := []byte("GET /v1/scope HTTP/1.1\r\n\r\n")

	t.Run("the candidate socket closes a root peer that claims the candidate UID", func(t *testing.T) {
		c := dial(layout.Candidate.Name)
		_, _, err := c.WriteMsgUnix(payload, forged, nil)
		require.NoError(t, err, "root may claim another PID and UID")
		select {
		case p := <-rejected:
			require.Equal(t, uint32(0), p.UID, "the kernel's UID, not the claimed 10001")
			require.Equal(t, int32(os.Getpid()), p.PID, "the kernel's PID, not the claimed 1")
		case c := <-accepted:
			t.Fatalf("a forged claim was accepted as %+v", c.Peer)
		case <-time.After(5 * time.Second):
			t.Fatal("the candidate listener neither accepted nor rejected the peer")
		}
	})

	t.Run("on the trusted socket the claim never becomes the binding", func(t *testing.T) {
		c := dial(layout.Trusted.Name)
		_, _, err := c.WriteMsgUnix(payload, forged, nil)
		require.NoError(t, err)
		var conn *Conn
		select {
		case conn = <-accepted:
		case <-time.After(5 * time.Second):
			t.Fatal("the trusted listener did not accept its own UID")
		}
		t.Cleanup(func() { _ = conn.Close() })
		require.Equal(t, Peer{UID: 0, GID: 0, PID: int32(os.Getpid())}, conn.Peer, "SO_PEERCRED at connect")
		// Without SO_PASSCRED the kernel delivers no credentials message: the
		// request arrives as sent and the peer stays the kernel's.
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 128)
		n, err := conn.Read(buf)
		require.NoError(t, err)
		require.Equal(t, payload, buf[:n])
		require.Equal(t, int32(os.Getpid()), conn.Peer.PID)
	})

	t.Run("a credentials message that does arrive is refused, never parsed", func(t *testing.T) {
		c := dial(layout.Trusted.Name)
		var conn *Conn
		select {
		case conn = <-accepted:
		case <-time.After(5 * time.Second):
			t.Fatal("the trusted listener did not accept its own UID")
		}
		t.Cleanup(func() { _ = conn.Close() })
		raw, err := conn.SyscallConn()
		require.NoError(t, err)
		var serr error
		require.NoError(t, raw.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) }))
		require.NoError(t, serr)
		_, _, err = c.WriteMsgUnix(payload, forged, nil)
		require.NoError(t, err)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(make([]byte, 128))
		require.Zero(t, n)
		require.True(t, errors.Is(err, ErrFDDelegation), "any control message closes the connection: %v", err)
		require.Equal(t, int32(os.Getpid()), conn.Peer.PID, "the binding is unchanged")
	})
}
