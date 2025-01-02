package executor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConnector_Connect(t *testing.T) {
	ctx := context.Background()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	t.Run("good connection", func(t *testing.T) {
		c, err := NewConnector("testdata/test_ssh_key", time.Second*10, MakeLogs(true, false, nil))
		require.NoError(t, err)
		sess, err := c.Connect(ctx, hostAndPort, "h1", "test", []string{})
		require.NoError(t, err)
		defer sess.Close()
	})

	t.Run("bad user", func(t *testing.T) {
		c, err := NewConnector("testdata/test_ssh_key", time.Second*10, MakeLogs(true, false, nil))
		require.NoError(t, err)
		_, err = c.Connect(ctx, hostAndPort, "h1", "test33", []string{})
		require.ErrorContains(t, err, "ssh: unable to authenticate")
	})

	t.Run("bad key", func(t *testing.T) {
		_, err := NewConnector("testdata/test_ssh_key33", time.Second*10, MakeLogs(true, false, nil))
		require.ErrorContains(t, err, "private key file \"testdata/test_ssh_key33\" does not exist", "test")
	})

	t.Run("wrong port", func(t *testing.T) {
		c, err := NewConnector("testdata/test_ssh_key", time.Second*10, MakeLogs(true, false, nil))
		require.NoError(t, err)
		_, err = c.Connect(ctx, "127.0.0.1:12345", "h1", "test", []string{})
		require.ErrorContains(t, err, "failed to dial: dial tcp 127.0.0.1:12345")
	})

	t.Run("timeout", func(t *testing.T) {
		c, err := NewConnector("testdata/test_ssh_key", time.Nanosecond, MakeLogs(true, false, nil))
		require.NoError(t, err)
		_, err = c.Connect(ctx, hostAndPort, "h1", "test", []string{})
		require.ErrorContains(t, err, "i/o timeout")
	})

	t.Run("unreachable host", func(t *testing.T) {
		c, err := NewConnector("testdata/test_ssh_key", time.Second, MakeLogs(true, false, nil))
		require.NoError(t, err)
		_, err = c.Connect(ctx, "10.255.255.1:22", "h1", "test", []string{})
		require.ErrorContains(t, err, "failed to dial: dial tcp 10.255.255.1:22: i/o timeout")
	})
}

func TestConnector_ConnectWithProxy(t *testing.T) {
	ctx := context.Background()

	bastionHostAndPort, _, teardown := start2TestContainers(t)
	defer teardown()

	t.Run("good connection", func(t *testing.T) {
		c, err := NewConnector("testdata/test_ssh_key", time.Second*10, MakeLogs(true, false, nil))
		require.NoError(t, err)
		sess, err := c.Connect(ctx, bastionHostAndPort, "bastion-host", "test", []string{})
		require.NoError(t, err)
		defer sess.Close()
	})

	// To test proxy command, the chain of connection will be next:
	// localhost -> localhost:<random_port> (this is also the bastion host) -> target-host:2222
	// In a real-world application, "target-host:2222" will be replaced with "%h:%p", but since
	// testcontainers returns "localhost:<random_port>" manually, overriding it.

	// "ssh -W" requires enabling AllowTcpForwarding, to enable it, modification was applied:
	// see pkg/executor/remote_test.go, env variable DOCKER_MODS on test container.
	// The "bastion-host" is a local host, and we are using a standard SSH client which tries to verify the host key;
	// to bypass this check, "-o StrictHostKeyChecking=no” was added to the proxy command.

	// There is a situation that I am not sure if it is a bug or should be handled on client/spot side.
	// If ssh server on proxy server works, but forbid TCP forwarding, go ssh client will connect but will not abort
	// the connection or return error, it will just print to terminal
	// "channel open failed: open failed: administratively prohibited: open failed".

	t.Run("good connection with proxy", func(t *testing.T) {
		c, err := NewConnector("testdata/test_ssh_key", time.Second*10, MakeLogs(true, false, nil))
		require.NoError(t, err)

		bastionAddr := strings.Split(bastionHostAndPort, ":")

		proxyCommand := []string{
			"ssh",
			"-W",
			"target-host:2222",
			"test@localhost",
			"-p",
			bastionAddr[1],
			"-i",
			"testdata/test_ssh_key",
			"-o",
			"StrictHostKeyChecking=no",
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		sess, err := c.Connect(ctx, "target-host:2222", "target-host", "test", proxyCommand)
		require.NoError(t, err)
		defer sess.Close()
	})

}

func TestSubstituteProxyCommand(t *testing.T) {
	tests := []struct {
		username     string
		address      string
		proxyCommand []string
		expected     []string
		expectError  bool
	}{
		{
			username:     "user",
			address:      "example.com:22",
			proxyCommand: []string{"ssh", "-W", "%h:%p", "%r@example.com"},
			expected:     []string{"ssh", "-W", "example.com:22", "user@example.com"},
			expectError:  false,
		},
		{
			username:     "user",
			address:      "example.com:22",
			proxyCommand: []string{"ssh", "-W", "%h:%p", "%r@example.com", "random arg with spaces"},
			expected:     []string{"ssh", "-W", "example.com:22", "user@example.com", "random arg with spaces"},
			expectError:  false,
		},
		{
			username:     "user",
			address:      "example.com",
			proxyCommand: []string{"ssh", "-W", "%h:%p", "%r@example.com"},
			expected:     nil,
			expectError:  true,
		},
		{
			username:     "user",
			address:      "example.com:22",
			proxyCommand: []string{},
			expected:     []string{},
			expectError:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			result, err := SubstituteProxyCommand(test.username, test.address, test.proxyCommand)
			if test.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.expected, result)
			}
		})
	}
}
