package runner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/umputun/simplotask/app/config"
	"github.com/umputun/simplotask/app/executor"
	"github.com/umputun/simplotask/app/runner/mocks"
)

func TestProcess_Run(t *testing.T) {
	ctx := context.Background()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	connector, err := executor.NewConnector("test", "testdata/test_ssh_key")
	require.NoError(t, err)
	conf, err := config.New("testdata/conf.yml", nil)
	require.NoError(t, err)

	p := Process{
		Concurrency: 1,
		Connector:   connector,
		Config:      conf,
		ColorWriter: executor.NewColorizedWriter(os.Stdout, "", ""),
	}
	_, err = p.Run(ctx, "task1", hostAndPort)
	require.NoError(t, err)
}

func TestProcess_RunVerbose(t *testing.T) {
	ctx := context.Background()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	log.SetOutput(io.Discard)
	connector, err := executor.NewConnector("test", "testdata/test_ssh_key")
	require.NoError(t, err)
	conf, err := config.New("testdata/conf.yml", nil)
	require.NoError(t, err)
	p := Process{
		Concurrency: 1,
		Connector:   connector,
		Config:      conf,
		ColorWriter: executor.NewColorizedWriter(os.Stdout, "", ""),
		Verbose:     true,
	}
	_, err = p.Run(ctx, "task1", hostAndPort)
	require.NoError(t, err)
}

func TestProcess_RunFailed(t *testing.T) {
	ctx := context.Background()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	connector, err := executor.NewConnector("test", "testdata/test_ssh_key")
	require.NoError(t, err)
	conf, err := config.New("testdata/conf.yml", nil)
	require.NoError(t, err)

	p := Process{
		Concurrency: 1,
		Connector:   connector,
		Config:      conf,
		ColorWriter: executor.NewColorizedWriter(os.Stdout, "", ""),
	}
	_, err = p.Run(ctx, "failed_task", hostAndPort)
	require.ErrorContains(t, err, `can't run command "bad command" on host`)
}

func TestProcess_RunFailed_WithOnError(t *testing.T) {
	ctx := context.Background()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	connector, err := executor.NewConnector("test", "testdata/test_ssh_key")
	require.NoError(t, err)
	conf, err := config.New("testdata/conf.yml", nil)
	require.NoError(t, err)

	p := Process{
		Concurrency: 1,
		Connector:   connector,
		Config:      conf,
		ColorWriter: executor.NewColorizedWriter(os.Stdout, "", ""),
	}

	var buf bytes.Buffer
	log.SetOutput(&buf)

	_, err = p.Run(ctx, "failed_task_with_onerror", hostAndPort)
	require.ErrorContains(t, err, `can't run command "bad command" on host`)
	t.Log(buf.String())
	require.Contains(t, buf.String(), "onerror called")
}

func TestProcess_RunFailedErrIgnored(t *testing.T) {
	ctx := context.Background()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	connector, err := executor.NewConnector("test", "testdata/test_ssh_key")
	require.NoError(t, err)
	conf, err := config.New("testdata/conf.yml", nil)
	require.NoError(t, err)
	conf.Tasks["failed_task"].Commands[1].Options.IgnoreErrors = true
	p := Process{
		Concurrency: 1,
		Connector:   connector,
		Config:      conf,
		ColorWriter: executor.NewColorizedWriter(os.Stdout, "", ""),
	}
	_, err = p.Run(ctx, "failed_task", hostAndPort)
	require.NoError(t, err, "error ignored")
}

func TestProcess_RunTaskWithWait(t *testing.T) {
	ctx := context.Background()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	connector, err := executor.NewConnector("test", "testdata/test_ssh_key")
	require.NoError(t, err)
	conf, err := config.New("testdata/conf.yml", nil)
	require.NoError(t, err)

	p := Process{
		Concurrency: 1,
		Connector:   connector,
		Config:      conf,
		ColorWriter: executor.NewColorizedWriter(os.Stdout, "", ""),
	}

	var buf bytes.Buffer
	log.SetOutput(&buf)

	_, err = p.Run(ctx, "with_wait", hostAndPort)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "wait done")
}

func TestProcess_applyTemplates(t *testing.T) {
	tests := []struct {
		name     string
		inp      string
		user     string
		tdata    templateData
		expected string
	}{
		{
			name: "all_variables",
			inp:  "${SPOT_REMOTE_HOST}:${SPOT_REMOTE_USER}:${SPOT_COMMAND}",
			user: "user",
			tdata: templateData{
				host:    "example.com",
				command: "ls",
				task:    &config.Task{Name: "task1"},
			},
			expected: "example.com:user:ls",
		},
		{
			name: "no_variables",
			inp:  "no_variables_here",
			user: "user",
			tdata: templateData{
				host:    "example.com",
				command: "ls",
				task:    &config.Task{Name: "task1"},
			},
			expected: "no_variables_here",
		},
		{
			name: "single_dollar_variable",
			inp:  "$SPOT_REMOTE_HOST:$SPOT_REMOTE_USER:$SPOT_COMMAND",
			user: "user",
			tdata: templateData{
				host:    "example.com",
				command: "ls",
				task:    &config.Task{Name: "task1"},
			},
			expected: "example.com:user:ls",
		},
		{
			name: "mixed_variables",
			inp:  "{SPOT_REMOTE_HOST}:$SPOT_REMOTE_USER:${SPOT_COMMAND}:{SPOT_TASK}",
			user: "user2",
			tdata: templateData{
				host:    "example.com",
				command: "ls",
				task:    &config.Task{Name: "task1"},
			},
			expected: "example.com:user2:ls:task1",
		},
		{
			name: "escaped_variables",
			inp:  "\\${SPOT_REMOTE_HOST}:\\$SPOT_REMOTE_USER:\\${SPOT_COMMAND}",
			user: "user",
			tdata: templateData{
				host:    "example.com",
				command: "ls",
				task:    &config.Task{Name: "task1"},
			},
			expected: "\\example.com:\\user:\\ls",
		},
		{
			name: "variables with normal text",
			inp:  "${SPOT_REMOTE_HOST} blah ${SPOT_TASK} ${SPOT_REMOTE_USER}:${SPOT_COMMAND}",
			user: "user2",
			tdata: templateData{
				host:    "example.com",
				command: "ls",
				task:    &config.Task{Name: "task1"},
			},
			expected: "example.com blah task1 user2:ls",
		},
		{
			name: "with error msg",
			inp:  "$SPOT_REMOTE_HOST:$SPOT_REMOTE_USER:$SPOT_COMMAND ${SPOT_ERROR}",
			user: "user",
			tdata: templateData{
				host:    "example.com",
				command: "ls",
				task:    &config.Task{Name: "task1"},
				err:     fmt.Errorf("some error"),
			},
			expected: "example.com:user:ls some error",
		},
		{
			name: "with error msg but no error",
			inp:  "$SPOT_REMOTE_HOST:$SPOT_REMOTE_USER:$SPOT_COMMAND ${SPOT_ERROR}",
			user: "user",
			tdata: templateData{
				host:    "example.com",
				command: "ls",
				task:    &config.Task{Name: "task1"},
				err:     nil,
			},
			expected: "example.com:user:ls ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &mocks.ConnectorMock{UserFunc: func() string { return tt.user }}
			p := Process{Connector: c}
			actual := p.applyTemplates(tt.inp, tt.tdata)
			require.Equal(t, tt.expected, actual)
		})
	}
}

func TestProcess_waitPassed(t *testing.T) {
	ctx := context.Background()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	connector, err := executor.NewConnector("test", "testdata/test_ssh_key")
	require.NoError(t, err)
	sess, err := connector.Connect(ctx, hostAndPort)
	require.NoError(t, err)

	p := Process{Connector: connector}
	time.AfterFunc(time.Second, func() {
		_, _ = sess.Run(ctx, "touch /tmp/wait.done", false)
	})
	err = p.wait(ctx, sess, config.WaitInternal{Timeout: 2 * time.Second, CheckDuration: time.Millisecond * 100,
		Command: "cat /tmp/wait.done"})
	require.NoError(t, err)
}

func TestProcess_waitFailed(t *testing.T) {
	ctx := context.Background()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	connector, err := executor.NewConnector("test", "testdata/test_ssh_key")
	require.NoError(t, err)
	sess, err := connector.Connect(ctx, hostAndPort)
	require.NoError(t, err)

	p := Process{Connector: connector}
	err = p.wait(ctx, sess, config.WaitInternal{Timeout: 2 * time.Second, CheckDuration: time.Millisecond * 100,
		Command: "cat /tmp/wait.done"})
	require.EqualError(t, err, "timeout exceeded")
}

func startTestContainer(t *testing.T) (hostAndPort string, teardown func()) {
	t.Helper()
	ctx := context.Background()
	pubKey, err := os.ReadFile("testdata/test_ssh_key.pub")
	require.NoError(t, err)

	req := testcontainers.ContainerRequest{
		Image:        "lscr.io/linuxserver/openssh-server:latest",
		ExposedPorts: []string{"2222/tcp"},
		WaitingFor:   wait.NewLogStrategy("done.").WithStartupTimeout(time.Second * 60),
		Files: []testcontainers.ContainerFile{
			{HostFilePath: "testdata/test_ssh_key.pub", ContainerFilePath: "/authorized_key"},
		},
		Env: map[string]string{
			"PUBLIC_KEY": string(pubKey),
			"USER_NAME":  "test",
			"TZ":         "Etc/UTC",
		},
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "2222")
	require.NoError(t, err)
	return fmt.Sprintf("%s:%s", host, port.Port()), func() { container.Terminate(ctx) }
}
