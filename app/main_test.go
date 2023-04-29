package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/umputun/simplotask/app/config"
)

func Test_main(t *testing.T) {
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	args := []string{"simplotask", "--dbg", "--file=runner/testdata/conf-local.yml", "--user=test", "--key=runner/testdata/test_ssh_key", "--target=" + hostAndPort}
	os.Args = args
	main()
}

func Test_runCompleted(t *testing.T) {
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	opts := options{
		SSHUser:      "test",
		SSHKey:       "runner/testdata/test_ssh_key",
		PlaybookFile: "runner/testdata/conf.yml",
		TaskName:     "task1",
		TargetName:   hostAndPort,
		Only:         []string{"wait"},
	}
	setupLog(true)
	st := time.Now()
	err := run(opts)
	require.NoError(t, err)
	assert.True(t, time.Since(st) >= 5*time.Second)
}

func Test_runCompletedAllTasks(t *testing.T) {
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	opts := options{
		SSHUser:      "test",
		SSHKey:       "runner/testdata/test_ssh_key",
		PlaybookFile: "runner/testdata/conf2.yml",
		TargetName:   hostAndPort,
		Dbg:          true,
	}
	setupLog(true)

	wr := &bytes.Buffer{}
	log.SetOutput(wr)

	st := time.Now()
	err := run(opts)
	t.Log("dbg: ", wr.String())
	require.NoError(t, err)
	assert.True(t, time.Since(st) >= 1*time.Second)
	assert.Contains(t, wr.String(), "task1")
	assert.Contains(t, wr.String(), "task2")
	assert.Contains(t, wr.String(), "all good, 123")
	assert.Contains(t, wr.String(), "good command 2")
	assert.Contains(t, wr.String(), "all good, 123 - foo-val bar-val")

}

func Test_runCanceled(t *testing.T) {
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	opts := options{
		SSHUser:      "test",
		SSHKey:       "runner/testdata/test_ssh_key",
		PlaybookFile: "runner/testdata/conf.yml",
		TaskName:     "task1",
		TargetName:   hostAndPort,
		Only:         []string{"wait"},
	}
	setupLog(true)
	go func() {
		err := run(opts)
		assert.ErrorContains(t, err, "remote command exited")
	}()

	time.Sleep(3 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	signal.NotifyContext(ctx, os.Interrupt)
}

func Test_sshUserAndKey(t *testing.T) {
	testCases := []struct {
		name         string
		opts         options
		conf         config.PlayBook
		expectedUser string
		expectedKey  string
	}{
		{
			name: "All defaults",
			opts: options{},
			conf: config.PlayBook{
				User:   "default_user",
				SSHKey: "default_key",
				Tasks:  map[string]config.Task{},
			},
			expectedUser: "default_user",
			expectedKey:  "default_key",
		},
		{
			name: "Task config overrides user",
			opts: options{
				TaskName: "test_task",
			},
			conf: config.PlayBook{
				User:   "default_user",
				SSHKey: "default_key",
				Tasks: map[string]config.Task{
					"test_task": {User: "task_user"},
				},
			},
			expectedUser: "task_user",
			expectedKey:  "default_key",
		},
		{
			name: "Command line overrides all",
			opts: options{
				TaskName: "test_task",
				SSHUser:  "cmd_user",
				SSHKey:   "cmd_key",
			},
			conf: config.PlayBook{
				User:   "default_user",
				SSHKey: "default_key",
				Tasks: map[string]config.Task{
					"test_task": {User: "task_user"},
				},
			},
			expectedUser: "cmd_user",
			expectedKey:  "cmd_key",
		},
		{
			name: "Tilde expansion in key path",
			opts: options{
				TaskName: "test_task",
				SSHUser:  "cmd_user",
				SSHKey:   "~/cmd_key",
			},
			conf: config.PlayBook{
				User:   "default_user",
				SSHKey: "~/default_key",
				Tasks: map[string]config.Task{
					"test_task": {User: "task_user"},
				},
			},
			expectedUser: "cmd_user",
			expectedKey:  fmt.Sprintf("%s/cmd_key", os.Getenv("HOME")),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			user, key := sshUserAndKey(tc.opts, &tc.conf)
			assert.Equal(t, tc.expectedUser, user, "user should match expected user")
			assert.Equal(t, tc.expectedKey, key, "key should match expected key")
		})
	}
}

func startTestContainer(t *testing.T) (hostAndPort string, teardown func()) {
	t.Helper()
	ctx := context.Background()
	pubKey, err := os.ReadFile("runner/testdata/test_ssh_key.pub")
	require.NoError(t, err)

	req := testcontainers.ContainerRequest{
		Image:        "lscr.io/linuxserver/openssh-server:latest",
		ExposedPorts: []string{"2222/tcp"},
		WaitingFor:   wait.NewLogStrategy("done.").WithStartupTimeout(time.Second * 60),
		Files: []testcontainers.ContainerFile{
			{HostFilePath: "runner/testdata/test_ssh_key.pub", ContainerFilePath: "/authorized_key"},
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

	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "2222")
	require.NoError(t, err)
	host, err := container.Host(ctx)
	require.NoError(t, err)
	return fmt.Sprintf("%s:%s", host, port.Port()), func() { container.Terminate(ctx) }
}
