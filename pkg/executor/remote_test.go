package executor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/go-pkgz/fileutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestExecuter_UploadAndDownload(t *testing.T) {
	ctx := context.Background()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	c, err := NewConnector("testdata/test_ssh_key", time.Second*10, MakeLogs(true, false, nil))
	require.NoError(t, err)

	sess, err := c.Connect(ctx, hostAndPort, "h1", "test", []string{})
	require.NoError(t, err)
	defer sess.Close()

	err = sess.Upload(ctx, "testdata/data1.txt", "/tmp/blah/data1.txt", &UpDownOpts{Mkdir: true})
	require.NoError(t, err)

	tmpFile, err := fileutils.TempFileName("", "data1.txt")
	require.NoError(t, err)
	defer os.RemoveAll(tmpFile)
	err = sess.Download(ctx, "/tmp/blah/data1.txt", tmpFile, &UpDownOpts{Mkdir: true})
	require.NoError(t, err)
	assert.FileExists(t, tmpFile)
	exp, err := os.ReadFile("testdata/data1.txt")
	require.NoError(t, err)
	act, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	assert.Equal(t, string(exp), string(act))
}

func TestExecuter_UploadGlobAndDownload(t *testing.T) {
	ctx := context.Background()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	c, err := NewConnector("testdata/test_ssh_key", time.Second*10, MakeLogs(true, false, nil))
	require.NoError(t, err)

	sess, err := c.Connect(ctx, hostAndPort, "h1", "test", []string{})
	require.NoError(t, err)
	defer sess.Close()

	err = sess.Upload(ctx, "testdata/data*.txt", "/tmp/blah", &UpDownOpts{Mkdir: true, Exclude: []string{"data3.txt"}})
	require.NoError(t, err)

	{
		tmpFile, err := fileutils.TempFileName("", "data1.txt")
		require.NoError(t, err)
		defer os.RemoveAll(tmpFile)
		err = sess.Download(ctx, "/tmp/blah/data1.txt", tmpFile, &UpDownOpts{Mkdir: true})
		require.NoError(t, err)
		assert.FileExists(t, tmpFile)
		exp, err := os.ReadFile("testdata/data1.txt")
		require.NoError(t, err)
		act, err := os.ReadFile(tmpFile)
		require.NoError(t, err)
		assert.Equal(t, string(exp), string(act))
	}
	{
		tmpFile, err := fileutils.TempFileName("", "data2.txt")
		require.NoError(t, err)
		defer os.RemoveAll(tmpFile)
		err = sess.Download(ctx, "/tmp/blah/data2.txt", tmpFile, &UpDownOpts{Mkdir: true})
		require.NoError(t, err)
		assert.FileExists(t, tmpFile)
		exp, err := os.ReadFile("testdata/data2.txt")
		require.NoError(t, err)
		act, err := os.ReadFile(tmpFile)
		require.NoError(t, err)
		assert.Equal(t, string(exp), string(act))
	}
	{
		tmpDir, err := os.MkdirTemp("", "test")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)
		err = sess.Download(ctx, "/tmp/blah/data*.txt", tmpDir, &UpDownOpts{Mkdir: true, Exclude: []string{"data2.txt"}})
		require.NoError(t, err)
		assert.FileExists(t, filepath.Join(tmpDir, "data1.txt"))
		exp, err := os.ReadFile("testdata/data1.txt")
		require.NoError(t, err)
		act, err := os.ReadFile(filepath.Join(tmpDir, "data1.txt"))
		require.NoError(t, err)
		assert.Equal(t, string(exp), string(act))
		assert.NoFileExists(t, filepath.Join(tmpDir, "data2.txt"), "remote file should be downloaded")
		assert.NoFileExists(t, filepath.Join(tmpDir, "data3.txt"), "remote file should be downloaded")
	}
}

func TestExecuter_Upload_FailedSourceNotFound(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	c, err := NewConnector("testdata/test_ssh_key", time.Second*10, MakeLogs(true, false, nil))
	require.NoError(t, err)
	sess, err := c.Connect(ctx, hostAndPort, "h1", "test", []string{})
	require.NoError(t, err)
	defer sess.Close()

	err = sess.Upload(ctx, "testdata/data-not-found.txt", "/tmp/blah/data.txt", &UpDownOpts{Mkdir: true})
	require.EqualError(t, err, "source file \"testdata/data-not-found.txt\" not found")
}

func TestExecuter_Upload_FailedNoRemoteDir(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	c, err := NewConnector("testdata/test_ssh_key", time.Second*10, MakeLogs(true, false, nil))
	require.NoError(t, err)
	sess, err := c.Connect(ctx, hostAndPort, "h1", "test", []string{})
	require.NoError(t, err)
	defer sess.Close()

	err = sess.Upload(ctx, "testdata/data1.txt", "/tmp/blah/data1.txt", nil)
	require.EqualError(t, err, `failed to create remote file "/tmp/blah/data1.txt": file does not exist`)
}

func TestExecuter_Upload_CantMakeRemoteDir(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	c, err := NewConnector("testdata/test_ssh_key", time.Second*10, MakeLogs(true, false, nil))
	require.NoError(t, err)
	sess, err := c.Connect(ctx, hostAndPort, "h1", "test", []string{})
	require.NoError(t, err)
	defer sess.Close()

	err = sess.Upload(ctx, "testdata/data1.txt", "/dev/blah/data1.txt", &UpDownOpts{Mkdir: true})
	require.EqualError(t, err, `failed to create remote directory "/dev/blah": permission denied`)
}

func TestExecuter_Upload_Canceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	c, err := NewConnector("testdata/test_ssh_key", time.Second*10, MakeLogs(true, false, nil))
	require.NoError(t, err)
	sess, err := c.Connect(ctx, hostAndPort, "h1", "test", []string{})
	require.NoError(t, err)
	defer sess.Close()

	cancel()
	err = sess.Upload(ctx, "testdata/data1.txt", "/tmp/blah/data1.txt", &UpDownOpts{Mkdir: true})
	require.EqualError(t, err, `failed to copy file "/tmp/blah/data1.txt": context canceled`)
}

func TestExecuter_UploadCanceledWithoutMkdir(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	c, err := NewConnector("testdata/test_ssh_key", time.Second*10, MakeLogs(true, false, nil))
	require.NoError(t, err)
	sess, err := c.Connect(ctx, hostAndPort, "h1", "test", []string{})
	require.NoError(t, err)
	defer sess.Close()

	cancel()

	err = sess.Upload(ctx, "testdata/data1.txt", "/tmp/data1.txt", nil)
	require.EqualError(t, err, "failed to copy file \"/tmp/data1.txt\": context canceled")
}

func TestUpload_UploadOverwriteWithAndWithoutForce(t *testing.T) {
	ctx := context.Background()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	c, err := NewConnector("testdata/test_ssh_key", time.Second*10, MakeLogs(true, false, nil))
	require.NoError(t, err)

	sess, err := c.Connect(ctx, hostAndPort, "h1", "test", []string{})
	require.NoError(t, err)
	defer sess.Close()

	wr := &bytes.Buffer{}
	log.SetOutput(io.MultiWriter(wr, os.Stdout))

	// first upload
	err = sess.Upload(ctx, "testdata/data1.txt", "testdata/data2.txt", &UpDownOpts{Mkdir: true})
	require.NoError(t, err)
	assert.NotContains(t, wr.String(), " skipping upload")
	wr.Reset()

	// attempt to upload again without force
	err = sess.Upload(ctx, "testdata/data1.txt", "testdata/data2.txt", &UpDownOpts{Mkdir: true})
	assert.NoError(t, err)
	assert.Contains(t, wr.String(), "remote file testdata/data2.txt identical to local file testdata/data1.txt, skipping upload")
	wr.Reset()

	// attempt to upload again with force
	err = sess.Upload(ctx, "testdata/data1.txt", "testdata/data2.txt", &UpDownOpts{Mkdir: true, Force: true})
	assert.NoError(t, err)
	assert.NotContains(t, wr.String(), "skipping upload")
}

func TestExecuter_ConnectCanceled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
	defer cancel()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	c, err := NewConnector("testdata/test_ssh_key", time.Second*10, MakeLogs(true, false, nil))
	require.NoError(t, err)
	_, err = c.Connect(ctx, hostAndPort, "h1", "test", []string{})
	assert.ErrorContains(t, err, "failed to dial: dial tcp: lookup localhost: i/o timeout")
}

func TestExecuter_Run(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	logs := MakeLogs(true, false, nil)
	c, err := NewConnector("testdata/test_ssh_key", time.Second*10, logs)
	require.NoError(t, err)
	sess, err := c.Connect(ctx, hostAndPort, "h1", "test", []string{})
	require.NoError(t, err)
	defer sess.Close()

	t.Run("single line out", func(t *testing.T) {
		out, e := sess.Run(ctx, "sh -c 'echo hello world'", nil)
		require.NoError(t, e)
		assert.Equal(t, []string{"hello world"}, out)
	})

	t.Run("multi line out", func(t *testing.T) {
		err = sess.Upload(ctx, "testdata/data1.txt", "/tmp/st/data1.txt", &UpDownOpts{Mkdir: true})
		assert.NoError(t, err)
		err = sess.Upload(ctx, "testdata/data2.txt", "/tmp/st/data2.txt", &UpDownOpts{Mkdir: true})
		assert.NoError(t, err)

		out, err := sess.Run(ctx, "ls -1 /tmp/st", nil)
		require.NoError(t, err)
		t.Logf("out: %v", out)
		assert.Equal(t, 2, len(out))
		assert.Equal(t, "data1.txt", out[0])
		assert.Equal(t, "data2.txt", out[1])
	})

	t.Run("find out", func(t *testing.T) {
		cmd := fmt.Sprintf("find %s -type f -exec stat -c '%%n:%%s' {} \\;", "/tmp/")
		out, e := sess.Run(ctx, cmd, &RunOpts{Verbose: true})
		require.NoError(t, e)
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		assert.Equal(t, []string{"/tmp/st/data1.txt:13", "/tmp/st/data2.txt:13"}, out)
	})

	t.Run("with secrets", func(t *testing.T) {

		capturedStdout := captureStdOut(t, func() {
			c, err := NewConnector("testdata/test_ssh_key", time.Second*10, MakeLogs(true, false, []string{"data2"}))
			require.NoError(t, err)
			session, err := c.Connect(ctx, hostAndPort, "h1", "test", []string{})
			require.NoError(t, err)
			defer session.Close()

			err = session.Upload(ctx, "testdata/data1.txt", "/tmp/st/data1.txt", &UpDownOpts{Mkdir: true})
			assert.NoError(t, err)
			err = session.Upload(ctx, "testdata/data2.txt", "/tmp/st/data2.txt", &UpDownOpts{Mkdir: true})
			assert.NoError(t, err)

			cmd := fmt.Sprintf("find %s -type f -exec stat -c '%%n:%%s' {} \\;", "/tmp/")
			out, e := session.Run(ctx, cmd, &RunOpts{Verbose: true})
			require.NoError(t, e)
			t.Logf("out: %v", out)
			sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
			assert.Equal(t, []string{"/tmp/st/data1.txt:13", "/tmp/st/data2.txt:13"}, out)
		})

		t.Logf("capturedStdout: %s", capturedStdout)
		assert.NotContains(t, capturedStdout, "data2", "captured stdout should not contain secrets")
		assert.Contains(t, capturedStdout, "****", "captured stdout should contain masked secrets")
	})

	t.Run("command failed", func(t *testing.T) {
		_, err := sess.Run(ctx, "sh -c 'exit 1'", nil)
		assert.ErrorContains(t, err, "failed to run command on remote server")
	})

	t.Run("ctx canceled", func(t *testing.T) {
		ctxCancel, cancel := context.WithCancel(ctx)
		cancel()
		_, err := sess.Run(ctxCancel, "sh -c 'echo hello world'", nil)
		assert.ErrorContains(t, err, "context canceled")
	})

}

func TestExecuter_Sync(t *testing.T) {
	ctx := context.Background()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	c, err := NewConnector("testdata/test_ssh_key", time.Second*10, MakeLogs(true, false, nil))
	require.NoError(t, err)
	sess, err := c.Connect(ctx, hostAndPort, "h1", "test", []string{})
	require.NoError(t, err)
	defer sess.Close()

	t.Run("sync", func(t *testing.T) {
		res, e := sess.Sync(ctx, "testdata/sync", "/tmp/sync.dest", &SyncOpts{Delete: true})
		require.NoError(t, e)
		sort.Slice(res, func(i, j int) bool { return res[i] < res[j] })
		assert.Equal(t, []string{"d1/file11.txt", "file1.txt", "file2.txt"}, res)
		out, e := sess.Run(ctx, "find /tmp/sync.dest -type f -exec stat -c '%s %n' {} \\;", &RunOpts{Verbose: true})
		require.NoError(t, e)
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		assert.Equal(t, []string{"17 /tmp/sync.dest/d1/file11.txt", "185 /tmp/sync.dest/file1.txt", "61 /tmp/sync.dest/file2.txt"}, out)

		res, e = sess.Sync(ctx, "testdata/sync", "/tmp/sync.dest", &SyncOpts{Delete: true})
		require.NoError(t, e)
		assert.Equal(t, 0, len(res), "no files should be synced", res)
	})

	t.Run("sync no src", func(t *testing.T) {
		_, err = sess.Sync(ctx, "/tmp/no-such-place", "/tmp/sync.dest", &SyncOpts{Delete: true})
		require.EqualError(t, err, "failed to get local files properties for /tmp/no-such-place: failed to walk local directory"+
			" /tmp/no-such-place: lstat /tmp/no-such-place: no such file or directory")
	})

	t.Run("sync with empty dir on remote to delete", func(t *testing.T) {
		_, e := sess.Run(ctx, "mkdir -p /tmp/sync.dest2/empty", &RunOpts{Verbose: true})
		require.NoError(t, e)
		res, e := sess.Sync(ctx, "testdata/sync", "/tmp/sync.dest2", &SyncOpts{Delete: true})
		require.NoError(t, e)
		sort.Slice(res, func(i, j int) bool { return res[i] < res[j] })
		assert.Equal(t, []string{"d1/file11.txt", "file1.txt", "file2.txt"}, res)
		out, e := sess.Run(ctx, "find /tmp/sync.dest2 -type f -exec stat -c '%s %n' {} \\;", &RunOpts{Verbose: true})
		require.NoError(t, e)
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		assert.Equal(t, []string{"17 /tmp/sync.dest2/d1/file11.txt", "185 /tmp/sync.dest2/file1.txt", "61 /tmp/sync.dest2/file2.txt"}, out)
	})

	t.Run("sync with non-empty dir on remote to delete", func(t *testing.T) {
		_, e := sess.Run(ctx, "mkdir -p /tmp/sync.dest3/empty", &RunOpts{Verbose: true})
		require.NoError(t, e)
		_, e = sess.Run(ctx, "touch /tmp/sync.dest3/empty/afile1.txt", &RunOpts{Verbose: true})
		require.NoError(t, e)
		res, e := sess.Sync(ctx, "testdata/sync", "/tmp/sync.dest3", &SyncOpts{Delete: true})
		require.NoError(t, e)
		sort.Slice(res, func(i, j int) bool { return res[i] < res[j] })
		assert.Equal(t, []string{"d1/file11.txt", "file1.txt", "file2.txt"}, res)
		out, e := sess.Run(ctx, "find /tmp/sync.dest3 -type f -exec stat -c '%s %n' {} \\;", &RunOpts{Verbose: true})
		require.NoError(t, e)
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		assert.Equal(t, []string{"17 /tmp/sync.dest3/d1/file11.txt", "185 /tmp/sync.dest3/file1.txt", "61 /tmp/sync.dest3/file2.txt"}, out)
	})

	t.Run("sync  with non-empty dir on remote to keep", func(t *testing.T) {
		_, e := sess.Run(ctx, "mkdir -p /tmp/sync.dest4/empty", &RunOpts{Verbose: true})
		require.NoError(t, e)
		_, e = sess.Run(ctx, "touch /tmp/sync.dest4/empty/afile1.txt", &RunOpts{Verbose: true})
		require.NoError(t, e)
		res, e := sess.Sync(ctx, "testdata/sync", "/tmp/sync.dest4", nil)
		require.NoError(t, e)
		sort.Slice(res, func(i, j int) bool { return res[i] < res[j] })
		assert.Equal(t, []string{"d1/file11.txt", "file1.txt", "file2.txt"}, res)
		out, e := sess.Run(ctx, "find /tmp/sync.dest4 -type f -exec stat -c '%s %n' {} \\;", &RunOpts{Verbose: true})
		require.NoError(t, e)
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		assert.Equal(t, []string{"0 /tmp/sync.dest4/empty/afile1.txt", "17 /tmp/sync.dest4/d1/file11.txt",
			"185 /tmp/sync.dest4/file1.txt", "61 /tmp/sync.dest4/file2.txt"}, out)
	})
}

func TestExecuter_Delete(t *testing.T) {
	ctx := context.Background()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	c, err := NewConnector("testdata/test_ssh_key", time.Second*10, MakeLogs(true, false, nil))
	require.NoError(t, err)
	sess, err := c.Connect(ctx, hostAndPort, "h1", "test", []string{})
	require.NoError(t, err)
	defer sess.Close()

	res, err := sess.Sync(ctx, "testdata/sync", "/tmp/sync.dest", &SyncOpts{Delete: true})
	require.NoError(t, err)
	sort.Slice(res, func(i, j int) bool { return res[i] < res[j] })
	assert.Equal(t, []string{"d1/file11.txt", "file1.txt", "file2.txt"}, res)

	t.Run("delete file", func(t *testing.T) {
		err = sess.Delete(ctx, "/tmp/sync.dest/file1.txt", nil)
		assert.NoError(t, err)
		out, e := sess.Run(ctx, "ls -1 /tmp/sync.dest", nil)
		require.NoError(t, e)
		assert.Equal(t, []string{"d1", "file2.txt"}, out)
	})

	t.Run("delete dir non-recursive", func(t *testing.T) {
		err = sess.Delete(ctx, "/tmp/sync.dest", nil)
		require.Error(t, err)
	})

	t.Run("delete dir", func(t *testing.T) {
		err = sess.Delete(ctx, "/tmp/sync.dest", &DeleteOpts{Recursive: true})
		assert.NoError(t, err)
		out, e := sess.Run(ctx, "ls -1 /tmp/", &RunOpts{Verbose: true})
		require.NoError(t, e)
		assert.NotContains(t, out, "file2.txt", out)
	})

	t.Run("delete empty dir", func(t *testing.T) {
		_, err = sess.Run(ctx, "mkdir -p /tmp/sync.dest/empty", &RunOpts{Verbose: true})
		require.NoError(t, err)
		out, e := sess.Run(ctx, "ls -1 /tmp/sync.dest", &RunOpts{Verbose: true})
		require.NoError(t, e)
		assert.Contains(t, out, "empty", out)
		err = sess.Delete(ctx, "/tmp/sync.dest/empty", nil)
		assert.NoError(t, err)
		out, e = sess.Run(ctx, "ls -1 /tmp/sync.dest", &RunOpts{Verbose: true})
		require.NoError(t, e)
		assert.NotContains(t, out, "empty", out)
	})

	t.Run("delete no-such-file", func(t *testing.T) {
		err = sess.Delete(ctx, "/tmp/sync.dest/no-such-file", nil)
		assert.NoError(t, err)
	})

	t.Run("delete no-such-dir", func(t *testing.T) {
		err = sess.Delete(ctx, "/tmp/sync.dest/no-such-dir", &DeleteOpts{Recursive: true})
		assert.NoError(t, err)
	})
}

func TestExecuter_DeleteWithExclude(t *testing.T) {
	ctx := context.Background()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	c, err := NewConnector("testdata/test_ssh_key", time.Second*10, MakeLogs(true, false, nil))
	require.NoError(t, err)
	sess, err := c.Connect(ctx, hostAndPort, "h1", "test", []string{})
	require.NoError(t, err)
	defer sess.Close()

	res, err := sess.Sync(ctx, "testdata/delete", "/tmp/delete.dest", &SyncOpts{Delete: true})
	require.NoError(t, err)
	sort.Slice(res, func(i, j int) bool { return res[i] < res[j] })
	assert.Equal(t, []string{"d1/file11.txt", "d1/file12.txt", "d2/file21.txt", "d2/file22.txt", "file1.txt", "file2.txt", "file3.txt"}, res)

	t.Run("delete dir with excluded files", func(t *testing.T) {
		err = sess.Delete(ctx, "/tmp/delete.dest", &DeleteOpts{Recursive: true, Exclude: []string{"file2.*", "d1/*", "d2/file21.txt"}})
		assert.NoError(t, err)
		out, e := sess.Run(ctx, "ls -1 /tmp/", &RunOpts{Verbose: true})
		require.NoError(t, e)
		assert.Contains(t, out, "delete.dest", out)

		out, e = sess.Run(ctx, "ls -1 /tmp/delete.dest", &RunOpts{Verbose: true})
		require.NoError(t, e)
		assert.Contains(t, out, "d1", out)
		assert.Contains(t, out, "d2", out)
		assert.Contains(t, out, "file2.txt", out)
		assert.NotContains(t, out, "file3.txt", out)

		out, e = sess.Run(ctx, "ls -1 /tmp/delete.dest/d1", &RunOpts{Verbose: true})
		require.NoError(t, e)
		assert.Contains(t, out, "file12.txt", out)

		out, e = sess.Run(ctx, "ls -1 /tmp/delete.dest/d2", &RunOpts{Verbose: true})
		require.NoError(t, e)
		assert.Contains(t, out, "file21.txt", out)
		assert.NotContains(t, out, "file22.txt", out)
	})
}

func TestRemote_CloseNoSession(t *testing.T) {
	sess := &Remote{}
	err := sess.Close()
	assert.NoError(t, err)
}

func TestExecuter_findUnmatchedFiles(t *testing.T) {
	tbl := []struct {
		name    string
		local   map[string]fileProperties
		remote  map[string]fileProperties
		exclude []string
		updated []string
		deleted []string
	}{
		{
			name: "all files match",
			local: map[string]fileProperties{
				"file1": {Size: 100, Time: time.Unix(0, 0)},
				"file2": {Size: 200, Time: time.Unix(0, 0)},
			},
			remote: map[string]fileProperties{
				"file1": {Size: 100, Time: time.Unix(0, 0)},
				"file2": {Size: 200, Time: time.Unix(0, 0)},
			},
			updated: []string{},
			deleted: []string{},
		},
		{
			name: "some files match",
			local: map[string]fileProperties{
				"file1": {Size: 100, Time: time.Unix(0, 0)},
				"file2": {Size: 200, Time: time.Unix(0, 0)},
			},
			remote: map[string]fileProperties{
				"file1": {Size: 100, Time: time.Unix(0, 0)},
				"file2": {Size: 200, Time: time.Unix(1, 1)},
			},
			updated: []string{"file2"},
			deleted: []string{},
		},
		{
			name: "no files match",
			local: map[string]fileProperties{
				"file1": {Size: 100, Time: time.Unix(0, 0)},
				"file2": {Size: 200, Time: time.Unix(0, 0)},
			},
			remote: map[string]fileProperties{
				"file1": {Size: 100, Time: time.Unix(1, 1)},
				"file2": {Size: 200, Time: time.Unix(1, 1)},
			},
			updated: []string{"file1", "file2"},
			deleted: []string{},
		},
		{
			name: "no files match, exclude file1",
			local: map[string]fileProperties{
				"file1": {Size: 100, Time: time.Unix(0, 0)},
				"file2": {Size: 200, Time: time.Unix(0, 0)},
			},
			remote: map[string]fileProperties{
				"file1": {Size: 100, Time: time.Unix(1, 1)},
				"file2": {Size: 200, Time: time.Unix(1, 1)},
			},
			exclude: []string{"file1"},
			updated: []string{"file2"},
			deleted: []string{},
		},
		{
			name: "some local files deleted",
			local: map[string]fileProperties{
				"file1": {Size: 100, Time: time.Unix(0, 0)},
				"file2": {Size: 200, Time: time.Unix(0, 0)},
			},
			remote: map[string]fileProperties{
				"file1": {Size: 100, Time: time.Unix(0, 0)},
				"file2": {Size: 200, Time: time.Unix(0, 0)},
				"file3": {Size: 300, Time: time.Unix(0, 0)},
			},
			updated: []string{},
			deleted: []string{"file3"},
		},
		{
			name: "some match, some excluded, some deleted",
			local: map[string]fileProperties{
				"d1/file1": {Size: 100, Time: time.Unix(0, 0)},
				"d1/file2": {Size: 200, Time: time.Unix(0, 0)},
				"d3/file2": {Size: 300, Time: time.Unix(0, 0)},
			},
			remote: map[string]fileProperties{
				"d1/file1": {Size: 100, Time: time.Unix(0, 0)},
				"d4/file2": {Size: 200, Time: time.Unix(0, 0)},
			},
			exclude: []string{"d1/*"},
			updated: []string{"d3/file2"},
			deleted: []string{"d4/file2"},
		},
	}

	for _, tc := range tbl {
		t.Run(tc.name, func(t *testing.T) {
			ex := &Remote{}
			updated, deleted := ex.findUnmatchedFiles(tc.local, tc.remote, tc.exclude)
			assert.Equal(t, tc.updated, updated)
			assert.Equal(t, tc.deleted, deleted)
		})
	}
}

func Test_getRemoteFilesProperties(t *testing.T) {
	ctx := context.Background()
	hostAndPort, teardown := startTestContainer(t)
	defer teardown()

	c, err := NewConnector("testdata/test_ssh_key", time.Second*10, MakeLogs(true, false, nil))
	require.NoError(t, err)

	sess, err := c.Connect(ctx, hostAndPort, "h1", "test", []string{})
	require.NoError(t, err)
	defer sess.Close()

	// create some test data on the remote host.
	_, err = sess.Run(ctx, "mkdir -p /tmp/testdata/dir1 /tmp/testdata/dir2 && echo 'Hello' > /tmp/testdata/dir1/file1.txt && echo 'World' > /tmp/testdata/dir2/file2.txt", &RunOpts{Verbose: true})
	require.NoError(t, err)

	props, err := sess.getRemoteFilesProperties(ctx, "/tmp/testdata", nil)
	require.NoError(t, err)

	// check if the file properties match what's expected.
	expected := map[string]fileProperties{
		"dir1/file1.txt": {
			Size:     6,
			FileName: "/tmp/testdata/dir1/file1.txt",
			IsDir:    false,
		},
		"dir2/file2.txt": {
			Size:     6,
			FileName: "/tmp/testdata/dir2/file2.txt",
			IsDir:    false,
		},
	}

	for path, prop := range props {
		t.Logf("path: %s, properties: %+v", path, prop)

		expectedProp, ok := expected[path]
		if !ok {
			t.Errorf("unexpected file: %s", path)
			continue
		}

		if prop.Size != expectedProp.Size || prop.FileName != expectedProp.FileName || prop.IsDir != expectedProp.IsDir {
			t.Errorf("properties of %s do not match. expected %+v, got %+v", path, expectedProp, prop)
		}
	}
}

func startTestContainer(t *testing.T) (hostAndPort string, teardown func()) {
	t.Helper()
	ctx := context.Background()
	pubKey, err := os.ReadFile("testdata/test_ssh_key.pub")
	require.NoError(t, err)

	req := testcontainers.ContainerRequest{
		AlwaysPullImage: true,
		Image:           "lscr.io/linuxserver/openssh-server:latest",
		ExposedPorts:    []string{"2222/tcp"},
		WaitingFor:      wait.NewLogStrategy("done.").WithStartupTimeout(time.Second * 60),
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
	if err != nil {
		t.Fatalf("failed to start container: %v", err)
	}

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "2222")
	require.NoError(t, err)
	return fmt.Sprintf("%s:%s", host, port.Port()), func() { container.Terminate(ctx) }
}

func start2TestContainers(t *testing.T) (hostAndPort1, hostAndPort2 string, teardown func()) {
	t.Helper()
	ctx := context.Background()
	pubKey, err := os.ReadFile("testdata/test_ssh_key.pub")
	require.NoError(t, err)

	// Create a custom network
	networkName := "test-network"

	networkRequest := testcontainers.NetworkRequest{
		Name:           networkName,
		CheckDuplicate: true,
	}
	network, err := testcontainers.GenericNetwork(ctx, testcontainers.GenericNetworkRequest{
		NetworkRequest: networkRequest,
	})
	require.NoError(t, err)

	// Define the container request
	containerRequest := func(name string) testcontainers.ContainerRequest {
		return testcontainers.ContainerRequest{
			AlwaysPullImage: true,
			Image:           "lscr.io/linuxserver/openssh-server:latest",
			ExposedPorts:    []string{"2222/tcp"},
			WaitingFor:      wait.NewLogStrategy("done.").WithStartupTimeout(time.Second * 60),
			Networks:        []string{networkName},
			NetworkAliases:  map[string][]string{networkName: {name}},
			Hostname:        name,
			Files: []testcontainers.ContainerFile{
				{HostFilePath: "testdata/test_ssh_key.pub", ContainerFilePath: "/authorized_key"},
			},
			Env: map[string]string{
				"PUBLIC_KEY":  string(pubKey),
				"USER_NAME":   "test",
				"TZ":          "Etc/UTC",
				"DOCKER_MODS": "linuxserver/mods:openssh-server-ssh-tunnel",
			},
		}
	}

	// Start the bastion container
	container1, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: containerRequest("bastion-host"),
		Started:          true,
	})
	require.NoError(t, err)

	// Start the container with final ssh connection
	container2, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: containerRequest("target-host"),
		Started:          true,
	})
	require.NoError(t, err)

	// Get the host and port for both containers
	host1, err := container1.Host(ctx)
	require.NoError(t, err)
	port1, err := container1.MappedPort(ctx, "2222")
	require.NoError(t, err)

	host2, err := container2.Host(ctx)
	require.NoError(t, err)
	port2, err := container2.MappedPort(ctx, "2222")
	require.NoError(t, err)

	teardown = func() {
		container1.Terminate(ctx)
		container2.Terminate(ctx)
		network.Remove(ctx)
	}

	return fmt.Sprintf("%s:%s", host1, port1.Port()), fmt.Sprintf("%s:%s", host2, port2.Port()), teardown
}
