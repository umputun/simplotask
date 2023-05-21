// Package executor provides an interface for the executor as well as a local and remote implementation.
// The executor is used to run commands on the local machine or on a remote machine.
package executor

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
)

// Interface is an interface for the executor.
// Implemented by Remote and Local structs.
type Interface interface {
	SetSecrets(secrets []string)
	Run(ctx context.Context, c string, opts *RunOpts) (out []string, err error)
	Upload(ctx context.Context, local, remote string, opts *UpDownOpts) (err error)
	Download(ctx context.Context, remote, local string, opts *UpDownOpts) (err error)
	Sync(ctx context.Context, localDir, remoteDir string, opts *SyncOpts) ([]string, error)
	Delete(ctx context.Context, remoteFile string, opts *DeleteOpts) (err error)
	Close() error
}

// RunOpts is a struct for run options.
type RunOpts struct {
	Verbose bool // print more info to primary stdout
}

// UpDownOpts is a struct for upload and download options.
type UpDownOpts struct {
	Mkdir    bool // create remote directory if it does not exist
	Checksum bool // compare checksums of local and remote files, default is size and modtime
	Force    bool // overwrite existing files on remote
}

// SyncOpts is a struct for sync options.
type SyncOpts struct {
	Delete   bool     // delete extra files on remote
	Exclude  []string // exclude files matching the given patterns
	Checksum bool     // compare checksums of local and remote files, default is size and modtime
	Force    bool     // overwrite existing files on remote
}

// DeleteOpts is a struct for delete options.
type DeleteOpts struct {
	Recursive bool // delete directories recursively
}

// StdOutLogWriter is a writer that writes to log with a prefix and a log level.
type StdOutLogWriter struct {
	prefix  string
	level   string
	secrets []string
}

// NewStdoutLogWriter creates a new StdOutLogWriter.
func NewStdoutLogWriter(prefix, level string, secrets []string) *StdOutLogWriter {
	return &StdOutLogWriter{prefix: prefix, level: level, secrets: secrets}
}

func (w *StdOutLogWriter) Write(p []byte) (n int, err error) {
	lines := strings.Split(string(p), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		line = maskSecrets(line, w.secrets)
		log.Printf("[%s] %s %s", w.level, w.prefix, line)
	}
	return len(p), nil
}

// ColorizedWriter is a writer that colorizes the output based on the hostAddr name.
type ColorizedWriter struct {
	wr       io.Writer
	prefix   string
	hostAddr string
	hostName string
	secrets  []string
}

// NewColorizedWriter creates a new ColorizedWriter with the given hostAddr name.
func NewColorizedWriter(wr io.Writer, prefix, hostAddr, hostName string, secrets []string) *ColorizedWriter {
	return &ColorizedWriter{wr: wr, hostAddr: hostAddr, hostName: hostName, prefix: prefix, secrets: secrets}
}

// WithHost creates a new StdoutColorWriter with the given hostAddr name.
func (s *ColorizedWriter) WithHost(hostAddr, hostName string) *ColorizedWriter {
	return &ColorizedWriter{wr: s.wr, hostAddr: hostAddr, hostName: hostName, prefix: s.prefix, secrets: s.secrets}
}

// Write writes the given byte slice to stdout with the colorized hostAddr prefix for each line.
// If the input does not end with a newline, one is added.
func (s *ColorizedWriter) Write(p []byte) (n int, err error) {
	scanner := bufio.NewScanner(bytes.NewReader(p))
	for scanner.Scan() {
		line := scanner.Text()
		hostID := s.hostAddr
		if s.hostName != "" {
			hostID = s.hostName + " " + s.hostAddr
		}
		formattedOutput := fmt.Sprintf("[%s] %s %s", hostID, s.prefix, line)
		formattedOutput = maskSecrets(formattedOutput, s.secrets)

		if s.prefix == "" {
			formattedOutput = fmt.Sprintf("[%s] %s", hostID, line)
		}
		colorizer := hostColorizer(s.hostAddr)
		colorizedOutput := colorizer("%s\n", formattedOutput)
		_, err = io.WriteString(s.wr, colorizedOutput)
		if err != nil {
			return 0, err
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return len(p), nil
}

// hostColorizer returns a function that formats a string with a color based on the hostAddr name.
func hostColorizer(host string) func(format string, a ...interface{}) string {
	colors := []color.Attribute{
		color.FgHiRed, color.FgHiGreen, color.FgHiYellow,
		color.FgHiBlue, color.FgHiMagenta, color.FgHiCyan,
		color.FgRed, color.FgGreen, color.FgYellow,
		color.FgBlue, color.FgMagenta, color.FgCyan,
	}
	i := crc32.ChecksumIEEE([]byte(host)) % uint32(len(colors))
	return color.New(colors[i]).SprintfFunc()
}

// MakeOutAndErrWriters creates a new StdoutLogWriter and StdoutLogWriter for the given hostAddr.
func MakeOutAndErrWriters(hostAddr, hostName string, verbose bool, secrets []string) (outWr, errWr io.Writer) {
	var outLog, errLog io.Writer
	if verbose {
		outLog = NewColorizedWriter(os.Stdout, " >", hostAddr, hostName, secrets)
		errLog = NewColorizedWriter(os.Stdout, " !", hostAddr, hostName, secrets)
	} else {
		outLog = NewStdoutLogWriter(" >", "DEBUG", secrets)
		errLog = NewStdoutLogWriter(" !", "WARN", secrets)
	}
	return outLog, errLog
}

func maskSecrets(s string, secrets []string) string {
	for _, secret := range secrets {
		if secret == " " || secret == "" {
			continue
		}
		s = strings.ReplaceAll(s, secret, "****")
	}
	return s
}

func isExcluded(path string, excl []string) bool {
	pathSegments := strings.Split(path, string(filepath.Separator))
	for i := range pathSegments {
		subpath := filepath.Join(pathSegments[:i+1]...)
		for _, ex := range excl {
			match, err := filepath.Match(ex, subpath)
			if err != nil {
				continue
			}
			if match {
				return true
			}
			// treat directory in exclusion list as excluding all of its contents
			if strings.TrimSuffix(ex, "/*") == subpath {
				return true
			}
		}
	}
	return false
}

func isWithinOneSecond(t1, t2 time.Time) bool {
	diff := t1.Sub(t2)
	if diff < 0 {
		diff = -diff
	}
	return diff <= time.Second
}
