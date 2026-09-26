package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"time"
)

var ErrOutputLimit = errors.New("scanner output limit exceeded")

type Spec struct {
	Name        string
	Args        []string
	Dir         string
	Timeout     time.Duration
	OutputLimit int64
	Stdin       []byte
}

type Result struct {
	Output   []byte
	Stderr   []byte
	ExitCode int
	TimedOut bool
	Err      error
}

type cappedBuffer struct {
	b        bytes.Buffer
	n        int64
	exceeded bool
}

func (w *cappedBuffer) Write(p []byte) (int, error) {
	orig := len(p)
	remaining := w.n - int64(w.b.Len())
	if remaining <= 0 {
		w.exceeded = true
		return orig, nil
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
		w.exceeded = true
	}
	_, _ = w.b.Write(p)
	return orig, nil
}

func Run(ctx context.Context, s Spec) Result {
	if s.Timeout <= 0 {
		s.Timeout = 2 * time.Minute
	}
	if s.OutputLimit <= 0 {
		s.OutputLimit = 10 << 20
	}
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.Name, s.Args...)
	cmd.Dir = s.Dir
	// Do not inherit credentials, proxy variables, or target-controlled environment.
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/nonexistent", "LANG=C.UTF-8"}
	if len(s.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(s.Stdin)
	}
	var out cappedBuffer
	out.n = s.OutputLimit
	var stderr cappedBuffer
	stderr.n = min(s.OutputLimit, 1<<20)
	cmd.Stdout = io.Writer(&out)
	cmd.Stderr = io.Writer(&stderr)
	err := cmd.Run()
	r := Result{Output: out.b.Bytes(), Stderr: stderr.b.Bytes(), Err: err, ExitCode: -1}
	if ctx.Err() == context.DeadlineExceeded {
		r.TimedOut = true
		r.Err = ctx.Err()
		return r
	}
	if out.exceeded || stderr.exceeded {
		r.Err = fmt.Errorf("%w (%d bytes)", ErrOutputLimit, s.OutputLimit)
		return r
	}
	if cmd.ProcessState != nil {
		r.ExitCode = cmd.ProcessState.ExitCode()
	}
	return r
}
