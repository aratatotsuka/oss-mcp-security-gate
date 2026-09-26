package runner

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestTimeout(t *testing.T) {
	name := "sh"
	args := []string{"-c", "sleep 2"}
	if runtime.GOOS == "windows" {
		name = "powershell.exe"
		args = []string{"-NoProfile", "-Command", "Start-Sleep -Seconds 2"}
	}
	r := Run(context.Background(), Spec{Name: name, Args: args, Timeout: 50 * time.Millisecond, OutputLimit: 1024})
	if !r.TimedOut {
		t.Fatalf("expected timeout: %#v", r)
	}
}
func TestMalformedCommandFails(t *testing.T) {
	r := Run(context.Background(), Spec{Name: "security-gate-command-that-does-not-exist", Timeout: time.Second})
	if r.Err == nil {
		t.Fatal("missing command succeeded")
	}
}

func TestOutputLimit(t *testing.T) {
	name := "sh"
	args := []string{"-c", "head -c 4096 /dev/zero"}
	if runtime.GOOS == "windows" {
		name = "powershell.exe"
		args = []string{"-NoProfile", "-Command", "[Console]::Out.Write(('x' * 4096))"}
	}
	r := Run(context.Background(), Spec{Name: name, Args: args, Timeout: time.Second, OutputLimit: 128})
	if r.Err == nil || len(r.Output) != 128 {
		t.Fatalf("output limit not enforced: len=%d err=%v", len(r.Output), r.Err)
	}
}
