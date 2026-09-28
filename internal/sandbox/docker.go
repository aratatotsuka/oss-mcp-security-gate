package sandbox

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/aratatotsuka/oss-mcp-security-gate/internal/containerref"
)

type Limits struct {
	CPUs          string
	Memory, Tmpfs string
	PIDs          int
}

type DockerSpec struct {
	Image      string
	Target     string
	Output     string
	Cache      string
	Config     string
	Entrypoint string
	Command    []string
	Network    string
	Limits     Limits
}

func DockerArgs(s DockerSpec) ([]string, error) {
	if !containerref.Provisioned(s.Image) {
		return nil, fmt.Errorf("UNSUPPORTED_SECURITY_REQUIREMENT: image must be digest-pinned")
	}
	if s.Network != "none" {
		return nil, fmt.Errorf("UNSUPPORTED_SECURITY_REQUIREMENT: restricted egress requires an external enforcing proxy")
	}
	if s.Limits.CPUs == "" {
		s.Limits.CPUs = "1.0"
	}
	if s.Limits.Memory == "" {
		s.Limits.Memory = "512m"
	}
	if s.Limits.Tmpfs == "" {
		s.Limits.Tmpfs = "64m"
	}
	if s.Limits.PIDs == 0 {
		s.Limits.PIDs = 128
	}
	args := []string{"run", "--rm", "--network", "none", "--read-only", "--user", "65532:65532", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--pids-limit", fmt.Sprint(s.Limits.PIDs), "--cpus", s.Limits.CPUs, "--memory", s.Limits.Memory, "--memory-swap", s.Limits.Memory, "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=" + s.Limits.Tmpfs}
	if s.Target != "" {
		target, err := filepath.Abs(s.Target)
		if err != nil {
			return nil, err
		}
		mountTarget := target
		if runtime.GOOS == "windows" {
			mountTarget = filepath.ToSlash(target)
		}
		args = append(args, "--mount", "type=bind,src="+mountTarget+",dst=/target,readonly")
	}
	if s.Output != "" {
		p, _ := filepath.Abs(s.Output)
		args = append(args, "--mount", "type=bind,src="+filepath.ToSlash(p)+",dst=/output")
	}
	if s.Cache != "" {
		p, _ := filepath.Abs(s.Cache)
		args = append(args, "--mount", "type=bind,src="+filepath.ToSlash(p)+",dst=/gate/cache,readonly")
	}
	if s.Config != "" {
		p, _ := filepath.Abs(s.Config)
		args = append(args, "--mount", "type=bind,src="+filepath.ToSlash(p)+",dst=/gate/config,readonly")
	}
	if s.Entrypoint != "" {
		args = append(args, "--entrypoint", s.Entrypoint)
	}
	args = append(args, s.Image)
	args = append(args, s.Command...)
	return args, nil
}

func ContainsForbidden(args []string) bool {
	joined := " " + strings.Join(args, " ") + " "
	for _, x := range []string{" --privileged ", " --cap-add ", " /var/run/docker.sock", " /run/containerd", " --network host ", " --pid host ", " --ipc host ", " -v /:/"} {
		if strings.Contains(joined, x) {
			return true
		}
	}
	return false
}
