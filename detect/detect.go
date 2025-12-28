// Package detect identifies what started/supervises a process.
package detect

import (
	"os"
	"strings"
	"time"
)

// SourceType identifies the type of process supervisor.
type SourceType string

const (
	SourceContainer  SourceType = "container"
	SourceSystemd    SourceType = "systemd"
	SourceLaunchd    SourceType = "launchd"
	SourceSupervisor SourceType = "supervisor"
	SourceCron       SourceType = "cron"
	SourceShell      SourceType = "shell"
	SourceUnknown    SourceType = "unknown"
)

// Source describes what started or supervises a process.
type Source struct {
	Type       SourceType
	Name       string
	Confidence float64
	Details    map[string]string
}

// Process is a minimal interface for detection (to avoid circular import).
type Process interface {
	GetPID() int
	GetPPID() int
	GetCommand() string
	GetCmdline() string
	GetUser() string
	GetWorkingDir() string
	GetBindAddresses() []string
	GetHealth() string
	GetContainer() string
	GetService() string
	GetStartedAt() time.Time
}

// Detect identifies the source that started/supervises the target process.
// Priority: container > supervisor > cron > shell > systemd/launchd
func Detect(ancestry []Process) Source {
	if src := detectContainer(ancestry); src != nil {
		return *src
	}
	if src := detectSupervisor(ancestry); src != nil {
		return *src
	}
	if src := detectCron(ancestry); src != nil {
		return *src
	}
	if src := detectShell(ancestry); src != nil {
		return *src
	}
	if src := detectInit(ancestry); src != nil {
		return *src
	}
	return Source{Type: SourceUnknown, Confidence: 0.2}
}

// Warnings returns potential issues with the process.
func Warnings(ancestry []Process) []string {
	if len(ancestry) == 0 {
		return nil
	}
	last := ancestry[len(ancestry)-1]
	var w []string

	// Health
	switch last.GetHealth() {
	case "zombie":
		w = append(w, "Process is a zombie (defunct)")
	case "stopped":
		w = append(w, "Process is stopped")
	case "high-cpu":
		w = append(w, "Process is using high CPU (>2h total)")
	case "high-mem":
		w = append(w, "Process is using high memory (>1GB RSS)")
	}

	// Security
	if isPublicBind(last.GetBindAddresses()) {
		w = append(w, "Process is listening on a public interface")
	}
	if last.GetUser() == "root" {
		w = append(w, "Process is running as root")
	}

	// Suspicious working dir
	if dir := last.GetWorkingDir(); dir == "/" || dir == "/tmp" || dir == "/var/tmp" {
		w = append(w, "Process running from suspicious directory: "+dir)
	}

	// Long running
	if time.Since(last.GetStartedAt()).Hours() > 90*24 {
		w = append(w, "Process has been running for over 90 days")
	}

	// Unknown source
	if Detect(ancestry).Type == SourceUnknown {
		w = append(w, "No known supervisor detected")
	}

	return w
}

func isPublicBind(addrs []string) bool {
	for _, a := range addrs {
		if a == "0.0.0.0" || a == "::" {
			return true
		}
	}
	return false
}

// Container detection via cgroup
func detectContainer(ancestry []Process) *Source {
	for _, p := range ancestry {
		data, err := os.ReadFile("/proc/" + itoa(p.GetPID()) + "/cgroup")
		if err != nil {
			continue
		}
		s := string(data)
		if strings.Contains(s, "docker") || strings.Contains(s, "containerd") || strings.Contains(s, "kubepods") {
			return &Source{Type: SourceContainer, Name: "container", Confidence: 0.9}
		}
	}
	return nil
}

// Known supervisors (not including systemd/init - handled separately)
var supervisors = map[string]string{
	"pm2": "pm2", "pm2 god": "pm2", "supervisord": "supervisord",
	"gunicorn": "gunicorn", "uwsgi": "uwsgi", "s6-supervise": "s6", "s6": "s6",
	"runsv": "runit", "runit": "runit", "openrc": "openrc", "monit": "monit",
	"circusd": "circus", "circus": "circus", "daemontools": "daemontools",
	"tini": "tini", "docker-init": "docker-init",
}

func detectSupervisor(ancestry []Process) *Source {
	// Reverse: find nearest supervisor to target
	for i := len(ancestry) - 1; i >= 0; i-- {
		p := ancestry[i]
		cmd := strings.ToLower(p.GetCommand())
		cmdline := strings.ToLower(p.GetCmdline())

		// PM2 special case
		if strings.Contains(cmd, "pm2") || strings.Contains(cmdline, "pm2") {
			return &Source{Type: SourceSupervisor, Name: "pm2", Confidence: 0.9}
		}
		// Known supervisors
		if name, ok := supervisors[cmd]; ok {
			return &Source{Type: SourceSupervisor, Name: name, Confidence: 0.7}
		}
		for sup, name := range supervisors {
			if strings.Contains(cmdline, sup) {
				return &Source{Type: SourceSupervisor, Name: name, Confidence: 0.7}
			}
		}
	}
	return nil
}

func detectCron(ancestry []Process) *Source {
	for i := len(ancestry) - 1; i >= 0; i-- {
		cmd := ancestry[i].GetCommand()
		if cmd == "cron" || cmd == "crond" {
			return &Source{Type: SourceCron, Name: "cron", Confidence: 0.6}
		}
	}
	return nil
}

var shells = map[string]bool{"bash": true, "zsh": true, "sh": true, "fish": true}

func detectShell(ancestry []Process) *Source {
	for i := len(ancestry) - 1; i >= 0; i-- {
		if shells[ancestry[i].GetCommand()] {
			return &Source{Type: SourceShell, Name: ancestry[i].GetCommand(), Confidence: 0.5}
		}
	}
	return nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
