// Package process provides process inspection and ancestry building.
package process

import "time"

// Process represents a running process with all its context.
type Process struct {
	PID, PPID      int
	Command        string // short name (comm)
	Cmdline        string // full command line
	User           string
	StartedAt      time.Time
	WorkingDir     string
	GitRepo        string
	GitBranch      string
	Container      string
	Service        string
	ListeningPorts []int
	BindAddresses  []string
	Health         string // healthy, zombie, stopped, high-cpu, high-mem
	Env            []string
}

// Getters to implement detect.Process interface
func (p Process) GetPID() int              { return p.PID }
func (p Process) GetPPID() int             { return p.PPID }
func (p Process) GetCommand() string       { return p.Command }
func (p Process) GetCmdline() string       { return p.Cmdline }
func (p Process) GetUser() string          { return p.User }
func (p Process) GetWorkingDir() string    { return p.WorkingDir }
func (p Process) GetBindAddresses() []string { return p.BindAddresses }
func (p Process) GetHealth() string        { return p.Health }
func (p Process) GetContainer() string     { return p.Container }
func (p Process) GetService() string       { return p.Service }
func (p Process) GetStartedAt() time.Time  { return p.StartedAt }

// BuildAncestry walks the process tree from pid up to init (PID 1).
// Returns the chain from root to target: [init, ..., parent, target]
func BuildAncestry(pid int) ([]Process, error) {
	var chain []Process
	seen := make(map[int]bool)

	for pid > 0 && !seen[pid] {
		seen[pid] = true
		p, err := Read(pid)
		if err != nil {
			break
		}
		chain = append([]Process{p}, chain...) // prepend
		if p.PID == 1 || p.PPID == 0 {
			break
		}
		pid = p.PPID
	}
	return chain, nil
}
