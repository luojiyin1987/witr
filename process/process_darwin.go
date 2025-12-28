//go:build darwin

package process

import (
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"
)

// Read reads process info using ps and lsof on macOS.
func Read(pid int) (Process, error) {
	// ps -p <pid> -o pid=,ppid=,uid=,lstart=,state=,ucomm=
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "pid=,ppid=,uid=,lstart=,state=,ucomm=").Output()
	if err != nil {
		return Process{}, err
	}

	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) < 9 {
		return Process{}, err
	}

	ppid, _ := strconv.Atoi(fields[1])
	uid, _ := strconv.Atoi(fields[2])
	// lstart: Mon Dec 25 12:00:00 2024
	startedAt, _ := time.Parse("Mon Jan 2 15:04:05 2006", strings.Join(fields[3:8], " "))
	state := fields[8]
	comm := ""
	if len(fields) > 9 {
		comm = fields[9]
	}

	health := "healthy"
	switch state {
	case "Z":
		health = "zombie"
	case "T":
		health = "stopped"
	}
	health = checkResourceUsage(pid, health)

	cwd := readCwd(pid)

	return Process{
		PID:            pid,
		PPID:           ppid,
		Command:        comm,
		Cmdline:        readCmdline(pid),
		User:           resolveUID(uid),
		StartedAt:      startedAt,
		WorkingDir:     cwd,
		GitRepo:        readGitRepo(cwd),
		GitBranch:      readGitBranch(cwd),
		Container:      detectContainer(pid),
		ListeningPorts: readPorts(pid),
		BindAddresses:  readBindAddrs(pid),
		Health:         health,
		Env:            readEnv(pid),
	}, nil
}

// GetCmdline returns the command line for a PID.
func GetCmdline(pid int) string {
	return readCmdline(pid)
}

func readCmdline(pid int) string {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "args=").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func readCwd(pid int) string {
	out, err := exec.Command("lsof", "-a", "-p", strconv.Itoa(pid), "-d", "cwd", "-F", "n").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if len(line) > 1 && line[0] == 'n' {
			return line[1:]
		}
	}
	return ""
}

func readEnv(pid int) []string {
	// macOS: ps -E is limited by SIP
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-E", "-o", "command=").Output()
	if err != nil {
		return nil
	}
	var env []string
	for _, part := range strings.Fields(string(out)) {
		if idx := strings.Index(part, "="); idx > 0 && isEnvVarName(part[:idx]) {
			env = append(env, part)
		}
	}
	return env
}

func isEnvVarName(name string) bool {
	for _, c := range name {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return len(name) > 0
}

func resolveUID(uid int) string {
	if uid == 0 {
		return "root"
	}
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		return u.Username
	}
	return strconv.Itoa(uid)
}

func detectContainer(pid int) string {
	cmd := strings.ToLower(readCmdline(pid))
	switch {
	case strings.Contains(cmd, "docker"):
		return "docker"
	case strings.Contains(cmd, "containerd"):
		return "containerd"
	}
	return ""
}

func readGitRepo(cwd string) string {
	for dir := cwd; dir != "/" && dir != ""; dir = parentDir(dir) {
		if isDir(dir + "/.git") {
			parts := strings.Split(strings.TrimRight(dir, "/"), "/")
			return parts[len(parts)-1]
		}
	}
	return ""
}

func readGitBranch(cwd string) string {
	for dir := cwd; dir != "/" && dir != ""; dir = parentDir(dir) {
		data, err := os.ReadFile(dir + "/.git/HEAD")
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(data))
		if strings.HasPrefix(s, "ref: refs/heads/") {
			return strings.TrimPrefix(s, "ref: refs/heads/")
		}
	}
	return ""
}

func parentDir(path string) string {
	if idx := strings.LastIndex(path, "/"); idx > 0 {
		return path[:idx]
	}
	return ""
}

func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func checkResourceUsage(pid int, health string) string {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "pcpu=,rss=").Output()
	if err != nil {
		return health
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return health
	}
	if cpu, _ := strconv.ParseFloat(fields[0], 64); cpu > 90 {
		return "high-cpu"
	}
	if rss, _ := strconv.ParseFloat(fields[1], 64); rss/1024 > 1024 { // >1GB
		return "high-mem"
	}
	return health
}

// Socket reading via lsof
type socket struct {
	inode, addr string
	port        int
}

func readPorts(pid int) []int {
	sockets := readListeningSockets()
	var ports []int
	for _, inode := range socketsForPID(pid) {
		if s, ok := sockets[inode]; ok {
			ports = append(ports, s.port)
		}
	}
	return ports
}

func readBindAddrs(pid int) []string {
	sockets := readListeningSockets()
	var addrs []string
	for _, inode := range socketsForPID(pid) {
		if s, ok := sockets[inode]; ok {
			addrs = append(addrs, s.addr)
		}
	}
	return addrs
}

func readListeningSockets() map[string]socket {
	sockets := make(map[string]socket)
	out, err := exec.Command("lsof", "-i", "TCP", "-s", "TCP:LISTEN", "-n", "-P", "-F", "pn").Output()
	if err != nil {
		return readListeningSocketsNetstat()
	}

	var currentPID string
	for _, line := range strings.Split(string(out), "\n") {
		if len(line) == 0 {
			continue
		}
		switch line[0] {
		case 'p':
			currentPID = line[1:]
		case 'n':
			addr, port := parseAddr(line[1:])
			if port > 0 {
				inode := currentPID + ":" + strconv.Itoa(port)
				sockets[inode] = socket{inode: inode, addr: addr, port: port}
			}
		}
	}
	return sockets
}

func readListeningSocketsNetstat() map[string]socket {
	sockets := make(map[string]socket)
	out, _ := exec.Command("netstat", "-an", "-p", "tcp").Output()
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "LISTEN") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			addr, port := parseAddr(fields[3])
			if port > 0 {
				inode := "netstat:" + fields[3]
				sockets[inode] = socket{inode: inode, addr: addr, port: port}
			}
		}
	}
	return sockets
}

func socketsForPID(pid int) []string {
	out, err := exec.Command("lsof", "-a", "-p", strconv.Itoa(pid), "-i", "TCP", "-n", "-P", "-F", "n").Output()
	if err != nil {
		return nil
	}
	var inodes []string
	for _, line := range strings.Split(string(out), "\n") {
		if len(line) > 1 && line[0] == 'n' {
			if _, port := parseAddr(line[1:]); port > 0 {
				inodes = append(inodes, strconv.Itoa(pid)+":"+strconv.Itoa(port))
			}
		}
	}
	return inodes
}

// parseAddr handles: *:8080, *.8080, 127.0.0.1:8080, 127.0.0.1.8080, [::1]:8080
func parseAddr(addr string) (string, int) {
	// IPv6: [::]:port
	if strings.HasPrefix(addr, "[") {
		if end := strings.LastIndex(addr, "]"); end != -1 && len(addr) > end+2 {
			ip := addr[1:end]
			port, _ := strconv.Atoi(addr[end+2:])
			if ip == "::" || ip == "" {
				return "::", port
			}
			return ip, port
		}
		return "", 0
	}
	// Wildcard: *:8080 or *.8080
	if strings.HasPrefix(addr, "*") && len(addr) > 2 {
		port, _ := strconv.Atoi(addr[2:])
		return "0.0.0.0", port
	}
	// IPv4 with colon: 127.0.0.1:8080
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		if port, err := strconv.Atoi(addr[idx+1:]); err == nil {
			return addr[:idx], port
		}
	}
	// macOS netstat dot format: 127.0.0.1.8080
	if idx := strings.LastIndex(addr, "."); idx != -1 {
		if port, err := strconv.Atoi(addr[idx+1:]); err == nil {
			return addr[:idx], port
		}
	}
	return "", 0
}
