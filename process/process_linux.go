//go:build linux

package process

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Read reads process info from /proc filesystem.
func Read(pid int) (Process, error) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return Process{}, err
	}

	// Parse stat - command is inside ()
	raw := string(stat)
	open, close := strings.Index(raw, "("), strings.LastIndex(raw, ")")
	if open == -1 || close == -1 {
		return Process{}, fmt.Errorf("invalid stat format")
	}

	comm := raw[open+1 : close]
	fields := strings.Fields(raw[close+2:])
	ppid, _ := strconv.Atoi(fields[1])
	state := fields[2]
	startTicks, _ := strconv.ParseInt(fields[19], 10, 64)
	startedAt := bootTime().Add(time.Duration(startTicks) * time.Second / 100)

	// Health status
	health := "healthy"
	switch state {
	case "Z":
		health = "zombie"
	case "T":
		health = "stopped"
	}

	// High resource usage
	utime, _ := strconv.ParseFloat(fields[11], 64)
	stime, _ := strconv.ParseFloat(fields[12], 64)
	if (utime+stime)/100 > 2*60*60 { // >2h CPU
		health = "high-cpu"
	}
	rssPages, _ := strconv.ParseFloat(fields[21], 64)
	if rssPages*float64(os.Getpagesize())/(1024*1024) > 1024 { // >1GB
		health = "high-mem"
	}

	return Process{
		PID:            pid,
		PPID:           ppid,
		Command:        comm,
		Cmdline:        readCmdline(pid),
		User:           readUser(pid),
		StartedAt:      startedAt,
		WorkingDir:     readCwd(pid),
		GitRepo:        readGitRepo(pid),
		GitBranch:      readGitBranch(pid),
		Container:      detectContainer(pid),
		ListeningPorts: readPorts(pid),
		BindAddresses:  readBindAddrs(pid),
		Health:         health,
		Env:            readEnv(pid),
	}, nil
}

// GetCmdline returns the command line for a PID (used externally).
func GetCmdline(pid int) string {
	return readCmdline(pid)
}

func readCmdline(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
}

func readCwd(pid int) string {
	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		return ""
	}
	return cwd
}

func readEnv(pid int) []string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return nil
	}
	var env []string
	for _, e := range strings.Split(string(data), "\x00") {
		if e != "" {
			env = append(env, e)
		}
	}
	return env
}

func readUser(pid int) string {
	info, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		return ""
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	uid := int(stat.Uid)
	if uid == 0 {
		return "root"
	}
	// Resolve from /etc/passwd
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return strconv.Itoa(uid)
	}
	uidStr := strconv.Itoa(uid)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) > 2 && fields[2] == uidStr {
			return fields[0]
		}
	}
	return uidStr
}

func detectContainer(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	s := string(data)
	switch {
	case strings.Contains(s, "docker"):
		return "docker"
	case strings.Contains(s, "containerd"):
		return "containerd"
	case strings.Contains(s, "kubepods"):
		return "kubernetes"
	}
	return ""
}

func readGitRepo(pid int) string {
	cwd := readCwd(pid)
	for dir := cwd; dir != "/" && dir != ""; dir = parentDir(dir) {
		if isDir(dir + "/.git") {
			parts := strings.Split(strings.TrimRight(dir, "/"), "/")
			return parts[len(parts)-1]
		}
	}
	return ""
}

func readGitBranch(pid int) string {
	cwd := readCwd(pid)
	for dir := cwd; dir != "/" && dir != ""; dir = parentDir(dir) {
		headFile := dir + "/.git/HEAD"
		data, err := os.ReadFile(headFile)
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
	idx := strings.LastIndex(path, "/")
	if idx <= 0 {
		return ""
	}
	return path[:idx]
}

func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// Socket/port reading
type socket struct {
	inode, addr string
	port        int
}

func readPorts(pid int) []int {
	sockets := readListeningSockets()
	inodes := socketsForPID(pid)
	var ports []int
	for _, inode := range inodes {
		if s, ok := sockets[inode]; ok {
			ports = append(ports, s.port)
		}
	}
	return ports
}

func readBindAddrs(pid int) []string {
	sockets := readListeningSockets()
	inodes := socketsForPID(pid)
	var addrs []string
	for _, inode := range inodes {
		if s, ok := sockets[inode]; ok {
			addrs = append(addrs, s.addr)
		}
	}
	return addrs
}

func readListeningSockets() map[string]socket {
	sockets := make(map[string]socket)
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		ipv6 := strings.HasSuffix(path, "6")
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Scan() // skip header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 || fields[3] != "0A" { // 0A = LISTEN
				continue
			}
			addr, port := parseAddr(fields[1], ipv6)
			sockets[fields[9]] = socket{inode: fields[9], addr: addr, port: port}
		}
		f.Close()
	}
	return sockets
}

func parseAddr(raw string, ipv6 bool) (string, int) {
	parts := strings.Split(raw, ":")
	if len(parts) < 2 {
		return "", 0
	}
	port, _ := strconv.ParseInt(parts[1], 16, 32)
	if ipv6 {
		return "::", int(port)
	}
	b, _ := hex.DecodeString(parts[0])
	if len(b) < 4 {
		return "", int(port)
	}
	ip := fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
	return ip, int(port)
}

func socketsForPID(pid int) []string {
	fdPath := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdPath)
	if err != nil {
		return nil
	}
	var inodes []string
	for _, e := range entries {
		link, err := os.Readlink(fdPath + "/" + e.Name())
		if err != nil {
			continue
		}
		if strings.HasPrefix(link, "socket:[") {
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			inodes = append(inodes, inode)
		}
	}
	return inodes
}

func bootTime() time.Time {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return time.Now()
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "btime ") {
			sec, _ := strconv.ParseInt(strings.Fields(scanner.Text())[1], 10, 64)
			return time.Unix(sec, 0)
		}
	}
	return time.Now()
}
