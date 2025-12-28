package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pranshuparmar/witr/detect"
	"github.com/pranshuparmar/witr/process"
)

var version = ""
var commit = ""
var buildDate = ""

func main() {
	if version == "" {
		fmt.Fprintln(os.Stderr, "ERROR: version not set")
		os.Exit(2)
	}

	var (
		pidFlag     = flag.Int("pid", 0, "explain a specific PID")
		portFlag    = flag.Int("port", 0, "explain port usage")
		shortFlag   = flag.Bool("short", false, "one-line summary")
		treeFlag    = flag.Bool("tree", false, "show process tree")
		jsonFlag    = flag.Bool("json", false, "output as JSON")
		warnFlag    = flag.Bool("warnings", false, "show only warnings")
		noColorFlag = flag.Bool("no-color", false, "disable color")
		envFlag     = flag.Bool("env", false, "show environment variables")
		helpFlag    = flag.Bool("help", false, "show help")
		versionFlag = flag.Bool("version", false, "show version")
	)
	flag.Parse()

	if *helpFlag {
		printHelp()
		return
	}
	if *versionFlag {
		fmt.Printf("witr %s (commit %s, built %s)\n", version, commit, buildDate)
		return
	}

	// Resolve target to PID
	pid, err := resolveTarget(*pidFlag, *portFlag, flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Build ancestry chain
	ancestry, err := process.BuildAncestry(pid)
	if err != nil || len(ancestry) == 0 {
		fmt.Fprintf(os.Stderr, "Error: cannot read process %d\n", pid)
		os.Exit(1)
	}

	target := ancestry[len(ancestry)-1]
	color := !*noColorFlag

	// Handle special output modes
	if *envFlag {
		renderEnv(target, *jsonFlag)
		return
	}

	// Convert to detect.Process interface
	procs := make([]detect.Process, len(ancestry))
	for i, p := range ancestry {
		procs[i] = p
	}

	src := detect.Detect(procs)
	warnings := detect.Warnings(procs)

	if *jsonFlag {
		renderJSON(ancestry, src, warnings)
	} else if *warnFlag {
		renderWarnings(warnings, color)
	} else if *treeFlag {
		renderTree(ancestry, color)
	} else if *shortFlag {
		renderShort(ancestry, color)
	} else {
		renderStandard(ancestry, src, warnings, color)
	}
}

func printHelp() {
	fmt.Println(`Usage: witr [--pid N | --port N | name] [options]

Options:
  --pid <n>      Explain a specific PID
  --port <n>     Explain port usage
  --short        One-line summary
  --tree         Show process ancestry tree
  --json         Output as JSON
  --warnings     Show only warnings
  --no-color     Disable colorized output
  --env          Show environment variables
  --help         Show this help
  --version      Show version`)
}

func resolveTarget(pid, port int, args []string) (int, error) {
	if pid > 0 {
		return pid, nil
	}
	if port > 0 {
		return resolvePort(port)
	}
	if len(args) > 0 {
		return resolveName(args[0])
	}
	return 0, fmt.Errorf("no target specified. Run: witr --help")
}

func resolveName(name string) (int, error) {
	var matches []int
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if strings.TrimSpace(string(comm)) == name {
			matches = append(matches, pid)
		}
	}
	if len(matches) == 0 {
		return 0, fmt.Errorf("no process found: %s", name)
	}
	if len(matches) > 1 {
		fmt.Println("Multiple processes found:")
		for i, pid := range matches {
			fmt.Printf("  [%d] PID %d  %s\n", i+1, pid, process.GetCmdline(pid))
		}
		return 0, fmt.Errorf("re-run with: witr --pid <pid>")
	}
	return matches[0], nil
}

func resolvePort(port int) (int, error) {
	// Read listening sockets from /proc/net/tcp
	sockets := make(map[string]int) // inode -> port
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 || fields[3] != "0A" { // 0A = LISTEN
				continue
			}
			local := fields[1]
			if idx := strings.LastIndex(local, ":"); idx != -1 {
				p, _ := strconv.ParseInt(local[idx+1:], 16, 32)
				if int(p) == port {
					sockets[fields[9]] = port // inode
				}
			}
		}
	}

	if len(sockets) == 0 {
		return 0, fmt.Errorf("no process listening on port %d", port)
	}

	// Find PID by scanning /proc/*/fd for matching inodes
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdPath := fmt.Sprintf("/proc/%d/fd", pid)
		fds, _ := os.ReadDir(fdPath)
		for _, fd := range fds {
			link, _ := os.Readlink(fdPath + "/" + fd.Name())
			if strings.HasPrefix(link, "socket:[") {
				inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
				if _, ok := sockets[inode]; ok {
					return pid, nil
				}
			}
		}
	}
	return 0, fmt.Errorf("socket found on port %d but process not detected (try sudo)", port)
}

// Output renderers
const (
	reset   = "\033[0m"
	red     = "\033[31m"
	green   = "\033[32m"
	blue    = "\033[34m"
	cyan    = "\033[36m"
	magenta = "\033[35m"
	dim     = "\033[2m"
)

func renderEnv(p process.Process, asJSON bool) {
	if asJSON {
		out, _ := json.MarshalIndent(map[string]any{
			"command": p.Cmdline,
			"env":     p.Env,
		}, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Printf("%sCommand%s: %s\n", green, reset, p.Cmdline)
		if len(p.Env) > 0 {
			fmt.Printf("%sEnvironment%s:\n", blue, reset)
			for _, e := range p.Env {
				fmt.Printf("  %s\n", e)
			}
		} else {
			fmt.Printf("%sNo environment variables found%s\n", red, reset)
		}
	}
}

func renderJSON(ancestry []process.Process, src detect.Source, warnings []string) {
	out, _ := json.MarshalIndent(map[string]any{
		"ancestry": ancestry,
		"source":   src,
		"warnings": warnings,
	}, "", "  ")
	fmt.Println(string(out))
}

func renderWarnings(warnings []string, color bool) {
	if len(warnings) == 0 {
		fmt.Println("No warnings.")
		return
	}
	for _, w := range warnings {
		if color {
			fmt.Printf("%s•%s %s\n", red, reset, w)
		} else {
			fmt.Printf("• %s\n", w)
		}
	}
}

func renderTree(ancestry []process.Process, color bool) {
	for i, p := range ancestry {
		indent := strings.Repeat("  ", i)
		prefix := ""
		if i > 0 {
			prefix = "└─ "
		}
		if color {
			fmt.Printf("%s%s%s%s (%spid %d%s)\n", indent, prefix, green, p.Command, dim, p.PID, reset)
		} else {
			fmt.Printf("%s%s%s (pid %d)\n", indent, prefix, p.Command, p.PID)
		}
	}
}

func renderShort(ancestry []process.Process, color bool) {
	var parts []string
	for _, p := range ancestry {
		if color {
			parts = append(parts, fmt.Sprintf("%s (%spid %d%s)", p.Command, dim, p.PID, reset))
		} else {
			parts = append(parts, fmt.Sprintf("%s (pid %d)", p.Command, p.PID))
		}
	}
	if color {
		fmt.Println(strings.Join(parts, fmt.Sprintf(" %s→%s ", magenta, reset)))
	} else {
		fmt.Println(strings.Join(parts, " → "))
	}
}

func renderStandard(ancestry []process.Process, src detect.Source, warnings []string, color bool) {
	p := ancestry[len(ancestry)-1]

	label := func(s string) string {
		if color {
			return fmt.Sprintf("%s%s%s", blue, s, reset)
		}
		return s
	}

	fmt.Printf("%s: %s\n\n", label("Target"), p.Command)
	fmt.Printf("%s: %s (pid %d)", label("Process"), p.Command, p.PID)
	if p.Health != "" && p.Health != "healthy" {
		fmt.Printf(" [%s]", p.Health)
	}
	fmt.Println()

	if p.User != "" {
		fmt.Printf("%s: %s\n", label("User"), p.User)
	}
	fmt.Printf("%s: %s\n", label("Command"), p.Cmdline)
	fmt.Printf("%s: %s\n", label("Started"), formatTime(p.StartedAt))

	// Ancestry chain
	fmt.Printf("\n%s:\n  ", label("Why It Exists"))
	for i, a := range ancestry {
		fmt.Printf("%s (pid %d)", a.Command, a.PID)
		if i < len(ancestry)-1 {
			if color {
				fmt.Printf(" %s→%s ", magenta, reset)
			} else {
				fmt.Print(" → ")
			}
		}
	}
	fmt.Println()

	// Source
	fmt.Printf("\n%s: %s", label("Source"), src.Name)
	if src.Name != string(src.Type) {
		fmt.Printf(" (%s)", src.Type)
	}
	fmt.Println()

	// Context
	if p.WorkingDir != "" {
		fmt.Printf("\n%s: %s\n", label("Working Dir"), p.WorkingDir)
	}
	if p.GitRepo != "" {
		if p.GitBranch != "" {
			fmt.Printf("%s: %s (%s)\n", label("Git Repo"), p.GitRepo, p.GitBranch)
		} else {
			fmt.Printf("%s: %s\n", label("Git Repo"), p.GitRepo)
		}
	}
	if len(p.ListeningPorts) > 0 {
		for i, port := range p.ListeningPorts {
			addr := "0.0.0.0"
			if i < len(p.BindAddresses) {
				addr = p.BindAddresses[i]
			}
			if i == 0 {
				fmt.Printf("%s: %s:%d\n", label("Listening"), addr, port)
			} else {
				fmt.Printf("            %s:%d\n", addr, port)
			}
		}
	}

	// Warnings
	if len(warnings) > 0 {
		fmt.Printf("\n%s:\n", label("Warnings"))
		for _, w := range warnings {
			fmt.Printf("  • %s\n", w)
		}
	}
}

func formatTime(t time.Time) string {
	dur := time.Since(t)
	var rel string
	switch {
	case dur.Hours() >= 48:
		rel = fmt.Sprintf("%d days ago", int(dur.Hours())/24)
	case dur.Hours() >= 24:
		rel = "1 day ago"
	case dur.Hours() >= 1:
		rel = fmt.Sprintf("%d hours ago", int(dur.Hours()))
	case dur.Minutes() >= 1:
		rel = fmt.Sprintf("%d min ago", int(dur.Minutes()))
	default:
		rel = "just now"
	}
	return fmt.Sprintf("%s (%s)", rel, t.Format("2006-01-02 15:04:05"))
}
