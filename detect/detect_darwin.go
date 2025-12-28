//go:build darwin

package detect

import (
	"os/exec"
	"strconv"
	"strings"
)

// detectInit checks for launchd as PID 1 and gets service details.
func detectInit(ancestry []Process) *Source {
	for _, p := range ancestry {
		if p.GetPID() == 1 && p.GetCommand() == "launchd" {
			// Try to get launchd service info for target process
			if len(ancestry) > 0 {
				target := ancestry[len(ancestry)-1]
				if label, domain := getLaunchdLabel(target.GetPID()); label != "" {
					return &Source{
						Type:       SourceLaunchd,
						Name:       label,
						Confidence: 0.9,
						Details:    map[string]string{"domain": domain},
					}
				}
			}
			return &Source{Type: SourceLaunchd, Name: "launchd", Confidence: 0.8}
		}
	}
	return nil
}

// getLaunchdLabel uses launchctl to get service label for a PID.
func getLaunchdLabel(pid int) (label, domain string) {
	out, err := exec.Command("launchctl", "blame", strconv.Itoa(pid)).Output()
	if err != nil {
		return "", ""
	}

	line := strings.TrimSpace(string(out))
	// Format: "system/com.apple.example" or "gui/501/com.example.app"
	if !strings.Contains(line, "/") {
		return "", "" // Not a service path
	}

	parts := strings.SplitN(line, "/", 2)
	if len(parts) < 2 {
		return line, ""
	}

	domain = parts[0]
	label = parts[1]

	// Handle gui/501/label format
	if domain == "gui" {
		if sub := strings.SplitN(label, "/", 2); len(sub) == 2 {
			domain = "gui/" + sub[0]
			label = sub[1]
		}
	}

	return label, domain
}
