//go:build linux

package detect

// detectInit checks for systemd as PID 1.
func detectInit(ancestry []Process) *Source {
	for _, p := range ancestry {
		if p.GetPID() == 1 && p.GetCommand() == "systemd" {
			return &Source{Type: SourceSystemd, Name: "systemd", Confidence: 0.8}
		}
	}
	return nil
}
