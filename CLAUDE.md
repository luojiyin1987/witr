# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

```bash
# Build with version info (required - build fails without version)
go build -ldflags "-X main.version=v0.2.0 -X main.commit=$(git rev-parse --short HEAD) -X 'main.buildDate=$(date +%Y-%m-%d)'" -o witr ./cmd/witr

# Cross-compile
GOOS=linux GOARCH=amd64 go build -ldflags "..." -o witr-linux-amd64 ./cmd/witr
GOOS=darwin GOARCH=arm64 go build -ldflags "..." -o witr-darwin-arm64 ./cmd/witr

# Format code
gofmt -w .
```

## Architecture

**witr** answers "why is this running?" by tracing process ancestry and detecting supervisors.

```
cmd/witr/main.go     # CLI, target resolution, output rendering
        │
        ▼
    process.BuildAncestry(pid)  →  []process.Process
        │
        ▼
    detect.Detect(ancestry)     →  detect.Source
        │
        ▼
    render output (standard/tree/short/json)
```

## Package Structure

```
cmd/witr/main.go          # CLI + target resolution + output rendering
process/
  process.go              # Process type + BuildAncestry()
  process_linux.go        # Linux: reads /proc filesystem
  process_darwin.go       # macOS: uses ps, lsof, launchctl
detect/
  detect.go               # Detect() + Warnings() + common detectors
  detect_linux.go         # systemd detection
  detect_darwin.go        # launchd detection
```

## Key Functions

- `process.Read(pid)` - Read process info (platform-specific)
- `process.BuildAncestry(pid)` - Walk PPID chain to init/systemd
- `detect.Detect([]Process)` - Identify supervisor (container > supervisor > cron > shell > systemd/launchd)
- `detect.Warnings([]Process)` - Generate health/security warnings

## Platform-Specific

Files ending in `_linux.go` or `_darwin.go` use build tags. Linux reads `/proc`; macOS uses `ps`, `lsof`, `launchctl`.
