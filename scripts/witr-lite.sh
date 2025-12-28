#!/usr/bin/env sh
set -eu

print_help() {
  cat <<'EOF'
witr-lite (semi-automatic)
Usage:
  scripts/witr-lite.sh --pid <pid>
  scripts/witr-lite.sh --port <port>
  scripts/witr-lite.sh --name <pattern>

Options:
  --pid <pid>       Explain a specific PID
  --port <port>     Explain the process listening on a TCP port
  --name <pattern>  Match a process by name/command substring
  -h, --help        Show this help message

Notes:
  - Best effort; some details may require sudo.
  - Uses lsof/pstree/systemctl/launchctl when available.
EOF
}

err() {
  printf "error: %s\n" "$*" >&2
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

ps_field() {
  ps -o "$2=" -p "$1" 2>/dev/null | awk '{$1=$1; print}'
}

OS="$(uname -s)"

pid=""
port=""
name=""

while [ $# -gt 0 ]; do
  case "$1" in
    --pid)
      [ $# -ge 2 ] || { err "missing value for --pid"; exit 2; }
      pid="$2"
      shift 2
      ;;
    --port)
      [ $# -ge 2 ] || { err "missing value for --port"; exit 2; }
      port="$2"
      shift 2
      ;;
    --name)
      [ $# -ge 2 ] || { err "missing value for --name"; exit 2; }
      name="$2"
      shift 2
      ;;
    -h|--help)
      print_help
      exit 0
      ;;
    *)
      err "unknown argument: $1"
      print_help
      exit 2
      ;;
  esac
done

count=0
[ -n "$pid" ] && count=$((count + 1))
[ -n "$port" ] && count=$((count + 1))
[ -n "$name" ] && count=$((count + 1))
if [ "$count" -ne 1 ]; then
  err "provide exactly one of --pid, --port, or --name"
  print_help
  exit 2
fi

if [ -n "$pid" ]; then
  case "$pid" in
    *[!0-9]*|"")
      err "pid must be numeric"
      exit 2
      ;;
  esac
fi

if [ -n "$port" ]; then
  case "$port" in
    *[!0-9]*|"")
      err "port must be numeric"
      exit 2
      ;;
  esac
fi

resolve_by_port() {
  pids=""
  if have_cmd lsof; then
    pids=$(lsof -nP -iTCP:"$1" -sTCP:LISTEN -t 2>/dev/null || true)
  fi
  if [ -z "$pids" ] && [ "$OS" = "Linux" ] && have_cmd ss; then
    pids=$(ss -lptn "sport = :$1" 2>/dev/null | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | sort -u)
  fi
  if [ -z "$pids" ] && [ "$OS" = "Darwin" ] && have_cmd netstat; then
    pids=$(netstat -anv -p tcp 2>/dev/null | awk -v p=".$1" '$0 ~ /LISTEN/ && $0 ~ p {print $9}' | sort -u)
  fi

  pids=$(printf "%s\n" "$pids" | awk 'NF')
  if [ -z "$pids" ]; then
    err "no process listening on port $1"
    exit 1
  fi

  count=$(printf "%s\n" "$pids" | awk 'END{print NR}')
  if [ "$count" -gt 1 ]; then
    printf "Multiple PIDs listening on port %s:\n" "$1"
    printf "%s\n" "$pids" | sed 's/^/  /'
    printf "Re-run with: --pid <pid>\n"
    exit 1
  fi

  printf "%s\n" "$pids"
}

resolve_by_name() {
  if have_cmd pgrep; then
    pids=$(pgrep -f "$1" 2>/dev/null || true)
  else
    pids=$(ps -ax -o pid=,command= 2>/dev/null | awk -v n="$1" 'BEGIN{n=tolower(n)} {line=tolower($0); if (index(line,n)) print $1}')
  fi

  pids=$(printf "%s\n" "$pids" | awk -v self="$$" '$1 ~ /^[0-9]+$/ && $1 != self')
  if [ -z "$pids" ]; then
    err "no process matching name: $1"
    exit 1
  fi

  count=$(printf "%s\n" "$pids" | awk 'END{print NR}')
  if [ "$count" -gt 1 ]; then
    printf "Multiple PIDs match name %s:\n" "$1"
    printf "%s\n" "$pids" | sed 's/^/  /'
    printf "Re-run with: --pid <pid>\n"
    exit 1
  fi

  printf "%s\n" "$pids"
}

SOURCE_TYPE="unknown"
SOURCE_DETAIL=""

detect_source() {
  SOURCE_TYPE="unknown"
  SOURCE_DETAIL=""

  if [ "$OS" = "Linux" ] && [ -r "/proc/$1/cgroup" ]; then
    cgroup=$(cat "/proc/$1/cgroup" 2>/dev/null || true)
    case "$cgroup" in
      *docker*)
        SOURCE_TYPE="container"
        SOURCE_DETAIL="docker"
        ;;
      *containerd*)
        SOURCE_TYPE="container"
        SOURCE_DETAIL="containerd"
        ;;
      *kubepods*)
        SOURCE_TYPE="container"
        SOURCE_DETAIL="kubernetes"
        ;;
    esac
  fi

  if [ "$SOURCE_TYPE" = "unknown" ] && [ "$OS" = "Linux" ] && have_cmd systemctl; then
    svc_out=$(systemctl status "$1" --no-pager 2>/dev/null || true)
    if printf "%s" "$svc_out" | grep -q "Loaded: loaded"; then
      unit=$(printf "%s" "$svc_out" | awk '/Loaded:/ {for (i=1;i<=NF;i++) if ($i ~ /\.service/) {print $i; exit}}')
      SOURCE_TYPE="systemd"
      SOURCE_DETAIL="$unit"
    fi
  fi

  if [ "$SOURCE_TYPE" = "unknown" ] && [ "$OS" = "Darwin" ] && have_cmd launchctl; then
    label=$(launchctl blame "$1" 2>/dev/null | head -n 1 || true)
    if [ -n "$label" ]; then
      SOURCE_TYPE="launchd"
      SOURCE_DETAIL="$label"
    fi
  fi
}

get_cwd() {
  if [ "$OS" = "Linux" ] && [ -r "/proc/$1/cwd" ]; then
    readlink "/proc/$1/cwd" 2>/dev/null || true
    return
  fi
  if have_cmd pwdx; then
    pwdx "$1" 2>/dev/null | awk '{print $2}'
    return
  fi
  if have_cmd lsof; then
    lsof -a -p "$1" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | head -n 1
    return
  fi
  printf ""
}

print_ancestry() {
  if have_cmd pstree; then
    printf "Ancestry (pstree):\n"
    pstree -s -p "$1" 2>/dev/null | sed 's/^/  /'
    return
  fi

  printf "Ancestry (leaf -> root):\n"
  current="$1"
  while :; do
    line=$(ps -o pid=,ppid=,comm= -p "$current" 2>/dev/null | awk '{$1=$1; print}')
    [ -z "$line" ] && break
    printf "  %s\n" "$line"
    ppid=$(printf "%s" "$line" | awk '{print $2}')
    case "$ppid" in
      ""|*[!0-9]*)
        break
        ;;
    esac
    [ "$ppid" -le 0 ] && break
    [ "$ppid" -eq "$current" ] && break
    current="$ppid"
  done
}

print_listeners() {
  if have_cmd lsof; then
    listeners=$(lsof -nP -p "$1" -iTCP -sTCP:LISTEN 2>/dev/null || true)
    if [ -n "$listeners" ]; then
      printf "Listeners (lsof):\n"
      printf "%s\n" "$listeners" | sed '1d' | sed 's/^/  /'
    fi
  fi
}

target_desc=""

if [ -n "$port" ]; then
  pid=$(resolve_by_port "$port")
  target_desc="from port $port"
elif [ -n "$name" ]; then
  pid=$(resolve_by_name "$name")
  target_desc="from name $name"
else
  target_desc="explicit pid"
fi

proc_user=$(ps_field "$pid" user)
proc_ppid=$(ps_field "$pid" ppid)
proc_start=$(ps_field "$pid" lstart)
proc_comm=$(ps_field "$pid" comm)
proc_cmd=$(ps_field "$pid" command)

cwd=$(get_cwd "$pid")
git_repo=""
git_branch=""
if [ -n "$cwd" ] && have_cmd git; then
  repo_root=$(git -C "$cwd" rev-parse --show-toplevel 2>/dev/null || true)
  if [ -n "$repo_root" ]; then
    git_repo=$(basename "$repo_root")
    git_branch=$(git -C "$repo_root" rev-parse --abbrev-ref HEAD 2>/dev/null || true)
  fi
fi

detect_source "$pid"

printf "witr-lite (semi-automatic)\n"
printf "Target: pid=%s (%s)\n" "$pid" "$target_desc"

printf "\nProcess:\n"
[ -n "$proc_user" ] && printf "  user: %s\n" "$proc_user"
[ -n "$proc_start" ] && printf "  started: %s\n" "$proc_start"
[ -n "$proc_ppid" ] && printf "  ppid: %s\n" "$proc_ppid"
[ -n "$proc_comm" ] && printf "  command: %s\n" "$proc_comm"
[ -n "$proc_cmd" ] && printf "  cmdline: %s\n" "$proc_cmd"

printf "\nContext (best effort):\n"
if [ -n "$cwd" ]; then
  printf "  cwd: %s\n" "$cwd"
else
  printf "  cwd: unknown\n"
fi
if [ -n "$git_repo" ]; then
  if [ -n "$git_branch" ]; then
    printf "  git: %s (%s)\n" "$git_repo" "$git_branch"
  else
    printf "  git: %s\n" "$git_repo"
  fi
fi

printf "\nSource (best effort):\n"
if [ "$SOURCE_TYPE" = "unknown" ]; then
  printf "  unknown\n"
else
  if [ -n "$SOURCE_DETAIL" ]; then
    printf "  %s: %s\n" "$SOURCE_TYPE" "$SOURCE_DETAIL"
  else
    printf "  %s\n" "$SOURCE_TYPE"
  fi
fi

printf "\n"
print_ancestry "$pid"

printf "\n"
print_listeners "$pid"

printf "\nNotes:\n"
printf "  - Some details may require sudo.\n"
printf "  - Missing tools reduce fidelity (lsof/pstree/systemctl/launchctl).\n"
