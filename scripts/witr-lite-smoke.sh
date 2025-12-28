#!/usr/bin/env sh
set -eu

out="$(./scripts/witr-lite.sh --help)"
printf "%s" "$out" | grep -q "Usage:" || {
  printf "witr-lite help output missing Usage\n" >&2
  exit 1
}

printf "ok: witr-lite help\n"
