#!/usr/bin/env bash
# L4Scope test suite. Runs unit + integration tests, then black-box smoke tests
# against the built binary. Native backend (eBPF/ETW) feature builds are attempted
# only when the toolchain is present and are non-fatal.
#
# Usage: ./scripts/run-tests.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
FAIL=0
step()  { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
ok()    { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()   { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=1; }
info()  { printf '  \033[33mSKIP/INFO\033[0m %s\n' "$1"; }

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found — install Rust (see README) then re-run." >&2
  exit 127
fi

# 1) Compile the whole workspace (default = std-only, all platforms).
step "cargo build (workspace, default features)"
if cargo build --workspace --quiet; then ok "workspace builds"; else bad "workspace build"; fi

# 2) Unit + integration tests.
step "cargo test (workspace)"
if cargo test --workspace --quiet; then ok "all tests"; else bad "cargo test"; fi

# 3) Release binary for black-box smoke tests.
step "cargo build --release -p l4scope-agent"
if cargo build --release -p l4scope-agent --quiet; then ok "release binary"; else bad "release build"; fi
BIN="$ROOT/target/release/l4scope"

# 4) Smoke: synthetic demo trips detectors.
step "smoke: --demo"
if [ -x "$BIN" ]; then
  OUT="$("$BIN" --demo --no-metrics 2>&1)"
  for kind in rst_storm retransmission zero_window handshake_failure syn_backlog; do
    if grep -qi "$kind" <<<"$OUT"; then ok "demo emitted $kind"; else bad "demo missing $kind"; fi
  done
else
  info "no release binary; skipping demo smoke"
fi

# 5) Smoke: pcap replay.
step "smoke: --pcap testdata/sample.pcap"
if [ -x "$BIN" ] && [ -f testdata/sample.pcap ]; then
  OUT="$("$BIN" --pcap testdata/sample.pcap --no-metrics 2>&1)"
  for kind in retransmission zero_window high_rtt; do
    if grep -qi "$kind" <<<"$OUT"; then ok "pcap emitted $kind"; else bad "pcap missing $kind"; fi
  done
else
  info "no binary or sample.pcap; skipping pcap smoke"
fi

# 6) Smoke: OTLP export reaches a collector (one-shot python receiver).
step "smoke: OTLP push"
if [ -x "$BIN" ] && command -v python3 >/dev/null 2>&1; then
  RECV=/tmp/l4scope_otlp.$$.json; rm -f "$RECV"
  python3 - "$RECV" <<'PY' &
import http.server, sys
out = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', '0'))
        open(out, 'wb').write(self.rfile.read(n))
        self.send_response(200); self.end_headers()
    def log_message(self, *a): pass
srv = http.server.HTTPServer(('127.0.0.1', 4318), H)
srv.timeout = 10
srv.handle_request()
PY
  PYPID=$!
  sleep 1
  CFG="$(mktemp)"; cat > "$CFG" <<EOF
[capture]
backend = "synthetic"
[export]
prometheus_addr = ""
json_events = "off"
[otlp]
enabled = true
endpoint = "http://127.0.0.1:4318"
interval_secs = 1
pod_attribution = true
pod_cidrs = "10.0.0.0/8"
EOF
  "$BIN" --config "$CFG" >/dev/null 2>&1
  wait "$PYPID" 2>/dev/null
  if [ -f "$RECV" ] && grep -q "resourceMetrics" "$RECV"; then
    ok "collector received OTLP metrics"
    grep -q "l4scope.pod.events" "$RECV" && ok "pod-level series present" || info "no pod series (check pod_cidrs)"
  else
    bad "no OTLP payload received"
  fi
  rm -f "$CFG" "$RECV"
else
  info "python3 or binary missing; skipping OTLP smoke"
fi

# 7) Native feature builds (Linux eBPF) — non-fatal, toolchain-gated.
step "native backend build (informational)"
if [ "$(uname -s)" = "Linux" ] && command -v clang >/dev/null 2>&1 && [ -f bpf/vmlinux.h ]; then
  if cargo build -p l4scope-agent --features ebpf --quiet; then ok "eBPF feature builds"; else info "eBPF build failed (see docs/BUILD_NATIVE.md)"; fi
else
  info "eBPF build skipped (needs Linux + clang + bpf/vmlinux.h)"
fi

# 8) Style (informational only).
step "fmt / clippy (informational)"
cargo fmt --all --check >/dev/null 2>&1 && ok "rustfmt clean" || info "run 'cargo fmt --all'"
cargo clippy --workspace --quiet >/dev/null 2>&1 && ok "clippy clean" || info "clippy has suggestions"

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[32mAll required checks passed.\033[0m\n'
else
  printf '\033[31mSome required checks failed.\033[0m\n'
fi
exit "$FAIL"
