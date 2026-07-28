#!/usr/bin/env bash
# End-to-end demo of taphttp's --intercept-socket feature.
#
# Starts a mock interceptor listening on a Unix socket, starts taphttp
# pointed at it, then fires two requests through the proxy: one that the
# interceptor forwards, one it drops. Prints every event the interceptor
# receives, the decision it sends back, and the resulting traffic log, so
# the intercept protocol is visible end to end.
#
# Requires: cargo, python3, curl. No task runner needed — just run it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
SOCKET="$WORKDIR/intercept.sock"
TRAFFIC_LOG="$WORKDIR/traffic.jsonl"
UPSTREAM_PORT=18081
PROXY_PORT=18080

PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  wait >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

wait_for_port() {
  for _ in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then
      exec 3>&-
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for 127.0.0.1:$1" >&2
  exit 1
}

echo "== Starting a mock upstream server on :$UPSTREAM_PORT =="
mkdir -p "$WORKDIR/upstream"
echo "hello from upstream" > "$WORKDIR/upstream/ok.txt"
(cd "$WORKDIR/upstream" && exec python3 -m http.server "$UPSTREAM_PORT" --bind 127.0.0.1) \
  >"$WORKDIR/upstream.log" 2>&1 &
PIDS+=("$!")
wait_for_port "$UPSTREAM_PORT"

echo "== Starting the mock interceptor on $SOCKET =="
# The interceptor implements the intercept-socket protocol: one connection
# per event, one JSON line in (a request or response event), one JSON line
# out (a forward or drop decision). This one forwards everything except
# requests for a URL containing "/block", which it drops with a 403.
python3 - "$SOCKET" <<'PY' &
import json
import os
import socket
import sys

sock_path = sys.argv[1]
if os.path.exists(sock_path):
    os.remove(sock_path)

srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(sock_path)
srv.listen(8)
print(f"[interceptor] listening on {sock_path}", flush=True)

while True:
    conn, _ = srv.accept()
    with conn:
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
        line = buf.decode().strip()
        if not line:
            continue

        event = json.loads(line)
        print(f"[interceptor] event:    {line}", flush=True)

        if event["type"] == "request" and "/block" in event["url"]:
            decision = {"action": "drop", "status": 403, "body": "blocked by interceptor demo"}
        else:
            decision = {"action": "forward"}

        print(f"[interceptor] decision: {json.dumps(decision)}", flush=True)
        conn.sendall((json.dumps(decision) + "\n").encode())
PY
PIDS+=("$!")

until [ -S "$SOCKET" ]; do sleep 0.1; done

echo "== Building taphttp =="
cargo build --quiet --manifest-path "$ROOT/Cargo.toml"
BIN="$ROOT/target/debug/taphttp"

echo "== Starting taphttp with --intercept-socket =="
TAPHTTP_DATA="$WORKDIR/data" "$BIN" start \
  --listen "127.0.0.1:$PROXY_PORT" \
  --intercept-socket "$SOCKET" \
  --log-file "$TRAFFIC_LOG" \
  >"$WORKDIR/taphttp.log" 2>&1 &
PIDS+=("$!")
wait_for_port "$PROXY_PORT"
sleep 0.2

echo
echo "== Request 1: GET /ok.txt (interceptor forwards it) =="
curl -s -x "http://127.0.0.1:$PROXY_PORT" \
  "http://127.0.0.1:$UPSTREAM_PORT/ok.txt" \
  -w '\nHTTP status: %{http_code}\n'

echo
echo "== Request 2: GET /block (interceptor drops it) =="
curl -s -x "http://127.0.0.1:$PROXY_PORT" \
  "http://127.0.0.1:$UPSTREAM_PORT/block" \
  -w '\nHTTP status: %{http_code}\n'

sleep 0.2

echo
echo "== Captured traffic (taphttp show) =="
echo "(only the forwarded request appears -- a drop short-circuits before the entry is recorded)"
"$BIN" show "$TRAFFIC_LOG"
