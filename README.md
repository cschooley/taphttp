# taphttp

A headless, TLS-terminating MITM proxy written in Rust. Built as a composable foundation for HTTP traffic inspection and manipulation.

> **Intended for authorized security testing and local development use only.**
> Do not use this tool to intercept traffic you are not authorized to inspect.

---

## What it does

- Intercepts HTTP and HTTPS traffic via a local proxy (CONNECT tunnel + TLS termination)
- Generates a local CA on first run; signs per-domain certificates on the fly
- Logs every request/response as JSON lines (optional SQLite backend)
- Lets you query and filter captured traffic from the command line
- Replays any captured request, optionally with modified headers or body

## What it doesn't do

No GUI, no TUI, no scanner, no fuzzer, no scripting engine. One tool, one job.
Future composable tools will consume this one's output — they won't be bolted onto this binary.

---

## Install

```sh
cargo install --path .
```

Or build from source:

```sh
cargo build --release
# binary at ./target/release/taphttp
```

---

## Quick start

**1. Start the proxy**

```sh
taphttp start
# taphttp listening on 127.0.0.1:8080
# taphttp: generated CA cert at ~/.local/share/taphttp/ca.crt
```

**2. Install the CA cert** (once, so your browser trusts intercepted HTTPS)

```sh
taphttp ca info        # shows install instructions per OS
taphttp ca print       # prints PEM to stdout, pipe it wherever you need it
```

Linux (system-wide):
```sh
sudo cp ~/.local/share/taphttp/ca.crt /usr/local/share/ca-certificates/taphttp.crt
sudo update-ca-certificates
```

**3. Point your client at the proxy**

```sh
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
curl https://example.com
```

**4. Query traffic**

```sh
taphttp logs
# ID                                    METHOD  HOST                  STATUS  URL
# ----------------------------------------------------------------------------------------------------
# 3f2a1b4c-...                          GET     example.com           200     https://example.com/

taphttp logs --host example.com --method GET --limit 20
taphttp logs --json | jq '.req_headers'
```

**5. Replay a request**

```sh
taphttp replay 3f2a1b4c-...
taphttp replay 3f2a1b4c-... --method POST --header "Authorization: Bearer newtoken" --body '{"key":"val"}'
```

---

## Options

### `taphttp start`

| Flag | Default | Description |
|---|---|---|
| `--listen` | `127.0.0.1:8080` | Address to listen on |
| `--sqlite` | off | Also write traffic to SQLite (`traffic.db`) |
| `--filter-host` | — | Only log requests whose host contains this substring |

### `taphttp logs`

| Flag | Default | Description |
|---|---|---|
| `--host` | — | Filter by host substring |
| `--method` | — | Filter by HTTP method |
| `--status` | — | Filter by response status code |
| `-n` / `--limit` | 50 | Show last N entries |
| `--json` | off | Output raw JSON lines instead of table |

### `taphttp replay <ID>`

| Flag | Description |
|---|---|
| `--method` | Override HTTP method |
| `--header KEY:VALUE` | Add or override a header (repeatable) |
| `--body` | Override request body |

### `taphttp ca`

| Subcommand | Description |
|---|---|
| `info` | Print CA cert path and OS-specific install instructions |
| `print` | Print CA cert as PEM (pipe to trust store tools) |

---

## Data directory

Default: `~/.local/share/taphttp/` (Linux) or `~/Library/Application Support/taphttp/` (macOS).

Override with `--data-dir <path>` or `TAPHTTP_DATA=<path>`.

Files:
- `ca.crt` / `ca.key` — local CA (generated once, keep the key private)
- `traffic.jsonl` — JSON-lines traffic log
- `traffic.db` — SQLite traffic log (only with `--sqlite`)

---

## Example traffic log entry

```json
{
  "id": "3f2a1b4c-8d9e-4a7b-b3c1-2e5f6a7d8e9f",
  "ts": "2026-07-02T14:23:01.123Z",
  "host": "example.com",
  "method": "GET",
  "url": "https://example.com/api/users",
  "req_headers": { "user-agent": "curl/8.4.0", "accept": "*/*" },
  "req_body": null,
  "status": 200,
  "res_headers": { "content-type": "application/json", "content-length": "42" },
  "res_body": "{\"users\":[]}",
  "duration_ms": 183
}
```

---

## Roadmap

v1 target: working proxy with logging and replay. ✓

Future tools (separate binaries that consume `taphttp`'s output):
- `taphttp-diff` — diff two traffic captures
- `taphttp-assert` — assert response shapes for regression testing
- `taphttp-export` — convert JSON lines to HAR, Burp XML, etc.

These will be separate tools that read from `traffic.jsonl`, not flags on this binary.

---

## Provenance

Built with Claude Code, human-directed and reviewed. See commit history for what was scaffolded vs. hand-written.
