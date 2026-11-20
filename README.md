# taphttp

A headless, TLS-terminating MITM proxy written in Rust. Built as a composable foundation for HTTP traffic inspection and manipulation.

> **Intended for authorized security testing and local development use only.**
> Do not use this tool to intercept traffic you are not authorized to inspect.

---

## What it does

- Intercepts HTTP and HTTPS traffic via a local proxy (CONNECT tunnel + TLS termination)
- Generates a local CA on first run; signs per-domain certificates on the fly
- Streams every request/response as JSON lines to stdout
- Optionally also writes to a file (`--log-file`) or SQLite (`--sqlite`)
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

Traffic is streamed to stdout as JSON lines. Redirect or pipe it however you like.

```sh
# Stream to another tool
taphttp start | assessment-tool

# Save to a file
taphttp start > traffic.jsonl

# Save to a file and also watch live
taphttp start | tee traffic.jsonl

# Save to a file explicitly (stdout still active)
taphttp start --log-file traffic.jsonl
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

**4. Inspect captured traffic**

```sh
# Show everything in a file
taphttp show traffic.jsonl

# Filter by host, method, or status
taphttp show traffic.jsonl --host api.example.com
taphttp show traffic.jsonl --method POST --status 401
taphttp show traffic.jsonl -n 20

# Raw JSON lines (pipe to jq, grep, etc.)
taphttp show traffic.jsonl --json | jq '.res_body'
taphttp show traffic.jsonl --json | jq 'select(.status >= 400)'
taphttp show traffic.jsonl --json | jq '{method, url, req_headers, res_headers}'

# Same patterns work on live output
taphttp start | jq '{method, url, req_headers, res_headers}'
taphttp start | jq 'select(.status >= 400)'
```

**5. Replay a request**

Replay reads the original request from a log file, so capture to one first
(stdout alone isn't enough). The replay is recorded into the same file,
linked to the original via `replay_of`.

```sh
taphttp start --log-file traffic.jsonl
# ...capture some traffic, then pick an ID:
taphttp show traffic.jsonl

taphttp replay --log-file traffic.jsonl <ID>
taphttp replay --log-file traffic.jsonl <ID> --method POST --header "Authorization: Bearer newtoken" --body '{"key":"val"}'
```

If `--log-file` is omitted, replay reads `<data-dir>/traffic.jsonl`.

**6. Intercept and modify traffic live**

`--intercept-socket <path>` pauses every request and response on a Unix
socket, one connection per event, until something on the other end writes
back a decision (forward, forward with overrides, or drop). See
[`demo/intercept.sh`](demo/intercept.sh) for a runnable example, including
the exact JSON the proxy sends and expects back:

```sh
./demo/intercept.sh
```

Intercept events carry headers as a `{name: value}` map. Repeated headers are
joined with `", "`, so a hook sees every value. The traffic log keeps them as
separate pairs.

---

## Options

### `taphttp start`

| Flag | Default | Description |
|---|---|---|
| `--listen` | `127.0.0.1:8080` | Address to listen on |
| `--log-file` | — | Also write traffic to this file |
| `--sqlite` | off | Also write traffic to SQLite (`traffic.db` in data dir) |
| `--filter-host` | — | Only log requests whose host contains this substring |
| `--intercept-socket` | — | Unix socket path for the intercept hook (pauses each request/response) |
| `--api-listen` | — | Also serve the [lever API](#lever-api) (HTTP + WebSocket) on this address |

Traffic is always written to stdout as JSON lines. `--log-file` and `--sqlite` are additive.

### `taphttp show <FILE>`

| Flag | Default | Description |
|---|---|---|
| `--host` | — | Filter by host substring |
| `--method` | — | Filter by HTTP method |
| `--status` | — | Filter by response status code |
| `-n` / `--limit` | all | Show last N entries |
| `--json` | off | Output raw JSON lines instead of table |

### `taphttp replay <ID>`

| Flag | Description |
|---|---|
| `--log-file` | Log to read the request from and record the replay into (default `<data-dir>/traffic.jsonl`) |
| `--method` | Override HTTP method |
| `--header KEY:VALUE` | Set a header, replacing every captured value for that name (repeatable) |
| `--body` | Override request body |

### `taphttp ca`

| Subcommand | Description |
|---|---|
| `info` | Print CA cert path and OS-specific install instructions |
| `print` | Print CA cert as PEM (pipe to trust store tools) |

---

## Lever API

An optional local HTTP + WebSocket interface over the capture store, so other
tools can query traffic and replay requests without shelling out to the CLI.
taphttp itself stays headless — this is the seam a separate dashboard, an MCP
server, or an agent consumes (see [docs/findings-architecture.md](docs/findings-architecture.md)).

Enable it with `--api-listen`, alongside `--log-file` so there is history to
read:

```bash
taphttp start --api-listen 127.0.0.1:8081 --log-file ./traffic.jsonl
```

### Authentication

Every endpoint requires a bearer token. On startup taphttp generates one,
prints it to stderr, and writes it to `<data-dir>/api-token` (mode `0600`).
Pass it as a header, or — for the WebSocket, which browsers can't send headers
on — as a `?token=` query parameter:

```bash
TOKEN=$(cat <data-dir>/api-token)
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8081/exchanges
```

### Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/schema` | `{ "schema_version": N }` — the traffic-entry contract to pin against |
| `GET` | `/exchanges` | Captured exchanges; filter with `?host=`, `?method=`, `?status=`, `?limit=` |
| `GET` | `/exchanges/{id}` | A single exchange by `id`, or `404` |
| `POST` | `/replay` | Replay a captured exchange; records the result linked via `replay_of` |
| `GET` | `/feed` | WebSocket stream of exchanges as they are recorded |

`POST /replay` takes a JSON body — `id` is required, the rest optional:

```bash
curl -X POST http://127.0.0.1:8081/replay \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"id":"<exchange-id>","method":"POST","headers":{"x-test":"1"},"body":"..."}'
```

Each entry in `headers` replaces every captured value for that name (the same
rule as the CLI's `--header`). Other captured headers, including repeated
ones, are sent as captured.

The response is the newly recorded exchange (with its own `id` and
`replay_of` set), which also appears on `/feed` and in `/exchanges`.

The API binds only where you tell it to; keep it on loopback unless you have a
reason not to. The `?token=` form can land in logs, so prefer the header
except for the WebSocket.

---

## Data directory

Default: `~/.local/share/taphttp/` (Linux) or `~/Library/Application Support/taphttp/` (macOS).

Override with `--data-dir <path>` or `TAPHTTP_DATA=<path>`.

Files written here:
- `ca.crt` / `ca.key` — local CA (generated once, keep the key private)
- `traffic.db` — SQLite traffic log (only with `--sqlite`)
- `api-token` — bearer token for the lever API, mode `0600` (only with `--api-listen`)

Traffic JSON lines go to stdout by default. Use `--log-file <path>` to also write to a file anywhere you choose.

---

## Example traffic log entry

Each line is one exchange (shown pretty-printed here):

```json
{
  "schema_version": 3,
  "id": "3f2a1b4c-8d9e-4a7b-b3c1-2e5f6a7d8e9f",
  "ts": "2026-07-02T14:23:01.123Z",
  "host": "example.com",
  "method": "GET",
  "url": "https://example.com/api/users",
  "req_headers": [["user-agent", "curl/8.4.0"], ["accept", "*/*"]],
  "req_body": null,
  "req_body_encoding": "utf8",
  "status": 200,
  "res_headers": [
    ["content-type", "application/json"],
    ["set-cookie", "session=abc; Secure; HttpOnly"],
    ["set-cookie", "theme=dark; SameSite=Lax"]
  ],
  "res_body": "{\"users\":[]}",
  "res_body_encoding": "utf8",
  "duration_ms": 183,
  "replay_of": null
}
```

- `schema_version` is on every line, so a tool tailing the log can detect a
  breaking change. The current version is 3.
- Headers are `[name, value]` pairs in wire order. Repeated headers (several
  `Set-Cookie`s, say) each get a pair. A value that isn't valid UTF-8 is
  kept with the bad bytes replaced by U+FFFD, not dropped.
- Bodies are byte-exact. `*_body_encoding` is `"utf8"` when the body string
  is the bytes, or `"base64"` when the bytes weren't valid UTF-8 (images,
  protobuf, undecoded gzip). Replay decodes base64 before sending.
- `replay_of` is `null` for captured traffic. For an exchange produced by a
  replay, it holds the `id` of the original.

To decode base64 bodies with jq: `jq -r 'select(.res_body_encoding=="base64") | .res_body | @base64d'`.

### Schema history and compatibility

| Version | Change |
|---|---|
| 3 | Headers as ordered pairs; non-UTF-8 header values kept; `req_body_encoding` / `res_body_encoding`; `schema_version` on every line |
| 2 | `replay_of` |
| 1 | Initial |

taphttp still reads v1 and v2 logs (`show`, `replay`, the lever API): a
header map is read as pairs, and a missing encoding means `utf8`. Anything
taphttp writes or re-emits (`show --json`, `/exchanges`) is v3.

### Using the types from Rust

The schema is published as the `taphttp-types` crate in this repo
(`crates/taphttp-types`). It depends only on `serde` and `chrono`, so
consumers don't pull in the proxy:

```toml
[dependencies]
taphttp-types = { git = "https://github.com/cschooley/taphttp", tag = "<tag>" }
```

```rust
use taphttp_types::{TrafficEntry, SchemaProbe, SCHEMA_VERSION};

let entry: TrafficEntry = serde_json::from_str(line)?;
let cookies: Vec<&str> = entry.res_headers.get_all("set-cookie").collect();
let body: Option<Vec<u8>> = entry.res_body_bytes()?; // exact bytes, base64 or not
```

`SchemaProbe` reads only `schema_version` from a raw line, for checking the
version before a full parse.

---

## Roadmap

v1 target: working proxy with logging and replay. ✓

Future tools (separate binaries that consume `taphttp`'s output):
- `taphttp-diff` — diff two traffic captures
- `taphttp-assert` — assert response shapes for regression testing
- `taphttp-export` — convert JSON lines to HAR, Burp XML, etc.
- Companion assessment tool (name TBD): SPA dashboard + MCP server for human and agentic testing on top of `taphttp`'s log and replay, with findings exported as [flux](docs/flux/SPEC.md) (a SARIF 2.1.0 profile). See [docs/findings-architecture.md](docs/findings-architecture.md).

These will be separate tools that read from `taphttp`'s stdout or a saved file, not flags on this binary.

---

## Provenance

Built with Claude Code, human-directed and reviewed. See commit history for what was scaffolded vs. hand-written.
