# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

A headless, TLS-terminating MITM proxy written in Rust. Built as a
composable foundation for HTTP traffic inspection and manipulation,
scoped narrowly on purpose.

**Design principle: Unix philosophy.** One tool, one job. No GUI, no
TUI, no bundled scanner, no scripting engine, no extension system.
If a feature request smells like "and it could also do X," the
answer is a separate tool that consumes this one's output, not a
new flag on this one.

## Scope (v1)

In scope:
- TLS-terminating MITM (local CA generation, cert install flow)
- Request/response interception
- Structured traffic logging (JSON lines; sqlite optional backend)
- Basic replay: resend a captured request with modifications
- Minimal CLI / query interface to inspect and filter captured traffic

Explicitly out of scope for v1, do not build unless asked:
- Any GUI or TUI
- Fuzzing / Intruder-style attack automation
- Scripting or plugin/extension system
- Active scanning logic
- VS Code or editor integration (that belongs in a separate tool)

If you find yourself designing for any of the above, stop and flag
it rather than building it.

## Architecture notes

- Async runtime: tokio
- Keep the proxy engine, the storage layer, and the CLI/query
  interface as separable modules. Other tools should be able to
  consume the structured output without depending on the CLI.
- Prefer composability over configuration: this tool should pipe
  cleanly into other tools rather than growing settings to replicate
  their behavior internally.

## Legal / ethical use

This is a security testing tool. The README must state plainly that
it's intended for authorized testing and local development use.
Don't build anything that implies or enables unauthorized
interception.

## Provenance

This project is built with Claude Code, human-directed and reviewed.
That's stated openly in the README, not hidden. Keep commit messages
and code comments honest about what was scaffolded vs. hand-written
where it's relevant, but don't over-narrate it either, normal
engineering commentary is enough.

## Commands

```
cargo build
cargo test
cargo clippy -- -D warnings
cargo run -- start                        # start proxy on 127.0.0.1:8080
cargo run -- logs                         # query captured traffic
cargo run -- replay <id>                  # replay a captured request
cargo run -- ca info                      # CA cert path + install instructions
```

## Status

Actively in the two-week trail sprint (see project roadmap / README
for current phase). v1 target: working proxy with logging and replay,
README with example output, roadmap section pointing at future
composable tools (not features bolted onto this one).
