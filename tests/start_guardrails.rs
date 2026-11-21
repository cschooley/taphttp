//! `taphttp start` refuses unsafe exposure before binding anything, and
//! still starts in every safe mode. Runs the real binary.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn taphttp(data_dir: &std::path::Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_taphttp"));
    c.arg("--data-dir").arg(data_dir);
    for var in [
        "TAPHTTP_PROXY_AUTH",
        "TAPHTTP_DB",
        "TAPHTTP_API_TOKEN_FILE",
        "RUST_LOG",
    ] {
        c.env_remove(var);
    }
    c.stdout(Stdio::null()).stderr(Stdio::piped());
    c
}

/// Run to completion; return (success, stderr).
fn refused(args: &[&str]) -> (bool, String, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().unwrap();
    let out = taphttp(dir.path())
        .arg("start")
        .args(args)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        dir,
    )
}

/// Spawn, wait until it reports the proxy listening, return the stderr seen.
fn starts(args: &[&str], env: &[(&str, &str)]) -> String {
    let dir = tempfile::TempDir::new().unwrap();
    let mut cmd = taphttp(dir.path());
    cmd.arg("start").args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child: Child = cmd.spawn().unwrap();
    let mut seen = String::new();
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match lines.next() {
            Some(Ok(line)) => {
                seen.push_str(&line);
                seen.push('\n');
                if line.starts_with("taphttp listening on") {
                    child.kill().ok();
                    child.wait().ok();
                    return seen;
                }
            }
            _ => break,
        }
    }
    child.kill().ok();
    child.wait().ok();
    panic!("taphttp {args:?} did not start:\n{seen}");
}

#[test]
fn local_default_still_starts_with_no_new_flags() {
    let err = starts(&["--listen", "127.0.0.1:0"], &[]);
    assert!(err.contains("mode: local"), "{err}");
}

#[test]
fn non_loopback_proxy_without_auth_and_tls_is_refused_before_creating_a_ca() {
    let (ok, err, dir) = refused(&["--listen", "0.0.0.0:0"]);
    assert!(!ok, "must exit non-zero");
    assert!(err.contains("refusing to listen on 0.0.0.0:0"), "{err}");
    assert!(
        err.contains("--proxy-auth-file")
            && err.contains("--proxy-tls")
            && err.contains("--allow-open-proxy"),
        "{err}"
    );
    assert!(
        !dir.path().join("ca.crt").exists(),
        "refused before touching the CA"
    );
}

#[test]
fn non_loopback_proxy_with_auth_but_no_tls_is_refused() {
    let dir = tempfile::TempDir::new().unwrap();
    let out = taphttp(dir.path())
        .args(["start", "--listen", "0.0.0.0:0"])
        .env("TAPHTTP_PROXY_AUTH", "you:pw")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--proxy-tls") && !err.contains("--proxy-auth-file"),
        "{err}"
    );
}

#[test]
fn non_loopback_api_without_tls_is_refused() {
    let (ok, err, _d) = refused(&["--listen", "127.0.0.1:0", "--api-listen", "0.0.0.0:0"]);
    assert!(!ok);
    assert!(
        err.contains("lever API")
            && err.contains("--api-tls")
            && err.contains("--api-allow-plaintext"),
        "{err}"
    );
}

#[test]
fn compose_style_explicit_opt_outs_start() {
    let err = starts(
        &[
            "--listen",
            "0.0.0.0:0",
            "--allow-open-proxy",
            "--api-listen",
            "0.0.0.0:0",
            "--api-allow-plaintext",
        ],
        &[],
    );
    assert!(err.contains("OPEN (--allow-open-proxy)"), "{err}");
    assert!(err.contains("plaintext (--api-allow-plaintext)"), "{err}");
}

#[test]
fn remote_with_auth_and_tls_starts_and_never_prints_the_password() {
    let err = starts(
        &[
            "--listen",
            "0.0.0.0:0",
            "--proxy-tls",
            "--tls-name",
            "proxy.lan",
            "--api-listen",
            "0.0.0.0:0",
            "--api-tls",
        ],
        &[("TAPHTTP_PROXY_AUTH", "agent.T-3:hunter2-secret")],
    );
    assert!(
        err.contains("mode: remote") && err.contains("proxy auth (1 user)") && err.contains("TLS"),
        "{err}"
    );
    assert!(err.contains("CA SHA-256:"), "{err}");
    assert!(!err.contains("hunter2-secret"), "{err}");
}

#[test]
fn tls_on_a_wildcard_without_a_name_is_refused() {
    let dir = tempfile::TempDir::new().unwrap();
    let out = taphttp(dir.path())
        .args(["start", "--listen", "0.0.0.0:0", "--proxy-tls"])
        .env("TAPHTTP_PROXY_AUTH", "you:pw")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--tls-name"));
}

#[test]
fn bad_allow_client_and_past_expiry_are_refused() {
    let (ok, err, _d) = refused(&["--listen", "127.0.0.1:0", "--allow-client", "10.0.0.0/40"]);
    assert!(!ok && err.contains("--allow-client"), "{err}");
    let (ok, err, _d) = refused(&[
        "--listen",
        "127.0.0.1:0",
        "--expires",
        "2020-01-01T00:00:00Z",
    ]);
    assert!(!ok && err.contains("in the past"), "{err}");
}

#[test]
fn expiry_makes_the_process_exit_on_its_own() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut child = taphttp(dir.path())
        .args(["start", "--listen", "127.0.0.1:0", "--expires", "2s"])
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let mut err = String::new();
            std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut err).unwrap();
            assert!(status.success(), "{err}");
            assert!(err.contains("expired"), "{err}");
            assert!(
                err.contains("expires: 20"),
                "banner states the expiry:\n{err}"
            );
            return;
        }
        if Instant::now() > deadline {
            child.kill().ok();
            child.wait().ok();
            panic!("did not exit after --expires 2s");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
