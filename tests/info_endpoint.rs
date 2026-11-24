//! `GET /info` from a fully configured `taphttp start`: it describes the
//! deployment, and no secret or path reaches it (#18). Runs the real binary.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const TOKEN: &str = "tok-5ecret-0123456789abcdef";
const USER: &str = "alice-user-marker";
const PASSWORD: &str = "hunter2-password-marker";

struct Running {
    child: Child,
    banner: String,
    api: String,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

/// Start taphttp and wait for both listeners; return the stderr seen and
/// the API's `host:port`.
fn start(data_dir: &std::path::Path, args: &[&str]) -> Running {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_taphttp"));
    cmd.arg("--data-dir").arg(data_dir).arg("start").args(args);
    for var in [
        "TAPHTTP_PROXY_AUTH",
        "TAPHTTP_DB",
        "TAPHTTP_API_TOKEN_FILE",
        "RUST_LOG",
    ] {
        cmd.env_remove(var);
    }
    let mut child = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    let mut banner = String::new();
    let (mut api, mut proxy_up) = (None, false);
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && !(api.is_some() && proxy_up) {
        let Some(Ok(line)) = lines.next() else { break };
        banner.push_str(&line);
        banner.push('\n');
        if let Some(addr) = line.strip_prefix("lever API listening on http://") {
            api = Some(addr.to_string());
        }
        proxy_up |= line.starts_with("taphttp listening on");
    }
    // Keep reading stderr for the child's lifetime. Dropping the pipe makes
    // taphttp's next stderr write fail with EPIPE, and `eprintln!` panics on
    // that, which killed the server mid-test (resets, refused connections).
    std::thread::spawn(move || lines.for_each(drop));
    let running = Running {
        child,
        banner: banner.clone(),
        api: api.unwrap_or_default(),
    };
    assert!(
        proxy_up && !running.api.is_empty(),
        "did not start:\n{banner}"
    );
    running
}

/// GET `path` over plain HTTP/1.1; return (status, body).
fn get(api: &str, path: &str, token: Option<&str>) -> (u16, String) {
    let (status, _, body) = get_bytes(api, path, token);
    (status, String::from_utf8(body).unwrap())
}

/// POST JSON to `path`; return (status, body).
fn post(api: &str, path: &str, token: &str, json: &serde_json::Value) -> (u16, String) {
    let mut s = TcpStream::connect(api).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let body = json.to_string();
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: {api}\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    let status = raw[9..12].parse().unwrap();
    let body = raw.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    (status, body.to_string())
}

/// GET `path`; return (status, raw head, body bytes).
fn get_bytes(api: &str, path: &str, token: Option<&str>) -> (u16, String, Vec<u8>) {
    let mut s = TcpStream::connect(api).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: {api}\r\n{auth}Connection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response head");
    let head = String::from_utf8(raw[..split].to_vec()).unwrap();
    let status = head[9..12].parse().unwrap();
    (status, head, raw[split + 4..].to_vec())
}

#[test]
fn info_describes_a_fully_configured_instance_and_leaks_nothing() {
    let dir = tempfile::TempDir::new().unwrap();
    let data = dir.path().join("data-dir-marker");
    std::fs::create_dir(&data).unwrap();
    let token_file = dir.path().join("token-file-marker");
    std::fs::write(&token_file, TOKEN).unwrap();
    let users = dir.path().join("users-file-marker");
    std::fs::write(&users, format!("{USER}:{PASSWORD}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&users, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let log = dir.path().join("log-file-marker.jsonl");
    let db = dir.path().join("db-file-marker.db");

    let t = start(
        &data,
        &[
            "--listen",
            "127.0.0.1:0",
            "--api-listen",
            "127.0.0.1:0",
            "--api-token-file",
            token_file.to_str().unwrap(),
            "--proxy-auth-file",
            users.to_str().unwrap(),
            "--allow-client",
            "127.0.0.0/8",
            "--log-file",
            log.to_str().unwrap(),
            "--db",
            db.to_str().unwrap(),
            "--expires",
            "1h",
        ],
    );

    let (status, _) = get(&t.api, "/info", None);
    assert_eq!(status, 401, "same bearer auth as every route");

    let (status, body) = get(&t.api, "/info", Some(TOKEN));
    assert_eq!(status, 200, "{body}");
    let info: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(info["taphttp_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(info["schema_version"], taphttp_types::SCHEMA_VERSION);
    assert!(info["started_at"].is_string());
    assert!(info["expires_at"].is_string(), "--expires 1h");
    assert_eq!(info["proxy"]["auth"], "basic");
    assert_eq!(info["proxy"]["tls"], false);
    assert_eq!(
        info["proxy"]["allow_client"],
        serde_json::json!(["127.0.0.0/8"])
    );
    let proxy_listen = info["proxy"]["listen"].as_str().unwrap();
    assert!(
        proxy_listen.starts_with("127.0.0.1:") && !proxy_listen.ends_with(":0"),
        "the bound port, not :0: {proxy_listen}"
    );
    assert_eq!(info["api"]["listen"], t.api.as_str());
    assert_eq!(info["api"]["send"], true, "POST /send is on by default");

    // POST /send refuses taphttp's own listeners (#22), by bound address,
    // and records nothing.
    for target in [proxy_listen, t.api.as_str()] {
        let (status, body) = post(
            &t.api,
            "/send",
            TOKEN,
            &serde_json::json!({"url": format!("http://{target}/")}),
        );
        assert_eq!(status, 400, "{target}: {body}");
        assert!(body.contains("own listeners"), "{body}");
    }
    let (_, recorded) = get(&t.api, "/exchanges?origin=send", Some(TOKEN));
    assert_eq!(recorded, "[]");
    assert_eq!(
        info["history"],
        serde_json::json!({"sqlite": true, "log_file": true})
    );
    assert_eq!(info["ca"]["subject"], "CN=taphttp local CA, O=taphttp");
    let sha = info["ca"]["sha256"].as_str().unwrap();
    assert!(
        t.banner.contains(&format!("CA SHA-256: {sha}")),
        "same pin as the banner:\n{}",
        t.banner
    );

    // Nothing secret, and no paths.
    let key_pem = std::fs::read_to_string(data.join("ca.key")).unwrap();
    let key_lines: Vec<&str> = key_pem
        .lines()
        .filter(|l| !l.starts_with("-----") && l.len() > 16)
        .collect();
    assert!(!key_lines.is_empty());
    // Every file and directory above is named `*-marker*`.
    let tmp = dir.path().to_str().unwrap();
    let mut forbidden: Vec<&str> = vec![TOKEN, USER, PASSWORD, "PRIVATE", "marker", tmp];
    forbidden.extend(key_lines);
    for needle in &forbidden {
        assert!(!body.contains(needle), "/info contains {needle:?}: {body}");
    }

    // GET /ca.pem and /ca.der (#20): the certificate /info pins, no key.
    for path in ["/ca.pem", "/ca.der"] {
        assert_eq!(get_bytes(&t.api, path, None).0, 401, "{path}");
    }
    let (status, _, pem) = get_bytes(&t.api, "/ca.pem", Some(TOKEN));
    assert_eq!(status, 200);
    let (status, head, der) = get_bytes(&t.api, "/ca.der", Some(TOKEN));
    assert_eq!(status, 200);
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: application/x-x509-ca-cert"),
        "{head}"
    );
    use rustls::pki_types::{pem::PemObject, CertificateDer};
    let from_pem = CertificateDer::from_pem_slice(&pem).unwrap();
    assert_eq!(from_pem.as_ref(), der.as_slice(), "same certificate");
    let pin: Vec<String> = ring::digest::digest(&ring::digest::SHA256, &der)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    assert_eq!(pin.join(":"), sha, "the certificate /info pins");
    let pem = String::from_utf8(pem).unwrap();
    assert_eq!(pem.matches("-----BEGIN").count(), 1, "{pem}");
    for needle in &forbidden {
        assert!(!pem.contains(needle), "/ca.pem contains {needle:?}");
    }
}

#[test]
fn info_reports_an_unauthenticated_local_instance_as_auth_none() {
    let dir = tempfile::TempDir::new().unwrap();
    let token_file = dir.path().join("tok");
    std::fs::write(&token_file, TOKEN).unwrap();
    let t = start(
        dir.path(),
        &[
            "--listen",
            "127.0.0.1:0",
            "--api-listen",
            "127.0.0.1:0",
            "--api-token-file",
            token_file.to_str().unwrap(),
        ],
    );
    let (status, body) = get(&t.api, "/info", Some(TOKEN));
    assert_eq!(status, 200, "{body}");
    let info: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(info["proxy"]["auth"], "none");
    assert_eq!(info["proxy"]["allow_client"], serde_json::json!([]));
    assert_eq!(info["expires_at"], serde_json::Value::Null);
    assert_eq!(
        info["history"],
        serde_json::json!({"sqlite": true, "log_file": false}),
        "--api-listen always records to sqlite"
    );
}

#[test]
fn send_can_be_turned_off_at_startup() {
    let dir = tempfile::TempDir::new().unwrap();
    let token_file = dir.path().join("tok");
    std::fs::write(&token_file, TOKEN).unwrap();
    let t = start(
        dir.path(),
        &[
            "--listen",
            "127.0.0.1:0",
            "--api-listen",
            "127.0.0.1:0",
            "--api-token-file",
            token_file.to_str().unwrap(),
            "--api-no-send",
        ],
    );
    let (_, body) = get(&t.api, "/info", Some(TOKEN));
    let info: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(info["api"]["send"], false);
    let (status, body) = post(
        &t.api,
        "/send",
        TOKEN,
        &serde_json::json!({"url": "http://127.0.0.1:1/"}),
    );
    assert_eq!(status, 403, "{body}");
}
