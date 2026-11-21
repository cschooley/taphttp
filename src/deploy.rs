//! Deployment safety: what taphttp may expose, to whom, and for how long.
//!
//! On loopback nothing here changes behavior. Off-box (a jump box, a VPS, a
//! client network) taphttp is a credential-capturing MITM proxy, so:
//! - a non-loopback proxy listener needs proxy auth **and** TLS on the
//!   listener (Basic credentials are cleartext otherwise), or an explicit
//!   `--allow-open-proxy` (e.g. a compose network published on 127.0.0.1);
//! - a non-loopback lever API needs TLS, or `--api-allow-plaintext`.
//!
//! Kept free of proxy internals so other sensors (the planned OOB listener)
//! can reuse the same rules.

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Duration, Utc};

// ---------------------------------------------------------------------------
// Startup exposure check
// ---------------------------------------------------------------------------

/// What `start` is about to expose. Checked before anything binds.
#[derive(Debug, Clone, Default)]
pub struct Exposure {
    pub proxy: Option<SocketAddr>,
    pub proxy_tls: bool,
    pub proxy_auth: bool,
    pub allow_open_proxy: bool,
    pub api: Option<SocketAddr>,
    pub api_tls: bool,
    pub api_allow_plaintext: bool,
}

/// Refuse the unsafe combinations, saying what to do instead.
pub fn check_exposure(e: &Exposure) -> Result<()> {
    if let Some(addr) = e.proxy {
        if !addr.ip().is_loopback() && !e.allow_open_proxy {
            let mut missing = Vec::new();
            if !e.proxy_auth {
                missing.push("proxy auth (--proxy-auth-file or TAPHTTP_PROXY_AUTH)");
            }
            if !e.proxy_tls {
                missing.push("TLS on the proxy listener (--proxy-tls)");
            }
            if !missing.is_empty() {
                bail!(
                    "refusing to listen on {addr}: off-loopback, taphttp is an intercepting proxy anyone \
                     on that network could use, with their traffic landing in your log. A non-loopback \
                     --listen needs {}. If the port is only reachable from a private network (e.g. a \
                     compose port published on 127.0.0.1), pass --allow-open-proxy.",
                    missing.join(" and ")
                );
            }
        }
    }
    if let Some(addr) = e.api {
        if !addr.ip().is_loopback() && !e.api_tls && !e.api_allow_plaintext {
            bail!(
                "refusing to serve the lever API on {addr} in plaintext: the token and every captured \
                 credential in /exchanges and /feed would cross the network in the clear. Pass --api-tls, \
                 or bind it to loopback or a tunnel interface (WireGuard, SSH). If only a private network \
                 can reach it (e.g. a compose network), pass --api-allow-plaintext."
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Client allowlist
// ---------------------------------------------------------------------------

/// An IPv4 or IPv6 network, e.g. `10.0.0.0/8`, `fd00::/8`, or one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl std::str::FromStr for Cidr {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let net: IpAddr = addr
            .parse()
            .with_context(|| format!("--allow-client {s:?}: not an IP address or CIDR (e.g. 10.0.0.0/8)"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .with_context(|| format!("--allow-client {s:?}: prefix must be 0..={max}"))?,
            None => max,
        };
        Ok(Self { net, prefix })
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.net, self.prefix)
    }
}

impl Cidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        // An IPv4 client on a dual-stack socket shows up as ::ffff:a.b.c.d.
        match (self.net, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.prefix)).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(self.prefix)).unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// An empty allowlist allows everyone.
pub fn client_allowed(allow: &[Cidr], ip: IpAddr) -> bool {
    allow.is_empty() || allow.iter().any(|c| c.contains(ip))
}

// ---------------------------------------------------------------------------
// Proxy credentials
// ---------------------------------------------------------------------------

/// `user:password` pairs proxy clients must present (Basic auth).
pub struct ProxyCredentials {
    users: Vec<(String, String)>,
}

impl std::fmt::Debug for ProxyCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print passwords.
        let names: Vec<&str> = self.users.iter().map(|(u, _)| u.as_str()).collect();
        f.debug_struct("ProxyCredentials").field("users", &names).finish()
    }
}

impl ProxyCredentials {
    /// One `user:password` per line; blank lines and `#` comments ignored.
    /// The username can't contain `:` (Basic auth splits on the first one),
    /// so tag task ids with another separator, e.g. `agent.T-3`.
    pub fn parse(text: &str) -> Result<Self> {
        let mut users = Vec::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((user, pass)) = line.split_once(':') else {
                bail!("proxy credentials line {}: expected user:password", n + 1);
            };
            if user.is_empty() || pass.is_empty() {
                bail!("proxy credentials line {}: user and password must both be non-empty", n + 1);
            }
            users.push((user.to_string(), pass.to_string()));
        }
        if users.is_empty() {
            bail!("proxy credentials: no user:password lines found");
        }
        Ok(Self { users })
    }

    /// From `--proxy-auth-file`, else from `TAPHTTP_PROXY_AUTH`, else none.
    /// Credentials are never taken from a CLI argument, where `ps` shows them.
    pub fn load(file: Option<&Path>, env: Option<String>) -> Result<Option<Self>> {
        if let Some(path) = file {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading proxy credentials from {}", path.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(path)?.permissions().mode();
                if mode & 0o077 != 0 {
                    tracing::warn!(
                        "proxy credentials file {} is readable by group/others (mode {:o}); run `chmod 600` on it",
                        path.display(),
                        mode & 0o777
                    );
                }
            }
            return Self::parse(&text)
                .with_context(|| format!("in {}", path.display()))
                .map(Some);
        }
        match env {
            Some(text) if !text.trim().is_empty() => {
                Self::parse(&text).context("in TAPHTTP_PROXY_AUTH").map(Some)
            }
            _ => Ok(None),
        }
    }

    pub fn len(&self) -> usize {
        self.users.len()
    }

    fn verify(&self, user: &str, pass: &str) -> bool {
        // Check every entry so timing doesn't reveal which usernames exist.
        let mut ok = false;
        for (u, p) in &self.users {
            ok |= constant_time_eq(u.as_bytes(), user.as_bytes()) & constant_time_eq(p.as_bytes(), pass.as_bytes());
        }
        ok
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// `Basic <base64(user:pass)>` -> `(user, pass)`. The scheme is
/// case-insensitive; the password may be empty.
pub fn parse_basic(value: &[u8]) -> Option<(String, String)> {
    let value = std::str::from_utf8(value).ok()?.trim();
    let (scheme, b64) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = taphttp_types::decode_body(Some(b64.trim()), taphttp_types::BodyEncoding::Base64).ok()??;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, pass) = decoded.split_once(':').unwrap_or((&decoded, ""));
    Some((user.to_string(), pass.to_string()))
}

/// The client failed proxy auth: answer `407 Proxy Authentication Required`.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthRequired;

/// Decide a request's `source` from its `Proxy-Authorization` header.
///
/// - No credentials configured: the username, if any, is a self-reported
///   label (`None` without one). Nothing is rejected.
/// - Credentials configured: the header must match one; the source is that
///   authenticated username. Anything else is [`AuthRequired`].
///
/// Only the username is ever returned, never the password.
pub fn authorize(header: Option<&[u8]>, creds: Option<&ProxyCredentials>) -> Result<Option<String>, AuthRequired> {
    let parsed = header.and_then(parse_basic);
    match creds {
        None => Ok(parsed.map(|(u, _)| u).filter(|u| !u.is_empty())),
        Some(creds) => match parsed {
            Some((u, p)) if creds.verify(&u, &p) => Ok(Some(u)),
            _ => Err(AuthRequired),
        },
    }
}

// ---------------------------------------------------------------------------
// Expiry
// ---------------------------------------------------------------------------

/// `--expires`: an RFC 3339 time, or a duration from `now` like `90s`,
/// `30m`, `8h`, `2d`. Must be in the future.
pub fn parse_expires(s: &str, now: DateTime<Utc>) -> Result<DateTime<Utc>> {
    let at = if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        t.with_timezone(&Utc)
    } else {
        let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
        let n: i64 = num
            .parse()
            .ok()
            .with_context(|| format!("--expires {s:?}: expected a duration like 8h or an RFC 3339 time"))?;
        let d = match unit {
            "s" => Duration::try_seconds(n),
            "m" => Duration::try_minutes(n),
            "h" => Duration::try_hours(n),
            "d" => Duration::try_days(n),
            _ => bail!("--expires {s:?}: unit must be s, m, h or d"),
        }
        .with_context(|| format!("--expires {s:?}: too large"))?;
        now + d
    };
    if at <= now {
        bail!("--expires {s:?} is already in the past ({at})");
    }
    Ok(at)
}

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

/// What a deployment is doing, for the startup log: an auditable record.
#[derive(Debug, Default)]
pub struct BannerInfo {
    pub exposure: Exposure,
    pub allow_clients: Vec<Cidr>,
    pub proxy_users: usize,
    pub expires: Option<DateTime<Utc>>,
    pub ca_fingerprint: String,
}

pub fn banner(b: &BannerInfo) -> String {
    let e = &b.exposure;
    let remote = e.proxy.is_some_and(|a| !a.ip().is_loopback()) || e.api.is_some_and(|a| !a.ip().is_loopback());
    let mut out = String::new();
    let _ = writeln!(out, "taphttp {} mode: {}", env!("CARGO_PKG_VERSION"), if remote { "remote" } else { "local (loopback only)" });
    if let Some(addr) = e.proxy {
        let mut access = Vec::new();
        if !b.allow_clients.is_empty() {
            let list: Vec<String> = b.allow_clients.iter().map(|c| c.to_string()).collect();
            access.push(format!("clients {}", list.join(", ")));
        }
        if e.proxy_auth {
            access.push(format!("proxy auth ({} user{})", b.proxy_users, if b.proxy_users == 1 { "" } else { "s" }));
        }
        if access.is_empty() {
            access.push(if e.allow_open_proxy { "OPEN (--allow-open-proxy)".into() } else { "none".into() });
        }
        let _ = writeln!(
            out,
            "  proxy: {addr} {}; access: {}",
            if e.proxy_tls { "TLS" } else { "plaintext" },
            access.join(" + ")
        );
    }
    if let Some(addr) = e.api {
        let transport = match (e.api_tls, e.api_allow_plaintext) {
            (true, _) => "TLS",
            (false, true) if !addr.ip().is_loopback() => "plaintext (--api-allow-plaintext)",
            _ => "plaintext",
        };
        let _ = writeln!(out, "  lever API: {addr} {transport}; bearer token");
    }
    match b.expires {
        Some(t) => {
            let _ = writeln!(out, "  expires: {}", t.to_rfc3339());
        }
        None => {
            let _ = writeln!(out, "  expires: never");
        }
    }
    let _ = write!(out, "  CA SHA-256: {}", b.ca_fingerprint);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> Option<SocketAddr> {
        Some(s.parse().unwrap())
    }

    // --- exposure ---

    #[test]
    fn loopback_needs_nothing() {
        let e = Exposure { proxy: addr("127.0.0.1:8080"), api: addr("127.0.0.1:8081"), ..Default::default() };
        check_exposure(&e).unwrap();
        let e = Exposure { proxy: addr("[::1]:8080"), ..Default::default() };
        check_exposure(&e).unwrap();
    }

    #[test]
    fn remote_proxy_needs_auth_and_tls() {
        let base = Exposure { proxy: addr("0.0.0.0:8080"), ..Default::default() };
        let err = check_exposure(&base).unwrap_err().to_string();
        assert!(err.contains("--proxy-auth-file") && err.contains("--proxy-tls") && err.contains("--allow-open-proxy"), "{err}");

        let auth_only = Exposure { proxy_auth: true, ..base.clone() };
        let err = check_exposure(&auth_only).unwrap_err().to_string();
        assert!(err.contains("--proxy-tls") && !err.contains("--proxy-auth-file"), "{err}");

        let tls_only = Exposure { proxy_tls: true, ..base.clone() };
        assert!(check_exposure(&tls_only).unwrap_err().to_string().contains("--proxy-auth-file"));

        check_exposure(&Exposure { proxy_auth: true, proxy_tls: true, ..base.clone() }).unwrap();
        check_exposure(&Exposure { allow_open_proxy: true, ..base }).unwrap();
    }

    #[test]
    fn remote_api_needs_tls_or_explicit_plaintext() {
        let base = Exposure { api: addr("10.1.2.3:8081"), ..Default::default() };
        let err = check_exposure(&base).unwrap_err().to_string();
        assert!(err.contains("--api-tls") && err.contains("--api-allow-plaintext"), "{err}");
        check_exposure(&Exposure { api_tls: true, ..base.clone() }).unwrap();
        check_exposure(&Exposure { api_allow_plaintext: true, ..base }).unwrap();
    }

    // --- allowlist ---

    #[test]
    fn cidr_parses_and_matches_v4_and_v6() {
        let net: Cidr = "10.0.0.0/8".parse().unwrap();
        assert!(net.contains("10.200.3.4".parse().unwrap()));
        assert!(!net.contains("11.0.0.1".parse().unwrap()));
        assert!(net.contains("::ffff:10.1.1.1".parse().unwrap()), "v4-mapped client matches");
        let host: Cidr = "192.168.1.5".parse().unwrap();
        assert!(host.contains("192.168.1.5".parse().unwrap()));
        assert!(!host.contains("192.168.1.6".parse().unwrap()));
        let v6: Cidr = "fd00::/8".parse().unwrap();
        assert!(v6.contains("fd12::1".parse().unwrap()));
        assert!(!v6.contains("fe80::1".parse().unwrap()));
        assert!(!v6.contains("10.0.0.1".parse().unwrap()));
        let all: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn cidr_rejects_garbage() {
        for bad in ["", "10.0.0.0/33", "fd00::/129", "example.com", "10.0.0.0/x"] {
            assert!(bad.parse::<Cidr>().is_err(), "{bad}");
        }
    }

    #[test]
    fn empty_allowlist_allows_everyone() {
        assert!(client_allowed(&[], "1.2.3.4".parse().unwrap()));
        let list = ["10.0.0.0/8".parse().unwrap()];
        assert!(!client_allowed(&list, "1.2.3.4".parse().unwrap()));
    }

    // --- credentials / auth ---

    fn basic(userpass: &str) -> Vec<u8> {
        format!("Basic {}", b64_std(userpass.as_bytes())).into_bytes()
    }

    /// Test-side base64, independent of the decoder under test.
    fn b64_std(bytes: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in bytes.chunks(3) {
            let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
            out.push(A[(n >> 18) as usize & 63] as char);
            out.push(A[(n >> 12) as usize & 63] as char);
            out.push(if c.len() > 1 { A[(n >> 6) as usize & 63] as char } else { '=' });
            out.push(if c.len() > 2 { A[n as usize & 63] as char } else { '=' });
        }
        out
    }

    #[test]
    fn credentials_parse_and_reject_bad_lines() {
        let c = ProxyCredentials::parse("# team\nagent.T-3:s3cret\n\nyou:pw:with:colons\n").unwrap();
        assert_eq!(c.len(), 2);
        assert!(c.verify("you", "pw:with:colons"), "password may contain ':'");
        for bad in ["nocolon", ":pw", "user:", "", "# only a comment"] {
            assert!(ProxyCredentials::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn credentials_debug_never_shows_passwords() {
        let c = ProxyCredentials::parse("u:topsecret").unwrap();
        assert!(!format!("{c:?}").contains("topsecret"));
    }

    #[test]
    fn credentials_load_prefers_file_then_env() {
        let dir = tempfile::TempDir::new().unwrap();
        let f = dir.path().join("auth");
        std::fs::write(&f, "a:1\n").unwrap();
        assert_eq!(ProxyCredentials::load(Some(&f), Some("b:2".into())).unwrap().unwrap().len(), 1);
        assert!(ProxyCredentials::load(None, Some("b:2".into())).unwrap().unwrap().verify("b", "2"));
        assert!(ProxyCredentials::load(None, None).unwrap().is_none());
        assert!(ProxyCredentials::load(None, Some("  ".into())).unwrap().is_none());
        assert!(ProxyCredentials::load(Some(&dir.path().join("missing")), None).is_err());
    }

    #[test]
    fn parse_basic_extracts_user_and_password() {
        assert_eq!(parse_basic(&basic("agent.T-3:pw")), Some(("agent.T-3".into(), "pw".into())));
        assert_eq!(parse_basic(&basic("agent:T-3")), Some(("agent".into(), "T-3".into())), "split on first ':'");
        assert_eq!(parse_basic(&basic("solo")), Some(("solo".into(), "".into())));
        assert_eq!(parse_basic(b"basic YTpi"), Some(("a".into(), "b".into())), "scheme is case-insensitive");
        assert_eq!(parse_basic(b"Bearer abc"), None);
        assert_eq!(parse_basic(b"Basic !!!"), None);
    }

    #[test]
    fn without_credentials_the_username_is_a_label_and_nothing_is_rejected() {
        assert_eq!(authorize(None, None), Ok(None));
        assert_eq!(authorize(Some(&basic("agent.T-3:anything")), None), Ok(Some("agent.T-3".into())));
        assert_eq!(authorize(Some(&basic(":x")), None), Ok(None), "empty username is no source");
        assert_eq!(authorize(Some(b"garbage"), None), Ok(None));
    }

    #[test]
    fn with_credentials_only_a_match_passes_and_source_is_the_user() {
        let c = ProxyCredentials::parse("agent.T-3:s3cret").unwrap();
        assert_eq!(authorize(Some(&basic("agent.T-3:s3cret")), Some(&c)), Ok(Some("agent.T-3".into())));
        assert_eq!(authorize(Some(&basic("agent.T-3:wrong")), Some(&c)), Err(AuthRequired));
        assert_eq!(authorize(Some(&basic("other:s3cret")), Some(&c)), Err(AuthRequired));
        assert_eq!(authorize(None, Some(&c)), Err(AuthRequired));
        assert_eq!(authorize(Some(b"Bearer x"), Some(&c)), Err(AuthRequired));
    }

    // --- expiry ---

    #[test]
    fn expires_accepts_durations_and_rfc3339() {
        let now: DateTime<Utc> = "2026-11-20T00:00:00Z".parse().unwrap();
        assert_eq!(parse_expires("90s", now).unwrap(), now + Duration::seconds(90));
        assert_eq!(parse_expires("30m", now).unwrap(), now + Duration::minutes(30));
        assert_eq!(parse_expires("8h", now).unwrap(), now + Duration::hours(8));
        assert_eq!(parse_expires("2d", now).unwrap(), now + Duration::days(2));
        assert_eq!(
            parse_expires("2026-11-21T09:00:00+01:00", now).unwrap(),
            "2026-11-21T08:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    #[test]
    fn expires_rejects_past_zero_and_garbage() {
        let now: DateTime<Utc> = "2026-11-20T00:00:00Z".parse().unwrap();
        for bad in ["0s", "2026-01-01T00:00:00Z", "8", "8w", "h", "", "-5m"] {
            assert!(parse_expires(bad, now).is_err(), "{bad:?}");
        }
    }

    // --- banner ---

    #[test]
    fn banner_states_mode_addresses_access_and_expiry() {
        let b = BannerInfo {
            exposure: Exposure {
                proxy: addr("0.0.0.0:8443"),
                proxy_tls: true,
                proxy_auth: true,
                api: addr("10.0.0.5:8081"),
                api_tls: true,
                ..Default::default()
            },
            allow_clients: vec!["10.0.0.0/8".parse().unwrap()],
            proxy_users: 2,
            expires: Some("2026-11-21T08:00:00Z".parse().unwrap()),
            ca_fingerprint: "AB:CD".into(),
        };
        let text = banner(&b);
        for want in ["mode: remote", "0.0.0.0:8443 TLS", "clients 10.0.0.0/8", "proxy auth (2 users)", "10.0.0.5:8081 TLS", "expires: 2026-11-21T08:00:00+00:00", "AB:CD"] {
            assert!(text.contains(want), "missing {want:?} in\n{text}");
        }
        let local = banner(&BannerInfo { exposure: Exposure { proxy: addr("127.0.0.1:8080"), ..Default::default() }, ..Default::default() });
        assert!(local.contains("mode: local") && local.contains("access: none") && local.contains("expires: never"), "{local}");
    }
}
