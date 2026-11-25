//! Proxy credentials issued through the lever API (#25): each one carries a
//! host allowlist, a rate limit and a request budget that taphttp enforces
//! on every request made with it, and `meta` recorded on every exchange.
//! What is allowed is the issuer's decision (spall's); taphttp enforces and
//! counts. Credentials live in memory: a restart revokes them all.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use taphttp_types::Timestamp;
use tokio::sync::watch;

use crate::deploy::{constant_time_eq, Cidr};

/// What `POST /clients` takes.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSpec {
    /// Hosts this credential may reach: `example.com`, `*.example.com`
    /// (subdomains only), an IP, a CIDR, or `*` for any host.
    pub allow: Vec<String>,
    #[serde(default)]
    pub rate: Option<Rate>,
    /// Requests it may send in total; past that, refused.
    #[serde(default)]
    pub budget: Option<u64>,
    /// Recorded on every exchange made with this credential.
    #[serde(default)]
    pub meta: BTreeMap<String, String>,
}

/// A token bucket: `per_second` sustained, bursts of up to `burst`
/// (default: `per_second` rounded up, at least 1).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rate {
    pub per_second: f64,
    #[serde(default)]
    pub burst: Option<u32>,
}

impl Rate {
    fn burst(&self) -> f64 {
        f64::from(
            self.burst
                .unwrap_or_else(|| self.per_second.ceil().clamp(1.0, f64::from(u32::MAX)) as u32),
        )
    }
}

/// One allowlist entry.
#[derive(Debug, Clone, PartialEq)]
enum HostRule {
    Any,
    Exact(String),
    /// `*.example.com` as `.example.com`: strict subdomains.
    Suffix(String),
    Net(Cidr),
}

impl std::str::FromStr for HostRule {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let rule = s.trim();
        if rule == "*" {
            return Ok(Self::Any);
        }
        let unbracketed = rule.trim_start_matches('[').trim_end_matches(']');
        if unbracketed.parse::<IpAddr>().is_ok() || rule.contains('/') {
            let net = unbracketed
                .parse::<Cidr>()
                .map_err(|_| anyhow::anyhow!("allow {s:?}: not a valid IP address or CIDR"))?;
            return Ok(Self::Net(net));
        }
        let (wild, name) = match rule.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, rule),
        };
        let name = normalize(name);
        let valid = !name.is_empty()
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            });
        if !valid {
            bail!("allow {s:?}: not a host name, *.wildcard, IP or CIDR");
        }
        Ok(if wild {
            Self::Suffix(format!(".{name}"))
        } else {
            Self::Exact(name)
        })
    }
}

/// Lowercase, without a trailing dot.
fn normalize(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// A credential's host allowlist.
#[derive(Debug, Clone, PartialEq)]
pub struct Allowlist(Vec<HostRule>);

impl Allowlist {
    pub fn parse(rules: &[String]) -> Result<Self> {
        if rules.is_empty() {
            bail!("allow must list at least one host (\"*\" allows any)");
        }
        Ok(Self(
            rules.iter().map(|r| r.parse()).collect::<Result<_>>()?,
        ))
    }

    /// Whether `host` (a name or an IP literal, as the request gave it) is
    /// allowed by name. An IP literal is checked against the IP rules.
    pub fn allows_name(&self, host: &str) -> bool {
        let unbracketed = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = unbracketed.parse::<IpAddr>() {
            return self.allows_ip(ip);
        }
        let host = normalize(host);
        self.0.iter().any(|r| match r {
            HostRule::Any => true,
            HostRule::Exact(name) => *name == host,
            HostRule::Suffix(suffix) => host.ends_with(suffix.as_str()),
            HostRule::Net(_) => false,
        })
    }

    pub fn allows_ip(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|r| match r {
            HostRule::Any => true,
            HostRule::Net(net) => net.contains(ip),
            _ => false,
        })
    }

    fn has_ip_rules(&self) -> bool {
        self.0.iter().any(|r| matches!(r, HostRule::Net(_)))
    }
}

/// Why taphttp refused a request made with an issued credential. Nothing
/// was sent.
#[derive(Debug, Clone, PartialEq)]
pub enum Refusal {
    HostNotAllowed(String),
    /// The target is one of taphttp's own listeners.
    OwnListener(SocketAddr),
    Rate {
        retry_after: Duration,
    },
    Budget,
    Revoked,
}

impl Refusal {
    /// What the proxy answers.
    pub fn status(&self) -> u16 {
        match self {
            Self::Rate { .. } => 429,
            _ => 403,
        }
    }

    /// Recorded as the exchange's `error`.
    pub fn reason(&self) -> String {
        match self {
            Self::HostNotAllowed(h) => {
                format!("refused: {h} is not in this credential's allowlist")
            }
            Self::OwnListener(a) => {
                format!("refused: resolves to {a}, one of taphttp's own listeners")
            }
            Self::Rate { .. } => "refused: rate limit".into(),
            Self::Budget => "refused: request budget used up".into(),
            Self::Revoked => "refused: credential revoked".into(),
        }
    }
}

/// Where a request may connect, or why it may not.
#[derive(Debug)]
pub enum Target {
    /// Connect only to these (checked) addresses.
    Allowed(Vec<SocketAddr>),
    Refused(Refusal),
    /// Allowed by name, but the name didn't resolve: a failed attempt, not
    /// a refusal.
    Unresolvable(String),
}

/// Check `host:port` for `allow`. A name allowed by name may use every
/// address it resolves to; otherwise only the addresses an IP rule allows
/// are used. Resolved once: the caller connects only to what is returned,
/// so a name can't resolve elsewhere afterwards. Any of taphttp's own
/// listeners (`own`) is refused.
pub async fn check_target(allow: &Allowlist, host: &str, port: u16, own: &[SocketAddr]) -> Target {
    let by_name = allow.allows_name(host);
    if !by_name && !allow.has_ip_rules() {
        return Target::Refused(Refusal::HostNotAllowed(host.to_string()));
    }
    let addrs = match crate::upstream::resolve_host(host, port).await {
        Ok(a) => a,
        Err(e) if by_name => return Target::Unresolvable(format!("resolving host: {e}")),
        Err(_) => return Target::Refused(Refusal::HostNotAllowed(host.to_string())),
    };
    let addrs: Vec<SocketAddr> = if by_name {
        addrs
    } else {
        addrs
            .into_iter()
            .filter(|a| allow.allows_ip(a.ip()))
            .collect()
    };
    if addrs.is_empty() {
        return Target::Refused(Refusal::HostNotAllowed(host.to_string()));
    }
    if let Some(a) = addrs
        .iter()
        .find(|a| crate::upstream::is_own_target(**a, own, crate::upstream::is_local_ip))
    {
        return Target::Refused(Refusal::OwnListener(*a));
    }
    Target::Allowed(addrs)
}

struct Bucket {
    rate: Rate,
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn new(rate: Rate, now: Instant) -> Self {
        Self {
            rate,
            tokens: rate.burst(),
            last: now,
        }
    }

    /// Take a token, or say how long until one is available.
    fn take(&mut self, now: Instant) -> Result<(), Duration> {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate.per_second).min(self.rate.burst());
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64(
                (1.0 - self.tokens) / self.rate.per_second,
            ))
        }
    }
}

struct Client {
    id: String,
    password: String,
    spec: ClientSpec,
    allow: Arc<Allowlist>,
    bucket: Option<Bucket>,
    sent: u64,
    refused: u64,
    created_at: Timestamp,
    revoked: bool,
    kill: watch::Sender<bool>,
}

impl Client {
    fn view(&self) -> ClientView {
        ClientView {
            id: self.id.clone(),
            meta: self.spec.meta.clone(),
            allow: self.spec.allow.clone(),
            rate: self.spec.rate,
            budget: self.spec.budget,
            sent: self.sent,
            refused: self.refused,
            remaining: self.spec.budget.map(|b| b.saturating_sub(self.sent)),
            created_at: self.created_at,
            revoked: self.revoked,
        }
    }
}

/// A credential as `GET /clients` lists it: never the password.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClientView {
    pub id: String,
    pub meta: BTreeMap<String, String>,
    pub allow: Vec<String>,
    pub rate: Option<Rate>,
    pub budget: Option<u64>,
    /// Requests sent upstream with it.
    pub sent: u64,
    /// Requests refused.
    pub refused: u64,
    /// Budget left, or `null` without a budget.
    pub remaining: Option<u64>,
    pub created_at: Timestamp,
    pub revoked: bool,
}

/// What `POST /clients` answers, once: the only time the password is shown.
#[derive(Debug, Clone, Serialize)]
pub struct Issued {
    /// The `Proxy-Authorization` Basic username (the credential's id).
    pub username: String,
    pub password: String,
    #[serde(flatten)]
    pub client: ClientView,
}

/// A request authenticated as an issued credential.
#[derive(Debug, Clone)]
pub struct Grant {
    pub id: String,
    pub meta: BTreeMap<String, String>,
    pub allow: Arc<Allowlist>,
    /// Becomes `true` when the credential is revoked: whatever holds this
    /// (a tunnel, a WebSocket relay, a client connection) closes.
    pub revoked: watch::Receiver<bool>,
}

/// The result of checking `Proxy-Authorization` against the registry.
#[derive(Debug)]
pub enum Lookup {
    /// Not an issued credential's username.
    Unknown,
    /// An issued credential's username with the wrong password, or revoked.
    Denied,
    Granted(Grant),
}

/// Every issued credential.
#[derive(Default)]
pub struct Registry {
    clients: Mutex<Vec<Client>>,
}

impl Registry {
    pub fn issue(&self, spec: ClientSpec) -> Result<Issued> {
        crate::replay::validate_meta(&spec.meta)?;
        let allow = Allowlist::parse(&spec.allow)?;
        if let Some(rate) = spec.rate {
            if !(rate.per_second.is_finite() && rate.per_second > 0.0) {
                bail!("rate.per_second must be a positive number");
            }
            if rate.burst == Some(0) {
                bail!("rate.burst must be at least 1");
            }
        }
        let id = format!("c-{}", uuid::Uuid::new_v4().simple());
        let password = crate::api::generate_token();
        let (kill, _) = watch::channel(false);
        let client = Client {
            id: id.clone(),
            password: password.clone(),
            bucket: spec.rate.map(|r| Bucket::new(r, Instant::now())),
            allow: Arc::new(allow),
            spec,
            sent: 0,
            refused: 0,
            created_at: Timestamp::now(),
            revoked: false,
            kill,
        };
        let view = client.view();
        self.clients.lock().unwrap().push(client);
        Ok(Issued {
            username: id,
            password,
            client: view,
        })
    }

    pub fn authenticate(&self, user: &str, pass: &str) -> Lookup {
        let clients = self.clients.lock().unwrap();
        let Some(c) = clients.iter().find(|c| c.id == user) else {
            return Lookup::Unknown;
        };
        if c.revoked || !constant_time_eq(c.password.as_bytes(), pass.as_bytes()) {
            return Lookup::Denied;
        }
        Lookup::Granted(Grant {
            id: c.id.clone(),
            meta: c.spec.meta.clone(),
            allow: c.allow.clone(),
            revoked: c.kill.subscribe(),
        })
    }

    /// Count one request against `id`'s budget and rate, or refuse it (and
    /// count the refusal).
    pub fn admit(&self, id: &str, now: Instant) -> Result<(), Refusal> {
        let mut clients = self.clients.lock().unwrap();
        let Some(c) = clients.iter_mut().find(|c| c.id == id) else {
            return Err(Refusal::Revoked);
        };
        let verdict = if c.revoked {
            Err(Refusal::Revoked)
        } else if c.spec.budget.is_some_and(|b| c.sent >= b) {
            Err(Refusal::Budget)
        } else if let Some(Err(wait)) = c.bucket.as_mut().map(|b| b.take(now)) {
            Err(Refusal::Rate { retry_after: wait })
        } else {
            Ok(())
        };
        match verdict {
            Ok(()) => c.sent += 1,
            Err(_) => c.refused += 1,
        }
        verdict
    }

    /// Count a refusal decided elsewhere (the host check).
    pub fn note_refused(&self, id: &str) {
        if let Some(c) = self.clients.lock().unwrap().iter_mut().find(|c| c.id == id) {
            c.refused += 1;
        }
    }

    /// Revoke `id`; `false` if there is no such credential.
    pub fn revoke(&self, id: &str) -> bool {
        let mut clients = self.clients.lock().unwrap();
        let Some(c) = clients.iter_mut().find(|c| c.id == id) else {
            return false;
        };
        c.revoked = true;
        c.kill.send_replace(true);
        true
    }

    /// Revoke every credential at once; returns how many were live.
    pub fn revoke_all(&self) -> usize {
        let mut clients = self.clients.lock().unwrap();
        let mut n = 0;
        for c in clients.iter_mut().filter(|c| !c.revoked) {
            c.revoked = true;
            c.kill.send_replace(true);
            n += 1;
        }
        n
    }

    pub fn list(&self) -> Vec<ClientView> {
        self.clients
            .lock()
            .unwrap()
            .iter()
            .map(Client::view)
            .collect()
    }
}

/// Resolves when `revoked` becomes `true`; never, if it can't.
pub async fn revoked(mut revoked: watch::Receiver<bool>) {
    if revoked.wait_for(|r| *r).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Parse a `Basic` `Proxy-Authorization` and look it up.
pub fn lookup(registry: &Registry, header: Option<&[u8]>) -> Lookup {
    match header.and_then(crate::deploy::parse_basic) {
        Some((user, pass)) => registry.authenticate(&user, &pass),
        None => Lookup::Unknown,
    }
}

/// `ClientSpec` from JSON, with a message naming the problem.
pub fn parse_spec(json: &[u8]) -> Result<ClientSpec> {
    serde_json::from_slice(json).context("invalid client spec")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(rules: &[&str]) -> Allowlist {
        Allowlist::parse(&rules.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    fn spec(rules: &[&str]) -> ClientSpec {
        ClientSpec {
            allow: rules.iter().map(|s| s.to_string()).collect(),
            rate: None,
            budget: None,
            meta: BTreeMap::new(),
        }
    }

    #[test]
    fn allowlist_matches_names_wildcards_ips_and_cidrs() {
        let a = allow(&[
            "example.com",
            "*.test.example",
            "203.0.113.7",
            "10.0.0.0/8",
            "[::1]",
        ]);
        for yes in [
            "example.com",
            "EXAMPLE.com.",
            "api.test.example",
            "a.b.test.example",
            "203.0.113.7",
            "10.9.8.7",
            "[::1]",
        ] {
            assert!(a.allows_name(yes), "{yes}");
        }
        for no in [
            "www.example.com",
            "test.example",
            "eviltest.example",
            "example.com.evil",
            "203.0.113.8",
            "11.0.0.1",
            "[::2]",
        ] {
            assert!(!a.allows_name(no), "{no}");
        }
        assert!(a.allows_ip("10.1.1.1".parse().unwrap()));
        assert!(!a.allows_ip("192.0.2.1".parse().unwrap()));
        let any = allow(&["*"]);
        assert!(any.allows_name("anything.example") && any.allows_ip("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn allowlist_rejects_nonsense_and_empty() {
        assert!(Allowlist::parse(&[]).is_err());
        for bad in ["", "exa mple.com", "*.", "10.0.0.0/99", "a..b", "http://x/"] {
            assert!(
                Allowlist::parse(&[bad.to_string()]).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[tokio::test]
    async fn target_check_refuses_unlisted_hosts_and_own_listeners() {
        let own: Vec<SocketAddr> = vec!["127.0.0.1:8080".parse().unwrap()];
        let a = allow(&["localhost", "127.0.0.0/8"]);
        match check_target(&a, "127.0.0.1", 9, &own).await {
            Target::Allowed(addrs) => assert_eq!(addrs, ["127.0.0.1:9".parse().unwrap()]),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            check_target(&a, "127.0.0.1", 8080, &own).await,
            Target::Refused(Refusal::OwnListener(_))
        ));
        let names_only = allow(&["example.com"]);
        assert!(matches!(
            check_target(&names_only, "127.0.0.1", 9, &own).await,
            Target::Refused(Refusal::HostNotAllowed(_))
        ));
        assert!(matches!(
            check_target(&names_only, "elsewhere.invalid", 80, &own).await,
            Target::Refused(Refusal::HostNotAllowed(_))
        ));
        // Allowed by name but it doesn't resolve: a failure, not a refusal.
        let invalid = allow(&["*.invalid"]);
        assert!(matches!(
            check_target(&invalid, "no-such.invalid", 80, &own).await,
            Target::Unresolvable(_)
        ));
    }

    #[tokio::test]
    async fn a_name_outside_the_allowlist_may_use_only_addresses_an_ip_rule_allows() {
        // `localhost` isn't listed by name, but 127.0.0.0/8 is: only its
        // IPv4 loopback addresses may be used, never ::1.
        let a = allow(&["127.0.0.0/8"]);
        match check_target(&a, "localhost", 9, &[]).await {
            Target::Allowed(addrs) => {
                assert!(!addrs.is_empty());
                assert!(addrs.iter().all(|a| a.ip().is_ipv4()), "{addrs:?}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn bucket_allows_a_burst_then_refills_at_the_rate() {
        let t0 = Instant::now();
        let mut b = Bucket::new(
            Rate {
                per_second: 2.0,
                burst: Some(3),
            },
            t0,
        );
        for _ in 0..3 {
            assert!(b.take(t0).is_ok());
        }
        let wait = b.take(t0).unwrap_err();
        assert!((wait.as_secs_f64() - 0.5).abs() < 1e-9, "{wait:?}");
        assert!(b.take(t0 + Duration::from_millis(500)).is_ok());
        assert!(b.take(t0 + Duration::from_millis(500)).is_err());
        // Never more than the burst, however long it waits.
        let later = t0 + Duration::from_secs(60);
        for _ in 0..3 {
            assert!(b.take(later).is_ok());
        }
        assert!(b.take(later).is_err());
    }

    #[test]
    fn default_burst_is_the_rate_rounded_up() {
        let r = |per_second| Rate {
            per_second,
            burst: None,
        };
        assert_eq!(r(0.2).burst(), 1.0);
        assert_eq!(r(2.5).burst(), 3.0);
    }

    #[test]
    fn issued_credentials_authenticate_and_carry_their_meta() {
        let reg = Registry::default();
        let mut s = spec(&["example.com"]);
        s.meta.insert("task".into(), "T-7".into());
        let issued = reg.issue(s).unwrap();
        assert!(issued.username.starts_with("c-"));
        assert_eq!(issued.username, issued.client.id);
        let Lookup::Granted(g) = reg.authenticate(&issued.username, &issued.password) else {
            panic!("expected a grant");
        };
        assert_eq!(g.meta["task"], "T-7");
        assert!(g.allow.allows_name("example.com"));
        assert!(matches!(
            reg.authenticate(&issued.username, "wrong"),
            Lookup::Denied
        ));
        assert!(matches!(reg.authenticate("someone", "x"), Lookup::Unknown));
    }

    #[test]
    fn bad_specs_are_rejected() {
        let reg = Registry::default();
        assert!(reg.issue(spec(&[])).is_err(), "empty allow");
        let mut s = spec(&["*"]);
        s.rate = Some(Rate {
            per_second: 0.0,
            burst: None,
        });
        assert!(reg.issue(s).is_err());
        let mut s = spec(&["*"]);
        s.rate = Some(Rate {
            per_second: 1.0,
            burst: Some(0),
        });
        assert!(reg.issue(s).is_err());
        let mut s = spec(&["*"]);
        s.meta.insert(String::new(), "v".into());
        assert!(reg.issue(s).is_err());
        assert!(parse_spec(br#"{"allow":["*"],"surprise":1}"#).is_err());
        assert!(reg.list().is_empty());
    }

    #[test]
    fn budget_and_rate_are_counted_and_enforced() {
        let reg = Registry::default();
        let mut s = spec(&["*"]);
        s.budget = Some(3);
        s.rate = Some(Rate {
            per_second: 1.0,
            burst: Some(2),
        });
        let id = reg.issue(s).unwrap().username;
        let t0 = Instant::now();
        assert_eq!(reg.admit(&id, t0), Ok(()));
        assert_eq!(reg.admit(&id, t0), Ok(()));
        assert!(matches!(reg.admit(&id, t0), Err(Refusal::Rate { .. })));
        let t1 = t0 + Duration::from_secs(5);
        assert_eq!(reg.admit(&id, t1), Ok(()));
        assert_eq!(reg.admit(&id, t1), Err(Refusal::Budget));
        reg.note_refused(&id);
        let view = &reg.list()[0];
        assert_eq!((view.sent, view.refused, view.remaining), (3, 3, Some(0)));
    }

    #[tokio::test]
    async fn revoking_denies_new_requests_and_signals_holders() {
        let reg = Registry::default();
        let a = reg.issue(spec(&["*"])).unwrap();
        let b = reg.issue(spec(&["*"])).unwrap();
        let Lookup::Granted(ga) = reg.authenticate(&a.username, &a.password) else {
            panic!()
        };
        let Lookup::Granted(gb) = reg.authenticate(&b.username, &b.password) else {
            panic!()
        };
        assert!(reg.revoke(&a.username));
        assert!(!reg.revoke("c-nope"));
        tokio::time::timeout(Duration::from_secs(1), revoked(ga.revoked.clone()))
            .await
            .expect("a's holders are told");
        assert!(!*gb.revoked.borrow(), "b is untouched");
        assert!(matches!(
            reg.authenticate(&a.username, &a.password),
            Lookup::Denied
        ));
        assert_eq!(
            reg.admit(&a.username, Instant::now()),
            Err(Refusal::Revoked)
        );

        assert_eq!(reg.revoke_all(), 1, "only b was still live");
        tokio::time::timeout(Duration::from_secs(1), revoked(gb.revoked.clone()))
            .await
            .expect("b's holders are told");
        let views = reg.list();
        assert!(views.iter().all(|v| v.revoked));
    }

    #[test]
    fn listing_never_shows_a_password() {
        let reg = Registry::default();
        let issued = reg.issue(spec(&["*"])).unwrap();
        let json = serde_json::to_string(&reg.list()).unwrap();
        assert!(!json.contains(&issued.password), "{json}");
        assert!(!json.contains("password"), "{json}");
        let shown = serde_json::to_value(&issued).unwrap();
        assert_eq!(shown["password"], issued.password.as_str());
        assert_eq!(shown["id"], issued.username.as_str());
    }
}
