use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use taphttp_types::Timestamp;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

use crate::ca::Ca;
use crate::cli::StartArgs;
use crate::clients::{Grant, Lookup, Refusal, Registry, Target};
use crate::deploy::{self, Cidr, Exposure, ProxyCredentials};
use crate::intercept::{self, Decision, InterceptEvent, RequestEvent, ResponseEvent};
use crate::storage::{Headers, Store, TrafficEntry};
use taphttp_types::{encode_body, header_value_to_string};

/// How the proxy listener behaves. `Default` is today's local proxy: no
/// filter, no intercept, no access control, no expiry, plaintext.
#[derive(Default)]
pub struct ProxyConfig {
    pub filter_host: Option<String>,
    pub intercept_socket: Option<PathBuf>,
    /// Source-IP allowlist; empty allows everyone.
    pub allow_clients: Vec<Cidr>,
    /// When set, every client must present one of these (Basic), and the
    /// username becomes each exchange's verified `source`.
    pub credentials: Option<ProxyCredentials>,
    /// After this, requests are refused (and `run` exits).
    pub expires: Option<Timestamp>,
    /// TLS on the proxy listener itself (an HTTPS proxy), so proxy
    /// credentials aren't cleartext on the network.
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// Credentials issued through the lever API (`POST /clients`), whose
    /// allowlist, rate and budget are enforced here.
    pub clients: Option<Arc<Registry>>,
    /// `--proxy-auth-api`: every client must present an issued credential
    /// (or one from `--proxy-auth-file`).
    pub require_client: bool,
    /// taphttp's own listeners, which an issued credential may never reach.
    /// [`serve`] adds the proxy's own.
    pub own: Vec<SocketAddr>,
}

/// What the proxy answers its clients with: buffered, or streamed through.
pub type ProxyBody = UnsyncBoxBody<Bytes, hyper::Error>;

/// A buffered body.
fn full(bytes: impl Into<Bytes>) -> ProxyBody {
    full_body(Full::new(bytes.into()))
}

fn full_body(body: Full<Bytes>) -> ProxyBody {
    body.map_err(|never| match never {}).boxed_unsync()
}

impl ProxyConfig {
    fn expired(&self) -> bool {
        self.expires.is_some_and(|t| Timestamp::now() >= t)
    }
}

/// The sqlite database to record into, if any: with `--sqlite`, or with
/// `--api-listen`, which serves history from it. `--db` only says where, so
/// it can be set as an environment default (as the Docker image does).
fn sqlite_path(args: &StartArgs, data_dir: &std::path::Path) -> Option<PathBuf> {
    let wanted = args.sqlite || args.api_listen.is_some();
    wanted.then(|| {
        args.db
            .clone()
            .unwrap_or_else(|| data_dir.join("traffic.db"))
    })
}

/// SANs for taphttp's own listener certs: every `--tls-name`, plus each
/// listener's IP when it's a specific address (not 0.0.0.0 / ::).
fn tls_names(names: &[String], listeners: &[Option<SocketAddr>]) -> Result<Vec<String>> {
    let mut out: Vec<String> = names.to_vec();
    for addr in listeners.iter().flatten() {
        if !addr.ip().is_unspecified() {
            out.push(addr.ip().to_string());
        }
    }
    out.sort();
    out.dedup();
    if out.is_empty() {
        anyhow::bail!(
            "TLS on a wildcard address needs the name clients will connect to: pass \
             --tls-name <host-or-ip> (repeatable)"
        );
    }
    Ok(out)
}

pub async fn run(args: StartArgs, data_dir: PathBuf) -> Result<()> {
    let started_at = Timestamp::now();
    // Decide what may be exposed before binding anything.
    let addr: SocketAddr = args.listen.parse().context("invalid listen address")?;
    let api_addr: Option<SocketAddr> = args
        .api_listen
        .as_deref()
        .map(|a| a.parse().context("invalid api-listen address"))
        .transpose()?;
    let auth_addr: Option<SocketAddr> = args
        .auth_listen
        .as_deref()
        .map(|a| a.parse().context("invalid auth-listen address"))
        .transpose()?;
    let credentials = ProxyCredentials::load(
        args.proxy_auth_file.as_deref(),
        std::env::var("TAPHTTP_PROXY_AUTH").ok(),
    )?;
    let allow_clients = args
        .allow_client
        .iter()
        .map(|c| c.parse())
        .collect::<Result<Vec<Cidr>>>()?;
    let expires = args
        .expires
        .as_deref()
        .map(|e| deploy::parse_expires(e, Timestamp::now()))
        .transpose()?;
    let exposure = Exposure {
        proxy: Some(addr),
        proxy_tls: args.proxy_tls,
        proxy_auth: credentials.is_some() || args.proxy_auth_api,
        allow_open_proxy: args.allow_open_proxy,
        api: api_addr,
        api_tls: args.api_tls,
        api_allow_plaintext: args.api_allow_plaintext,
        auth_proxy: auth_addr,
        auth_proxy_allow_plaintext: args.auth_listen_allow_plaintext,
        file_users: credentials.is_some(),
    };
    if args.proxy_auth_api && api_addr.is_none() {
        anyhow::bail!(
            "--proxy-auth-api needs --api-listen: credentials are issued through the lever API"
        );
    }
    deploy::check_exposure(&exposure)?;
    let names = if args.proxy_tls || args.api_tls {
        tls_names(
            &args.tls_name,
            &[
                args.proxy_tls.then_some(addr),
                auth_addr.filter(|_| args.proxy_tls),
                api_addr.filter(|_| args.api_tls),
            ],
        )?
    } else {
        Vec::new()
    };

    let ca = Arc::new(Ca::load_or_create(&data_dir)?);
    let listener_tls = if names.is_empty() {
        None
    } else {
        Some(ca.listener_tls_config(&names)?)
    };

    let info = deploy::BannerInfo {
        exposure,
        allow_clients: allow_clients.clone(),
        proxy_users: credentials.as_ref().map_or(0, |c| c.len()),
        expires,
        ca_fingerprint: ca.fingerprint_sha256(),
    };
    let banner = deploy::banner(&info);
    eprintln!("{banner}");
    if !names.is_empty() {
        eprintln!("  TLS names: {}", names.join(", "));
    }
    tracing::info!("{}", banner.replace('\n', " |"));

    if let Some(at) = expires {
        tokio::spawn(async move {
            let wait = Timestamp::now().until(at);
            tokio::time::sleep(wait).await;
            eprintln!(
                "taphttp: deployment expired at {}; exiting",
                at.to_rfc3339_offset()
            );
            tracing::warn!("deployment expired at {}; exiting", at.to_rfc3339_offset());
            std::process::exit(0);
        });
    }

    let clients = api_addr.map(|_| Arc::new(crate::clients::Registry::default()));
    // Every listener taphttp binds: what an issued credential, /send and
    // /replay may never reach.
    let mut own = Vec::new();
    let db = sqlite_path(&args, &data_dir);
    if let Some(db) = &db {
        eprintln!("recording to sqlite at {}", db.display());
    }
    let store = Store::new(args.log_file.as_deref(), db.as_deref())?;
    let listener = TcpListener::bind(addr).await.context("binding listener")?;
    own.push(listener.local_addr()?);
    let auth_listener = match auth_addr {
        Some(a) => Some(
            TcpListener::bind(a)
                .await
                .context("binding --auth-listen")?,
        ),
        None => None,
    };
    if let Some(l) = &auth_listener {
        own.push(l.local_addr()?);
    }
    let api_listener = match api_addr {
        Some(a) => Some(TcpListener::bind(a).await.context("binding lever API")?),
        None => None,
    };
    if let Some(l) = &api_listener {
        own.push(l.local_addr()?);
    }

    // Optionally serve the lever API alongside the proxy, sharing the same
    // live Store so its /feed carries real traffic as it is recorded.
    if let Some(api_listener) = api_listener {
        // /info reports where things actually listen (a port of 0 in
        // --listen becomes the real one).
        let mut described = info;
        described.exposure.proxy = Some(listener.local_addr()?);
        described.exposure.api = Some(api_listener.local_addr()?);
        if let Some(l) = &auth_listener {
            described.exposure.auth_proxy = Some(l.local_addr()?);
        }
        let history = deploy::HistoryInfo {
            sqlite: db.is_some(),
            log_file: args.log_file.is_some(),
        };
        let deployment = deploy::deployment_info(
            &described,
            ca.public_info()?,
            history,
            started_at,
            !args.api_no_send,
        )
        .context("describing the deployment for /info")?;
        let token = match &args.api_token_file {
            // From a file: print only where it is, so it stays out of logs.
            Some(path) => {
                let token = crate::api::load_or_create_token_file(path)?;
                eprintln!("lever API token: in {}", path.display());
                token
            }
            None => {
                let token = crate::api::generate_token();
                let token_path = crate::api::write_token_file(&data_dir, &token)?;
                eprintln!("lever API token: {token}");
                eprintln!("  (also written to {}, mode 0600)", token_path.display());
                token
            }
        };
        let state = Arc::new(crate::api::ApiState {
            store: store.clone(),
            token,
            info: deployment,
            ca_cert: ca.public_cert(),
            own: own.clone(),
            send_enabled: !args.api_no_send,
            clients: clients.clone().expect("the API is on"),
        });
        let api_tls = if args.api_tls {
            listener_tls.clone()
        } else {
            None
        };
        tokio::spawn(async move {
            if let Err(e) = crate::api::serve(state, api_listener, api_tls).await {
                tracing::error!("lever API exited: {e}");
            }
        });
    }

    let tls = if args.proxy_tls { listener_tls } else { None };
    if let Some(auth_listener) = auth_listener {
        // The locked door: same CA, recording and hooks, but every client
        // needs a credential, and --allow-client is --listen's alone.
        let config = ProxyConfig {
            filter_host: args.filter_host.clone(),
            intercept_socket: args.intercept_socket.clone(),
            allow_clients: Vec::new(),
            credentials: credentials.clone(),
            expires,
            tls: tls.clone(),
            clients: clients.clone(),
            require_client: true,
            own: own.clone(),
        };
        let (ca, store) = (ca.clone(), store.clone());
        tokio::spawn(async move {
            if let Err(e) = serve(auth_listener, ca, store, config).await {
                tracing::error!("--auth-listen exited: {e}");
            }
        });
    }
    let config = ProxyConfig {
        filter_host: args.filter_host,
        intercept_socket: args.intercept_socket,
        allow_clients,
        credentials,
        expires,
        tls,
        clients,
        require_client: args.proxy_auth_api,
        own,
    };
    serve(listener, ca, store, config).await
}

pub async fn serve(
    listener: TcpListener,
    ca: Arc<Ca>,
    store: Arc<Store>,
    mut config: ProxyConfig,
) -> Result<()> {
    let addr = listener.local_addr()?;
    config.own.push(addr);
    let scheme = if config.tls.is_some() {
        "https"
    } else {
        "http"
    };
    let acceptor = config.tls.clone().map(TlsAcceptor::from);
    let config = Arc::new(config);
    tracing::info!("taphttp listening on {}", addr);
    eprintln!("taphttp listening on {addr}");
    eprintln!("Configure your HTTP client to use proxy {scheme}://{addr}");

    loop {
        let (stream, peer) = listener.accept().await?;
        if !deploy::client_allowed(&config.allow_clients, peer.ip()) {
            // Close without a byte: a stranger learns nothing.
            tracing::warn!("refused proxy client {peer}: not in --allow-client");
            drop(stream);
            continue;
        }
        let ca = ca.clone();
        let store = store.clone();
        let config = config.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let result = match acceptor {
                Some(acceptor) => match acceptor.accept(stream).await {
                    Ok(tls) => handle_connection(tls, ca, store, config).await,
                    Err(e) => Err(anyhow::Error::from(e).context("proxy listener TLS handshake")),
                },
                None => handle_connection(stream, ca, store, config).await,
            };
            if let Err(e) = result {
                tracing::debug!("connection error from {peer}: {e:#}");
            }
        });
    }
}

async fn handle_connection<IO>(
    stream: IO,
    ca: Arc<Ca>,
    store: Arc<Store>,
    config: Arc<ProxyConfig>,
) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = hyper_util::rt::TokioIo::new(stream);
    let (closer, closed) = ConnCloser::new();
    let serving = hyper::server::conn::http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req| {
                let ca = ca.clone();
                let store = store.clone();
                let config = config.clone();
                let closer = closer.clone();
                async move { dispatch(req, ca, store, config, closer).await }
            }),
        )
        .with_upgrades();
    tokio::select! {
        r = serving => r.context("serving http1 connection"),
        // An issued credential used on this connection was revoked: drop it.
        _ = crate::clients::revoked(closed) => Ok(()),
    }
}

/// Closes a client connection when a credential used on it is revoked.
#[derive(Clone)]
struct ConnCloser {
    close: Arc<tokio::sync::watch::Sender<bool>>,
    watching: Arc<std::sync::atomic::AtomicBool>,
}

impl ConnCloser {
    fn new() -> (Self, tokio::sync::watch::Receiver<bool>) {
        let (tx, rx) = tokio::sync::watch::channel(false);
        (
            Self {
                close: Arc::new(tx),
                watching: Default::default(),
            },
            rx,
        )
    }

    /// Close this connection when `grant` is revoked. Watches once per
    /// connection, and stops watching when the connection ends.
    fn watch(&self, grant: &Grant) {
        if self
            .watching
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return;
        }
        let close = self.close.clone();
        let revoked = grant.revoked.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = crate::clients::revoked(revoked) => { close.send_replace(true); }
                _ = close.closed() => {}
            }
        });
    }
}

async fn dispatch(
    req: Request<Incoming>,
    ca: Arc<Ca>,
    store: Arc<Store>,
    config: Arc<ProxyConfig>,
    closer: ConnCloser,
) -> Result<Response<ProxyBody>> {
    if config.expired() {
        return make_drop_response(503, Some("taphttp: this deployment has expired".into()));
    }
    // For HTTPS this is the CONNECT, which is where clients send proxy auth;
    // the source then applies to every request in that tunnel.
    let header = req
        .headers()
        .get(hyper::header::PROXY_AUTHORIZATION)
        .map(|v| v.as_bytes());
    let lookup = match &config.clients {
        Some(registry) => crate::clients::lookup(registry, header),
        None => Lookup::Unknown,
    };
    let (source, grant) = match lookup {
        Lookup::Granted(g) => {
            closer.watch(&g);
            (Some(g.id.clone()), Some(Arc::new(g)))
        }
        Lookup::Denied => return proxy_auth_required(),
        Lookup::Unknown if config.require_client && config.credentials.is_none() => {
            return proxy_auth_required()
        }
        Lookup::Unknown => match deploy::authorize(header, config.credentials.as_ref()) {
            Ok(source) => (source, None),
            Err(deploy::AuthRequired) => return proxy_auth_required(),
        },
    };
    // `http://taphttp/`: answered here, never forwarded or recorded. A
    // CONNECT to it (https://taphttp) gets a 405: there is no upstream, and
    // a client without the CA can't trust taphttp's TLS anyway.
    if crate::cert_host::is_cert_host(req.uri()) {
        return Ok(crate::cert_host::respond(
            req.method(),
            req.uri().path(),
            &ca.public_cert(),
            &ca.fingerprint_sha256(),
        )?
        .map(full_body));
    }
    if req.method() == hyper::Method::CONNECT {
        handle_connect(req, source, grant, ca, store, config).await
    } else {
        handle_http(req, source, grant, store, config).await
    }
}

fn proxy_auth_required() -> Result<Response<ProxyBody>> {
    Ok(Response::builder()
        .status(407)
        .header(
            hyper::header::PROXY_AUTHENTICATE,
            r#"Basic realm="taphttp""#,
        )
        .body(full(Bytes::from_static(b"proxy authentication required")))?)
}

async fn handle_connect(
    req: Request<Incoming>,
    source: Option<String>,
    grant: Option<Arc<Grant>>,
    ca: Arc<Ca>,
    store: Arc<Store>,
    config: Arc<ProxyConfig>,
) -> Result<Response<ProxyBody>> {
    let host_port = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_default();

    let host = host_port
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(&host_port)
        .to_string();

    // An issued credential's allowlist is checked here, once, and every
    // request in the tunnel connects only to the addresses checked.
    let mut addrs = None;
    if let Some(g) = &grant {
        let port = req.uri().port_u16().unwrap_or(443);
        let refusal = match crate::clients::check_target(&g.allow, &host, port, &config.own).await {
            Target::Allowed(a) => {
                addrs = Some(Arc::new(a));
                None
            }
            Target::Refused(r) => Some(r),
            // Allowed by name but unresolvable: nothing to tunnel to.
            Target::Unresolvable(e) => {
                tracing::debug!("CONNECT {host_port}: {e}");
                return make_drop_response(502, Some(format!("taphttp: {e}")));
            }
        };
        if let Some(r) = refusal {
            let url = host_port.clone();
            return refuse(&req, host, url, source, g, r, &store, &config);
        }
    }

    tokio::task::spawn(async move {
        let revoked = grant.as_ref().map(|g| g.revoked.clone());
        let tunnel = async {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let target = Tunnel {
                        host,
                        host_port,
                        source,
                        grant,
                        addrs,
                    };
                    if let Err(e) = mitm_tls(upgraded, target, ca, store, config).await {
                        tracing::debug!("mitm error: {e}");
                    }
                }
                Err(e) => tracing::debug!("upgrade error: {e}"),
            }
        };
        match revoked {
            // Revoking the credential closes the tunnel.
            Some(r) => tokio::select! {
                _ = tunnel => {}
                _ = crate::clients::revoked(r) => {}
            },
            None => tunnel.await,
        }
    });

    Ok(Response::new(full(Bytes::new())))
}

/// Where a CONNECT tunnel goes and who opened it.
struct Tunnel {
    host: String,
    host_port: String,
    source: Option<String>,
    grant: Option<Arc<Grant>>,
    /// Checked at CONNECT time for an issued credential.
    addrs: Option<Arc<Vec<SocketAddr>>>,
}

async fn mitm_tls(
    upgraded: hyper::upgrade::Upgraded,
    tunnel: Tunnel,
    ca: Arc<Ca>,
    store: Arc<Store>,
    config: Arc<ProxyConfig>,
) -> Result<()> {
    let Tunnel {
        host,
        host_port,
        source,
        grant,
        addrs,
    } = tunnel;
    let server_cfg = ca
        .server_config_for(&host)
        .await
        .context("getting server config")?;

    let acceptor = TlsAcceptor::from(server_cfg);
    let tls_stream = acceptor
        .accept(hyper_util::rt::TokioIo::new(upgraded))
        .await
        .context("TLS accept")?;

    let io = hyper_util::rt::TokioIo::new(tls_stream);
    let host_clone = host.clone();
    let host_port_clone = host_port.clone();

    hyper::server::conn::http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |mut req: Request<Incoming>| {
                let host = host_clone.clone();
                let host_port = host_port_clone.clone();
                let source = source.clone();
                let grant = grant.clone();
                let addrs = addrs.clone();
                let store = store.clone();
                let config = config.clone();
                async move {
                    // An open tunnel doesn't outlive the deployment.
                    if config.expired() {
                        return make_drop_response(
                            503,
                            Some("taphttp: this deployment has expired".into()),
                        );
                    }
                    let path = req
                        .uri()
                        .path_and_query()
                        .map(|p| p.as_str())
                        .unwrap_or("/");
                    let full_url = format!("https://{host_port}{path}");
                    *req.uri_mut() = full_url.parse()?;
                    forward(req, host, source, grant, addrs, store, config).await
                }
            }),
        )
        // WebSockets inside the tunnel (wss).
        .with_upgrades()
        .await
        .context("serving mitm https")
}

/// A plain-HTTP request from the client: absolute-form, so the URL names
/// the upstream.
async fn handle_http(
    req: Request<Incoming>,
    source: Option<String>,
    grant: Option<Arc<Grant>>,
    store: Arc<Store>,
    config: Arc<ProxyConfig>,
) -> Result<Response<ProxyBody>> {
    let host = req.uri().host().unwrap_or("").to_string();
    forward(req, host, source, grant, None, store, config).await
}

/// Refuse a request made with an issued credential: record it (`refused`,
/// nothing sent), count it, and answer 403 or 429.
#[allow(clippy::too_many_arguments)]
fn refuse(
    req: &Request<Incoming>,
    host: String,
    url: String,
    source: Option<String>,
    grant: &Grant,
    refusal: Refusal,
    store: &Store,
    config: &ProxyConfig,
) -> Result<Response<ProxyBody>> {
    if !matches!(
        refusal,
        Refusal::Rate { .. } | Refusal::Budget | Refusal::Revoked
    ) {
        // `admit` counted those itself.
        if let Some(registry) = &config.clients {
            registry.note_refused(&grant.id);
        }
    }
    let mut req_headers = collect_headers(req.headers());
    req_headers.remove("proxy-authorization");
    let reason = refusal.reason();
    tracing::info!("{} {} {reason}", req.method(), url);
    store.record(TrafficEntry {
        id: Uuid::new_v4().to_string(),
        ts: Timestamp::now(),
        host,
        method: req.method().to_string(),
        url,
        req_headers,
        req_body: None,
        req_body_encoding: Default::default(),
        status: None,
        res_headers: Headers::new(),
        res_body: None,
        res_body_encoding: Default::default(),
        duration_ms: None,
        replay_of: None,
        source,
        meta: grant.meta.clone(),
        error: Some(reason.clone()),
        origin: crate::storage::Origin::Proxy,
        peer: None,
        refused: true,
    });
    let mut res = Response::builder().status(refusal.status());
    if let Refusal::Rate { retry_after } = refusal {
        res = res.header(
            hyper::header::RETRY_AFTER,
            retry_after.as_secs_f64().ceil().max(1.0).to_string(),
        );
    }
    Ok(res.body(full(format!("taphttp: {reason}")))?)
}

/// Forward one proxied request (plain HTTP, or from inside a MITM'd
/// tunnel; `req`'s URI is absolute either way) and record the exchange,
/// unless `--filter-host` leaves this host out.
async fn forward(
    mut req: Request<Incoming>,
    host: String,
    source: Option<String>,
    grant: Option<Arc<Grant>>,
    addrs: Option<Arc<Vec<SocketAddr>>>,
    store: Arc<Store>,
    config: Arc<ProxyConfig>,
) -> Result<Response<ProxyBody>> {
    // An issued credential: the host check (unless a CONNECT already did
    // it), then its budget and rate.
    let mut checked = addrs.map(|a| a.to_vec());
    let mut unresolvable = None;
    if let Some(g) = &grant {
        if checked.is_none() {
            let port = req.uri().port_u16().unwrap_or(80);
            match crate::clients::check_target(&g.allow, &host, port, &config.own).await {
                Target::Allowed(a) => checked = Some(a),
                Target::Unresolvable(e) => unresolvable = Some(e),
                Target::Refused(r) => {
                    let url = req.uri().to_string();
                    return refuse(&req, host, url, source, g, r, &store, &config);
                }
            }
        }
        if let Some(registry) = &config.clients {
            if let Err(r) = registry.admit(&g.id, std::time::Instant::now()) {
                let url = req.uri().to_string();
                return refuse(&req, host, url, source, g, r, &store, &config);
            }
        }
    }
    let meta = grant.as_ref().map(|g| g.meta.clone()).unwrap_or_default();

    let record = config
        .filter_host
        .as_ref()
        .is_none_or(|f| host.contains(f.as_str()));

    let id = Uuid::new_v4().to_string();
    let mut method = req.method().to_string();
    let mut url = req.uri().to_string();
    let mut req_headers = collect_headers(req.headers());
    // Proxy credentials are ours: never logged, never shown to an intercept
    // hook, never sent upstream.
    req_headers.remove("proxy-authorization");
    // A WebSocket handshake: take the client side of the upgrade now, and
    // negotiate no extensions, since the relay can't read compressed frames.
    let mut client_upgrade =
        crate::stream::is_websocket_upgrade(req.headers()).then(|| hyper::upgrade::on(&mut req));
    if client_upgrade.is_some() {
        req_headers.remove("sec-websocket-extensions");
    }

    let (_, body) = req.into_parts();
    let mut req_body_bytes = body.collect().await?.to_bytes();

    // --- intercept request ---
    if let (true, Some(socket)) = (record, &config.intercept_socket) {
        let event = InterceptEvent::Request(RequestEvent {
            id: id.clone(),
            method: method.clone(),
            url: url.clone(),
            headers: intercept_header_map(&req_headers),
            body: maybe_utf8(&req_body_bytes),
        });
        match intercept::pause(socket, &event).await {
            Ok(Decision::Forward(mods)) => {
                apply_request_mods(
                    &mut method,
                    &mut url,
                    &mut req_headers,
                    &mut req_body_bytes,
                    mods,
                );
            }
            Ok(Decision::Drop(d)) => return make_drop_response(d.status.unwrap_or(403), d.body),
            Err(e) => {
                tracing::warn!("intercept error on request: {e}");
                return make_drop_response(502, Some("intercept unavailable".into()));
            }
        }
    }

    let start = Instant::now();
    let upstream_req = build_upstream_request(&method, &url, &req_headers, req_body_bytes.clone())?;
    let resolved = match (checked, unresolvable) {
        (Some(a), _) => Ok(a),
        (None, Some(e)) => Err(e),
        (None, None) => crate::upstream::resolve(upstream_req.uri())
            .await
            .map_err(|e| format!("resolving host: {e}")),
    };
    let (res, peer) = match resolved {
        Ok(addrs) => {
            let (res, peer) = crate::upstream::request(upstream_req, addrs).await;
            (
                res.map_err(|e| format!("sending request: {}", crate::upstream::error_chain(&e))),
                peer.get(),
            )
        }
        Err(e) => (Err(e), None),
    };
    let duration_ms = start.elapsed().as_millis() as u64;

    // A WebSocket the upstream accepted, or an event stream: recorded now,
    // then passed through as it flows (no response intercept, no buffering).
    let res = match res {
        Ok(mut r) => {
            let upgrade = (r.status() == hyper::StatusCode::SWITCHING_PROTOCOLS)
                .then(|| client_upgrade.take())
                .flatten();
            let event_stream = crate::stream::is_event_stream(r.headers());
            if upgrade.is_some() || event_stream {
                let raw = r.headers().clone();
                let status = r.status().as_u16();
                let recorder = record.then(|| {
                    let (req_body, req_body_encoding) = encode_body(&req_body_bytes);
                    store.record(TrafficEntry {
                        id: id.clone(),
                        ts: Timestamp::now(),
                        host: host.clone(),
                        method: method.clone(),
                        url: url.clone(),
                        req_headers: req_headers.clone(),
                        req_body,
                        req_body_encoding,
                        status: Some(status),
                        res_headers: collect_headers(&raw),
                        res_body: None,
                        res_body_encoding: Default::default(),
                        duration_ms: Some(duration_ms),
                        replay_of: None,
                        source: source.clone(),
                        meta: meta.clone(),
                        error: None,
                        origin: crate::storage::Origin::Proxy,
                        peer,
                        refused: false,
                    });
                    crate::stream::Recorder::new(store.clone(), id.clone())
                });
                tracing::info!("{method} {url} {status} {duration_ms}ms (streaming)");
                if let Some(client_upgrade) = upgrade {
                    let upstream_upgrade = hyper::upgrade::on(&mut r);
                    let revoked = grant.as_ref().map(|g| g.revoked.clone());
                    let stop = async move {
                        match revoked {
                            Some(r) => crate::clients::revoked(r).await,
                            None => std::future::pending().await,
                        }
                    };
                    tokio::spawn(crate::stream::relay_websocket(
                        client_upgrade,
                        upstream_upgrade,
                        recorder,
                        stop,
                    ));
                    return switching_protocols(&raw);
                }
                // A compressed stream passes through, but its events can't
                // be read.
                let readable = raw
                    .get(hyper::header::CONTENT_ENCODING)
                    .is_none_or(|v| v.as_bytes().eq_ignore_ascii_case(b"identity"));
                let body = crate::stream::SseTap::new(r.into_body(), recorder.filter(|_| readable));
                return client_response_streamed(status, &raw, body.boxed());
            }
            Ok(r)
        }
        Err(e) => Err(e),
    };

    let mut upstream_error = None;
    let (mut status, mut res_headers, mut res_raw_headers, mut res_body_bytes) = match res {
        Ok(r) => {
            let s = r.status().as_u16();
            let h = collect_headers(r.headers());
            let raw = r.headers().clone();
            let b = r.into_body().collect().await?.to_bytes();
            (Some(s), h, raw, b)
        }
        Err(e) => {
            tracing::debug!("upstream error: {e}");
            upstream_error = Some(e);
            (None, Headers::new(), hyper::HeaderMap::new(), Bytes::new())
        }
    };
    if !record {
        return match status {
            Some(s) => client_response(s, &res_raw_headers, res_body_bytes),
            None => make_drop_response(502, None),
        };
    }

    // --- intercept response ---
    if let Some(socket) = &config.intercept_socket {
        if let Some(s) = status {
            let event = InterceptEvent::Response(ResponseEvent {
                id: Uuid::new_v4().to_string(),
                request_id: id.clone(),
                status: s,
                headers: intercept_header_map(&res_headers),
                body: maybe_utf8(&res_body_bytes),
            });
            match intercept::pause(socket, &event).await {
                Ok(Decision::Forward(mods)) => {
                    apply_response_mods(
                        &mut status,
                        &mut res_headers,
                        &mut res_raw_headers,
                        &mut res_body_bytes,
                        mods,
                    );
                }
                Ok(Decision::Drop(d)) => {
                    return make_drop_response(d.status.unwrap_or(502), d.body);
                }
                Err(e) => {
                    tracing::warn!("intercept error on response: {e}");
                    return make_drop_response(502, Some("intercept unavailable".into()));
                }
            }
        }
    }

    let (req_body, req_body_encoding) = encode_body(&req_body_bytes);
    let (res_body, res_body_encoding) = encode_body(&res_body_bytes);
    let entry = TrafficEntry {
        id,
        ts: Timestamp::now(),
        host,
        method,
        url,
        req_headers,
        req_body,
        req_body_encoding,
        status,
        res_headers,
        res_body,
        res_body_encoding,
        duration_ms: Some(duration_ms),
        replay_of: None,
        source,
        meta,
        error: upstream_error,
        origin: crate::storage::Origin::Proxy,
        peer,
        refused: false,
    };

    tracing::info!(
        "{} {} {} {}ms",
        entry.method,
        entry.url,
        entry
            .status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "ERR".to_string()),
        duration_ms
    );

    store.record(entry);

    match status {
        Some(s) => client_response(s, &res_raw_headers, res_body_bytes),
        None => make_drop_response(502, None),
    }
}

fn build_upstream_request(
    method: &str,
    url: &str,
    headers: &Headers,
    body: Bytes,
) -> Result<Request<Full<Bytes>>> {
    let mut builder = Request::builder()
        .method(method)
        .uri(url.parse::<hyper::Uri>()?);
    // `header` appends, so repeated headers go upstream as captured.
    for (k, v) in headers.iter() {
        if !k.eq_ignore_ascii_case("host")
            && !k.eq_ignore_ascii_case("proxy-connection")
            && !k.eq_ignore_ascii_case("proxy-authorization")
        {
            builder = builder.header(k, v);
        }
    }
    Ok(builder.body(Full::new(body))?)
}

fn apply_request_mods(
    method: &mut String,
    url: &mut String,
    headers: &mut Headers,
    body_bytes: &mut Bytes,
    mods: crate::intercept::ForwardDecision,
) {
    if let Some(m) = mods.method {
        *method = m;
    }
    if let Some(u) = mods.url {
        *url = u;
    }
    if let Some(h) = mods.headers {
        *headers = h.into_iter().collect();
    }
    if let Some(b) = mods.body {
        *body_bytes = Bytes::from(b.into_bytes());
    }
}

fn apply_response_mods(
    status: &mut Option<u16>,
    headers: &mut Headers,
    raw_headers: &mut hyper::HeaderMap,
    body_bytes: &mut Bytes,
    mods: crate::intercept::ForwardDecision,
) {
    if let Some(s) = mods.status {
        *status = Some(s);
    }
    if let Some(h) = mods.headers {
        *headers = h.into_iter().collect();
        *raw_headers = to_header_map(headers);
    }
    if let Some(b) = mods.body {
        *body_bytes = Bytes::from(b.into_bytes());
    }
}

/// Headers that describe one connection, not the message (RFC 9110 §7.6.1),
/// plus content-length, which hyper recomputes from the buffered body.
const NOT_FORWARDED: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// The response the proxy sends back to its client: upstream's status and
/// headers (every repeated one, raw bytes) minus hop-by-hop and framing
/// headers, since the body has been buffered and is re-framed here.
fn client_response(
    status: u16,
    headers: &hyper::HeaderMap,
    body: Bytes,
) -> Result<Response<ProxyBody>> {
    client_response_streamed(status, headers, full(body))
}

/// The 101 for an accepted WebSocket: upstream's headers, `Upgrade` and
/// `Connection` included (they are the point), minus framing and proxy
/// headers.
fn switching_protocols(headers: &hyper::HeaderMap) -> Result<Response<ProxyBody>> {
    let mut builder = Response::builder().status(hyper::StatusCode::SWITCHING_PROTOCOLS);
    for (k, v) in headers {
        let name = k.as_str();
        if name != "connection"
            && name != "upgrade"
            && (NOT_FORWARDED.contains(&name) || name == "content-length")
        {
            continue;
        }
        builder = builder.header(k, v);
    }
    Ok(builder.body(full(Bytes::new()))?)
}

/// [`client_response`] with any body, e.g. one streamed through.
fn client_response_streamed(
    status: u16,
    headers: &hyper::HeaderMap,
    body: ProxyBody,
) -> Result<Response<ProxyBody>> {
    // Headers named in Connection are hop-by-hop too.
    let named: Vec<String> = headers
        .get_all(hyper::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .collect();
    let mut builder = Response::builder().status(status);
    for (k, v) in headers {
        let name = k.as_str();
        if NOT_FORWARDED.contains(&name)
            || name == "content-length"
            || named.iter().any(|n| n == name)
        {
            continue;
        }
        builder = builder.header(k, v);
    }
    Ok(builder.body(body)?)
}

/// Build a sendable header map from string headers (an intercept hook's
/// override). Names or values hyper can't send are skipped, not fatal.
fn to_header_map(headers: &Headers) -> hyper::HeaderMap {
    let mut map = hyper::HeaderMap::new();
    for (k, v) in headers.iter() {
        let (Ok(name), Ok(value)) = (
            hyper::header::HeaderName::from_bytes(k.as_bytes()),
            hyper::header::HeaderValue::from_str(v),
        ) else {
            tracing::debug!("skipping unsendable header {k:?}");
            continue;
        };
        map.append(name, value);
    }
    map
}

fn make_drop_response(status: u16, body: Option<String>) -> Result<Response<ProxyBody>> {
    let body_bytes = body
        .map(|b| Bytes::from(b.into_bytes()))
        .unwrap_or_default();
    Ok(Response::builder()
        .status(status)
        .body(full(body_bytes))
        .unwrap())
}

/// Every header in wire order, repeated names included. Values that are not
/// valid UTF-8 are kept lossily rather than dropped.
pub(crate) fn collect_headers(headers: &hyper::HeaderMap) -> Headers {
    headers
        .iter()
        .map(|(k, v)| (k.to_string(), header_value_to_string(v.as_bytes())))
        .collect()
}

/// The intercept-socket protocol still carries headers as a `{name: value}`
/// map. Repeated names are joined with ", " (RFC 9110 field combining) so a
/// hook sees every value; Set-Cookie is joined too, which is lossy only if
/// the hook writes the map back.
fn intercept_header_map(headers: &Headers) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    for (k, v) in headers.iter() {
        map.entry(k.to_string())
            .and_modify(|existing| {
                existing.push_str(", ");
                existing.push_str(v);
            })
            .or_insert_with(|| v.to_string());
    }
    map
}

/// Body as text for the intercept-socket protocol, which is string-only.
/// The traffic log uses `encode_body` instead, which is byte-exact.
fn maybe_utf8(b: &Bytes) -> Option<String> {
    if b.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(b).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::Ca;
    use crate::storage::{Store, TrafficEntry};
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream, UnixListener};

    // --- unit tests ---

    #[test]
    fn maybe_utf8_empty_is_none() {
        assert_eq!(maybe_utf8(&Bytes::new()), None);
    }

    #[test]
    fn maybe_utf8_valid_string() {
        assert_eq!(maybe_utf8(&Bytes::from("hello")), Some("hello".to_string()));
    }

    #[test]
    fn maybe_utf8_invalid_bytes_returns_lossy_string() {
        let result = maybe_utf8(&Bytes::from(vec![0xFF, 0xFE, 0x00]));
        assert!(result.is_some());
    }

    #[test]
    fn collect_headers_basic() {
        let mut map = hyper::HeaderMap::new();
        map.insert(
            hyper::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        map.insert(hyper::header::ACCEPT, "*/*".parse().unwrap());
        let collected = collect_headers(&map);
        assert_eq!(collected.get("content-type"), Some("application/json"));
        assert_eq!(collected.get("accept"), Some("*/*"));
    }

    #[test]
    fn collect_headers_keeps_repeated_values_in_order() {
        let mut map = hyper::HeaderMap::new();
        map.append(hyper::header::SET_COOKIE, "a=1".parse().unwrap());
        map.append(hyper::header::SET_COOKIE, "b=2".parse().unwrap());
        let collected = collect_headers(&map);
        assert_eq!(
            collected.get_all("set-cookie").collect::<Vec<_>>(),
            ["a=1", "b=2"]
        );
    }

    #[test]
    fn collect_headers_keeps_non_utf8_values() {
        let mut map = hyper::HeaderMap::new();
        map.insert(
            "x-odd",
            hyper::header::HeaderValue::from_bytes(b"caf\xe9").unwrap(),
        );
        let v = collect_headers(&map).get("x-odd").unwrap().to_string();
        assert!(v.starts_with("caf") && v.len() > 3, "got {v:?}");
    }

    #[test]
    fn build_upstream_request_sends_repeated_headers() {
        let h: Headers = [("x-multi", "one"), ("host", "h"), ("x-multi", "two")]
            .into_iter()
            .collect();
        let req = build_upstream_request("GET", "http://h/", &h, Bytes::new()).unwrap();
        let vals: Vec<_> = req
            .headers()
            .get_all("x-multi")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(vals, ["one", "two"]);
        assert!(!req.headers().contains_key("host"));
    }

    #[test]
    fn intercept_header_map_joins_repeated_values() {
        let h: Headers = [("a", "1"), ("b", "x"), ("a", "2")].into_iter().collect();
        let m = intercept_header_map(&h);
        assert_eq!(m["a"], "1, 2");
        assert_eq!(m["b"], "x");
    }

    fn start_args(sqlite: bool, db: Option<&str>, api: bool) -> StartArgs {
        StartArgs {
            listen: "127.0.0.1:0".into(),
            log_file: None,
            sqlite,
            db: db.map(PathBuf::from),
            filter_host: None,
            intercept_socket: None,
            api_listen: api.then(|| "127.0.0.1:0".into()),
            api_token_file: None,
            proxy_auth_file: None,
            allow_client: vec![],
            proxy_tls: false,
            api_tls: false,
            tls_name: vec![],
            allow_open_proxy: false,
            api_no_send: false,
            proxy_auth_api: false,
            auth_listen: None,
            auth_listen_allow_plaintext: false,
            api_allow_plaintext: false,
            expires: None,
        }
    }

    #[test]
    fn sqlite_path_is_on_when_asked_for_or_when_the_api_needs_it() {
        let dd = std::path::Path::new("/dd");
        assert_eq!(sqlite_path(&start_args(false, None, false), dd), None);
        assert_eq!(
            sqlite_path(&start_args(true, None, false), dd),
            Some(PathBuf::from("/dd/traffic.db"))
        );
        assert_eq!(
            sqlite_path(&start_args(false, None, true), dd),
            Some(PathBuf::from("/dd/traffic.db"))
        );
        assert_eq!(
            sqlite_path(&start_args(false, Some("/data/t.db"), false), dd),
            None,
            "--db alone only sets the location"
        );
        assert_eq!(
            sqlite_path(&start_args(true, Some("/data/t.db"), false), dd),
            Some(PathBuf::from("/data/t.db"))
        );
        assert_eq!(
            sqlite_path(&start_args(true, Some("/data/t.db"), true), dd),
            Some(PathBuf::from("/data/t.db"))
        );
    }

    #[test]
    fn upstream_request_strips_proxy_headers() {
        let mut h = Headers::new();
        h.append("proxy-connection", "keep-alive");
        h.append("proxy-authorization", "Basic eDp5");
        h.append("accept", "*/*");
        let req = build_upstream_request("GET", "http://example.com/", &h, Bytes::new()).unwrap();
        assert!(!req.headers().contains_key("proxy-connection"));
        assert!(!req.headers().contains_key("proxy-authorization"));
        assert!(req.headers().contains_key("accept"));
    }

    // --- integration test helpers ---

    async fn start_echo_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            hyper_util::rt::TokioIo::new(stream),
                            service_fn(|_req: Request<Incoming>| async move {
                                Ok::<_, anyhow::Error>(Response::new(Full::new(Bytes::from(
                                    "echo-ok",
                                ))))
                            }),
                        )
                        .await
                        .ok();
                });
            }
        });
        port
    }

    /// Start a mock Unix socket interceptor that replies with the given decisions in order,
    /// one per connection (one connection per intercepted event).
    async fn start_mock_interceptor(socket_path: PathBuf, decisions: Vec<&'static str>) {
        let listener = UnixListener::bind(&socket_path).unwrap();
        tokio::spawn(async move {
            for decision in decisions {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let (reader, mut writer) = tokio::io::split(stream);
                    let mut reader = BufReader::new(reader);
                    let mut _line = String::new();
                    reader.read_line(&mut _line).await.ok();
                    writer.write_all(decision.as_bytes()).await.ok();
                    writer.write_all(b"\n").await.ok();
                });
            }
        });
    }

    async fn send_http_through_proxy(proxy_port: u16, echo_port: u16, path: &str) -> String {
        let target_url = format!("http://127.0.0.1:{echo_port}{path}");
        let raw = format!(
            "GET {target_url} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\nConnection: close\r\n\r\n"
        );
        let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
            .await
            .unwrap();
        stream.write_all(raw.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    }

    async fn start_proxy(
        data_dir: &std::path::Path,
        log_file: &std::path::Path,
        intercept_socket: Option<PathBuf>,
    ) -> u16 {
        start_proxy_with(
            data_dir,
            log_file,
            ProxyConfig {
                intercept_socket,
                ..Default::default()
            },
        )
        .await
    }

    async fn start_proxy_with(
        data_dir: &std::path::Path,
        log_file: &std::path::Path,
        config: ProxyConfig,
    ) -> u16 {
        // `main` does this; tests that do TLS need it too.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = Arc::new(Ca::load_or_create(data_dir).unwrap());
        // sqlite too, for the messages (see `messages_of`).
        let store = Store::new(Some(log_file), Some(&data_dir.join("t.db"))).unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = proxy_listener.local_addr().unwrap().port();
        tokio::spawn(serve(proxy_listener, ca, store, config));
        tokio::time::sleep(Duration::from_millis(20)).await;
        port
    }

    // --- proxy integration tests (no intercept) ---

    #[tokio::test]
    async fn http_proxy_records_request_in_log() {
        let echo_port = start_echo_server().await;
        let dir = TempDir::new().unwrap();
        let log_file = dir.path().join("traffic.jsonl");
        let proxy_port = start_proxy(dir.path(), &log_file, None).await;

        let response = send_http_through_proxy(proxy_port, echo_port, "/probe").await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "expected 200, got: {response}"
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        let content = std::fs::read_to_string(&log_file).expect("traffic.jsonl should exist");
        let entry: TrafficEntry = serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(entry.method, "GET");
        assert_eq!(entry.origin, crate::storage::Origin::Proxy);
        assert_eq!(entry.status, Some(200));
        assert!(entry.url.contains("/probe"), "url was: {}", entry.url);
        assert!(entry.duration_ms.is_some());
        let to: std::net::SocketAddr = format!("127.0.0.1:{echo_port}").parse().unwrap();
        assert_eq!(entry.peer, Some(to), "the upstream it connected to");
    }

    #[tokio::test]
    async fn unreachable_upstream_is_recorded_with_its_error() {
        // A port nothing listens on: bind, note it, close.
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let dir = TempDir::new().unwrap();
        let log_file = dir.path().join("traffic.jsonl");
        let proxy_port = start_proxy(dir.path(), &log_file, None).await;

        send_http_through_proxy(proxy_port, dead_port, "/gone").await;

        tokio::time::sleep(Duration::from_millis(50)).await;
        let content = std::fs::read_to_string(&log_file).unwrap();
        let entry: TrafficEntry = serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(entry.status, None);
        let error = entry.error.expect("the failure is recorded");
        assert!(error.to_lowercase().contains("connect"), "{error}");
        assert!(entry.meta.is_empty());
        assert_eq!(entry.peer, None, "never connected");
    }

    /// Upstream that answers with two Set-Cookie headers, a header value that
    /// is not valid UTF-8, and a binary body; it echoes nothing. Raw TCP so
    /// the bytes on the wire are exactly what the test says.
    async fn start_awkward_upstream() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 8192];
            let _ = stream.read(&mut buf).await;
            let mut res: Vec<u8> = b"HTTP/1.1 200 OK\r\n\
                set-cookie: session=abc; Secure; HttpOnly\r\n\
                set-cookie: theme=dark; SameSite=Lax\r\n\
                x-odd: caf\xe9\r\n\
                content-length: 6\r\n\
                connection: close\r\n\r\n"
                .to_vec();
            res.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x00, 0xff]);
            stream.write_all(&res).await.ok();
        });
        port
    }

    #[tokio::test]
    async fn proxy_log_keeps_repeated_headers_odd_values_and_binary_bodies() {
        let up = start_awkward_upstream().await;
        let dir = TempDir::new().unwrap();
        let log_file = dir.path().join("traffic.jsonl");
        let proxy_port = start_proxy(dir.path(), &log_file, None).await;

        let req_body: &[u8] = &[0x1f, 0x8b, 0x08, 0x00, 0xfe];
        let mut raw = format!(
            "POST http://127.0.0.1:{up}/bin HTTP/1.1\r\nHost: 127.0.0.1:{up}\r\n\
             x-multi: one\r\nx-multi: two\r\ncontent-length: {}\r\nConnection: close\r\n\r\n",
            req_body.len()
        )
        .into_bytes();
        raw.extend_from_slice(req_body);
        let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
            .await
            .unwrap();
        stream.write_all(&raw).await.unwrap();
        let mut sink = Vec::new();
        stream.read_to_end(&mut sink).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        let line = std::fs::read_to_string(&log_file).unwrap();
        let entry: TrafficEntry = serde_json::from_str(line.lines().next().unwrap()).unwrap();

        assert_eq!(
            entry.res_headers.get_all("set-cookie").collect::<Vec<_>>(),
            ["session=abc; Secure; HttpOnly", "theme=dark; SameSite=Lax"],
            "every Set-Cookie must be logged, in order"
        );
        assert_eq!(
            entry.req_headers.get_all("x-multi").collect::<Vec<_>>(),
            ["one", "two"]
        );
        let odd = entry.res_headers.get("x-odd").unwrap();
        assert!(
            odd.starts_with("caf") && odd.len() > 3,
            "non-UTF-8 value kept, got {odd:?}"
        );
        assert_eq!(entry.req_body_bytes().unwrap().as_deref(), Some(req_body));
        assert_eq!(
            entry.res_body_bytes().unwrap().as_deref(),
            Some(&[0x89, b'P', b'N', b'G', 0x00, 0xff][..]),
            "binary response body must be byte-exact"
        );
    }

    /// Upstream that answers with a chunked body, two Set-Cookies and hop-by-hop
    /// headers, as a browser-facing app server would.
    async fn start_cookie_upstream() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 8192];
            let _ = stream.read(&mut buf).await;
            let res = "HTTP/1.1 200 OK\r\n\
                content-type: text/html; charset=utf-8\r\n\
                set-cookie: session=abc; Secure; HttpOnly\r\n\
                set-cookie: theme=dark\r\n\
                keep-alive: timeout=5\r\n\
                transfer-encoding: chunked\r\n\
                connection: close\r\n\r\n\
                5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
            stream.write_all(res.as_bytes()).await.ok();
        });
        port
    }

    /// Send a GET through the proxy and parse the response with hyper, so
    /// framing errors (e.g. a stale transfer-encoding) fail the test.
    async fn get_through_proxy(
        proxy_port: u16,
        target: &str,
    ) -> (hyper::http::response::Parts, Bytes) {
        let stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
            .await
            .unwrap();
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                .await
                .unwrap();
        tokio::spawn(conn);
        let req = Request::get(target)
            .header("host", "upstream")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let res = sender.send_request(req).await.unwrap();
        let (parts, body) = res.into_parts();
        let body = tokio::time::timeout(Duration::from_secs(5), body.collect())
            .await
            .expect("body must be framed so the client can finish reading it")
            .unwrap()
            .to_bytes();
        (parts, body)
    }

    #[tokio::test]
    async fn http_proxy_forwards_response_headers_to_client() {
        let up = start_cookie_upstream().await;
        let dir = TempDir::new().unwrap();
        let proxy_port = start_proxy(dir.path(), &dir.path().join("t.jsonl"), None).await;

        let (parts, body) = get_through_proxy(proxy_port, &format!("http://127.0.0.1:{up}/")).await;

        assert_eq!(parts.status, 200);
        let cookies: Vec<_> = parts
            .headers
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            cookies,
            ["session=abc; Secure; HttpOnly", "theme=dark"],
            "browser must get every Set-Cookie"
        );
        assert_eq!(parts.headers["content-type"], "text/html; charset=utf-8");
        assert!(
            !parts.headers.contains_key("keep-alive"),
            "hop-by-hop headers are not forwarded"
        );
        assert!(
            !parts.headers.contains_key("transfer-encoding"),
            "body is re-framed by the proxy"
        );
        assert_eq!(body, "hello world");
    }

    #[tokio::test]
    async fn intercept_response_header_override_reaches_client() {
        let echo_port = start_echo_server().await;
        let dir = TempDir::new().unwrap();
        let socket_path = dir.path().join("intercept.sock");
        start_mock_interceptor(
            socket_path.clone(),
            vec![
                r#"{"action":"forward"}"#,
                r#"{"action":"forward","headers":{"x-injected":"yes"}}"#,
            ],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        let proxy_port =
            start_proxy(dir.path(), &dir.path().join("t.jsonl"), Some(socket_path)).await;

        let (parts, body) =
            get_through_proxy(proxy_port, &format!("http://127.0.0.1:{echo_port}/")).await;
        assert_eq!(parts.headers["x-injected"], "yes");
        assert_eq!(body, "echo-ok");
    }

    #[test]
    fn client_response_drops_hop_by_hop_and_length_headers() {
        let h: Headers = [
            ("connection", "keep-alive, x-private"),
            ("x-private", "1"),
            ("keep-alive", "timeout=5"),
            ("Transfer-Encoding", "chunked"),
            ("content-length", "999"),
            ("upgrade", "h2c"),
            ("set-cookie", "a=1"),
            ("set-cookie", "b=2"),
            ("content-encoding", "gzip"),
        ]
        .into_iter()
        .collect();
        let res = client_response(200, &to_header_map(&h), Bytes::from_static(b"abc")).unwrap();
        let names: Vec<_> = res.headers().keys().map(|k| k.as_str()).collect();
        assert_eq!(names, ["set-cookie", "content-encoding"]);
        assert_eq!(res.headers().get_all("set-cookie").iter().count(), 2);
    }

    #[test]
    fn to_header_map_skips_headers_hyper_rejects() {
        // An intercept hook can send any string; a name with a space can't
        // go on the wire and must not fail the whole response.
        let h: Headers = [("bad name", "x"), ("ok", "1"), ("ok", "2")]
            .into_iter()
            .collect();
        let map = to_header_map(&h);
        assert_eq!(map.get_all("ok").iter().count(), 2);
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn client_response_forwards_raw_non_utf8_value_bytes() {
        let mut map = hyper::HeaderMap::new();
        map.insert(
            "x-odd",
            hyper::header::HeaderValue::from_bytes(b"caf\xe9").unwrap(),
        );
        let res = client_response(200, &map, Bytes::new()).unwrap();
        assert_eq!(res.headers()["x-odd"].as_bytes(), b"caf\xe9");
    }

    // --- access control, attribution, expiry, TLS listener (#8, #9) ---

    type SeenHeaders = Arc<tokio::sync::Mutex<Vec<hyper::HeaderMap>>>;

    /// Upstream that remembers every request's headers and answers 200 "ok".
    async fn start_header_capture_upstream() -> (u16, SeenHeaders) {
        let seen: SeenHeaders = Default::default();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let s = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let s = s.clone();
                tokio::spawn(async move {
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            hyper_util::rt::TokioIo::new(stream),
                            service_fn(move |req: Request<Incoming>| {
                                let s = s.clone();
                                async move {
                                    s.lock().await.push(req.headers().clone());
                                    Ok::<_, anyhow::Error>(Response::new(Full::new(Bytes::from(
                                        "ok",
                                    ))))
                                }
                            }),
                        )
                        .await
                        .ok();
                });
            }
        });
        (port, seen)
    }

    /// `Basic <base64(user:pass)>`, encoded test-side.
    fn basic_header(userpass: &str) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in userpass.as_bytes().chunks(3) {
            let n = (u32::from(c[0]) << 16)
                | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                | u32::from(*c.get(2).unwrap_or(&0));
            out.push(A[(n >> 18) as usize & 63] as char);
            out.push(A[(n >> 12) as usize & 63] as char);
            out.push(if c.len() > 1 {
                A[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if c.len() > 2 {
                A[n as usize & 63] as char
            } else {
                '='
            });
        }
        format!("Basic {out}")
    }

    /// One request through the proxy over an already-connected stream.
    async fn request_over<IO>(
        io: IO,
        req: Request<Full<Bytes>>,
    ) -> (hyper::http::response::Parts, Bytes)
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(io))
                .await
                .unwrap();
        tokio::spawn(conn);
        let res = sender.send_request(req).await.unwrap();
        let (parts, body) = res.into_parts();
        (parts, body.collect().await.unwrap().to_bytes())
    }

    fn proxied_get(target: &str, auth: Option<&str>) -> Request<Full<Bytes>> {
        let mut b = Request::get(target).header("host", "upstream");
        if let Some(a) = auth {
            b = b.header("proxy-authorization", basic_header(a));
        }
        b.body(Full::new(Bytes::new())).unwrap()
    }

    fn creds(text: &str) -> Option<ProxyCredentials> {
        Some(ProxyCredentials::parse(text).unwrap())
    }

    fn logged(log: &std::path::Path) -> Vec<TrafficEntry> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn proxy_answers_the_cert_host_itself_and_records_nothing() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let port = start_proxy(dir.path(), &log, None).await;
        let cert = Ca::load_or_create(dir.path()).unwrap().public_cert();
        let connect = || TcpStream::connect(format!("127.0.0.1:{port}"));

        let (parts, body) = request_over(
            connect().await.unwrap(),
            proxied_get("http://taphttp/ca.pem", None),
        )
        .await;
        assert_eq!(parts.status, 200);
        assert_eq!(parts.headers["content-type"], crate::ca::PEM_CONTENT_TYPE);
        assert_eq!(body, cert.pem.as_bytes());

        let (parts, body) = request_over(
            connect().await.unwrap(),
            proxied_get("http://TAPHTTP/ca.der", None),
        )
        .await;
        assert_eq!(parts.status, 200);
        assert_eq!(body, cert.der);

        let (parts, body) = request_over(
            connect().await.unwrap(),
            proxied_get("http://taphttp/", None),
        )
        .await;
        assert_eq!(parts.status, 200);
        let ca = Ca::load_or_create(dir.path()).unwrap();
        assert!(String::from_utf8_lossy(&body).contains(&ca.fingerprint_sha256()));

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            logged(&log).is_empty(),
            "not upstream traffic: not recorded"
        );
    }

    #[tokio::test]
    async fn connect_to_the_cert_host_is_refused_not_tunnelled() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let port = start_proxy(dir.path(), &log, None).await;
        let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let connect = Request::connect("taphttp:443")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (parts, _) = request_over(stream, connect).await;
        assert_eq!(parts.status, 405, "https://taphttp is not served");
    }

    #[tokio::test]
    async fn cert_host_is_behind_proxy_auth() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let port = start_proxy_with(
            dir.path(),
            &log,
            ProxyConfig {
                credentials: creds("phone:s3cret"),
                ..Default::default()
            },
        )
        .await;
        let connect = || TcpStream::connect(format!("127.0.0.1:{port}"));
        let (parts, _) = request_over(
            connect().await.unwrap(),
            proxied_get("http://taphttp/ca.pem", None),
        )
        .await;
        assert_eq!(parts.status, 407);
        let (parts, _) = request_over(
            connect().await.unwrap(),
            proxied_get("http://taphttp/ca.pem", Some("phone:s3cret")),
        )
        .await;
        assert_eq!(parts.status, 200);
    }

    #[tokio::test]
    async fn expired_proxy_refuses_the_cert_host_too() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let port = start_proxy_with(
            dir.path(),
            &log,
            ProxyConfig {
                expires: Some("2020-01-01T00:00:00Z".parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
        let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let (parts, _) = request_over(stream, proxied_get("http://taphttp/ca.pem", None)).await;
        assert_eq!(parts.status, 503);
    }

    #[tokio::test]
    async fn proxy_auth_required_when_credentials_configured() {
        let (up, seen) = start_header_capture_upstream().await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let port = start_proxy_with(
            dir.path(),
            &log,
            ProxyConfig {
                credentials: creds("agent.T-3:s3cret"),
                ..Default::default()
            },
        )
        .await;
        let target = format!("http://127.0.0.1:{up}/x");
        let connect = || TcpStream::connect(format!("127.0.0.1:{port}"));

        for bad in [None, Some("agent.T-3:wrong"), Some("someone:s3cret")] {
            let (parts, _) =
                request_over(connect().await.unwrap(), proxied_get(&target, bad)).await;
            assert_eq!(parts.status, 407, "{bad:?}");
            assert_eq!(
                parts.headers["proxy-authenticate"],
                r#"Basic realm="taphttp""#
            );
        }
        assert!(
            seen.lock().await.is_empty(),
            "rejected requests never reach upstream"
        );

        let (parts, body) = request_over(
            connect().await.unwrap(),
            proxied_get(&target, Some("agent.T-3:s3cret")),
        )
        .await;
        assert_eq!(parts.status, 200);
        assert_eq!(body, "ok");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let entries = logged(&log);
        assert_eq!(entries.len(), 1, "only the authenticated request is logged");
        assert_eq!(
            entries[0].source.as_deref(),
            Some("agent.T-3"),
            "verified identity recorded"
        );
    }

    #[tokio::test]
    async fn proxy_authorization_never_reaches_upstream_or_the_log() {
        let (up, seen) = start_header_capture_upstream().await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        // No credentials configured: the username is a self-reported label.
        let port = start_proxy(dir.path(), &log, None).await;
        let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let (parts, _) = request_over(
            stream,
            proxied_get(
                &format!("http://127.0.0.1:{up}/"),
                Some("agent.T-3:not-a-secret"),
            ),
        )
        .await;
        assert_eq!(parts.status, 200);

        let upstream = seen.lock().await;
        assert!(
            !upstream[0].contains_key("proxy-authorization"),
            "credentials must not leak to the target"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        let raw = std::fs::read_to_string(&log).unwrap();
        assert!(
            !raw.to_ascii_lowercase().contains("proxy-authorization"),
            "{raw}"
        );
        assert!(
            !raw.contains("not-a-secret")
                && !raw.contains(&basic_header("agent.T-3:not-a-secret")[6..])
        );
        let entries = logged(&log);
        assert_eq!(entries[0].source.as_deref(), Some("agent.T-3"));
    }

    #[tokio::test]
    async fn intercept_hook_cannot_send_proxy_authorization_upstream() {
        let (up, seen) = start_header_capture_upstream().await;
        let dir = TempDir::new().unwrap();
        let socket_path = dir.path().join("intercept.sock");
        start_mock_interceptor(
            socket_path.clone(),
            vec![
                r#"{"action":"forward","headers":{"proxy-authorization":"Basic eDp5","x-kept":"1"}}"#,
                r#"{"action":"forward"}"#,
            ],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        let port = start_proxy(dir.path(), &dir.path().join("t.jsonl"), Some(socket_path)).await;
        let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        request_over(
            stream,
            proxied_get(&format!("http://127.0.0.1:{up}/"), None),
        )
        .await;
        let upstream = seen.lock().await;
        assert_eq!(upstream[0]["x-kept"], "1", "the hook's other headers apply");
        assert!(!upstream[0].contains_key("proxy-authorization"));
    }

    #[tokio::test]
    async fn untagged_traffic_has_no_source() {
        let (up, _) = start_header_capture_upstream().await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let port = start_proxy(dir.path(), &log, None).await;
        let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        request_over(
            stream,
            proxied_get(&format!("http://127.0.0.1:{up}/"), None),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(logged(&log)[0].source, None);
    }

    /// Open a CONNECT tunnel through the proxy, then TLS to taphttp's MITM
    /// cert for `host` (trusting the CA in `dir`). Returns the CONNECT status
    /// and, if it was 200, the TLS stream.
    async fn connect_tunnel(
        proxy_port: u16,
        authority: &str,
        auth: Option<&str>,
        dir: &std::path::Path,
    ) -> (u16, Option<tokio_rustls::client::TlsStream<TcpStream>>) {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
            .await
            .unwrap();
        let mut head = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if let Some(a) = auth {
            head.push_str(&format!("Proxy-Authorization: {}\r\n", basic_header(a)));
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).await.unwrap() == 0 {
                break;
            }
            buf.push(byte[0]);
        }
        let status: u16 = String::from_utf8_lossy(&buf)[9..12].parse().unwrap();
        if status != 200 {
            return (status, None);
        }
        let host = authority.rsplit_once(':').unwrap().0.to_string();
        let tls = tls_connector(dir)
            .connect(
                rustls::pki_types::ServerName::try_from(host).unwrap(),
                stream,
            )
            .await
            .unwrap();
        (status, Some(tls))
    }

    /// A TLS client that trusts only taphttp's CA in `dir`.
    fn tls_connector(dir: &std::path::Path) -> tokio_rustls::TlsConnector {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pem = std::fs::read_to_string(dir.join("ca.crt")).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        use rustls::pki_types::{pem::PemObject, CertificateDer};
        for c in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tokio_rustls::TlsConnector::from(Arc::new(cfg))
    }

    #[tokio::test]
    async fn connect_is_authenticated_and_its_source_covers_the_tunnel() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let port = start_proxy_with(
            dir.path(),
            &log,
            ProxyConfig {
                credentials: creds("agent.T-3:s3cret"),
                ..Default::default()
            },
        )
        .await;
        // Nothing listens on :9 upstream, so the exchange records as a 502;
        // what matters is the auth decision and the recorded source.
        let authority = "localhost:9";
        assert_eq!(
            connect_tunnel(port, authority, None, dir.path()).await.0,
            407
        );
        assert_eq!(
            connect_tunnel(port, authority, Some("agent.T-3:nope"), dir.path())
                .await
                .0,
            407
        );

        let (status, tls) =
            connect_tunnel(port, authority, Some("agent.T-3:s3cret"), dir.path()).await;
        assert_eq!(status, 200);
        let req = Request::get("/inside")
            .header("host", "localhost")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (parts, _) = request_over(tls.unwrap(), req).await;
        assert_eq!(parts.status, 502);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let entries = logged(&log);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].url.ends_with("/inside"));
        assert_eq!(
            entries[0].origin,
            crate::storage::Origin::Proxy,
            "MITM'd HTTPS"
        );
        assert_eq!(entries[0].source.as_deref(), Some("agent.T-3"));
    }

    #[tokio::test]
    async fn mitm_records_the_upstream_peer_even_when_tls_fails() {
        // Accepts TCP, then hangs up: the upstream TLS handshake fails, but
        // taphttp did connect there.
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((s, _)) = up.accept().await {
                drop(s);
            }
        });
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let port = start_proxy_with(dir.path(), &log, ProxyConfig::default()).await;
        let authority = format!("localhost:{}", up_addr.port());
        let (status, tls) = connect_tunnel(port, &authority, None, dir.path()).await;
        assert_eq!(status, 200);
        let req = Request::get("/peer")
            .header("host", "localhost")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (parts, _) = request_over(tls.unwrap(), req).await;
        assert_eq!(parts.status, 502);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let entries = logged(&log);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].error.is_some());
        assert_eq!(entries[0].peer, Some(up_addr));
    }

    // --- WebSocket and SSE (#26) ---

    fn messages_of(dir: &std::path::Path, id: &str) -> Vec<taphttp_types::Message> {
        crate::storage::SqliteBackend::new(&dir.join("t.db"))
            .unwrap()
            .messages(id, None, 1000)
            .unwrap()
    }

    type Seen = Arc<std::sync::Mutex<Vec<hyper::HeaderMap>>>;

    /// A WebSocket echo server that greets each client with Binary [1,2,3].
    /// With `tls`, it speaks wss with a certificate taphttp trusts.
    async fn start_ws_upstream(tls: Option<&std::path::Path>) -> (u16, Seen) {
        let acceptor = match tls {
            Some(dir) => {
                let ca = Ca::load_or_create(dir).unwrap();
                crate::upstream::TEST_ROOTS
                    .lock()
                    .unwrap()
                    .push(ca.public_cert().der.into());
                Some(TlsAcceptor::from(
                    ca.server_config_for("localhost").await.unwrap(),
                ))
            }
            None => None,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen: Seen = Default::default();
        let s = seen.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let s = s.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let callback =
                        |req: &tokio_tungstenite::tungstenite::handshake::server::Request, res| {
                            s.lock().unwrap().push(req.headers().clone());
                            Ok(res)
                        };
                    match acceptor {
                        Some(a) => {
                            let tls = a.accept(stream).await.unwrap();
                            let ws = tokio_tungstenite::accept_hdr_async(tls, callback).await;
                            echo(ws.unwrap()).await
                        }
                        None => {
                            let ws = tokio_tungstenite::accept_hdr_async(stream, callback).await;
                            echo(ws.unwrap()).await
                        }
                    }
                });
            }
        });
        (port, seen)
    }

    async fn echo<S>(mut ws: tokio_tungstenite::WebSocketStream<S>)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message as M;
        ws.send(M::Binary(vec![1, 2, 3].into())).await.unwrap();
        while let Some(Ok(m)) = ws.next().await {
            if matches!(m, M::Text(_) | M::Binary(_)) && ws.send(m).await.is_err() {
                break;
            }
        }
    }

    /// The client side of a WebSocket handshake over `io` (through the
    /// proxy: `target` is absolute-form, or origin-form inside a tunnel).
    async fn ws_through<IO>(
        mut io: IO,
        target: &str,
        auth: Option<&str>,
    ) -> (u16, tokio_tungstenite::WebSocketStream<IO>)
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use tokio_tungstenite::tungstenite::handshake::{client::generate_key, derive_accept_key};
        let key = generate_key();
        let accept = derive_accept_key(key.as_bytes()).to_ascii_lowercase();
        let mut head = format!(
            "GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n\
             Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Extensions: permessage-deflate\r\n"
        );
        if let Some(a) = auth {
            head.push_str(&format!("Proxy-Authorization: {}\r\n", basic_header(a)));
        }
        head.push_str("\r\n");
        io.write_all(head.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            assert_eq!(io.read(&mut byte).await.unwrap(), 1, "head cut short");
            buf.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&buf).to_ascii_lowercase();
        let status: u16 = head[9..12].parse().unwrap();
        if status == 101 {
            for needle in [
                format!("sec-websocket-accept: {accept}"),
                "upgrade: websocket".into(),
                "connection: upgrade".into(),
            ] {
                assert!(
                    head.contains(needle.as_str()),
                    "{needle} reaches the client: {head}"
                );
            }
        }
        let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            io,
            tokio_tungstenite::tungstenite::protocol::Role::Client,
            None,
        )
        .await;
        (status, ws)
    }

    /// Talk to the echo server and check what came back.
    async fn chat<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message as M;
        let hello = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("a message within 5s")
            .unwrap()
            .unwrap();
        assert_eq!(hello, M::Binary(vec![1, 2, 3].into()));
        ws.send(M::Text("hello".into())).await.unwrap();
        assert_eq!(ws.next().await.unwrap().unwrap(), M::Text("hello".into()));
        ws.send(M::Binary(vec![0xff, 0].into())).await.unwrap();
        assert_eq!(
            ws.next().await.unwrap().unwrap(),
            M::Binary(vec![0xff, 0].into())
        );
        ws.close(None).await.unwrap();
        while let Some(Ok(_)) = ws.next().await {}
    }

    /// What a [`chat`] records, in order.
    fn check_chat_recorded(messages: &[taphttp_types::Message]) {
        use taphttp_types::{Direction::*, MessageKind, Opcode::*};
        let got: Vec<_> = messages
            .iter()
            .map(|m| {
                (
                    m.direction,
                    m.opcode.unwrap(),
                    m.data_bytes().unwrap().unwrap_or_default(),
                )
            })
            .collect();
        assert!(got.len() >= 6, "{got:?}");
        assert_eq!(
            got[..6],
            [
                (ServerToClient, Binary, vec![1, 2, 3]),
                (ClientToServer, Text, b"hello".to_vec()),
                (ServerToClient, Text, b"hello".to_vec()),
                (ClientToServer, Binary, vec![0xff, 0]),
                (ServerToClient, Binary, vec![0xff, 0]),
                (ClientToServer, Close, vec![]),
            ]
        );
        for (i, m) in messages.iter().enumerate() {
            assert_eq!(m.seq, i as u64);
            assert_eq!(m.kind, MessageKind::Websocket);
            assert_eq!(
                m.size,
                m.data_bytes().unwrap().map_or(0, |d| d.len()) as u64
            );
        }
    }

    #[tokio::test]
    async fn websockets_are_relayed_and_every_message_recorded() {
        let (up, seen) = start_ws_upstream(None).await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let port = start_proxy(dir.path(), &log, None).await;
        let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let (status, mut ws) =
            ws_through(stream, &format!("http://127.0.0.1:{up}/chat"), None).await;
        assert_eq!(status, 101);
        chat(&mut ws).await;

        tokio::time::sleep(Duration::from_millis(100)).await;
        let entries = logged(&log);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].status, Some(101));
        assert!(entries[0].url.ends_with("/chat"));
        check_chat_recorded(&messages_of(dir.path(), &entries[0].id));
        let up_headers = &seen.lock().unwrap()[0];
        assert!(
            !up_headers.contains_key("sec-websocket-extensions"),
            "no extensions: the relay can't read compressed frames"
        );
    }

    #[tokio::test]
    async fn websockets_inside_a_mitm_tunnel_are_relayed_and_recorded() {
        let up_dir = TempDir::new().unwrap();
        let (up, _) = start_ws_upstream(Some(up_dir.path())).await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let port = start_proxy(dir.path(), &log, None).await;
        let (status, tls) =
            connect_tunnel(port, &format!("localhost:{up}"), None, dir.path()).await;
        assert_eq!(status, 200);
        let (status, mut ws) = ws_through(tls.unwrap(), "/chat", None).await;
        assert_eq!(status, 101);
        chat(&mut ws).await;

        tokio::time::sleep(Duration::from_millis(100)).await;
        let entries = logged(&log);
        assert_eq!(entries[0].status, Some(101));
        assert!(
            entries[0].url.starts_with("https://localhost:"),
            "{}",
            entries[0].url
        );
        check_chat_recorded(&messages_of(dir.path(), &entries[0].id));
    }

    #[tokio::test]
    async fn a_websocket_outside_the_filter_is_relayed_unrecorded() {
        let (up, _) = start_ws_upstream(None).await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let port = start_proxy_with(
            dir.path(),
            &log,
            ProxyConfig {
                filter_host: Some("example.com".into()),
                ..Default::default()
            },
        )
        .await;
        let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let (status, mut ws) = ws_through(stream, &format!("http://127.0.0.1:{up}/"), None).await;
        assert_eq!(status, 101);
        chat(&mut ws).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!log.exists() || logged(&log).is_empty());
    }

    #[tokio::test]
    async fn revoking_a_credential_closes_its_websockets() {
        use futures_util::StreamExt;
        let (up, _) = start_ws_upstream(None).await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let reg = Arc::new(crate::clients::Registry::default());
        let (id, creds) = issue(&reg, &["127.0.0.1"], None, None);
        let port = start_proxy_with(dir.path(), &log, with_clients(&reg)).await;
        let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let (status, mut ws) =
            ws_through(stream, &format!("http://127.0.0.1:{up}/"), Some(&creds)).await;
        assert_eq!(status, 101);
        ws.next().await.unwrap().unwrap();
        assert!(reg.revoke(&id));
        let end = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("the socket is closed");
        assert!(!matches!(
            end,
            Some(Ok(tokio_tungstenite::tungstenite::Message::Text(_)))
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(logged(&log)[0].meta["task"], "T-7");
    }

    type EventTx = tokio::sync::mpsc::UnboundedSender<String>;

    /// An upstream whose `text/event-stream` body is whatever the test
    /// sends on the returned channel; dropping it ends the stream.
    async fn start_sse_upstream() -> (u16, Arc<tokio::sync::Mutex<Option<EventTx>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let slot: Arc<tokio::sync::Mutex<Option<EventTx>>> = Default::default();
        let s = slot.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let s = s.clone();
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    hyper_util::rt::TokioIo::new(stream),
                    service_fn(move |_req: Request<Incoming>| {
                        let s = s.clone();
                        async move {
                            let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
                            *s.lock().await = Some(tx);
                            let body = http_body_util::StreamBody::new(
                                futures_util::stream::unfold(rx, next_chunk),
                            );
                            Ok::<_, anyhow::Error>(
                                Response::builder()
                                    .header("content-type", "text/event-stream")
                                    .header("cache-control", "no-cache")
                                    .body(body)
                                    .unwrap(),
                            )
                        }
                    }),
                )
                .await
                .ok();
        });
        (port, slot)
    }

    async fn next_chunk(
        mut rx: tokio::sync::mpsc::UnboundedReceiver<String>,
    ) -> Option<(
        Result<hyper::body::Frame<Bytes>, std::convert::Infallible>,
        tokio::sync::mpsc::UnboundedReceiver<String>,
    )> {
        let chunk = rx.recv().await?;
        Some((Ok(hyper::body::Frame::data(Bytes::from(chunk))), rx))
    }

    #[tokio::test]
    async fn event_streams_are_streamed_through_and_each_event_recorded() {
        let (up, tx) = start_sse_upstream().await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let port = start_proxy(dir.path(), &log, None).await;
        let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                .await
                .unwrap();
        tokio::spawn(conn);
        let res = sender
            .send_request(proxied_get(&format!("http://127.0.0.1:{up}/events"), None))
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        assert_eq!(res.headers()["content-type"], "text/event-stream");
        let mut body = res.into_body();
        let tx = tx.lock().await.take().unwrap();
        tx.send("event: tick\nid: 1\ndata: one\n\n".into()).unwrap();
        let first = tokio::time::timeout(Duration::from_secs(5), body.frame())
            .await
            .expect("the first event arrives while the stream is still open")
            .unwrap()
            .unwrap();
        assert_eq!(
            first.data_ref().unwrap(),
            &b"event: tick\nid: 1\ndata: one\n\n"[..]
        );

        // The exchange is recorded when the stream starts, not when it ends.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let entries = logged(&log);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].status, Some(200));
        assert_eq!(
            entries[0].res_body, None,
            "the body is recorded as messages"
        );

        tx.send("data: two\r\ndata: lines\r\n\r\n: keepalive\n\n".into())
            .unwrap();
        drop(tx);
        let rest = tokio::time::timeout(Duration::from_secs(5), body.collect())
            .await
            .unwrap()
            .unwrap()
            .to_bytes();
        assert!(rest.starts_with(b"data: two"));

        tokio::time::sleep(Duration::from_millis(50)).await;
        let messages = messages_of(dir.path(), &entries[0].id);
        let got: Vec<_> = messages
            .iter()
            .map(|m| {
                (
                    m.seq,
                    m.kind,
                    m.direction,
                    m.event.clone(),
                    m.event_id.clone(),
                    m.data.clone(),
                )
            })
            .collect();
        use taphttp_types::{Direction::ServerToClient, MessageKind::Sse};
        assert_eq!(
            got,
            [
                (
                    0,
                    Sse,
                    ServerToClient,
                    Some("tick".into()),
                    Some("1".into()),
                    Some("one".into())
                ),
                (
                    1,
                    Sse,
                    ServerToClient,
                    None,
                    None,
                    Some("two\nlines".into())
                ),
            ]
        );
    }

    // --- issued credentials (#25) ---

    fn issue(
        reg: &crate::clients::Registry,
        allow: &[&str],
        budget: Option<u64>,
        rate: Option<crate::clients::Rate>,
    ) -> (String, String) {
        let issued = reg
            .issue(crate::clients::ClientSpec {
                allow: allow.iter().map(|s| s.to_string()).collect(),
                rate,
                budget,
                meta: [("task".to_string(), "T-7".to_string())].into(),
            })
            .unwrap();
        let id = issued.username.clone();
        (id.clone(), format!("{id}:{}", issued.password))
    }

    fn with_clients(reg: &Arc<crate::clients::Registry>) -> ProxyConfig {
        ProxyConfig {
            clients: Some(reg.clone()),
            ..Default::default()
        }
    }

    async fn proxy_get(port: u16, target: &str, auth: &str) -> hyper::http::response::Parts {
        let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        request_over(stream, proxied_get(target, Some(auth)))
            .await
            .0
    }

    #[tokio::test]
    async fn issued_credentials_enforce_the_allowlist_and_budget_and_are_recorded() {
        let (up, seen) = start_header_capture_upstream().await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let reg = Arc::new(crate::clients::Registry::default());
        let (id, creds) = issue(&reg, &["127.0.0.1"], Some(2), None);
        let port = start_proxy_with(dir.path(), &log, with_clients(&reg)).await;
        let allowed = format!("http://127.0.0.1:{up}/a");

        assert_eq!(proxy_get(port, &allowed, &creds).await.status, 200);
        let refused = proxy_get(port, "http://192.0.2.1:9/", &creds).await;
        assert_eq!(refused.status, 403, "not in the allowlist");
        assert_eq!(proxy_get(port, &allowed, &creds).await.status, 200);
        assert_eq!(
            proxy_get(port, &allowed, &creds).await.status,
            403,
            "budget of 2 used up"
        );
        let (user, _) = creds.split_once(':').unwrap();
        assert_eq!(
            proxy_get(port, &allowed, &format!("{user}:wrong"))
                .await
                .status,
            407
        );

        assert_eq!(seen.lock().await.len(), 2, "refusals never reach upstream");
        for h in seen.lock().await.iter() {
            assert!(!h.contains_key("proxy-authorization"));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let entries = logged(&log);
        assert_eq!(entries.len(), 4, "the 407 isn't an exchange");
        let refused: Vec<bool> = entries.iter().map(|e| e.refused).collect();
        assert_eq!(refused, [false, true, false, true]);
        for e in &entries {
            assert_eq!(e.source.as_deref(), Some(id.as_str()));
            assert_eq!(e.meta["task"], "T-7", "the credential's meta");
            if e.refused {
                assert_eq!(e.status, None);
                assert_eq!(e.peer, None);
                assert!(
                    e.error.as_deref().unwrap().starts_with("refused: "),
                    "{e:?}"
                );
            }
        }
        assert!(entries[1].error.as_deref().unwrap().contains("allowlist"));
        assert!(entries[3].error.as_deref().unwrap().contains("budget"));
        let view = &reg.list()[0];
        assert_eq!((view.sent, view.refused, view.remaining), (2, 2, Some(0)));
    }

    #[tokio::test]
    async fn issued_credentials_are_rate_limited_with_retry_after() {
        let (up, _) = start_header_capture_upstream().await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let reg = Arc::new(crate::clients::Registry::default());
        let rate = crate::clients::Rate {
            per_second: 0.01,
            burst: Some(1),
        };
        let (_, creds) = issue(&reg, &["*"], None, Some(rate));
        let port = start_proxy_with(dir.path(), &log, with_clients(&reg)).await;
        let target = format!("http://127.0.0.1:{up}/");
        assert_eq!(proxy_get(port, &target, &creds).await.status, 200);
        let limited = proxy_get(port, &target, &creds).await;
        assert_eq!(limited.status, 429);
        let wait: u64 = limited.headers["retry-after"]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((90..=100).contains(&wait), "{wait}");
    }

    #[tokio::test]
    async fn issued_credentials_cant_reach_the_proxy_itself() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let reg = Arc::new(crate::clients::Registry::default());
        let (_, creds) = issue(&reg, &["*"], None, None);
        let port = start_proxy_with(dir.path(), &log, with_clients(&reg)).await;
        let own = proxy_get(port, &format!("http://127.0.0.1:{port}/"), &creds).await;
        assert_eq!(own.status, 403);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let e = &logged(&log)[0];
        assert!(e.refused);
        assert!(
            e.error.as_deref().unwrap().contains("own listeners"),
            "{e:?}"
        );
    }

    #[tokio::test]
    async fn connect_to_a_host_outside_the_allowlist_is_refused_and_recorded() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let reg = Arc::new(crate::clients::Registry::default());
        let (id, creds) = issue(&reg, &["example.com"], None, None);
        let port = start_proxy_with(dir.path(), &log, with_clients(&reg)).await;
        let (status, tls) = connect_tunnel(port, "192.0.2.1:443", Some(&creds), dir.path()).await;
        assert_eq!(status, 403);
        assert!(tls.is_none());
        tokio::time::sleep(Duration::from_millis(50)).await;
        let e = &logged(&log)[0];
        assert!(e.refused);
        assert_eq!(e.method, "CONNECT");
        assert_eq!(e.host, "192.0.2.1");
        assert_eq!(e.source.as_deref(), Some(id.as_str()));
        assert_eq!(reg.list()[0].refused, 1);
    }

    #[tokio::test]
    async fn requests_inside_a_tunnel_use_the_checked_addresses_and_count() {
        // Accepts TCP and hangs up: the upstream TLS handshake fails, but
        // the connection went to the address checked at CONNECT time.
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((s, _)) = up.accept().await {
                drop(s);
            }
        });
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let reg = Arc::new(crate::clients::Registry::default());
        let (_, creds) = issue(&reg, &["127.0.0.0/8"], Some(1), None);
        let port = start_proxy_with(dir.path(), &log, with_clients(&reg)).await;
        let authority = format!("localhost:{}", up_addr.port());
        let (status, tls) = connect_tunnel(port, &authority, Some(&creds), dir.path()).await;
        assert_eq!(
            status, 200,
            "localhost is allowed through its 127.0.0.1 address"
        );
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls.unwrap()))
                .await
                .unwrap();
        tokio::spawn(conn);
        let get = || {
            Request::get("/x")
                .header("host", "localhost")
                .body(Full::new(Bytes::new()))
                .unwrap()
        };
        assert_eq!(sender.send_request(get()).await.unwrap().status(), 502);
        assert_eq!(
            sender.send_request(get()).await.unwrap().status(),
            403,
            "budget 1: counted inside the tunnel"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        let entries = logged(&log);
        assert_eq!(entries[0].peer, Some(up_addr), "never ::1");
        assert!(entries[1].refused);
    }

    #[tokio::test]
    async fn a_tunnel_keeps_the_addresses_checked_at_connect_when_the_name_rebinds() {
        let (up, _) = start_header_capture_upstream().await;
        let name = format!("rebind-{up}.test");
        let set = |ip: &str| {
            crate::upstream::TEST_DNS
                .lock()
                .unwrap()
                .insert(name.clone(), vec![ip.parse().unwrap()]);
        };
        set("127.0.0.1");
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let reg = Arc::new(crate::clients::Registry::default());
        let (_, creds) = issue(&reg, &[name.as_str()], None, None);
        let port = start_proxy_with(dir.path(), &log, with_clients(&reg)).await;
        let (status, tls) =
            connect_tunnel(port, &format!("{name}:{up}"), Some(&creds), dir.path()).await;
        assert_eq!(status, 200);
        // After the CONNECT's check, the name points somewhere else.
        set("127.0.0.2");
        let req = Request::get("/")
            .header("host", name.as_str())
            .body(Full::new(Bytes::new()))
            .unwrap();
        // The upstream speaks plain HTTP, so TLS to it fails; what matters is
        // where taphttp connected.
        request_over(tls.unwrap(), req).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let to: SocketAddr = format!("127.0.0.1:{up}").parse().unwrap();
        assert_eq!(
            logged(&log)[0].peer,
            Some(to),
            "pinned at CONNECT, not re-resolved"
        );
    }

    #[tokio::test]
    async fn revoking_closes_open_connections_and_tunnels() {
        let (up, _) = start_header_capture_upstream().await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let reg = Arc::new(crate::clients::Registry::default());
        let (id, creds) = issue(&reg, &["127.0.0.1", "localhost"], None, None);
        let port = start_proxy_with(dir.path(), &log, with_clients(&reg)).await;

        // A keep-alive connection that has made one request.
        let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                .await
                .unwrap();
        let conn = tokio::spawn(conn);
        let res = sender
            .send_request(proxied_get(
                &format!("http://127.0.0.1:{up}/"),
                Some(&creds),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        res.into_body().collect().await.unwrap();

        // And an open tunnel.
        let (status, tls) =
            connect_tunnel(port, &format!("localhost:{up}"), Some(&creds), dir.path()).await;
        assert_eq!(status, 200);
        let mut tls = tls.unwrap();

        assert!(reg.revoke(&id));
        tokio::time::timeout(Duration::from_secs(2), conn)
            .await
            .expect("the keep-alive connection is closed")
            .unwrap()
            .ok();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buf))
            .await
            .expect("the tunnel is closed");
        assert!(matches!(n, Ok(0) | Err(_)), "{n:?}");
        assert_eq!(
            proxy_get(port, &format!("http://127.0.0.1:{up}/"), &creds)
                .await
                .status,
            407,
            "revoked credentials no longer authenticate"
        );
    }

    #[tokio::test]
    async fn proxy_auth_api_requires_an_issued_credential() {
        let (up, _) = start_header_capture_upstream().await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let reg = Arc::new(crate::clients::Registry::default());
        let (_, creds) = issue(&reg, &["*"], None, None);
        let port = start_proxy_with(
            dir.path(),
            &log,
            ProxyConfig {
                require_client: true,
                ..with_clients(&reg)
            },
        )
        .await;
        let target = format!("http://127.0.0.1:{up}/");
        let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        assert_eq!(
            request_over(stream, proxied_get(&target, None))
                .await
                .0
                .status,
            407
        );
        assert_eq!(
            proxy_get(port, &target, "self-labelled:x").await.status,
            407
        );
        assert_eq!(proxy_get(port, &target, &creds).await.status, 200);
    }

    #[tokio::test]
    async fn without_require_client_other_users_keep_the_old_behaviour() {
        let (up, _) = start_header_capture_upstream().await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let reg = Arc::new(crate::clients::Registry::default());
        let port = start_proxy_with(dir.path(), &log, with_clients(&reg)).await;
        let target = format!("http://127.0.0.1:{up}/");
        assert_eq!(proxy_get(port, &target, "agent.T-3:x").await.status, 200);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let e = &logged(&log)[0];
        assert_eq!(
            e.source.as_deref(),
            Some("agent.T-3"),
            "self-reported label"
        );
        assert!(e.meta.is_empty() && !e.refused);
    }

    #[tokio::test]
    async fn client_outside_allowlist_is_disconnected() {
        let (up, seen) = start_header_capture_upstream().await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let allow = vec!["10.0.0.0/8".parse().unwrap()];
        let port = start_proxy_with(
            dir.path(),
            &log,
            ProxyConfig {
                allow_clients: allow,
                ..Default::default()
            },
        )
        .await;

        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let req = format!("GET http://127.0.0.1:{up}/ HTTP/1.1\r\nHost: x\r\n\r\n");
        let _ = stream.write_all(req.as_bytes()).await;
        let mut buf = Vec::new();
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf))
            .await
            .unwrap()
            .unwrap_or(0);
        assert_eq!(n, 0, "closed without a response");
        assert!(seen.lock().await.is_empty());

        // 127.0.0.1 allowed: works.
        let ok = start_proxy_with(
            dir.path(),
            &log,
            ProxyConfig {
                allow_clients: vec!["127.0.0.0/8".parse().unwrap()],
                ..Default::default()
            },
        )
        .await;
        let stream = TcpStream::connect(format!("127.0.0.1:{ok}")).await.unwrap();
        assert_eq!(
            request_over(
                stream,
                proxied_get(&format!("http://127.0.0.1:{up}/"), None)
            )
            .await
            .0
            .status,
            200
        );
    }

    #[tokio::test]
    async fn requests_after_expiry_are_refused() {
        let (up, seen) = start_header_capture_upstream().await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let expires = Timestamp::now().checked_add_secs(-1);
        let port = start_proxy_with(
            dir.path(),
            &log,
            ProxyConfig {
                expires,
                ..Default::default()
            },
        )
        .await;
        let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let (parts, body) = request_over(
            stream,
            proxied_get(&format!("http://127.0.0.1:{up}/"), None),
        )
        .await;
        assert_eq!(parts.status, 503);
        assert!(String::from_utf8_lossy(&body).contains("expired"));
        assert!(seen.lock().await.is_empty());
        assert_eq!(
            connect_tunnel(port, "localhost:9", None, dir.path())
                .await
                .0,
            503
        );
    }

    #[tokio::test]
    async fn tls_proxy_listener_serves_trusting_clients_and_rejects_plaintext() {
        let (up, seen) = start_header_capture_upstream().await;
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("t.jsonl");
        let ca = Ca::load_or_create(dir.path()).unwrap();
        let tls = Some(ca.listener_tls_config(&["127.0.0.1".into()]).unwrap());
        let port = start_proxy_with(
            dir.path(),
            &log,
            ProxyConfig {
                tls,
                credentials: creds("you:pw"),
                ..Default::default()
            },
        )
        .await;

        let tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
        let stream = tls_connector(dir.path())
            .connect(name, tcp)
            .await
            .expect("listener cert chains to ca.crt");
        let (parts, body) = request_over(
            stream,
            proxied_get(&format!("http://127.0.0.1:{up}/"), Some("you:pw")),
        )
        .await;
        assert_eq!((parts.status.as_u16(), body.as_ref()), (200, &b"ok"[..]));
        assert_eq!(seen.lock().await.len(), 1);

        // A plaintext client gets no HTTP response from a TLS listener.
        let mut plain = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        plain
            .write_all(format!("GET http://127.0.0.1:{up}/ HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), plain.read_to_end(&mut buf)).await;
        assert!(!String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 200"));
        assert_eq!(
            seen.lock().await.len(),
            1,
            "plaintext request never forwarded"
        );
    }

    #[test]
    fn tls_names_include_specific_listener_ips_and_require_one_for_wildcards() {
        let a: SocketAddr = "10.0.0.5:8443".parse().unwrap();
        let any: SocketAddr = "0.0.0.0:8443".parse().unwrap();
        assert_eq!(tls_names(&[], &[Some(a)]).unwrap(), ["10.0.0.5"]);
        assert_eq!(
            tls_names(&["proxy.lan".into()], &[Some(any), Some(a)]).unwrap(),
            ["10.0.0.5", "proxy.lan"]
        );
        let err = tls_names(&[], &[Some(any), None]).unwrap_err().to_string();
        assert!(err.contains("--tls-name"), "{err}");
    }

    #[tokio::test]
    async fn http_proxy_filter_host_skips_unmatched() {
        let echo_port = start_echo_server().await;
        let dir = TempDir::new().unwrap();
        let log_file = dir.path().join("traffic.jsonl");

        let ca = Arc::new(Ca::load_or_create(dir.path()).unwrap());
        let store = Store::new(Some(&log_file), None).unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let config = ProxyConfig {
            filter_host: Some("only-this-host.example".to_string()),
            ..Default::default()
        };
        tokio::spawn(serve(proxy_listener, ca, store, config));
        tokio::time::sleep(Duration::from_millis(20)).await;

        send_http_through_proxy(proxy_port, echo_port, "/nolog").await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !log_file.exists(),
            "log file should not exist when filter doesn't match"
        );
    }

    // --- intercept integration tests ---

    #[tokio::test]
    async fn intercept_request_drop_returns_configured_status() {
        let echo_port = start_echo_server().await;
        let dir = TempDir::new().unwrap();
        let log_file = dir.path().join("traffic.jsonl");
        let socket_path = dir.path().join("intercept.sock");

        // Decision: drop the request before it reaches the server
        start_mock_interceptor(
            socket_path.clone(),
            vec![r#"{"action":"drop","status":403}"#],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        let proxy_port = start_proxy(dir.path(), &log_file, Some(socket_path)).await;
        let response = send_http_through_proxy(proxy_port, echo_port, "/secret").await;

        assert!(
            response.starts_with("HTTP/1.1 403"),
            "expected 403 from drop, got: {response}"
        );
        // Nothing should reach the echo server, so no 200 log entry
        tokio::time::sleep(Duration::from_millis(50)).await;
        if log_file.exists() {
            let content = std::fs::read_to_string(&log_file).unwrap();
            let entry: TrafficEntry =
                serde_json::from_str(content.lines().next().unwrap()).unwrap();
            // If logged, status must NOT be 200 (request was dropped before upstream)
            assert_ne!(entry.status, Some(200));
        }
    }

    #[tokio::test]
    async fn intercept_response_drop_returns_configured_status() {
        let echo_port = start_echo_server().await;
        let dir = TempDir::new().unwrap();
        let log_file = dir.path().join("traffic.jsonl");
        let socket_path = dir.path().join("intercept.sock");

        // Two events: forward the request, drop the response
        start_mock_interceptor(
            socket_path.clone(),
            vec![
                r#"{"action":"forward"}"#,
                r#"{"action":"drop","status":502,"body":"blocked"}"#,
            ],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        let proxy_port = start_proxy(dir.path(), &log_file, Some(socket_path)).await;
        let response = send_http_through_proxy(proxy_port, echo_port, "/anything").await;

        assert!(
            response.starts_with("HTTP/1.1 502"),
            "expected 502 from dropped response, got: {response}"
        );
        assert!(response.ends_with("blocked"), "expected body 'blocked'");
    }

    #[tokio::test]
    async fn intercept_request_forward_reaches_upstream() {
        let echo_port = start_echo_server().await;
        let dir = TempDir::new().unwrap();
        let log_file = dir.path().join("traffic.jsonl");
        let socket_path = dir.path().join("intercept.sock");

        // Forward request, forward response
        start_mock_interceptor(
            socket_path.clone(),
            vec![r#"{"action":"forward"}"#, r#"{"action":"forward"}"#],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        let proxy_port = start_proxy(dir.path(), &log_file, Some(socket_path)).await;
        let response = send_http_through_proxy(proxy_port, echo_port, "/pass").await;

        assert!(
            response.starts_with("HTTP/1.1 200"),
            "expected 200, got: {response}"
        );
    }

    #[tokio::test]
    async fn intercept_response_body_modification_reaches_client() {
        let echo_port = start_echo_server().await;
        let dir = TempDir::new().unwrap();
        let log_file = dir.path().join("traffic.jsonl");
        let socket_path = dir.path().join("intercept.sock");

        start_mock_interceptor(
            socket_path.clone(),
            vec![
                r#"{"action":"forward"}"#,
                r#"{"action":"forward","body":"injected-body"}"#,
            ],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        let proxy_port = start_proxy(dir.path(), &log_file, Some(socket_path)).await;
        let response = send_http_through_proxy(proxy_port, echo_port, "/modify").await;

        assert!(
            response.contains("injected-body"),
            "expected injected body in response, got: {response}"
        );
    }
}
