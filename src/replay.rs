use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::ClientConfig;
use std::path::PathBuf;
use crate::cli::ReplayArgs;
use crate::storage;

pub async fn run(args: ReplayArgs, data_dir: PathBuf) -> Result<()> {
    let mut entry = storage::load_entry(&data_dir, &args.id)?;

    if let Some(method) = args.method {
        entry.method = method.to_uppercase();
    }

    for kv in &args.headers {
        let (k, v) = kv.split_once(':').context("header must be key:value")?;
        entry.req_headers.insert(k.trim().to_string(), v.trim().to_string());
    }

    if let Some(body) = args.body {
        entry.req_body = Some(body);
    }

    let method = hyper::Method::from_bytes(entry.method.as_bytes())
        .context("invalid method")?;

    let uri: hyper::Uri = entry.url.parse().context("invalid url")?;

    let body_bytes = entry
        .req_body
        .map(|b| Bytes::from(b.into_bytes()))
        .unwrap_or_default();

    let mut builder = Request::builder()
        .method(method)
        .uri(uri.clone());

    for (k, v) in &entry.req_headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    let req = builder
        .body(Full::new(body_bytes))
        .context("building request")?;

    eprintln!("Replaying {} {}", entry.method, entry.url);

    let scheme = uri.scheme_str().unwrap_or("http");

    let res = if scheme == "https" {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .build();
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);
        client.request(req).await.context("sending request")?
    } else {
        let http = hyper_util::client::legacy::connect::HttpConnector::new();
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(http);
        client.request(req).await.context("sending request")?
    };

    let status = res.status();
    eprintln!("Status: {}", status);

    for (k, v) in res.headers() {
        eprintln!("{}: {}", k, v.to_str().unwrap_or("?"));
    }
    eprintln!();

    let body = res.into_body().collect().await?.to_bytes();
    println!("{}", String::from_utf8_lossy(&body));

    Ok(())
}
