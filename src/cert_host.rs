//! `http://taphttp/`: a hostname the proxy answers itself, so a client
//! already pointed at the proxy (a phone, a VM) can fetch the CA
//! certificate without reaching the lever API. Plain HTTP only: until the
//! CA is installed, a client can't trust anything taphttp serves over TLS.

use anyhow::Result;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Response, Uri};

use crate::ca::{self, CaCert};

/// The magic hostname, matched case-insensitively on any port.
pub const HOST: &str = "taphttp";

/// Whether a proxied request is addressed to [`HOST`] rather than an
/// upstream. Only absolute-form URIs (`GET http://taphttp/ HTTP/1.1`, what a
/// client sends its proxy) have a host here.
pub fn is_cert_host(uri: &Uri) -> bool {
    uri.host().is_some_and(|h| h.eq_ignore_ascii_case(HOST))
}

/// Answer a request for [`HOST`]: `/` is a short page linking to the
/// certificate, `/ca.pem` and `/ca.der` are the certificate itself.
pub fn respond(
    method: &Method,
    path: &str,
    cert: &CaCert,
    pin: &str,
) -> Result<Response<Full<Bytes>>> {
    if method != Method::GET && method != Method::HEAD {
        return Ok(Response::builder()
            .status(405)
            .header(hyper::header::ALLOW, "GET, HEAD")
            .body(Full::new(Bytes::new()))?);
    }
    let (content_type, filename, body) = match path {
        "/" => {
            return Ok(Response::builder()
                .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
                .body(Full::new(Bytes::from(index(pin))))?)
        }
        "/ca.pem" => (
            ca::PEM_CONTENT_TYPE,
            ca::PEM_FILENAME,
            cert.pem.clone().into_bytes(),
        ),
        "/ca.der" => (ca::DER_CONTENT_TYPE, ca::DER_FILENAME, cert.der.clone()),
        _ => {
            return Ok(Response::builder()
                .status(404)
                .body(Full::new(Bytes::from_static(b"not found")))?)
        }
    };
    Ok(Response::builder()
        .header(hyper::header::CONTENT_TYPE, content_type)
        .header(
            hyper::header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(Full::new(Bytes::from(body)))?)
}

/// Two links and the pin to check the download against. `pin` is
/// [`ca::Ca::fingerprint_sha256`]: hex and colons, nothing to escape.
fn index(pin: &str) -> String {
    format!(
        r#"<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>taphttp CA certificate</title>
<h1>taphttp CA certificate</h1>
<p>Install this certificate to let taphttp intercept HTTPS from this device.
Only do this on a device you are testing with.</p>
<ul>
<li><a href="/ca.pem">ca.pem</a> (most browsers and systems)</li>
<li><a href="/ca.der">ca.der</a> (Android, some Windows dialogs)</li>
</ul>
<p>SHA-256: <code>{pin}</code></p>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert() -> CaCert {
        CaCert {
            pem: "-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n".into(),
            der: vec![0, 1, 2, 0xff],
        }
    }

    fn get(path: &str) -> Response<Full<Bytes>> {
        respond(&Method::GET, path, &cert(), "AB:CD:EF").unwrap()
    }

    async fn body(resp: Response<Full<Bytes>>) -> Vec<u8> {
        use http_body_util::BodyExt;
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec()
    }

    #[test]
    fn matches_only_the_magic_host() {
        for yes in [
            "http://taphttp/",
            "http://TapHTTP/ca.pem",
            "http://taphttp:80/ca.der",
            "http://taphttp:8080/",
        ] {
            assert!(is_cert_host(&yes.parse().unwrap()), "{yes}");
        }
        for no in [
            "http://taphttp.example/",
            "http://example.taphttp/",
            "http://example.com/taphttp",
            "http://127.0.0.1/",
            "/ca.pem",
        ] {
            assert!(!is_cert_host(&no.parse().unwrap()), "{no}");
        }
    }

    #[tokio::test]
    async fn serves_the_certificate_as_pem_and_der() {
        let c = cert();
        for (path, ctype, file, want) in [
            (
                "/ca.pem",
                ca::PEM_CONTENT_TYPE,
                ca::PEM_FILENAME,
                c.pem.clone().into_bytes(),
            ),
            (
                "/ca.der",
                ca::DER_CONTENT_TYPE,
                ca::DER_FILENAME,
                c.der.clone(),
            ),
        ] {
            let resp = get(path);
            assert_eq!(resp.status(), 200, "{path}");
            assert_eq!(resp.headers()["content-type"], ctype);
            assert_eq!(
                resp.headers()["content-disposition"],
                format!("attachment; filename=\"{file}\"").as_str()
            );
            assert_eq!(body(resp).await, want, "{path}");
        }
    }

    #[tokio::test]
    async fn index_links_to_both_and_shows_the_pin() {
        let resp = get("/");
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers()["content-type"], "text/html; charset=utf-8");
        let html = String::from_utf8(body(resp).await).unwrap();
        for needle in [r#"href="/ca.pem""#, r#"href="/ca.der""#, "AB:CD:EF"] {
            assert!(html.contains(needle), "{needle} missing:\n{html}");
        }
    }

    #[tokio::test]
    async fn other_paths_404_and_other_methods_405() {
        assert_eq!(get("/ca.key").status(), 404);
        assert_eq!(get("/index.html").status(), 404);
        let head = respond(&Method::HEAD, "/ca.pem", &cert(), "x").unwrap();
        assert_eq!(head.status(), 200, "HEAD is fine");
        for m in [Method::POST, Method::PUT, Method::DELETE] {
            let resp = respond(&m, "/ca.pem", &cert(), "x").unwrap();
            assert_eq!(resp.status(), 405, "{m}");
            assert_eq!(resp.headers()["allow"], "GET, HEAD");
        }
    }
}
