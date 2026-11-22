use crate::cli::{CaAction, CaArgs};
use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

/// What anyone may know about the CA: the public certificate's subject,
/// pin and validity. Nothing derived from the key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CaPublicInfo {
    /// The subject DN, e.g. `CN=taphttp local CA, O=taphttp`.
    pub subject: String,
    /// [`Ca::fingerprint_sha256`], as the startup banner shows it.
    pub sha256: String,
    pub not_before: taphttp_types::Timestamp,
    pub not_after: taphttp_types::Timestamp,
}

/// How the certificate is served for download, by the lever API and by
/// `http://taphttp/`.
pub const PEM_CONTENT_TYPE: &str = "application/x-pem-file";
pub const PEM_FILENAME: &str = "taphttp-ca.pem";
pub const DER_CONTENT_TYPE: &str = "application/x-x509-ca-cert";
pub const DER_FILENAME: &str = "taphttp-ca.der";

/// The CA's public certificate, for clients to install: what `GET /ca.pem`
/// and `GET /ca.der` serve. Only the certificate whose pin is
/// [`Ca::fingerprint_sha256`]; never the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaCert {
    /// One `CERTIFICATE` block, LF line endings, built from `der`.
    pub pem: String,
    pub der: Vec<u8>,
}

pub struct Ca {
    /// Signs leaves: the CA's subject and key identifier, read from ca.crt,
    /// plus its private key.
    issuer: Issuer<'static, KeyPair>,
    /// `ca.crt` as on disk: what clients trust and pin.
    disk_pem: String,
    disk_der: Vec<u8>,
    cert_cache: Mutex<HashMap<String, Arc<rustls::ServerConfig>>>,
}

impl Ca {
    pub fn load_or_create(data_dir: &Path) -> Result<Self> {
        let cert_path = data_dir.join("ca.crt");
        let key_path = data_dir.join("ca.key");

        if cert_path.exists() && key_path.exists() {
            let key_pem = std::fs::read_to_string(&key_path).context("reading CA key")?;
            let cert_pem = std::fs::read_to_string(&cert_path).context("reading CA cert")?;
            let key = KeyPair::from_pem(&key_pem).context("parsing CA key")?;
            // Older versions wrote the key world-readable; tighten it.
            if let Err(e) = restrict_to_owner(&key_path) {
                tracing::warn!(
                    "could not make {} owner-only ({e}); run `chmod 600` on it",
                    key_path.display()
                );
            }
            let disk_der = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                .next()
                .context("no certificate in ca.crt")?
                .context("parsing ca.crt")?;
            let issuer = Issuer::from_ca_cert_der(&disk_der, key).context("parsing CA cert")?;
            tracing::debug!("Loaded existing CA from {}", data_dir.display());
            return Ok(Self {
                issuer,
                disk_pem: cert_pem,
                disk_der: disk_der.to_vec(),
                cert_cache: Mutex::new(HashMap::new()),
            });
        }

        let key = KeyPair::generate().context("generating CA key")?;
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "taphttp local CA");
        dn.push(DnType::OrganizationName, "taphttp");
        params.distinguished_name = dn;
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);

        let cert = params.self_signed(&key).context("generating CA cert")?;

        std::fs::write(&cert_path, cert.pem()).context("writing CA cert")?;
        write_private(&key_path, key.serialize_pem().as_bytes()).context("writing CA key")?;

        tracing::info!("Generated new CA cert at {}", cert_path.display());
        eprintln!(
            "taphttp: generated CA cert at {}\nInstall it as a trusted root to intercept HTTPS traffic.",
            cert_path.display()
        );

        Ok(Self {
            disk_pem: cert.pem(),
            disk_der: cert.der().to_vec(),
            issuer: Issuer::new(params, key),
            cert_cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn cert_pem(&self) -> String {
        self.disk_pem.clone()
    }

    /// The certificate alone. The PEM is re-encoded from the parsed DER, not
    /// copied from ca.crt, so nothing else in that file can come along.
    pub fn public_cert(&self) -> CaCert {
        CaCert {
            pem: pem::encode_config(
                &pem::Pem::new("CERTIFICATE", self.disk_der.clone()),
                pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
            ),
            der: self.disk_der.clone(),
        }
    }

    /// SHA-256 of the CA certificate, `AB:CD:...`, for pinning.
    pub fn fingerprint_sha256(&self) -> String {
        let digest = ring::digest::digest(&ring::digest::SHA256, &self.disk_der);
        digest
            .as_ref()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// The public details of `ca.crt`, read from the certificate itself.
    pub fn public_info(&self) -> Result<CaPublicInfo> {
        let (_, cert) = x509_parser::parse_x509_certificate(&self.disk_der)
            .map_err(|e| anyhow::anyhow!("parsing ca.crt: {e}"))?;
        let time = |t: x509_parser::time::ASN1Time| {
            t.timestamp()
                .checked_mul(1_000_000)
                .and_then(taphttp_types::Timestamp::from_unix_micros)
                .context("ca.crt validity is out of range")
        };
        let validity = cert.validity();
        Ok(CaPublicInfo {
            subject: cert.subject().to_string(),
            sha256: self.fingerprint_sha256(),
            not_before: time(validity.not_before)?,
            not_after: time(validity.not_after)?,
        })
    }

    /// TLS config for taphttp's own listeners (the HTTPS proxy, the lever
    /// API): a fresh leaf for `names` (DNS names or IPs), signed by this CA,
    /// so a client that trusts the CA (as it must, to be intercepted)
    /// trusts the listener too. HTTP/1.1 only.
    pub fn listener_tls_config(&self, names: &[String]) -> Result<Arc<rustls::ServerConfig>> {
        let (chain, key_der) = self.listener_chain(names)?;
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key_der)
            .context("building listener TLS config")?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(cfg))
    }

    /// The leaf + CA chain and key a listener serves.
    fn listener_chain(
        &self,
        names: &[String],
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let key = KeyPair::generate().context("generating listener key")?;
        let mut params =
            CertificateParams::new(names.to_vec()).context("building listener cert params")?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "taphttp listener");
        params.distinguished_name = dn;
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);
        let leaf = params
            .signed_by(&key, &self.issuer)
            .context("signing listener cert")?;
        let chain = vec![
            CertificateDer::from(leaf.der().to_vec()),
            CertificateDer::from(self.disk_der.clone()),
        ];
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        Ok((chain, key_der))
    }

    pub fn cert_path(data_dir: &Path) -> PathBuf {
        data_dir.join("ca.crt")
    }

    pub async fn server_config_for(&self, host: &str) -> Result<Arc<rustls::ServerConfig>> {
        let mut cache = self.cert_cache.lock().await;
        if let Some(cfg) = cache.get(host) {
            return Ok(cfg.clone());
        }

        let key = KeyPair::generate().context("generating leaf key")?;
        let mut params =
            CertificateParams::new(vec![host.to_string()]).context("building leaf cert params")?;
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);
        let leaf = params
            .signed_by(&key, &self.issuer)
            .context("signing leaf cert")?;

        let cert_der = CertificateDer::from(leaf.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .context("building rustls ServerConfig")?;

        let cfg = Arc::new(server_cfg);
        cache.insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }
}

/// Write `contents` to a new file readable only by its owner. The mode is set
/// at creation, so the key is never briefly world-readable.
fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(contents)?;
    // `mode` applies only when the file is created; cover a pre-existing one.
    restrict_to_owner(path)
}

fn restrict_to_owner(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub async fn manage(args: CaArgs, data_dir: PathBuf) -> Result<()> {
    match args.action {
        CaAction::Info => {
            let path = Ca::cert_path(&data_dir);
            println!("CA cert: {}", path.display());
            println!();
            println!("Install instructions:");
            println!(
                "  Linux (system): sudo cp {} /usr/local/share/ca-certificates/taphttp.crt && sudo update-ca-certificates",
                path.display()
            );
            println!(
                "  macOS:          sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {}",
                path.display()
            );
            println!(
                "  Firefox:        Settings → Privacy → Certificates → Import → {}",
                path.display()
            );
        }
        CaAction::Print => {
            let ca = Ca::load_or_create(&data_dir)?;
            print!("{}", ca.cert_pem());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn install_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn creates_ca_files_on_first_run() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        Ca::load_or_create(&path).unwrap();
        assert!(path.join("ca.crt").exists(), "ca.crt should be written");
        assert!(path.join("ca.key").exists(), "ca.key should be written");
    }

    /// `taphttp ca print` must emit the certificate clients actually trust
    /// (ca.crt), byte for byte, so its fingerprint matches the banner's.
    #[test]
    fn printed_ca_cert_is_exactly_ca_crt_on_create_and_on_reload() {
        let dir = TempDir::new().unwrap();
        let on_disk = || std::fs::read_to_string(dir.path().join("ca.crt")).unwrap();
        let created = Ca::load_or_create(dir.path()).unwrap();
        assert_eq!(created.cert_pem(), on_disk());
        let reloaded = Ca::load_or_create(dir.path()).unwrap();
        assert_eq!(reloaded.cert_pem(), on_disk());
    }

    #[cfg(unix)]
    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn new_ca_key_is_owner_only() {
        let dir = TempDir::new().unwrap();
        Ca::load_or_create(dir.path()).unwrap();
        assert_eq!(
            mode(&dir.path().join("ca.key")),
            0o600,
            "CA private key must be owner-only"
        );
    }

    #[cfg(unix)]
    #[test]
    fn existing_world_readable_ca_key_is_tightened_on_load() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        Ca::load_or_create(dir.path()).unwrap();
        let key = dir.path().join("ca.key");
        // What older taphttp versions left on disk.
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        Ca::load_or_create(dir.path()).unwrap();
        assert_eq!(mode(&key), 0o600);
    }

    #[test]
    fn fingerprint_is_stable_across_loads_and_matches_ca_crt() {
        let dir = TempDir::new().unwrap();
        let a = Ca::load_or_create(dir.path()).unwrap().fingerprint_sha256();
        let b = Ca::load_or_create(dir.path()).unwrap().fingerprint_sha256();
        assert_eq!(a, b, "a pin must survive restarts");
        assert_eq!(a.len(), 32 * 3 - 1);
        let pem = std::fs::read_to_string(dir.path().join("ca.crt")).unwrap();
        let der = CertificateDer::pem_slice_iter(pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        let want = ring::digest::digest(&ring::digest::SHA256, &der);
        assert!(a.starts_with(&format!("{:02X}:", want.as_ref()[0])));
    }

    #[test]
    fn public_info_describes_a_generated_ca() {
        let dir = TempDir::new().unwrap();
        let ca = Ca::load_or_create(dir.path()).unwrap();
        let info = ca.public_info().unwrap();
        assert_eq!(info.subject, "CN=taphttp local CA, O=taphttp");
        assert_eq!(info.sha256, ca.fingerprint_sha256());
        assert_eq!(info.not_before.to_string(), "2024-01-01T00:00:00Z");
        assert_eq!(info.not_after.to_string(), "2035-01-01T00:00:00Z");
    }

    #[test]
    fn public_cert_is_the_pinned_certificate_and_nothing_else() {
        let dir = TempDir::new().unwrap();
        Ca::load_or_create(dir.path()).unwrap();
        // Someone appends the key to ca.crt: the served PEM must still carry
        // only the certificate.
        let key = std::fs::read_to_string(dir.path().join("ca.key")).unwrap();
        let crt = dir.path().join("ca.crt");
        let mut on_disk = std::fs::read_to_string(&crt).unwrap();
        on_disk.push_str(&key);
        std::fs::write(&crt, &on_disk).unwrap();

        let ca = Ca::load_or_create(dir.path()).unwrap();
        let cert = ca.public_cert();
        let parsed: Vec<_> = CertificateDer::pem_slice_iter(cert.pem.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].as_ref(), cert.der.as_slice());
        assert_eq!(cert.pem.matches("-----BEGIN").count(), 1, "{}", cert.pem);
        assert!(cert.pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(!cert.pem.contains("PRIVATE") && !cert.pem.contains('\r'));
        let digest = ring::digest::digest(&ring::digest::SHA256, &cert.der);
        let hex: Vec<String> = digest.as_ref().iter().map(|b| format!("{b:02X}")).collect();
        assert_eq!(hex.join(":"), ca.fingerprint_sha256(), "same pin as /info");
    }

    #[test]
    fn public_info_is_read_from_ca_crt_not_assumed() {
        // A CA taphttp didn't make: other subject, other dates.
        let dir = TempDir::new().unwrap();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, "Acme Test");
        dn.push(DnType::CommonName, "Acme Interception CA");
        params.distinguished_name = dn;
        params.not_before = rcgen::date_time_ymd(2025, 3, 4);
        params.not_after = rcgen::date_time_ymd(2030, 5, 6);
        let cert = params.self_signed(&key).unwrap();
        std::fs::write(dir.path().join("ca.crt"), cert.pem()).unwrap();
        std::fs::write(dir.path().join("ca.key"), key.serialize_pem()).unwrap();

        let ca = Ca::load_or_create(dir.path()).unwrap();
        let info = ca.public_info().unwrap();
        assert_eq!(info.subject, "O=Acme Test, CN=Acme Interception CA");
        assert_eq!(info.not_before.to_string(), "2025-03-04T00:00:00Z");
        assert_eq!(info.not_after.to_string(), "2030-05-06T00:00:00Z");
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("PRIVATE"), "{json}");
    }

    /// A leaf for `name` from `ca`, checked by a client that trusts only
    /// the ca.crt in `dir`.
    fn verify_leaf_against_ca_crt(ca: &Ca, dir: &Path, name: &str) -> Result<(), rustls::Error> {
        let pem = std::fs::read_to_string(dir.join("ca.crt")).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for c in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        use rustls::client::danger::ServerCertVerifier;
        let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let (chain, _) = ca.listener_chain(&[name.to_string()]).unwrap();
        verifier
            .verify_server_cert(
                &chain[0],
                &chain[1..],
                &rustls::pki_types::ServerName::try_from(name.to_string()).unwrap(),
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .map(|_| ())
    }

    /// Existing installs reload their CA from disk: leaves signed after a
    /// reload must still chain to the ca.crt clients already trust.
    #[test]
    fn leaves_signed_by_a_reloaded_ca_verify_against_ca_crt() {
        install_crypto_provider();
        let dir = TempDir::new().unwrap();
        drop(Ca::load_or_create(dir.path()).unwrap());
        let reloaded = Ca::load_or_create(dir.path()).unwrap();
        verify_leaf_against_ca_crt(&reloaded, dir.path(), "app.example")
            .unwrap_or_else(|e| panic!("reloaded CA leaf rejected: {e}"));
    }

    /// And a different CA's leaves must not verify (the check has teeth).
    #[test]
    fn leaves_from_another_ca_do_not_verify() {
        install_crypto_provider();
        let ours = TempDir::new().unwrap();
        let theirs = TempDir::new().unwrap();
        Ca::load_or_create(ours.path()).unwrap();
        let other = Ca::load_or_create(theirs.path()).unwrap();
        assert!(verify_leaf_against_ca_crt(&other, ours.path(), "app.example").is_err());
    }

    #[test]
    fn listener_tls_config_verifies_against_ca_crt_for_its_names() {
        install_crypto_provider();
        let dir = TempDir::new().unwrap();
        let ca = Ca::load_or_create(dir.path()).unwrap();
        let cfg = ca
            .listener_tls_config(&["proxy.example".into(), "10.0.0.5".into()])
            .unwrap();
        assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);

        // Verify the served leaf with a client that trusts only ca.crt.
        let pem = std::fs::read_to_string(dir.path().join("ca.crt")).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for c in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        use rustls::client::danger::ServerCertVerifier;
        let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let (chain, _) = ca
            .listener_chain(&["proxy.example".into(), "10.0.0.5".into()])
            .unwrap();
        for name in ["proxy.example", "10.0.0.5"] {
            let sn = rustls::pki_types::ServerName::try_from(name).unwrap();
            verifier
                .verify_server_cert(
                    &chain[0],
                    &chain[1..],
                    &sn,
                    &[],
                    rustls::pki_types::UnixTime::now(),
                )
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        let wrong = rustls::pki_types::ServerName::try_from("other.example").unwrap();
        assert!(verifier
            .verify_server_cert(
                &chain[0],
                &chain[1..],
                &wrong,
                &[],
                rustls::pki_types::UnixTime::now()
            )
            .is_err());
    }

    #[test]
    fn loads_existing_ca_without_regenerating() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        Ca::load_or_create(&path).unwrap();
        let mtime = std::fs::metadata(path.join("ca.crt"))
            .unwrap()
            .modified()
            .unwrap();
        // Second call must not overwrite the cert
        Ca::load_or_create(&path).unwrap();
        let mtime2 = std::fs::metadata(path.join("ca.crt"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(
            mtime, mtime2,
            "ca.crt should not be regenerated on second load"
        );
    }

    #[test]
    fn cert_path_points_inside_data_dir() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        assert_eq!(Ca::cert_path(&path), path.join("ca.crt"));
    }

    #[tokio::test]
    async fn server_config_caches_cert_for_same_host() {
        install_crypto_provider();
        let dir = TempDir::new().unwrap();
        let ca = Ca::load_or_create(dir.path()).unwrap();
        let cfg1 = ca.server_config_for("example.com").await.unwrap();
        let cfg2 = ca.server_config_for("example.com").await.unwrap();
        assert!(
            Arc::ptr_eq(&cfg1, &cfg2),
            "same host should return the same cached Arc"
        );
    }

    #[tokio::test]
    async fn server_config_different_for_different_hosts() {
        install_crypto_provider();
        let dir = TempDir::new().unwrap();
        let ca = Ca::load_or_create(dir.path()).unwrap();
        let cfg1 = ca.server_config_for("alpha.com").await.unwrap();
        let cfg2 = ca.server_config_for("beta.com").await.unwrap();
        assert!(
            !Arc::ptr_eq(&cfg1, &cfg2),
            "different hosts should get different server configs"
        );
    }

    #[test]
    fn cert_pem_is_valid_pem() {
        let dir = TempDir::new().unwrap();
        let ca = Ca::load_or_create(dir.path()).unwrap();
        let pem = ca.cert_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.trim_end().ends_with("-----END CERTIFICATE-----"));
    }
}
