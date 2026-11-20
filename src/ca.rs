use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa,
    KeyPair,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;
use crate::cli::{CaArgs, CaAction};

pub struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
    cert_cache: Mutex<HashMap<String, Arc<rustls::ServerConfig>>>,
}

impl Ca {
    pub fn load_or_create(data_dir: &Path) -> Result<Self> {
        let cert_path = data_dir.join("ca.crt");
        let key_path = data_dir.join("ca.key");

        if cert_path.exists() && key_path.exists() {
            let key_pem = std::fs::read_to_string(&key_path)
                .context("reading CA key")?;
            let cert_pem = std::fs::read_to_string(&cert_path)
                .context("reading CA cert")?;
            let key = KeyPair::from_pem(&key_pem).context("parsing CA key")?;
            let params = CertificateParams::from_ca_cert_pem(&cert_pem)
                .context("parsing CA cert params")?;
            let cert = params.self_signed(&key).context("re-signing CA cert")?;
            tracing::debug!("Loaded existing CA from {}", data_dir.display());
            return Ok(Self {
                cert,
                key,
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
        std::fs::write(&key_path, key.serialize_pem()).context("writing CA key")?;

        tracing::info!("Generated new CA cert at {}", cert_path.display());
        eprintln!(
            "taphttp: generated CA cert at {}\nInstall it as a trusted root to intercept HTTPS traffic.",
            cert_path.display()
        );

        Ok(Self {
            cert,
            key,
            cert_cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn cert_pem(&self) -> String {
        self.cert.pem()
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
        let mut params = CertificateParams::new(vec![host.to_string()])
            .context("building leaf cert params")?;
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);
        let leaf = params
            .signed_by(&key, &self.cert, &self.key)
            .context("signing leaf cert")?;

        let cert_der = CertificateDer::from(leaf.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            key.serialize_der(),
        ));

        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .context("building rustls ServerConfig")?;

        let cfg = Arc::new(server_cfg);
        cache.insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }
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
        assert_eq!(mtime, mtime2, "ca.crt should not be regenerated on second load");
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

