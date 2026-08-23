//! TLS material for the SMTP and HTTPS listeners.
//!
//! The certificate is held behind a [`CertStore`] that implements rustls'
//! [`ResolvesServerCert`], so a renewed certificate can be swapped in at
//! runtime without rebuilding the [`ServerConfig`] or restarting listeners.
//! Existing connections keep the certificate they handshook with; every new
//! one picks up the fresh material.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

/// Where the certificate came from, for display in the admin UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertSource {
    SelfSigned,
    Acme,
    /// Dropped in by the operator (or an unrecognised issuer).
    External,
}

impl CertSource {
    pub fn label(self) -> &'static str {
        match self {
            CertSource::SelfSigned => "self-signed",
            CertSource::Acme => "Let's Encrypt / ACME",
            CertSource::External => "external",
        }
    }
}

/// What the admin UI shows about the certificate currently in use.
#[derive(Debug, Clone)]
pub struct CertInfo {
    pub source: CertSource,
    pub issuer: String,
    /// DNS names the certificate is valid for (SANs, falling back to the CN).
    pub names: Vec<String>,
    pub not_before: i64,
    pub not_after: i64,
}

impl CertInfo {
    /// Whether this certificate covers every one of `wanted`.
    pub fn covers(&self, wanted: &[String]) -> bool {
        wanted.iter().all(|w| {
            self.names.iter().any(|n| {
                n.eq_ignore_ascii_case(w)
                    || n.strip_prefix("*.").is_some_and(|suffix| {
                        w.split_once('.').is_some_and(|(_, rest)| rest.eq_ignore_ascii_case(suffix))
                    })
            })
        })
    }
}

/// Holds the live certificate and the files it is persisted to.
pub struct CertStore {
    dir: PathBuf,
    current: RwLock<Option<Arc<CertifiedKey>>>,
    info: RwLock<Option<CertInfo>>,
}

impl std::fmt::Debug for CertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertStore").field("dir", &self.dir).finish_non_exhaustive()
    }
}

impl CertStore {
    pub fn new(data_dir: &Path) -> Result<Arc<CertStore>> {
        let dir = data_dir.join("tls");
        fs::create_dir_all(&dir)
            .with_context(|| format!("cannot create TLS directory {}", dir.display()))?;
        Ok(Arc::new(CertStore {
            dir,
            current: RwLock::new(None),
            info: RwLock::new(None),
        }))
    }

    fn cert_path(&self) -> PathBuf {
        self.dir.join("cert.pem")
    }

    fn key_path(&self) -> PathBuf {
        self.dir.join("key.pem")
    }

    pub fn info(&self) -> Option<CertInfo> {
        self.info.read().expect("cert info lock poisoned").clone()
    }

    /// Generate a self-signed certificate for `names` and make it current.
    pub fn generate_self_signed(&self, names: &[String]) -> Result<()> {
        let mut sans: Vec<String> = names.to_vec();
        if !sans.iter().any(|n| n == "localhost") {
            sans.push("localhost".to_string());
        }
        tracing::info!("generating self-signed TLS certificate for {}", sans.join(", "));

        let mut params = rcgen::CertificateParams::new(sans.clone())
            .context("invalid names for a self-signed certificate")?;
        // rcgen's defaults are 1975..4096, which makes the admin UI's "expires
        // in" reading meaningless. A year is plenty for a placeholder cert.
        let now = time::OffsetDateTime::from_unix_timestamp(crate::config::now_unix())
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
        params.not_before = now - time::Duration::hours(1); // tolerate clock skew
        params.not_after = now + time::Duration::days(365);
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, sans[0].clone());

        let key = rcgen::KeyPair::generate().context("generating a key pair")?;
        let cert = params
            .self_signed(&key)
            .context("failed to generate self-signed certificate")?;
        self.install_pem(&cert.pem(), &key.serialize_pem())
    }

    /// Write a PEM certificate chain and key to disk, then make them current.
    /// The new material is validated before either file is replaced, so a bad
    /// ACME response cannot leave the server without a usable certificate.
    pub fn install_pem(&self, cert_pem: &str, key_pem: &str) -> Result<()> {
        let (certs, key) = parse_pem(cert_pem, key_pem)?;
        let certified = build_certified_key(certs.clone(), key)?;
        let info = inspect(&certs)?;

        // Key first: a chain without its key is useless, a key without its
        // chain is harmless, so this ordering survives a crash between writes.
        write_private(&self.key_path(), key_pem)?;
        fs::write(self.cert_path(), cert_pem)
            .with_context(|| format!("writing {}", self.cert_path().display()))?;

        self.set(certified, info.clone());
        tracing::info!(
            "TLS certificate installed: {} for [{}], valid until {}",
            info.source.label(),
            info.names.join(", "),
            crate::config::fmt_ts(info.not_after)
        );
        Ok(())
    }

    /// Load `cert.pem` / `key.pem` from disk and make them current.
    pub fn load_from_disk(&self) -> Result<()> {
        let cert_pem = fs::read_to_string(self.cert_path())
            .with_context(|| format!("reading {}", self.cert_path().display()))?;
        let key_pem = fs::read_to_string(self.key_path())
            .with_context(|| format!("reading {}", self.key_path().display()))?;
        let (certs, key) = parse_pem(&cert_pem, &key_pem)?;
        let certified = build_certified_key(certs.clone(), key)?;
        self.set(certified, inspect(&certs)?);
        Ok(())
    }

    /// Load the certificate from disk, generating a self-signed one if there
    /// is nothing usable there yet. Called once at startup.
    pub fn load_or_generate(&self, names: &[String]) -> Result<()> {
        if self.cert_path().exists() && self.key_path().exists() {
            match self.load_from_disk() {
                Ok(()) => return Ok(()),
                Err(e) => tracing::warn!(
                    "existing TLS material is unusable ({e:#}); generating a self-signed replacement"
                ),
            }
        }
        self.generate_self_signed(names)
    }

    fn set(&self, certified: Arc<CertifiedKey>, info: CertInfo) {
        *self.current.write().expect("cert lock poisoned") = Some(certified);
        *self.info.write().expect("cert info lock poisoned") = Some(info);
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current.read().expect("cert lock poisoned").clone()
    }
}

/// Build the single [`ServerConfig`] shared by every TLS listener. It reads
/// through to the store on each handshake, so it never needs replacing.
pub fn server_config(store: Arc<CertStore>) -> Arc<ServerConfig> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(store);
    // Lets the HTTPS listener negotiate HTTP/1.1 explicitly; SMTP ignores ALPN.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

fn parse_pem(
    cert_pem: &str,
    key_pem: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("certificate is not valid PEM")?;
    if certs.is_empty() {
        return Err(anyhow!("no certificate found in PEM data"));
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .context("private key is not valid PEM")?
        .ok_or_else(|| anyhow!("no private key found in PEM data"))?;
    Ok((certs, key))
}

fn build_certified_key(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<CertifiedKey>> {
    let provider = rustls::crypto::ring::default_provider();
    let ck = CertifiedKey::from_der(certs, key, &provider)
        .map_err(|e| anyhow!("certificate and private key do not match or are unsupported: {e}"))?;
    Ok(Arc::new(ck))
}

/// Pull the human-facing details out of the leaf certificate.
fn inspect(certs: &[CertificateDer<'static>]) -> Result<CertInfo> {
    let leaf = certs.first().ok_or_else(|| anyhow!("empty certificate chain"))?;
    let (_, parsed) = X509Certificate::from_der(leaf.as_ref())
        .map_err(|e| anyhow!("cannot parse certificate: {e}"))?;

    let mut names: Vec<String> = Vec::new();
    if let Ok(Some(san)) = parsed.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                names.push((*dns).to_string());
            }
        }
    }
    if names.is_empty() {
        names.extend(parsed.subject().iter_common_name().filter_map(|cn| cn.as_str().ok()).map(str::to_string));
    }

    let issuer = parsed
        .issuer()
        .iter_common_name()
        .find_map(|cn| cn.as_str().ok())
        .unwrap_or("(unknown issuer)")
        .to_string();

    let self_signed = parsed.subject() == parsed.issuer();
    let source = if self_signed {
        CertSource::SelfSigned
    } else if issuer.contains("Let's Encrypt")
        || issuer.starts_with('E') && issuer.len() <= 3
        || issuer.starts_with('R') && issuer.len() <= 3
        || issuer.contains("(STAGING)")
        || issuer.contains("Pretend Pear")
        || issuer.contains("Fake LE")
    {
        CertSource::Acme
    } else {
        CertSource::External
    };

    Ok(CertInfo {
        source,
        issuer,
        names,
        not_before: parsed.validity().not_before.timestamp(),
        not_after: parsed.validity().not_after.timestamp(),
    })
}

/// Write a secret with owner-only permissions where the platform supports it.
fn write_private(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting permissions on {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn self_signed_round_trips_through_the_store() {
        provider();
        let dir = std::env::temp_dir().join(format!("smtpvoid-tls-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = CertStore::new(&dir).expect("store");
        store
            .generate_self_signed(&["mail.example.test".to_string()])
            .expect("generate");

        let info = store.info().expect("info present");
        assert_eq!(info.source, CertSource::SelfSigned);
        assert!(info.names.iter().any(|n| n == "mail.example.test"));
        // Roughly a year, not rcgen's 1975..4096 default.
        let days = (info.not_after - info.not_before) / 86_400;
        assert!((364..=366).contains(&days), "unexpected validity of {days} days");
        assert!(info.not_before <= crate::config::now_unix());

        // A fresh store reading the same directory sees the same certificate.
        let reopened = CertStore::new(&dir).expect("reopen");
        reopened.load_from_disk().expect("load");
        assert_eq!(reopened.info().expect("info").names, info.names);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn covers_matches_exact_and_wildcard_names() {
        let info = CertInfo {
            source: CertSource::Acme,
            issuer: "E5".into(),
            names: vec!["mail.example.test".into(), "*.wild.test".into()],
            not_before: 0,
            not_after: 0,
        };
        assert!(info.covers(&["mail.example.test".to_string()]));
        assert!(info.covers(&["MAIL.EXAMPLE.TEST".to_string()]));
        assert!(info.covers(&["smtp.wild.test".to_string()]));
        assert!(!info.covers(&["deep.smtp.wild.test".to_string()]));
        assert!(!info.covers(&["other.test".to_string()]));
    }

    #[test]
    fn mismatched_key_is_rejected_before_anything_is_written() {
        provider();
        let a = rcgen::generate_simple_self_signed(vec!["a.test".to_string()]).expect("a");
        let b = rcgen::generate_simple_self_signed(vec!["b.test".to_string()]).expect("b");
        let dir = std::env::temp_dir().join(format!("smtpvoid-tls-bad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = CertStore::new(&dir).expect("store");

        let err = store.install_pem(&a.cert.pem(), &b.signing_key.serialize_pem());
        assert!(err.is_err(), "mismatched key must be refused");
        assert!(!store.cert_path().exists(), "nothing should have been written");
        assert!(store.info().is_none());

        let _ = fs::remove_dir_all(&dir);
    }
}
