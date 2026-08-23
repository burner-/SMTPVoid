use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

/// Load the TLS server config from `<data_dir>/tls/{cert.pem,key.pem}`,
/// generating a self-signed certificate on first run. Operators can replace
/// the files with a real certificate at any time.
pub fn load_or_generate(data_dir: &Path, hostname: &str) -> Result<Arc<ServerConfig>> {
    let tls_dir = data_dir.join("tls");
    fs::create_dir_all(&tls_dir)?;
    let cert_path = tls_dir.join("cert.pem");
    let key_path = tls_dir.join("key.pem");

    if !cert_path.exists() || !key_path.exists() {
        tracing::info!("generating self-signed TLS certificate for {hostname}");
        let ck = rcgen::generate_simple_self_signed(vec![
            hostname.to_string(),
            "localhost".to_string(),
        ])
        .context("failed to generate self-signed certificate")?;
        fs::write(&cert_path, ck.cert.pem())?;
        fs::write(&key_path, ck.key_pair.serialize_pem())?;
    }

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(fs::File::open(&cert_path)?))
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to read cert.pem")?;
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut std::io::BufReader::new(fs::File::open(&key_path)?))
            .context("failed to read key.pem")?
            .ok_or_else(|| anyhow!("no private key found in key.pem"))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid TLS certificate/key")?;
    Ok(Arc::new(config))
}
