//! Development smoke-test SMTP client.
//!
//! Usage:
//!   cargo run --example smoke_client -- <mode> <host:port> <username> <password>
//! where <mode> is one of: plain | starttls | tls
//!
//! Sends one test message and prints the whole SMTP dialogue. Accepts any TLS
//! certificate (this is a test tool for talking to SMTPVoid's self-signed cert).

use std::sync::Arc;

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

struct Client {
    inner: Option<Box<dyn Stream>>,
    buf: Vec<u8>,
}

impl Client {
    async fn read_reply(&mut self) -> anyhow::Result<String> {
        let mut reply = String::new();
        loop {
            let line = self.read_line().await?;
            println!("S: {line}");
            reply.push_str(&line);
            reply.push('\n');
            // last line of a reply has a space (or nothing) after the code
            if line.len() < 4 || line.as_bytes()[3] != b'-' {
                return Ok(reply);
            }
        }
    }

    async fn read_line(&mut self) -> anyhow::Result<String> {
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                let mut line: Vec<u8> = self.buf.drain(..=pos).collect();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(String::from_utf8_lossy(&line).into_owned());
            }
            let mut chunk = [0u8; 4096];
            let n = self.inner.as_mut().unwrap().read(&mut chunk).await?;
            anyhow::ensure!(n > 0, "server closed connection");
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    async fn send(&mut self, line: &str) -> anyhow::Result<String> {
        println!("C: {line}");
        let s = self.inner.as_mut().unwrap();
        s.write_all(line.as_bytes()).await?;
        s.write_all(b"\r\n").await?;
        s.flush().await?;
        self.read_reply().await
    }
}

#[derive(Debug)]
struct NoVerify(rustls::crypto::CryptoProvider);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn tls_connector() -> TlsConnector {
    let provider = rustls::crypto::ring::default_provider();
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = std::env::args().collect();
    anyhow::ensure!(args.len() == 5, "usage: smoke_client <plain|starttls|tls> <host:port> <user> <pass>");
    let (mode, addr, user, pass) = (&args[1], &args[2], &args[3], &args[4]);
    let host = addr.split(':').next().unwrap().to_string();

    let tcp = TcpStream::connect(addr).await?;
    let mut client = if mode == "tls" {
        let sni = rustls::pki_types::ServerName::try_from(host.clone())?;
        let stream = tls_connector().connect(sni, tcp).await?;
        Client { inner: Some(Box::new(stream)), buf: Vec::new() }
    } else {
        Client { inner: Some(Box::new(tcp)), buf: Vec::new() }
    };

    client.read_reply().await?; // greeting
    client.send("EHLO smoke.test").await?;

    if mode == "starttls" {
        let reply = client.send("STARTTLS").await?;
        anyhow::ensure!(reply.starts_with("220"), "STARTTLS refused");
        let inner = client.inner.take().unwrap();
        let sni = rustls::pki_types::ServerName::try_from(host.clone())?;
        let stream = tls_connector().connect(sni, inner).await?;
        client.buf.clear();
        client.inner = Some(Box::new(stream));
        client.send("EHLO smoke.test").await?;
    }

    let token = base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{pass}"));
    let reply = client.send(&format!("AUTH PLAIN {token}")).await?;
    anyhow::ensure!(reply.starts_with("235"), "authentication failed");

    client.send("MAIL FROM:<tester@smoke.test>").await?;
    client.send("RCPT TO:<anyone@example.com>").await?;
    client.send("RCPT TO:<postmaster@whitehouse.gov>").await?;
    let reply = client.send("DATA").await?;
    anyhow::ensure!(reply.starts_with("354"), "DATA refused");
    let body = format!(
        "From: Smoke Tester <tester@smoke.test>\r\nTo: anyone@example.com\r\nSubject: Smoke test via {mode}\r\n\r\nHello from the {mode} smoke test.\r\n.. this line began with a dot.\r\n."
    );
    let reply = client.send(&body).await?;
    anyhow::ensure!(reply.starts_with("250"), "message not accepted");
    client.send("QUIT").await?;
    println!("OK: {mode} message accepted");
    Ok(())
}
