use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use anyhow::{Error, Result};
use clap::Parser;
use log::{debug, info};
use rustls::pki_types::ServerName;

#[derive(clap::Parser, Debug)]
#[command(version, after_help = "https://github.com/ThomasHabets/tlshake")]
struct Opt {
    #[clap(short, default_value = "0")]
    verbose: usize,

    #[clap(long)]
    tls12: bool,

    #[clap(long)]
    tls13: bool,

    #[clap(short, default_value = "443")]
    port: u16,

    #[clap(long)]
    alpn: Option<String>,

    #[clap(long)]
    http_get: Option<String>,

    #[clap(long, help = "Read early data from file.")]
    early_data: Option<std::path::PathBuf>,

    #[clap(long, default_value = "false", help = "Dump reply content.")]
    contents: bool,

    #[clap(long)]
    endpoint: Option<String>,

    #[clap(long, default_value = "false")]
    noverify: bool,

    #[clap()]
    addr: String,
}

fn doit(
    name: &str,
    config: Arc<rustls::ClientConfig>,
    host: &str,
    hostport: &str,
    request: Option<&str>,
    dump_contents: bool,
) -> Result<()> {
    let mut conn = rustls::ClientConnection::new(config, ServerName::try_from(host)?.to_owned())?;

    println!("Connection: {name}");
    let sent_early = if let Some(req) = request {
        if let Some(mut early_data) = conn.early_data() {
            early_data.write_all(req.as_bytes())?;
            println!("  Attempting early data");
            true
        } else {
            false
        }
    } else {
        false
    };

    // Connect TCP.
    let tcp_start = std::time::Instant::now();
    let mut sock = TcpStream::connect(&hostport)?;
    println!("  Connect time:       {:?}", tcp_start.elapsed());
    sock.set_nodelay(true)?;

    // Handshake.
    let mut stream = rustls::Stream::new(&mut conn, &mut sock);
    let start = std::time::Instant::now();
    stream.flush()?;
    println!("  Handshake time:     {:?}", start.elapsed());
    println!(
        "  Handshake kind:     {:?}",
        stream
            .conn
            .handshake_kind()
            .ok_or(Error::msg("no handshake kind?"))?
    );
    println!(
        "  Protocol version:   {:?}",
        stream
            .conn
            .protocol_version()
            .ok_or(Error::msg("no protocol version?"))?
    );
    println!(
        "  Cipher suite:       {:?}",
        stream
            .conn
            .negotiated_cipher_suite()
            .ok_or(Error::msg("no cipher?"))?
    );
    println!(
        "  ALPN protocol       {:?}",
        stream
            .conn
            .alpn_protocol()
            .map(|s| String::from_utf8(s.to_vec()))
    );

    if let Some(req) = request {
        let start = std::time::Instant::now();
        if stream.conn.is_early_data_accepted() {
            println!("  Early data:         accepted");
        } else {
            if sent_early {
                println!("  Early data:         NOT accepted");
            }
            stream.write_all(req.as_bytes())?;
        }
        let firstline = {
            let mut r = String::new();
            let mut buf = BufReader::new(stream);
            buf.read_line(&mut r)?;
            if dump_contents {
                let mut contents = String::new();
                buf.read_to_string(&mut contents)?;
                println!("{contents}");
            }
            r.replace("\r", "").replace("\n", "")
        };
        println!("  HTTP first line:    {firstline}");
        println!("  Request time:       {:?}", start.elapsed());
    }
    println!("  Total time:         {:?}", tcp_start.elapsed());

    Ok(())
}

#[derive(Debug)]
struct TicketStore {
    inner: rustls::client::ClientSessionMemoryCache,
}

impl TicketStore {
    fn new() -> Self {
        Self {
            inner: rustls::client::ClientSessionMemoryCache::new(100),
        }
    }
}

use rustls::client::Tls12ClientSessionValue;
use rustls::client::Tls13ClientSessionValue;
impl rustls::client::ClientSessionStore for TicketStore {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: rustls::NamedGroup) {
        info!("Set KX hint: {server_name:?}, {group:?}");
        self.inner.set_kx_hint(server_name, group)
    }
    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<rustls::NamedGroup> {
        let r = self.inner.kx_hint(server_name);
        info!("KX hint: {server_name:?} => {r:?}");
        r
    }
    fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue) {
        info!("Set TLS 1.2 session: {server_name:?}, […]");
        self.inner.set_tls12_session(server_name, value)
    }
    fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        let r = self.inner.tls12_session(server_name);
        let val = match r {
            None => "None",
            Some(_) => "[…]",
        };
        info!("TLS1.2 session: {server_name:?} => {val}");
        r
    }
    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        info!("Remove TLS 1.2 session: {server_name:?}");
        self.inner.remove_tls12_session(server_name)
    }
    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: Tls13ClientSessionValue,
    ) {
        info!("Insert TLS 1.3 ticket: {server_name:?}, […]");
        self.inner.insert_tls13_ticket(server_name, value)
    }
    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue> {
        let r = self.inner.take_tls13_ticket(server_name);
        info!("Take TLS 1.3 ticket: {server_name:?} => […]");
        r
    }
}

#[derive(Debug)]
struct AcceptAll {}

impl AcceptAll {
    fn new() -> Result<Arc<Self>> {
        Ok(Arc::new(Self {}))
    }
}
impl rustls::client::danger::ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        info!("Verifying server name {server_name:?}");
        return Ok(rustls::client::danger::ServerCertVerified::assertion());
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        return Ok(rustls::client::danger::HandshakeSignatureValid::assertion());
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
        // TODO: Really, wa want a complete list, or delegate to a
        // parent verifier.
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

fn main() -> Result<()> {
    let opt = Opt::parse();
    stderrlog::new()
        .module(module_path!())
        .module("agw")
        .quiet(false)
        .verbosity(opt.verbose)
        .timestamp(stderrlog::Timestamp::Second)
        .init()
        .unwrap();

    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let versions = if opt.tls12 && !opt.tls13 {
        vec![&rustls::version::TLS12]
    } else if !opt.tls12 && opt.tls13 {
        vec![&rustls::version::TLS13]
    } else {
        vec![&rustls::version::TLS12, &rustls::version::TLS13]
    };

    let config = {
        let crypto = rustls::crypto::aws_lc_rs::default_provider();
        info!("Cipher suites: {:?}", crypto.cipher_suites);
        info!("KX groups: {:?}", crypto.kx_groups);
        debug!(
            "Signature algs {:?}",
            crypto.signature_verification_algorithms.all
        );
        debug!(
            "Signature algs {:?}",
            crypto.signature_verification_algorithms.mapping
        );

        let config = rustls::ClientConfig::builder_with_provider(Arc::new(crypto))
            .with_protocol_versions(&versions)?;
        let mut config = if opt.noverify {
            config
                .dangerous()
                .with_custom_certificate_verifier(AcceptAll::new()?)
        } else {
            config.with_root_certificates(root_store)
        }
        .with_no_client_auth();

        if let Some(alpn) = opt.alpn {
            config.alpn_protocols = vec![alpn.bytes().collect()];
        }
        config.resumption = rustls::client::Resumption::store(Arc::new(TicketStore::new()));
        config.enable_early_data = true;
        assert!(config.enable_sni);
        assert!(config.enable_early_data);
        Arc::new(config)
    };

    let host = &opt.addr;
    // TODO: support IPv6 literals.

    let hostport = if let Some(endpoint) = opt.endpoint {
        endpoint
    } else {
        host.to_owned() + ":" + &opt.port.to_string()
    };
    let request = if let Some(url) = opt.http_get {
        Some(format!(
            "GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n"))
    } else if let Some(data) = opt.early_data {
        Some(std::fs::read_to_string(data)?)
    } else {
        None
    };
    let res = doit(
        "initial",
        config.clone(),
        &host,
        &hostport,
        request.as_deref(),
        opt.contents,
    )?;
    println!("");
    doit(
        "resume",
        config.clone(),
        &host,
        &hostport,
        request.as_deref(),
        opt.contents,
    )?;
    Ok(())
}
