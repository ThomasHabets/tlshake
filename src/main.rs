use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use anyhow::{Error, Result};
use clap::Parser;
use log::{debug, info};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
struct ConnectionResult {
    timestamp_us: u128,

    name: String,
    target: String,
    endpoint: String,
    sent_early_data: bool,
    early_data_accepted: bool,
    connect_time_ms: f64,
    handshake_time_ms: f64,
    handshake_kind: String,
    protocol_version: String,
    cipher_suite: String,
    total_time_ms: f64,

    #[serde(skip_serializing_if = "Option::is_none")]
    alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_time_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contents: Option<String>,
}

impl core::fmt::Display for ConnectionResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "Connection: {}\n", self.name)?;
        write!(f, "  Target:           {}\n", self.target)?;
        write!(f, "  Endpoint:         {}\n", self.endpoint)?;
        write!(f, "  Connect time:     {:.3}ms\n", self.connect_time_ms)?;
        write!(f, "  Handshake time:   {:.3}ms\n", self.handshake_time_ms)?;
        write!(f, "  Handshake kind:   {}\n", self.handshake_kind)?;
        write!(f, "  Protocol version: {}\n", self.protocol_version)?;
        write!(f, "  Cipher suite:     {}\n", self.cipher_suite)?;
        write!(f, "  ALPN protocol:    {:?}\n", self.alpn)?;
        if self.early_data_accepted {
            write!(f, "  Early data:       accepted\n")?;
        } else if self.sent_early_data {
            write!(f, "  Early data:       NOT accepted\n")?;
        }
        if let Some(rt) = &self.request_time_ms {
            write!(f, "  Request time:     {rt:.3}ms\n")?;
        }
        if let Some(firstline) = &self.first_line {
            write!(f, "  Reply first line: {firstline}\n")?;
        }
        write!(f, "  Total time:       {:.3}ms\n", self.total_time_ms)?;
        if let Some(contents) = &self.contents {
            write!(f, "  Contents:\n{contents}\n")?;
        }
        Ok(())
    }
}

#[derive(clap::Parser, Debug)]
#[command(version, after_help = "https://github.com/ThomasHabets/tlshake")]
struct Opt {
    #[clap(short, default_value = "0", help = "Output some debug output.")]
    verbose: usize,

    #[clap(long, help = "Output results in JSON format.", default_value = "false")]
    json: bool,

    #[clap(long, help = "Use TLS 1.2.")]
    tls12: bool,

    #[clap(long, help = "Use TLS 1.3.")]
    tls13: bool,

    #[clap(
        short,
        default_value = "443",
        help = "Default port.\nOverridden by --endpoint."
    )]
    port: u16,

    #[clap(long, help = "Set inner protocol using ALPN field.")]
    alpn: Option<String>,

    #[clap(
        long,
        help = "Send HTTP GET on connection,\nas early data if resuming TLS 1.3."
    )]
    http_get: Option<String>,

    #[clap(long, help = "Read early data from file.")]
    early_data: Option<std::path::PathBuf>,

    #[clap(long, default_value = "false", help = "Dump reply content.")]
    contents: bool,

    #[clap(
        long,
        help = "Override connect to host:port instead\nof resolving target."
    )]
    endpoint: Option<String>,

    #[clap(long, default_value = "false", help = "Don't verify server cert.")]
    noverify: bool,

    #[clap(long, default_value = "1", help = "Number of resumptions to attempt.")]
    resumptions: usize,

    #[clap(help = "Target to connect to, excluding port.")]
    addr: String,
}

fn doit(
    name: &str,
    config: Arc<rustls::ClientConfig>,
    host: &str,
    hostport: &str,
    request: Option<&str>,
    dump_contents: bool,
) -> Result<ConnectionResult> {
    let mut conn = rustls::ClientConnection::new(config, ServerName::try_from(host)?.to_owned())?;

    let mut res: ConnectionResult = Default::default();
    res.timestamp_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_micros();
    res.name = name.to_string();
    res.target = host.to_string();
    res.endpoint = hostport.to_string();

    res.sent_early_data = if let Some(req) = request {
        if let Some(mut early_data) = conn.early_data() {
            early_data.write_all(req.as_bytes())?;
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
    res.connect_time_ms = tcp_start.elapsed().as_secs_f64() * 1000.0;
    sock.set_nodelay(true)?;

    // Handshake.
    let mut stream = rustls::Stream::new(&mut conn, &mut sock);
    let start = std::time::Instant::now();
    stream.flush()?;
    res.handshake_time_ms = start.elapsed().as_secs_f64() * 1000.0;
    res.handshake_kind = format!(
        "{:?}",
        stream
            .conn
            .handshake_kind()
            .ok_or(Error::msg("no handshake kind?"))?
    );
    res.protocol_version = format!(
        "{:?}",
        stream
            .conn
            .protocol_version()
            .ok_or(Error::msg("no protocol version?"))?
    );
    res.cipher_suite = format!(
        "{:?}",
        stream
            .conn
            .negotiated_cipher_suite()
            .ok_or(Error::msg("no cipher?"))?
    );
    res.alpn = stream
        .conn
        .alpn_protocol()
        .map(|s| format!("{:?}", String::from_utf8(s.to_vec())));
    debug!("About to send request as 'late data'");
    if let Some(req) = request {
        let start = std::time::Instant::now();
        if res.sent_early_data && stream.conn.is_early_data_accepted() {
            res.early_data_accepted = true;
        } else {
            stream.write_all(req.as_bytes())?;
        }
        res.first_line = {
            let mut r = String::new();
            let mut buf = BufReader::new(stream);
            buf.read_line(&mut r)?;
            if dump_contents {
                let mut contents = String::new();
                buf.read_to_string(&mut contents)?;
                res.contents = Some(contents);
            }
            Some(r.replace("\r", "").replace("\n", ""))
        };
        res.request_time_ms = Some(start.elapsed().as_secs_f64() * 1000.0);
    }

    res.total_time_ms = tcp_start.elapsed().as_secs_f64() * 1000.0;
    debug!("Request all done");
    Ok(res)
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
    if opt.json {
        println!("{}", serde_json::to_string(&res)?);
    } else {
        print!("{}", res);
    }

    for _ in 0..opt.resumptions {
        if !opt.json {
            println!();
        }
        let res = doit(
            "resume",
            config.clone(),
            &host,
            &hostport,
            request.as_deref(),
            opt.contents,
        )?;
        if opt.json {
            println!("{}", serde_json::to_string(&res)?);
        } else {
            print!("{}", res);
        }
    }
    Ok(())
}
