use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use anyhow::{Error, Result};
use clap::Parser;
use log::{debug, info};
use rustls::pki_types::ServerName;

#[derive(clap::Parser, Debug)]
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

    #[clap(long, default_value = "false")]
    contents: bool,

    #[clap()]
    addr: String,
}

fn doit(
    config: Arc<rustls::ClientConfig>,
    host: &str,
    hostport: &str,
    request: Option<&str>,
    dump_contents: bool,
) -> Result<()> {
    let mut conn = rustls::ClientConnection::new(config, ServerName::try_from(host)?.to_owned())?;

    println!("Connection");
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

        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(crypto))
            .with_protocol_versions(&versions)?
            .with_root_certificates(root_store)
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
    let hostport = host.to_owned() + ":" + &opt.port.to_string();
    let request = opt.http_get.map(|url| {
	format!(
            "GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n")
    });
    doit(
        config.clone(),
        &host,
        &hostport,
        request.as_deref(),
        opt.contents,
    )?;
    println!("");
    doit(
        config.clone(),
        &host,
        &hostport,
        request.as_deref(),
        opt.contents,
    )?;
    Ok(())
}
