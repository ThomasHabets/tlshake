use std::sync::Arc;

use anyhow::Result;
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

    #[clap(long, default_value = "")]
    alpn: String,

    #[clap()]
    addr: String,
}

fn doit(config: Arc<rustls::ClientConfig>, host: String, hostport: String) -> Result<()> {
    let mut client = rustls::ClientConnection::new(config, ServerName::try_from(host)?)?;

    // Connect TCP.
    let start = std::time::Instant::now();
    let mut tcp_stream = std::net::TcpStream::connect(hostport)?;
    println!("Connect time:       {:?}", start.elapsed());

    // Handshake.
    let start = std::time::Instant::now();
    //let tls_stream = rustls::Stream::new(&mut client, &mut tcp_stream);
    while client.is_handshaking() {
        client.complete_io(&mut tcp_stream)?;
    }
    println!("Handshake time:     {:?}", start.elapsed());
    // https://docs.rs/rustls/latest/rustls/enum.HandshakeKind.html
    println!("  Handshake kind:   {:?}", client.handshake_kind().unwrap());
    println!(
        "  Protocol version: {:?}",
        client.protocol_version().unwrap()
    );
    println!(
        "  Cipher suite:     {:?}",
        client.negotiated_cipher_suite().unwrap()
    );
    println!(
        "  ALPN protocol     {:?}",
        client
            .alpn_protocol()
            .map(|s| String::from_utf8(s.to_vec()))
    );
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
        info!("Insert TLS 1.3 ticket: {server_name:?}, {value:?}");
        self.inner.insert_tls13_ticket(server_name, value)
    }
    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue> {
        let r = self.inner.take_tls13_ticket(server_name);
        info!("Take TLS 1.3 ticket: {server_name:?} => {r:?}");
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
        if !opt.alpn.is_empty() {
            config.alpn_protocols = vec![opt.alpn.bytes().collect()];
        }
        // config.resumption = rustls::client::Resumption::disabled();
        config.resumption = rustls::client::Resumption::store(Arc::new(TicketStore::new()));
        Arc::new(config)
    };

    let host = &opt.addr;
    // TODO: support IPv6 literals.
    let hostport = host.to_owned() + ":" + &opt.port.to_string();

    doit(config.clone(), host.to_string(), hostport.clone())?;
    println!("");
    doit(config.clone(), host.to_string(), hostport.clone())?;
    println!("");
    Ok(())
}
