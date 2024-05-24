use anyhow::Result;
use clap::Parser;
use rustls::pki_types::ServerName;
use std::sync::Arc;

#[derive(clap::Parser, Debug)]
struct Opt {
    #[clap(long)]
    tls13: bool,

    #[clap()]
    addr: String,
}

fn doit(config: Arc<rustls::ClientConfig>, host: String, hostport: String) -> Result<()> {
    let mut client = rustls::ClientConnection::new(config, ServerName::try_from(host)?)?;

    // Connect TCP.
    let start = std::time::Instant::now();
    let mut tcp_stream = std::net::TcpStream::connect(hostport)?;
    println!("Connect time: {:?}", start.elapsed());

    // Handshake.
    let start = std::time::Instant::now();
    //let tls_stream = rustls::Stream::new(&mut client, &mut tcp_stream);
    while client.is_handshaking() {
        client.complete_io(&mut tcp_stream)?;
    }
    println!("Handshake time: {:?}", start.elapsed());
    // https://docs.rs/rustls/latest/rustls/enum.HandshakeKind.html
    println!("{:?}", client.handshake_kind());
    println!("{:?}", client.protocol_version());
    println!("{:?}", client.negotiated_cipher_suite());
    Ok(())
}

fn main() -> Result<()> {
    let opt = Opt::parse();
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let versions = if opt.tls13 {
        [&rustls::version::TLS13]
    } else {
        [&rustls::version::TLS12]
    };

    let config = rustls::ClientConfig::builder_with_protocol_versions(&versions)
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let host = &opt.addr;
    let hostport = host.to_owned() + ":443";

    let config = Arc::new(config);

    doit(config.clone(), host.to_string(), hostport.clone())?;
    println!("");
    doit(config.clone(), host.to_string(), hostport.clone())?;
    println!("");
    Ok(())
}
