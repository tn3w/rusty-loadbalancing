use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::RwLock,
};
use std::{sync::Arc, time::Duration, path::PathBuf, fs};
use redis::{Client, Commands};
use clap::Parser;
use tokio::time::sleep;
use tokio_rustls::{TlsAcceptor, rustls};
use rcgen::{Certificate, CertificateParams, DistinguishedName};
use rustls::{ServerConfig, PrivateKey, Certificate as RustlsCert};
use tokio::runtime::Handle;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = 1)]
    workers: usize,

    #[arg(short, long, value_parser = parse_bind_address)]
    bind: String,

    #[arg(long)]
    https: bool,

    #[arg(long)]
    cert_file: Option<PathBuf>,

    #[arg(long)]
    key_file: Option<PathBuf>,
}

enum StreamType {
    Plain(TcpStream),
    Tls(tokio_rustls::server::TlsStream<TcpStream>),
}

impl StreamType {
    async fn into_split(
        self,
    ) -> (
        Box<dyn AsyncRead + Unpin + Send>,
        Box<dyn AsyncWrite + Unpin + Send>,
    ) {
        match self {
            StreamType::Plain(stream) => {
                let (read_half, write_half) = stream.into_split();
                (Box::new(read_half), Box::new(write_half))
            }
            StreamType::Tls(stream) => {
                let (read_half, write_half) = tokio::io::split(stream);
                (Box::new(read_half), Box::new(write_half))
            }
        }
    }
}

fn parse_bind_address(s: &str) -> Result<String, String> {
    if s.starts_with(':') {
        return Ok(format!("0.0.0.0{}", s));
    }

    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return Err("Address must be in format 'host:port' or ':port'".to_string());
    }

    let host = if parts[0] == "localhost" { "127.0.0.1" } else { parts[0] };
    Ok(format!("{}:{}", host, parts[1]))
}

#[derive(Clone, Debug)]
struct Backend {
    address: String,
    active_connections: Arc<RwLock<u32>>,
}

struct LoadBalancer {
    backends: Arc<RwLock<Vec<Backend>>>,
    redis_client: Client,
    tls_acceptor: Option<TlsAcceptor>,
}

impl LoadBalancer {
    async fn new(redis_url: &str, args: &Args) -> Result<Self, Box<dyn std::error::Error>> {
        let redis_client = Client::open(redis_url)?;
        let tls_acceptor = if args.https || args.cert_file.is_some() || args.key_file.is_some() {
            Some(Self::setup_tls(args)?)
        } else {
            None
        };

        Ok(LoadBalancer {
            backends: Arc::new(RwLock::new(Vec::new())),
            redis_client,
            tls_acceptor,
        })
    }

    fn setup_tls(args: &Args) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
        let (cert_pem, key_pem) = match (&args.cert_file, &args.key_file) {
            (Some(cert_path), Some(key_path)) => {
                (fs::read_to_string(cert_path)?, fs::read_to_string(key_path)?)
            },
            _ => {
                println!("Generating self-signed certificate...");
                let mut params = CertificateParams::new(vec!["localhost".to_string()]);
                let mut dn = DistinguishedName::new();
                dn.push(rcgen::DnType::CommonName, "localhost");
                params.distinguished_name = dn;

                let cert = Certificate::from_params(params)?;
                (cert.serialize_pem()?, cert.serialize_private_key_pem())
            }
        };

        if args.cert_file.is_none() && args.key_file.is_none() {
            fs::write("cert.pem", &cert_pem)?;
            fs::write("key.pem", &key_pem)?;
            println!("Certificate and key saved to cert.pem and key.pem");
        }

        let cert_chain = vec![RustlsCert(
            rustls_pemfile::certs(&mut cert_pem.as_bytes())?
                .into_iter()
                .next()
                .ok_or("No certificate found")?
        )];

        let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_bytes())?;
        if keys.is_empty() {
            keys = rustls_pemfile::rsa_private_keys(&mut key_pem.as_bytes())?;
        }
        let key = PrivateKey(keys.into_iter().next().ok_or("No private key found")?);

        let config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;

        Ok(TlsAcceptor::from(Arc::new(config)))
    }

    async fn update_backends(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.redis_client.get_connection()?;
        let backend_list: Vec<String> = conn.lrange("backend_servers", 0, -1)?;

        let mut backends = self.backends.write().await;
        backends.clear();

        backends.extend(backend_list.into_iter().map(|address| Backend {
            address,
            active_connections: Arc::new(RwLock::new(0)),
        }));

        Ok(())
    }

    async fn get_least_loaded_backend(&self) -> Option<Backend> {
        let backends = self.backends.read().await;
        if backends.is_empty() {
            return None;
        }

        let mut min_connections = u32::MAX;
        let mut selected_backend = None;

        for backend in backends.iter() {
            let connections = *backend.active_connections.read().await;
            if connections < min_connections {
                min_connections = connections;
                selected_backend = Some(backend.clone());
            }
        }

        selected_backend
    }

    async fn handle_connection(&self, stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
        let stream = match &self.tls_acceptor {
            Some(acceptor) => StreamType::Tls(acceptor.accept(stream).await?),
            None => StreamType::Plain(stream),
        };

        let backend = self.get_least_loaded_backend().await
            .ok_or("No available backends")?;

        {
            let mut counter = backend.active_connections.write().await;
            *counter += 1;
        }

        let server = TcpStream::connect(&backend.address).await?;
        let (mut client_read, mut client_write) = stream.into_split().await;
        let (mut server_read, mut server_write) = server.into_split();

        let client_to_server = tokio::io::copy(&mut client_read, &mut server_write);
        let server_to_client = tokio::io::copy(&mut server_read, &mut client_write);

        let _ = tokio::join!(client_to_server, server_to_client);

        {
            let mut counter = backend.active_connections.write().await;
            *counter -= 1;
        }

        Ok(())
    }

    async fn run_backend_updater(&self) {
        loop {
            if let Err(e) = self.update_backends().await {
                eprintln!("Error updating backends: {}", e);
            }
            sleep(Duration::from_secs(10)).await;
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let runtime = Handle::current();
    let lb = Arc::new(LoadBalancer::new("redis://127.0.0.1/", &args).await?);

    let updater_lb = lb.clone();
    runtime.spawn(async move {
        updater_lb.run_backend_updater().await;
    });

    let listener = TcpListener::bind(&args.bind).await?;
    println!("Listening on {} ({})", args.bind,
             if lb.tls_acceptor.is_some() { "HTTPS" } else { "HTTP" });

    let semaphore = Arc::new(tokio::sync::Semaphore::new(args.workers));

    loop {
        let (client, _) = listener.accept().await?;
        let lb = lb.clone();
        let permit = semaphore.clone().acquire_owned().await?;

        runtime.spawn(async move {
            if let Err(e) = lb.handle_connection(client).await {
                eprintln!("Error handling connection: {}", e);
            }
            drop(permit);
        });
    }
}