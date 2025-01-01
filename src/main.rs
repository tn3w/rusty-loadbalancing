use crate::StreamType::{Plain, Tls};
use clap::Parser;
use ipnetwork::IpNetwork;
use rand::{seq::SliceRandom, thread_rng};
use rcgen::{Certificate, CertificateParams, DistinguishedName};
use redis::{Client, Commands};
use rustls::{Certificate as RustlsCert, PrivateKey, ServerConfig};
use sha2::{Digest, Sha256};
use std::{
    fs, fmt,
    collections::HashMap,
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
    error::Error
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    runtime::Handle,
    sync::RwLock,
    time::sleep,
};
use tokio_rustls::{rustls, TlsAcceptor};


static LOGO: &str = r#"
░░       ░░░  ░░░░  ░░░      ░░░        ░░  ░░░░  ░
▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒▒  ▒▒  ▒▒
▓▓       ▓▓▓  ▓▓▓▓  ▓▓▓      ▓▓▓▓▓▓  ▓▓▓▓▓▓▓    ▓▓▓
██  ███  ███  ████  ████████  █████  ████████  ████
██  ████  ███      ████      ██████  ████████  ████                                           
 A fast, efficient, and small load balancing tool.

Author: TN3W
GitHub: https://github.com/tn3w/rusty-loadbalancing
"#;


#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, value_parser = parse_bind_address, help = "Address to bind the server to.")]
    bind: String,

    #[arg(short, long, default_value_t = 1, help = "Number of worker threads to use.")]
    workers: usize,

    #[arg(short, long, value_parser = parse_bind_address, default_value = "127.0.0.1:6379", help = "Redis server address.")]
    redis: String,

    #[arg(long, help = "Enable HTTPS for secure connections.")]
    https: bool,

    #[arg(long, help = "Path to the SSL certificate file.")]
    cert_file: Option<PathBuf>,

    #[arg(long, help = "Path to the SSL key file.")]
    key_file: Option<PathBuf>,

    #[arg(long, help = "Rate limit for incoming requests (requests per 10 seconds).")]
    rate_limit: Option<u32>,

    #[arg(long, help = "Path to the rate limit configuration page.")]
    rate_limit_page: Option<PathBuf>,

    #[arg(long, num_args = 0..=1, default_missing_value = "", help = "Value for the Server header in responses (omit if empty).")]
    server_header: Option<String>,
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
            Plain(stream) => {
                let (read_half, write_half) = stream.into_split();
                (Box::new(read_half), Box::new(write_half))
            }
            Tls(stream) => {
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

#[derive(Clone)]
struct BackendGroup {
    backends: Vec<Backend>,
}

#[derive(Debug)]
pub enum ProxyError {
    Io(std::io::Error),
    Tls(String),
    Other(String),
    NoBackend,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyError::Io(e) => write!(f, "IO error: {}", e),
            ProxyError::Tls(e) => write!(f, "TLS error: {}", e),
            ProxyError::Other(e) => write!(f, "Other error: {}", e),
            ProxyError::NoBackend => write!(f, "No backend available"),
        }
    }
}

impl Error for ProxyError {}

impl From<std::io::Error> for ProxyError {
    fn from(e: std::io::Error) -> Self {
        ProxyError::Io(e)
    }
}


struct LoadBalancer {
    backend_groups: Arc<RwLock<HashMap<String, BackendGroup>>>,
    default_backends: Arc<RwLock<BackendGroup>>,
    redis_client: Client,
    tls_acceptor: Option<TlsAcceptor>,
    rate_limit: Option<u32>,
    rate_limit_page: Option<String>,
    server_header: Option<String>,
    whitelisted_networks: Arc<RwLock<Vec<IpNetwork>>>,
}

impl LoadBalancer {
    async fn new(redis_url: &str, args: &Args) -> Result<Self, Box<dyn std::error::Error>> {
        let redis_client = Client::open(redis_url)?;
        let tls_acceptor = if args.https || args.cert_file.is_some() || args.key_file.is_some() {
            Some(Self::setup_tls(args)?)
        } else {
            None
        };

        let rate_limit_page = if let Some(path) = &args.rate_limit_page {
            Some(fs::read_to_string(path)?)
        } else {
            None
        };

        Ok(LoadBalancer {
            backend_groups: Arc::new(RwLock::new(HashMap::new())),
            default_backends: Arc::new(RwLock::new(BackendGroup {
                backends: Vec::new(),
            })),
            redis_client,
            tls_acceptor,
            rate_limit: args.rate_limit,
            rate_limit_page,
            server_header: args.server_header.clone(),
            whitelisted_networks: Arc::new(RwLock::new(Vec::new())),
        })
    }

    fn hash_ip(ip: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(ip.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }

    async fn check_rate_limit(&self, ip: &str) -> Result<bool, redis::RedisError> {
        if let Some(rate_limit) = self.rate_limit {
            let mut conn = self.redis_client.get_connection()?;
            let hashed_ip = Self::hash_ip(ip);
            let key = format!("rusty:rate_limit:{}", hashed_ip);

            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            let _result_rpush: () = conn.rpush(&key, current_time)?;
            let _result_ltrim: () = conn.ltrim(&key, -(rate_limit as isize + 3), -1)?;
            let result_lrange: Vec<i64> = conn.lrange(&key, 0, -1)?;
            let _result_expire: () = conn.expire(&key, 10)?;

            let recent_requests = result_lrange
                .iter()
                .filter(|&&t| current_time - t <= 10)
                .count();

            Ok(recent_requests > rate_limit as usize)
        } else {
            Ok(false)
        }
    }

    async fn modify_response_headers(&self, response: Vec<u8>) -> Vec<u8> {
        if let Ok(response_str) = String::from_utf8(response.clone()) {
            let parts: Vec<&str> = response_str.split("\r\n\r\n").collect();
            if parts.len() >= 1 {
                let headers: Vec<&str> = parts[0].split("\r\n").collect();
                let mut new_headers = Vec::new();
                let mut server_header_found = false;

                for header in headers {
                    if header.to_lowercase().starts_with("server:") {
                        server_header_found = true;
                        if let Some(new_server) = &self.server_header {
                            if !new_server.is_empty() {
                                new_headers.push(format!("Server: {}", new_server));
                            }
                        }
                    } else {
                        new_headers.push(header.to_string());
                    }
                }

                if !server_header_found && self.server_header.as_ref().map_or(false, |h| !h.is_empty()) {
                    new_headers.push(format!("Server: {}", self.server_header.as_ref().unwrap()));
                }

                let mut new_response = new_headers.join("\r\n");
                if parts.len() > 1 {
                    new_response.push_str("\r\n\r\n");
                    new_response.push_str(parts[1]);
                } else {
                    new_response.push_str("\r\n\r\n");
                }

                return new_response.into_bytes();
            }
        }
        response
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

    async fn update_backends(&self) -> Result<(), String> {
        let mut conn = self.redis_client.get_connection()
            .map_err(|e| e.to_string())?;
        let mut keys: Vec<String> = conn.keys("rusty:backend_servers*")
            .map_err(|e| e.to_string())?;
        keys.sort();

        let mut new_groups = HashMap::new();

        let default_backends: Vec<String> = conn.lrange("rusty:backend_servers", 0, -1)
            .map_err(|e| e.to_string())?;
        let default_group = BackendGroup {
            backends: default_backends.into_iter()
                .map(|address| Backend {
                    address,
                    active_connections: Arc::new(RwLock::new(0)),
                })
                .collect(),
        };
        *self.default_backends.write().await = default_group;

        for key in keys {
            if key == "rusty:backend_servers" {
                continue;
            }

            let host = key.strip_prefix("rusty:backend_servers:")
                .unwrap_or("")
                .to_string();

            if !host.is_empty() {
                let backend_list: Vec<String> = conn.lrange(&key, 0, -1)
                    .map_err(|e| e.to_string())?;
                if !backend_list.is_empty() {
                    let group = BackendGroup {
                        backends: backend_list.into_iter()
                            .map(|address| Backend {
                                address,
                                active_connections: Arc::new(RwLock::new(0)),
                            })
                            .collect(),
                    };
                    new_groups.insert(host, group);
                }
            }
        }

        *self.backend_groups.write().await = new_groups;
        Ok(())
    }

    async fn update_whitelisted_ips(&self) -> Result<(), String> {
        let mut conn = self.redis_client.get_connection()
            .map_err(|e| e.to_string())?;
        let ip_list: Vec<String> = conn.lrange("rusty:whitelisted_ips", 0, -1)
            .map_err(|e| e.to_string())?;

        let mut networks = Vec::new();
        for ip_str in ip_list {
            if let Ok(network) = ip_str.parse::<IpNetwork>() {
                networks.push(network);
            }
        }

        let mut whitelisted = self.whitelisted_networks.write().await;
        *whitelisted = networks;
        Ok(())
    }

    fn is_ip_whitelisted(&self, ip: IpAddr, networks: &[IpNetwork]) -> bool {
        if networks.is_empty() {
            return true;
        }

        networks.iter().any(|network| network.contains(ip))
    }

    async fn get_least_loaded_backend(&self, host: Option<&str>) -> Option<Backend> {
        let groups = self.backend_groups.read().await;
        let default_group = self.default_backends.read().await;

        let backends = if let Some(host) = host {
            if let Some(group) = groups.get(host) {
                &group.backends
            } else {
                let domain_parts: Vec<&str> = host.split('.').collect();
                if domain_parts.len() > 2 {
                    let wildcard_domain = domain_parts[1..].join(".");
                    if let Some(group) = groups.get(&wildcard_domain) {
                        &group.backends
                    } else {
                        &default_group.backends
                    }
                } else {
                    &default_group.backends
                }
            }
        } else {
            &default_group.backends
        };

        if backends.is_empty() {
            return None;
        }

        let mut min_connections = u32::MAX;
        let mut candidates = Vec::new();

        for backend in backends {
            let connections = *backend.active_connections.read().await;
            if connections < min_connections {
                min_connections = connections;
                candidates.clear();
                candidates.push(backend.clone());
            } else if connections == min_connections {
                candidates.push(backend.clone());
            }
        }

        if candidates.len() > 1 {
            candidates.choose(&mut thread_rng()).cloned()
        } else {
            candidates.into_iter().next()
        }
    }

    async fn run_updaters(&self) {
        loop {
            if let Err(e) = self.update_backends().await {
                eprintln!("Error updating backends: {}", e);
            }

            if let Err(e) = self.update_whitelisted_ips().await {
                eprintln!("Error updating IP whitelist: {}", e);
            }

            sleep(Duration::from_secs(1)).await;
        }
    }

    async fn check_ip_whitelist(&self, ip: &str) -> Result<bool, ProxyError> {
        let networks = self.whitelisted_networks.read().await;
        let parsed_ip = ip
            .parse()
            .map_err(|e| ProxyError::Other(format!("IP parsing error: {}", e)))?;
        Ok(self.is_ip_whitelisted(parsed_ip, &networks))
    }

    async fn setup_tls_stream(&self, stream: TcpStream) -> Result<StreamType, ProxyError> {
        Ok(match &self.tls_acceptor {
            Some(acceptor) => {
                let tls_stream = acceptor.accept(stream)
                    .await
                    .map_err(|e| ProxyError::Tls(e.to_string()))?;
                Tls(tls_stream)
            }
            None => Plain(stream),
        })
    }

    async fn parse_request_headers(
        &self,
        client_read: &mut (impl AsyncRead + Unpin),
    ) -> Result<(Vec<u8>, Option<String>), ProxyError> {
        let mut headers = Vec::new();
        let mut host = None;
        let mut reader = BufReader::new(client_read);
        let mut line = String::new();

        while let Ok(n) = reader.read_line(&mut line).await {
            if n == 0 || line == "\r\n" {
                break;
            }
            if line.to_lowercase().starts_with("host:") {
                host = line.split(':').nth(1).map(|s| s.trim().to_string());
            }
            headers.extend_from_slice(line.as_bytes());
            line.clear();
        }

        Ok((headers, host))
    }

    async fn handle_rate_limit_response(
        &self,
        client_write: &mut (impl AsyncWrite + Unpin),
    ) -> Result<(), ProxyError> {
        let response = if let Some(ref page) = self.rate_limit_page {
            let body = page.as_bytes();
            let content_length = body.len();
            format!(
                "HTTP/1.1 429 Too Many Requests\r\n\
                 Content-Type: text/html\r\n\
                 Content-Length: {}\r\n\r\n{}",
                content_length,
                String::from_utf8_lossy(body)
            ).into_bytes()
        } else {
            let body = "Rate Limit Exceeded".as_bytes();
            let content_length = body.len();
            format!(
                "HTTP/1.1 429 Too Many Requests\r\n\
                 Content-Type: text/plain\r\n\
                 Content-Length: {}\r\n\r\n{}",
                content_length,
                String::from_utf8_lossy(body)
            ).into_bytes()
        };

        let response = self.modify_response_headers(response).await;
        client_write.write_all(&response).await?;
        Ok(())
    }

    async fn handle_proxy_connection(
        &self,
        mut client_read: impl AsyncRead + Unpin,
        mut client_write: impl AsyncWrite + Unpin,
        host: Option<String>,
    ) -> Result<(), ProxyError> {
        let backend = self.get_least_loaded_backend(host.as_deref()).await
            .ok_or(ProxyError::NoBackend)?;

        {
            let mut counter = backend.active_connections.write().await;
            *counter += 1;
        }

        let server = TcpStream::connect(&backend.address).await?;
        let (mut server_read, mut server_write) = server.into_split();

        let result = self.proxy_data(
            &mut client_read,
            &mut client_write,
            &mut server_read,
            &mut server_write,
        ).await;

        {
            let mut counter = backend.active_connections.write().await;
            *counter -= 1;
        }

        result
    }

    async fn proxy_data(
        &self,
        client_read: &mut (impl AsyncRead + Unpin),
        client_write: &mut (impl AsyncWrite + Unpin),
        server_read: &mut (impl AsyncRead + Unpin),
        server_write: &mut (impl AsyncWrite + Unpin),
    ) -> Result<(), ProxyError> {
        let client_to_server = tokio::io::copy(client_read, server_write);
        let server_to_client = self.handle_server_response(server_read, client_write);

        let (client_result, server_result) = tokio::join!(client_to_server, server_to_client);
        client_result.map_err(ProxyError::from)?;
        server_result.map_err(ProxyError::from)?;
        Ok(())
    }

    async fn handle_server_response(
        &self,
        server_read: &mut (impl AsyncRead + Unpin),
        client_write: &mut (impl AsyncWrite + Unpin),
    ) -> Result<(), ProxyError> {
        let mut server_reader = BufReader::new(server_read);
        let mut buffer = Vec::new();
        let mut line = String::new();
        let mut found_end = false;

        loop {
            line.clear();
            if server_reader.read_line(&mut line).await? == 0 {
                break;
            }
            if line == "\r\n" {
                found_end = true;
                break;
            }

            if line.to_lowercase().starts_with("server:") {
                match &self.server_header {
                    Some(new_header) if !new_header.is_empty() => {
                        buffer.extend_from_slice(format!("Server: {}\r\n", new_header).as_bytes());
                    }
                    Some(_) => (),
                    None => buffer.extend_from_slice(line.as_bytes()),
                }
            } else {
                buffer.extend_from_slice(line.as_bytes());
            }
        }

        if let Some(header) = &self.server_header {
            if !header.is_empty() {
                buffer.extend_from_slice(format!("Server: {}\r\n", header).as_bytes());
            }
        }

        if found_end {
            buffer.extend_from_slice(b"\r\n");
        }

        client_write.write_all(&buffer).await?;
        tokio::io::copy(&mut server_reader, client_write).await?;
        Ok(())
    }

    async fn handle_connection(&self, stream: TcpStream) -> Result<(), ProxyError> {
        let peer_addr = stream.peer_addr().map_err(ProxyError::Io)?;
        let ip = peer_addr.ip().to_string();

        // Check IP whitelist
        if !self.check_ip_whitelist(&ip).await? {
            return Ok(());
        }

        // Handle TLS if configured
        let stream = self.setup_tls_stream(stream).await?;
        let (mut client_read, mut client_write) = stream.into_split().await;

        // Parse request headers
        let (_headers, host) = self.parse_request_headers(&mut client_read).await?;

        // Check rate limiting
        if self.check_rate_limit(&ip).await.map_err(|e| ProxyError::Other(e.to_string()))? {
            self.handle_rate_limit_response(&mut client_write).await?;
            return Ok(());
        }

        // Get backend and handle proxying
        self.handle_proxy_connection(client_read, client_write, host).await?;

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", LOGO);

    let args = Args::parse();

    let runtime = Handle::current();
    let redis_url = format!("redis://{}/", args.redis);
    let lb = Arc::new(LoadBalancer::new(&redis_url, &args).await?);

    let updater_lb = lb.clone();
    runtime.spawn(async move {
        updater_lb.run_updaters().await;
    });

    let listener = TcpListener::bind(&args.bind).await?;
    println!(
        "Listening on {}://{}",
        if lb.tls_acceptor.is_some() { "https" } else { "http" },
        args.bind
    );

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