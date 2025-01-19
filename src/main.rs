use bytes::BytesMut;
use clap::Parser;
use dashmap;
use fastrand;
use futures_util::StreamExt;
use parking_lot::RwLock;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, PKCS_ECDSA_P256_SHA256};
use redis::{aio::ConnectionManager, Client as RedisClient};
use rustls::{Certificate as RustlsCert, PrivateKey, ServerConfig};
use serde::Deserialize;
use siphasher::sip::SipHasher13;
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap},
    fs,
    hash::{Hash, Hasher},
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter},
    net::{TcpListener, TcpStream},
    sync::broadcast,
};
use tokio_rustls::TlsAcceptor;

fn parse_bind_address(s: &str) -> Result<String, String> {
    if s.starts_with(':') {
        return Ok(format!("0.0.0.0{}", s));
    }

    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return Err("Address must be in format 'host:port' or ':port'".to_string());
    }

    let host = if parts[0] == "localhost" {
        "127.0.0.1"
    } else {
        parts[0]
    };
    Ok(format!("{}:{}", host, parts[1]))
}

#[derive(Deserialize, Debug, Clone)]
struct Config {
    bind: Option<String>,
    workers: Option<usize>,
    redis: Option<String>,
    https: Option<bool>,
    cert_file: Option<PathBuf>,
    key_file: Option<PathBuf>,
    rate_limit: Option<u32>,
    rate_limit_page: Option<PathBuf>,
    server_header: Option<String>,
    default_backends: Option<Vec<String>>,
    backends: Option<HashMap<String, Vec<String>>>,
}

#[derive(Parser, Debug, Default)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, value_parser = parse_bind_address, help = "Address to bind the server to.")]
    bind: Option<String>,

    #[arg(
        short,
        long,
        default_value_t = 1,
        help = "Number of worker threads to use."
    )]
    workers: usize,

    #[arg(short, long, value_parser = parse_bind_address, help = "Redis server address.")]
    redis: Option<String>,

    #[arg(long, help = "Enable HTTPS for secure connections.")]
    https: bool,

    #[arg(long, help = "Path to the SSL certificate file.")]
    cert_file: Option<PathBuf>,

    #[arg(long, help = "Path to the SSL key file.")]
    key_file: Option<PathBuf>,

    #[arg(
        long,
        help = "Rate limit for incoming requests (requests per 10 seconds)."
    )]
    rate_limit: Option<u32>,

    #[arg(long, help = "Path to the rate limit configuration page.")]
    rate_limit_page: Option<PathBuf>,

    #[arg(long, num_args = 0..=1, default_missing_value = "", help = "Value for the Server header in responses (omit if empty).")]
    server_header: Option<String>,

    #[arg(short = 'c', long, help = "Path to the configuration file.")]
    config_file: Option<PathBuf>,
}

#[derive(Clone)]
struct Backend {
    address: String,
    active_connections: Arc<RwLock<u32>>,
}

impl Backend {
    fn get_connections(&self) -> u32 {
        *self.active_connections.read()
    }
}

struct BackendGroup {
    backends: Vec<Backend>,
    min_heap: Arc<parking_lot::Mutex<BinaryHeap<Reverse<(u32, usize)>>>>,
}

impl BackendGroup {
    fn new(backends: Vec<Backend>) -> Self {
        let mut min_heap = BinaryHeap::with_capacity(backends.len());
        for (idx, backend) in backends.iter().enumerate() {
            min_heap.push(Reverse((backend.get_connections(), idx)));
        }
        
        BackendGroup {
            backends,
            min_heap: Arc::new(parking_lot::Mutex::new(min_heap)),
        }
    }

    fn get_backend(&self) -> Option<Backend> {
        if self.backends.is_empty() {
            return None;
        }

        let mut heap = self.min_heap.lock();
        
        let min_conns = heap.peek()?.0 .0;
        let mut min_indices = Vec::with_capacity(self.backends.len());
        
        while let Some(Reverse((conns, idx))) = heap.pop() {
            if conns != min_conns {
                heap.push(Reverse((conns, idx)));
                break;
            }
            min_indices.push(idx);
        }

        let selected_idx = min_indices[fastrand::usize(..min_indices.len())];
        let backend = self.backends[selected_idx].clone();

        let new_count = backend.get_connections() + 1;
        for idx in min_indices {
            heap.push(Reverse((
                if idx == selected_idx {
                    new_count
                } else {
                    min_conns
                },
                idx,
            )));
        }

        Some(backend)
    }

    fn release_backend(&self, backend: &Backend) {
        let mut heap = self.min_heap.lock();
        
        let mut entries = Vec::with_capacity(self.backends.len());
        while let Some(Reverse((conns, idx))) = heap.pop() {
            if self.backends[idx].address == backend.address {
                entries.push(Reverse((conns.saturating_sub(1), idx)));
            } else {
                entries.push(Reverse((conns, idx)));
            }
        }
        
        for entry in entries {
            heap.push(entry);
        }
    }
}

struct RateLimiter {
    requests: Arc<dashmap::DashMap<u64, Vec<SystemTime>>>,
    limit: u32,
    window: Duration,
    error_page: Option<String>,
    salt: [u8; 16],
    server_header: Option<String>,
}

impl RateLimiter {
    fn new(
        limit: u32,
        error_page_path: Option<PathBuf>,
        server_header: Option<String>,
    ) -> Result<Self, String> {
        let error_page = if let Some(path) = error_page_path {
            Some(
                fs::read_to_string(path)
                    .map_err(|e| format!("Failed to read rate limit page: {}", e))?,
            )
        } else {
            None
        };

        let mut salt = [0u8; 16];
        fastrand::fill(&mut salt);

        Ok(RateLimiter {
            requests: Arc::new(dashmap::DashMap::with_capacity(1024)),
            limit: limit + ((limit * 40) / 100),
            window: Duration::from_secs(10),
            error_page,
            salt,
            server_header,
        })
    }

    #[inline]
    fn hash_ip(&self, ip: IpAddr) -> u64 {
        let mut hasher = SipHasher13::new_with_keys(
            u64::from_le_bytes(self.salt[0..8].try_into().unwrap()),
            u64::from_le_bytes(self.salt[8..16].try_into().unwrap()),
        );
        ip.hash(&mut hasher);
        hasher.finish()
    }

    fn is_rate_limited(&self, ip: IpAddr) -> bool {
        let now = SystemTime::now();
        let ip_hash = self.hash_ip(ip);

        let mut is_limited = false;
        self.requests
            .entry(ip_hash)
            .and_modify(|timestamps| {
                let window = self.window;
            timestamps.retain(|&time| {
                if let Ok(elapsed) = time.elapsed() {
                        elapsed <= window
                } else {
                    false
                }
            });

                if timestamps.len() >= self.limit as usize {
                    is_limited = true;
        } else {
                    timestamps.push(now);
                }
            })
            .or_insert_with(|| {
                let mut timestamps = Vec::with_capacity(self.limit as usize);
                timestamps.push(now);
                timestamps
            });

        is_limited
    }

    fn get_error_response(&self) -> Vec<u8> {
        let status_line = "HTTP/1.1 429 Too Many Requests\r\n";
        let content = self.error_page.as_deref().unwrap_or("Rate limit exceeded");
        
        let mut response = Vec::with_capacity(
            status_line.len() + content.len() + 100,
        );

        response.extend_from_slice(status_line.as_bytes());

        response.extend_from_slice(b"Content-Type: text/html\r\n");
        response.extend_from_slice(b"Content-Length: ");
        response.extend_from_slice(content.len().to_string().as_bytes());
        response.extend_from_slice(b"\r\nConnection: close\r\n");
        
        if let Some(server) = &self.server_header {
            if !server.is_empty() {
                response.extend_from_slice(b"Server: ");
                response.extend_from_slice(server.as_bytes());
                response.extend_from_slice(b"\r\n");
            }
        }
        
        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(content.as_bytes());
        response
    }
}

struct LoadBalancer {
    redis_client: RedisClient,
    default_backends: Arc<RwLock<BackendGroup>>,
    backend_groups: Arc<RwLock<HashMap<String, BackendGroup>>>,
    shutdown: broadcast::Sender<()>,
    tls_acceptor: Option<TlsAcceptor>,
    server_header: Option<String>,
    rate_limiter: Option<RateLimiter>,
}

trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

#[derive(Debug)]
enum ProxyError {
    Io(std::io::Error),
    Join(tokio::task::JoinError),
    Other(String),
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::Io(e) => write!(f, "IO error: {}", e),
            ProxyError::Join(e) => write!(f, "Task join error: {}", e),
            ProxyError::Other(e) => write!(f, "{}", e),
        }
    }
}

impl From<std::io::Error> for ProxyError {
    fn from(err: std::io::Error) -> Self {
        ProxyError::Io(err)
    }
}

impl From<tokio::task::JoinError> for ProxyError {
    fn from(err: tokio::task::JoinError) -> Self {
        ProxyError::Join(err)
    }
}

impl From<String> for ProxyError {
    fn from(err: String) -> Self {
        ProxyError::Other(err)
    }
}

impl From<ProxyError> for String {
    fn from(err: ProxyError) -> Self {
        err.to_string()
    }
}

impl LoadBalancer {
    pub async fn new(
        args: &Args,
        default_backends: Option<Vec<String>>,
        backend_groups: Option<HashMap<String, Vec<String>>>,
    ) -> Result<Self, String> {
        let redis_url = if let Some(ref redis_url) = args.redis {
            redis_url.clone()
        } else {
            parse_bind_address(":6379")?
        };

        let redis_client = RedisClient::open(format!("redis://{}", redis_url))
            .map_err(|e| format!("Failed to create Redis client: {}", e))?;

        let (shutdown_tx, _) = broadcast::channel(1);
        
        let tls_acceptor = if args.https {
            Some(
                setup_tls(&Args {
                cert_file: args.cert_file.clone(),
                key_file: args.key_file.clone(),
                ..Args::default()
                })
                .map_err(|e| format!("Failed to setup TLS: {}", e))?,
            )
        } else {
            None
        };

        let rate_limiter = if let Some(limit) = args.rate_limit {
            Some(RateLimiter::new(
                limit,
                args.rate_limit_page.clone(),
                args.server_header.clone(),
            )?)
        } else {
            None
        };

        let lb = LoadBalancer {
            redis_client,
            default_backends: Arc::new(RwLock::new(BackendGroup::new(Vec::new()))),
            backend_groups: Arc::new(RwLock::new(HashMap::new())),
            shutdown: shutdown_tx,
            tls_acceptor,
            server_header: args.server_header.clone(),
            rate_limiter,
        };

        if let Some(default_backends) = default_backends {
            let default_group = BackendGroup::new(
                default_backends
                    .into_iter()
                .map(|address| -> Result<Backend, String> {
                    Ok(Backend {
                        address: parse_bind_address(&address)?,
                        active_connections: Arc::new(RwLock::new(0)),
                    })
                })
                    .collect::<Result<Vec<_>, _>>()?,
            );
            *lb.default_backends.write() = default_group;
        }

        if let Some(backend_groups) = backend_groups {
            let mut groups = HashMap::new();
            for (host, backends) in backend_groups {
                let group = BackendGroup::new(
                    backends
                        .into_iter()
                    .map(|address| -> Result<Backend, String> {
                        Ok(Backend {
                            address: parse_bind_address(&address)?,
                            active_connections: Arc::new(RwLock::new(0)),
                        })
                    })
                        .collect::<Result<Vec<_>, _>>()?,
                );
                groups.insert(host, group);
            }
            *lb.backend_groups.write() = groups;
        }

        if args.redis.is_some() {
            lb.update_backends().await?;
            lb.start_redis_listener();
        }
        
        Ok(lb)
    }

    fn start_redis_listener(&self) {
        let redis_client = self.redis_client.clone();
        let default_backends = self.default_backends.clone();
        let backend_groups = self.backend_groups.clone();
        let mut shutdown_rx = self.shutdown.subscribe();

        tokio::spawn(async move {
            let mut pubsub = match redis_client.get_async_connection().await {
                Ok(conn) => conn.into_pubsub(),
                Err(e) => {
                    tracing::error!("Failed to create Redis PubSub connection: {}", e);
                    return;
                }
            };

            if let Err(e) = pubsub
                .psubscribe("__keyspace@*__:rusty:backend_servers*")
                .await
            {
                tracing::error!("Failed to subscribe to Redis keyspace events: {}", e);
                return;
            }

            let mut msg_stream = pubsub.on_message();
            
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                    Some(_msg) = msg_stream.next() => {
                        let lb = LoadBalancer {
                            redis_client: redis_client.clone(),
                            default_backends: default_backends.clone(),
                            backend_groups: backend_groups.clone(),
                            shutdown: broadcast::channel(1).0,
                            tls_acceptor: None,
                            server_header: None,
                            rate_limiter: None,
                        };
                        if let Err(e) = lb.update_backends().await {
                            tracing::error!("Failed to update backends: {}", e);
                        }
                    }
                }
            }
        });
    }

    async fn update_backends(&self) -> Result<(), String> {
        let mut conn = ConnectionManager::new(self.redis_client.clone())
            .await
            .map_err(|e| e.to_string())?;
        
        let mut keys: Vec<String> = redis::cmd("KEYS")
            .arg("rusty:backend_servers*")
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;
        keys.sort();

        let mut new_groups = HashMap::new();

        let default_backends: Vec<String> = redis::cmd("LRANGE")
            .arg("rusty:backend_servers")
            .arg(0)
            .arg(-1)
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;

        let default_group = BackendGroup::new(
            default_backends
                .into_iter()
            .map(|address| -> Result<Backend, String> {
                Ok(Backend {
                    address: parse_bind_address(&address)?,
                    active_connections: Arc::new(RwLock::new(0)),
                })
            })
                .collect::<Result<Vec<_>, _>>()?,
        );
        *self.default_backends.write() = default_group;

        for key in keys {
            if key == "rusty:backend_servers" {
                continue;
            }

            let host = key
                .strip_prefix("rusty:backend_servers:")
                .unwrap_or("")
                .to_string();

            if !host.is_empty() {
                let backend_list: Vec<String> = redis::cmd("LRANGE")
                    .arg(&key)
                    .arg(0)
                    .arg(-1)
                    .query_async(&mut conn)
                    .await
                    .map_err(|e| e.to_string())?;

                if !backend_list.is_empty() {
                    let group = BackendGroup::new(
                        backend_list
                            .into_iter()
                        .map(|address| -> Result<Backend, String> {
                            Ok(Backend {
                                address: parse_bind_address(&address)?,
                                active_connections: Arc::new(RwLock::new(0)),
                            })
                        })
                            .collect::<Result<Vec<_>, _>>()?,
                    );
                    new_groups.insert(host, group);
                }
            }
        }

        *self.backend_groups.write() = new_groups;
        Ok(())
    }

    pub fn get_backend(&self, host: Option<&str>) -> Option<Backend> {
        let backend_groups = self.backend_groups.read();
        let backends = if let Some(host) = host {
            if let Some(group) = backend_groups.get(host) {
                group.get_backend()
            } else {
                self.default_backends.read().get_backend()
            }
        } else {
            self.default_backends.read().get_backend()
        };

        backends
    }

    pub async fn shutdown(&self) {
        let _ = self.shutdown.send(());
    }

    async fn handle_connection(&self, mut stream: TcpStream) -> Result<(), String> {
        let remote_addr = stream
            .peer_addr()
            .map_err(|e| format!("Failed to get peer address: {}", e))?;

        if let Some(rate_limiter) = &self.rate_limiter {
            if rate_limiter.is_rate_limited(remote_addr.ip()) {
                if let Some(tls_acceptor) = &self.tls_acceptor {
                    let mut peek_buf = [0u8; 1];
                    if let Ok(1) = stream.peek(&mut peek_buf).await {
                        if peek_buf[0] == 0x16 {
                            if let Ok(mut tls_stream) = tls_acceptor.accept(stream).await {
                                let response = rate_limiter.get_error_response();
                                let _ = tls_stream.write_all(&response).await;
                            }
                        }
                    }
                } else {
                    let response = rate_limiter.get_error_response();
                    let _ = stream.write_all(&response).await;
                }
                return Ok(());
            }
        }

        if let Some(tls_acceptor) = &self.tls_acceptor {
            let mut peek_buf = [0u8; 1];
            if let Ok(1) = stream.peek(&mut peek_buf).await {
                if peek_buf[0] != 0x16 {
                    return Ok(());
                }
            }
            
            match tls_acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    return self.handle_stream(Box::new(tls_stream)).await;
                }
                Err(_) => {
                    return Ok(());
                }
            }
        }

        return self.handle_stream(Box::new(stream)).await;
    }

    async fn handle_stream(&self, stream: Box<dyn AsyncStream>) -> Result<(), String> {
        let (reader, writer) = tokio::io::split(stream);
        let mut reader = BufReader::with_capacity(32 * 1024, reader);
        let mut writer = BufWriter::with_capacity(32 * 1024, writer);
        
        let mut buf = BytesMut::with_capacity(32 * 1024);
        let bytes_read = reader.read_buf(&mut buf).await
            .map_err(|e| format!("Failed to read from stream: {}", e))?;

        if bytes_read == 0 {
            return Ok(());
        }

        let request_data = &buf[..bytes_read];
        let request_str = String::from_utf8_lossy(request_data);
        let mut host = None;

        for line in request_str.lines() {
            if line.to_lowercase().starts_with("host:") {
                host = Some(line.split(':').nth(1)
                    .map(|s| s.trim())
                    .unwrap_or("")
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .to_string());
                break;
            }
            
            if line.is_empty() {
                break;
            }
        }
        
        let backend = self.get_backend(host.as_deref())
            .ok_or_else(|| "No backend servers available".to_string())?;
                
        let mut backend_stream = TcpStream::connect(&backend.address).await
            .map_err(|e| format!("Failed to connect to backend {}: {}", backend.address, e))?;
        backend_stream.set_nodelay(true)
            .map_err(|e| format!("Failed to set TCP_NODELAY: {}", e))?;

        backend_stream.write_all(&buf).await
            .map_err(|e| format!("Failed to write request to backend: {}", e))?;

        let (backend_reader, _) = backend_stream.into_split();
        let mut backend_reader = BufReader::with_capacity(32 * 1024, backend_reader);
        
        let mut response_buf = BytesMut::with_capacity(32 * 1024);
        let mut found_server = false;
        
        loop {
            let bytes_read = backend_reader.read_buf(&mut response_buf).await
                .map_err(|e| format!("Failed to read from backend: {}", e))?;
            
            if bytes_read == 0 {
                if response_buf.is_empty() {
                    return Err("Backend closed connection without sending response".to_string());
                }
                break;
            }

            if let Some(pos) = find_headers_end(&response_buf) {
                let headers = String::from_utf8_lossy(&response_buf[..pos]);
                let mut modified_headers = Vec::new();
                
                for line in headers.lines() {
                    if line.to_lowercase().starts_with("server:") {
                        found_server = true;
                        if let Some(server_value) = &self.server_header {
                            if !server_value.is_empty() {
                                modified_headers.push(format!("Server: {}", server_value));
                            }
                        } else {
                            modified_headers.push(line.to_string());
                        }
                    } else {
                        modified_headers.push(line.to_string());
                    }
                }

                if !found_server && self.server_header.as_ref().map_or(false, |s| !s.is_empty()) {
                    modified_headers.push(format!("Server: {}", self.server_header.as_ref().unwrap()));
                }

                let modified_response = modified_headers.join("\r\n") + "\r\n\r\n";
                writer.write_all(modified_response.as_bytes()).await
                    .map_err(|e| format!("Failed to write headers to client: {}", e))?;

                if response_buf.len() > pos {
                    writer.write_all(&response_buf[pos..]).await
                        .map_err(|e| format!("Failed to write body to client: {}", e))?;
                }
                
                break;
            }
        }

        let mut buf = BytesMut::with_capacity(32 * 1024);
        loop {
            buf.clear();
            let bytes_read = backend_reader.read_buf(&mut buf).await
                .map_err(|e| format!("Failed to read from backend: {}", e))?;
            
            if bytes_read == 0 {
                break;
            }
            
            writer.write_all(&buf[..bytes_read]).await
                .map_err(|e| format!("Failed to write to client: {}", e))?;
        }
        
        writer.flush().await
            .map_err(|e| format!("Failed to flush response to client: {}", e))?;

        if let Some(group) = self.backend_groups.read().get(&host.unwrap_or_default()) {
            group.release_backend(&backend);
        } else {
            self.default_backends.read().release_backend(&backend);
        }

        Ok(())
    }
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    let mut pos = 0;
    while pos + 4 <= buf.len() {
        if &buf[pos..pos + 4] == b"\r\n\r\n" {
            return Some(pos + 4);
        }
        pos += 1;
    }
    None
}

fn setup_tls(args: &Args) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let (cert_pem, key_pem) =
        if let (Some(cert_path), Some(key_path)) = (&args.cert_file, &args.key_file) {
            (
                fs::read_to_string(cert_path)?,
                fs::read_to_string(key_path)?,
            )
    } else {
        println!("Generating self-signed certificate...");
        
        let mut params = CertificateParams::new(vec!["localhost".to_string()]);
        let now = SystemTime::now();
        params.not_before = now.into();
        params.not_after = (now + std::time::Duration::from_secs(365 * 24 * 60 * 60)).into();
        params.alg = &PKCS_ECDSA_P256_SHA256;
        
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "localhost");
        dn.push(DnType::OrganizationName, "Rusty LoadBalancer");
        dn.push(DnType::CountryName, "US");
        params.distinguished_name = dn;
        
        let cert = Certificate::from_params(params)?;
        let cert_pem = cert.serialize_pem()?;
        let key_pem = cert.serialize_private_key_pem();
        
        fs::write("cert.pem", &cert_pem)?;
        fs::write("key.pem", &key_pem)?;
        println!("Self-signed certificate and key saved to cert.pem and key.pem");
        
        (cert_pem, key_pem)
    };

    let cert_chain = rustls_pemfile::certs(&mut cert_pem.as_bytes())?
        .into_iter()
        .map(RustlsCert)
        .collect();

    let key = {
        let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_bytes())?;
        if keys.is_empty() {
            keys = rustls_pemfile::rsa_private_keys(&mut key_pem.as_bytes())?;
        }
        PrivateKey(keys.into_iter().next().ok_or("No private key found")?)
    };

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let args = Args::parse();
    
    let config = if let Some(config_path) = &args.config_file {
        let config_str = fs::read_to_string(config_path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;
        let mut config: Config = toml::from_str(&config_str)
            .map_err(|e| format!("Failed to parse config file: {}", e))?;
        
        if let Some(bind) = config.bind {
            config.bind = Some(parse_bind_address(&bind)?);
        }
        
        if let Some(redis) = config.redis {
            config.redis = Some(parse_bind_address(&redis)?);
        }
        
        config
    } else {
        Config {
            bind: args.bind.clone(),
            workers: Some(args.workers),
            redis: args.redis.clone(),
            https: Some(args.https || (args.cert_file.is_some() && args.key_file.is_some())),
            cert_file: args.cert_file.clone(),
            key_file: args.key_file.clone(),
            rate_limit: args.rate_limit,
            rate_limit_page: args.rate_limit_page.clone(),
            server_header: args.server_header.clone(),
            default_backends: None,
            backends: None,
        }
    };

    let config_clone = config.clone();
    let final_args = Args {
        bind: config.bind,
        workers: config.workers.unwrap_or(1),
        redis: config.redis,
        https: config.https.unwrap_or(false)
            || (config.cert_file.is_some() && config.key_file.is_some()),
        cert_file: config.cert_file,
        key_file: config.key_file,
        rate_limit: config.rate_limit,
        rate_limit_page: config.rate_limit_page,
        server_header: config.server_header,
        config_file: None,
    };

    println!("Config: {:?}", config_clone);

    if let Some(ref backends) = config_clone.default_backends {
        println!("Default backends: {:?}", backends);
    }
    if let Some(ref host_backends) = config_clone.backends {
        println!("Host-specific backends: {:?}", host_backends);
    }

    let load_balancer = Arc::new(
        LoadBalancer::new(
            &final_args,
            config_clone.default_backends,
            config_clone.backends,
        )
        .await?,
    );
    
    let bind_addr = final_args.bind.as_deref().unwrap_or(":8080");
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| format!("Failed to bind to {}: {}", bind_addr, e))?;
    
    println!(
        "Listening on {}://{} with {} workers",
        if load_balancer.tls_acceptor.is_some() {
            "https"
        } else {
            "http"
        },
        bind_addr,
        final_args.workers
    );

    let semaphore = Arc::new(tokio::sync::Semaphore::new(final_args.workers));

    loop {
        tokio::select! {
            Ok((socket, _)) = listener.accept() => {
                let lb = load_balancer.clone();
                let permit = semaphore.clone().acquire_owned().await
                    .map_err(|e| format!("Failed to acquire semaphore: {}", e))?;

                tokio::spawn(async move {
                    if let Err(e) = lb.handle_connection(socket).await {
                        tracing::error!("Error handling connection: {}", e);
                    }
                    drop(permit);
                });
            }
            Ok(()) = tokio::signal::ctrl_c() => {
                println!("Shutting down...");
                load_balancer.shutdown().await;
                break;
            }
        }
    }

    Ok(())
}
