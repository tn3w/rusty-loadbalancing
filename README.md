<p align="center">
    <picture>
        <source height="128" media="(prefers-color-scheme: dark)" srcset="https://github.com/tn3w/rusty-loadbalancing/releases/download/logo/rusty-logo-dark.png">
        <source height="128" media="(prefers-color-scheme: light)" srcset="https://github.com/tn3w/rusty-loadbalancing/releases/download/logo/rusty-logo-light.png">
        <img height="128" alt="Picture from Block Page" src="https://github.com/tn3w/rusty-loadbalancing/releases/download/logo/rusty-logo-light.png">
    </picture>
</p>
<h1 align="center">rusty-loadbalancing</h1>
<h6 align="center">A component of the Rusty toolbox designed for web application security: <a href="https://github.com/tn3w/rusty-loadbalancing">rusty-loadbalancing</a>, <a href="https://github.com/tn3w/rusty-shield">rusty-shield</a></h6>
<p align="center">A fast, efficient, and small load balancing tool written in Rust. It implements a least-connections algorithm and uses Redis for storing server locations.</p>


## 🚀 Installing
1. Install Rust using rust-up (optional): 
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```

2. Clone the git project:
    ```bash
    git clone https://github.com/tn3w/rusty-loadbalancing.git
    ```

3. Move into the project folder:
    ```bash
    cd rusty-loadbalancing
    ```

4. Setup Redis
    ```bash
    sudo apt-get update
    sudo apt-get install redis -y
    sudo systemctl enable redis-server.service
    sudo systemctl start redis-server.service
    ```

5. Build rusty-loadbalancing
    ```bash
    cargo build --release
    ```

6. Run rusty-loadbalancing
    ```bash
    ./target/release/rusty-loadbalancing --help
    ```

## CLI
```
Usage: rusty-loadbalancing [OPTIONS] --bind <BIND>

Options:
  -b, --bind <BIND>                        
  -w, --workers <WORKERS>                  [default: 1]
  -r, --redis <REDIS>                      [default: 127.0.0.1:6379]
      --https                              
      --cert-file <CERT_FILE>              
      --key-file <KEY_FILE>                
      --rate-limit <RATE_LIMIT>            
      --rate-limit-page <RATE_LIMIT_PAGE>  
      --server-header [<SERVER_HEADER>]    
  -h, --help                               Print help
  -V, --version                            Print version
```

### Backend Server Mapping
You can configure separate backend server lists for different hosts or IP addresses making requests to the server. For example, using `rusty:backend_servers:test.example.com`, all requests to `test.example.com` will use the origins defined in that Redis list. If no specific match for a host or IP address is found, the rusty:backend_servers list serves as the default. Each backend_servers list follows an isolatet least-connections principle.

Example:
```bash
redis-cli RPUSH rusty:backend_servers:test.example.com "127.0.0.1:8080"
redis-cli RPUSH rusty:backend_servers:www.example.com "127.0.0.1:5000"
```

### IP Allowlist / Network Whitelisting
Configure the `rusty:whitelisted_ips` list with IPv4 or IPv6 network addresses, such as 103.21.244.0/22 or 2400:cb00::/32 (Cloudflare). When this list is present, it can be used to block all connections from IP addresses outside the specified network ranges. For domains using Cloudflare as a front, the relevant IPs can be found [here for IPv4](https://www.cloudflare.com/ips-v4) and [here for IPv6](https://www.cloudflare.com/ips-v6).

Example:
```bash
redis-cli RPUSH rusty:whitelisted_ips "103.21.244.0/22"
redis-cli RPUSH rusty:whitelisted_ips "2400:cb00::/32"
```

## Examples
Commands using redis-cli:
```bash
# Add backend server
redis-cli RPUSH rusty:backend_servers "localhost:8081"

# Remove backend server 
redis-cli LREM rusty:backend_servers 0 "localhost:8081"

# List backends
redis-cli LRANGE rusty:backend_servers 0 -1
```

Python code example:
```python
import redis

r = redis.Redis(host='localhost', port=6379)

# Add backend server
r.rpush('rusty:backend_servers', 'localhost:8081')

# Remove backend server
r.lrem('rusty:backend_servers', 0, 'localhost:8081')

# List backends
servers = r.lrange('rusty:backend_servers', 0, -1)
for server in servers:
    print(server.decode())
```

This process can be initiated when the web server starts up, adding it to the list, and it can be removed from the list upon termination.

### Attribution
- Logo icon: [Rust icons created by Freepik - Flaticon](https://www.flaticon.com/free-icons/rust)
