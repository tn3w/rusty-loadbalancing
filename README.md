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

2. Setup Redis

    **Use the standard repository:**
    ```bash
    sudo apt-get update
    sudo apt-get install redis -y
    ```

    **OR build Redis from source:**

    Install wget and build-essentials (optional):
    ```bash
    sudo apt-get update
    sudo apt-get install wget build-essential -y
    ```

    Build Redis from source:
    ```bash
    wget https://download.redis.io/redis-stable.tar.gz
    tar -xzvf redis-stable.tar.gz
    cd redis-stable
    sudo make install
    redis-server & # or setup services
    ```

    **And setup services: (optional)**
    ```bash
    sudo systemctl enable redis-server.service
    sudo systemctl start redis-server.service
    ```

3. Clone the git project:
    ```bash
    git clone https://github.com/tn3w/rusty-loadbalancing.git
    ```

4. Move into the project folder:
    ```bash
    cd rusty-loadbalancing
    ```

5. Build rusty-loadbalancing
    ```bash
    cargo build --release
    ```

6. Move executable into /usr/local/bin (optional)
    ```bash
    sudo cp ./target/release/rusty-loadbalancing /usr/local/bin/rusty-loadbalancing
    ```

7. Run rusty-loadbalancing
    ```bash
    ./target/release/rusty-loadbalancing --help
    ```

    OR:
    ```bash
    rusty-loadbalancing --help
    ```

8. Cleaning up (optional):
    ```bash
    rm redis-stable.tar.gz
    sudo rm -rf redis-stable
    rm -rf rusty-loadbalancing
    ```

    Remove rust, cargo, build-essentials and wget:
    ```
    sudo apt purge rust cargo build-essential wget -y
    sudo apt autoremove
    ```

Quick command (for Ubuntu/Debian):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh; sudo apt-get update; sudo apt-get install wget build-essential -y; wget https://download.redis.io/redis-stable.tar.gz; tar -xzvf redis-stable.tar.gz; cd redis-stable; sudo make install; sudo systemctl enable redis-server.service; sudo systemctl start redis-server.service; cd ..; rm redis-stable.tar.gz; sudo rm -rf redis-stable; git clone https://github.com/tn3w/rusty-loadbalancing.git; cd rusty-loadbalancing; cargo build --release; sudo cp ./target/release/rusty-loadbalancing /usr/local/bin/rusty-loadbalancing; cd ..; rm -rf rusty-loadbalancing; rusty-loadbalancing --help
```


## CLI
```
░░       ░░░  ░░░░  ░░░      ░░░        ░░  ░░░░  ░
▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒▒  ▒▒  ▒▒
▓▓       ▓▓▓  ▓▓▓▓  ▓▓▓      ▓▓▓▓▓▓  ▓▓▓▓▓▓▓    ▓▓▓
██  ███  ███  ████  ████████  █████  ████████  ████
██  ████  ███      ████      ██████  ████████  ████
 A fast, efficient, and small load balancing tool.

Author: TN3W
GitHub: https://github.com/tn3w/rusty-loadbalancing

Usage: rusty-loadbalancing [OPTIONS] --bind <BIND>

Options:
  -b, --bind <BIND>
          Address to bind the server to.
  -w, --workers <WORKERS>
          Number of worker threads to use. [default: 1]
  -r, --redis <REDIS>
          Redis server address. [default: 127.0.0.1:6379]
      --https
          Enable HTTPS for secure connections.
      --cert-file <CERT_FILE>
          Path to the SSL certificate file.
      --key-file <KEY_FILE>
          Path to the SSL key file.
      --rate-limit <RATE_LIMIT>
          Rate limit for incoming requests (requests per 10 seconds).
      --rate-limit-page <RATE_LIMIT_PAGE>
          Path to the rate limit configuration page.
      --server-header [<SERVER_HEADER>]
          Value for the Server header in responses (omit if empty).
  -h, --help
          Print help
  -V, --version
          Print version
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
