<p align="center">
    <picture>
        <source height="128" media="(prefers-color-scheme: dark)" srcset="https://github.com/tn3w/rusty-loadbalancing/releases/download/logo/rusty-logo-dark.png">
        <source height="128" media="(prefers-color-scheme: light)" srcset="https://github.com/tn3w/rusty-loadbalancing/releases/download/logo/rusty-logo-light.png">
        <img height="128" alt="Picture" src="https://github.com/tn3w/rusty-loadbalancing/releases/download/logo/rusty-logo-light.png">
    </picture>
</p>
<h1 align="center">rusty-loadbalancing</h1>
<h6 align="center">A component of the Rusty toolbox designed for web application security: <a href="https://github.com/tn3w/rusty-loadbalancing">rusty-loadbalancing</a>, <a href="https://github.com/tn3w/rusty-shield">rusty-shield</a></h6>
<p align="center">A fast, efficient, and small load balancing tool written in Rust. It implements a least-connections algorithm and uses Redis for storing server locations.</p>


## Content Table
- [Content Table](#content-table)
- [Installing](#installing)
    - [Quick commands](#quick-commands)
- [Documentation](#documentation)
    - [CLI](#cli)
    - [Backend Server Mapping](#backend-server-mapping)
    - [IP Allowlist / Network Whitelisting](#ip-allowlist--network-whitelisting)
    - [Examples](#examples)
- [Attribution](#attribution)


## Installing
1. Install Rust using rust-up (optional):

    Install curl (optional):
    ```bash
    sudo apt-get update
    sudo apt-get install curl -y
    ``` 

    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    export PATH="$HOME/.cargo/bin:$PATH"
    ```

2. Setup Redis

    **Use the standard repository:**
    ```bash
    sudo apt-get update
    sudo apt-get install redis -y
    ```

    **OR build Redis from source:**

    Install build-essentials (optional):
    ```bash
    sudo apt-get update
    sudo apt-get install build-essential -y
    ```

    Build Redis from source:
    ```bash
    sudo curl -o redis-stable.tar.gz https://download.redis.io/redis-stable.tar.gz
    sudo tar -xzvf redis-stable.tar.gz
    cd redis-stable
    sudo make install
    redis-server & # or setup services
    ```

    **AND setup services: (optional)**
    ```bash
    sudo bash -c 'cat > /etc/systemd/system/redis.service <<EOF
    [Unit]
    Description=Redis In-Memory Data Store
    After=network.target

    [Service]
    User=redis
    Group=redis
    ExecStart=/usr/local/bin/redis-server /etc/redis/redis.conf
    ExecStop=/usr/local/bin/redis-cli shutdown
    Restart=always

    [Install]
    WantedBy=multi-user.target
    EOF'
    sudo systemctl daemon-reload
    sudo systemctl enable redis
    sudo systemctl start redis
    ```

3. Clone the git project:

    Install git (optional):
    ```bash
    sudo apt-get update
    sudo apt-get install git -y
    ``` 

    ```bash
    sudo git clone https://github.com/tn3w/rusty-loadbalancing.git
    ```

4. Move into the project folder:
    ```bash
    cd rusty-loadbalancing
    ```

5. Build rusty-loadbalancing

    Install git (optional):
    ```bash
    sudo apt-get update
    sudo apt-get install cargo -y
    ``` 

    ```bash
    sudo cargo build --release
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
    sudo rm redis-stable.tar.gz
    sudo rm -rf redis-stable
    sudo rm -rf rusty-loadbalancing
    ```

    Remove rust, cargo, build-essentials, curl and git:
    ```
    sudo apt purge rust cargo build-essential curl git -y
    sudo apt autoremove
    ```

### Quick commands 
Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install git curl build-essential -y
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.bashrc
export PATH="$HOME/.cargo/bin:$PATH"

sudo curl -o redis-stable.tar.gz https://download.redis.io/redis-stable.tar.gz
sudo tar -xzvf redis-stable.tar.gz; cd redis-stable
sudo make install
sudo bash -c 'cat > /etc/systemd/system/redis.service <<EOF
[Unit]
Description=Redis In-Memory Data Store
After=network.target

[Service]
User=redis
Group=redis
ExecStart=/usr/local/bin/redis-server /etc/redis/redis.conf
ExecStop=/usr/local/bin/redis-cli shutdown
Restart=always

[Install]
WantedBy=multi-user.target
EOF'
sudo systemctl daemon-reload
sudo systemctl enable redis
sudo systemctl start redis
cd ..
sudo rm redis-stable.tar.gz
sudo rm -rf redis-stable

sudo git clone https://github.com/tn3w/rusty-loadbalancing.git
cd rusty-loadbalancing
sudo cargo build --release
sudo cp ./target/release/rusty-loadbalancing /usr/local/bin/rusty-loadbalancing
cd ..
sudo rm -rf rusty-loadbalancing

rusty-loadbalancing --help
```

Fedora:
```bash
sudo dnf update -y; sudo dnf groupinstall "Development Tools" -y; sudo dnf install git curl -y; curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh; sudo curl -o redis-stable.tar.gz https://download.redis.io/redis-stable.tar.gz; sudo tar -xzvf redis-stable.tar.gz; cd redis-stable; sudo make install; sudo systemctl enable redis-server.service; sudo systemctl start redis-server.service; cd ..; sudo rm redis-stable.tar.gz; sudo rm -rf redis-stable; sudo git clone https://github.com/tn3w/rusty-loadbalancing.git; cd rusty-loadbalancing; cargo build --release; sudo cp ./target/release/rusty-loadbalancing /usr/local/bin/rusty-loadbalancing; cd ..; sudo rm -rf rusty-loadbalancing; rusty-loadbalancing --help
```

CentOS/RHEL
```bash
sudo yum update -y; sudo yum groupinstall "Development Tools" -y; sudo yum install git curl -y; curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh; sudo curl -o redis-stable.tar.gz https://download.redis.io/redis-stable.tar.gz; sudo tar -xzvf redis-stable.tar.gz; cd redis-stable; sudo make install; sudo systemctl enable redis-server.service; sudo systemctl start redis-server.service; cd ..; sudo rm redis-stable.tar.gz; sudo rm -rf redis-stable; sudo git clone https://github.com/tn3w/rusty-loadbalancing.git; cd rusty-loadbalancing; cargo build --release; sudo cp ./target/release/rusty-loadbalancing /usr/local/bin/rusty-loadbalancing; cd ..; sudo rm -rf rusty-loadbalancing; rusty-loadbalancing --help
```

Arch Linux
```bash
sudo pacman -Syu --noconfirm; sudo pacman -S --noconfirm base-devel curl git; curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh; sudo curl -o redis-stable.tar.gz https://download.redis.io/redis-stable.tar.gz; sudo tar -xzvf redis-stable.tar.gz; cd redis-stable; sudo make install; sudo systemctl enable redis-server.service; sudo systemctl start redis-server.service; cd ..; sudo rm redis-stable.tar.gz; sudo rm -rf redis-stable; sudo git clone https://github.com/tn3w/rusty-loadbalancing.git; cd rusty-loadbalancing; cargo build --release; sudo cp ./target/release/rusty-loadbalancing /usr/local/bin/rusty-loadbalancing; cd ..; sudo rm -rf rusty-loadbalancing; rusty-loadbalancing --help
```

openSUSE
```bash
sudo zypper refresh; sudo zypper install -y gcc make curl git; curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh; sudo curl -o redis-stable.tar.gz https://download.redis.io/redis-stable.tar.gz; sudo tar -xzvf redis-stable.tar.gz; cd redis-stable; sudo make install; sudo systemctl enable redis-server.service; sudo systemctl start redis-server.service; cd ..; sudo rm redis-stable.tar.gz; sudo rm -rf redis-stable; sudo git clone https://github.com/tn3w/rusty-loadbalancing.git; cd rusty-loadbalancing; cargo build --release; sudo cp ./target/release/rusty-loadbalancing /usr/local/bin/rusty-loadbalancing; cd ..; sudo rm -rf rusty-loadbalancing; rusty-loadbalancing --help
```

Windows Powershell:
```powershell
# Allow running scripts from untrusted source temporarily
Set-ExecutionPolicy Bypass -Scope Process -Force

# Set SecurityProtocol to include TLS 1.2 temporarily
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072

# Install Chocolatey (if not already installed)
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

# Update Chocolatey and curl, git, make and redis
choco upgrade chocolatey -y
choco install curl git make redis-64 -y

# Start Redis as a background service
redis-server --service-install
redis-server --service-start

# Install Rust using rustup
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://sh.rustup.rs')) -NoProfile

# Clone and build the rusty-loadbalancing project
git clone https://github.com/tn3w/rusty-loadbalancing.git
cd rusty-loadbalancing
cargo build --release

# Move the executable to a directory in the PATH
Move-Item .\target\release\rusty-loadbalancing.exe "C:\Program Files\rusty-loadbalancing.exe"

# Clean up the cloned repository
cd ..
Remove-Item -Recurse -Force rusty-loadbalancing

# Test the executable
rusty-loadbalancing --help
```

macOS:
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Update Homebrew and install dependencies
brew update
brew install curl curl rust git redis

# Set up Redis
brew services start redis

# Clone and build the project
sudo git clone https://github.com/tn3w/rusty-loadbalancing.git
cd rusty-loadbalancing
cargo build --release

# Move the binary to a location in PATH
sudo cp ./target/release/rusty-loadbalancing /usr/local/bin/rusty-loadbalancing
cd ..
sudo rm -rf rusty-loadbalancing

# Verify installation
rusty-loadbalancing --help
```

## Documentation
### CLI
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

### Examples
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

## Attribution
- Logo icon: [Rust icons created by Freepik - Flaticon](https://www.flaticon.com/free-icons/rust)
