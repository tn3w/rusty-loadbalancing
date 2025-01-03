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
        - [Windows](#windows-powershell)
        - [macOS (not tested)](#macos-not-tested)
        - [Ubuntu/Debian](#ubuntudebian)
        - [Fedora](#fedora)
        - [CentOS/RHEL](#centosrhel)
        - [Arch Linux](#arch-linux)
        - [openSUSE](#opensuse)
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
    sudo adduser --system --group --no-create-home redis
    sudo bash -c 'cat > /etc/systemd/system/redis.service <<EOF
    [Unit]
    Description=Redis In-Memory Data Store
    After=network.target

    [Service]
    User=redis
    Group=redis
    ExecStart=/usr/local/bin/redis-server
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
    git clone https://github.com/tn3w/rusty-loadbalancing.git
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
#### Windows Powershell:
```powershell
cd ~; Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))}; choco upgrade chocolatey -y; choco install git redis -y; $TaskName="Redis Server"; $Action=New-ScheduledTaskAction -Execute "C:\ProgramData\chocolatey\lib\redis\tools\redis-server.exe"; $Trigger=New-ScheduledTaskTrigger -AtStartup; $Principal=New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest; if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue}; Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal; function Is-RedisRunning {Get-Process -Name "redis-server" -ErrorAction SilentlyContinue -ne $null}; if (Is-RedisRunning) {Write-Host "Redis is already running."} else {Start-Process "C:\ProgramData\chocolatey\lib\redis\tools\redis-server.exe" -WindowStyle Hidden; Start-Sleep -Seconds 2; if (-not (Is-RedisRunning)) {Write-Error "Failed to start Redis server."}}; function Is-RustInstalled {& rustc --version 2>$null -match "^rustc"}; if (-not (Is-RustInstalled)) {Invoke-WebRequest https://win.rustup.rs -OutFile rustup-init.exe; Start-Process -FilePath ".\rustup-init.exe" -ArgumentList "-y" -Wait; Remove-Item rustup-init.exe -Force}; function Is-BuildToolsInstalled {& "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath -ne $null}; if (-not (Is-BuildToolsInstalled)) {Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vs_buildtools.exe" -OutFile "vs_buildtools.exe"; Start-Process -FilePath ".\vs_buildtools.exe" -ArgumentList "--quiet", "--norestart", "--nocache", "--installPath", "C:\BuildTools", "--add", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "--add", "Microsoft.VisualStudio.Component.Windows10SDK.19041" -Wait; Remove-Item -Path "vs_buildtools.exe" -Force}; $env:Path=[System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User"); git clone https://github.com/tn3w/rusty-loadbalancing.git; cd rusty-loadbalancing; cargo build --release; Move-Item .\target\release\rusty-loadbalancing.exe "C:\Program Files\rusty-loadbalancing.exe"; cd ..; Remove-Item -Recurse -Force rusty-loadbalancing
```

After using this command you can start the tool with the following command:
```powershell
& "C:\Program Files\rusty-loadbalancing.exe" --help
```

#### macOS (not tested):
```bash
/bin/bash -c "$(command -v brew &>/dev/null || /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\") && brew update && brew install rust git redis && brew services start redis && git clone https://github.com/tn3w/rusty-loadbalancing.git && cd rusty-loadbalancing && cargo build --release && sudo cp ./target/release/rusty-loadbalancing /usr/local/bin/rusty-loadbalancing && cd .. && sudo rm -rf rusty-loadbalancing"
```

After using this command you can start the tool with the following command:
```bash
rusty-loadbalancing --help
```


#### Ubuntu/Debian:
```bash
sudo apt-get update; sudo apt-get install git curl build-essential -y; curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; source ~/.bashrc; sudo curl -o redis-stable.tar.gz https://download.redis.io/redis-stable.tar.gz; sudo tar -xzvf redis-stable.tar.gz; cd redis-stable; sudo make install; sudo adduser --system --group --no-create-home redis; echo -e "[Unit]\nDescription=Redis In-Memory Data Store\nAfter=network.target\n\n[Service]\nUser=redis\nGroup=redis\nExecStart=/usr/local/bin/redis-server\nExecStop=/usr/local/bin/redis-cli shutdown\nRestart=always\n\n[Install]\nWantedBy=multi-user.target" | sudo tee /etc/systemd/system/redis.service > /dev/null; sudo systemctl daemon-reload; sudo systemctl enable redis; sudo systemctl start redis; cd ..; sudo rm redis-stable.tar.gz; sudo rm -rf redis-stable; git clone https://github.com/tn3w/rusty-loadbalancing.git; cd rusty-loadbalancing; cargo build --release; sudo cp ./target/release/rusty-loadbalancing /usr/local/bin/rusty-loadbalancing; cd ..; sudo rm -rf rusty-loadbalancing; rusty-loadbalancing --help
```

After using this command you can start the tool with the following command:
```bash
rusty-loadbalancing --help
```

#### Fedora:
```bash
sudo dnf update -y; sudo dnf groupinstall "Development Tools" -y; sudo dnf install git curl -y; curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; source ~/.bashrc; sudo curl -o redis-stable.tar.gz https://download.redis.io/redis-stable.tar.gz; sudo tar -xzvf redis-stable.tar.gz; cd redis-stable; sudo make install; sudo adduser --system --group --no-create-home redis; echo -e "[Unit]\nDescription=Redis In-Memory Data Store\nAfter=network.target\n\n[Service]\nUser=redis\nGroup=redis\nExecStart=/usr/local/bin/redis-server\nExecStop=/usr/local/bin/redis-cli shutdown\nRestart=always\n\n[Install]\nWantedBy=multi-user.target" | sudo tee /etc/systemd/system/redis.service > /dev/null; sudo systemctl daemon-reload; sudo systemctl enable redis; sudo systemctl start redis; cd ..; sudo rm redis-stable.tar.gz; sudo rm -rf redis-stable; git clone https://github.com/tn3w/rusty-loadbalancing.git; cd rusty-loadbalancing; cargo build --release; sudo cp ./target/release/rusty-loadbalancing /usr/local/bin/rusty-loadbalancing; cd ..; sudo rm -rf rusty-loadbalancing; rusty-loadbalancing --help
```

After using this command you can start the tool with the following command:
```bash
rusty-loadbalancing --help
```

#### CentOS/RHEL
```bash
sudo yum update -y; sudo yum groupinstall "Development Tools" -y; sudo yum install git curl -y; curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; source ~/.bashrc; sudo curl -o redis-stable.tar.gz https://download.redis.io/redis-stable.tar.gz; sudo tar -xzvf redis-stable.tar.gz; cd redis-stable; sudo make install; sudo adduser --system --group --no-create-home redis; echo -e "[Unit]\nDescription=Redis In-Memory Data Store\nAfter=network.target\n\n[Service]\nUser=redis\nGroup=redis\nExecStart=/usr/local/bin/redis-server\nExecStop=/usr/local/bin/redis-cli shutdown\nRestart=always\n\n[Install]\nWantedBy=multi-user.target" | sudo tee /etc/systemd/system/redis.service > /dev/null; sudo systemctl daemon-reload; sudo systemctl enable redis; sudo systemctl start redis; cd ..; sudo rm redis-stable.tar.gz; sudo rm -rf redis-stable; git clone https://github.com/tn3w/rusty-loadbalancing.git; cd rusty-loadbalancing; cargo build --release; sudo cp ./target/release/rusty-loadbalancing /usr/local/bin/rusty-loadbalancing; cd ..; sudo rm -rf rusty-loadbalancing; rusty-loadbalancing --help
```

After using this command you can start the tool with the following command:
```bash
rusty-loadbalancing --help
```

#### Arch Linux
```bash
sudo pacman -Syu --noconfirm; sudo pacman -S --noconfirm git curl base-devel; curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; source ~/.bashrc; sudo curl -o redis-stable.tar.gz https://download.redis.io/redis-stable.tar.gz; sudo tar -xzvf redis-stable.tar.gz; cd redis-stable; sudo make install; sudo adduser --system --group --no-create-home redis; echo -e "[Unit]\nDescription=Redis In-Memory Data Store\nAfter=network.target\n\n[Service]\nUser=redis\nGroup=redis\nExecStart=/usr/local/bin/redis-server\nExecStop=/usr/local/bin/redis-cli shutdown\nRestart=always\n\n[Install]\nWantedBy=multi-user.target" | sudo tee /etc/systemd/system/redis.service > /dev/null; sudo systemctl daemon-reload; sudo systemctl enable redis; sudo systemctl start redis; cd ..; sudo rm redis-stable.tar.gz; sudo rm -rf redis-stable; git clone https://github.com/tn3w/rusty-loadbalancing.git; cd rusty-loadbalancing; cargo build --release; sudo cp ./target/release/rusty-loadbalancing /usr/local/bin/rusty-loadbalancing; cd ..; sudo rm -rf rusty-loadbalancing; rusty-loadbalancing --help
```

After using this command you can start the tool with the following command:
```bash
rusty-loadbalancing --help
```

#### openSUSE
```bash
sudo zypper refresh; sudo zypper install -y git curl gcc gcc-c++ make; curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; source ~/.bashrc; sudo curl -o redis-stable.tar.gz https://download.redis.io/redis-stable.tar.gz; sudo tar -xzvf redis-stable.tar.gz; cd redis-stable; sudo make install; sudo adduser --system --group --no-create-home redis; echo -e "[Unit]\nDescription=Redis In-Memory Data Store\nAfter=network.target\n\n[Service]\nUser=redis\nGroup=redis\nExecStart=/usr/local/bin/redis-server\nExecStop=/usr/local/bin/redis-cli shutdown\nRestart=always\n\n[Install]\nWantedBy=multi-user.target" | sudo tee /etc/systemd/system/redis.service > /dev/null; sudo systemctl daemon-reload; sudo systemctl enable redis; sudo systemctl start redis; cd ..; sudo rm redis-stable.tar.gz; sudo rm -rf redis-stable; git clone https://github.com/tn3w/rusty-loadbalancing.git; cd rusty-loadbalancing; cargo build --release; sudo cp ./target/release/rusty-loadbalancing /usr/local/bin/rusty-loadbalancing; cd ..; sudo rm -rf rusty-loadbalancing; rusty-loadbalancing --help
```

After using this command you can start the tool with the following command:
```bash
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
