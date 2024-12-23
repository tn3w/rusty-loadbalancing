<p align="center">
    <picture>
        <source height="128" media="(prefers-color-scheme: dark)" srcset="https://github.com/tn3w/rusty-loadbalancing/releases/download/logo/rusty-logo-dark.png">
        <source height="128" media="(prefers-color-scheme: light)" srcset="https://github.com/tn3w/rusty-loadbalancing/releases/download/logo/rusty-logo-light.png">
        <img height="128" alt="Picture from Block Page" src="https://github.com/tn3w/rusty-loadbalancing/releases/download/logo/rusty-logo-light.png">
    </picture>
    <br>
    A fast, efficient, and small load balancing tool written in Rust. It implements a least-connections algorithm and uses Redis for storing server locations.
</p>


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

## Managing backend load balancing server list
Commands using redis-cli:
```bash
# Add backend server
redis-cli RPUSH backend_servers "localhost:8081"

# Remove backend server 
redis-cli LREM backend_servers 0 "localhost:8081"

# List backends
redis-cli LRANGE backend_servers 0 -1
```

Python code example:
```python
import redis

r = redis.Redis(host='localhost', port=6379)

# Add backend server
r.rpush('backend_servers', 'localhost:8081')

# Remove backend server
r.lrem('backend_servers', 0, 'localhost:8081')

# List backends
servers = r.lrange('backend_servers', 0, -1)
for server in servers:
    print(server.decode())
```

This process can be initiated when the web server starts up, adding it to the list, and it can be removed from the list upon termination.


### Attribution
- Logo icon: [Rust icons created by Freepik - Flaticon](https://www.flaticon.com/free-icons/rust)
