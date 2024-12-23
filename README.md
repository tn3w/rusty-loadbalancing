<picture align="center">
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/tn3w/rusty-loadbalancing/releases/download/logo/rusty-logo-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/tn3w/rusty-loadbalancing/releases/download/logo/rusty-logo-light.png">
  <img alt="Picture from Block Page" src="https://github.com/tn3w/rusty-loadbalancing/releases/download/logo/rusty-logo-light.png">
</picture>
<p align="center">A fast, efficient, and small load balancing tool written in Rust. It implements a least-connections algorithm and uses Redis for storing server locations.</p>

---

## 🚀 Installing
1. Install Rust using rust-up (optional): 
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```

2. Clone the git project:
    ```bash
    https://github.com/tn3w/rusty-loadbalancing.git
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

### Attribution
- Logo icon: [Rust icons created by Freepik - Flaticon](https://www.flaticon.com/free-icons/rust)
