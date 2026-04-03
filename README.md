# QwikCAP VPN

Route mobile device traffic through Burp Suite with a single command. QwikCAP spins up a WireGuard VPN in Docker, intercepts HTTP/HTTPS from connected phones or tablets, and forwards it transparently to your local Burp proxy — no manual certificate imports or system proxy settings required on the device.

## How it works

```
Phone ──WireGuard──▶ Docker container
                         │
                    iptables REDIRECT
                         │
                    proxy bridge (proxy.py)
                    ├── excepted hosts ──▶ direct connection
                    └── everything else ──▶ Burp Suite (host)
```

1. A WireGuard container is started with `NET_ADMIN` capabilities.
2. `iptables` redirects all TCP port 80/443 traffic from the WireGuard interface to an in-container Python proxy.
3. The proxy peeks at the TLS SNI (HTTPS) or `Host` header (HTTP) to decide routing:
   - **Excepted hosts** (cert-pinned Apple/Google system services) → direct TCP relay to the real destination.
   - **Everything else** → forwarded to Burp Suite running on your machine.
4. QUIC (HTTP/3 over UDP 443) is blocked with `iptables` to force apps onto TCP, where traffic can be intercepted.
5. IPv6 forwarding is dropped to prevent apps from bypassing the proxy via IPv6.
6. A QR code of each client's WireGuard config is printed in the terminal — scan it in the WireGuard app to connect.

## Requirements

- **Python** 3.9+
- **Docker Desktop** (macOS or Windows) or Docker Engine (Linux)
- **Burp Suite** listening on your machine (default: `127.0.0.1:8080`)
- **WireGuard** app installed on the target device ([iOS](https://apps.apple.com/app/wireguard/id1441195209) / [Android](https://play.google.com/store/apps/details?id=com.wireguard.android))

## Installation

```bash
git clone https://github.com/your-org/QwikCAP-VPN.git
cd QwikCAP-VPN
pip install -r requirements.txt
```

## Quick start

1. Start Burp Suite and ensure its proxy listener is active (default port 8080).
2. Install Burp's CA certificate on your device (one-time setup — visit `http://burp` or export from Burp's Proxy settings).
3. Start QwikCAP:

```bash
python qwikcap.py start
```

On first run, the Docker image is built (~30 seconds). A QR code for the default client (`phone`) is printed in the terminal.

4. Open the WireGuard app on your device, tap **+**, and scan the QR code.
5. Activate the tunnel — all traffic now flows through Burp.
6. Press `Ctrl+C` to stop the VPN when done.

## CLI reference

| Command | Description |
|---|---|
| `start [--proxy-port PORT] [--rebuild]` | Build image (if needed), start VPN, print client QR codes |
| `stop` | Stop and remove the WireGuard container |
| `add-client <name>` | Generate a new WireGuard client and print its QR code |
| `status` | Show container state, proxy config, clients, and active peers |
| `config [--proxy-port] [--proxy-host] [--vpn-port]` | View or update configuration |
| `logs [--tail N]` | Print container logs (default: last 50 lines) |
| `debug` | Dump `wg show`, `iptables`, `ip_forward`, and routing table from inside the container |

### Examples

```bash
# Use a non-default Burp port
python qwikcap.py start --proxy-port 8888

# Add a second device
python qwikcap.py add-client tablet

# Check which peers are connected and when they last handshook
python qwikcap.py status

# Force a full Docker image rebuild
python qwikcap.py start --rebuild
```

## Configuration

QwikCAP stores its config and state in `~/.qwikcap/`. Copy the example and edit as needed:

```bash
cp config.yaml.example ~/.qwikcap/config.yaml
```

| Key | Default | Description |
|---|---|---|
| `proxy.host` | `127.0.0.1` | IP address of the Burp listener |
| `proxy.port` | `8080` | Port of the Burp listener |
| `vpn.listen_port` | `51820` | WireGuard UDP port (must be open on the host firewall) |
| `vpn.subnet` | `10.13.37.0/24` | VPN subnet |
| `docker.image_name` | `qwikcap-wg` | Docker image tag |
| `docker.container_name` | `qwikcap-vpn` | Docker container name |
| `exceptions` | *(list)* | Hosts routed directly instead of through Burp |

### Exception list

Hosts or domain suffixes listed under `exceptions` bypass Burp and connect directly. This prevents cert-pinned system services from breaking connectivity. Leading-dot suffixes match all subdomains (`.apple.com` matches `foo.apple.com`).

Default exceptions include Apple Push Notification, OCSP, Location Services, captive portal probes, and Android/Google Play connectivity checks.

## Troubleshooting

**Container exits immediately**
Run `python qwikcap.py logs` to see the startup output. The most common cause is Docker not having `NET_ADMIN` capability or the WireGuard kernel module not being available (both are included in Docker Desktop's kernel).

**Traffic not appearing in Burp**
- Confirm the WireGuard tunnel is active on the device (the app shows a green indicator).
- Run `python qwikcap.py status` to verify an active peer handshake.
- Ensure Burp's listener is set to **All interfaces** or at least to the IP shown in `qwikcap status`.
- Run `python qwikcap.py debug` to inspect `iptables` rules and WireGuard state inside the container.

**TLS handshake failures on the device**
The Burp CA certificate must be installed and trusted on the device. See [Burp's documentation](https://portswigger.net/burp/documentation/desktop/mobile/config-android-device) for per-platform instructions.

**Device cannot reach the internet after connecting**
Check that UDP port `51820` is not blocked between the device and the machine running QwikCAP. On macOS, check System Settings → Firewall.
