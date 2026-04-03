import json
import os
import tempfile
import urllib.request
from pathlib import Path

import docker
import docker.errors


DOCKER_DIR = Path(__file__).parent.parent / "docker"


def _client():
    try:
        return docker.from_env()
    except docker.errors.DockerException as e:
        raise RuntimeError(
            f"Cannot connect to Docker: {e}\n"
            "Make sure Docker Desktop is running."
        ) from e


def build_image(image_name: str) -> None:
    client = _client()
    client.images.build(path=str(DOCKER_DIR), tag=image_name, rm=True)


def image_exists(image_name: str) -> bool:
    client = _client()
    try:
        client.images.get(image_name)
        return True
    except docker.errors.ImageNotFound:
        return False


def start(cfg: dict, server_privkey: str, peers: list[dict]) -> str:
    """Build the container config dir, start the container, return container ID."""
    client = _client()
    image_name = cfg["docker"]["image_name"]
    container_name = cfg["docker"]["container_name"]

    # Stop any existing container with this name
    stop(cfg)

    if not image_exists(image_name):
        build_image(image_name)

    wg_conf = _render_server_conf(server_privkey, cfg["vpn"]["listen_port"], peers)

    # Write wg0.conf to a temp directory that survives for the container lifetime.
    # We keep a reference in the state so we can clean it up on stop.
    conf_dir = tempfile.mkdtemp(prefix="qwikcap-")
    conf_path = Path(conf_dir) / "wg0.conf"
    conf_path.write_text(wg_conf)
    os.chmod(conf_path, 0o600)

    container = client.containers.run(
        image_name,
        name=container_name,
        detach=True,
        cap_add=["NET_ADMIN"],
        sysctls={"net.ipv4.ip_forward": "1"},
        extra_hosts={"host.docker.internal": "host-gateway"},
        ports={
            f"{cfg['vpn']['listen_port']}/udp": cfg["vpn"]["listen_port"],
            "9292/tcp": cfg["proxy"].get("control_port", 9292),
        },
        volumes={conf_dir: {"bind": "/etc/wireguard", "mode": "ro"}},
        environment={
            "BURP_PORT": str(cfg["proxy"]["port"]),
            "WG_PORT": str(cfg["vpn"]["listen_port"]),
            "EXCEPTION_HOSTS": ",".join(cfg.get("exceptions", [])),
            "CTRL_PORT": str(cfg["proxy"].get("control_port", 9292)),
        },
    )
    return container.id, conf_dir


def get_logs(cfg: dict, tail: int = 50) -> str:
    client = _client()
    try:
        container = client.containers.get(cfg["docker"]["container_name"])
        return container.logs(tail=tail).decode(errors="replace")
    except docker.errors.NotFound:
        return "(container not found)"


def exec_cmd(cfg: dict, cmd: str) -> str:
    client = _client()
    try:
        container = client.containers.get(cfg["docker"]["container_name"])
        result = container.exec_run(cmd, demux=True)
        stdout = (result.output[0] or b"").decode(errors="replace")
        stderr = (result.output[1] or b"").decode(errors="replace")
        return stdout + stderr
    except docker.errors.NotFound:
        return "(container not found)"


def stop(cfg: dict) -> None:
    client = _client()
    container_name = cfg["docker"]["container_name"]
    try:
        container = client.containers.get(container_name)
        container.stop(timeout=5)
        container.remove()
    except docker.errors.NotFound:
        pass


def is_running(cfg: dict) -> bool:
    client = _client()
    try:
        container = client.containers.get(cfg["docker"]["container_name"])
        return container.status == "running"
    except docker.errors.NotFound:
        return False


def get_peers(cfg: dict) -> list[dict]:
    """Parse `wg show` output from inside the container."""
    client = _client()
    try:
        container = client.containers.get(cfg["docker"]["container_name"])
        result = container.exec_run("wg show wg0", demux=True)
        stdout = (result.output[0] or b"").decode()
        return _parse_wg_show(stdout)
    except docker.errors.NotFound:
        return []


def _render_server_conf(private_key: str, listen_port: int, peers: list[dict]) -> str:
    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"ListenPort = {listen_port}",
    ]
    for peer in peers:
        lines += [
            "",
            "[Peer]",
            f"# {peer.get('name', 'unnamed')}",
            f"PublicKey = {peer['public_key']}",
            f"AllowedIPs = {peer['allowed_ips']}",
        ]
    return "\n".join(lines) + "\n"


def _ctrl_url(cfg: dict, path: str) -> str:
    port = cfg["proxy"].get("control_port", 9292)
    return f"http://localhost:{port}{path}"


def get_proxy_stats(cfg: dict) -> dict:
    """Fetch live traffic counters from the in-container proxy."""
    try:
        with urllib.request.urlopen(_ctrl_url(cfg, "/stats"), timeout=1) as r:
            return json.loads(r.read())
    except Exception:
        return {}


def list_proxy_exceptions(cfg: dict) -> list:
    """Return the live exception list from the running proxy."""
    try:
        with urllib.request.urlopen(_ctrl_url(cfg, "/exceptions"), timeout=2) as r:
            return json.loads(r.read())
    except Exception:
        return []


def _ctrl_request(cfg: dict, path: str, method: str, hosts: list) -> bool:
    try:
        data = json.dumps(hosts).encode()
        req = urllib.request.Request(
            _ctrl_url(cfg, path),
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=2)
        return True
    except Exception:
        return False


def add_proxy_exception(cfg: dict, host: str) -> bool:
    return _ctrl_request(cfg, "/exceptions", "POST", [host])


def remove_proxy_exception(cfg: dict, host: str) -> bool:
    return _ctrl_request(cfg, "/exceptions", "DELETE", [host])


def _parse_wg_show(output: str) -> list[dict]:
    peers = []
    current = None  # type: dict
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("peer:"):
            if current:
                peers.append(current)
            current = {"public_key": line.split(":", 1)[1].strip()}
        elif current and line.startswith("latest handshake:"):
            current["latest_handshake"] = line.split(":", 1)[1].strip()
        elif current and line.startswith("transfer:"):
            current["transfer"] = line.split(":", 1)[1].strip()
        elif current and line.startswith("endpoint:"):
            current["endpoint"] = line.split(":", 1)[1].strip()
    if current:
        peers.append(current)
    return peers
