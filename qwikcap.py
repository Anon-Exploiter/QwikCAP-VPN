#!/usr/bin/env python3
import datetime
import json
import shutil
import sys
import threading
import time
import urllib.request

import click

from qwikcap import config as cfg_mod
from qwikcap import docker_manager as dm
from qwikcap import keys as keys_mod
from qwikcap import profile_gen


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def _render_stats(cfg: dict, stats: dict, peers: list, pubkey_to_name: dict, start_time: datetime.datetime) -> list:
    elapsed = datetime.datetime.now() - start_time
    h, rem = divmod(int(elapsed.total_seconds()), 3600)
    m, s = divmod(rem, 60)
    uptime = f"{h}:{m:02d}:{s:02d}"

    lines = [f"uptime {uptime}  proxy {cfg['proxy']['host']}:{cfg['proxy']['port']}"]

    if stats:
        active = stats.get("active", 0)
        lines.append(
            f"  -> Burp   {stats.get('conn_proxied', 0):>6} conns  "
            f"{_fmt_bytes(stats.get('bytes_proxied', 0)):>9}  ({active} active)"
        )
        lines.append(
            f"  -> Direct {stats.get('conn_bypassed', 0):>6} conns  "
            f"{_fmt_bytes(stats.get('bytes_bypassed', 0)):>9}"
        )
    else:
        lines.append("  (proxy stats unavailable — waiting for container...)")

    if peers:
        lines.append("peers:")
        for p in peers:
            name = pubkey_to_name.get(p["public_key"], p["public_key"][:16] + "...")
            hs = p.get("latest_handshake", "—")
            tf = p.get("transfer", "")
            lines.append(f"  {name:<16} handshake: {hs}  {tf}")
    else:
        lines.append("peers: (none connected)")

    return lines


def _live_stats_loop(cfg: dict, pubkey_to_name: dict, start_time: datetime.datetime, stop: threading.Event) -> None:
    if not sys.stdout.isatty():
        stop.wait()
        return

    prev_lines = 0
    while not stop.is_set():
        try:
            stats = dm.get_proxy_stats(cfg)
            peers = dm.get_peers(cfg)
        except Exception:
            stats = {}
            peers = []

        lines = _render_stats(cfg, stats, peers, pubkey_to_name, start_time)

        if prev_lines:
            sys.stdout.write(f"\033[{prev_lines}A")
        for line in lines:
            sys.stdout.write(f"\033[2K{line}\n")
        sys.stdout.flush()
        prev_lines = len(lines)

        stop.wait(timeout=2)


def _load_or_init_state(cfg: dict) -> dict:
    state = cfg_mod.load_state()
    if "server_private_key" not in state:
        priv, pub = keys_mod.generate_keypair()
        state["server_private_key"] = priv
        state["server_public_key"] = pub
        state["clients"] = {}
        cfg_mod.save_state(state)
    return state


def _client_ip(index: int, subnet_base: str = "10.13.37") -> str:
    return f"{subnet_base}.{index + 2}"


@click.group()
def cli():
    """QwikCAP VPN — route phone traffic through Burp Suite."""


@cli.command()
@click.option("--proxy-port", default=None, type=int, help="Burp proxy port (default: 8080)")
@click.option("--rebuild", is_flag=True, help="Force Docker image rebuild")
def start(proxy_port, rebuild):
    """Build the WireGuard container, start the VPN, and serve the setup page."""
    cfg = cfg_mod.load()
    if proxy_port:
        cfg["proxy"]["port"] = proxy_port

    state = _load_or_init_state(cfg)

    # Ensure at least one client exists
    if not state.get("clients"):
        click.echo("No clients found — generating a default client 'phone'.")
        priv, pub = keys_mod.generate_keypair()
        state["clients"]["phone"] = {
            "private_key": priv,
            "public_key": pub,
            "ip_index": 0,
        }
        cfg_mod.save_state(state)

    if rebuild and dm.image_exists(cfg["docker"]["image_name"]):
        import docker
        docker.from_env().images.remove(cfg["docker"]["image_name"], force=True)

    if not dm.image_exists(cfg["docker"]["image_name"]):
        click.echo("Building Docker image (first run — takes ~30s)...")
        dm.build_image(cfg["docker"]["image_name"])
        click.echo("Image built.")

    peers = [
        {
            "name": name,
            "public_key": c["public_key"],
            "allowed_ips": f"{_client_ip(c['ip_index'])}/32",
        }
        for name, c in state["clients"].items()
    ]

    click.echo("Starting WireGuard container...")
    container_id, conf_dir = dm.start(cfg, state["server_private_key"], peers)
    state["container_id"] = container_id
    state["conf_dir"] = conf_dir
    cfg_mod.save_state(state)

    # Brief pause then verify the container didn't exit immediately
    time.sleep(2)
    if not dm.is_running(cfg):
        click.echo("\nERROR: Container exited unexpectedly. Last logs:", err=True)
        click.echo(dm.get_logs(cfg, tail=20), err=True)
        _do_stop(cfg, state)
        sys.exit(1)

    lan_ip = cfg_mod.get_lan_ip()

    click.echo(f"\nVPN is up. Proxy: {cfg['proxy']['host']}:{cfg['proxy']['port']}")

    for name, c in state["clients"].items():
        conf = profile_gen.render_client_conf(
            client_privkey=c["private_key"],
            client_ip=_client_ip(c["ip_index"]),
            server_pubkey=state["server_public_key"],
            server_endpoint=lan_ip,
            listen_port=cfg["vpn"]["listen_port"],
        )
        click.echo(f"\n--- WireGuard config QR: '{name}' (scan in WireGuard app) ---\n")
        click.echo(profile_gen.conf_to_qr_terminal(conf))

    pubkey_to_name = {c["public_key"]: name for name, c in state["clients"].items()}
    start_time = datetime.datetime.now()
    stop_event = threading.Event()

    click.echo("\nPress Ctrl+C to stop. Run 'qwikcap exceptions add/remove' in another terminal.\n")

    stats_thread = threading.Thread(
        target=_live_stats_loop,
        args=(cfg, pubkey_to_name, start_time, stop_event),
        daemon=True,
    )
    stats_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()
        stats_thread.join(timeout=3)
        click.echo("\nStopping...")
        _do_stop(cfg, state)


@cli.command()
def stop():
    """Stop the WireGuard container."""
    cfg = cfg_mod.load()
    state = cfg_mod.load_state()
    _do_stop(cfg, state)
    click.echo("Stopped.")


def _do_stop(cfg: dict, state: dict) -> None:
    dm.stop(cfg)
    conf_dir = state.get("conf_dir")
    if conf_dir:
        shutil.rmtree(conf_dir, ignore_errors=True)
        state.pop("conf_dir", None)
        state.pop("container_id", None)
        cfg_mod.save_state(state)


@cli.command("add-client")
@click.argument("name")
def add_client(name):
    """Generate a new WireGuard client keypair and print its QR code."""
    cfg = cfg_mod.load()
    state = _load_or_init_state(cfg)

    if name in state.get("clients", {}):
        click.echo(f"Client '{name}' already exists. Use 'qwikcap status' to view it.", err=True)
        sys.exit(1)

    existing_indices = {c["ip_index"] for c in state.get("clients", {}).values()}
    idx = next(i for i in range(253) if i not in existing_indices)

    priv, pub = keys_mod.generate_keypair()
    state.setdefault("clients", {})[name] = {
        "private_key": priv,
        "public_key": pub,
        "ip_index": idx,
    }
    cfg_mod.save_state(state)

    lan_ip = cfg_mod.get_lan_ip()
    conf = profile_gen.render_client_conf(
        client_privkey=priv,
        client_ip=_client_ip(idx),
        server_pubkey=state["server_public_key"],
        server_endpoint=lan_ip,
        listen_port=cfg["vpn"]["listen_port"],
    )

    click.echo(f"\nClient '{name}' created. Scan in the WireGuard app:\n")
    click.echo(profile_gen.conf_to_qr_terminal(conf))
    click.echo(f"\nConfig:\n{conf}")

    if dm.is_running(cfg):
        click.echo("VPN is running — restart with 'qwikcap stop && qwikcap start' to apply.")


@cli.command()
def status():
    """Show VPN status and connected peers."""
    cfg = cfg_mod.load()
    state = cfg_mod.load_state()

    running = dm.is_running(cfg)
    click.echo(f"Container : {'running' if running else 'stopped'}")
    click.echo(f"Proxy     : {cfg['proxy']['host']}:{cfg['proxy']['port']}")
    click.echo(f"VPN port  : {cfg['vpn']['listen_port']}/udp")

    clients = state.get("clients", {})
    click.echo(f"\nClients ({len(clients)}):")
    for name, c in clients.items():
        click.echo(f"  {name:20s}  {_client_ip(c['ip_index'])}")

    if running:
        peers = dm.get_peers(cfg)
        if peers:
            click.echo("\nActive peers:")
            for p in peers:
                hs = p.get("latest_handshake", "never")
                tx = p.get("transfer", "")
                ep = p.get("endpoint", "")
                click.echo(f"  {p['public_key'][:20]}...  handshake: {hs}  {tx}  {ep}")


@cli.command()
@click.option("--proxy-port", type=int, help="Set Burp proxy port")
@click.option("--proxy-host", type=str, help="Set Burp proxy host")
@click.option("--vpn-port", type=int, help="Set WireGuard listen port")
def config(proxy_port, proxy_host, vpn_port):
    """View or update configuration."""
    cfg = cfg_mod.load()

    if proxy_port:
        cfg["proxy"]["port"] = proxy_port
    if proxy_host:
        cfg["proxy"]["host"] = proxy_host
    if vpn_port:
        cfg["vpn"]["listen_port"] = vpn_port

    if any([proxy_port, proxy_host, vpn_port]):
        cfg_mod.save(cfg)
        click.echo("Config saved.")
    else:
        import yaml
        click.echo(yaml.dump(cfg, default_flow_style=False))


@cli.command()
@click.option("--tail", default=50, help="Number of log lines to show")
def logs(tail):
    """Show container logs (useful for diagnosing startup failures)."""
    cfg = cfg_mod.load()
    click.echo(dm.get_logs(cfg, tail=tail))


@cli.command()
def debug():
    """Show WireGuard state and iptables rules inside the container."""
    cfg = cfg_mod.load()
    if not dm.is_running(cfg):
        click.echo("Container is not running.", err=True)
        sys.exit(1)
    click.echo("=== wg show ===")
    click.echo(dm.exec_cmd(cfg, "wg show"))
    click.echo("=== iptables nat PREROUTING ===")
    click.echo(dm.exec_cmd(cfg, "iptables -t nat -L PREROUTING -n -v"))
    click.echo("=== ip_forward ===")
    click.echo(dm.exec_cmd(cfg, "cat /proc/sys/net/ipv4/ip_forward"))
    click.echo("=== routing ===")
    click.echo(dm.exec_cmd(cfg, "ip route"))


@cli.group("exceptions")
def exceptions_cmd():
    """Manage bypass exceptions (hosts that skip Burp interception)."""


@exceptions_cmd.command("list")
def exceptions_list():
    """List current bypass exceptions."""
    cfg = cfg_mod.load()
    if dm.is_running(cfg):
        hosts = dm.list_proxy_exceptions(cfg)
        if hosts:
            for h in hosts:
                click.echo(h)
        else:
            click.echo("(no exceptions active)")
    else:
        hosts = cfg.get("exceptions", [])
        click.echo("(VPN not running — showing config defaults)")
        for h in hosts:
            click.echo(h)


@exceptions_cmd.command("add")
@click.argument("host")
def exceptions_add(host):
    """Add HOST to bypass exceptions. Updates live proxy if VPN is running."""
    cfg = cfg_mod.load()
    exceptions = list(cfg.get("exceptions", []))
    if host not in exceptions:
        exceptions.append(host)
        cfg["exceptions"] = exceptions
        cfg_mod.save(cfg)
        click.echo(f"Added '{host}' to config.")
    else:
        click.echo(f"'{host}' already in config.")

    if dm.is_running(cfg):
        if dm.add_proxy_exception(cfg, host):
            click.echo("Live proxy updated.")
        else:
            click.echo("Warning: could not reach live proxy.", err=True)


@exceptions_cmd.command("remove")
@click.argument("host")
def exceptions_remove(host):
    """Remove HOST from bypass exceptions. Updates live proxy if VPN is running."""
    cfg = cfg_mod.load()
    exceptions = list(cfg.get("exceptions", []))
    if host in exceptions:
        exceptions.remove(host)
        cfg["exceptions"] = exceptions
        cfg_mod.save(cfg)
        click.echo(f"Removed '{host}' from config.")
    else:
        click.echo(f"'{host}' not found in config.")

    if dm.is_running(cfg):
        if dm.remove_proxy_exception(cfg, host):
            click.echo("Live proxy updated.")
        else:
            click.echo("Warning: could not reach live proxy.", err=True)


if __name__ == "__main__":
    cli()
