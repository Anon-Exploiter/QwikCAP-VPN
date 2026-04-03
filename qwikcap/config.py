import os
import socket
import yaml
from pathlib import Path
from typing import Any

CONFIG_PATH = Path(os.environ.get("QWIKCAP_CONFIG", Path.home() / ".qwikcap" / "config.yaml"))
STATE_PATH = CONFIG_PATH.parent / "state.yaml"

DEFAULTS: dict[str, Any] = {
    "proxy": {
        "host": "127.0.0.1",
        "port": 8080,
        "control_port": 9292,
    },
    "vpn": {
        "subnet": "10.13.37.0/24",
        "server_ip": "10.13.37.1",
        "listen_port": 51820,
    },
    "docker": {
        "image_name": "qwikcap-wg",
        "container_name": "qwikcap-vpn",
    },
    # Hosts that bypass Burp and connect directly.
    # Use exact hostname or leading-dot suffix (.apple.com matches all subdomains).
    "exceptions": [
        # ── Apple Push Notification Service (APNs) ──────────────────────────────
        # Uses its own CA + pinning. Breaks all push notifications if intercepted.
        ".push.apple.com",

        # ── Apple ID / iCloud auth ───────────────────────────────────────────────
        # System-level identity; pinned by the OS.
        "identity.apple.com",
        "setup.icloud.com",
        "idmsa.apple.com",

        # ── iCloud Private Relay (iOS 15+) ───────────────────────────────────────
        "mask.icloud.com",
        "mask-h2.icloud.com",
        "mask-api.icloud.com",

        # ── Location services (gsp) ──────────────────────────────────────────────
        # Apple Maps / Core Location backend; all use pinned leaf certs.
        "gsp-ssl.ls.apple.com",
        "gspe1-ssl.ls.apple.com",
        "gspe3-ssl.ls.apple.com",
        "gspe7-ssl.ls.apple.com",
        "gspe11-ssl.ls.apple.com",
        "gspe15-ssl.ls.apple.com",
        "gspe21-ssl.ls.apple.com",
        "gspe35-ssl.ls.apple.com",
        "gsp64-ssl.ls.apple.com",

        # ── Captive portal / connectivity check ─────────────────────────────────
        "captive.apple.com",

        # ── OCSP / certificate validation ────────────────────────────────────────
        # Intercepting these breaks TLS validation for all other connections.
        "ocsp.apple.com",
        "ocsp2.apple.com",
        "valid.apple.com",
        "csp.apple.com",

        # ── iMessage / FaceTime ──────────────────────────────────────────────────
        "query.ess.apple.com",
        "init.ess.apple.com",
        "id.apple.com",

        # ── App Attest / DeviceCheck ─────────────────────────────────────────────
        # Apple's app integrity framework; pinned at the OS level.
        "data.appattest.apple.com",
        "api.devicecheck.apple.com",

        # ── App Store / provisioning ─────────────────────────────────────────────
        "ppq.apple.com",
        "bag.itunes.apple.com",
        "xp.apple.com",

        # ── Software updates ─────────────────────────────────────────────────────
        "mesu.apple.com",
        "gdmf.apple.com",
        "xprotect.apple.com",

        # ── Siri ─────────────────────────────────────────────────────────────────
        "guzzoni.apple.com",
        ".siri.apple.com",

        # ── Apple analytics / telemetry ──────────────────────────────────────────
        "ca.csp.apple.com",
        "pancake.apple.com",

        # ════════════════════════════════════════════════════════════════════════
        # ── Android / Google system services ────────────────────────────────────
        # ════════════════════════════════════════════════════════════════════════

        # ── Firebase Cloud Messaging (FCM) / GCM ────────────────────────────────
        # Android's push notification transport; pinned by Play Services.
        "mtalk.google.com",
        "alt1-mtalk.google.com",
        "alt2-mtalk.google.com",
        "alt3-mtalk.google.com",
        "alt4-mtalk.google.com",
        "alt5-mtalk.google.com",
        "alt6-mtalk.google.com",
        "alt7-mtalk.google.com",
        "alt8-mtalk.google.com",
        "fcm.googleapis.com",
        "fcm-xmpp.googleapis.com",

        # ── Google Play / Android services ───────────────────────────────────────
        "android.clients.google.com",
        "play.google.com",

        # ── Android connectivity probes ──────────────────────────────────────────
        # Used by Android to detect internet / captive portal; must reach real server.
        "connectivitycheck.gstatic.com",
        "connectivitycheck.android.com",
        "clients1.google.com",
        "clients3.google.com",

        # ── Play Integrity / SafetyNet ───────────────────────────────────────────
        # Google's device attestation; pinned and will fail with intercepted cert.
        "attest.android.com",
        "www.googleapis.com",

        # ── Certificate Transparency ─────────────────────────────────────────────
        "ct.googleapis.com",

        # ── Google DNS-over-HTTPS (Android Private DNS default) ──────────────────
        "dns.google",
    ],
}


def load() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            user = yaml.safe_load(f) or {}
        return _deep_merge(DEFAULTS, user)
    return _deep_merge(DEFAULTS, {})


def save(cfg: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        yaml.dump(cfg, f, default_flow_style=False)


def load_state() -> dict:
    if STATE_PATH.exists():
        with open(STATE_PATH) as f:
            return yaml.safe_load(f) or {}
    return {}


def save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_PATH, "w") as f:
        yaml.dump(state, f, default_flow_style=False)


def get_lan_ip() -> str:
    """Best-effort detection of the LAN IP other devices can reach."""
    try:
        import netifaces
        gws = netifaces.gateways()
        default_iface = gws.get("default", {}).get(netifaces.AF_INET, [None, None])[1]
        if default_iface:
            addrs = netifaces.ifaddresses(default_iface)
            inet = addrs.get(netifaces.AF_INET)
            if inet:
                return inet[0]["addr"]
    except Exception:
        pass
    # Fallback: UDP trick (no packet sent)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result
