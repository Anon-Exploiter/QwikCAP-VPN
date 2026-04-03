import io
import qrcode
from qrcode.image.pil import PilImage


def render_client_conf(
    client_privkey: str,
    client_ip: str,
    server_pubkey: str,
    server_endpoint: str,
    listen_port: int,
    dns: str = "1.1.1.1",
) -> str:
    return (
        "[Interface]\n"
        f"PrivateKey = {client_privkey}\n"
        f"Address = {client_ip}/32\n"
        f"DNS = {dns}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {server_pubkey}\n"
        f"Endpoint = {server_endpoint}:{listen_port}\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
    )


def conf_to_qr_png_bytes(conf: str) -> bytes:
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(conf)
    qr.make(fit=True)
    img: PilImage = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def conf_to_qr_terminal(conf: str) -> str:
    """Return an ANSI block-character QR code for terminal display."""
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(conf)
    qr.make(fit=True)
    f = io.StringIO()
    qr.print_ascii(out=f, invert=True)
    return f.getvalue()
