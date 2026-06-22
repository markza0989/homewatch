"""ARP discovery and supporting network helpers.

Scapy is imported lazily inside `arp_sweep` so this module imports cleanly in
environments without Scapy or raw-socket privileges (tests, CI, dev laptops).
`parse_arp_responses` is split out as the pure, testable unit.
"""
import socket

from ..models import normalize_mac


def parse_arp_responses(answered) -> list[tuple[str, str]]:
    """Turn Scapy's `answered` list of (sent, received) pairs into
    normalised (mac, ip) tuples. Pure function — no network, no Scapy import."""
    results: list[tuple[str, str]] = []
    for entry in answered:
        # Scapy yields (sent_pkt, received_pkt); the reply carries hwsrc/psrc.
        received = entry[1]
        results.append((normalize_mac(received.hwsrc), received.psrc))
    return results


def arp_sweep(subnet: str, timeout: int = 3) -> list[tuple[str, str]]:
    """Broadcast an ARP request across `subnet` (e.g. '192.168.1.0/24') and
    return discovered (mac, ip) pairs. Requires CAP_NET_RAW."""
    from scapy.layers.l2 import ARP, Ether  # lazy
    from scapy.sendrecv import srp  # lazy

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    answered, _ = srp(packet, timeout=timeout, verbose=False)
    return parse_arp_responses(answered)


def reverse_dns(ip: str, timeout: float = 1.0) -> str | None:
    """Best-effort reverse DNS with a short timeout. Returns None on any
    failure so a slow or absent resolver can't stall the scan."""
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(previous)


def get_primary_ip() -> str:
    """Primary outbound IP, via a UDP socket that sends no packets."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        sock.close()


def detect_subnet(override: str | None = None) -> str:
    """Resolve the subnet to scan. Honours an explicit override
    (HOMEWATCH_SUBNET); otherwise assumes a /24 around the primary IP — the
    single-subnet MVP assumption documented in the threat model."""
    if override:
        return override
    ip = get_primary_ip()
    octets = ip.split(".")
    octets[3] = "0/24"
    return ".".join(octets)
