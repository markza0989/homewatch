"""ICMP follow-up using ping3.

Used as an optional confirmation step (off by default — see SCAN_ICMP_CONFIRM):
before marking a stale device offline, ping its last known IP once in case the
ARP reply was simply missed. ping3's raw ICMP socket also needs CAP_NET_RAW.
"""


def icmp_ping(ip: str, timeout: float = 1.0) -> bool:
    """True if the host answers within `timeout`. Any error -> False."""
    try:
        from ping3 import ping  # lazy: avoids requiring ping3/raw sockets to import

        result = ping(ip, timeout=timeout, unit="s")
        # ping3 returns delay (float) on success, None on timeout, False on error.
        return isinstance(result, float)
    except Exception:
        return False
