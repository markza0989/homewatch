"""OUI -> vendor resolution with an in-memory cache.

Backed by `mac-vendor-lookup`, chosen over per-scan network calls: it caches the
IEEE OUI list locally and resolves offline after the first fetch. We add a
process-local cache keyed by OUI prefix so each vendor is resolved at most once
per run. Failures (offline, unknown OUI) resolve to None — never fatal.
"""

# Keyed by the 8-char OUI prefix (e.g. "a4:83:e7"). Value may be None (a cached
# "we looked and found nothing"), which still saves a repeat lookup.
_cache: dict[str, str | None] = {}
_mac_lookup = None


def _get_lookup():
    global _mac_lookup
    if _mac_lookup is None:
        from mac_vendor_lookup import MacLookup  # lazy: avoids import at test time

        _mac_lookup = MacLookup()
    return _mac_lookup


def _raw_lookup(mac: str) -> str | None:
    """Single uncached lookup. Isolated so tests can monkeypatch it."""
    try:
        return _get_lookup().lookup(mac)
    except Exception:  # unknown OUI, missing or unreachable vendor DB, etc.
        return None


def lookup_vendor(mac: str) -> str | None:
    oui = mac.lower()[:8]
    if oui in _cache:
        return _cache[oui]
    vendor = _raw_lookup(mac)
    _cache[oui] = vendor
    return vendor


def clear_cache() -> None:
    _cache.clear()
