"""IP geolocation helper.

Privacy-first design:
  * Private / loopback / reserved addresses are labelled locally - no network.
  * Public addresses are looked up ONLY when ``geo_lookup_enabled`` is true
    (uses the free ip-api.com endpoint), and results are cached in SQLite.
"""

from __future__ import annotations

import ipaddress
from typing import Optional


def classify(ip: str) -> tuple[bool, Optional[str]]:
    """Return ``(is_private, label)``. label is set only for local ranges."""
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False, None
    if addr.is_loopback:
        return True, "Loopback (local machine)"
    if addr.is_link_local:
        return True, "Link-local"
    if addr.is_private:
        return True, "Private network"
    if addr.is_reserved or addr.is_unspecified or addr.is_multicast:
        return True, "Non-routable"
    return False, None


def online_lookup(ip: str, timeout: float = 4.0) -> Optional[dict]:
    """Look up public IP data via ip-api.com. Returns dict or None."""
    try:
        import requests  # lazy import: optional dependency
    except ImportError:
        return None
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,city,as,lat,lon"},
            timeout=timeout,
        )
        data = resp.json()
    except Exception:
        return None
    if data.get("status") != "success":
        return None
    return {
        "country": data.get("country"),
        "city": data.get("city"),
        "asn": data.get("as"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
    }


def enrich(event: dict, db=None, enabled: bool = False) -> dict:
    """Attach geo fields to a normalized event before insert."""
    ip = event["src_ip"]
    private, label = classify(ip)
    event["_is_private"] = private
    if private:
        event["geo_country"] = label
        return event
    if not enabled or db is None:
        return event
    cached = db.ip_meta_get(ip)
    if cached and cached.get("country") and not cached.get("is_private"):
        event["geo_country"] = cached["country"]
        event["geo_city"] = cached["city"]
        event["geo_asn"] = cached["asn"]
        event["geo_lat"] = cached["lat"]
        event["geo_lon"] = cached["lon"]
        return event
    info = online_lookup(ip)
    if info:
        event.update({
            "geo_country": info["country"],
            "geo_city": info["city"],
            "geo_asn": info["asn"],
            "geo_lat": info["lat"],
            "geo_lon": info["lon"],
        })
        db.ip_meta_set_geo(ip, info["country"], info["city"], info["asn"],
                           info["lat"], info["lon"])
    return event
