from __future__ import annotations

import ipaddress
import re
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple, Union

from Evtx.Evtx import Evtx
from defusedxml import ElementTree as ET

# Pragmatic IPv4 + IPv6 matchers. We still validate with ipaddress afterwards.
RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
RE_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b")


def _safe_xml(xml_text: str) -> Optional[ET.Element]:
    try:
        return ET.fromstring(xml_text)
    except Exception:
        return None


def _gather_text(root: ET.Element) -> str:
    """Collects visible text + attribute values from the whole XML tree."""
    chunks: List[str] = []
    for el in root.iter():
        if el.text and el.text.strip():
            chunks.append(el.text.strip())
        for v in el.attrib.values():
            if v and v.strip():
                chunks.append(v.strip())
    return " ".join(chunks)


def _event_meta(root: Optional[ET.Element]) -> Dict[str, Optional[Union[str, int]]]:
    """Best-effort extraction of common EVTX metadata from XML."""
    if root is None:
        return {"provider": None, "event_id": None, "channel": None, "created": None}

    # Namespaces vary; {.*}X to match any ns
    provider = None
    prov_el = root.find(".//{*}Provider")
    if prov_el is not None:
        provider = prov_el.attrib.get("Name")

    event_id = None
    eid_el = root.find(".//{*}EventID")
    if eid_el is not None and eid_el.text and eid_el.text.isdigit():
        event_id = int(eid_el.text)

    channel = None
    ch_el = root.find(".//{*}Channel")
    if ch_el is not None and ch_el.text:
        channel = ch_el.text

    created = None
    tc_el = root.find(".//{*}TimeCreated")
    if tc_el is not None:
        created = tc_el.attrib.get("SystemTime")

    return {
        "provider": provider,
        "event_id": event_id,
        "channel": channel,
        "created": created,
    }


def _iter_ips(text: str) -> Iterator[str]:
    for m in RE_IPV4.finditer(text):
        yield m.group(0)
    for m in RE_IPV6.finditer(text):
        yield m.group(0)


def _is_allowed(
    ip: ipaddress._BaseAddress,
    ignore_private: bool,
    ignore_link_local: bool,
    ignore_reserved: bool,
    ignore_loopback: bool,
    ignore_multicast: bool,
) -> bool:
    """Apply simple allow/deny rules for common non-routable ranges."""
    if ignore_private and ip.is_private:
        return False
    if ignore_link_local and ip.is_link_local:
        return False
    if ignore_reserved and ip.is_reserved:
        return False
    if ignore_loopback and ip.is_loopback:
        return False
    if ignore_multicast and ip.is_multicast:
        return False
    return True


# -------- NEW: plain-text fallback scanner (for non-EVTX inputs) --------
def _scan_text_file_for_ips(
    path: str,
    include_context: bool,
    allow_fn,
) -> tuple[List[Dict], Set[str]]:
    results: List[Dict] = []
    unique: Set[str] = set()

    try:
        with open(path, "rb") as f:
            data = f.read()
        # best-effort decode
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        return results, unique

    for raw in _iter_ips(text):
        try:
            ip_obj = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if not allow_fn(ip_obj):
            continue
        ip_s = str(ip_obj)
        unique.add(ip_s)
        if include_context:
            # No EVTX metadata available for plain text
            results.append(
                {
                    "ip": ip_s,
                    "event_record_id": None,
                    "created": None,
                    "channel": None,
                    "provider": None,
                    "event_id": None,
                }
            )
    return results, unique
# ------------------------------------------------------------------------

def extract_ips_from_evtx_files(
    evtx_paths: Iterable[str],
    include_context: bool = True,
    ignore_private: bool = True,
    ignore_link_local: bool = True,
    ignore_reserved: bool = False,
    ignore_loopback: bool = True,
    ignore_multicast: bool = True,
) -> Dict:
    """
    Parse one or more EVTX files and return:
      {
        "records": [ {ip, event_record_id, created, channel, provider, event_id}, ... ],
        "unique_ips": ["1.2.3.4", "2001:db8::1", ...],
        "counts": {"records": N, "unique_ips": M}
      }

    If a file is not a valid EVTX OR yields zero records, fall back to plain-text regex scanning.
    """
    def allow(ip_obj: ipaddress._BaseAddress) -> bool:
        return _is_allowed(
            ip_obj,
            ignore_private=ignore_private,
            ignore_link_local=ignore_link_local,
            ignore_reserved=ignore_reserved,
            ignore_loopback=ignore_loopback,
            ignore_multicast=ignore_multicast,
        )

    results: List[Dict] = []
    seen_pair: Set[Tuple[str, Optional[int]]] = set()
    all_ips: Set[str] = set()

    for path in evtx_paths:
        parsed_as_evtx = False
        saw_any_record = False  # <-- new

        # Try EVTX parsing first
        try:
            with Evtx(path) as log:
                parsed_as_evtx = True
                for record in log.records():
                    saw_any_record = True  # <-- new
                    xml = record.xml()
                    root = _safe_xml(xml)
                    text = _gather_text(root) if root is not None else xml
                    meta = _event_meta(root)

                    for raw in _iter_ips(text):
                        try:
                            ip_obj = ipaddress.ip_address(raw)
                        except ValueError:
                            continue
                        if not allow(ip_obj):
                            continue

                        ip_s = str(ip_obj)
                        all_ips.add(ip_s)

                        if include_context:
                            key = (ip_s, record.event_record_id())
                            if key in seen_pair:
                                continue
                            seen_pair.add(key)
                            results.append(
                                {
                                    "ip": ip_s,
                                    "event_record_id": record.event_record_id(),
                                    "created": meta.get("created"),
                                    "channel": meta.get("channel"),
                                    "provider": meta.get("provider"),
                                    "event_id": meta.get("event_id"),
                                }
                            )
        except Exception:
            parsed_as_evtx = False  # fall through to text scan

        # NEW: If not EVTX OR yielded zero records, do a plain-text scan
        if (not parsed_as_evtx) or (parsed_as_evtx and not saw_any_record):
            recs, uniq = _scan_text_file_for_ips(path, include_context, allow)
            for ip_s in uniq:
                all_ips.add(ip_s)
            if include_context:
                for r in recs:
                    key = (r["ip"], r["event_record_id"])  # (ip, None) in text mode
                    if key in seen_pair:
                        continue
                    seen_pair.add(key)
                    results.append(r)

    payload = {
        "unique_ips": sorted(all_ips),
        "counts": {
            "records": len(results) if include_context else 0,
            "unique_ips": len(all_ips),
        },
    }
    payload["records"] = results if include_context else []
    return payload