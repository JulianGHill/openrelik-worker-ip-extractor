from __future__ import annotations
import ipaddress
import io
import os
import re
import gzip
import bz2
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple
from datetime import datetime

try:
    # Optional but nice to have (add to pyproject deps). If missing, we’ll fall back.
    from dateutil import parser as dateutil_parser  # type: ignore
except Exception:  # pragma: no cover
    dateutil_parser = None  # type: ignore

# Reuse the same IP regexes idea you used for EVTX
RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
RE_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b")

# Common timestamp shapes we’ll try, in order of likelihood
SYSLOG_TS = [
    # RFC 3164-ish: "Oct  8 12:34:56", "Sep  2 03:04:05"
    re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d"),
    # RFC 5424-ish / ISO 8601 variants
    re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2})?"),
    # e.g., "2025-09-02T19:05:00"
    re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"),
]

# Simple Apache/Nginx time like: [08/Oct/2024:12:34:56 +0000]
RE_WEB_TIME = re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+\-]\d{4})\]")

# Quick detector for access-log-ish line (combined/common); not strict
RE_ACCESS_HINT = re.compile(r'"\S+\s+\S+\s+HTTP/\d\.\d"|HTTP/\d\.\d"\s+\d{3}\s+\d+')

def _iter_ips(s: str) -> Iterator[str]:
    for m in RE_IPV4.finditer(s):
        yield m.group(0)
    for m in RE_IPV6.finditer(s):
        yield m.group(0)

def _allowed(ip: ipaddress._BaseAddress,
             ignore_private: bool,
             ignore_link_local: bool,
             ignore_reserved: bool,
             ignore_loopback: bool,
             ignore_multicast: bool) -> bool:
    if ignore_private and ip.is_private: return False
    if ignore_link_local and ip.is_link_local: return False
    if ignore_reserved and ip.is_reserved: return False
    if ignore_loopback and ip.is_loopback: return False
    if ignore_multicast and ip.is_multicast: return False
    return True

def _open_text_any(path: str) -> io.TextIOBase:
    # transparently read .gz/.bz2/.log/*.*
    if path.endswith(".gz"):
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="ignore")
    if path.endswith(".bz2"):
        return io.TextIOWrapper(bz2.open(path, "rb"), encoding="utf-8", errors="ignore")
    return open(path, "r", encoding="utf-8", errors="ignore")

def _parse_ts(line: str) -> Optional[str]:
    # 1) web logs: [08/Oct/2024:12:34:56 +0000]
    m = RE_WEB_TIME.search(line)
    if m:
        try:
            dt = datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S %z")
            return dt.isoformat()
        except Exception:
            pass
    # 2) syslog-ish candidates
    for rx in SYSLOG_TS:
        m = rx.search(line)
        if m:
            ts = m.group(0)
            # Fuzzy parsing if dateutil is available; else return raw
            if dateutil_parser:
                try:
                    dt = dateutil_parser.parse(ts, fuzzy=True)
                    return dt.isoformat()
                except Exception:
                    return ts
            return ts
    return None

def _likely_access_log(line: str) -> bool:
    return bool(RE_ACCESS_HINT.search(line))

def extract_ips_from_text_files(
    log_paths: Iterable[str],
    include_context: bool = True,
    ignore_private: bool = True,
    ignore_link_local: bool = True,
    ignore_reserved: bool = False,
    ignore_loopback: bool = True,
    ignore_multicast: bool = True,
) -> Dict:
    """
    Extract IPs from generic Linux text logs (.log, syslog, auth.log, messages, access logs, .gz/.bz2).
    Returns:
      {
        "records": [ {ip, created, source, line_no, kind}, ... ],
        "unique_ips": [...],
        "counts": {"records": N, "unique_ips": M}
      }
    """
    unique: Set[str] = set()
    records: List[Dict] = []

    def allow(ip_obj: ipaddress._BaseAddress) -> bool:
        return _allowed(ip_obj, ignore_private, ignore_link_local, ignore_reserved, ignore_loopback, ignore_multicast)

    for path in log_paths:
        if not os.path.isfile(path):
            continue
        try:
            with _open_text_any(path) as fh:
                for idx, line in enumerate(fh, 1):
                    hits = []
                    for raw in _iter_ips(line):
                        try:
                            ip_obj = ipaddress.ip_address(raw)
                        except ValueError:
                            continue
                        if not allow(ip_obj):
                            continue
                        ip_s = str(ip_obj)
                        hits.append(ip_s)
                    if not hits:
                        continue

                    ts = _parse_ts(line)
                    kind = "access" if _likely_access_log(line) else "syslog"

                    for ip_s in hits:
                        if include_context:
                            records.append({
                                "ip": ip_s,
                                "created": ts,
                                "source": path,
                                "line_no": idx,
                                "kind": kind,
                            })
                        unique.add(ip_s)
        except Exception:
            # Ignore unreadable/corrupt files quietly; you can log if you like
            continue

    payload = {
        "unique_ips": sorted(unique),
        "counts": {"records": len(records) if include_context else 0, "unique_ips": len(unique)},
    }
    payload["records"] = records if include_context else []
    return payload
