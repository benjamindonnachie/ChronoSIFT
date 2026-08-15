#!/usr/bin/env python3
"""
ChronoSift – deterministic behavioural scoring over forensic super-timelines

Single-file research implementation.

ChronoSift consumes a Plaso-derived timeline DataFrame (typically imported from JSONL/JSON)
and emits:


# -----------------------------------------------------------------------------
# GeoIP Enrichment Design Rationale
# -----------------------------------------------------------------------------
# ChronoSift performs GeoIP enrichment using a *unique-IP lookup + merge*
# approach rather than per-row lookups with caching.
#
# Rationale:
#
# 1. Deterministic behaviour
#    Each IP is looked up exactly once and produces a stable enrichment table.
#    This avoids cache eviction effects and ensures repeatable results across
#    runs, which is important for research reproducibility.
#
# 2. Auditability
#    The intermediate enrichment table (IP → geo attributes) can be inspected
#    independently. This is useful for validating unusual infrastructure
#    locations and for thesis evaluation.
#
# 3. Performance on large timelines
#    Plaso timelines often contain millions of rows but relatively few unique
#    IP addresses. Looking up unique IPs and merging is significantly faster
#    than invoking a cached lookup function per event.
#
# 4. Architectural clarity
#    The enrichment stage is explicitly separated from scoring logic:
#
#        Extraction → Normalisation → Enrichment → Scoring
#
#    This keeps ChronoSift explainable and easier to extend.
#
# Caching may be introduced later for streaming or interactive use, but batch
# forensic processing benefits from the explicit enrichment-table approach.
# -----------------------------------------------------------------------------
- per-event `chronosift_signals`: dict(signal_name -> numeric or auxiliary)
- per-event `chronosift_score`: weighted sum of numeric signals (capped)
- per-event `chronosift_explain`: list of rule firings + modifiers + profiling multipliers

Key research-driven design decisions
-----------------------------------
1) Post-breach / disk image constraint:
   - No reliable live sockets; PID may be absent/inconsistent; operate on artefacts Plaso extracts.

2) Heterogeneous schemas:
   - Plaso outputs vary by parser coverage and platform. Rules must be robust under missing fields.

3) Stable schema for rule evaluation:
   - Fields referenced in YAML are ensured as DataFrame columns; missing columns are created as None.

4) Placeholder strings:
   - Placeholder artefacts (e.g., "-", "N/A") are treated as semantic nulls globally.
   - This prevents accidental matches and improves temporal key stability (no grouping on "-").

5) Normalisation:
   - Prefer structured fields (ip_address, username, port, url, http_request_user_agent).
   - Message parsing is supported as fallback only.

6) `exists` operator:
   - Supported for clarity, but generally optional because other operators are missing-safe and return
     False on None/empty. Use `exists` when you want explicit intent.
   - Future option (parked): an engine flag could auto-inject `exists` guards to keep YAML concise.

7) Dataset-wide quiet-time profiling:
   - Builds hour-of-week baseline (168 buckets) from the dataset itself.
   - Computes per-event `hour_rarity` in [0, 1] (surprisal with smoothing).
   - Quiet time does not create danger itself; it can modulate selected signals via multipliers.

8) Temporal composite saturation (PATCH ADDED):
   - Temporal rules may be keyed by multiple actor anchors (e.g., user and IP).
   - If both keys exist, the same composite signal could otherwise be emitted twice.
   - We saturate temporal numeric emits to 1.0 per signal per event to avoid inflation.
     Semantics: “composite behaviour occurred”, not “occurred twice because two keys existed”.

What is intentionally not in this file (future work)
----------------------------------------------------
- Safe signal computation (explicitly removed per your instruction).
- Multi-host correlation (host field unreliable; dead-box composites use a
  global sentinel key so all events correlate as a single host).
- MaxMind enrichment (city/country/ASN) – integrate as a pre-processing stage.
- Adaptive antigen definitions beyond fixed windows.
"""

# =============================================================================
# ChronoSift authoritative consolidated baseline
# =============================================================================
# This file consolidates the active baseline features into a single engine:
# - YAML-driven normalisation and rule evaluation
# - AV and Luhn CSV enrichment inside apply()
# - NSRL SQLite enrichment inside apply()
# - structured-first IP recovery
# - GeoLite2 City/ASN enrichment via join()
# - enrichment-owned field exclusions in ensure_required_fields()
# - overlap-safe GeoIP join
# - hour-of-week profiling
# - impossible travel
# - temporal-rule-aware config validation
# - NaT guard for DatetimeIndex integrity
# =============================================================================



# =============================================================================
# ChronoSift baseline release note
# =============================================================================
# This file is the cleaned research baseline incorporating:
# - placeholder-safe normalisation
# - YARA count normalisation
# - structured-first IP recovery
# - unique-IP GeoLite2 enrichment
# - hour-of-week profiling (hour_rarity / quiet_time_event)
# - impossible travel on configurable actor continuity
# - config/weight alignment checks
# - reproducibility metadata in df.attrs
# =============================================================================


from __future__ import annotations

from pathlib import Path

import ast
import bisect
import json
import logging
import math
import os
import posixpath
import datetime
import time
import re
import shutil
import warnings
from decimal import Decimal, InvalidOperation
from xml.etree import ElementTree as ET
from dataclasses import dataclass
from datetime import timedelta
from functools import lru_cache
from itertools import islice
from typing import Any, ClassVar, Dict, Iterable, List, Optional, Set, Tuple, Union
from urllib.parse import parse_qsl, unquote, unquote_plus, urlparse

import numpy as np
import pandas as pd
import pyarrow as pa

import duckdb  # required dependency since v2.31

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore

import ipaddress

def _geoip_db_metadata(path: str | None) -> dict | None:
    """Return reproducibility metadata for a GeoLite2 MMDB file."""
    if not path:
        return None
    try:
        p = Path(path)
        st = p.stat()
        return {
            "path": str(p),
            "mtime_utc": datetime.datetime.utcfromtimestamp(st.st_mtime).replace(tzinfo=datetime.timezone.utc).isoformat(),
            "size_bytes": int(st.st_size),
        }
    except Exception:
        return {"path": str(path)}

import geoip2.database as geoip2_database  # required dependency since v2.31


try:
    import yaml  # type: ignore
except ImportError as e:
    raise SystemExit("PyYAML is required. Install with: pip install pyyaml") from e


Number = Union[int, float]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger(__name__)

CHRONOSIFT_ROW_ID_COLUMN = "chronosift_row_id"
# Sidecar outputs intentionally contain only derived ChronoSift/enrichment
# fields plus this stable row key. The preserved base parquet remains the
# source of truth for original event columns.
CHRONOSIFT_SIDECAR_PREFIXES = ("chronosift_", "geo_", "travel_")
CHRONOSIFT_SIDECAR_COLUMNS = {
    "av_hit",
    "luhn_hit",
    "nsrl_application_type",
    "nsrl_is_os_component",
    "yara_match_count",
    "yara_hit_strength",
    "hour_of_week",
    "hour_rarity",
    "quiet_time_event",
    "event_identifier",
    "logon_type",
    "client_address",
    "source_network_address",
    "rdp_client_address",
    "workstation_name",
    "authentication_package",
    "logon_process",
    "provider_name",
    "event_channel",
    "target_user_name",
    "target_domain_name",
    "subject_user_name",
    "subject_domain_name",
    "group_name",
    "member_name",
    "share_name",
    "share_local_path",
    "relative_target_name",
    "rdp_session_name",
    "actor_principal",
    "src_ip",
    "dst_ip",
    "auth_protocol",
    "auth_direction",
    "auth_outcome",
    "session_id",
    "logon_id",
    "destination_ip",
    "destination_fqdn",
    "destination_hostname",
    "pivot_dest_key",
}

DEFAULT_SCHEMA_ALIASES: Dict[str, Tuple[str, ...]] = {
    "event_identifier": ("event_id", "eventid"),
    "actor_user": ("user_name", "account_name", "target_username"),
    "actor_principal": ("actor_user", "username", "user", "target_user_name"),
    "ip_address": ("source_ip", "src_ip", "client_ip", "remote_ip", "ip"),
    "src_ip": ("ip_address", "source_ip", "client_ip", "remote_ip", "ip", "actor_ip_final"),
    "dst_ip": ("destination_ip", "dest_ip", "server_ip", "target_ip"),
    "destination_ip": ("dst_ip", "dest_ip", "server_ip", "target_ip"),
    "destination_fqdn": ("dest_fqdn", "target_fqdn", "fqdn", "server_name", "dns_name"),
    "destination_hostname": ("dest_hostname", "target_hostname", "hostname", "host_name", "computer_name", "workstation_name"),
    "provider_name": ("provider",),
    "event_channel": ("channel",),
    "group_name": ("group", "groupname"),
    "member_name": ("member", "membername"),
    "share_name": ("sharename",),
    "share_local_path": ("sharelocalpath",),
    "relative_target_name": ("relativetargetname", "relativepathname"),
    "logon_id": ("target_logon_id", "logonid", "logon_guid"),
    "session_id": ("sessionid", "session_id"),
    "http_request_body": ("request_body", "request_body_text", "post_data", "form_data", "http_post_data"),
    "http_content_disposition": ("content_disposition", "multipart_content_disposition", "part_content_disposition"),
    "http_upload_filename": ("upload_filename", "multipart_filename", "part_filename", "file_name"),
    "http_upload_content_type": ("upload_content_type", "multipart_content_type", "part_content_type", "mime_type"),
    "http_upload_sha256": ("upload_sha256", "body_sha256", "request_body_sha256", "part_sha256"),
    "http_request_content_length": ("request_content_length", "content_length", "body_size", "request_body_bytes"),
}


def _delete_columns_inplace(df: pd.DataFrame, columns: Iterable[str]) -> None:
    for col in columns:
        if col in df.columns:
            del df[col]


def _telemetry_rss_mb() -> Optional[float]:
    if psutil is None:
        if os.name == "nt":
            try:
                import ctypes

                class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                    _fields_ = [
                        ("cb", ctypes.c_ulong),
                        ("PageFaultCount", ctypes.c_ulong),
                        ("PeakWorkingSetSize", ctypes.c_size_t),
                        ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t),
                        ("PeakPagefileUsage", ctypes.c_size_t),
                    ]

                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                psapi_lib = ctypes.WinDLL("psapi", use_last_error=True)
                kernel32.GetCurrentProcess.restype = ctypes.c_void_p
                psapi_lib.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
                psapi_lib.GetProcessMemoryInfo.restype = ctypes.c_int

                counters = PROCESS_MEMORY_COUNTERS()
                counters.cb = ctypes.sizeof(counters)
                ok = psapi_lib.GetProcessMemoryInfo(
                    kernel32.GetCurrentProcess(),
                    ctypes.byref(counters),
                    counters.cb,
                )
                if ok:
                    return round(float(counters.WorkingSetSize) / (1024.0 * 1024.0), 2)
            except Exception:
                return None
        return None
    try:
        return round(float(psutil.Process(os.getpid()).memory_info().rss) / (1024.0 * 1024.0), 2)
    except Exception:
        return None


class _TelemetryWriter:
    def __init__(self, path: Optional[str]):
        self.path = str(path) if path else None
        self._fh = None

    def open(self) -> None:
        if not self.path:
            return
        out_path = Path(self.path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        # Truncate on open so reruns against the same output_root do not
        # silently combine telemetry from multiple runs into one JSONL.
        self._fh = out_path.open("w", encoding="utf-8")

    def close(self) -> None:
        if self._fh is None:
            return
        try:
            self._fh.close()
        finally:
            self._fh = None

    def emit(self, event: str, **fields: Any) -> None:
        if self._fh is None:
            return
        payload = {
            "ts_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event": event,
            "rss_mb": _telemetry_rss_mb(),
        }
        payload.update(fields)
        self._fh.write(json.dumps(payload, default=str) + "\n")
        self._fh.flush()

    def stage(self, stage: str, **fields: Any) -> "_TelemetryStage":
        return _TelemetryStage(self, stage, fields)


class _TelemetryStage:
    def __init__(self, writer: _TelemetryWriter, stage: str, fields: Dict[str, Any]):
        self.writer = writer
        self.stage = stage
        self.fields = dict(fields)
        self._start = 0.0

    def __enter__(self) -> "_TelemetryStage":
        self._start = time.perf_counter()
        self.writer.emit("stage_start", stage=self.stage, **self.fields)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        duration_s = round(time.perf_counter() - self._start, 6)
        status = "error" if exc_type is not None else "ok"
        extra: Dict[str, Any] = {
            "stage": self.stage,
            "status": status,
            "duration_s": duration_s,
        }
        if exc is not None:
            extra["error"] = str(exc)
        extra.update(self.fields)
        self.writer.emit("stage_end", **extra)


# =============================================================================
# Null-safe helpers (with placeholder normalisation)
# =============================================================================
#
# ChronoSift treats certain placeholder strings as semantic nulls.
# This avoids rule drift caused by parser artefacts such as "-", "N/A", etc.
#
# Keep this conservative: do NOT include "0" or "unknown" as placeholders,
# because they can be meaningful values (ports, legitimate log messages).
#

PLACEHOLDER_STRINGS = {"-", "--", "n/a", "na", "none", "null"}


def _is_null(x: Any) -> bool:
    """
    Unified null detection.

    Returns True for:
      - None
      - pandas NA / NaN
      - empty string
      - configured placeholder strings
    """
    if x is None:
        return True

    # Do not treat containers as null; their emptiness may be meaningful later.
    if isinstance(x, (dict, list)):
        return False

    try:
        if bool(pd.isna(x)):
            return True
    except Exception:
        pass

    if isinstance(x, str):
        s = x.strip()
        if not s:
            return True
        if s.lower() in PLACEHOLDER_STRINGS:
            return True

    return False


def _safe_str(x: Any) -> str:
    """Stable string conversion; semantic null (including placeholders) -> empty string."""
    if _is_null(x):
        return ""
    return str(x)


def _safe_num(x: Any) -> Optional[float]:
    """Stable numeric conversion; semantic null (including placeholders) -> None."""
    if _is_null(x):
        return None
    try:
        return float(x)
    except Exception:
        return None


def _normalise_integral_metadata_value(x: Any) -> Optional[int]:
    """Normalise metadata values that should remain integral across explain payloads."""
    if _is_null(x):
        return None

    if isinstance(x, (int, np.integer)) and not isinstance(x, (bool, np.bool_)):
        return int(x)

    if isinstance(x, (float, np.floating)):
        try:
            if bool(pd.isna(x)):
                return None
        except Exception:
            pass
        return int(x)

    if isinstance(x, str):
        s = x.strip()
        if not s or s.lower() in PLACEHOLDER_STRINGS:
            return None
        try:
            dec = Decimal(s)
        except InvalidOperation:
            return None
        if not dec.is_finite():
            return None
        return int(dec)

    try:
        return int(x)
    except Exception:
        return None


# =============================================================================
# Normalisation methods (fallback parsing is intentionally conservative)
# =============================================================================

# Strict IPv4 to avoid version numbers; still only a fallback if structured fields absent.
_IPV4_STRICT = re.compile(
    r"(?<![\w.-])"
    r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?![\w.-])"
)
_IPV4_CANDIDATE_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){1,3}")
_IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Fa-f])"
    r"(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.%]+"
    r"(?![0-9A-Fa-f])"
)
_IP_LITERAL_CANDIDATE_RE = re.compile(
    rf"(?:{_IPV4_CANDIDATE_RE.pattern})|(?:{_IPV6_CANDIDATE_RE.pattern})"
)

_WINDOWS_EVENT_FIELD_ALIASES = {
    "event_identifier": ("eventid",),
    "logon_type": ("logontype",),
    "client_address": ("clientaddress", "clientip", "ipaddress", "remoteaddress", "remoteip"),
    "source_network_address": ("sourcenetworkaddress", "networkaddress", "sourceip", "srcip", "peeraddress"),
    "workstation_name": ("workstationname", "workstation"),
    "authentication_package": ("authenticationpackagename", "authenticationpackage"),
    "logon_process": ("logonprocessname", "logonprocess"),
    "provider_name": ("providername",),
    "event_channel": ("channel",),
    "target_user_name": ("targetusername",),
    "target_domain_name": ("targetdomainname",),
    "subject_user_name": ("subjectusername",),
    "subject_domain_name": ("subjectdomainname",),
    "group_name": ("groupname",),
    "member_name": ("membername", "member"),
    "share_name": ("sharename",),
    "share_local_path": ("sharelocalpath",),
    "relative_target_name": ("relativetargetname", "relativepathname"),
    "rdp_session_name": ("sessionname",),
    "logon_id": ("targetlogonid", "logonid", "logonguid"),
    "session_id": ("sessionid", "sessionidentifier"),
    "new_process_name": ("newprocessname",),
    "parent_process_name": ("parentprocessname", "parentimage", "creatorprocessname"),
    "command_line": ("commandline", "processcommandline"),
    "parent_command_line": ("parentcommandline",),
}
_WINDOWS_AUTH_ADDRESS_PLACEHOLDERS = {
    "",
    "-",
    "::1",
    "127.0.0.1",
    "0.0.0.0",
    "::",
    "local",
    "localhost",
    "local machine",
}

_SSH_ACCEPT_RE = re.compile(
    r"(?i)\baccepted\s+([a-z0-9_-]+(?:/[a-z0-9_-]+)?)\s+for\s+([A-Za-z0-9._$@-]+)\s+from\s+([0-9A-Fa-f:.]+)"
)
_SSH_FAIL_RE = re.compile(
    r"(?i)\bfailed\s+([a-z0-9_-]+(?:/[a-z0-9_-]+)?)\s+for(?:\s+invalid\s+user)?\s+([A-Za-z0-9._$@-]+)\s+from\s+([0-9A-Fa-f:.]+)"
)
_SSH_INVALID_USER_RE = re.compile(
    r"(?i)\binvalid user\s+([A-Za-z0-9._$@-]+)\s+from\s+([0-9A-Fa-f:.]+)"
)
_SSH_SESSION_OPEN_RE = re.compile(
    r"(?i)\bsession opened for user\s+([A-Za-z0-9._$@-]+)\b"
)
_SSH_ESCAPED_CONTROL_RE = re.compile(r"(?:\\r|\\n|\\t)+", re.IGNORECASE)
_HTTP_REQUEST_LINE_RE = re.compile(
    r"(?i)\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)(?:\s+HTTP/\d(?:\.\d)?)?"
)
_UPLOAD_FILENAME_RE = re.compile(
    r"(?i)\bfilename\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s;]+))"
)
_UPLOAD_FILENAME_STAR_RE = re.compile(
    r"(?i)\bfilename\*\s*=\s*(?:[A-Za-z0-9._-]+'[^']*')?([^\s;]+)"
)
_UPLOAD_SHA256_RE = re.compile(r"(?i)\b(?:sha-?256|body_sha256|file_hash)\s*[=:]\s*([0-9a-f]{64})\b")
_MULTIPART_CONTENT_TYPE_RE = re.compile(r"(?im)^\s*content-type\s*:\s*([^\r\n;]+)")
_HTTP_UPLOAD_QUERY_KEYS = (
    "filename",
    "file",
    "name",
    "path",
    "upload",
    "uploadfile",
    "qqfile",
    "dest",
    "destination",
)


def normalise_regex_first(value: Any, pattern: str, group: int = 0, flags: int = 0) -> Optional[str]:
    """Return the first regex match group (or whole match) or None."""
    s = _safe_str(value)
    if not s:
        return None
    rx = re.compile(pattern, flags)
    m = rx.search(s)
    if not m:
        return None
    try:
        return m.group(group)
    except IndexError:
        return m.group(0)


def normalise_file_extension(filename: Any) -> Optional[str]:
    """Return lowercase file extension including dot, or None."""
    s = _safe_str(filename).strip()
    if not s:
        return None
    idx = s.rfind(".")
    if idx <= 0 or idx == len(s) - 1:
        return None
    ext = s[idx:].lower()
    if len(ext) > 12:
        return None
    return ext


def normalise_ipv4_first(message: Any) -> Optional[str]:
    """Fallback-only IPv4 extraction from free text."""
    s = _safe_str(message)
    if not s:
        return None
    m = _IPV4_STRICT.search(s)
    return m.group(0) if m else None


def normalise_ipv4_first_series(series: "pd.Series") -> "pd.Series":
    if len(series) == 0:
        return pd.Series(np.array([], dtype=object), index=series.index, dtype=object)
    values = np.fromiter(
        (normalise_ipv4_first(v) for v in series.to_numpy(copy=False)),
        dtype=object,
        count=len(series),
    )
    return pd.Series(values, index=series.index, dtype=object)


# -----------------------------------------------------------------------------
# IP recovery helpers (Windows EVTX + URL promotion)
# -----------------------------------------------------------------------------
#
# Quirk (Plaso):
#   Windows EVT/EVTX parsers (winevt*, winevtx*) often do NOT populate `ip_address`
#   even when a remote/client IP is present (e.g., RDP logons). The IP remains in:
#     - xml_string (full EVTX XML)
#     - strings (rendered message fragments)
#
#   Additionally, some artefacts record destination infrastructure as URLs
#   (e.g., Explorer/WinINet FTP): 'admin@ftp://185.239.106.67/...'
#   In these cases the IP appears in `url` (or related HTTP fields), not `ip_address`.
#
# ChronoSift therefore performs a deterministic, structured-first recovery:
#   1) Preserve existing ip_address if present
#   2) For winevt*/winevtx*: parse xml_string (EventData/Data Name=...) then scan strings
#   3) Promote IPv4 literals from url/http fields
#   4) As a last resort, scan message/text only when clear network context tokens exist
#
# This avoids the earlier false-positive problem where naive regex matched version numbers
# (e.g., '...-7.8.19.0.fw').

_EVTX_IP_FIELDNAMES = {
    "ipaddress",
    "ip_address",
    "source network address",
    "sourcenetworkaddress",
    "clientaddress",
    "clientip",
    "remoteaddress",
    "remoteip",
    "sourceip",
    "srcip",
    "peeraddress",
    "networkaddress",
}

_NET_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"ftp://|sftp://|scp://|http://|https://|smb://|cifs://|rdp://|ssh://|"
    r"\bhost:\b|\bclient\b|\bremote\b|\bfrom\b|\bto\b|\bsrc\b|\bdst\b|"
    r"\bconnect\b|\bconnected\b|\blogon\b|\bauth\b"
    r")"
)

def _strip_user_prefix(s: str) -> str:
    """
    Remove a leading 'user@' prefix when it precedes a URL scheme (or 'Host:' token),
    e.g. 'admin@ftp://1.2.3.4/' -> 'ftp://1.2.3.4/'.
    """
    if not s:
        return s
    s2 = re.sub(r"^[^@\s]{1,64}@(ftp|sftp|scp|http|https|smb|cifs)://", r"\1://", s, flags=re.I)
    if s2 != s:
        return s2
    s2 = re.sub(r"^[^@\s]{1,64}@:\s*(Host:)", r"\1", s, flags=re.I)
    return s2

def _strip_xml_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _normalise_windows_event_field_name(name: Any) -> str:
    return re.sub(r"[\s_\-]+", "", _safe_str(name).strip().lower())


def _normalise_windows_auth_value(value: Any) -> Optional[str]:
    s = _safe_str(value).strip()
    if not s:
        return None
    if s.lower() in _WINDOWS_AUTH_ADDRESS_PLACEHOLDERS:
        return None
    return s


def _normalise_ip_literal(value: Any) -> Optional[str]:
    s = _safe_str(value).strip().strip("[](){}<>.,;:'\"")
    if not s:
        return None
    if s.lower() in _WINDOWS_AUTH_ADDRESS_PLACEHOLDERS:
        return None
    if s.startswith("::ffff:"):
        try:
            mapped = ipaddress.ip_address(s)
            if getattr(mapped, "ipv4_mapped", None) is not None:
                s = str(mapped.ipv4_mapped)
        except Exception:
            pass
    try:
        ip_obj = ipaddress.ip_address(s)
    except Exception:
        return None
    if ip_obj.is_loopback or ip_obj.is_unspecified:
        return None
    return ip_obj.compressed


def _extract_ip_literal_from_text(value: Any) -> Optional[str]:
    s = _strip_user_prefix(_safe_str(value))
    if not s:
        return None
    m = _IPV4_STRICT.search(s)
    if m:
        ip_s = _normalise_ip_literal(m.group(0))
        if ip_s:
            return ip_s
    for match in _IPV6_CANDIDATE_RE.finditer(s):
        ip_s = _normalise_ip_literal(match.group(0))
        if ip_s:
            return ip_s
    return None


def _extract_windows_event_values_from_evtx_xml(xml_string: Any) -> Dict[str, Optional[str]]:
    """
    Parse Windows EVTX XML once and extract structured auth/RDP fields.

    This stage exists so Windows rules can operate on stable event semantics
    (event ID, logon type, client address, provider/channel) instead of costly
    or brittle free-text matching. The parser is intentionally conservative:
    it normalises known placeholders to nulls and only derives `rdp_client_address`
    from explicit network-address fields.
    """
    extracted = {name: None for name in _WINDOWS_EVENT_FIELD_ALIASES}
    s = _safe_str(xml_string)
    if not s:
        extracted["rdp_client_address"] = None
        return extracted

    try:
        root = ET.fromstring(s)
    except Exception:
        extracted["rdp_client_address"] = None
        return extracted

    data_map: Dict[str, str] = {}
    provider_name: Optional[str] = None
    event_channel: Optional[str] = None
    event_identifier: Optional[str] = None

    for elem in root.iter():
        tag = _strip_xml_ns(elem.tag).lower()
        if tag == "provider" and not provider_name:
            provider_name = _normalise_windows_auth_value(elem.attrib.get("Name"))
        elif tag == "channel" and not event_channel:
            event_channel = _normalise_windows_auth_value(elem.text)
        elif tag == "eventid" and not event_identifier:
            event_identifier = _normalise_windows_auth_value(elem.text)
        elif tag in {"data", "param"}:
            key = _normalise_windows_event_field_name(elem.attrib.get("Name", ""))
            val = _normalise_windows_auth_value(elem.text)
            if key and val and key not in data_map:
                data_map[key] = val

    extracted["provider_name"] = provider_name or data_map.get("providername")
    extracted["event_channel"] = event_channel or data_map.get("channel")
    extracted["event_identifier"] = event_identifier or data_map.get("eventid")

    for out_name, aliases in _WINDOWS_EVENT_FIELD_ALIASES.items():
        if extracted.get(out_name):
            continue
        for alias in aliases:
            val = data_map.get(alias)
            if val:
                extracted[out_name] = val
                break

    client_address = None
    for field_name in ("client_address", "source_network_address"):
        ip_s = _normalise_ip_literal(extracted.get(field_name))
        if ip_s:
            client_address = ip_s
            break
    extracted["rdp_client_address"] = client_address
    extracted["src_ip"] = client_address

    event_id = _safe_str(extracted.get("event_identifier")).strip()
    logon_type = _safe_str(extracted.get("logon_type")).strip()
    if event_id in {"4624", "1149", "4778"}:
        extracted["auth_outcome"] = "success"
    elif event_id in {"4625", "4779"}:
        extracted["auth_outcome"] = "failure"
    else:
        extracted["auth_outcome"] = None

    extracted["auth_direction"] = "remote" if client_address else None
    if event_id == "1149" or logon_type == "10":
        extracted["auth_protocol"] = "rdp"
    elif logon_type == "3" and client_address:
        extracted["auth_protocol"] = "windows-network"
    else:
        extracted["auth_protocol"] = None
    extracted["dst_ip"] = None
    extracted["session_id"] = extracted.get("session_id")
    return extracted


def _extract_ip_from_evtx_xml(xml_string: Any) -> Optional[str]:
    """
    Extract an IP literal from Windows EVTX xml_string.

    Only returns addresses from explicitly named EVTX fields (IpAddress,
    Source Network Address, client_address, etc.) which are reliably the
    actor/source IP.  A previous whole-XML text scan fallback was removed
    because it could misattribute destination or incidental addresses as
    the source, corrupting downstream auth direction/protocol derivation.
    """
    extracted = _extract_windows_event_values_from_evtx_xml(xml_string)
    ip_s = _normalise_ip_literal(extracted.get("rdp_client_address"))
    if ip_s:
        return ip_s
    # Do NOT fall back to free-text IP scanning — it is unreliable and can
    # attribute destination or incidental addresses as the actor/source IP.
    return None


def _extract_http_request_semantics(*values: Any) -> Dict[str, Optional[str]]:
    """
    Recover coarse HTTP request semantics from sparse web-log fields.

    Plaso exports are inconsistent across web parsers, so this accepts raw
    request-line text from `message`, `http_request`, or `url` and returns a
    bounded method/path pair when one is recoverable.
    """
    normalised_values = tuple(
        s for s in (_safe_str(value).strip() for value in values) if s
    )
    method, path = _extract_http_request_semantics_cached(normalised_values)
    return {"method": method, "path": path}


@lru_cache(maxsize=32768)
def _extract_http_request_semantics_cached(values: Tuple[str, ...]) -> Tuple[Optional[str], Optional[str]]:
    for s in values:
        w3c_method = normalise_regex_first(s, r"(?i)\bcs-method=([A-Z]+)\b", group=1)
        w3c_path = normalise_regex_first(s, r"(?i)\bcs-uri-stem=(\S+)", group=1)
        w3c_query = normalise_regex_first(s, r"(?i)\bcs-uri-query=(\S+)", group=1)
        if w3c_method or w3c_path:
            path = _safe_str(w3c_path).strip()
            query = _safe_str(w3c_query).strip()
            if path and query and query != "-":
                path = f"{path}?{query}"
            return _safe_str(w3c_method).strip().upper() or None, path or None
        m = _HTTP_REQUEST_LINE_RE.search(s)
        if m:
            return m.group(1).upper(), m.group(2)
        if "://" in s:
            try:
                parsed = urlparse(s)
                path = parsed.path or "/"
                if parsed.query:
                    path = f"{path}?{parsed.query}"
                return None, path
            except Exception:
                continue
    return None, None


@lru_cache(maxsize=131072)
def _canonical_web_request_path_from_string(value: str) -> Optional[str]:
    """Return a stable URL-path identity for web/filesystem correlation."""
    candidate = value.strip()
    if not candidate:
        return None
    try:
        parsed = urlparse(candidate if "://" in candidate else f"http://localhost{candidate if candidate.startswith('/') else '/' + candidate}")
        candidate = parsed.path
    except Exception:
        candidate = candidate.split("?", 1)[0].split("#", 1)[0]
    try:
        candidate = unquote(candidate)
    except Exception:
        pass
    candidate = candidate.replace("\\", "/")
    if not candidate.startswith("/"):
        candidate = f"/{candidate}"
    candidate = posixpath.normpath(candidate)
    if candidate == ".":
        return "/"
    return candidate or "/"


def _canonical_web_request_path(value: Any) -> Optional[str]:
    text = _safe_str(value).strip()
    if not text:
        return None
    return _canonical_web_request_path_from_string(text)


_SQLI_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = (
    ("union_select", re.compile(r"(?i)\bunion\s+(?:all\s+)?select\b")),
    ("schema_enumeration", re.compile(r"(?i)\binformation_schema\b|\b(?:table|column)_name\b")),
    ("database_function", re.compile(r"(?i)\b(?:database|version|current_user|user)\s*\(")),
    ("file_access", re.compile(r"(?i)\b(?:load_file|into\s+(?:out|dump)file)\b")),
    ("time_delay", re.compile(r"(?i)\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b")),
    ("error_based", re.compile(r"(?i)\b(?:extractvalue|updatexml)\s*\(")),
    ("stacked_query", re.compile(r"(?i);\s*(?:select|insert|update|delete|drop|alter|create)\b")),
    # A bare `<word> and <word>=<word>` shape matches ordinary prose once `+`
    # separators decode to spaces (`?q=cats+and+dogs=1`), so a tautology must
    # additionally show a quote/paren breakout artefact or a numeric
    # self-comparison — the forms that actually distinguish injected boolean
    # logic from a search phrase.
    ("boolean_tautology", re.compile(
        r"(?i)(?:"
        # Breakout quote or closing paren immediately before the operator:
        #   1' or 1=1     2%' and 5443=5443     2') and (3782=CONVERT(
        r"['\"`)]\s*(?:or|and)\s+[^\s&]{0,64}?="
        # Numeric left operand compared against another number (including the
        # blind `and 1=2` variant), a subquery, or a function call — as in
        # `and 5577=(select ...)`, `and 1644=cast(...)`, `and 9292=dbms_pipe.receive_message(...)`:
        r"|\b(?:or|and)\s+\(?\s*\d+\s*=\s*(?:\d+\b|[\w.]*\()"
        # Quoted operands on both sides:  or 'a'='a
        r"|\b(?:or|and)\s+['\"`]\s*[^\s&'\"`]*\s*['\"`]?\s*=\s*['\"`]"
        r")"
    )),
    ("ordered_probe", re.compile(r"(?i)\border\s+by\s+\d+\s*(?:--|#|/\*)")),
    # A parameter value that opens directly with a subquery, e.g.
    # `?id=(select concat(0x71,...))`.  Previously these were only caught
    # incidentally, because `concat` contains the `cat` command token.
    ("inline_subquery", re.compile(r"(?i)(?:^|[?&])[^=&]*=\s*\(\s*select\b")),
)


@lru_cache(maxsize=131072)
def _decode_http_detection_text_from_string(value: str) -> str:
    """Decode bounded URL escaping for web-attack signature evaluation."""
    decoded = value.strip()
    for _ in range(2):
        try:
            next_value = unquote_plus(decoded)
        except Exception:
            break
        if next_value == decoded:
            break
        decoded = next_value
    return decoded.lower()


def _http_sqli_indicators(value: Any) -> Tuple[str, ...]:
    text = _safe_str(value).strip()
    if not text:
        return tuple()
    decoded = _decode_http_detection_text_from_string(text)
    return tuple(name for name, pattern in _SQLI_PATTERNS if pattern.search(decoded))


_WEB_COMMAND_TOKEN_ALTERNATION = (
    r"sh|bash|dash|zsh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh"
    r"|whoami|id|uname|cat|type|curl|wget|nc|netcat"
)
# Command injection is asserted only when a command token sits in *command
# position* — directly after a shell separator, optionally via an absolute or
# relative program path.  Matching the token anywhere in the request instead
# flagged ordinary traffic, because `id`, `cat`, `type`, and `sh` are among the
# most common query-parameter names on the web and `&` is the standard query
# delimiter rather than a shell operator.  The trailing `(?!\s*=)` keeps
# parameter names such as `&amp;id=2` out of the match.
_WEB_COMMAND_INJECTION_RE = re.compile(
    r"(?i)(?:&&|\|\||\$\(|`|;|\|)\s*/?(?:[\w.-]+/)*"
    rf"(?:{_WEB_COMMAND_TOKEN_ALTERNATION})\b(?!\s*=)"
)
# A remote URL in a parameter is only inclusion evidence when the parameter is
# inclusion-shaped or the remote target is itself a script.  Plain redirect and
# OAuth callback parameters carry absolute URLs as a matter of course.
_WEB_RFI_PARAM_RE = re.compile(
    r"(?i)(?:^|[?&])\s*(?:page|file|path|template|include|inc|doc|document|lang"
    r"|module|dir|root|conf|config|load|read|show|pg)\s*=\s*https?://"
)
_WEB_RFI_REMOTE_SCRIPT_RE = re.compile(
    r"(?i)(?:^|[?&])[^=&]+\s*=\s*https?://[^\s&]+"
    r"\.(?:php|phtml|php[345]|asp|aspx|ashx|jsp|jspx|cgi|pl|py|rb|sh|txt)\b"
)
# Injection probing: a scanner testing whether a parameter can be broken out of
# quoting, without yet forming valid SQL.  This is evidence of an attempt only,
# never of success, and is scored accordingly.
_WEB_PROBE_BREAKOUT_RE = re.compile(r"['\"`]\s*[<>\"'`]|[<>]\s*['\"`]")
_WEB_PROBE_METACHAR_RE = re.compile(r"['\"`()<>]")
_WEB_PROBE_QUOTE_RE = re.compile(r"['\"`]")


def _http_injection_probe(decoded: str) -> bool:
    """Detect quote/metacharacter breakout probing in a decoded request target."""
    for parameter in re.split(r"[?&]", decoded):
        value = parameter.split("=", 1)[1] if "=" in parameter else parameter
        if not value:
            continue
        if _WEB_PROBE_BREAKOUT_RE.search(value):
            return True
        metacharacters = _WEB_PROBE_METACHAR_RE.findall(value)
        # A dense mix of metacharacters counts only when a quote is among them.
        # Balanced parentheses alone are ordinary in URLs such as
        # /wiki/Foo_(bar) or /calc?expr=(1+2)*(3+4).
        if (
            len(metacharacters) >= 4
            and len(set(metacharacters)) >= 2
            and _WEB_PROBE_QUOTE_RE.search(value)
        ):
            return True
    return False


def _http_attack_indicators(value: Any) -> Tuple[str, ...]:
    """Return normalized, evidence-level web attack indicators.

    These are features rather than ATT&CK mappings.  Mapping remains a
    separate step so an encoded traversal probe is not treated as successful
    exploitation merely because its request syntax is suspicious.
    """
    text = _safe_str(value).strip()
    if not text:
        return tuple()
    decoded = _decode_http_detection_text_from_string(text)
    lowered = text.lower()
    indicators: List[str] = [f"sqli:{name}" for name in _http_sqli_indicators(text)]
    # `decoded` has already absorbed two rounds of percent-decoding, so it
    # covers singly and doubly encoded traversal.  The raw-text check therefore
    # only needs to catch encoding depths beyond that, and must look for an
    # encoded *double* dot: a lone `%2e` is ordinary escaping of a filename dot.
    if (
        "../" in decoded
        or "..\\" in decoded
        or "%2e%2e" in lowered
        or "%252e" in lowered
    ):
        indicators.append("path_traversal")
    if any(token in decoded for token in (
        "/etc/passwd", "/etc/shadow", "proc/self/environ", "php://filter",
        "file://", "boot.ini", "win.ini",
    )):
        indicators.append("local_file_inclusion")
    if _WEB_RFI_PARAM_RE.search(decoded) or _WEB_RFI_REMOTE_SCRIPT_RE.search(decoded):
        indicators.append("remote_file_inclusion")
    if _WEB_COMMAND_INJECTION_RE.search(decoded):
        indicators.append("command_injection")
    if _http_injection_probe(decoded):
        indicators.append("injection_probe")
    if re.search(r"(?i)(?:^|[?&])(?:cmd|exec|command|shell)=", decoded):
        indicators.append("webshell_command_parameter")
    return tuple(dict.fromkeys(indicators))


def _http_header_value(headers: Any, name: str) -> Optional[str]:
    text = _safe_str(headers).strip()
    if not text:
        return None
    pattern = rf"(?im)(?:^|[;\r\n]\s*){re.escape(name)}\s*[:=]\s*([^;\r\n]+)"
    value = normalise_regex_first(text, pattern, group=1)
    return _safe_str(value).strip() or None


def _web_request_host(path_or_url: Any, headers: Any) -> Optional[str]:
    value = _safe_str(path_or_url).strip()
    if "://" in value:
        try:
            return (urlparse(value).hostname or "").strip().lower() or None
        except Exception:
            pass
    host = _http_header_value(headers, "host")
    if not host:
        return None
    return host.rsplit(":", 1)[0].strip("[]").lower() or None


def _web_path_aliases_for_filesystem_path(path: Any, document_roots: Iterable[str]) -> Tuple[str, ...]:
    """Map a filesystem path below a configured document root to URL aliases."""
    raw_path = _safe_str(path).strip().replace("\\", "/")
    if not raw_path:
        return tuple()
    while "//" in raw_path:
        raw_path = raw_path.replace("//", "/")
    path_folded = raw_path.casefold()
    aliases: List[str] = []
    seen: Set[str] = set()
    for configured_root in document_roots:
        root = _safe_str(configured_root).strip().replace("\\", "/").rstrip("/")
        if not root:
            continue
        root_folded = root.casefold()
        start = 0 if path_folded.startswith(f"{root_folded}/") else -1
        if start < 0 and not root_folded.startswith("/"):
            marker = f"/{root_folded.lstrip('/')}"
            marker_i = path_folded.find(marker)
            if marker_i >= 0:
                start = marker_i
                root_folded = marker
        if start < 0:
            continue
        remainder = raw_path[start + len(root_folded):].lstrip("/")
        alias = _canonical_web_request_path(remainder)
        if alias and alias not in seen:
            seen.add(alias)
            aliases.append(alias)
    return tuple(aliases)


def _normalise_upload_filename(value: Any) -> Optional[str]:
    candidate = unquote(_safe_str(value).strip(" '\""))
    candidate = os.path.basename(candidate.replace("\\", "/"))
    if not candidate or candidate in {".", ".."} or "." not in candidate:
        return None
    return candidate.casefold()


def _bounded_metadata_strings(value: Any, max_items: int = 32, max_chars: int = 65536) -> Tuple[str, ...]:
    """Flatten bounded structured metadata without retaining arbitrary request bodies."""
    pending: List[Any] = [value]
    out: List[str] = []
    total_chars = 0
    while pending and len(out) < max_items and total_chars < max_chars:
        current = pending.pop(0)
        if _is_null(current):
            continue
        if isinstance(current, dict):
            pending.extend(item for _, item in islice(current.items(), max_items))
            continue
        if isinstance(current, (list, tuple, set, np.ndarray, pd.Series)):
            pending.extend(islice(iter(current), max_items))
            continue
        remaining = max_chars - total_chars
        if isinstance(current, bytes):
            text = current[:remaining].decode("utf-8", errors="replace").strip()
        elif isinstance(current, str):
            text = current[:remaining].strip()
        else:
            text = _safe_str(current).strip()[:remaining]
        if not text:
            continue
        total_chars += len(text)
        out.append(text)
    return tuple(out)


def _extract_structured_upload_names(value: Any) -> Tuple[str, ...]:
    names: List[str] = []
    seen: Set[str] = set()
    for text in _bounded_metadata_strings(value):
        parsed = _extract_http_upload_names(text)
        candidates = parsed or tuple(
            token.strip() for token in re.split(r"[|,\r\n]+", text) if token.strip()
        )
        for candidate in candidates:
            name = _normalise_upload_filename(candidate)
            if name and name not in seen:
                seen.add(name)
                names.append(name)
    return tuple(names)


def _extract_http_upload_names(*values: Any) -> Tuple[str, ...]:
    normalised_values = tuple(
        text
        for value in values
        for text in _bounded_metadata_strings(value)
        if text
    )
    return _extract_http_upload_names_cached(normalised_values)


def _extract_http_upload_name(*values: Any) -> Optional[str]:
    """
    Recover a likely uploaded filename from sparse request fields.

    Supports multipart-style `filename=...`, full URLs, request paths with query
    strings, and W3C-style request fragments after `_extract_http_request_semantics`.
    """
    names = _extract_http_upload_names(*values)
    return names[0] if names else None


@lru_cache(maxsize=32768)
def _extract_http_upload_name_cached(values: Tuple[str, ...]) -> Optional[str]:
    """Compatibility wrapper retained for callers/tests of the cached helper."""
    names = _extract_http_upload_names_cached(values)
    return names[0] if names else None


@lru_cache(maxsize=32768)
def _extract_http_upload_names_cached(values: Tuple[str, ...]) -> Tuple[str, ...]:
    names: List[str] = []
    seen: Set[str] = set()
    for s in values:
        for match in _UPLOAD_FILENAME_STAR_RE.finditer(s):
            candidate = _normalise_upload_filename(match.group(1))
            if candidate and candidate not in seen:
                seen.add(candidate)
                names.append(candidate)
        for match in _UPLOAD_FILENAME_RE.finditer(s):
            candidate = _normalise_upload_filename(next((g for g in match.groups() if g is not None), ""))
            if candidate and candidate not in seen:
                seen.add(candidate)
                names.append(candidate)

        candidates: List[str] = []
        if "://" in s:
            candidates.append(s)
        else:
            _, http_path = _extract_http_request_semantics_cached((s,))
            http_path = _safe_str(http_path).strip()
            if http_path:
                candidates.append(http_path)
            elif s.startswith("/") or "?" in s:
                candidates.append(s if s.startswith("/") else f"/{s.lstrip('/')}")

        for candidate_value in candidates:
            try:
                parsed = urlparse(candidate_value if "://" in candidate_value else f"http://localhost{candidate_value}")
            except Exception:
                continue
            for key, val in parse_qsl(parsed.query, keep_blank_values=True):
                key_l = _safe_str(key).strip().lower()
                if key_l not in _HTTP_UPLOAD_QUERY_KEYS:
                    continue
                cleaned = _normalise_upload_filename(val)
                if cleaned and cleaned not in seen:
                    seen.add(cleaned)
                    names.append(cleaned)
    return tuple(names)


def _extract_upload_sha256_values(value: Any) -> Tuple[str, ...]:
    hashes: List[str] = []
    seen: Set[str] = set()
    for text in _bounded_metadata_strings(value):
        candidates = [text] if re.fullmatch(r"(?i)[0-9a-f]{64}", text.strip()) else []
        candidates.extend(match.group(1) for match in _UPLOAD_SHA256_RE.finditer(text))
        for candidate in candidates:
            normalised = candidate.strip().upper()
            if normalised not in seen:
                seen.add(normalised)
                hashes.append(normalised)
    return tuple(hashes)

def _extract_ip_from_strings_field(strings_field: Any) -> Optional[str]:
    """
    Extract an IPv4/IPv6 literal from the EVTX `strings` field.
    """
    if strings_field is None:
        return None
    if isinstance(strings_field, list):
        joined = " ".join(s for s in (_safe_str(x) for x in strings_field) if s)
        return _extract_ip_literal_from_text(joined)

    s = _safe_str(strings_field)
    if not s:
        return None
    return _extract_ip_literal_from_text(s)


def _extract_ip_from_text_field(value: Any, require_context: bool = False) -> Optional[str]:
    """Extract a strict IPv4/IPv6 literal from a text-like field after user-prefix stripping."""
    s = _strip_user_prefix(_safe_str(value))
    if not s:
        return None
    if require_context and _NET_CONTEXT_RE.search(s) is None:
        return None
    return _extract_ip_literal_from_text(s)


def _extract_ssh_auth_fields_from_message(message: Any) -> Dict[str, Optional[str]]:
    """
    Extract structured SSH authentication semantics from common sshd log lines.
    """
    s = _safe_str(message)
    out = {
        "ssh_actor_user_auth": None,
        "ssh_actor_user_session": None,
        "ssh_auth_method": None,
        "src_ip": None,
        "dst_ip": None,
        "auth_protocol": None,
        "auth_direction": None,
        "auth_outcome": None,
        "session_id": None,
        "logon_id": None,
    }
    if not s:
        return out

    # Plaso syslog material often preserves escaped control markers between the
    # username and the following clause (for example `Invalid user bob\r from
    # 192.0.2.1`). Collapse those escapes so the structured parser sees the same
    # auth semantics as the original sshd line.
    s = _SSH_ESCAPED_CONTROL_RE.sub(" ", s)

    m = _SSH_ACCEPT_RE.search(s)
    if m:
        out["ssh_auth_method"] = m.group(1).lower()
        out["ssh_actor_user_auth"] = m.group(2)
        out["src_ip"] = _normalise_ip_literal(m.group(3))
        out["auth_protocol"] = "ssh"
        out["auth_direction"] = "remote"
        out["auth_outcome"] = "success"
        return out

    m = _SSH_FAIL_RE.search(s)
    if m:
        out["ssh_auth_method"] = m.group(1).lower()
        out["ssh_actor_user_auth"] = m.group(2)
        out["src_ip"] = _normalise_ip_literal(m.group(3))
        out["auth_protocol"] = "ssh"
        out["auth_direction"] = "remote"
        out["auth_outcome"] = "failure"
        return out

    m = _SSH_INVALID_USER_RE.search(s)
    if m:
        out["ssh_actor_user_auth"] = m.group(1)
        out["src_ip"] = _normalise_ip_literal(m.group(2))
        out["auth_protocol"] = "ssh"
        out["auth_direction"] = "remote"
        out["auth_outcome"] = "failure"
        return out

    m = _SSH_SESSION_OPEN_RE.search(s)
    if m:
        out["ssh_actor_user_session"] = m.group(1)
        out["auth_protocol"] = "ssh"
        out["auth_direction"] = "remote"
        out["auth_outcome"] = "success"
        return out

    return out

def recover_ip_address_row(row: pd.Series) -> Optional[str]:
    """
    Row-level IP recovery.

    Returns a recovered IP literal if possible; otherwise None.
    Does NOT overwrite a valid existing ip_address.
    """
    existing = row.get("ip_address", None)
    if not _is_null(existing):
        ip_s = _normalise_ip_literal(existing)
        return ip_s or _safe_str(existing)

    parser = _safe_str(row.get("parser", ""))
    parser_l = parser.lower()

    # 1) Windows EVT/EVTX: parse xml_string then strings
    if parser_l.startswith(("winevt", "winevtx")):
        for field_name in ("rdp_client_address", "client_address", "source_network_address"):
            ip = _normalise_ip_literal(row.get(field_name, None))
            if ip:
                return ip
        ip = _extract_ip_from_evtx_xml(row.get("xml_string", None))
        if ip:
            return ip
        ip = _extract_ip_from_strings_field(row.get("strings", None))
        if ip:
            return ip

    # 2) URL field (preferred for destination infrastructure such as ftp://IP)
    url = _strip_user_prefix(_safe_str(row.get("url", "")))
    if url:
        ip = _extract_ip_literal_from_text(url)
        if ip:
            return ip

    # 3) HTTP fields if present
    for fld in ("http_request", "http_headers", "http_request_referer", "http_request_user_agent"):
        v = _strip_user_prefix(_safe_str(row.get(fld, "")))
        if v:
            ip = _extract_ip_literal_from_text(v)
            if ip:
                return ip

    # 4) Guarded message/text fallback
    for fld in ("message", "text"):
        v = _strip_user_prefix(_safe_str(row.get(fld, "")))
        if v and _NET_CONTEXT_RE.search(v):
            ip = _extract_ip_literal_from_text(v)
            if ip:
                return ip

    return None

# -----------------------------------------------------------------------------
# YARA normalisation (count only)
# -----------------------------------------------------------------------------
#
# Plaso exports `yara_match` variably across datasets:
#   - None / NA
#   - a list of rule names
#   - a single rule name (string)
#   - a stringified list (JSON or Python literal)
#
# ChronoSift normalises this to `yara_match_count` to stabilise scoring and to
# support later bounded/non-linear scaling (long-tail compression).  We only
# compute the count here; mapping into points remains a weighting decision in
# the scoring layer.
#


def build_geoip_enrichment_table(
    df: pd.DataFrame,
    city_db_path: str,
    asn_db_path: str,
    ip_field: str = "ip_address",
) -> pd.DataFrame:
    """
    Build an IP→Geo enrichment table and return it as a DataFrame.

    Design rationale
    ---------------
    ChronoSift operates on very large timelines. Per-row GeoIP lookups are
    prohibitively expensive and introduce needless exception overhead. Instead,
    we extract unique IP addresses, enrich each once, then merge the results back
    onto the full event frame. This approach is deterministic, auditable, and
    produces a standalone enrichment artefact that can be saved for replication.

    Returned columns (all nullable)
    -------------------------------
      - ip_address
      - geo_city_geoname_id
      - geo_city_name
      - geo_country_iso
      - geo_latitude
      - geo_longitude
      - geo_asn
    """
    if ip_field not in df.columns:
        return pd.DataFrame(
            columns=[
                ip_field,
                "geo_city_geoname_id",
                "geo_city_name",
                "geo_country_iso",
                "geo_latitude",
                "geo_longitude",
                "geo_asn",
            ]
        )

    # Unique, non-null IPs
    ips = df[ip_field].dropna().astype("string")
    if ips.empty:
        return pd.DataFrame(
            columns=[
                ip_field,
                "geo_city_geoname_id",
                "geo_city_name",
                "geo_country_iso",
                "geo_latitude",
                "geo_longitude",
                "geo_asn",
            ]
        )

    unique_ips = pd.unique(ips)

    rows = []
    reader_city = geoip2_database.Reader(city_db_path)
    try:
        reader_asn = geoip2_database.Reader(asn_db_path)
    except Exception:
        reader_city.close()
        raise
    try:
        for ip in unique_ips:
            ip_s = str(ip).strip()
            if not ip_s:
                continue
            # Ignore placeholder strings defensively
            if ip_s in {"-", "None", "null", "NULL"}:
                continue

            # Only enrich globally routable addresses; private/loopback/etc. remain None.
            try:
                ip_obj = ipaddress.ip_address(ip_s)
                if not ip_obj.is_global:
                    rows.append(
                        {
                            ip_field: ip_s,
                            "geo_city_geoname_id": None,
                            "geo_city_name": None,
                            "geo_country_iso": None,
                            "geo_latitude": None,
                            "geo_longitude": None,
                            "geo_asn": None,
                        }
                    )
                    continue
            except Exception:
                # Invalid IP string
                rows.append(
                    {
                        ip_field: ip_s,
                        "geo_city_geoname_id": None,
                        "geo_city_name": None,
                        "geo_country_iso": None,
                        "geo_latitude": None,
                        "geo_longitude": None,
                        "geo_asn": None,
                    }
                )
                continue

            out = {
                ip_field: ip_s,
                "geo_city_geoname_id": None,
                "geo_city_name": None,
                "geo_country_iso": None,
                "geo_latitude": None,
                "geo_longitude": None,
                "geo_asn": None,
            }

            # City DB
            try:
                resp = reader_city.city(ip_s)
                out["geo_city_geoname_id"] = resp.city.geoname_id
                out["geo_city_name"] = resp.city.name
                out["geo_country_iso"] = resp.country.iso_code
                out["geo_latitude"] = resp.location.latitude
                out["geo_longitude"] = resp.location.longitude
            except Exception:
                pass

            # ASN DB
            try:
                resp_asn = reader_asn.asn(ip_s)
                out["geo_asn"] = resp_asn.autonomous_system_number
            except Exception:
                pass

            rows.append(out)
    finally:
        reader_city.close()
        reader_asn.close()

    return pd.DataFrame.from_records(rows)


def normalise_yara_match_count(v: Any) -> int:
    if _is_null(v):
        return 0

    # pandas NA may leak through as float NaN; _is_null should catch most, but keep safe.
    try:
        if isinstance(v, float) and bool(pd.isna(v)):
            return 0
    except Exception:
        pass

    if isinstance(v, list):
        return len([x for x in v if not _is_null(x)])

    if isinstance(v, str):
        s = v.strip()
        if _is_null(s):
            return 0

        if s.startswith("[") and s.endswith("]"):
            # JSON list?
            try:
                j = json.loads(s)
                if isinstance(j, list):
                    return len(j)
            except Exception:
                pass

            # Python literal list?
            try:
                lit = ast.literal_eval(s)
                if isinstance(lit, list):
                    return len(lit)
            except Exception:
                pass

        # Fallback: treat any non-empty string as one hit.
        return 1

    # Any other type: treat as single hit.
    return 1


def normalise_yara_match_count_series(series: "pd.Series") -> "pd.Series":
    if len(series) == 0:
        return pd.Series(np.array([], dtype=np.int64), index=series.index, dtype="int64")
    counts = np.fromiter(
        (normalise_yara_match_count(v) for v in series.to_numpy(copy=False)),
        dtype=np.int64,
        count=len(series),
    )
    return pd.Series(counts, index=series.index, dtype="int64")


def extract_yara_rule_names(v: Any) -> List[str]:
    """Extract individual YARA rule name strings from a yara_match column value.

    Handles the same format variability as ``normalise_yara_match_count``
    (None, list, JSON-serialised list, Python literal list, bare string) but
    returns the actual rule names rather than just a count.
    """
    if _is_null(v):
        return []
    try:
        if isinstance(v, float) and bool(pd.isna(v)):
            return []
    except Exception:
        pass

    if isinstance(v, list):
        return [str(x).strip() for x in v if not _is_null(x) and str(x).strip()]

    if isinstance(v, str):
        s = v.strip()
        if _is_null(s):
            return []
        if s.startswith("[") and s.endswith("]"):
            try:
                j = json.loads(s)
                if isinstance(j, list):
                    return [str(x).strip() for x in j if not _is_null(x) and str(x).strip()]
            except Exception:
                pass
            try:
                lit = ast.literal_eval(s)
                if isinstance(lit, list):
                    return [str(x).strip() for x in lit if not _is_null(x) and str(x).strip()]
            except Exception:
                pass
        return [s] if s else []

    return [str(v).strip()] if str(v).strip() else []


# ─── YARA Forge Metadata Index ───────────────────────────────────────────────
#
# YARA Forge distributes curated rulesets as single concatenated .yar files
# with rich per-rule ``meta:`` blocks.  Plaso stores only the matched rule
# *name* — all metadata (score, quality, tags, detection type) is discarded.
#
# ``parse_yara_forge_metadata()`` parses a .yar file once and builds a
# lightweight index: ``rule_name → YaraRuleMeta``.  The engine uses this
# at YARA signal injection time to classify each matched rule into a
# forensic category and apply differential weighting.

YARA_CAT_OFFENSIVE_TOOL = "offensive_tool"
YARA_CAT_RANSOMWARE = "ransomware"
YARA_CAT_WEBSHELL = "webshell"
YARA_CAT_APT = "apt"
YARA_CAT_EXPLOIT = "exploit"
YARA_CAT_CERTIFICATE = "certificate"
YARA_CAT_MALWARE = "malware"

# Signals emitted per YARA category.  Keyed by category constant above.
YARA_CATEGORY_SIGNALS: Dict[str, str] = {
    YARA_CAT_OFFENSIVE_TOOL: "yara_offensive_tool",
    YARA_CAT_RANSOMWARE: "yara_ransomware",
    YARA_CAT_WEBSHELL: "yara_webshell",
    YARA_CAT_APT: "yara_apt",
    YARA_CAT_EXPLOIT: "yara_exploit",
    YARA_CAT_CERTIFICATE: "yara_certificate_blocklist",
    YARA_CAT_MALWARE: "yara_malware",
}


@dataclass
class YaraRuleMeta:
    """Lightweight metadata extracted from a YARA Forge rule's ``meta:`` block."""
    score: int = 75
    quality: int = 70
    category: str = YARA_CAT_MALWARE


# Compiled patterns for category inference from rule names.  Applied only when
# ``meta:`` fields do not provide an explicit classification.
_YARA_NAME_CATEGORY_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)Cert_Blocklist|INDICATOR_KB_CERT"), YARA_CAT_CERTIFICATE),
    (re.compile(r"(?i)Webshell|web_shell"), YARA_CAT_WEBSHELL),
    (re.compile(r"(?i)Cobaltstrike|cobalt_strike|Mimikatz|Rubeus|HKTL_|Hacktool|INDICATOR_TOOL|SafetyKatz|SharpKatz|LaZagne|Impacket"), YARA_CAT_OFFENSIVE_TOOL),
    (re.compile(r"(?i)Ransomware|Ransom_"), YARA_CAT_RANSOMWARE),
    (re.compile(r"(?i)(?:^|_)APT(?:_|\d)|(?:^|_)Apt_"), YARA_CAT_APT),
    (re.compile(r"(?i)Exploit|Shellcode|CVE_\d|CVE\d"), YARA_CAT_EXPLOIT),
    (re.compile(r"(?i)Rootkit|LOLDriver"), YARA_CAT_EXPLOIT),
]


def _classify_yara_rule(
    rule_name: str,
    inline_tags: str = "",
    meta_category: str = "",
    meta_tc_detection_type: str = "",
    meta_tags: str = "",
) -> str:
    """Classify a YARA rule into a forensic category.

    Classification hierarchy (first match wins):
    1. ``tc_detection_type`` metadata (ReversingLabs — explicit, high quality)
    2. Inline tags from rule declaration line
    3. ``category`` metadata field
    4. ``tags`` metadata string
    5. Rule name pattern matching
    6. Default → ``malware``
    """
    # 1. tc_detection_type (explicit, most reliable)
    tc = meta_tc_detection_type.strip().lower()
    if tc:
        if tc == "ransomware":
            return YARA_CAT_RANSOMWARE
        if tc in ("backdoor", "trojan", "rat"):
            return YARA_CAT_MALWARE
        if tc in ("infostealer",):
            return YARA_CAT_MALWARE
        if tc in ("exploit",):
            return YARA_CAT_EXPLOIT
        if tc in ("rootkit",):
            return YARA_CAT_EXPLOIT
        if tc in ("pua",):
            return YARA_CAT_MALWARE

    # 2. Inline tags (from "rule NAME : TAG1 TAG2")
    tags_combined = f"{inline_tags} {meta_tags}".upper()
    if "RANSOMWARE" in tags_combined:
        return YARA_CAT_RANSOMWARE
    if "INFO" in tags_combined and "MALICIOUS" not in tags_combined and "MALWARE" not in tags_combined:
        # INFO-only tag (e.g., "INFO, FILE") — typically certificate blocklists
        if "CERT" in rule_name.upper() or "BLOCKLIST" in rule_name.upper():
            return YARA_CAT_CERTIFICATE

    # 3. category metadata field
    cat = meta_category.strip().lower()
    if cat == "info":
        if "CERT" in rule_name.upper() or "BLOCKLIST" in rule_name.upper():
            return YARA_CAT_CERTIFICATE

    # 4. Rule name pattern matching (catches most rules)
    for pattern, category in _YARA_NAME_CATEGORY_PATTERNS:
        if pattern.search(rule_name):
            return category

    return YARA_CAT_MALWARE


_YARA_META_RE = re.compile(r'^\s+(\w+)\s*=\s*(.+)$')


def parse_yara_forge_metadata(yar_path: str) -> Dict[str, YaraRuleMeta]:
    """Parse a YARA Forge ``.yar`` file and return ``rule_name → YaraRuleMeta``.

    Performs a single sequential scan of the file.  For the 17 MB extended
    ruleset (~10K rules) this typically completes in <2 seconds.

    Parameters
    ----------
    yar_path : str
        Path to the YARA Forge concatenated ``.yar`` file.

    Returns
    -------
    dict
        Mapping from YARA rule name (str) to ``YaraRuleMeta``.
    """
    index: Dict[str, YaraRuleMeta] = {}
    current_name: Optional[str] = None
    inline_tags: str = ""
    in_meta = False
    meta_fields: Dict[str, str] = {}

    def _finalise():
        nonlocal current_name, in_meta, meta_fields, inline_tags
        if current_name:
            score = 75
            quality = 70
            try:
                score = int(meta_fields.get("score", "75"))
            except (ValueError, TypeError):
                pass
            try:
                quality = int(meta_fields.get("quality", "70"))
            except (ValueError, TypeError):
                pass
            category = _classify_yara_rule(
                current_name,
                inline_tags=inline_tags,
                meta_category=meta_fields.get("category", ""),
                meta_tc_detection_type=meta_fields.get("tc_detection_type", ""),
                meta_tags=meta_fields.get("tags", ""),
            )
            index[current_name] = YaraRuleMeta(score=score, quality=quality, category=category)
        current_name = None
        inline_tags = ""
        in_meta = False
        meta_fields = {}

    with open(yar_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stripped = line.strip()

            if stripped.startswith("rule "):
                _finalise()
                # Parse: "rule NAME" or "rule NAME : TAG1 TAG2"
                rest = stripped[5:].strip()
                if rest.endswith("{"):
                    rest = rest[:-1].strip()
                if ":" in rest:
                    parts = rest.split(":", 1)
                    current_name = parts[0].strip()
                    inline_tags = parts[1].strip()
                else:
                    current_name = rest.strip()
                    inline_tags = ""
                in_meta = False
                meta_fields = {}
                continue

            if not current_name:
                continue

            if stripped == "meta:":
                in_meta = True
                continue

            if stripped in ("strings:", "condition:"):
                in_meta = False
                continue

            if in_meta:
                m = _YARA_META_RE.match(line)
                if m:
                    key = m.group(1).strip().lower()
                    val = m.group(2).strip()
                    # Strip surrounding quotes from string values
                    if val.startswith('"') and val.endswith('"'):
                        val = val[1:-1]
                    meta_fields[key] = val

        _finalise()

    logger.info("YARA Forge metadata: parsed %d rules from %s", len(index), yar_path)
    return index


# ─── ClamAV Signature Classification ─────────────────────────────────────────
#
# ClamAV signatures follow the naming convention:
#     {Platform}.{Category}.{FamilyName}-{SignatureID}-{Revision}
#
# The ``Category`` field is the primary classifier.  Some older or community
# signatures may deviate from this scheme, so the parser is lenient.

AV_CAT_OFFENSIVE_TOOL = "offensive_tool"
AV_CAT_RANSOMWARE = "ransomware"
AV_CAT_EXPLOIT = "exploit"
AV_CAT_MALWARE = "malware"
AV_CAT_PUA = "pua"
AV_CAT_WEBSHELL = "webshell"

# Signals emitted per AV category.
AV_CATEGORY_SIGNALS: Dict[str, str] = {
    AV_CAT_OFFENSIVE_TOOL: "av_offensive_tool",
    AV_CAT_RANSOMWARE: "av_ransomware",
    AV_CAT_EXPLOIT: "av_exploit",
    AV_CAT_MALWARE: "av_malware",
    AV_CAT_PUA: "av_pua",
    AV_CAT_WEBSHELL: "av_webshell",
}

# ClamAV category tokens → forensic category mapping.
_CLAMAV_CATEGORY_MAP: Dict[str, str] = {
    "ransomware": AV_CAT_RANSOMWARE,
    "trojan": AV_CAT_MALWARE,
    "backdoor": AV_CAT_MALWARE,
    "virus": AV_CAT_MALWARE,
    "worm": AV_CAT_MALWARE,
    "malware": AV_CAT_MALWARE,
    "dropper": AV_CAT_MALWARE,
    "downloader": AV_CAT_MALWARE,
    "loader": AV_CAT_MALWARE,
    "infostealer": AV_CAT_MALWARE,
    "spyware": AV_CAT_MALWARE,
    "keylogger": AV_CAT_MALWARE,
    "ircbot": AV_CAT_MALWARE,
    "proxy": AV_CAT_MALWARE,
    "rootkit": AV_CAT_EXPLOIT,
    "exploit": AV_CAT_EXPLOIT,
    "tool": AV_CAT_OFFENSIVE_TOOL,
    "hacktool": AV_CAT_OFFENSIVE_TOOL,
    "pua": AV_CAT_PUA,
    "adware": AV_CAT_PUA,
    "coinminer": AV_CAT_PUA,
    "joke": AV_CAT_PUA,
    "phishing": AV_CAT_MALWARE,
    "packed": AV_CAT_MALWARE,
    "packer": AV_CAT_MALWARE,
    "file": AV_CAT_MALWARE,
    "countermeasure": AV_CAT_OFFENSIVE_TOOL,
}

# Family names that override category-based classification.
_CLAMAV_FAMILY_OVERRIDES: Dict[str, str] = {
    "mimikatz": AV_CAT_OFFENSIVE_TOOL,
    "pwdump": AV_CAT_OFFENSIVE_TOOL,
    "lazagne": AV_CAT_OFFENSIVE_TOOL,
    "rubeus": AV_CAT_OFFENSIVE_TOOL,
    "impacket": AV_CAT_OFFENSIVE_TOOL,
    "cobaltstrike": AV_CAT_OFFENSIVE_TOOL,
    "metasploit": AV_CAT_OFFENSIVE_TOOL,
    "meterpreter": AV_CAT_OFFENSIVE_TOOL,
    "sharphound": AV_CAT_OFFENSIVE_TOOL,
    "bloodhound": AV_CAT_OFFENSIVE_TOOL,
    "c99shell": AV_CAT_WEBSHELL,
    "c99": AV_CAT_WEBSHELL,
    "r57shell": AV_CAT_WEBSHELL,
    "b374k": AV_CAT_WEBSHELL,
    "weevely": AV_CAT_WEBSHELL,
    "wso": AV_CAT_WEBSHELL,
    "petya": AV_CAT_RANSOMWARE,
    "wannacry": AV_CAT_RANSOMWARE,
    "lockbit": AV_CAT_RANSOMWARE,
    "conti": AV_CAT_RANSOMWARE,
    "revil": AV_CAT_RANSOMWARE,
    "ryuk": AV_CAT_RANSOMWARE,
    "maze": AV_CAT_RANSOMWARE,
    "blackcat": AV_CAT_RANSOMWARE,
    "alphv": AV_CAT_RANSOMWARE,
    "babuk": AV_CAT_RANSOMWARE,
    "akira": AV_CAT_RANSOMWARE,
    "razy": AV_CAT_RANSOMWARE,
}


@dataclass
class ClamAVSignatureMeta:
    """Parsed ClamAV signature components."""
    platform: str = ""
    category_token: str = ""
    family: str = ""
    forensic_category: str = AV_CAT_MALWARE


def parse_clamav_signature(signature: Any) -> ClamAVSignatureMeta:
    """Parse a ClamAV signature string into structured components.

    Handles the standard naming convention ``Platform.Category.Family-ID-Rev``
    as well as common deviations (PUA.Platform.Family, Heuristics.*, etc.).
    """
    s = _safe_str(signature).strip()
    if not s:
        return ClamAVSignatureMeta()

    # Split on '.' to get parts
    parts = s.split(".")
    platform = ""
    category_token = ""
    family = ""

    if len(parts) >= 3:
        # Standard: Platform.Category.Family-ID-Rev
        platform = parts[0]
        category_token = parts[1]
        # Family is everything after the second dot, before the first '-'
        remainder = ".".join(parts[2:])
        family = remainder.split("-")[0] if "-" in remainder else remainder
    elif len(parts) == 2:
        # Two parts: could be Category.Family or Platform.Family — ambiguous,
        # so treat parts[0] as the category and leave platform indeterminate.
        platform = ""
        category_token = parts[0]
        family = parts[1].split("-")[0] if "-" in parts[1] else parts[1]
    elif len(parts) == 1:
        family = s.split("-")[0] if "-" in s else s

    # Handle PUA prefix: PUA.Platform.Family → category=PUA, platform from part[1]
    if platform.upper() == "PUA":
        category_token = "PUA"
        if len(parts) >= 3:
            platform = parts[1]
            family = ".".join(parts[2:]).split("-")[0]

    # Classify into forensic category
    family_lower = family.lower()
    cat_lower = category_token.lower()

    # 1. Family name overrides (highest priority — catches Mimikatz as Tool, webshells, etc.)
    for fam_key, fam_cat in _CLAMAV_FAMILY_OVERRIDES.items():
        if fam_key in family_lower:
            return ClamAVSignatureMeta(
                platform=platform, category_token=category_token,
                family=family, forensic_category=fam_cat,
            )

    # 2. Category token mapping
    forensic_cat = _CLAMAV_CATEGORY_MAP.get(cat_lower, AV_CAT_MALWARE)

    return ClamAVSignatureMeta(
        platform=platform, category_token=category_token,
        family=family, forensic_category=forensic_cat,
    )


def normalise_coalesce(row: Any, fields: List[str]) -> Optional[Any]:
    """
    Return first meaningful (non-null, non-placeholder) value from a list of fields.

    IMPORTANT:
    - This must respect placeholder-as-null policy. Do not treat "-" as a value.
    """
    for f in fields:
        v = getattr(row, f, None)
        if _is_null(v):
            continue
        if isinstance(v, str):
            sv = _safe_str(v).strip()  # placeholder -> ""
            if sv:
                return sv
            continue
        return v
    return None


def _normalise_coalesce_candidate_series(values: pd.Series) -> pd.Series:
    if str(values.dtype) == "string":
        norm = values.astype("string")
        norm = norm.str.strip()
        placeholder_mask = norm.str.lower().isin(PLACEHOLDER_STRINGS)
        norm = norm.mask(norm.eq("") | placeholder_mask)
        return norm.astype(object)

    if pd.api.types.is_object_dtype(values.dtype):
        inferred = pd.api.types.infer_dtype(values, skipna=True)
        if inferred in {"string", "unicode", "mixed", "mixed-string"}:
            try:
                norm = values.astype("string")
                norm = norm.str.strip()
                placeholder_mask = norm.str.lower().isin(PLACEHOLDER_STRINGS)
                norm = norm.mask(norm.eq("") | placeholder_mask)
                return norm.astype(object)
            except Exception:
                pass
        norm_vals = np.fromiter(
            (normalise_coalesce_value(v) for v in values.to_numpy(copy=False)),
            dtype=object,
            count=len(values),
        )
        return pd.Series(norm_vals, index=values.index, dtype=object)

    obj = values.astype(object, copy=False)
    na_mask = pd.isna(values)
    if bool(na_mask.any()):
        obj = obj.where(~na_mask, None)
    return obj


def normalise_coalesce_value(v: Any) -> Optional[Any]:
    if _is_null(v):
        return None
    if isinstance(v, str):
        sv = v.strip()
        if not sv or sv.lower() in PLACEHOLDER_STRINGS:
            return None
        return sv
    return v


def _truncate_evidence_text(s: str, limit: int = 240) -> str:
    if len(s) <= limit:
        return s
    return s[:limit] + "..."


def _coalesce_first_meaningful(df: pd.DataFrame, fields: List[str]) -> pd.Series:
    if not fields:
        return pd.Series(pd.NA, index=df.index, dtype=object)

    candidates = [_normalise_coalesce_candidate_series(df[f]) for f in fields]
    if len(candidates) == 1:
        return pd.Series(candidates[0].to_numpy(copy=False), index=df.index, dtype=object)

    result = candidates[0].to_numpy(dtype=object, copy=True)
    missing = pd.isna(result)

    for cand in candidates[1:]:
        if not bool(missing.any()):
            break
        cand_vals = cand.to_numpy(dtype=object, copy=False)
        take = missing & ~pd.isna(cand_vals)
        if bool(take.any()):
            result[take] = cand_vals[take]
            missing[take] = False

    result_series = pd.Series(result, index=df.index, dtype=object)
    result_series = result_series.where(pd.notna(result_series), None)
    return result_series


def _coalesce_first_meaningful_for_mask(
    df: pd.DataFrame,
    fields: List[str],
    mask: pd.Series,
) -> pd.Series:
    """Coalesce fields only for masked rows without materialising a masked frame."""
    if not fields:
        return pd.Series(pd.NA, index=df.index[mask], dtype=object)
    mask_array = mask.to_numpy(dtype=bool, copy=False) if hasattr(mask, "to_numpy") else np.asarray(mask, dtype=bool)
    out_index = df.index[mask_array]
    if out_index.empty:
        return pd.Series([], index=out_index, dtype=object)

    candidates = []
    for field in fields:
        if field not in df.columns:
            continue
        norm = _normalise_coalesce_candidate_series(df[field])
        candidates.append(norm.iloc[mask_array])
    if not candidates:
        return pd.Series(pd.NA, index=out_index, dtype=object)
    if len(candidates) == 1:
        return pd.Series(candidates[0].to_numpy(copy=False), index=out_index, dtype=object)

    result = candidates[0].to_numpy(dtype=object, copy=True)
    missing = pd.isna(result)
    for cand in candidates[1:]:
        if not bool(missing.any()):
            break
        cand_vals = cand.to_numpy(dtype=object, copy=False)
        take = missing & ~pd.isna(cand_vals)
        if bool(take.any()):
            result[take] = cand_vals[take]
            missing[take] = False

    result_series = pd.Series(result, index=out_index, dtype=object)
    result_series = result_series.where(pd.notna(result_series), None)
    return result_series


def _ensure_object_columns(df: pd.DataFrame, columns: Iterable[str]) -> pd.DataFrame:
    """
    Add missing placeholder columns in one batch to avoid DataFrame fragmentation.
    """
    missing: List[str] = []
    seen: Set[str] = set()
    for col in columns:
        if not col or col in seen or col in df.columns:
            continue
        seen.add(col)
        missing.append(col)
    if not missing:
        return df

    additions = pd.DataFrame(index=df.index, columns=missing, dtype=object)
    out = pd.concat([df, additions], axis=1, copy=False)
    if df.attrs:
        out.attrs = dict(df.attrs)
    return out


# -----------------------------------------------------------------------------
# Impossible travel (configurable actor continuity)
# -----------------------------------------------------------------------------
# Implemented as a post-processing step over per-event signals, using GeoLite2
# latitude/longitude (when available) and *successful* authentication events.
#
# Design note:
# - ChronoSift’s primary actor aggregation may remain `user + ip_address` for
#   other behaviours. However, “impossible travel” inherently requires *user
#   continuity across changing IP addresses*. We therefore compute it on a
#   separate continuity key (default: username; configurable via key_by).
#
# - The signal is emitted as IMPOSSIBLE_TRAVEL=1 with distance/time/velocity
#   attached to the explain payload. A weight can be supplied in weights.yaml
#   (e.g., IMPOSSIBLE_TRAVEL: 10) to contribute to the capped event score.
#
# - We deliberately restrict evaluation to events that already indicate an
#   authentication success (as derived by the rule DSL), to avoid treating web
#   request volume or background services as “travel”.
# -----------------------------------------------------------------------------

def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres between two WGS84 points."""
    # Earth mean radius (km)
    r = 6371.0088
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2.0) ** 2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return r * c

def _signals_indicate_auth_success(
    signals: dict,
    success_keys: list[str] | None = None,
) -> bool:
    """Return True if per-event signals indicate authentication success.

    Behaviour:
      - If success_keys is provided and non-empty, matching is case-insensitive.
      - If success_keys is empty/None, fall back to a conservative heuristic
        (any signal name containing 'success' and not containing 'fail'/'error').
    """
    if not isinstance(signals, dict) or not signals:
        return False

    if success_keys:
        key_map = {str(k).strip().lower(): v for k, v in signals.items()}
        for wanted in success_keys:
            v = key_map.get(str(wanted).strip().lower(), None)
            if isinstance(v, (int, float)):
                if float(v) > 0:
                    return True
            elif not _is_null(v) and bool(v):
                return True
        return False

    for k, v in signals.items():
        if _is_null(v) or not v:
            continue
        name = str(k).lower()
        if "success" in name and "fail" not in name and "error" not in name:
            return True
    return False

    # if success_keys:
    #     for k in success_keys:
    #         if k in signals and isinstance(signals[k], (int, float)) and float(signals[k]) > 0:
    #             return True
    #     return False

    # # Heuristic fallback (kept conservative).
    # for k, v in signals.items():
    #     if not isinstance(v, (int, float)) or float(v) <= 0:
    #         continue
    #     kk = str(k).upper()
    #     if "SUCCESS" in kk and any(tok in kk for tok in ("AUTH", "LOGIN", "RDP", "SSH")):
    #         return True
    # return False
# =============================================================================
# Condition operators (missing-safe by default)
# =============================================================================
#
# ChronoSift authoring choice (Option A):
# - Keep `exists` available for clarity but do not require it everywhere.
# - Other operators already return False on None/empty, so `exists` is often redundant.
#
# Future enhancement (Option B, parked):
# - Add engine.auto_exists_guard to auto-inject existence guards for regex/contains/comparisons,
#   reducing YAML clutter without losing semantics.
#

def op_exists(field_val: Any, expected: Any = None) -> bool:
    return not _is_null(field_val) and _safe_str(field_val) != ""


def op_eq(field_val: Any, expected: Any) -> bool:
    if _is_null(field_val):
        return False
    return field_val == expected


def op_in(field_val: Any, expected_list: List[Any]) -> bool:
    if _is_null(field_val):
        return False
    return field_val in expected_list


def op_in_ci(field_val: Any, expected_list: List[str]) -> bool:
    s = _safe_str(field_val).strip()
    if not s:
        return False
    s_l = s.lower()
    return any(s_l == _safe_str(v).strip().lower() for v in expected_list)


def op_contains(field_val: Any, needle: str) -> bool:
    s = _safe_str(field_val)
    if not s:
        return False
    return needle in s


def op_contains_ci(field_val: Any, needle: str) -> bool:
    s = _safe_str(field_val)
    if not s:
        return False
    return needle.lower() in s.lower()


def op_regex(field_val: Any, pattern: str, flags: int = 0) -> bool:
    s = _safe_str(field_val)
    if not s:
        return False
    return re.search(pattern, s, flags=flags) is not None


def op_lt(field_val: Any, expected: Number) -> bool:
    n = _safe_num(field_val)
    return n is not None and n < float(expected)


def op_lte(field_val: Any, expected: Number) -> bool:
    n = _safe_num(field_val)
    return n is not None and n <= float(expected)


def op_gt(field_val: Any, expected: Number) -> bool:
    n = _safe_num(field_val)
    return n is not None and n > float(expected)


def op_gte(field_val: Any, expected: Number) -> bool:
    n = _safe_num(field_val)
    return n is not None and n >= float(expected)


OP_MAP = {
    "exists": op_exists,
    "eq": op_eq,
    "in": op_in,
    "in_ci": op_in_ci,
    "contains": op_contains,
    "contains_ci": op_contains_ci,
    "regex": op_regex,
    "lt": op_lt,
    "lte": op_lte,
    "gt": op_gt,
    "gte": op_gte,
}


# =============================================================================
# Temporal lookback parsing
# =============================================================================

_DURATION_RX = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.IGNORECASE)


def parse_lookback(s: str) -> timedelta:
    """
    Supported: Ns, Nm, Nh, Nd, Nw (seconds, minutes, hours, days, weeks)
    Examples: "15m", "2h", "30d", "1w"
    """
    m = _DURATION_RX.match(str(s))
    if not m:
        raise ValueError(f"Invalid lookback duration: {s!r} (expected e.g. '2h', '30d')")
    n = int(m.group(1))
    unit = m.group(2).lower()
    if unit == "s":
        return timedelta(seconds=n)
    if unit == "m":
        return timedelta(minutes=n)
    if unit == "h":
        return timedelta(hours=n)
    if unit == "d":
        return timedelta(days=n)
    if unit == "w":
        return timedelta(weeks=n)
    raise ValueError(f"Unsupported duration unit: {unit!r}")


# =============================================================================
# Data models (parsed YAML)
# =============================================================================

# -----------------------------------------------------------------------------
# Temporal Activity Profiling (Hour-of-Week) → hour_rarity, quiet_time_event
# -----------------------------------------------------------------------------
# Objective:
#   Replace hard-coded "out of hours" heuristics with a dataset-derived baseline.
#   This supports both SME servers (quiet overnight) and 24x7 ecommerce systems
#   (diurnal but continuous activity) by learning each system’s quiet periods.
#
# Design:
#   - Build a baseline distribution over hour-of-week (0..167) using *host-resident*
#     events, excluding externally-driven request telemetry such as apache access logs.
#   - Apply Dirichlet/Laplace smoothing to avoid zero-probability bins.
#   - Compute surprisal: S(h) = -log(p(h)), then normalise to [0, 1].
#   - Emit per-event signals:
#        hour_rarity: continuous 0..1
#        quiet_time_event: 1 if hour in quiet quantile (default bottom decile)
#
# Interaction with other danger signals:
#   hour_rarity is a context signal; it becomes more meaningful when paired with
#   events likely to represent attacker action. ChronoSift supports static
#   multipliers when high-impact signals are present in the same event.
# -----------------------------------------------------------------------------

def _select_profile_events(df: pd.DataFrame) -> pd.DataFrame:
    """Select events used to build the baseline activity profile.

    Profiling objective:
      Build a dataset-derived hour-of-week baseline from file-system activity.

    Exclusions:
      - NSRL Operating System artefacts
    
    """
      
    subset = df

    if "parser" in subset.columns:
        p = subset["parser"].astype("string").fillna("")
        fs_mask = p.str.contains(
            r"(?:mft|usnjrnl|filestat)",
            case=False,
            regex=True,
            na=False,
        )
        candidate = subset[fs_mask]
        if len(candidate):
            subset = candidate

    # -----------------------------------------------------------------
    # NSRL exclusion: remove operating system artefacts from the baseline
    # -----------------------------------------------------------------

    if "nsrl_is_os_component" in subset.columns:
        subset = subset[
            ~subset["nsrl_is_os_component"].astype("boolean").fillna(False).astype(bool)
        ]
    elif "nsrl_application_type" in subset.columns:
        subset = subset[
            ~subset["nsrl_application_type"].astype("string").fillna("").str.contains(
                "Operating System",
                case=False,
                regex=False,
                na=False,
            )
        ]

    return subset

def _ensure_datetime_series(df: pd.DataFrame) -> pd.Series:
    """Return a timezone-aware datetime series for event timestamps."""
    if isinstance(df.index, pd.DatetimeIndex):
        return df.index.to_series(index=df.index)
    for col in ("date_time", "datetime", "timestamp", "date_time_iso"):
        if col in df.columns:
            return pd.to_datetime(df[col], errors="coerce", utc=True)
    raise ValueError("No datetime index or recognised datetime column found for profiling.")

def _hour_of_week(dt: pd.Series) -> pd.Series:
    """Map timestamps to hour-of-week 0..167."""
    d = dt.dt.dayofweek.astype("Int64")
    h = dt.dt.hour.astype("Int64")
    return (d * 24 + h).astype("Int64")

def _compute_hour_of_week_profile(
    df: pd.DataFrame,
    alpha: float = 1.0,
    quiet_quantile: float = 0.10,
) -> tuple[dict[int, float], set[int]]:
    """Compute normalised surprisal profile (0..1) and quiet-hour set."""
    dt = _ensure_datetime_series(df)
    how = _hour_of_week(dt)
    counts = how.value_counts(dropna=True).reindex(range(168), fill_value=0).astype(float)

    total = float(counts.sum())
    denom = total + 168.0 * float(alpha)
    p = (counts + float(alpha)) / denom

    surprisal = pd.Series(-np.log(p.to_numpy()), index=p.index)
    s_min = float(surprisal.min())
    s_max = float(surprisal.max())
    if s_max > s_min:
        s_norm = (surprisal - s_min) / (s_max - s_min)
    else:
        s_norm = surprisal * 0.0

    threshold = float(p.quantile(float(quiet_quantile)))
    quiet_hours = set(int(i) for i, pv in p.items() if float(pv) <= threshold)

    profile = {int(i): float(v) for i, v in s_norm.items()}
    return profile, quiet_hours

# -----------------------------------------------------------------------------
# Configuration hygiene: signal ↔ weight alignment
# -----------------------------------------------------------------------------
# Research intent:
#   Silent misconfiguration (e.g., a rule emits a signal with no weight) can invalidate
#   evaluation results. ChronoSift therefore offers an optional validation step that:
#     - warns (or raises) if emitted signals have no corresponding weight entry
#     - optionally warns on unused weights (helpful for pruning configuration drift)
#
# The validator uses rules.yaml's rule 'emit.signals[].name' fields plus a small set
# of engine-injected context signals. As of v2.30 this also enforces the
# source-versus-canonical taxonomy split for auth, execution, persistence, and
# transfer so rule/weight drift is visible during config load instead of only at
# runtime.
# -----------------------------------------------------------------------------

def _collect_emitted_signals_from_rules(rules_cfg: dict) -> set[str]:
    emitted: set[str] = set()

    # Atomic/event rules
    for rule in (rules_cfg or {}).get("rules", []) or []:
        emit = (rule or {}).get("emit", {}) or {}
        for s in emit.get("signals", []) or []:
            name = (s or {}).get("name")
            if name:
                emitted.add(str(name).strip().lower())

    # Temporal rules
    for tr in (rules_cfg or {}).get("temporal_rules", []) or []:
        emit = (tr or {}).get("emit", {}) or {}
        for s in emit.get("signals", []) or []:
            name = (s or {}).get("name")
            if name:
                emitted.add(str(name).strip().lower())

    # Engine-injected signals (not emitted by YAML atomic/temporal rules):
    emitted.update({
        "auth_success",
        "auth_failure",
        "auth_remote_success",
        "auth_remote_failure",
        "auth_local_success",
        "auth_local_failure",
        "auth_remote_interactive_success",
        "auth_remote_shell_success",
        "auth_invalid_user",
        "execution_lolbin",
        "execution_interpreter",
        "execution_scheduled",
        "execution_privileged_scheduled",
        "execution_lolbin_suspicious_args",
        "exec_from_tmp",
        "exec_from_user_writable",
        "exec_suspicious_path",
        "exec_system_binary_in_user_path",
        "exec_compiler_activity",
        "exec_shell_spawn",
        "exec_network_tool",
        "exec_archive_tool",
        "exec_privileged_context",
        "exec_new_suid_binary",
        "exec_privilege_escalation_sequence",
        "exec_staging_sequence",
        "persistence_mechanism",
        "persistence_scheduled",
        "persistence_registry",
        "persistence_service_install",
        "identity_persistence_change",
        "staging_archive",
        "transfer_execution",
        "transfer_large_http",
        "transfer_exfiltration_pattern",
        "transfer_cross_border",
        "transfer_sensitive_staging",
        "suspicious_execution",
        "file_created",
        "file_modified",
        "file_deleted",
        "short_lived_file",
        "web_executable_file_created",
        "mass_file_modification",
        "ransomware_extension_burst",
        "sensitive_file_access",
        "archive_created",
        "database_dump_candidate",
        "defacement_candidate",
        "archive_after_sensitive_access",
        "account_created",
        "privileged_account_created",
        "cron_persistence",
        "repeated_scheduled_exec",
        "firewall_modified",
        "defender_disabled",
        "group_policy_modified",
        "service_configuration_changed",
        "hour_rarity",
        "quiet_time_event",
        "impossible_travel",
        "av_hit",
        "luhn_hit",
        "yara_hit_strength",
        "referenced_file_yara_hit",
        "referenced_file_av_hit",
        "referenced_file_luhn_hit",
        "web_file_access",
        "web_malicious_file_access",
        "web_sensitive_file_download",
        "web_malicious_file_upload",
        "web_confirmed_webshell_access",
        "web_external_sensitive_transfer",
        "web_sqli_attempt",
        "web_sqli_response_anomaly",
        "web_sqli_probable_success",
        "web_injection_probe",
        "mitre_t1190",
        "mitre_t1505_003",
        "mitre_t1105",
        "mitre_t1213_006",
        "user_changed_private_ip",
        "user_crossed_private_subnet",
        "user_private_to_public_ip",
        "user_public_to_private_ip",
        "auth_newcredentials_logon",
        "auth_service_logon",
        "auth_ntlm_remote",
        "lateral_movement_indicator",
        "prefetch_execution",
        "amcache_execution",
        "shimcache_execution",
        "usb_device_connected",
        "browser_download",
        "systemd_service_persistence",
        "authorized_keys_persistence",
        "authorized_keys_root_persistence",
        "webshell_artifact",
        "webshell_activity",
        "masquerading",
        "inhibit_system_recovery",
        "ingress_tool_transfer",
        "user_execution_after_download",
        "smb_admin_share",
        "indicator_removal_on_host",
        "ransomware_impact",
        "exploit_public_facing_app",
        "external_remote_service",
        "credential_dumping",
        "password_store_access",
        "file_and_directory_discovery",
        "remote_system_discovery",
        "system_owner_user_discovery",
        "automated_collection",
        "application_layer_protocol",
        "automated_exfiltration",
        "account_access_removal",
        "alternate_auth_material",
        "credential_dump_collection",
        "password_store_exfil_chain",
        "web_upload_execution_chain",
        "winlogon_helper_persistence",
        "com_hijack_persistence",
        "service_stop",
        "timestomping",
        # YARA Forge category-aware signals (emitted by _inject_yara_signal_sparse)
        "yara_offensive_tool",
        "yara_ransomware",
        "yara_webshell",
        "yara_apt",
        "yara_exploit",
        "yara_malware",
        "yara_certificate_blocklist",
        # ClamAV category-aware signals (emitted by _inject_av_signal_sparse)
        "av_offensive_tool",
        "av_ransomware",
        "av_exploit",
        "av_malware",
        "av_pua",
        "av_webshell",
        # Geo continuity signals (emitted by _apply_geo_continuity_sparse)
        "new_city",
        "new_country",
        "new_asn",
        "boundary_crossing",
    })
    return emitted


def _collect_temporal_input_signals(rules_cfg: dict) -> set[str]:
    needed: set[str] = set()
    for tr in (rules_cfg or {}).get("temporal_rules", []) or []:
        for step in ((tr or {}).get("sequence", []) or []):
            sig = (step or {}).get("signal")
            if sig:
                needed.add(str(sig).strip().lower())
        co = ((tr or {}).get("cooccur", {}) or {}).get("all", []) or []
        for step in co:
            sig = (step or {}).get("signal")
            if sig:
                needed.add(str(sig).strip().lower())
    return needed

def _validate_signal_weight_alignment(
    rules_cfg: dict,
    weights_cfg: dict,
    strict: bool = False,
) -> None:
    weights_map = (weights_cfg or {}).get("weights", {}) or {}
    weight_keys = {str(k).strip().lower() for k in weights_map.keys()}
    emitted = _collect_emitted_signals_from_rules(rules_cfg)
    temporal_inputs = _collect_temporal_input_signals(rules_cfg)

    missing_weights = sorted([s for s in emitted if s not in weight_keys])
    unused_weights = sorted([w for w in weight_keys if w not in emitted])
    temporal_missing = sorted([s for s in temporal_inputs if s not in emitted])

    legacy_auth_weight_keys = sorted([
        w for w in weight_keys
        if w in {
            "auth_fail",
            "remote_auth_success",
            "remote_auth_failure",
            "local_auth_success",
            "local_auth_failure",
            "auth_success_canonical",
            "auth_fail_canonical",
        }
    ])

    canonical_cfg = ((rules_cfg or {}).get("engine_config", {}) or {}).get("canonical_auth_signals", {}) or {}
    canonical_targets = {
        str(canonical_cfg.get("success_target", "auth_success")).strip().lower(),
        str(canonical_cfg.get("fail_target", "auth_failure")).strip().lower(),
        "auth_remote_success",
        "auth_remote_failure",
        "auth_local_success",
        "auth_local_failure",
        "auth_success",
        "auth_failure",
    }
    canonical_never_produced = sorted([s for s in canonical_targets if s and s not in emitted])

    legacy_execution_inputs = {
        "lolbin_windows",
        "lolbin_linux",
        "lolbin_suspicious_args",
        "scheduled_exec",
        "interpreter_exec_linux",
        "privileged_scheduled_exec",
    }
    legacy_execution_temporal = sorted([s for s in temporal_inputs if s in legacy_execution_inputs])
    canonical_execution_sources = {
        "execution_lolbin": {"lolbin_windows", "lolbin_linux"},
        "execution_interpreter": {"interpreter_exec_linux"},
        "execution_scheduled": {"scheduled_exec"},
        "execution_privileged_scheduled": {"privileged_scheduled_exec"},
        "execution_lolbin_suspicious_args": {"lolbin_suspicious_args"},
    }
    canonical_execution_context_targets = {
        "exec_from_tmp",
        "exec_from_user_writable",
        "exec_suspicious_path",
        "exec_system_binary_in_user_path",
        "exec_compiler_activity",
        "exec_shell_spawn",
        "exec_network_tool",
        "exec_archive_tool",
        "exec_privileged_context",
        "exec_new_suid_binary",
        "exec_privilege_escalation_sequence",
        "exec_staging_sequence",
    }
    canonical_execution_targets = set(canonical_execution_sources.keys())
    canonical_execution_never_produced = sorted([
        target
        for target, sources in canonical_execution_sources.items()
        if not any(source in emitted for source in sources)
    ])

    source_execution_weight_keys = {
        "lolbin_windows",
        "lolbin_linux",
        "lolbin_suspicious_args",
        "scheduled_exec",
        "interpreter_exec_linux",
        "privileged_scheduled_exec",
    }
    canonical_execution_weight_keys = canonical_execution_targets
    source_exec_scored = sorted([w for w in weight_keys if w in source_execution_weight_keys and float(weights_map.get(w, 0) or 0) != 0.0])
    canonical_exec_scored = sorted([w for w in weight_keys if w in canonical_execution_weight_keys and float(weights_map.get(w, 0) or 0) != 0.0])

    legacy_persistence_inputs = {
        "persistence_service",
        "persistence_scheduled_task",
        "persistence_runkey",
        "account_or_group_change",
    }
    legacy_persistence_temporal = sorted([s for s in temporal_inputs if s in legacy_persistence_inputs])
    canonical_persistence_sources = {
        "persistence_mechanism": {"persistence_service", "persistence_scheduled_task", "persistence_runkey"},
        "persistence_scheduled": {"persistence_scheduled_task"},
        "persistence_registry": {"persistence_runkey"},
        "persistence_service_install": {"persistence_service"},
        "identity_persistence_change": {"account_or_group_change"},
    }
    canonical_persistence_targets = set(canonical_persistence_sources.keys())
    canonical_persistence_never_produced = sorted([
        target
        for target, sources in canonical_persistence_sources.items()
        if not any(source in emitted for source in sources)
    ])
    source_persistence_weight_keys = legacy_persistence_inputs
    canonical_persistence_weight_keys = canonical_persistence_targets
    source_persistence_scored = sorted([w for w in weight_keys if w in source_persistence_weight_keys and float(weights_map.get(w, 0) or 0) != 0.0])
    canonical_persistence_scored = sorted([w for w in weight_keys if w in canonical_persistence_weight_keys and float(weights_map.get(w, 0) or 0) != 0.0])

    legacy_transfer_inputs = {
        "large_archive_created",
        "archive_created",
        "data_transfer_tool_exec",
        "large_http_transfer",
        "sensitive_data_staged",
        "staging_then_transfer",
        "cross_border_transfer",
        "archive_after_sensitive_access",
    }
    legacy_transfer_temporal = sorted([s for s in temporal_inputs if s in legacy_transfer_inputs])
    canonical_transfer_sources = {
        "staging_archive": {"large_archive_created", "archive_created"},
        "transfer_execution": {"data_transfer_tool_exec"},
        "transfer_large_http": {"large_http_transfer"},
        "transfer_exfiltration_pattern": {"staging_then_transfer"},
        "transfer_cross_border": {"cross_border_transfer"},
        "transfer_sensitive_staging": {"sensitive_data_staged", "archive_after_sensitive_access"},
    }
    canonical_transfer_targets = set(canonical_transfer_sources.keys())
    canonical_transfer_never_produced = sorted([
        target
        for target, sources in canonical_transfer_sources.items()
        if not any(source in emitted for source in sources)
    ])
    source_transfer_weight_keys = legacy_transfer_inputs
    canonical_transfer_weight_keys = canonical_transfer_targets
    source_transfer_scored = sorted([w for w in weight_keys if w in source_transfer_weight_keys and float(weights_map.get(w, 0) or 0) != 0.0])
    canonical_transfer_scored = sorted([w for w in weight_keys if w in canonical_transfer_weight_keys and float(weights_map.get(w, 0) or 0) != 0.0])

    if missing_weights:
        msg = "ChronoSift config warning: signals emitted without weights: " + ", ".join(missing_weights)
        if strict:
            raise ValueError(msg)
        print(msg)

    if temporal_missing:
        msg = "ChronoSift config warning: temporal rules reference signals never emitted: " + ", ".join(temporal_missing)
        if strict:
            raise ValueError(msg)
        print(msg)

    if legacy_auth_weight_keys:
        print(
            "ChronoSift config warning: legacy/duplicate auth weight keys present: "
            + ", ".join(legacy_auth_weight_keys)
        )

    if canonical_never_produced:
        msg = "ChronoSift config warning: canonical auth targets are configured but never produced: " + ", ".join(canonical_never_produced)
        if strict:
            raise ValueError(msg)
        print(msg)

    if legacy_execution_temporal:
        print(
            "ChronoSift config warning: temporal rules reference legacy execution source signals where canonical execution_* names exist: "
            + ", ".join(legacy_execution_temporal)
        )

    if canonical_execution_never_produced:
        msg = "ChronoSift config warning: canonical execution targets are defined but never produced: " + ", ".join(canonical_execution_never_produced)
        if strict:
            raise ValueError(msg)
        print(msg)

    context_execution_unknown_weights = sorted([
        w for w in weight_keys
        if w.startswith("exec_") and w not in canonical_execution_context_targets
    ])
    if context_execution_unknown_weights:
        print(
            "ChronoSift config warning: execution-context weights are present for unknown signals: "
            + ", ".join(context_execution_unknown_weights)
        )

    if source_exec_scored and canonical_exec_scored:
        print(
            "ChronoSift config warning: both source and canonical execution weights are non-zero; ensure this double-counting is intentional. "
            f"source={','.join(source_exec_scored)} canonical={','.join(canonical_exec_scored)}"
        )

    if legacy_persistence_temporal:
        print(
            "ChronoSift config warning: temporal rules reference legacy persistence source signals where canonical persistence_* names exist: "
            + ", ".join(legacy_persistence_temporal)
        )

    if canonical_persistence_never_produced:
        msg = "ChronoSift config warning: canonical persistence targets are defined but never produced: " + ", ".join(canonical_persistence_never_produced)
        if strict:
            raise ValueError(msg)
        print(msg)

    if source_persistence_scored and canonical_persistence_scored:
        print(
            "ChronoSift config warning: both source and canonical persistence weights are non-zero; ensure this double-counting is intentional. "
            f"source={','.join(source_persistence_scored)} canonical={','.join(canonical_persistence_scored)}"
        )

    if legacy_transfer_temporal:
        print(
            "ChronoSift config warning: temporal rules reference legacy transfer/exfiltration signals where canonical transfer_* names exist: "
            + ", ".join(legacy_transfer_temporal)
        )

    if canonical_transfer_never_produced:
        msg = "ChronoSift config warning: canonical transfer targets are defined but never produced: " + ", ".join(canonical_transfer_never_produced)
        if strict:
            raise ValueError(msg)
        print(msg)

    if source_transfer_scored and canonical_transfer_scored:
        print(
            "ChronoSift config warning: both source and canonical transfer weights are non-zero; ensure this double-counting is intentional. "
            f"source={','.join(source_transfer_scored)} canonical={','.join(canonical_transfer_scored)}"
        )

    # Unused weights are not necessarily wrong (e.g., future work), so warn only.
    if unused_weights:
        print("ChronoSift config note: weights defined but not currently emitted: " + ", ".join(unused_weights))


@dataclass(frozen=True)
class Condition:
    field: str
    op: str
    value: Any = None


@dataclass(frozen=True)
class Modifier:
    """
    Modifiers are applied after rule evaluation. They are the correct place for
    controlled dampening/amplification (e.g., YARA artefact dampening).
    """
    target_signal: str
    op: str  # currently only "multiply"
    value: float


@dataclass(frozen=True)
class EmitSignal:
    name: str
    value: Any


@dataclass(frozen=True)
class Rule:
    rule_id: str
    description: str
    priority: int
    scope_any: List[Condition]
    scope_all: List[Condition]
    when_any: List[Condition]
    when_all: List[Condition]
    emit_signals: List[EmitSignal]
    emit_modifiers: List[Modifier]
    evidence_fields: List[str]
    confidence: str = "medium"


@dataclass(frozen=True)
class TemporalNeed:
    signal: str
    min_count: int = 1


@dataclass(frozen=True)
class TemporalRule:
    rule_id: str
    description: str
    priority: int
    key_by: List[str]
    lookback: timedelta
    mode: str  # sequence|cooccur|first_seen_value|change_detected
    sequence: List[TemporalNeed]
    cooccur_all: List[TemporalNeed]
    field: Optional[str]
    emit_signals: List[EmitSignal]
    confidence: str = "medium"


def _merge_schema_aliases(raw: Dict[str, Any]) -> Dict[str, Tuple[str, ...]]:
    merged: Dict[str, Tuple[str, ...]] = dict(DEFAULT_SCHEMA_ALIASES)
    for canonical, aliases in (raw or {}).items():
        key = str(canonical).strip()
        if not key:
            continue
        vals = tuple(str(v).strip() for v in (aliases or []) if str(v).strip())
        if vals:
            merged[key] = vals
    return merged


@dataclass(frozen=True)
class TemporalGroupPlan:
    ordered_rows: Any
    group_slices: List[Tuple[int, int, Tuple[str, ...]]]
    groups_seen: int
    largest_group: int


@dataclass(frozen=True)
class ProfileMultiplier:
    """
    Dataset-derived quiet-time is not danger by itself; it modulates other signals.

    Multiplier formula (deliberately constrained for reproducibility):
        m = 1 + k * hour_rarity

    Applied to the *signal value* of selected signals (not to the whole event score).
    """
    mid: str
    applies_to: Set[str]
    k: float


# =============================================================================
# ChronoSift engine
# =============================================================================



_PATH_RE_UNIX = re.compile(r'/(?:[^ \t\r\n"\'<>|]+/)*[^ \t\r\n"\'<>|]+')
_PATH_RE_WIN = re.compile(r'[A-Za-z]:\\(?:[^ \t\r\n"\'<>|]+\\)*[^ \t\r\n"\'<>|]+')
_PATH_RE_REL = re.compile(r'(?:(?:\./)|(?:\.\./))[^ \t\r\n"\'<>|]+')
def _hour_rarity_explain_item() -> Dict[str, Any]:
    return {
        "rule_id": "HOUR_RARITY",
        "description": "Dataset activity profile rarity contributed to score",
        "confidence": "low",
        "evidence_type": "profiling",
        "evidence": {
            "score_column": "chronosift_hour_rarity_score",
            "rarity_column": "hour_rarity",
        },
    }


@lru_cache(maxsize=131072)
def _normalise_reference_path_from_string(s: str) -> Optional[str]:
    """Cached string-only helper backing conservative reference-path normalisation."""
    s = s.strip()
    if not s:
        return None
    # Remove surrounding quotes/backticks first.
    s = s.strip('\'"`')
    # Trim punctuation commonly adjacent in messages/commands.
    s = s.rstrip('.,;:)]}>')
    s = s.lstrip('([{<')
    # A second pass helps with wrapped cron/syslog command strings like CMD (/path/to/file)
    s = s.strip('\'"`')
    # Normalise trivial duplicate separators without attempting expensive path resolution.
    s = s.replace('\\\\', '\\')
    while '//' in s:
        s = s.replace('//', '/')
    return s or None


def _normalise_reference_path(value: Any) -> Optional[str]:
    """Normalise an extracted path token conservatively for exact-match comparison."""
    s = _safe_str(value)
    if not s:
        return None
    return _normalise_reference_path_from_string(s)


@lru_cache(maxsize=131072)
def _basename_from_reference_path(path: str) -> str:
    return os.path.basename(path.replace("\\", "/"))


def _extract_referenced_paths_from_text(value: Any) -> Tuple[str, ...]:
    """Extract file-like paths from free-text messages for referenced-file correlation."""
    s = _safe_str(value)
    if not s:
        return tuple()

    return _extract_referenced_paths_from_string(s)


@lru_cache(maxsize=32768)
def _extract_referenced_paths_from_string(s: str) -> Tuple[str, ...]:
    """Cached string-only helper backing referenced-file path extraction."""
    if not s:
        return tuple()

    out: List[str] = []
    seen: Set[str] = set()

    for rx in (_PATH_RE_UNIX, _PATH_RE_WIN):
        for m in rx.finditer(s):
            p = _normalise_reference_path(m.group(0))
            if p and p not in seen:
                seen.add(p)
                out.append(p)

    # Also recognise very common relative execution forms in shell and cron contexts.
    for m in _PATH_RE_REL.finditer(s):
        p = _normalise_reference_path(m.group(0))
        if p and p not in seen:
            seen.add(p)
            out.append(p)

    return tuple(out)


DEFAULT_PATH_TAXONOMY: Dict[str, Tuple[str, ...]] = {
    "web_root_patterns": (
        "/var/www/",
        "/srv/www/",
        "/usr/share/nginx/html/",
        "/htdocs/",
        "/httpdocs/",
        "\\inetpub\\wwwroot\\",
        "\\xampp\\htdocs\\",
    ),
    "sensitive_path_patterns": (
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/root/.ssh/",
        "/.ssh/",
        "/.gnupg/",
        "/.bash_history",
        "/.zsh_history",
        "/.mysql_history",
        "/.psql_history",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "authorized_keys",
        "known_hosts",
        "\\windows\\system32\\config\\sam",
        "\\windows\\system32\\config\\system",
        "\\windows\\system32\\config\\security",
        "ntds.dit",
        "web.config",
        "\\repair\\sam",
        "\\repair\\system",
    ),
    "database_dump_patterns": (
        "dump",
        "mysqldump",
        "pg_dump",
        "sqlite dump",
    ),
    "cron_path_patterns": (
        "/etc/crontab",
        "/etc/anacrontab",
        "/etc/cron.d/",
        "/etc/cron.daily/",
        "/etc/cron.hourly/",
        "/etc/cron.monthly/",
        "/etc/cron.weekly/",
        "/var/spool/cron/",
        "/var/spool/cron/crontabs/",
    ),
    "service_config_patterns": (
        "/etc/systemd/system/",
        "/lib/systemd/system/",
        "/usr/lib/systemd/system/",
        "/etc/init.d/",
        "\\system\\currentcontrolset\\services\\",
    ),
    "firewall_path_patterns": (
        "/etc/firewalld/",
        "/etc/ufw/",
        "/etc/sysconfig/iptables",
        "/etc/iptables/",
        "\\sharedaccess\\parameters\\firewallpolicy\\",
    ),
    "group_policy_path_patterns": (
        "\\grouppolicy\\",
        "\\sysvol\\",
        "\\policies\\",
        "registry.pol",
    ),
    "winlogon_path_patterns": (
        "\\microsoft\\windows nt\\currentversion\\winlogon",
    ),
    "com_hijack_path_patterns": (
        "\\classes\\clsid\\",
        "\\classes\\wow6432node\\clsid\\",
    ),
    "os_update_path_patterns": (
        "\\winsxs\\",
        "\\softwaredistribution\\",
        "\\windows\\assembly\\",
        "\\windows\\installer\\",
        "/usr/lib/",
        "/usr/share/doc/",
        "/usr/share/man/",
        "/var/cache/apt/",
        "/var/cache/dnf/",
        "/var/cache/yum/",
        "/var/lib/dpkg/",
        "/var/lib/rpm/",
    ),
}

DEFAULT_WEB_DOCUMENT_ROOTS: Tuple[str, ...] = (
    "/var/www/html",
    "/srv/www",
    "/usr/share/nginx/html",
    "/htdocs",
    "/httpdocs",
    "inetpub/wwwroot",
    "xampp/htdocs",
)

DEFAULT_DETECTION_VOCABULARY: Dict[str, Tuple[str, ...]] = {
    "archive_extensions": (".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz"),
    "web_script_extensions": (".php", ".phtml", ".php3", ".php4", ".php5", ".asp", ".aspx", ".ashx", ".jsp", ".jspx", ".cgi", ".pl"),
    "web_content_extensions": (".php", ".phtml", ".php3", ".php4", ".php5", ".asp", ".aspx", ".jsp", ".jspx", ".cgi", ".pl", ".html", ".htm", ".js", ".css"),
    "database_dump_extensions": (".sql", ".dump", ".bak", ".sqlite", ".db"),
    "suspicious_temp_web_name_tokens": ("tmp", "temp"),
    "defender_disable_tokens": (
        "disableantispyware",
        "disablerealtimemonitoring",
        "realtime protection disabled",
        "real-time protection disabled",
        "microsoft defender antivirus has been disabled",
        "windows defender has been turned off",
    ),
    "windows_privileged_group_tokens": (
        "administrators",
        "domain admins",
        "enterprise admins",
        "remote desktop users",
    ),
    "windows_remote_admin_pipe_tokens": (
        "svcctl",
        "atsvc",
        "winreg",
        "samr",
        "lsarpc",
        "srvsvc",
        "wkssvc",
        "spoolss",
    ),
    "firewall_message_tokens": ("firewalld", "iptables", "ufw", "windows firewall"),
    "firewall_change_tokens": ("changed", "modified", "disabled", "added", "deleted"),
    "account_created_message_tokens": ("user account was created", " useradd[", "useradd["),
    "systemd_unit_extensions": (".service", ".socket", ".timer", ".mount", ".path"),
    "systemd_enable_tokens": ("systemctl enable", "systemctl start", "systemctl restart", "systemctl link", "systemctl preset", "daemon-reload"),
    "webshell_name_tokens": ("cmd", "shell", "webshell", "c99", "r57", "b374k", "wso", "filemanager", "upload"),
    "recovery_inhibit_command_tokens": (
        "vssadmin delete shadows",
        "wmic shadowcopy delete",
        "wbadmin delete",
        "bcdedit /set",
        "reagentc /disable",
        "delete catalog",
        "shadowcopy delete",
    ),
    "cleanup_command_tokens": (
        "wevtutil cl",
        "history -c",
        "rm .bash_history",
        "rm ~/.bash_history",
        "truncate -s 0",
        "shred ",
        "sdelete",
        "clear-eventlog",
    ),
    "credential_dump_command_tokens": (
        "procdump",
        "comsvcs.dll",
        "minidump",
        "ntdsutil",
        "reg save hklm\\sam",
        "reg save hklm\\system",
        "lsass.dmp",
        "sekurlsa",
    ),
    "password_store_path_tokens": (
        "login data",
        "key4.db",
        "logins.json",
        ".kdbx",
        "credentials",
        "vault",
        "web.config",
    ),
    "password_store_message_tokens": (
        "login data",
        "key4.db",
        "logins.json",
        ".kdbx",
        "credentials",
        "vault",
        "web.config",
    ),
    "file_discovery_command_tokens": (" dir", "dir ", " ls", "ls ", "find ", "tree ", "locate ", "grep "),
    "remote_discovery_command_tokens": (
        "net view",
        "quser",
        "qwinsta",
        "arp -a",
        "route print",
        "ip neigh",
        "nslookup ",
        "resolve-dnsname",
        "nltest /dclist",
        "nltest.exe /dclist",
        "ping -n 1",
        "ping -c 1",
    ),
    "system_owner_discovery_command_tokens": ("whoami", "id ", "hostname", "uname -a", "ipconfig", "ifconfig"),
    "admin_share_tokens": ("\\\\c$", "\\\\admin$", "\\\\ipc$", "/admin$", "/ipc$"),
    "account_access_removed_message_tokens": (
        "user account disabled",
        "user account was disabled",
        "user account deleted",
        "removed from local group",
        "removed from group",
        "userdel",
    ),
    "log_artifact_tokens": (
        "/var/log/",
        "\\windows\\system32\\winevt\\logs\\",
        ".bash_history",
        ".zsh_history",
        ".psql_history",
        ".mysql_history",
    ),
    "application_protocol_tokens": ("http://", "https://", "ftp://", "sftp://", "scp://", "smb://", "cifs://", "\\\\"),
    "web_upload_tokens": ("multipart/form-data", "filename=", "upload"),
    "web_upload_endpoint_tokens": ("upload", "filemanager", "connector", "ajaxfilemanager", "ckfinder", "elfinder"),
    "web_log_parser_tokens": ("apache", "nginx", "iis", "w3c", "msiis"),
    "credential_copy_command_tokens": (
        "copy ",
        "cp ",
        "xcopy ",
        "robocopy ",
        "move ",
        "mv ",
        "copy-item ",
        "tar ",
        "zip ",
        "7z ",
        "rar ",
        "scp ",
        "sftp ",
        "curl ",
        "wget ",
    ),
    "ransom_note_name_tokens": ("readme", "decrypt", "recover", "restore", "how_to", "ransom"),
    "ransom_extension_tokens": (
        ".locked",
        ".lockbit",
        ".encrypted",
        ".crypt",
        ".crypted",
        ".conti",
        ".akira",
        ".blackcat",
        ".cl0p",
        ".clop",
        ".zepto",
        ".cerber",
        ".deadbolt",
        ".wannacry",
        ".wncry",
        ".play",
        ".royal",
        ".phobos",
    ),
    "remote_service_message_tokens": ("rdp", "remote desktop", "ssh", "winrm", "terminalservices", "session opened"),
    "service_stop_command_tokens": (
        "sc stop",
        "sc.exe stop",
        "net stop",
        "net.exe stop",
        "stop-service",
        "taskkill /f",
        "taskkill.exe /f",
        "systemctl stop",
        # Note: "service stop" is intentionally excluded. Standard Linux SysV
        # syntax is "service <name> stop" (not "service stop <name>"), so the
        # token does not match real commands. It does false-positive on EVTX
        # 7036 messages like "The X service stopped" where "service stop" is
        # a substring of "service stopped".
    ),
    "winlogon_persistence_value_tokens": (
        "shell",
        "userinit",
        "notify",
        "appinit_dlls",
        "taskman",
    ),
}

DEFAULT_DETECTION_EVENT_IDS: Dict[str, Tuple[str, ...]] = {
    "account_created": ("4720",),
    "account_disabled": ("4725",),
    "account_deleted": ("4726",),
    "privileged_group_change": ("4728", "4732", "4756"),
    "group_removal_change": ("4729", "4733", "4757"),
    "share_access": ("5140", "5145"),
    "explicit_credential_logon": ("4648",),
    "service_stopped": ("7036",),
    "service_start_type_changed": ("7040",),
}

DEFAULT_DETECTION_THRESHOLDS: Dict[str, Any] = {
    "short_lived_file_window": "2h",
    "mass_file_modification_window": "10m",
    "mass_file_modification_threshold": 25,
    "ransom_extension_burst_window": "15m",
    "ransom_extension_burst_threshold": 6,
    "repeated_scheduled_exec_window": "10m",
    "repeated_scheduled_exec_threshold": 3,
    "download_exec_window": "2h",
    "webshell_activity_window": "30m",
    "automated_exfiltration_window": "30m",
    "automated_exfiltration_threshold": 2,
    "credential_collection_window": "1h",
}

_EXEC_TMP_PATH_TOKENS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "\\temp\\",
    "%temp%",
    "\\windows\\temp\\",
    "\\appdata\\local\\temp\\",
)
_EXEC_USER_WRITABLE_PATH_TOKENS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/home/",
    "/users/",
    "/downloads/",
    "\\users\\public\\",
    "\\users\\",
    "\\temp\\",
    "\\appdata\\",
    "%temp%",
    "%appdata%",
    "\\windows\\temp\\",
    "\\appdata\\local\\temp\\",
)
_EXEC_SUSPICIOUS_PATH_TOKENS = (
    "/run/",
    "/var/run/",
    "/opt/",
    "\\programdata\\",
    "\\perflogs\\",
    "\\recycler\\",
    "\\windows\\debug\\",
    "\\intel\\",
)
_SYSTEM_BINARY_NAMES = {
    "svchost.exe",
    "lsass.exe",
    "explorer.exe",
    "sshd",
    "bash",
}
_EXEC_COMPILER_NAMES = {"gcc", "cc", "make"}
_EXEC_SHELL_NAMES = {"sh", "bash", "cmd", "cmd.exe", "powershell", "pwsh"}
_EXEC_NETWORK_NAMES = {"nc", "netcat", "ncat", "socat", "curl", "wget", "ftp", "scp", "sftp"}
_EXEC_ARCHIVE_NAMES = {"tar", "zip", "7z", "rar", "gzip"}
_EXEC_SUID_RE = re.compile(
    r"(?i)(?:chmod\s+4[0-7]{3}|chmod\s+u\+s|setuid|setgid|chown\s+root(?::root)?|suid)"
)
_UNC_PATH_RE = re.compile(r"(?i)(\\\\\\\\[^\\/\s]+\\(?:c\$|admin\$|ipc\$|print\$|netlogon|sysvol))")
_COMMAND_TOKEN_RE = re.compile(r"[A-Za-z0-9_./:\\-]+")


@lru_cache(maxsize=131072)
def _classify_command_name_mentions_cached(s: str) -> Tuple[bool, bool, bool, bool]:
    if not s:
        return False, False, False, False
    compiler_hit = False
    shell_hit = False
    network_hit = False
    archive_hit = False
    for match in _COMMAND_TOKEN_RE.finditer(s):
        token = match.group(0)
        base = _basename_from_reference_path(token) if ("/" in token or "\\" in token) else token
        if not compiler_hit and (token in _EXEC_COMPILER_NAMES or base in _EXEC_COMPILER_NAMES):
            compiler_hit = True
        if not shell_hit and (token in _EXEC_SHELL_NAMES or base in _EXEC_SHELL_NAMES):
            shell_hit = True
        if not network_hit and (token in _EXEC_NETWORK_NAMES or base in _EXEC_NETWORK_NAMES):
            network_hit = True
        if not archive_hit and (token in _EXEC_ARCHIVE_NAMES or base in _EXEC_ARCHIVE_NAMES):
            archive_hit = True
        if compiler_hit and shell_hit and network_hit and archive_hit:
            break
    return compiler_hit, shell_hit, network_hit, archive_hit


def _classify_command_name_mentions(value: Any) -> Tuple[bool, bool, bool, bool]:
    s = _safe_str(value).strip().lower()
    if not s:
        return False, False, False, False
    return _classify_command_name_mentions_cached(s)


def _merge_string_tuple_config(defaults: Dict[str, Tuple[str, ...]], raw: Dict[str, Any]) -> Dict[str, Tuple[str, ...]]:
    merged: Dict[str, Tuple[str, ...]] = dict(defaults)
    for key, values in (raw or {}).items():
        cfg_key = str(key).strip()
        if not cfg_key:
            continue
        merged[cfg_key] = tuple(str(v).strip() for v in (values or []) if str(v).strip())
    return merged


def _merge_generic_config(defaults: Dict[str, Any], raw: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(defaults)
    for key, value in (raw or {}).items():
        cfg_key = str(key).strip()
        if cfg_key:
            merged[cfg_key] = value
    return merged


def _best_effort_file_path_values(
    filename: Any = None,
    relative_path: Any = None,
    display_name: Any = None,
    pathspec: Any = None,
    link_target: Any = None,
) -> Optional[str]:
    for value in (filename, relative_path, display_name, pathspec, link_target):
        norm = _normalise_reference_path(value)
        if norm:
            return norm
    return None


def _timestamp_desc_kind(value: Any) -> str:
    s = _safe_str(value).strip().lower()
    if not s:
        return ""
    if "create" in s or "creation" in s or "birth" in s:
        return "create"
    if "delete" in s or "delet" in s:
        return "delete"
    if "modif" in s or "change" in s or "content" in s or "mtime" in s:
        return "modify"
    if "access" in s or "open" in s or "atime" in s:
        return "access"
    return ""


def _timestamp_desc_kind_vectorised(series: "pd.Series") -> "pd.Series":
    """Vectorised equivalent of _timestamp_desc_kind — classifies timestamp_desc."""
    s = series.astype("string").fillna("").str.strip().str.lower()
    result = pd.Series("", index=series.index, dtype="string")
    create_mask = s.str.contains("create|creation|birth", regex=True, na=False)
    result = result.where(~create_mask, "create")
    delete_mask = s.str.contains("delet", regex=False, na=False) & result.eq("")
    result = result.where(~delete_mask, "delete")
    modify_mask = s.str.contains("modif|change|content|mtime", regex=True, na=False) & result.eq("")
    result = result.where(~modify_mask, "modify")
    access_mask = s.str.contains("access|open|atime", regex=True, na=False) & result.eq("")
    result = result.where(~access_mask, "access")
    return result


def _normalise_reference_path_series(series: "pd.Series") -> "pd.Series":
    """Vectorised equivalent of _normalise_reference_path for path coalescing."""
    s = series.astype("string").fillna("").str.strip()
    if len(s) == 0:
        return pd.Series([], index=series.index, dtype=object)
    s = s.str.strip("'\"`")
    s = s.str.rstrip(".,;:)]}>")
    s = s.str.lstrip("([{<")
    s = s.str.strip("'\"`")
    s = s.str.replace("\\\\", "\\", regex=False)
    s = s.str.replace(r"/{2,}", "/", regex=True)
    s = s.mask(s.eq(""))
    out = s.astype(object)
    return out.where(pd.notna(out), None)


def _best_effort_file_path_vectorised(df: "pd.DataFrame") -> "pd.Series":
    """Vectorised coalesce across path columns — first non-empty normalised path wins."""
    _PATH_COLS = ("filename", "relative_path", "display_name", "pathspec", "link_target")
    result = np.full(len(df), None, dtype=object)
    filled_mask = np.zeros(len(df), dtype=bool)
    for col in _PATH_COLS:
        if col not in df.columns:
            continue
        if filled_mask.all():
            break
        norm_vals = _normalise_reference_path_series(df[col]).to_numpy(dtype=object, copy=False)
        take = (~filled_mask) & pd.notna(norm_vals)
        if bool(take.any()):
            result[take] = norm_vals[take]
            filled_mask[take] = True
    return pd.Series(result, index=df.index, dtype=object)


def _column_values_or_none(df: "pd.DataFrame", column: str) -> np.ndarray:
    if column in df.columns:
        return df[column].to_numpy(copy=False)
    return np.full(len(df), None, dtype=object)


def _normalised_text_array(
    df: "pd.DataFrame",
    column: str,
    *,
    lower: bool = False,
) -> np.ndarray:
    """Return a stripped text array for a column, defaulting to empty strings."""
    if column not in df.columns:
        return np.full(len(df), "", dtype=object)
    s = df[column].astype("string").fillna("").str.strip()
    if lower:
        s = s.str.lower()
    return s.to_numpy(dtype=object, copy=False)


def _contextual_cached_array(
    cache: Optional[Dict[Tuple[Any, ...], np.ndarray]],
    key: Tuple[Any, ...],
    builder,
) -> np.ndarray:
    """Build a contextual working array once without storing it in DataFrame attrs."""
    if cache is None:
        return builder()
    cached = cache.get(key)
    if cached is None:
        cached = builder()
        cache[key] = cached
    return cached


def _contextual_text_array(
    df: "pd.DataFrame",
    cache: Optional[Dict[Tuple[Any, ...], np.ndarray]],
    column: str,
    *,
    lower: bool = False,
) -> np.ndarray:
    return _contextual_cached_array(
        cache,
        ("text", column, bool(lower)),
        lambda: _normalised_text_array(df, column, lower=lower),
    )


def _contextual_file_paths(
    df: "pd.DataFrame",
    cache: Optional[Dict[Tuple[Any, ...], np.ndarray]],
) -> np.ndarray:
    return _contextual_cached_array(
        cache,
        ("file_paths",),
        lambda: _best_effort_file_path_vectorised(df).to_numpy(dtype=object, copy=False),
    )


def _contextual_path_lower(
    df: "pd.DataFrame",
    cache: Optional[Dict[Tuple[Any, ...], np.ndarray]],
) -> np.ndarray:
    def build() -> np.ndarray:
        file_paths = _contextual_file_paths(df, cache)
        return (
            pd.Series(file_paths, index=df.index, dtype="string")
            .fillna("")
            .str.strip()
            .str.lower()
            .str.replace("\\", "/", regex=False)
            .to_numpy(dtype=object, copy=False)
        )

    return _contextual_cached_array(cache, ("path_lower",), build)


def _contextual_timestamp_kinds(
    df: "pd.DataFrame",
    cache: Optional[Dict[Tuple[Any, ...], np.ndarray]],
) -> np.ndarray:
    def build() -> np.ndarray:
        values = df["timestamp_desc"] if "timestamp_desc" in df.columns else pd.Series(None, index=df.index)
        return _timestamp_desc_kind_vectorised(values).to_numpy(dtype=object, copy=False)

    return _contextual_cached_array(cache, ("timestamp_kinds",), build)


def _text_array_contains_any(values: np.ndarray, tokens: Iterable[str]) -> np.ndarray:
    """Vectorised literal-token containment for contextual prefilters."""
    terms = tuple(str(token) for token in tokens if str(token))
    if not terms:
        return np.zeros(len(values), dtype=bool)
    pattern = "|".join(re.escape(token) for token in terms)
    return (
        pd.Series(values, dtype="string")
        .str.contains(pattern, regex=True, na=False)
        .to_numpy(dtype=bool, copy=False)
    )


def _combined_command_text_array(df: "pd.DataFrame") -> np.ndarray:
    """Build and cache the joined actor/command/message text used by dampening passes."""
    cached = df.attrs.get("_chronosift_combined_command_text")
    if isinstance(cached, np.ndarray) and len(cached) == len(df):
        return cached

    actor_cmd_vals = _normalised_text_array(df, "actor_cmd")
    command_line_vals = _normalised_text_array(df, "command_line")
    message_vals = _normalised_text_array(df, "message")
    combined = np.empty(len(df), dtype=object)

    for i in range(len(df)):
        parts = []
        actor_cmd = actor_cmd_vals[i]
        command_line = command_line_vals[i]
        message = message_vals[i]
        if actor_cmd:
            parts.append(actor_cmd)
        if command_line:
            parts.append(command_line)
        if message:
            parts.append(message)
        combined[i] = " ".join(parts)

    df.attrs["_chronosift_combined_command_text"] = combined
    return combined


def _extract_scheduled_command_text_values(
    actor_cmd: Any = None,
    command_line: Any = None,
    message: Any = None,
) -> str:
    actor_cmd_s = _safe_str(actor_cmd).strip()
    if actor_cmd_s:
        return actor_cmd_s
    command_line_s = _safe_str(command_line).strip()
    if command_line_s:
        return command_line_s
    message_s = _safe_str(message).strip()
    if not message_s:
        return ""
    m = re.search(r"CMD\s*\((.*?)\)", message_s, flags=re.IGNORECASE)
    if m:
        return _safe_str(m.group(1)).strip()
    return message_s[:200]





def _ip_scope(value: Any) -> Optional[str]:
    """Classify an IP for continuity analysis."""
    s = _safe_str(value).strip()
    if not s:
        return None
    try:
        ip = ipaddress.ip_address(s)
    except Exception:
        return None
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return None
    if ip.is_private:
        return "private"
    if ip.is_global:
        return "public"
    return None


def _ip_subnet_label(value: Any, prefix_v4: int = 24, prefix_v6: int = 64) -> Optional[str]:
    """Return a subnet label for private-IP continuity comparison."""
    s = _safe_str(value).strip()
    if not s:
        return None
    try:
        ip = ipaddress.ip_address(s)
    except Exception:
        return None
    if not ip.is_private:
        return None
    prefix = prefix_v4 if ip.version == 4 else prefix_v6
    try:
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return str(net)
    except Exception:
        return None


def _normalise_hash_series(series: pd.Series) -> pd.Series:
    """Normalise hash text for case/whitespace-insensitive lookups."""
    return series.astype("string").str.strip().str.upper()


def _reindex_lookup_frame_for_hashes(
    lookup_hash: pd.Series,
    lookup_df: pd.DataFrame,
    *,
    columns: Optional[Iterable[str]] = None,
) -> pd.DataFrame:
    """Align a hash-indexed lookup frame to a normalised hash Series in one pass."""
    cols = list(columns) if columns is not None else list(lookup_df.columns)
    if len(lookup_df) == 0:
        return pd.DataFrame(index=lookup_hash.index, columns=cols)

    aligned = lookup_df.reindex(pd.Index(lookup_hash.to_numpy(copy=False), name=lookup_df.index.name))
    aligned.index = lookup_hash.index
    if columns is not None:
        aligned = aligned.loc[:, cols]
    return aligned


def _truthy_like(value: Any) -> bool:
    """Interpret common CSV-style truthy values safely."""
    if value is None:
        return False
    try:
        if pd.isna(value):
            return False
    except Exception:
        pass
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        try:
            return float(value) != 0.0
        except Exception:
            return False
    return str(value).strip().lower() in {"1", "true", "t", "yes", "y"}


def _load_hash_hit_set_from_csv(
    csv_path: str,
    hit_col: str,
    csv_hash_col: str = "sha256",
) -> Set[str]:
    """Load the set of normalised hashes whose hit column is truthy."""
    enrich = _load_hash_enrichment_frame(csv_path, csv_hash_col=csv_hash_col)
    if hit_col not in enrich.columns:
        return set()
    hit_mask = enrich[hit_col].map(_truthy_like)
    idx = enrich.index[hit_mask]
    valid = idx[idx.notna()]
    str_vals = valid.astype(str)
    stripped = str_vals.str.strip()
    return set(str_vals[stripped != ""])


def _load_hash_enrichment_frame(
    csv_path: str,
    csv_hash_col: str = "sha256",
) -> pd.DataFrame:
    """Load and normalise a hash-keyed enrichment CSV once per file version."""
    p = Path(csv_path)
    stat = p.stat()
    cache_key = (str(p.resolve()), str(csv_hash_col), int(stat.st_mtime_ns), int(stat.st_size))
    cached = ChronoSiftEngine._hash_enrichment_cache.get(cache_key)
    if cached is not None:
        return cached

    enrich = pd.read_csv(csv_path, comment="#")
    if csv_hash_col not in enrich.columns:
        raise ValueError(f"Enrichment CSV missing required column: {csv_hash_col!r}")

    norm_name = "_chronosift_norm_hash"
    hash_col_matches = np.flatnonzero(enrich.columns.to_numpy(dtype=object) == csv_hash_col)
    if len(hash_col_matches) == 0:
        raise ValueError(f"Enrichment CSV missing required column: {csv_hash_col!r}")
    norm_hash = _normalise_hash_series(enrich.iloc[:, int(hash_col_matches[0])])
    valid_norm_hash = norm_hash.notna() & norm_hash.ne("")
    if not bool(valid_norm_hash.all()):
        enrich = enrich.loc[valid_norm_hash]
        norm_hash = norm_hash.loc[valid_norm_hash]
    norm_index = pd.Index(norm_hash.to_numpy(copy=False), name=norm_name)
    keep_mask = ~norm_index.duplicated(keep="last")
    if not bool(np.all(keep_mask)):
        enrich = enrich.loc[keep_mask]
        norm_index = norm_index[keep_mask]
    enrich.index = norm_index
    enrich = enrich.drop(columns=[csv_hash_col], errors="ignore")
    ChronoSiftEngine._hash_enrichment_cache[cache_key] = enrich
    return enrich


def _nsrl_lookup_candidate_mask(df: pd.DataFrame, hash_col: str = "sha256_hash") -> pd.Series:
    """Restrict NSRL lookups to rows that plausibly describe real file artefacts."""
    if hash_col not in df.columns:
        return pd.Series(False, index=df.index, dtype=bool)

    sha = _normalise_hash_series(df[hash_col])
    mask = sha.str.fullmatch(r"[0-9A-F]{64}", na=False)

    if "filename" in df.columns:
        fname_mask = df["filename"].astype("string").fillna("").str.strip().ne("")
        mask &= fname_mask

    return mask.fillna(False).astype(bool)


def _prepare_nsrl_cache_df(nsrl_cache_df: pd.DataFrame) -> pd.DataFrame:
    """Normalise a parquet NSRL cache and prepare reusable lookup maps once."""
    df = nsrl_cache_df
    if df is None or len(df) == 0:
        return df
    if "sha256" not in df.columns:
        raise ValueError("NSRL cache missing sha256 column")
    if "nsrl_application_types" in df.columns and "nsrl_application_type" not in df.columns:
        df = df.rename(columns={"nsrl_application_types": "nsrl_application_type"})

    df = df.drop_duplicates("sha256")
    application_type = (
        df["nsrl_application_type"].astype("string")
        if "nsrl_application_type" in df.columns
        else pd.Series(pd.NA, index=df.index, dtype="string")
    )
    is_os_component = (
        df["nsrl_is_os_component"].astype("boolean")
        if "nsrl_is_os_component" in df.columns
        else application_type
        .fillna("")
        .str.contains("Operating System", case=False, regex=False)
        .astype("boolean")
    )
    df = pd.DataFrame(
        {
            "sha256": df["sha256"].astype("string").str.upper(),
            "nsrl_application_type": application_type,
            "nsrl_is_os_component": is_os_component,
        },
        index=df.index,
    )

    cache = df.set_index("sha256")
    df.attrs["_chronosift_lookup_df"] = cache.loc[:, ["nsrl_application_type", "nsrl_is_os_component"]]
    df.attrs["_chronosift_lookup_application_type"] = cache["nsrl_application_type"].to_dict()
    df.attrs["_chronosift_lookup_is_os_component"] = (
        cache["nsrl_is_os_component"].astype("boolean").fillna(False).astype(bool).to_dict()
    )
    return df


def _make_nsrl_cache_descriptor(parquet_path: str) -> pd.DataFrame:
    """Create a lightweight NSRL cache descriptor without materialising the parquet."""
    df = pd.DataFrame()
    df.attrs["_chronosift_nsrl_parquet_path"] = str(parquet_path)
    return df


def _ensure_duckdb_nsrl_lookup(parquet_path: str) -> str:
    con = _get_duckdb_connection()
    view_name = "_chronosift_nsrl_lookup"

    if ChronoSiftEngine._duckdb_nsrl_view_path == str(parquet_path):
        return view_name

    available = set(_duckdb_dataset_columns(parquet_path))
    if "sha256" not in available:
        raise ValueError(f"NSRL parquet missing required column: sha256 ({parquet_path})")

    if "nsrl_application_type" in available:
        app_expr = "nsrl_application_type"
    elif "nsrl_application_types" in available:
        app_expr = "nsrl_application_types"
    else:
        raise ValueError(
            f"NSRL parquet missing required application type column "
            f"(expected nsrl_application_type or nsrl_application_types): {parquet_path}"
        )

    if "nsrl_is_os_component" in available:
        os_expr = (
            f"COALESCE(nsrl_is_os_component, POSITION('Operating System' IN {app_expr}) > 0)"
        )
    else:
        os_expr = f"(POSITION('Operating System' IN {app_expr}) > 0)"

    parquet_sql = str(parquet_path).replace("'", "''")
    sql = f"""
        CREATE OR REPLACE TEMP VIEW {view_name} AS
        SELECT
            sha256,
            {app_expr} AS nsrl_application_type,
            {os_expr} AS nsrl_is_os_component
        FROM read_parquet('{parquet_sql}')
    """
    con.execute(sql)
    ChronoSiftEngine._duckdb_nsrl_view_path = str(parquet_path)
    return view_name

def _duckdb_lookup_nsrl_hashes(parquet_path: str, hashes: Iterable[str]) -> pd.DataFrame:
    """Resolve a distinct set of SHA-256 values against the NSRL parquet via DuckDB."""
    values = [str(x).upper() for x in hashes if pd.notna(x) and str(x).strip()]
    if not values:
        return pd.DataFrame(columns=["sha256", "nsrl_application_type", "nsrl_is_os_component"])

    con = _get_duckdb_connection()
    view_name = _ensure_duckdb_nsrl_lookup(parquet_path)
    unique_sha = pd.Series(pd.unique(pd.Series(values, dtype="string")), dtype="string")
    workload_df = pd.DataFrame({"sha256": unique_sha})
    rel_name = "chronosift_nsrl_workload_hashes"
    con.register(rel_name, workload_df)
    try:
        df = con.execute(
            f"""
            SELECT
                w.sha256,
                n.nsrl_application_type,
                COALESCE(n.nsrl_is_os_component, FALSE) AS nsrl_is_os_component
            FROM {rel_name} AS w
            LEFT JOIN {view_name} AS n
              ON n.sha256 = w.sha256
            """
        ).fetch_df()
    finally:
        try:
            con.unregister(rel_name)
        except Exception:
            pass

    if len(df) > 0:
        application_type = (
            df["nsrl_application_type"].astype("string")
            if "nsrl_application_type" in df.columns
            else pd.Series(pd.NA, index=df.index, dtype="string")
        )
        is_os_component = (
            df["nsrl_is_os_component"].astype("boolean")
            if "nsrl_is_os_component" in df.columns
            else pd.Series(False, index=df.index, dtype="boolean")
        )
        df = pd.DataFrame(
            {
                "sha256": df["sha256"].astype("string").str.upper(),
                "nsrl_application_type": application_type,
                "nsrl_is_os_component": is_os_component,
            },
            index=df.index,
        )
    return df


class ChronoSiftEngine:
    _dataset_columns_cache: ClassVar[Dict[Tuple[str, Tuple[Any, ...]], List[str]]] = {}
    _duckdb_conn: ClassVar[Any] = None
    _duckdb_nsrl_view_path: ClassVar[Optional[str]] = None
    _hash_enrichment_cache: ClassVar[Dict[Tuple[str, str, int, int], pd.DataFrame]] = {}

    def __init__(self, rules_doc: Dict[str, Any], weights_doc: Dict[str, Any], yara_metadata_path: Optional[str] = None):
        self.rules_doc = rules_doc
        self.weights_doc = weights_doc

        self.max_event_score: float = float(weights_doc.get("max_event_score", 50))
        self.weights: Dict[str, float] = {
           str(k).strip().lower(): float(v)
           for k, v in (weights_doc.get("weights", {}) or {}).items()
           }

        # YAML sections
        self.normalisation = rules_doc.get("normalisation", []) or []
        self.rules: List[Rule] = self._parse_rules(rules_doc.get("rules", []) or [])
        self.temporal_rules: List[TemporalRule] = self._parse_temporal_rules(rules_doc.get("temporal_rules", []) or [])
        self.engine_cfg: Dict[str, Any] = rules_doc.get("engine_config", {}) or {}
        self.schema_aliases: Dict[str, Tuple[str, ...]] = _merge_schema_aliases(
            (self.engine_cfg.get("schema_aliases", {}) or {})
        )
        # Vocabularies and policy thresholds live in config so scenario-specific
        # ontology can evolve without changing the sparse/stateful engine code.
        self.path_taxonomy_cfg: Dict[str, Tuple[str, ...]] = _merge_string_tuple_config(
            DEFAULT_PATH_TAXONOMY,
            (self.engine_cfg.get("path_taxonomy", {}) or {}),
        )
        self.detection_vocabulary_cfg: Dict[str, Tuple[str, ...]] = _merge_string_tuple_config(
            DEFAULT_DETECTION_VOCABULARY,
            (self.engine_cfg.get("detection_vocabulary", {}) or {}),
        )
        self.detection_event_ids_cfg: Dict[str, Tuple[str, ...]] = _merge_string_tuple_config(
            DEFAULT_DETECTION_EVENT_IDS,
            (self.engine_cfg.get("detection_event_ids", {}) or {}),
        )
        self.detection_thresholds_cfg: Dict[str, Any] = _merge_generic_config(
            DEFAULT_DETECTION_THRESHOLDS,
            (self.engine_cfg.get("detection_thresholds", {}) or {}),
        )
        self.trust_dampening_cfg: Dict[str, Any] = self.engine_cfg.get("trust_dampening", {}) or {}
        self.referenced_file_cfg: Dict[str, Any] = self.engine_cfg.get("referenced_file_hit_propagation", {}) or {}
        self.canonical_auth_cfg: Dict[str, Any] = self.engine_cfg.get("canonical_auth_signals", {}) or {}
        temporal_policy_cfg: Dict[str, Any] = self.engine_cfg.get("temporal_signal_policy", {}) or {}
        default_ineligible = {
            "referenced_file_yara_hit",
            "referenced_file_av_hit",
            "referenced_file_luhn_hit",
            "quiet_time_event",
            "hour_rarity",
            "impossible_travel",
            "user_changed_private_ip",
            "user_crossed_private_subnet",
            "user_private_to_public_ip",
            "user_public_to_private_ip",
        }
        configured_ineligible = {
            str(x).strip().lower()
            for x in (temporal_policy_cfg.get("ineligible_signals") or [])
            if str(x).strip()
        }
        self.temporal_ineligible_signals: Set[str] = default_ineligible | configured_ineligible

        # Lookup caches — populated lazily by _detection_terms / _detection_event_ids
        self._detection_terms_cache: Dict[str, Tuple[str, ...]] = {}
        self._detection_event_ids_cache: Dict[str, frozenset] = {}

        # Profiling config
        self.profiling_cfg = {
            **((self.engine_cfg.get("profiling", {}) or {})),
            **(((rules_doc.get("profiling", {}) or {}).get("hour_of_week", {}) or {})),
        }
        self.profile_multipliers: List[ProfileMultiplier] = self._parse_profile_multipliers(
            rules_doc.get("profile_multipliers", []) or []
        )
        self.rule_emit_signals: Dict[str, List[str]] = {
            r.rule_id: [str(es.name).strip() for es in r.emit_signals if str(es.name).strip()]
            for r in self.rules
        }
        self.temporal_emit_signals: Dict[str, List[str]] = {
            tr.rule_id: [str(es.name).strip() for es in tr.emit_signals if str(es.name).strip()]
            for tr in self.temporal_rules
        }
        self.profile_multiplier_ids: Set[str] = {
            str(pm.mid).strip() for pm in self.profile_multipliers if str(pm.mid).strip()
        }

        # Impossible travel configuration (optional).
        # Uses GeoLite2 lat/long and authentication success signals to detect
        # physically implausible location changes for the same user.
        self.impossible_travel_cfg: Dict[str, Any] = rules_doc.get("impossible_travel", {}) or {}

        # Private/public continuity configuration (optional).
        self.private_ip_continuity_cfg: Dict[str, Any] = rules_doc.get("private_ip_continuity", {}) or {}

        # Required columns for stable evaluation across datasets
        self.required_fields: Set[str] = self._collect_required_fields()

        # YARA Forge metadata index — maps rule names to forensic categories
        # and quality scores.  Required since v2.31.  Loaded lazily from the
        # .yar file path specified in engine_config.yara_forge_metadata_path
        # or the constructor argument.
        self._yara_metadata_index: Optional[Dict[str, YaraRuleMeta]] = None
        _yara_cfg_path = (self.engine_cfg.get("yara_forge_metadata_path") or "").strip()
        self._yara_metadata_path: Optional[str] = yara_metadata_path or (_yara_cfg_path if _yara_cfg_path else None)
        if not self._yara_metadata_path:
            raise ValueError(
                "YARA Forge metadata path is required since v2.31. "
                "Provide yara_metadata_path to the constructor or set "
                "engine_config.yara_forge_metadata_path in your rules YAML."
            )

    @property
    def yara_metadata_index(self) -> Dict[str, YaraRuleMeta]:
        """Lazily load the YARA Forge metadata index on first access."""
        if self._yara_metadata_index is None:
            if self._yara_metadata_path and os.path.isfile(self._yara_metadata_path):
                try:
                    self._yara_metadata_index = parse_yara_forge_metadata(self._yara_metadata_path)
                except Exception:
                    logger.warning("Failed to parse YARA Forge metadata from %s; falling back to undifferentiated scoring", self._yara_metadata_path)
                    self._yara_metadata_index = {}
            else:
                self._yara_metadata_index = {}
        return self._yara_metadata_index

    @classmethod
    def from_yaml(cls, rules_path: str, weights_path: str, yara_metadata_path: Optional[str] = None) -> "ChronoSiftEngine":
        with open(rules_path, "r", encoding="utf-8") as f:
            rules_doc = yaml.safe_load(f) or {}
        with open(weights_path, "r", encoding="utf-8") as f:
            weights_doc = yaml.safe_load(f) or {}
        # Optional configuration hygiene checks.
        cfg_val = (rules_doc or {}).get("engine_config", {}).get("config_validation", {}) or {}
        if bool(cfg_val.get("enabled", False)):
            _validate_signal_weight_alignment(rules_doc, weights_doc, strict=bool(cfg_val.get("strict", False)))
        return cls(rules_doc, weights_doc, yara_metadata_path=yara_metadata_path)

    def _taxonomy_patterns(self, key: str) -> Tuple[str, ...]:
        return tuple(self.path_taxonomy_cfg.get(key, ()) or ())

    def _detection_terms(self, key: str) -> Tuple[str, ...]:
        try:
            return self._detection_terms_cache[key]
        except KeyError:
            val = tuple(self.detection_vocabulary_cfg.get(key, ()) or ())
            self._detection_terms_cache[key] = val
            return val

    def _detection_event_ids(self, key: str) -> frozenset:
        try:
            return self._detection_event_ids_cache[key]
        except KeyError:
            val = frozenset(
                str(v).strip()
                for v in (self.detection_event_ids_cfg.get(key, ()) or ())
                if str(v).strip()
            )
            self._detection_event_ids_cache[key] = val
            return val

    def _path_matches_taxonomy(self, path: Any, taxonomy_key: str) -> bool:
        s = _safe_str(path).strip().lower().replace("\\", "/")
        if not s:
            return False
        return any(tok.replace("\\", "/") in s for tok in self._taxonomy_patterns(taxonomy_key))

    def _path_extension_in_vocab(self, path: Any, vocab_key: str) -> bool:
        s = _safe_str(path).strip().lower().replace("\\", "/")
        if not s:
            return False
        _, ext = os.path.splitext(s)
        return ext in set(self._detection_terms(vocab_key))

    def _looks_like_web_root_path(self, path: Any) -> bool:
        return self._path_matches_taxonomy(path, "web_root_patterns")

    def _looks_like_sensitive_path(self, path: Any) -> bool:
        return self._path_matches_taxonomy(path, "sensitive_path_patterns")

    def _looks_like_database_dump(self, path: Any, message: Any = None) -> bool:
        s = _safe_str(path).strip().lower()
        if s:
            _, ext = os.path.splitext(s.replace("\\", "/"))
            if ext in set(self._detection_terms("database_dump_extensions")):
                return True
            basename = os.path.basename(s)
            if any(tok in basename for tok in self._taxonomy_patterns("database_dump_patterns")):
                return True
        msg = _safe_str(message).strip().lower()
        return bool(msg and any(tok in msg for tok in self._taxonomy_patterns("database_dump_patterns")))

    def _looks_like_cron_path(self, path: Any) -> bool:
        return self._path_matches_taxonomy(path, "cron_path_patterns")

    def _looks_like_service_config_path(self, path: Any) -> bool:
        return self._path_matches_taxonomy(path, "service_config_patterns")

    def _looks_like_firewall_path(self, path: Any) -> bool:
        return self._path_matches_taxonomy(path, "firewall_path_patterns")

    def _looks_like_group_policy_path(self, path: Any) -> bool:
        return self._path_matches_taxonomy(path, "group_policy_path_patterns")

    def _looks_like_winlogon_path(self, path: Any) -> bool:
        return self._path_matches_taxonomy(path, "winlogon_path_patterns")

    def _looks_like_com_hijack_path(self, path: Any) -> bool:
        return self._path_matches_taxonomy(path, "com_hijack_path_patterns")

    def _looks_like_authorized_keys_path(self, path: Any) -> bool:
        s = _safe_str(path).strip().lower().replace("\\", "/")
        return bool(s and s.endswith("/authorized_keys"))

    def _looks_like_systemd_unit_path(self, path: Any) -> bool:
        s = _safe_str(path).strip().lower().replace("\\", "/")
        if not s or not self._path_matches_taxonomy(s, "service_config_patterns"):
            return False
        _, ext = os.path.splitext(s)
        return ext in set(self._detection_terms("systemd_unit_extensions"))

    def _looks_like_password_store_path(self, path: Any) -> bool:
        s = _safe_str(path).strip().lower().replace("\\", "/")
        if not s:
            return False
        return any(tok in s for tok in self._detection_terms("password_store_path_tokens"))

    def _extract_artifact_labels(self, values: Iterable[Any], tokens: Iterable[str]) -> Set[str]:
        labels: Set[str] = set()
        normalised_tokens = tuple(
            _safe_str(tok).strip().lower().replace("\\", "/")
            for tok in tokens
            if _safe_str(tok).strip()
        )
        for value in values:
            s = _safe_str(value).strip().lower().replace("\\ ", " ").replace("\\", "/")
            if not s:
                continue
            basename = os.path.basename(s)
            for tok in normalised_tokens:
                if tok and tok in s:
                    labels.add(os.path.basename(tok) if "/" in tok else tok)
            if basename and basename in normalised_tokens:
                labels.add(basename)
        return labels

    def _extract_password_store_labels(self, *values: Any) -> Set[str]:
        return self._extract_artifact_labels(values, self._detection_terms("password_store_message_tokens"))

    def _extract_credential_dump_labels(self, *values: Any) -> Set[str]:
        return self._extract_artifact_labels(
            values,
            (
                "lsass.dmp",
                "lsass",
                "ntds.dit",
                "sam.save",
                "security.save",
                "system.save",
                "comsvcs.dll",
                "minidump",
                "procdump",
                "sekurlsa",
            ),
        )

    def _looks_like_web_log_parser(self, parser: Any) -> bool:
        s = _safe_str(parser).strip().lower()
        if not s:
            return False
        return any(tok in s for tok in self._detection_terms("web_log_parser_tokens"))

    def _materialise_normalised_web_features(self, df: pd.DataFrame) -> None:
        """Materialise typed HTTP features once for detectors and sidecars."""
        nrows = len(df)
        parser_vals = _column_values_or_none(df, "parser")
        message_vals = _column_values_or_none(df, "message")
        request_vals = _column_values_or_none(df, "http_request")
        url_vals = _column_values_or_none(df, "url")
        header_vals = _column_values_or_none(df, "http_headers")
        status_vals = _column_values_or_none(df, "http_response_code")
        response_bytes_vals = _column_values_or_none(df, "http_response_bytes")
        actor_ip_vals = _column_values_or_none(df, "actor_ip")
        src_ip_vals = _column_values_or_none(df, "src_ip")
        ip_vals = _column_values_or_none(df, "ip_address")
        ua_vals = _column_values_or_none(df, "http_request_user_agent")
        referer_vals = _column_values_or_none(df, "http_request_referer")
        body_vals = _column_values_or_none(df, "http_request_body")
        disposition_vals = _column_values_or_none(df, "http_content_disposition")
        upload_filename_vals = _column_values_or_none(df, "http_upload_filename")
        upload_content_type_vals = _column_values_or_none(df, "http_upload_content_type")
        upload_sha256_vals = _column_values_or_none(df, "http_upload_sha256")
        request_length_vals = _column_values_or_none(df, "http_request_content_length")
        web_log_parser_tokens = self._detection_terms("web_log_parser_tokens")

        # Vectorised prefilter. A forensic partition is overwhelmingly filestat
        # and registry rows, so interpreting every row in Python to discover it
        # is not a web event dominated this pass. The candidate test below is
        # exactly the condition the row loop used to apply one row at a time.
        request_text = _normalised_text_array(df, "http_request")
        url_text = _normalised_text_array(df, "url")
        parser_lower = _normalised_text_array(df, "parser", lower=True)
        web_candidates = (request_text != "") | (url_text != "")
        if web_log_parser_tokens:
            web_candidates |= _text_array_contains_any(parser_lower, web_log_parser_tokens)
        candidate_rows = np.flatnonzero(web_candidates)

        # Columns are always created, even when no row qualifies, so the
        # sidecar schema stays identical across partitions. Object arrays are
        # allocated at C level rather than as Python lists of pd.NA.
        string_field_names = (
            "chronosift_web_method",
            "chronosift_web_request_target",
            "chronosift_web_endpoint",
            "chronosift_web_query",
            "chronosift_web_host",
            "chronosift_web_source_ip",
            "chronosift_web_user_agent",
            "chronosift_web_referer",
            "chronosift_web_content_type",
            "chronosift_web_upload_name",
            "chronosift_web_upload_names",
            "chronosift_web_upload_hashes",
            "chronosift_web_upload_content_types",
            "chronosift_web_upload_outcome",
            "chronosift_web_attack_indicators",
            "chronosift_web_outcome",
            "chronosift_web_file_hit_types",
            "chronosift_web_file_categories",
            "chronosift_web_file_rules",
            "chronosift_web_file_families",
            "chronosift_attack_techniques",
        )
        integer_field_names = (
            "chronosift_web_status_code",
            "chronosift_web_response_bytes",
            "chronosift_web_upload_count",
            "chronosift_web_request_body_bytes",
        )

        if candidate_rows.size == 0:
            # Nothing to interpret. Broadcasting the NA scalar lets pandas build
            # each column directly instead of validating a per-row object array,
            # which is an order of magnitude cheaper on a partition that holds
            # no web records at all — the common case in a forensic timeline.
            for name in string_field_names:
                df[name] = pd.Series(pd.NA, index=df.index, dtype="string")
            for name in integer_field_names:
                df[name] = pd.Series(pd.NA, index=df.index, dtype="Int64")
            df["chronosift_web_is_event"] = pd.Series(False, index=df.index, dtype="boolean")
            return

        string_fields: Dict[str, np.ndarray] = {
            name: np.full(nrows, None, dtype=object) for name in string_field_names
        }
        status_codes = np.full(nrows, None, dtype=object)
        response_sizes = np.full(nrows, None, dtype=object)
        upload_counts = np.full(nrows, None, dtype=object)
        request_body_sizes = np.full(nrows, None, dtype=object)
        is_web_event = np.zeros(nrows, dtype=bool)

        for row_i in candidate_rows:
            request = request_text[row_i]
            url = url_text[row_i]
            semantics = _extract_http_request_semantics(message_vals[row_i], request, url)
            request_target = _safe_str(semantics.get("path")).strip()
            if not request_target:
                continue
            is_web_event[row_i] = True
            method = _safe_str(semantics.get("method")).strip().upper()
            endpoint = _canonical_web_request_path(request_target)
            try:
                parsed_target = urlparse(
                    request_target if "://" in request_target else f"http://localhost{request_target if request_target.startswith('/') else '/' + request_target}"
                )
                query = parsed_target.query
            except Exception:
                query = request_target.split("?", 1)[1].split("#", 1)[0] if "?" in request_target else ""
            decoded_query = _decode_http_detection_text_from_string(query) if query else ""
            content_type = _http_header_value(header_vals[row_i], "content-type")
            upload_names: List[str] = []
            upload_hashes: List[str] = []
            upload_content_types: List[str] = []
            if method in {"POST", "PUT", "PATCH"}:
                structured_names = (
                    *_extract_structured_upload_names(upload_filename_vals[row_i]),
                    *_extract_http_upload_names(
                        disposition_vals[row_i], body_vals[row_i],
                    ),
                )
                upload_endpoint = any(
                    token in endpoint
                    for token in self._detection_terms("web_upload_endpoint_tokens")
                )
                legacy_names = ()
                if (
                    structured_names
                    or method == "PUT"
                    or upload_endpoint
                    or (content_type and "multipart/form-data" in content_type.lower())
                ):
                    legacy_names = _extract_http_upload_names(
                        message_vals[row_i], request, url, request_target
                    )
                for candidate in (*structured_names, *legacy_names):
                    if candidate not in upload_names:
                        upload_names.append(candidate)
                for source in (upload_sha256_vals[row_i], body_vals[row_i]):
                    for candidate in _extract_upload_sha256_values(source):
                        if candidate not in upload_hashes:
                            upload_hashes.append(candidate)
                for text in _bounded_metadata_strings(upload_content_type_vals[row_i]):
                    content_type_value = text.strip().lower()
                    if content_type_value and content_type_value not in upload_content_types:
                        upload_content_types.append(content_type_value)
                for text in _bounded_metadata_strings(body_vals[row_i]):
                    for match in _MULTIPART_CONTENT_TYPE_RE.finditer(text):
                        content_type_value = match.group(1).strip().lower()
                        if content_type_value and content_type_value not in upload_content_types:
                            upload_content_types.append(content_type_value)
            upload_name = upload_names[0] if upload_names else ""
            status_code = _normalise_integral_metadata_value(status_vals[row_i])
            request_body_size = _normalise_integral_metadata_value(request_length_vals[row_i])
            if request_body_size is None:
                request_body_size = _normalise_integral_metadata_value(
                    _http_header_value(header_vals[row_i], "content-length")
                )
            upload_semantics = bool(
                method == "PUT" or upload_names or upload_hashes
                or (content_type and "multipart/form-data" in content_type.lower())
            )
            upload_outcome = ""
            if upload_semantics:
                if status_code is None:
                    upload_outcome = "unknown"
                elif 200 <= status_code < 300:
                    upload_outcome = "accepted"
                elif 300 <= status_code < 400:
                    upload_outcome = "redirected"
                else:
                    upload_outcome = "rejected"
            indicators = list(_http_attack_indicators(request_target))
            if upload_semantics:
                indicators.append("file_upload")
            if any(any(name.endswith(ext) for ext in self._detection_terms("web_script_extensions")) for name in upload_names):
                indicators.append("executable_upload")
            if any(name.count(".") >= 2 for name in upload_names):
                indicators.append("double_extension_upload")
            image_extensions = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg"}
            if len(upload_names) == 1 and len(upload_content_types) == 1 and any(
                os.path.splitext(name)[1].lower() in image_extensions
                and not any(content_type_value.startswith("image/") for content_type_value in upload_content_types)
                for name in upload_names
            ):
                indicators.append("upload_mime_extension_mismatch")
            if len(upload_names) == 1 and len(upload_content_types) == 1 and any(
                any(name.endswith(ext) for ext in self._detection_terms("web_script_extensions"))
                and any(content_type_value.startswith("image/") for content_type_value in upload_content_types)
                for name in upload_names
            ):
                indicators.append("upload_mime_extension_mismatch")
            indicators = list(dict.fromkeys(indicators))

            string_fields["chronosift_web_method"][row_i] = method or pd.NA
            string_fields["chronosift_web_request_target"][row_i] = request_target[:2000]
            string_fields["chronosift_web_endpoint"][row_i] = endpoint or pd.NA
            string_fields["chronosift_web_query"][row_i] = decoded_query[:2000] or pd.NA
            string_fields["chronosift_web_host"][row_i] = _web_request_host(url or request_target, header_vals[row_i]) or pd.NA
            string_fields["chronosift_web_source_ip"][row_i] = (
                _safe_str(actor_ip_vals[row_i]).strip()
                or _safe_str(src_ip_vals[row_i]).strip()
                or _safe_str(ip_vals[row_i]).strip()
                or pd.NA
            )
            string_fields["chronosift_web_user_agent"][row_i] = _safe_str(ua_vals[row_i]).strip()[:500] or pd.NA
            string_fields["chronosift_web_referer"][row_i] = _safe_str(referer_vals[row_i]).strip()[:1000] or pd.NA
            string_fields["chronosift_web_content_type"][row_i] = content_type[:240] if content_type else pd.NA
            string_fields["chronosift_web_upload_name"][row_i] = upload_name[:500] or pd.NA
            string_fields["chronosift_web_upload_names"][row_i] = "|".join(upload_names)[:2000] or pd.NA
            string_fields["chronosift_web_upload_hashes"][row_i] = "|".join(upload_hashes) or pd.NA
            string_fields["chronosift_web_upload_content_types"][row_i] = "|".join(upload_content_types)[:1000] or pd.NA
            string_fields["chronosift_web_upload_outcome"][row_i] = upload_outcome or pd.NA
            string_fields["chronosift_web_attack_indicators"][row_i] = "|".join(indicators) or pd.NA
            string_fields["chronosift_web_outcome"][row_i] = "attempt" if indicators else "observed"
            status_codes[row_i] = status_code
            response_sizes[row_i] = _normalise_integral_metadata_value(response_bytes_vals[row_i])
            upload_counts[row_i] = len(upload_names) if upload_semantics else pd.NA
            request_body_sizes[row_i] = request_body_size

        for column, values in string_fields.items():
            df[column] = pd.array(values, dtype="string")
        df["chronosift_web_status_code"] = pd.array(status_codes, dtype="Int64")
        df["chronosift_web_response_bytes"] = pd.array(response_sizes, dtype="Int64")
        df["chronosift_web_upload_count"] = pd.array(upload_counts, dtype="Int64")
        df["chronosift_web_request_body_bytes"] = pd.array(request_body_sizes, dtype="Int64")
        df["chronosift_web_is_event"] = pd.array(is_web_event, dtype="boolean")

    _CHAIN_OPERATORS_RE = re.compile(r"&&|\|\||;")

    def _looks_like_benign_admin_query_command(self, value: Any) -> bool:
        s = _safe_str(value).strip().lower()
        if not s:
            return False
        # Reject commands that chain multiple independent statements — only the
        # first may be benign while later segments carry the real payload.
        # Single pipe (|) is allowed since piped commands (e.g. ps aux | grep)
        # are common benign admin patterns and the full pipeline is visible.
        if self._CHAIN_OPERATORS_RE.search(s):
            return False
        if "net user " in s and not any(
            tok in s
            for tok in (
                " /add",
                " /delete",
                " /active:",
                " /expires:",
                " /passwordchg:",
                " /passwordreq:",
                " /times:",
                " /comment:",
                " /fullname:",
                " /homedir:",
                " /scriptpath:",
                " /usercomment:",
            )
        ):
            return True
        if "net localgroup" in s and not any(tok in s for tok in (" /add", " /delete")):
            return True
        if "cmd.exe /c klist" in s and not any(tok in s for tok in (" purge", " add_bind", " kcd_cache")):
            return True
        benign_patterns = (
            "schtasks /query",
            "schtasks.exe /query",
            "wmic ",
            " reg query",
            "reg query ",
            "sc query",
            "sc qc",
            "sc queryex",
            "wevtutil qe",
            "get-mppreference",
            "get-netfirewallprofile",
            "get-service",
            "get-scheduledtask",
            "get-nettcpconnection",
            "get-process",
            "get-ciminstance",
            "get-winevent",
            "test-netconnection",
            "netsh advfirewall show",
            "tasklist",
            "netstat ",
            "ps aux | grep",
            "ps -ef | grep",
            "ipconfig ",
            "route print",
            "arp -a",
            "net accounts",
            "gpresult /r",
            "whoami /groups",
            "whoami /priv",
            "cmd.exe /c klist",
            "get-computerinfo",
            "get-localuser",
            "get-localgroup",
            "get-hotfix",
            "get-netipaddress",
            "get-netroute",
            "get-dnsclientcache",
            "get-netneighbor",
            "netsh interface ip show",
            "query user",
            "query session",
            "qwinsta",
            "quser",
            "auditpol /get",
            "net user ",
            "net localgroup",
            "uname -a",
            "uname -r",
            "uname -s",
            "hostnamectl status",
            "cat /etc/os-release",
            "lsb_release -a",
            "ifconfig -a",
        )
        if not any(tok in s for tok in benign_patterns):
            return False
        inherently_read_only_patterns = (
            "get-scheduledtask",
            "get-nettcpconnection",
            "get-process",
            "get-ciminstance",
            "get-winevent",
            "test-netconnection",
            "tasklist",
            "netstat ",
            "ps aux | grep",
            "ps -ef | grep",
            "ipconfig ",
            "route print",
            "arp -a",
            "query user",
            "query session",
            "qwinsta",
            "quser",
            "auditpol /get",
            "net user ",
            "net localgroup",
            "net accounts",
            "gpresult /r",
            "whoami /groups",
            "whoami /priv",
            "get-computerinfo",
            "get-localuser",
            "get-localgroup",
            "get-hotfix",
            "get-netipaddress",
            "get-netroute",
            "get-dnsclientcache",
            "get-netneighbor",
            "netsh interface ip show",
            "uname -a",
            "uname -r",
            "uname -s",
            "hostnamectl status",
            "cat /etc/os-release",
            "lsb_release -a",
            "ifconfig -a",
        )
        if any(tok in s for tok in inherently_read_only_patterns):
            return True
        query_qualifiers = (
            "/query",
            " query",
            " list",
            " get ",
            " get-",
            " qe ",
            "enum ",
            " /fo ",
            " /v",
            " show ",
            " qc ",
            " status",
            " test-netconnection",
            " | grep",
            " /svc",
            " -an",
            " -ano",
            " -a ",
        )
        return any(tok in s for tok in query_qualifiers)

    def _looks_like_benign_backup_archive_command(self, value: Any) -> bool:
        s = _safe_str(value).strip().lower().replace("\\", "/")
        if not s:
            return False
        archive_tool_hit = any(f"{name} " in s for name in _EXEC_ARCHIVE_NAMES)
        if not archive_tool_hit:
            return False
        backup_target_hit = any(tok in s for tok in ("/var/backups/", "/backup/", " backup", ".bak", ".tgz", ".tar.gz", ".zip"))
        sensitive_token_hit = any(tok in s for tok in (
            "login data",
            "logins.json",
            "key4.db",
            ".kdbx",
            "lsass",
            "ntds.dit",
            "sam.save",
            "web.config",
        ))
        return backup_target_hit and not sensitive_token_hit

    def _looks_like_read_only_discovery_command(self, value: Any) -> bool:
        s = _safe_str(value).strip().lower()
        if not s:
            return False
        explicit_remote_patterns = (
            "net view",
            "nslookup ",
            "resolve-dnsname",
            "nltest /dclist",
            "nltest.exe /dclist",
            "ping -n 1",
            "ping -c 1",
        )
        return any(tok in s for tok in explicit_remote_patterns)

    def _looks_like_log_or_history_path(self, path: Any) -> bool:
        s = _safe_str(path).strip().lower().replace("\\", "/")
        if not s:
            return False
        return any(tok.replace("\\", "/") in s for tok in self._detection_terms("log_artifact_tokens"))

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------


    def _apply_hash_enrichment_csv(
        self,
        df: pd.DataFrame,
        csv_path: str,
        hash_col: str = "sha256_hash",
        csv_hash_col: str = "sha256",
    ) -> pd.DataFrame:
        """Join a hash-keyed enrichment CSV onto the timeline while preserving the index."""
        out = df
        if hash_col not in out.columns:
            return out

        enrich = _load_hash_enrichment_frame(csv_path, csv_hash_col=csv_hash_col)
        if len(enrich) == 0:
            return out

        lookup_hash = _normalise_hash_series(out[hash_col])
        matched = _reindex_lookup_frame_for_hashes(lookup_hash, enrich)
        for col in matched.columns:
            matched_col = matched[col]
            if col in out.columns:
                out[col] = matched_col.combine_first(out[col])
            else:
                out[col] = matched_col
        return out

    def _atomic_required_columns(self) -> List[str]:
        """
        Return the minimal column subset needed for the atomic pass.
        This includes:
          - all rule/normalisation required fields
          - enrichment inputs
          - fields required by sparse AV/YARA injection
          - fields needed later for candidate selection
        """
        # This method is part of the parquet/DuckDB optimisation contract. Any
        # new field added to atomic logic should be reflected here so projected
        # reads stay minimal instead of silently widening to full-row loads.
        cols: Set[str] = set(self.required_fields)

        # Core enrichment and injection inputs
        cols.update({
            CHRONOSIFT_ROW_ID_COLUMN,
            "sha256_hash",
            "filename",
            "file_path",
            "image_path",
            "message",
            "parser",
            "yara_match",
            "ip_address",
            "username",
            "actor_user",
            "actor_principal",
            "command",
            "command_line",
            "xml_string",
            "strings",
            "url",
            "http_request",
            "http_headers",
            "http_request_referer",
            "http_request_user_agent",
            "http_request_body",
            "http_content_disposition",
            "http_upload_filename",
            "http_upload_content_type",
            "http_upload_sha256",
            "http_request_content_length",
            "text",
        })

        # Profiling support
        if self.profiling_cfg:
            cols.update({"parser", "nsrl_is_os_component", "nsrl_application_type", "filename"})

        # Candidate window actor columns
        cols.update({"actor_principal", "actor_user", "ip_address"})

        if self.impossible_travel_cfg:
            for k in (self.impossible_travel_cfg.get("key_by") or ["actor_principal"]):
                ks = str(k).strip()
                if ks:
                    cols.add(ks)
        for canonical, aliases in self.schema_aliases.items():
            if canonical in cols:
                cols.update(a for a in aliases if a)

        return sorted(c for c in cols if c)

    def _apply_nsrl_enrichment_from_cache(
        self,
        df: pd.DataFrame,
        nsrl_cache_df: pd.DataFrame,
        hash_col: str = "sha256_hash",
    ) -> pd.DataFrame:
        """Apply NSRL enrichment from a prebuilt Parquet cache."""
        out = df
        if hash_col not in out.columns:
            return out
        if nsrl_cache_df is None:
            return out

        sha = _normalise_hash_series(out[hash_col])
        lookup_mask = _nsrl_lookup_candidate_mask(out, hash_col=hash_col)
        parquet_path = nsrl_cache_df.attrs.get("_chronosift_nsrl_parquet_path")

        for col in ("nsrl_application_type", "nsrl_is_os_component"):
            if col in out.columns:
                out = out.drop(columns=[col])

        app_series = pd.Series(pd.NA, index=out.index, dtype="string")
        os_series = pd.Series(False, index=out.index, dtype=bool)

        if not lookup_mask.any():
            out["nsrl_application_type"] = app_series
            out["nsrl_is_os_component"] = os_series
            return out

        lookup_sha = sha[lookup_mask].dropna().drop_duplicates()
        if parquet_path:
            joined = _duckdb_lookup_nsrl_hashes(str(parquet_path), lookup_sha.tolist())
            joined = _prepare_nsrl_cache_df(joined)
            lookup_df = joined.attrs.get("_chronosift_lookup_df")
        else:
            if len(nsrl_cache_df) == 0:
                out["nsrl_application_type"] = app_series
                out["nsrl_is_os_component"] = os_series
                return out
            lookup_df = nsrl_cache_df.attrs.get("_chronosift_lookup_df")
            if lookup_df is None:
                nsrl_cache_df = _prepare_nsrl_cache_df(nsrl_cache_df)
                lookup_df = nsrl_cache_df.attrs.get("_chronosift_lookup_df")

        masked_sha = sha[lookup_mask]
        lookup_positions = np.flatnonzero(lookup_mask.to_numpy(dtype=bool, copy=False))
        aligned = _reindex_lookup_frame_for_hashes(
            masked_sha,
            lookup_df if lookup_df is not None else pd.DataFrame(columns=["nsrl_application_type", "nsrl_is_os_component"]),
            columns=("nsrl_application_type", "nsrl_is_os_component"),
        )
        app_series.iloc[lookup_positions] = aligned["nsrl_application_type"].astype("string").to_numpy(copy=False)
        os_series.iloc[lookup_positions] = aligned["nsrl_is_os_component"].astype("boolean").fillna(False).astype(bool).to_numpy(copy=False)

        out["nsrl_application_type"] = app_series
        out["nsrl_is_os_component"] = os_series
        return out

    def _extract_windows_auth_fields(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Materialise structured Windows auth/RDP fields from EVTX XML.

        This stage runs before normalisation so downstream canonical columns and
        rules can prefer event semantics over message matching. It is restricted
        to winevt*/winevtx* rows already projected into the atomic pass, so the
        Parquet/DuckDB read contract stays narrow.
        """
        out = df
        derived_fields = [
            "event_identifier",
            "logon_type",
            "client_address",
            "source_network_address",
            "rdp_client_address",
            "src_ip",
            "dst_ip",
            "auth_protocol",
            "auth_direction",
            "auth_outcome",
            "session_id",
            "logon_id",
            "workstation_name",
            "authentication_package",
            "logon_process",
            "provider_name",
            "event_channel",
            "target_user_name",
            "target_domain_name",
            "subject_user_name",
            "subject_domain_name",
            "group_name",
            "member_name",
            "share_name",
            "share_local_path",
            "relative_target_name",
            "rdp_session_name",
            "new_process_name",
            "parent_process_name",
            "command_line",
            "parent_command_line",
        ]
        out = _ensure_object_columns(out, ["parser", "xml_string", *derived_fields])

        parser_vals = out["parser"].astype("string").fillna("").str.lower()
        xml_vals = out["xml_string"].astype("string").fillna("")
        evtx_mask = parser_vals.str.startswith(("winevt", "winevtx")).to_numpy(dtype=bool, copy=False)
        xml_mask = xml_vals.ne("").to_numpy(dtype=bool, copy=False)
        target_mask = evtx_mask & xml_mask
        if not bool(target_mask.any()):
            return out

        target_pos = np.flatnonzero(target_mask)
        extracted = (
            out["xml_string"]
            .iloc[target_pos]
            .map(_extract_windows_event_values_from_evtx_xml)
        )
        extracted_df = pd.DataFrame(list(extracted), index=out.index[target_pos])
        if extracted_df.empty:
            return out

        for col in derived_fields:
            if col not in extracted_df.columns:
                continue
            target_values = extracted_df[col].astype("string")
            existing = out[col].iloc[target_pos].astype("string")
            missing = existing.fillna("").str.strip().eq("").to_numpy(dtype=bool, copy=False)
            if not bool(missing.any()):
                continue
            fill_pos = target_pos[np.flatnonzero(missing)]
            fill_values = target_values.iloc[np.flatnonzero(missing)].to_numpy(copy=False)
            col_loc = out.columns.get_loc(col)
            out.iloc[fill_pos, col_loc] = fill_values

        return out

    def _extract_ssh_auth_fields(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Materialise structured SSH auth fields from sshd/syslog messages.
        """
        out = df
        derived_fields = [
            "ssh_actor_user_auth",
            "ssh_actor_user_session",
            "ssh_auth_method",
            "src_ip",
            "dst_ip",
            "auth_protocol",
            "auth_direction",
            "auth_outcome",
            "session_id",
            "logon_id",
        ]
        out = _ensure_object_columns(out, ["message", "parser", *derived_fields])

        parser_vals = out["parser"].astype("string").fillna("").str.lower()
        message_vals = out["message"].astype("string").fillna("")
        target_mask = (
            parser_vals.isin(["systemd_journal", "syslog", "text/syslog_traditional"])
            | message_vals.str.contains("sshd", case=False, regex=False, na=False)
        ) & message_vals.ne("")
        if not bool(target_mask.any()):
            return out

        target_pos = np.flatnonzero(target_mask.to_numpy(dtype=bool, copy=False))
        extracted = out["message"].iloc[target_pos].map(_extract_ssh_auth_fields_from_message)
        extracted_df = pd.DataFrame(list(extracted), index=out.index[target_pos])
        if extracted_df.empty:
            return out

        for col in derived_fields:
            if col not in extracted_df.columns:
                continue
            target_values = extracted_df[col].astype("string")
            existing = out[col].iloc[target_pos].astype("string")
            missing = existing.fillna("").str.strip().eq("").to_numpy(dtype=bool, copy=False)
            if not bool(missing.any()):
                continue
            fill_pos = target_pos[np.flatnonzero(missing)]
            fill_values = target_values.iloc[np.flatnonzero(missing)].to_numpy(copy=False)
            col_loc = out.columns.get_loc(col)
            out.iloc[fill_pos, col_loc] = fill_values

        return out

    def _apply_schema_aliases(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Populate canonical columns from known schema aliases without widening
        rules to every source-specific field name.
        """
        out = df
        for canonical, aliases in self.schema_aliases.items():
            if not canonical:
                continue
            alias_fields = [a for a in aliases if a and a in out.columns]
            if canonical not in out.columns and not alias_fields:
                continue
            if canonical not in out.columns:
                out = _ensure_object_columns(out, [canonical])
                out[canonical] = _coalesce_first_meaningful(out, alias_fields)
                continue

            if not (
                pd.api.types.is_object_dtype(out[canonical].dtype)
                or pd.api.types.is_string_dtype(out[canonical].dtype)
            ):
                # Replace the whole column so pandas updates dtype before later
                # fill operations, rather than attempting an incompatible .loc
                # assignment into the existing numeric/boolean dtype.
                out[canonical] = out[canonical].astype("object")
            missing = out[canonical].astype("string").fillna("").str.strip().eq("")
            if not bool(missing.any()) or not alias_fields:
                continue
            filled = _coalesce_first_meaningful_for_mask(out, alias_fields, missing)
            out.loc[missing, canonical] = filled.to_numpy(copy=False)
        return out

    def _derive_pivot_destination_fields(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Build deterministic destination identity fields for pivot narratives.

        Temporal grouping needs a single stable destination key, but evidence
        should still preserve the underlying IP/FQDN/hostname components. The
        precedence is:
            destination IP -> FQDN -> hostname
        """
        out = df
        for col in ("destination_ip", "destination_fqdn", "destination_hostname", "pivot_dest_key"):
            if col not in out.columns:
                out[col] = None

        destination_specs = {
            "destination_ip": [f for f in ("destination_ip", "dst_ip", "dest_ip", "server_ip", "target_ip") if f in out.columns],
            "destination_fqdn": [f for f in ("destination_fqdn", "dest_fqdn", "target_fqdn", "fqdn", "server_name", "dns_name") if f in out.columns],
            "destination_hostname": [f for f in ("destination_hostname", "dest_hostname", "target_hostname", "hostname", "host_name", "computer_name", "workstation_name") if f in out.columns],
        }
        for canonical, source_fields in destination_specs.items():
            missing = out[canonical].astype("string").fillna("").str.strip().eq("")
            if not bool(missing.any()) or not source_fields:
                continue
            filled = _coalesce_first_meaningful_for_mask(out, source_fields, missing)
            out.loc[missing, canonical] = filled.to_numpy(copy=False)

        ip_vals = out["destination_ip"].astype("string").fillna("").str.strip()
        fqdn_vals = out["destination_fqdn"].astype("string").fillna("").str.strip()
        host_vals = out["destination_hostname"].astype("string").fillna("").str.strip()

        # Pre-filter: only call _normalise_ip_literal on non-empty rows
        ip_norm = pd.Series("", index=out.index, dtype="string")
        _ip_nonempty = ip_vals.ne("")
        if bool(_ip_nonempty.any()):
            ip_norm.loc[_ip_nonempty] = ip_vals.loc[_ip_nonempty].map(_normalise_ip_literal).fillna("").astype("string")
        fqdn_norm = fqdn_vals.mask(fqdn_vals.str.lower().isin(PLACEHOLDER_STRINGS), "").str.lower()
        host_norm = host_vals.mask(host_vals.str.lower().isin(PLACEHOLDER_STRINGS), "").str.lower()

        pivot = pd.Series("", index=out.index, dtype="string")
        has_ip = ip_norm.ne("")
        if bool(has_ip.any()):
            pivot.loc[has_ip] = "ip:" + ip_norm.loc[has_ip]
        remaining = pivot.eq("")
        has_fqdn = remaining & fqdn_norm.ne("")
        if bool(has_fqdn.any()):
            pivot.loc[has_fqdn] = "fqdn:" + fqdn_norm.loc[has_fqdn]
        remaining = pivot.eq("")
        has_host = remaining & host_norm.ne("")
        if bool(has_host.any()):
            pivot.loc[has_host] = "host:" + host_norm.loc[has_host]
        auth_protocol_vals = out["auth_protocol"].astype("string").fillna("").str.strip() if "auth_protocol" in out.columns else pd.Series("", index=out.index, dtype="string")
        auth_direction_vals = out["auth_direction"].astype("string").fillna("").str.strip() if "auth_direction" in out.columns else pd.Series("", index=out.index, dtype="string")
        event_id_vals = out["event_identifier"].astype("string").fillna("").str.strip() if "event_identifier" in out.columns else pd.Series("", index=out.index, dtype="string")
        logon_type_vals = out["logon_type"].astype("string").fillna("").str.strip() if "logon_type" in out.columns else pd.Series("", index=out.index, dtype="string")
        auth_like = auth_protocol_vals.ne("") | auth_direction_vals.ne("") | event_id_vals.ne("") | logon_type_vals.ne("")
        pivot = pivot.where(auth_like, "")
        out["pivot_dest_key"] = pivot.replace("", pd.NA).astype("string")
        return out

    def _apply_canonical_auth_signals_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
    ) -> None:
        """
        Inject protocol-agnostic auth signals for continuity and temporal logic.
        """
        cfg = self.canonical_auth_cfg or {}
        success_sources = [str(x).strip() for x in (cfg.get("success_sources") or ["auth_success_generic", "ssh_success", "rdp_success"]) if str(x).strip()]
        fail_sources = [str(x).strip() for x in (cfg.get("fail_sources") or ["auth_fail_generic", "ssh_fail", "rdp_fail"]) if str(x).strip()]
        success_target = str(cfg.get("success_target", "auth_success")).strip() or "auth_success"
        fail_target = str(cfg.get("fail_target", "auth_failure")).strip() or "auth_failure"
        nrows = len(df)
        auth_protocol_vals = _normalised_text_array(df, "auth_protocol", lower=True)
        auth_direction_vals = _normalised_text_array(df, "auth_direction", lower=True)
        auth_outcome_vals = _normalised_text_array(df, "auth_outcome", lower=True)
        logon_type_vals = _normalised_text_array(df, "logon_type")
        message_vals = _normalised_text_array(df, "message", lower=True)
        auth_pkg_vals = _normalised_text_array(df, "authentication_package", lower=True)

        # Pre-filter: only iterate rows with an auth outcome or existing auth signals.
        # Auth events are typically 0.1–5% of a forensic timeline.
        _success_keys_lower = tuple(s.lower() for s in success_sources)
        _fail_keys_lower = tuple(s.lower() for s in fail_sources)
        _has_outcome = np.isin(auth_outcome_vals, ("success", "failure"))
        _candidate_rows: List[int] = [int(_ri) for _ri in np.flatnonzero(_has_outcome)]
        # Also include rows that already carry auth-related signals from rule evaluation
        for _ri, _sigs in signal_map.items():
            if not (0 <= _ri < nrows) or _has_outcome[_ri]:
                continue
            if any(str(k).strip().lower() in _success_keys_lower or str(k).strip().lower() in _fail_keys_lower for k in _sigs):
                _candidate_rows.append(int(_ri))
        _candidate_rows = sorted(set(_candidate_rows))

        for row_i in _candidate_rows:
            signals = signal_map.get(row_i)
            if signals is None:
                signals = {}
            source_hits = {str(k).strip().lower(): v for k, v in signals.items()}
            added: List[Tuple[str, str]] = []

            outcome = auth_outcome_vals[row_i]
            protocol = auth_protocol_vals[row_i]
            direction = auth_direction_vals[row_i]
            logon_type = logon_type_vals[row_i]
            message = message_vals[row_i]
            auth_pkg = auth_pkg_vals[row_i]

            success = outcome == "success" or any(
                float(source_hits.get(src, 0.0)) > 0.0
                for src in _success_keys_lower
                if isinstance(source_hits.get(src, 0.0), (int, float))
            )
            failure = outcome == "failure" or any(
                float(source_hits.get(src, 0.0)) > 0.0
                for src in _fail_keys_lower
                if isinstance(source_hits.get(src, 0.0), (int, float))
            )
            remote = direction == "remote" or protocol in {"ssh", "rdp", "windows-network"}
            remote_interactive = protocol == "rdp" or logon_type == "10"
            remote_shell = protocol == "ssh"
            invalid_user = "invalid user" in message or "unknown user" in message
            if not (success or failure):
                continue
            if row_i not in signal_map:
                signal_map[row_i] = signals

            if success:
                if float(signals.get(success_target, 0.0) or 0.0) <= 0.0:
                    signals[success_target] = 1.0
                    added.append((success_target, ",".join(success_sources)))
                if remote:
                    signals["auth_remote_success"] = max(float(signals.get("auth_remote_success", 0.0) or 0.0), 1.0)
                    added.append(("auth_remote_success", protocol or direction or "remote"))
                if remote_interactive:
                    signals["auth_remote_interactive_success"] = max(float(signals.get("auth_remote_interactive_success", 0.0) or 0.0), 1.0)
                    added.append(("auth_remote_interactive_success", protocol or logon_type or "remote_interactive"))
                if remote_shell:
                    signals["auth_remote_shell_success"] = max(float(signals.get("auth_remote_shell_success", 0.0) or 0.0), 1.0)
                    added.append(("auth_remote_shell_success", protocol or "ssh"))
                if not remote:
                    signals["auth_local_success"] = max(float(signals.get("auth_local_success", 0.0) or 0.0), 1.0)
                    added.append(("auth_local_success", protocol or direction or "local"))
            if failure:
                if float(signals.get(fail_target, 0.0) or 0.0) <= 0.0:
                    signals[fail_target] = 1.0
                    added.append((fail_target, ",".join(fail_sources)))
                if remote:
                    signals["auth_remote_failure"] = max(float(signals.get("auth_remote_failure", 0.0) or 0.0), 1.0)
                    added.append(("auth_remote_failure", protocol or direction or "remote"))
                if not remote:
                    signals["auth_local_failure"] = max(float(signals.get("auth_local_failure", 0.0) or 0.0), 1.0)
                    added.append(("auth_local_failure", protocol or direction or "local"))
                if invalid_user:
                    signals["auth_invalid_user"] = max(float(signals.get("auth_invalid_user", 0.0) or 0.0), 1.0)
                    added.append(("auth_invalid_user", "invalid user"))

            # Lateral movement / Windows logon type signals
            if success and logon_type == "9":
                signals["auth_newcredentials_logon"] = max(float(signals.get("auth_newcredentials_logon", 0.0) or 0.0), 1.0)
                added.append(("auth_newcredentials_logon", "logon_type_9"))
            if success and logon_type in {"4", "5"}:
                signals["auth_service_logon"] = max(float(signals.get("auth_service_logon", 0.0) or 0.0), 1.0)
                added.append(("auth_service_logon", f"logon_type_{logon_type}"))
            if success and remote and auth_pkg == "ntlm":
                signals["auth_ntlm_remote"] = max(float(signals.get("auth_ntlm_remote", 0.0) or 0.0), 1.0)
                added.append(("auth_ntlm_remote", "ntlm_remote_success"))
            # Lateral movement composite: ≥2 of (remote+success, network/RDP logon type, NTLM)
            if success:
                lateral_count = sum([
                    bool(remote),
                    logon_type in {"3", "10"},
                    auth_pkg == "ntlm",
                ])
                if lateral_count >= 2:
                    signals["lateral_movement_indicator"] = max(float(signals.get("lateral_movement_indicator", 0.0) or 0.0), 1.0)
                    added.append(("lateral_movement_indicator", f"logon_type={logon_type},pkg={auth_pkg}"))

            if added:
                expl = self._sparse_explain_list(explain_map, row_i)
                for target, sources in added:
                    expl.append({
                        "rule_id": target.upper(),
                        "description": "Canonical authentication signal derived from protocol-specific success/failure semantics",
                        "confidence": "high",
                        "evidence_type": "direct",
                        "signals": [target],
                        "evidence": {
                            "derived_from": sources,
                        },
                    })

    def _derive_canonical_execution_signals_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
    ) -> None:
        """
        Keep parser-specific execution provenance intact while exposing stable
        execution_* signals for scoring and future temporal narratives.
        """
        del df
        canonical_map = (
            ("execution_lolbin", ("lolbin_windows", "lolbin_linux")),
            ("execution_lolbin_suspicious_args", ("lolbin_suspicious_args",)),
            ("execution_interpreter", ("interpreter_exec_linux",)),
            ("execution_scheduled", ("scheduled_exec",)),
            ("execution_privileged_scheduled", ("privileged_scheduled_exec",)),
        )
        for row_i, signals in signal_map.items():
            if not signals:
                continue
            added: List[Tuple[str, str]] = []
            for target, sources in canonical_map:
                matched = [
                    src for src in sources
                    if isinstance(signals.get(src), (int, float)) and float(signals.get(src, 0.0)) > 0.0
                ]
                if not matched:
                    continue
                prior = float(signals.get(target, 0.0) or 0.0)
                source_strength = max(float(signals.get(src, 0.0) or 0.0) for src in matched)
                new_value = max(prior, source_strength)
                if new_value <= prior:
                    continue
                signals[target] = new_value
                added.append((target, ",".join(matched)))
            if not added:
                continue
            expl = self._sparse_explain_list(explain_map, row_i)
            for target, sources in added:
                expl.append({
                    "rule_id": target.upper(),
                    "description": "Canonical execution signal derived from execution-related source detections",
                    "confidence": "high",
                    "evidence_type": "direct",
                    "signals": [target],
                    "evidence": {
                        "derived_from": sources,
                    },
                })

    def _derive_execution_context_signals_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
    ) -> None:
        """
        Recover lightweight process-aware execution context from Plaso-visible
        command and path artefacts without assuming PID or parent/child lineage.
        """
        if len(df) == 0:
            return

        path_candidates = _coalesce_first_meaningful(
            df,
            [c for c in ("image_path", "new_process_name", "file_path", "filename", "relative_path", "display_name", "pathspec", "path") if c in df.columns],
        ) if any(c in df.columns for c in ("image_path", "new_process_name", "file_path", "filename", "relative_path", "display_name", "pathspec", "path")) else pd.Series([None] * len(df), index=df.index)
        cmd_candidates = _coalesce_first_meaningful(
            df,
            [c for c in ("actor_cmd", "command_line", "command", "message") if c in df.columns],
        ) if any(c in df.columns for c in ("actor_cmd", "command_line", "command", "message")) else pd.Series([None] * len(df), index=df.index)

        path_vals = path_candidates.astype("string").fillna("").str.strip().to_numpy(dtype=object, copy=False)
        path_lower = (
            path_candidates.astype("string")
            .fillna("")
            .str.strip()
            .str.lower()
            .str.replace("\\", "/", regex=False)
            .to_numpy(dtype=object, copy=False)
        )
        basenames = np.array([os.path.basename(path) if path else "" for path in path_lower], dtype=object)
        cmd_vals = cmd_candidates.astype("string").fillna("").str.strip().to_numpy(dtype=object, copy=False)
        cmd_lower = (
            cmd_candidates.astype("string")
            .fillna("")
            .str.strip()
            .str.lower()
            .to_numpy(dtype=object, copy=False)
        )
        actor_source = df["actor_principal"] if "actor_principal" in df.columns else pd.Series(_column_values_or_none(df, "actor_user"), index=df.index)
        actor_lower = actor_source.astype("string").fillna("").str.strip().str.lower().to_numpy(dtype=object, copy=False)
        tmp_path_tokens = tuple(tok.replace("\\", "/") for tok in _EXEC_TMP_PATH_TOKENS)
        user_writable_tokens = tuple(tok.replace("\\", "/") for tok in _EXEC_USER_WRITABLE_PATH_TOKENS)
        suspicious_path_tokens = tuple(tok.replace("\\", "/") for tok in _EXEC_SUSPICIOUS_PATH_TOKENS)
        command_class_cache: Dict[str, Tuple[bool, bool, bool, bool]] = {}

        for row_i in range(len(df)):
            path = path_vals[row_i]
            path_l = path_lower[row_i]
            basename = basenames[row_i]
            cmd = cmd_vals[row_i]
            cmd_l = cmd_lower[row_i]
            actor = actor_lower[row_i]

            tmp_path = bool(path_l and any(tok in path_l for tok in tmp_path_tokens))
            user_writable = bool(path_l and any(tok in path_l for tok in user_writable_tokens))
            suspicious_path = bool(path_l and any(tok in path_l for tok in suspicious_path_tokens))
            system_binary_mask = bool(basename and basename in _SYSTEM_BINARY_NAMES and (tmp_path or user_writable or suspicious_path))
            cached_classes = command_class_cache.get(cmd_l)
            if cached_classes is None:
                cached_classes = _classify_command_name_mentions(cmd_l)
                command_class_cache[cmd_l] = cached_classes
            compiler_hit, shell_hit, network_hit, archive_hit = cached_classes
            privileged_hit = actor in {"root", "administrator", "admin"}
            suid_hit = bool(cmd_l and _EXEC_SUID_RE.search(cmd_l))

            to_emit: List[Tuple[str, str, str]] = []
            if tmp_path:
                to_emit.append(("exec_from_tmp", path, "Execution path indicates a temporary directory"))
            if tmp_path or user_writable:
                to_emit.append(("exec_from_user_writable", path, "Execution path indicates a user-writable location"))
            if suspicious_path and not (tmp_path or user_writable):
                to_emit.append(("exec_suspicious_path", path, "Execution path indicates a suspicious location"))
            if system_binary_mask:
                to_emit.append(("exec_system_binary_in_user_path", path, "System binary name executed from a suspicious or user-writable path"))
            if compiler_hit:
                to_emit.append(("exec_compiler_activity", cmd, "Compiler or build-tool activity observed"))
            if shell_hit:
                to_emit.append(("exec_shell_spawn", cmd, "Shell execution observed"))
            if network_hit:
                to_emit.append(("exec_network_tool", cmd, "Network transfer tooling observed"))
            if archive_hit:
                to_emit.append(("exec_archive_tool", cmd, "Archive tooling observed"))
            if privileged_hit:
                to_emit.append(("exec_privileged_context", actor, "Execution occurred in a privileged user context"))
            if suid_hit:
                to_emit.append(("exec_new_suid_binary", cmd, "Privilege-escalation or SUID-related command semantics observed"))

            if not to_emit:
                continue

            signals = self._sparse_signal_dict(signal_map, row_i)
            expl = self._sparse_explain_list(explain_map, row_i)
            for signal_name, evidence_value, description in to_emit:
                prior = float(signals.get(signal_name, 0.0) or 0.0)
                if prior >= 1.0:
                    continue
                signals[signal_name] = 1.0
                expl.append({
                    "rule_id": signal_name.upper(),
                    "description": description,
                    "confidence": "medium" if signal_name != "exec_new_suid_binary" else "high",
                    "evidence_type": "direct",
                    "signals": [signal_name],
                    "evidence": {
                        "path": path[:240] if path else "",
                        "command": cmd[:240] if cmd else "",
                        "actor_user": actor,
                        "derived_from": evidence_value[:240] if isinstance(evidence_value, str) else _safe_str(evidence_value)[:240],
                    },
                })

    def _derive_canonical_persistence_signals_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
    ) -> None:
        """
        Canonical persistence_* signals keep persistence provenance stable while
        making broader persistence semantics explicit for later consumers.
        """
        del df
        canonical_map = (
            ("persistence_mechanism", ("persistence_service", "persistence_scheduled_task", "persistence_runkey", "systemd_service_persistence", "authorized_keys_persistence", "authorized_keys_root_persistence")),
            ("persistence_service_install", ("persistence_service", "systemd_service_persistence")),
            ("persistence_scheduled", ("persistence_scheduled_task",)),
            ("persistence_registry", ("persistence_runkey",)),
            ("identity_persistence_change", ("account_or_group_change", "authorized_keys_persistence", "authorized_keys_root_persistence")),
        )
        for row_i, signals in signal_map.items():
            if not signals:
                continue
            added: List[Tuple[str, str]] = []
            for target, sources in canonical_map:
                matched = [
                    src for src in sources
                    if isinstance(signals.get(src), (int, float)) and float(signals.get(src, 0.0)) > 0.0
                ]
                if not matched:
                    continue
                prior = float(signals.get(target, 0.0) or 0.0)
                source_strength = max(float(signals.get(src, 0.0) or 0.0) for src in matched)
                new_value = max(prior, source_strength)
                if new_value <= prior:
                    continue
                signals[target] = new_value
                added.append((target, ",".join(matched)))
            if not added:
                continue
            expl = self._sparse_explain_list(explain_map, row_i)
            for target, sources in added:
                description = "Canonical persistence signal derived from persistence-related source detections"
                if target == "identity_persistence_change":
                    description = "Canonical identity persistence signal derived from broader account/group change provenance"
                expl.append({
                    "rule_id": target.upper(),
                    "description": description,
                    "confidence": "high",
                    "evidence_type": "direct",
                    "signals": [target],
                    "evidence": {
                        "derived_from": sources,
                    },
                })

    def _derive_canonical_transfer_signals_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
    ) -> None:
        """
        Canonical transfer_* signals separate staging, raw transfer behaviour,
        and stronger exfiltration-pattern composites without removing provenance.
        """
        del df
        canonical_map = (
            ("staging_archive", ("large_archive_created", "archive_created")),
            ("transfer_execution", ("data_transfer_tool_exec",)),
            ("transfer_large_http", ("large_http_transfer",)),
            ("transfer_exfiltration_pattern", ("staging_then_transfer",)),
            ("transfer_cross_border", ("cross_border_transfer",)),
            ("transfer_sensitive_staging", ("sensitive_data_staged", "archive_after_sensitive_access")),
        )
        for row_i, signals in signal_map.items():
            if not signals:
                continue
            added: List[Tuple[str, str]] = []
            for target, sources in canonical_map:
                matched = [
                    src for src in sources
                    if isinstance(signals.get(src), (int, float)) and float(signals.get(src, 0.0)) > 0.0
                ]
                if not matched:
                    continue
                prior = float(signals.get(target, 0.0) or 0.0)
                source_strength = max(float(signals.get(src, 0.0) or 0.0) for src in matched)
                new_value = max(prior, source_strength)
                if new_value <= prior:
                    continue
                signals[target] = new_value
                added.append((target, ",".join(matched)))
            if not added:
                continue
            expl = self._sparse_explain_list(explain_map, row_i)
            for target, sources in added:
                expl.append({
                    "rule_id": target.upper(),
                    "description": "Canonical transfer/exfiltration signal derived from staging, transfer, or exfiltration-pattern detections",
                    "confidence": "high",
                    "evidence_type": "direct",
                    "signals": [target],
                    "evidence": {
                        "derived_from": sources,
                    },
                })

    def _apply_execution_family_signals_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
    ) -> None:
        """
        Collapse execution-like atomic detections into one narrative-ready signal.
        """
        execution_sources = (
            "execution_interpreter",
            "execution_lolbin",
            "execution_lolbin_suspicious_args",
            "execution_scheduled",
            "execution_privileged_scheduled",
            "data_transfer_tool_exec",
        )
        for row_i, signals in signal_map.items():
            if not signals:
                continue
            matched = [
                sig_name for sig_name in execution_sources
                if isinstance(signals.get(sig_name), (int, float)) and float(signals.get(sig_name, 0.0)) > 0.0
            ]
            if not matched:
                continue
            signals["suspicious_execution"] = max(float(signals.get("suspicious_execution", 0.0) or 0.0), 1.0)
            expl = self._sparse_explain_list(explain_map, row_i)
            expl.append({
                "rule_id": "SUSPICIOUS_EXECUTION",
                "description": "Suspicious execution family derived from execution-related atomic detections",
                "confidence": "medium",
                "evidence_type": "direct",
                "signals": ["suspicious_execution"],
                "evidence": {
                    "derived_from": ",".join(matched),
                },
            })

    def _apply_trust_dampening_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
    ) -> None:
        cfg = self.trust_dampening_cfg or {}
        if not cfg.get("enabled", False):
            return

        multiplier = float(cfg.get("multiplier", 0.5))
        trusted_principals = {str(x).strip().lower() for x in (cfg.get("trusted_actor_principals") or []) if str(x).strip()}
        trusted_ips = {str(x).strip() for x in (cfg.get("trusted_ips") or []) if str(x).strip()}
        trusted_asns = {str(x).strip() for x in (cfg.get("trusted_asns") or []) if str(x).strip()}
        principal_patterns = [re.compile(str(p), re.I) for p in (cfg.get("trusted_actor_principal_regex") or []) if str(p).strip()]
        target_signals = {str(x).strip().lower() for x in (cfg.get("signals") or []) if str(x).strip()}
        if not target_signals:
            target_signals = {
                "impossible_travel",
                "fail_then_success_user",
                "fail_then_success_ip",
                "new_country",
                "new_asn",
                "boundary_crossing",
                "cross_border_transfer",
            }

        principal_vals = _normalised_text_array(df, "actor_principal", lower=True)
        ip_vals = _normalised_text_array(df, "ip_address")
        asn_vals = _normalised_text_array(df, "geo_asn")

        for row_i, signals in signal_map.items():
            if not signals or row_i >= len(df):
                continue
            principal = principal_vals[row_i]
            ip_s = ip_vals[row_i]
            asn_s = asn_vals[row_i]
            trusted = False
            trusted_reason = None
            if principal and principal in trusted_principals:
                trusted = True
                trusted_reason = "trusted_actor_principal"
            elif principal and any(rx.search(principal) for rx in principal_patterns):
                trusted = True
                trusted_reason = "trusted_actor_principal_regex"
            elif ip_s and ip_s in trusted_ips:
                trusted = True
                trusted_reason = "trusted_ip"
            elif asn_s and asn_s in trusted_asns:
                trusted = True
                trusted_reason = "trusted_asn"
            if not trusted:
                continue

            changed: List[str] = []
            for sig_name, sig_val in list(signals.items()):
                sig_key = str(sig_name).strip().lower()
                if sig_key not in target_signals or not isinstance(sig_val, (int, float)):
                    continue
                signals[sig_name] = float(sig_val) * multiplier
                changed.append(sig_key)
            if changed:
                expl = self._sparse_explain_list(explain_map, row_i)
                expl.append({
                    "rule_id": "TRUST_DAMPENING",
                    "description": "Trusted principal/infrastructure dampened selected behavioural signals",
                    "confidence": "medium",
                    "evidence_type": "contextual",
                    "evidence": {
                        "reason": trusted_reason or "",
                        "multiplier": round(multiplier, 4),
                        "signals": ",".join(sorted(changed)),
                    },
                        })

    def _apply_benign_admin_dampening_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
    ) -> None:
        if len(df) == 0:
            return

        combined_vals = _combined_command_text_array(df)

        target_signals = (
            "lolbin_windows",
            "execution_lolbin",
            "exec_shell_spawn",
            "exec_network_tool",
            "data_transfer_tool_exec",
            "transfer_execution",
            "application_layer_protocol",
            "suspicious_execution",
            "file_and_directory_discovery",
            "remote_system_discovery",
            "system_owner_user_discovery",
        )
        for row_i, signals in signal_map.items():
            if not signals or row_i >= len(df):
                continue
            if float(signals.get("lolbin_suspicious_args", 0.0) or 0.0) > 0.0:
                continue
            combined = combined_vals[row_i]
            if not self._looks_like_benign_admin_query_command(combined):
                continue

            changed: List[str] = []
            for sig_name in target_signals:
                sig_val = signals.get(sig_name)
                if not isinstance(sig_val, (int, float)) or float(sig_val) <= 0.0:
                    continue
                signals[sig_name] = 0.0
                changed.append(sig_name)
            if not changed:
                continue
            expl = self._sparse_explain_list(explain_map, row_i)
            expl.append({
                "rule_id": "BENIGN_ADMIN_QUERY_DAMPENING",
                "description": "Query-only administrative command dampened generic LOLBin execution signals",
                "confidence": "medium",
                "evidence_type": "contextual",
                "evidence": {
                    "signals": ",".join(sorted(changed)),
                    "command": combined[:240],
                },
            })

    def _apply_discovery_reclassification_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
    ) -> None:
        if len(df) == 0:
            return

        combined_vals = _combined_command_text_array(df)

        target_signals = (
            "lolbin_windows",
            "lolbin_linux",
            "execution_lolbin",
            "exec_shell_spawn",
            "exec_network_tool",
            "suspicious_execution",
        )
        discovery_signals = (
            "file_and_directory_discovery",
            "remote_system_discovery",
            "system_owner_user_discovery",
        )
        for row_i, signals in signal_map.items():
            if not signals or row_i >= len(df):
                continue
            if float(signals.get("lolbin_suspicious_args", 0.0) or 0.0) > 0.0:
                continue
            if not any(float(signals.get(sig_name, 0.0) or 0.0) > 0.0 for sig_name in discovery_signals):
                continue
            combined = combined_vals[row_i]
            if not self._looks_like_read_only_discovery_command(combined):
                continue

            changed: List[str] = []
            for sig_name in target_signals:
                sig_val = signals.get(sig_name)
                if not isinstance(sig_val, (int, float)) or float(sig_val) <= 0.0:
                    continue
                signals[sig_name] = 0.0
                changed.append(sig_name)
            if not changed:
                continue
            preserved = [
                sig_name for sig_name in discovery_signals
                if float(signals.get(sig_name, 0.0) or 0.0) > 0.0
            ]
            expl = self._sparse_explain_list(explain_map, row_i)
            expl.append({
                "rule_id": "DISCOVERY_RECLASSIFICATION",
                "description": "Read-only discovery command was reclassified from generic execution to explicit discovery semantics",
                "confidence": "medium",
                "evidence_type": "contextual",
                "evidence": {
                    "dampened_signals": ",".join(sorted(changed)),
                    "preserved_discovery_signals": ",".join(sorted(preserved)),
                    "command": combined[:240],
                },
            })

    def _apply_benign_backup_dampening_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
    ) -> None:
        if len(df) == 0:
            return

        combined_vals = _combined_command_text_array(df)

        target_signals = ("lolbin_linux", "execution_lolbin", "exec_archive_tool", "suspicious_execution")
        for row_i, signals in signal_map.items():
            if not signals or row_i >= len(df):
                continue
            if float(signals.get("password_store_access", 0.0) or 0.0) > 0.0:
                continue
            if float(signals.get("credential_dumping", 0.0) or 0.0) > 0.0:
                continue
            if float(signals.get("sensitive_file_access", 0.0) or 0.0) > 0.0:
                continue

            combined = combined_vals[row_i]
            if not self._looks_like_benign_backup_archive_command(combined):
                continue

            changed: List[str] = []
            for sig_name in target_signals:
                sig_val = signals.get(sig_name)
                if not isinstance(sig_val, (int, float)) or float(sig_val) <= 0.0:
                    continue
                signals[sig_name] = 0.0
                changed.append(sig_name)
            if not changed:
                continue
            expl = self._sparse_explain_list(explain_map, row_i)
            expl.append({
                "rule_id": "BENIGN_BACKUP_ARCHIVE_DAMPENING",
                "description": "Routine backup-style archive command dampened generic execution signals",
                "confidence": "medium",
                "evidence_type": "contextual",
                "evidence": {
                    "signals": ",".join(sorted(changed)),
                    "command": combined[:240],
                },
            })

    def _run_atomic_sparse(
        self,
        out: pd.DataFrame,
        apply_profiling: bool = True,
        enforce_required_fields: bool = True,
        geoip_city_db: Optional[str] = None,
        geoip_asn_db: Optional[str] = None,
        av_csv_path: Optional[str] = None,
        luhn_csv_path: Optional[str] = None,
        nsrl_parquet_path: Optional[str] = None,
        nsrl_cache_df: Optional[pd.DataFrame] = None,
        profile_manifest: Optional[Dict[str, Any]] = None,
    ) -> Tuple[pd.DataFrame, Dict[int, Dict[str, Any]], Dict[int, List[Dict[str, Any]]]]:
        # Atomic-stage ordering matters: normalise first, then enrichment, then
        # structured IP recovery, then profiling, then rule evaluation. Later
        # steps assume earlier canonical fields already exist.
        if enforce_required_fields:
            out = self.ensure_required_fields(out)

        out = self._apply_schema_aliases(out)
        out = self._extract_windows_auth_fields(out)
        out = self._extract_ssh_auth_fields(out)
        out = self._apply_normalisation(out)
        out = self._derive_pivot_destination_fields(out)

        if av_csv_path:
            out = self._apply_hash_enrichment_csv(out, av_csv_path, hash_col="sha256_hash", csv_hash_col="sha256")
        if luhn_csv_path:
            out = self._apply_hash_enrichment_csv(out, luhn_csv_path, hash_col="sha256_hash", csv_hash_col="sha256")

        for _col in ("av_hit", "luhn_hit"):
            if _col in out.columns:
                out[_col] = out[_col].astype("boolean").fillna(False).astype(bool)

        if nsrl_cache_df is not None:
            out = self._apply_nsrl_enrichment_from_cache(out, nsrl_cache_df, hash_col="sha256_hash")
        elif nsrl_parquet_path:
            nsrl_cache_df = _make_nsrl_cache_descriptor(nsrl_parquet_path)
            out = self._apply_nsrl_enrichment_from_cache(out, nsrl_cache_df, hash_col="sha256_hash")

        out = self._recover_ip_address(out)
        out = self._apply_normalisation(
            out,
            selected_names={
                "actor_ip",
                "actor_ip_final",
                "actor_principal",
                "src_ip",
                "dst_ip",
                "auth_protocol",
                "auth_direction",
                "auth_outcome",
                "session_id",
                "logon_id",
            },
        )
        self._materialise_normalised_web_features(out)

        if "yara_match" not in out.columns:
            out["yara_match"] = None
        out["yara_match_count"] = normalise_yara_match_count_series(out["yara_match"])
        # yara_hit_strength is computed inside _inject_yara_signal_sparse using
        # category-aware metadata scoring; no pre-computation needed here.
        out["yara_hit_strength"] = 0.0

        if geoip_city_db and geoip_asn_db and "ip_address" in out.columns:
            geo_df = build_geoip_enrichment_table(out, geoip_city_db, geoip_asn_db, ip_field="ip_address")
            if not geo_df.empty:
                geo_df = geo_df.set_index("ip_address")
                overlap = [c for c in geo_df.columns if c in out.columns]
                if overlap:
                    out = out.drop(columns=overlap)
                out = out.join(geo_df, on="ip_address")

        if apply_profiling and self.profiling_cfg:
            out = self._apply_hour_of_week_profiling(out, profile_manifest=profile_manifest)

        try:
            signal_map, explain_map = self._eval_atomic_rules_sparse(out)
        except Exception:
            logger.exception("Atomic stage: vectorized rule evaluation failed; falling back to legacy tuple evaluation")
            signal_map, explain_map = self._eval_atomic_rules_sparse_legacy(out)
        self._apply_web_sqli_signals_sparse(out, signal_map, explain_map)
        # Source execution signals preserve provenance; canonical execution_* keys
        # are added centrally so later scoring and temporal rules can target a
        # stable taxonomy without depending on parser-specific rule names.
        self._apply_canonical_auth_signals_sparse(out, signal_map, explain_map)
        self._derive_canonical_execution_signals_sparse(out, signal_map, explain_map)
        self._derive_execution_context_signals_sparse(out, signal_map, explain_map)
        # Persistence source signals follow the same pattern: retain the
        # originating rule names for provenance, but expose a stable canonical
        # taxonomy for later scoring and temporal/contextual consumers.
        self._derive_canonical_persistence_signals_sparse(out, signal_map, explain_map)
        # Transfer/exfiltration source signals are introduced across atomic,
        # contextual, and temporal stages, so this helper is idempotent and is
        # re-applied later as stronger staging/exfiltration composites appear.
        self._derive_canonical_transfer_signals_sparse(out, signal_map, explain_map)
        self._apply_execution_family_signals_sparse(out, signal_map, explain_map)

        self._inject_av_signal_sparse(out, signal_map, explain_map)
        self._inject_yara_signal_sparse(out, signal_map, explain_map)
        out["chronosift_score"] = self._score_signal_map_sparse(len(out), signal_map, index=out.index, df=out)
        out.attrs.setdefault("chronosift_sparse", {})
        out.attrs["chronosift_sparse"]["signal_map"] = signal_map
        out.attrs["chronosift_sparse"]["explain_map"] = explain_map
        return out, signal_map, explain_map

    def apply_atomic(
        self,
        df: pd.DataFrame,
        apply_profiling: bool = True,
        enforce_required_fields: bool = True,
        geoip_city_db: Optional[str] = None,
        geoip_asn_db: Optional[str] = None,
        av_csv_path: Optional[str] = None,
        luhn_csv_path: Optional[str] = None,
        nsrl_parquet_path: Optional[str] = None,
        nsrl_cache_df: Optional[pd.DataFrame] = None,
        materialise_event_columns: bool = False,
        profile_manifest: Optional[Dict[str, Any]] = None,
    ) -> pd.DataFrame:
        logger.info("Atomic stage: validating input frame")
        if not isinstance(df.index, pd.DatetimeIndex):
            raise ValueError("DataFrame index must be a DatetimeIndex.")
        if df.index.hasnans:
            raise ValueError(
                "DataFrame index contains NaT values. Drop rows with invalid timestamps "
                "before calling ChronoSiftEngine.apply_atomic()."
            )
        df = _stable_sort_datetime_frame(df)
        out = df
        logger.info("Atomic stage: evaluating atomic rules and enrichment")
        out, signal_map, explain_map = self._run_atomic_sparse(
            out,
            apply_profiling=apply_profiling,
            enforce_required_fields=enforce_required_fields,
            geoip_city_db=geoip_city_db,
            geoip_asn_db=geoip_asn_db,
            av_csv_path=av_csv_path,
            luhn_csv_path=luhn_csv_path,
            nsrl_parquet_path=nsrl_parquet_path,
            nsrl_cache_df=nsrl_cache_df,
            profile_manifest=profile_manifest,
        )
        if materialise_event_columns:
            logger.info("Atomic stage: materialising sparse event columns")
            self._materialise_sparse_event_columns(out, signal_map, explain_map)
        logger.info("Atomic stage: complete")
        return out

    def apply_contextual(
        self,
        df: pd.DataFrame,
        apply_temporal: bool = True,
        apply_profiling: bool = True,
        materialise_event_columns: bool = True,
        file_hit_manifest: Optional[Dict[str, Any]] = None,
        impossible_travel_state: Optional[Dict[tuple, Dict[str, Any]]] = None,
    ) -> pd.DataFrame:
        logger.info("Contextual stage: loading sparse state")
        signal_map = ((df.attrs.get("chronosift_sparse", {}) or {}).get("signal_map", {}) or {})
        explain_map = ((df.attrs.get("chronosift_sparse", {}) or {}).get("explain_map", {}) or {})

        self._apply_non_temporal_contextual_sparse(
            df,
            signal_map,
            explain_map,
            apply_profiling=apply_profiling,
            file_hit_manifest=file_hit_manifest,
        )

        if apply_temporal:
            self._apply_temporal_contextual_sparse(
                df,
                signal_map,
                explain_map,
                impossible_travel_state=impossible_travel_state,
            )

        logger.info("Contextual stage: scoring contextual output")
        df["chronosift_score"] = self._score_signal_map_sparse(len(df), signal_map, index=df.index, df=df)

        if materialise_event_columns:
            logger.info("Contextual stage: materialising sparse event columns")
            self._materialise_sparse_event_columns(df, signal_map, explain_map)
        else:
            df.attrs.setdefault("chronosift_sparse", {})
            df.attrs["chronosift_sparse"]["signal_map"] = signal_map
            df.attrs["chronosift_sparse"]["explain_map"] = explain_map
        logger.info("Contextual stage: complete")
        return df

    def _contextual_required_columns(
        self,
        apply_temporal: bool = True,
        apply_profiling: bool = True,
    ) -> List[str]:
        """Return the minimal column subset needed for contextual processing."""
        cols: Set[str] = set()

        cols.update({
            "filename",
            "relative_path",
            "display_name",
            "pathspec",
            "link_target",
            "message",
            "xml_string",
            "parser",
            "hostname",
            "timestamp_desc",
            "is_allocated",
            "file_size",
            "file_ext",
            "actor_cmd",
            "command_line",
            "event_identifier",
            "target_user_name",
            "group_name",
            "member_name",
            "share_name",
            "share_local_path",
            "relative_target_name",
            "provider_name",
            "workstation_name",
            "authentication_package",
            "url",
            "actor_url",
            "http_request",
            "http_headers",
            "http_request_user_agent",
            "http_request_body",
            "http_content_disposition",
            "http_upload_filename",
            "http_upload_content_type",
            "http_upload_sha256",
            "http_request_content_length",
            "src_ip",
            "dst_ip",
            "actor_principal",
            "auth_protocol",
            "auth_outcome",
            "logon_type",
            "av_hit",
            "luhn_hit",
            "yara_match_count",
        })

        if apply_profiling and self.profiling_cfg:
            cols.update({"hour_rarity", "hour_of_week"})

        if apply_temporal:
            if self.impossible_travel_cfg:
                cols.update({"src_ip", "ip_address", "geo_latitude", "geo_longitude", "geo_country_iso", "geo_asn"})
                for k in (self.impossible_travel_cfg.get("key_by") or ["actor_principal"]):
                    ks = str(k).strip()
                    if ks:
                        cols.add(ks)
            if self.private_ip_continuity_cfg:
                cols.update({"actor_principal", "src_ip", "ip_address"})
            for tr in self.temporal_rules:
                for k in tr.key_by:
                    if k:
                        cols.add(k)
                if tr.field:
                    cols.add(tr.field)

        return sorted(c for c in cols if c)

    def _temporal_required_columns(self) -> List[str]:
        """Return the minimal column subset needed for stateful temporal processing."""
        cols: Set[str] = set()
        if self.impossible_travel_cfg:
            cols.update({"src_ip", "ip_address", "geo_latitude", "geo_longitude", "geo_country_iso", "geo_asn"})
            for k in (self.impossible_travel_cfg.get("key_by") or ["actor_principal"]):
                ks = str(k).strip()
                if ks:
                    cols.add(ks)
        if self.private_ip_continuity_cfg:
            cols.update({"actor_principal", "src_ip", "ip_address"})
        for tr in self.temporal_rules:
            for k in tr.key_by:
                if k:
                    cols.add(k)
            if tr.field:
                cols.add(tr.field)
        return sorted(c for c in cols if c)

    def _apply_non_temporal_contextual_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
        apply_profiling: bool = True,
        file_hit_manifest: Optional[Dict[str, Any]] = None,
        retain_zero_weight_lifecycle_signals: bool = True,
    ) -> None:
        contextual_cache: Dict[Tuple[Any, ...], np.ndarray] = {}
        logger.info("Contextual stage: applying file lifecycle signals")
        self._apply_file_lifecycle_signals_sparse(
            df,
            signal_map,
            explain_map,
            contextual_cache=contextual_cache,
            retain_zero_weight_generic_signals=retain_zero_weight_lifecycle_signals,
        )
        logger.info("Contextual stage: applying MFT timestomping detection")
        self._apply_timestomping_detection_sparse(
            df, signal_map, explain_map, contextual_cache=contextual_cache
        )
        # Transfer taxonomy spans multiple stages: archive/file-lifecycle signals
        # appear here, while stronger exfiltration composites only exist after
        # temporal rules. Re-applying the canonical helper keeps the taxonomy
        # current without mutating provenance or changing scores by itself.
        self._derive_canonical_transfer_signals_sparse(df, signal_map, explain_map)

        logger.info("Contextual stage: applying persistence and system-change signals")
        self._apply_persistence_and_config_signals_sparse(
            df, signal_map, explain_map, contextual_cache=contextual_cache
        )

        logger.info("Contextual stage: propagating referenced-file hit signals")
        self._apply_referenced_file_hit_signals_sparse(df, signal_map, explain_map, hit_manifest=file_hit_manifest)

        logger.info("Contextual stage: applying evidence-qualified web ATT&CK mapping")
        self._apply_web_attack_mapping_sparse(df, signal_map, explain_map)

        logger.info("Contextual stage: applying direct dead-box ATT&CK signals")
        self._apply_deadbox_direct_signals_sparse(
            df, signal_map, explain_map, contextual_cache=contextual_cache
        )
        self._derive_canonical_persistence_signals_sparse(df, signal_map, explain_map)
        self._apply_discovery_reclassification_sparse(df, signal_map, explain_map)
        self._apply_benign_admin_dampening_sparse(df, signal_map, explain_map)
        self._apply_benign_backup_dampening_sparse(df, signal_map, explain_map)

        if apply_profiling and self.profiling_cfg:
            logger.info("Contextual stage: applying temporal profiling signals")
            self._apply_profile_signals_and_multipliers_sparse(df, signal_map, explain_map)
        self._apply_canonical_auth_signals_sparse(df, signal_map, explain_map)
        self._apply_trust_dampening_sparse(df, signal_map, explain_map)

    def _apply_temporal_contextual_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
        geo_continuity_state: Optional[Dict[tuple, Dict[str, Any]]] = None,
        impossible_travel_state: Optional[Dict[tuple, Dict[str, Any]]] = None,
        ip_continuity_state: Optional[Dict[tuple, Dict[str, Any]]] = None,
    ) -> None:
        logger.info("Contextual stage: applying geo continuity detection")
        self._apply_geo_continuity_sparse(
            df,
            signal_map,
            explain_map,
            carried_state=geo_continuity_state,
        )

        if self.impossible_travel_cfg:
            logger.info("Contextual stage: applying impossible travel detection")
            self._apply_impossible_travel_sparse(
                df,
                signal_map,
                explain_map,
                carried_last=impossible_travel_state,
            )

        if self.private_ip_continuity_cfg:
            logger.info("Contextual stage: applying private IP continuity detection")
            self._apply_private_ip_continuity_sparse(
                df, signal_map, explain_map,
                carried_last=ip_continuity_state,
            )

        if self.temporal_rules:
            logger.info("Contextual stage: applying temporal rules")
            self._apply_temporal_rules_sparse(df, signal_map, explain_map)
            self._derive_canonical_transfer_signals_sparse(df, signal_map, explain_map)

        logger.info("Contextual stage: applying dead-box temporal composites")
        self._apply_deadbox_temporal_composites_sparse(df, signal_map, explain_map)

    def _temporal_candidate_reduction_safe(self) -> bool:
        cfg = self.private_ip_continuity_cfg or {}
        if cfg and bool(cfg.get("enabled", True)):
            return False
        for tr in self.temporal_rules:
            if tr.mode in {"first_seen_value", "change_detected"}:
                return False
        return True

    def _temporal_candidate_actor_columns(self) -> List[str]:
        cols: List[str] = ["actor_principal", "src_ip", "ip_address"]
        for k in (self.impossible_travel_cfg.get("key_by") or ["actor_principal"]):
            ks = str(k).strip()
            if ks and ks not in cols:
                cols.append(ks)
        for tr in self.temporal_rules:
            for k in tr.key_by:
                ks = str(k).strip()
                if ks and ks not in cols:
                    cols.append(ks)
        return cols

    # Dead-box composite precursor signals that must seed the candidate mask
    # so that candidate reduction does not suppress dead-box temporal composites.
    _DEADBOX_COMPOSITE_PRECURSOR_SIGNALS: ClassVar[frozenset] = frozenset({
        # user_execution_after_download / ingress_tool_transfer precursors
        "browser_download", "suspicious_execution", "prefetch_execution",
        "amcache_execution", "execution_lolbin", "execution_interpreter",
        # webshell_activity / web_upload_execution_chain precursors
        "webshell_artifact", "web_exploitation_hint", "exploit_public_facing_app",
        # ransomware_impact precursors
        "mass_file_modification", "ransomware_extension_burst",
        "yara_ransomware", "av_ransomware",
        "defender_disabled", "inhibit_system_recovery",
        # automated_exfiltration precursors
        "transfer_execution", "data_transfer_tool_exec",
        "staging_then_transfer", "large_http_transfer",
        "application_layer_protocol", "cross_border_transfer",
        # credential_dump_collection / password_store_exfil_chain precursors
        "credential_dumping", "yara_offensive_tool", "av_offensive_tool",
        "password_store_access",
        # automated_collection precursors
        "sensitive_file_access", "archive_created", "large_archive_created",
        "repeated_scheduled_exec",
    })

    def _temporal_candidate_base_mask(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
    ) -> pd.Series:
        base = pd.Series(False, index=df.index, dtype=bool)
        needed_signals: Set[str] = set()
        for tr in self.temporal_rules:
            if tr.mode == "cooccur":
                needed_signals.update(
                    need.signal for need in tr.cooccur_all if getattr(need, "signal", None)
                )
            elif tr.mode == "sequence":
                needed_signals.update(
                    step.signal for step in tr.sequence if getattr(step, "signal", None)
                )

        # Include dead-box composite precursors so candidate reduction cannot
        # skip entire partitions that only contain dead-box-relevant signals.
        needed_signals.update(self._DEADBOX_COMPOSITE_PRECURSOR_SIGNALS)

        success_keys = (self.impossible_travel_cfg or {}).get("success_signal_keys") or []
        success_keys = [str(k) for k in success_keys if str(k).strip()]

        for pos, signals in signal_map.items():
            if not (0 <= pos < len(df)):
                continue
            if not isinstance(signals, dict) or not signals:
                continue

            include = False
            if needed_signals:
                for name, value in signals.items():
                    if name not in needed_signals:
                        continue
                    if isinstance(value, (int, float)):
                        if float(value) > 0:
                            include = True
                            break
                    elif not _is_null(value) and bool(value):
                        include = True
                        break

            if not include and self.impossible_travel_cfg:
                include = _signals_indicate_auth_success(signals, success_keys)

            if include:
                base.iat[pos] = True

        return base

    def _temporal_candidate_window(self, base_window: Union[str, timedelta]) -> timedelta:
        td = parse_lookback(base_window) if isinstance(base_window, str) else base_window
        for tr in self.temporal_rules:
            if tr.mode in {"cooccur", "sequence"} and tr.lookback > td:
                td = tr.lookback
        return td

    def apply(
        self,
        df: pd.DataFrame,
        apply_temporal: bool = True,
        apply_profiling: bool = True,
        enforce_required_fields: bool = True,
        geoip_city_db: Optional[str] = None,
        geoip_asn_db: Optional[str] = None,
        av_csv_path: Optional[str] = None,
        luhn_csv_path: Optional[str] = None,
        nsrl_parquet_path: Optional[str] = None,
        nsrl_cache_df: Optional[pd.DataFrame] = None,
        materialise_event_columns: bool = True,
        profile_manifest: Optional[Dict[str, Any]] = None,
        file_hit_manifest: Optional[Dict[str, Any]] = None,
    ) -> pd.DataFrame:
        """
        Apply ChronoSift to a timeline DataFrame.

        Performance note
        ----------------
        ChronoSift operates in-place on the supplied DataFrame. During processing,
        event signals and explanations are held internally in sparse form.
        """
        out = self.apply_atomic(
            df,
            apply_profiling=apply_profiling,
            enforce_required_fields=enforce_required_fields,
            geoip_city_db=geoip_city_db,
            geoip_asn_db=geoip_asn_db,
            av_csv_path=av_csv_path,
            luhn_csv_path=luhn_csv_path,
            nsrl_parquet_path=nsrl_parquet_path,
            nsrl_cache_df=nsrl_cache_df,
            materialise_event_columns=False,
            profile_manifest=profile_manifest,
        )

        out = self.apply_contextual(
            out,
            apply_temporal=apply_temporal,
            apply_profiling=apply_profiling,
            materialise_event_columns=materialise_event_columns,
            file_hit_manifest=file_hit_manifest,
        )

        out.attrs.setdefault("chronosift_metadata", {})
        out.attrs["chronosift_metadata"]["geoip"] = {
            "city": _geoip_db_metadata(geoip_city_db),
            "asn": _geoip_db_metadata(geoip_asn_db),
        }
        out.attrs["chronosift_metadata"]["enrichment"] = {
            "av_csv_path": av_csv_path,
            "luhn_csv_path": luhn_csv_path,
            "nsrl_parquet_path": nsrl_parquet_path,
        }

        return out

    def _sparse_signal_dict(self, signal_map: Dict[int, Dict[str, Any]], row_i: int) -> Dict[str, Any]:
        return signal_map.setdefault(row_i, {})

    def _sparse_explain_list(self, explain_map: Dict[int, List[Dict[str, Any]]], row_i: int) -> List[Dict[str, Any]]:
        return explain_map.setdefault(row_i, [])

    def _infer_explain_evidence_type(self, item: Dict[str, Any]) -> str:
        explicit = _safe_str(item.get("evidence_type")).strip().lower()
        if explicit:
            return explicit
        evidence = item.get("evidence")
        if isinstance(evidence, dict):
            evidence_type = _safe_str(evidence.get("evidence_type")).strip().lower()
            if evidence_type:
                return evidence_type

        rule_id = _safe_str(item.get("rule_id")).strip()
        if rule_id in self.temporal_emit_signals:
            return "temporal"
        if rule_id == "HOUR_RARITY" or rule_id in self.profile_multiplier_ids:
            return "profiling"
        if rule_id in {
            "IMPOSSIBLE_TRAVEL",
            "TRUST_DAMPENING",
            "USER_CHANGED_PRIVATE_IP",
            "USER_CROSSED_PRIVATE_SUBNET",
            "USER_PRIVATE_TO_PUBLIC_IP",
            "USER_PUBLIC_TO_PRIVATE_IP",
            "REFERENCED_FILE_YARA_HIT",
            "REFERENCED_FILE_AV_HIT",
            "REFERENCED_FILE_LUHN_HIT",
        }:
            return "contextual"
        return "direct"

    def _explain_signal_names(self, item: Dict[str, Any]) -> List[str]:
        explicit = item.get("signals")
        if isinstance(explicit, str) and explicit.strip():
            return [explicit.strip()]
        if isinstance(explicit, (list, tuple)):
            out: List[str] = []
            for sig in explicit:
                sig_s = str(sig).strip()
                if sig_s:
                    out.append(sig_s)
            if out:
                return out

        evidence = item.get("evidence")
        if isinstance(evidence, dict):
            target_signal = _safe_str(evidence.get("target_signal")).strip()
            if target_signal:
                return [target_signal]
            evidence_signals = evidence.get("signals")
            if isinstance(evidence_signals, str) and evidence_signals.strip():
                return [s for s in (part.strip() for part in evidence_signals.split(",")) if s]

        rule_id = _safe_str(item.get("rule_id")).strip()
        if rule_id in self.rule_emit_signals:
            return list(self.rule_emit_signals[rule_id])
        if rule_id in self.temporal_emit_signals:
            return list(self.temporal_emit_signals[rule_id])
        if rule_id == "HOUR_RARITY":
            return ["hour_rarity"]

        lower_rule = rule_id.lower()
        if lower_rule in self.weights:
            return [lower_rule]
        return []

    def _normalise_explain_item(
        self,
        item: Dict[str, Any],
        row_i: int,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        canonical_actor_values: Any = None,
        canonical_src_ip_values: Any = None,
    ) -> Dict[str, Any]:
        # Explain items are materialised late in the pipeline and can be numerous
        # on hot partitions. A shallow copy of the top-level item plus any
        # directly embedded container fields preserves output isolation without
        # the full cost of deepcopy on every record.
        out = dict(item)
        if isinstance(out.get("evidence"), dict):
            out["evidence"] = dict(out["evidence"])
        if isinstance(out.get("signals"), list):
            out["signals"] = list(out["signals"])
        # Arrow nested encoding requires stable scalar types for the same field
        # path. Normalise file_size here so one malformed row cannot force a
        # per-subchunk JSON fallback late in write-out.
        if "file_size" in out:
            out["file_size"] = _normalise_integral_metadata_value(out.get("file_size"))
        evidence = out.get("evidence")
        if isinstance(evidence, dict) and "file_size" in evidence:
            evidence["file_size"] = _normalise_integral_metadata_value(evidence.get("file_size"))
        out["evidence_type"] = self._infer_explain_evidence_type(out)

        canonical_actor = None
        if canonical_actor_values is not None and 0 <= row_i < len(canonical_actor_values):
            canonical_actor = canonical_actor_values[row_i]
        elif "actor_principal" in df.columns and 0 <= row_i < len(df):
            actor_val = df["actor_principal"].iloc[row_i]
            if not _is_null(actor_val):
                actor_s = _safe_str(actor_val).strip()
                canonical_actor = actor_s or None

        canonical_src_ip = None
        if canonical_src_ip_values is not None and 0 <= row_i < len(canonical_src_ip_values):
            canonical_src_ip = canonical_src_ip_values[row_i]
        elif 0 <= row_i < len(df):
            src_val = None
            if "src_ip" in df.columns:
                src_val = df["src_ip"].iloc[row_i]
            elif "ip_address" in df.columns:
                src_val = df["ip_address"].iloc[row_i]
            if not _is_null(src_val):
                src_s = _safe_str(src_val).strip()
                canonical_src_ip = src_s or None
        out["canonical_actor"] = canonical_actor
        out["canonical_src_ip"] = canonical_src_ip

        signal_names = self._explain_signal_names(out)
        row_signals = signal_map.get(row_i, {}) or {}
        signal_details: List[Dict[str, Any]] = []
        total_weight = 0.0
        total_value = 0.0
        total_contribution = 0.0
        for signal_name in signal_names:
            sig_key = str(signal_name).strip()
            if not sig_key:
                continue
            sig_val = row_signals.get(sig_key)
            if not isinstance(sig_val, (int, float)):
                continue
            weight = float(self.weights.get(sig_key.lower(), 0.0))
            value = float(sig_val)
            contribution = value * weight
            signal_details.append({
                "name": sig_key,
                "signal_weight": weight,
                "signal_value": value,
                "score_contribution": contribution,
            })
            total_weight += weight
            total_value += value
            total_contribution += contribution

        out["signal_weight"] = total_weight
        out["signal_value"] = total_value
        out["score_contribution"] = total_contribution
        if signal_details:
            out["signals"] = signal_details
        return out

    def _materialise_sparse_event_columns(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
        materialise_explain_columns: bool = True,
    ) -> None:
        if getattr(df, "attrs", None):
            # Sparse state is passed in explicitly here, so keeping attrs on the
            # frame only creates avoidable propagation work while we assign the
            # nested review columns on hot partitions.
            df.attrs = {}

        n = len(df)
        hour_contrib = self._hour_rarity_contribution_values(df)
        hour_note_mask = (hour_contrib > 0.0) if hour_contrib is not None else None

        canonical_actor_values: Optional[np.ndarray] = None
        if "actor_principal" in df.columns:
            actor_series = df["actor_principal"].astype("string").fillna("").str.strip()
            actor_series = actor_series.mask(actor_series.str.lower().isin(PLACEHOLDER_STRINGS), "")
            canonical_actor_values = actor_series.where(actor_series.ne(""), other=None).to_numpy(copy=False)

        canonical_src_ip_values: Optional[np.ndarray] = None
        src_field = "src_ip" if "src_ip" in df.columns else ("ip_address" if "ip_address" in df.columns else None)
        if src_field is not None:
            src_series = df[src_field].astype("string").fillna("").str.strip()
            src_series = src_series.mask(src_series.str.lower().isin(PLACEHOLDER_STRINGS), "")
            canonical_src_ip_values = src_series.where(src_series.ne(""), other=None).to_numpy(copy=False)

        if signal_map:
            signals_col: List[Optional[Dict[str, Any]]] = [None] * n
            for i, sig in signal_map.items():
                if 0 <= i < n:
                    signals_col[i] = dict(sig)
            df["chronosift_signals"] = signals_col
        else:
            _delete_columns_inplace(df, ["chronosift_signals"])

        if hour_contrib is not None:
            df["chronosift_hour_rarity_score"] = hour_contrib
        else:
            _delete_columns_inplace(df, ["chronosift_hour_rarity_score"])

        if materialise_explain_columns:
            if explain_map:
                explain_col: List[Optional[List[Dict[str, Any]]]] = [None] * n
                for i, expl in explain_map.items():
                    if 0 <= i < n:
                        explain_col[i] = [
                            self._normalise_explain_item(
                                item,
                                i,
                                df,
                                signal_map,
                                canonical_actor_values=canonical_actor_values,
                                canonical_src_ip_values=canonical_src_ip_values,
                            )
                            for item in expl
                        ]

                if hour_note_mask is not None:
                    for i, existing in enumerate(explain_col):
                        if not (0 <= i < n) or not bool(hour_note_mask[i]):
                            continue
                        if existing is None:
                            continue
                        augmented = list(existing)
                        augmented.append(_hour_rarity_explain_item())
                        explain_col[i] = augmented

                df["chronosift_explain"] = explain_col
            else:
                _delete_columns_inplace(df, ["chronosift_explain"])

            if hour_note_mask is not None and bool(np.any(hour_note_mask)):
                df["chronosift_hour_rarity_explained"] = hour_note_mask
            else:
                _delete_columns_inplace(df, ["chronosift_hour_rarity_explained"])
        else:
            _delete_columns_inplace(
                df,
                ["chronosift_explain", "chronosift_hour_rarity_explained"],
            )

    def _hour_rarity_values(self, df: Optional[pd.DataFrame]) -> Optional[Any]:
        if df is None or "hour_rarity" not in df.columns:
            return None
        hour_series = df["hour_rarity"]
        if pd.api.types.is_numeric_dtype(hour_series.dtype):
            try:
                return hour_series.to_numpy(dtype="float64", na_value=0.0, copy=False)
            except TypeError:
                pass
            values = hour_series.to_numpy(copy=False)
            if str(getattr(values, "dtype", "")) == "float64":
                if pd.isna(values).any():
                    values[pd.isna(values)] = 0.0
                return values
            return hour_series.fillna(0.0).astype("float64", copy=False).to_numpy(copy=False)
        return pd.to_numeric(hour_series, errors="coerce").fillna(0.0).to_numpy(dtype="float64", copy=False)

    def _hour_rarity_contribution_values(self, df: Optional[pd.DataFrame]) -> Optional[Any]:
        hour_weight = float(self.weights.get("hour_rarity", 0.0))
        if (
            hour_weight == 0.0
            or not bool(self.profiling_cfg.get("emit_hour_rarity_signal", True))
        ):
            return None
        hour_scores = self._hour_rarity_values(df)
        if hour_scores is None:
            return None
        return hour_scores * hour_weight

    def _score_signal_map_sparse(
        self,
        n_rows: int,
        signal_map: Dict[int, Dict[str, Any]],
        index=None,
        df: Optional[pd.DataFrame] = None,
    ) -> pd.Series:
        scores = [0.0] * n_rows
        for row_i, signals in signal_map.items():
            scores[row_i] = self._score_signals(signals)
        if index is None:
            index = range(n_rows)
        score_series = pd.Series(scores, index=index, dtype="float64")

        hour_contrib = self._hour_rarity_contribution_values(df)
        if hour_contrib is not None:
            score_series = score_series.add(hour_contrib, fill_value=0.0)

        return score_series.clip(upper=self.max_event_score)

    def _apply_referenced_file_hit_signals_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
        hit_manifest: Optional[Dict[str, Any]] = None,
    ) -> None:
        if "filename" not in df.columns and hit_manifest is None:
            return

        if hit_manifest is not None:
            hit_map = (hit_manifest.get("hit_map", {}) or {})
            basename_map = (hit_manifest.get("basename_map", {}) or {})
            web_path_map = (hit_manifest.get("web_path_map", {}) or {})
            web_basename_map = (hit_manifest.get("web_basename_map", {}) or {})
            web_identity_map = (hit_manifest.get("web_identity_map", {}) or {})
            web_basename_identity_map = (hit_manifest.get("web_basename_identity_map", {}) or {})
            hash_hit_map = (hit_manifest.get("hash_hit_map", {}) or {})
            hash_identity_map = (hit_manifest.get("hash_identity_map", {}) or {})
        else:
            hit_map = {}
            basename_map = {}
            web_path_map = {}
            web_basename_map = {}
            web_identity_map = {}
            web_basename_identity_map = {}
            hash_hit_map = {}
            hash_identity_map = {}

            current_filenames = _normalise_reference_path_series(df["filename"]).to_numpy(dtype=object, copy=False)
            _av_mask = df["av_hit"].astype(bool, errors="ignore").fillna(False).to_numpy() if "av_hit" in df.columns else np.zeros(len(df), dtype=bool)
            _luhn_mask = df["luhn_hit"].astype(bool, errors="ignore").fillna(False).to_numpy() if "luhn_hit" in df.columns else np.zeros(len(df), dtype=bool)
            _ymc_arr = pd.to_numeric(df["yara_match_count"], errors="coerce").fillna(0).to_numpy() if "yara_match_count" in df.columns else np.zeros(len(df))
            _yara_mask = _ymc_arr > 0
            # Only iterate rows with at least one hit type
            _any_hit = _av_mask | _luhn_mask | _yara_mask
            for i in np.flatnonzero(_any_hit):
                fname = current_filenames[i]
                if not fname:
                    continue
                tags: Set[str] = set()
                if _av_mask[i]:
                    tags.add("av")
                if _luhn_mask[i]:
                    tags.add("luhn")
                if _yara_mask[i]:
                    tags.add("yara")
                if tags:
                    hit_map.setdefault(fname, set()).update(tags)
                    base = _basename_from_reference_path(fname)
                    if base:
                        basename_map.setdefault(base, set()).update(tags)

        if not hit_map and not web_path_map and not hash_hit_map:
            return

        current_filenames = (
            _normalise_reference_path_series(df["filename"]).to_numpy(dtype=object, copy=False)
            if "filename" in df.columns
            else np.full(len(df), None, dtype=object)
        )
        messages = _column_values_or_none(df, "message")
        parser_vals = _column_values_or_none(df, "parser")
        http_request_vals = _column_values_or_none(df, "http_request")
        url_vals = _column_values_or_none(df, "url")
        response_code_vals = _column_values_or_none(df, "http_response_code")
        response_bytes_vals = _column_values_or_none(df, "http_response_bytes")
        upload_names_vals = _column_values_or_none(df, "chronosift_web_upload_names")
        upload_hashes_vals = _column_values_or_none(df, "chronosift_web_upload_hashes")
        upload_outcome_vals = _column_values_or_none(df, "chronosift_web_upload_outcome")
        web_log_parser_tokens = self._detection_terms("web_log_parser_tokens")

        # Collect execution-context columns that may reference hit files.
        # These cover scheduled tasks, services, prefetch, amcache, process
        # creation, and command lines — all of which may reference a file
        # that carries AV/Luhn/YARA hits independently of the message field.
        _EXEC_CTX_TEXT_COLS = (
            "image_path",
            "display_name",
            "command_line",
            "parent_command_line",
        )
        _EXEC_CTX_DIRECT_COLS = (
            "new_process_name",
            "file_path",
            "parent_process_name",
            "service_dll",
        )
        exec_ctx_text_vals: List[np.ndarray] = []
        exec_ctx_direct_vals: List[np.ndarray] = []
        for col in _EXEC_CTX_TEXT_COLS:
            if col in df.columns:
                exec_ctx_text_vals.append(df[col].to_numpy(copy=False))
                exec_ctx_direct_vals.append(_normalise_reference_path_series(df[col]).to_numpy(dtype=object, copy=False))
        for col in _EXEC_CTX_DIRECT_COLS:
            if col in df.columns:
                exec_ctx_direct_vals.append(_normalise_reference_path_series(df[col]).to_numpy(dtype=object, copy=False))

        signal_meta = {
            "yara": ("referenced_file_yara_hit", "Event references file with YARA hits", "medium"),
            "av": ("referenced_file_av_hit", "Event references file with antivirus hits", "high"),
            "luhn": ("referenced_file_luhn_hit", "Event references file with Luhn hits", "low"),
        }
        propagated_multiplier = float((self.referenced_file_cfg or {}).get("propagated_multiplier", 0.5))

        for i in range(len(df)):
            msg = messages[i]
            current_fname = current_filenames[i]
            # Extract referenced paths from message text.
            refs = _extract_referenced_paths_from_text(msg)
            ref_set = set(refs)
            refs = list(refs)
            # Also extract from execution-context fields so that prefetch,
            # scheduled tasks, services, and process creation events can
            # propagate AV/Luhn/YARA hits from the files they reference.
            for vals in exec_ctx_text_vals:
                for rp in _extract_referenced_paths_from_text(vals[i]):
                    if rp not in ref_set:
                        ref_set.add(rp)
                        refs.append(rp)
            for direct_vals in exec_ctx_direct_vals:
                # For columns that ARE a path (not free-text), also do a
                # direct normalised lookup so single-token filenames like
                # "malware.exe" are caught even without a directory prefix.
                direct = direct_vals[i]
                if direct and direct not in ref_set:
                    ref_set.add(direct)
                    refs.append(direct)
            matched: Dict[str, List[str]] = {"yara": [], "av": [], "luhn": []}
            for rp in refs:
                if current_fname and rp == current_fname:
                    continue
                tags = hit_map.get(rp)
                if not tags and (rp.startswith("./") or rp.startswith("../")):
                    base = _basename_from_reference_path(rp)
                    tags = basename_map.get(base)
                if not tags:
                    continue
                for tag in tags:
                    matched[tag].append(rp)

            http_method = ""
            http_path = ""
            canonical_web_path = None
            web_access_tags: Set[str] = set()
            web_upload_tags: Set[str] = set()
            web_access_identity = _empty_file_identity()
            web_upload_identity = _empty_file_identity()
            parser = _safe_str(parser_vals[i]).strip().lower()
            request_semantics = (
                bool(_safe_str(http_request_vals[i]).strip())
                or bool(_safe_str(url_vals[i]).strip())
                or any(token in parser for token in web_log_parser_tokens)
            )
            if (web_path_map or web_basename_map or hash_hit_map) and request_semantics:
                http_semantics = _extract_http_request_semantics(msg, http_request_vals[i], url_vals[i])
                http_method = _safe_str(http_semantics.get("method")).strip().upper()
                http_path = _safe_str(http_semantics.get("path")).strip()
                canonical_web_path = _canonical_web_request_path(http_path)
                if canonical_web_path:
                    web_path_key = canonical_web_path.casefold()
                    web_access_tags.update(web_path_map.get(web_path_key, set()) or set())
                    _merge_file_identity(web_access_identity, web_identity_map.get(web_path_key))
                    for tag in web_access_tags:
                        matched[tag].append(canonical_web_path)

                if http_method in {"POST", "PUT", "PATCH"} and web_basename_map:
                    upload_names = [
                        value for value in _safe_str(upload_names_vals[i]).split("|") if value
                    ] or list(_extract_http_upload_names(msg, http_request_vals[i], url_vals[i], http_path))
                    for upload_name in upload_names:
                        upload_key = upload_name.casefold()
                        web_upload_tags.update(web_basename_map.get(upload_key, set()) or set())
                        _merge_file_identity(web_upload_identity, web_basename_identity_map.get(upload_key))
                        for tag in web_basename_map.get(upload_key, set()) or set():
                            matched[tag].append(f"upload:{upload_name}")
                if http_method in {"POST", "PUT", "PATCH"} and hash_hit_map:
                    for upload_hash in _safe_str(upload_hashes_vals[i]).split("|"):
                        upload_hash = upload_hash.strip().upper()
                        if not upload_hash:
                            continue
                        hash_tags = hash_hit_map.get(upload_hash, set()) or set()
                        web_upload_tags.update(hash_tags)
                        _merge_file_identity(web_upload_identity, hash_identity_map.get(upload_hash))
                        for tag in hash_tags:
                            matched[tag].append(f"upload-sha256:{upload_hash}")

            if not any(matched.values()):
                continue

            sig = self._sparse_signal_dict(signal_map, i)
            expl = self._sparse_explain_list(explain_map, i)
            for tag, paths in matched.items():
                if not paths:
                    continue
                signal_name, desc, conf = signal_meta[tag]
                sig[signal_name] = max(float(sig.get(signal_name, 0.0)), propagated_multiplier)
                expl.append({
                    "rule_id": signal_name.upper(),
                    "description": desc,
                    "confidence": conf,
                    "evidence_type": "contextual",
                    "signals": [signal_name],
                    "evidence": {
                        "evidence_type": "propagated",
                        "propagated_multiplier": propagated_multiplier,
                        "target_message_row_filename": current_fname or "",
                        "source_path_count": len(sorted(set(paths))),
                        "referenced_paths": "|".join(sorted(set(paths))),
                        "message": _safe_str(msg)[:240],
                    },
                })

            if web_access_tags or web_upload_tags:
                response_code = _normalise_integral_metadata_value(response_code_vals[i])
                response_bytes = _normalise_integral_metadata_value(response_bytes_vals[i])
                successful_response = response_code is not None and 200 <= response_code < 300
                all_web_tags = web_access_tags | web_upload_tags
                combined_identity = _empty_file_identity()
                _merge_file_identity(combined_identity, web_access_identity)
                _merge_file_identity(combined_identity, web_upload_identity)
                combined_identity["hit_types"].update(all_web_tags)
                categories = sorted(combined_identity["av_categories"] | combined_identity["yara_categories"])
                rules = sorted(combined_identity["yara_rules"])
                families = sorted(combined_identity["av_families"])

                def emit_web_context(signal_name: str, description: str, confidence: str) -> None:
                    sig[signal_name] = max(float(sig.get(signal_name, 0.0) or 0.0), 1.0)
                    expl.append({
                        "rule_id": signal_name.upper(),
                        "description": description,
                        "confidence": confidence,
                        "evidence_type": "contextual",
                        "signals": [signal_name],
                        "evidence": {
                            "evidence_type": "web_file_identity",
                            "http_method": http_method,
                            "http_path": http_path[:240],
                            "canonical_web_path": canonical_web_path or "",
                            "http_response_code": response_code,
                            "http_response_bytes": response_bytes,
                            "upload_outcome": _safe_str(upload_outcome_vals[i]).strip(),
                            "file_hit_types": "|".join(sorted(all_web_tags)),
                            "file_categories": "|".join(categories),
                            "yara_rules": "|".join(rules),
                            "av_families": "|".join(families),
                            "yara_rule_metadata": _serialise_file_identity(combined_identity)["yara_rule_metadata"],
                        },
                    })

                feature_updates = {
                    "chronosift_web_file_hit_types": "|".join(sorted(all_web_tags)),
                    "chronosift_web_file_categories": "|".join(categories),
                    "chronosift_web_file_rules": "|".join(rules),
                    "chronosift_web_file_families": "|".join(families),
                }
                for column, value in feature_updates.items():
                    if column in df.columns:
                        df.iat[i, df.columns.get_loc(column)] = value or pd.NA

                emit_web_context(
                    "web_file_access",
                    "Web request accesses or uploads a file identity carrying forensic content hits",
                    "medium",
                )
                if web_access_tags & {"av", "yara"}:
                    emit_web_context(
                        "web_malicious_file_access",
                        "Web request targets a file with antivirus or strong YARA support",
                        "high",
                    )
                    if AV_CAT_WEBSHELL in categories or YARA_CAT_WEBSHELL in categories:
                        emit_web_context(
                            "web_confirmed_webshell_access",
                            "Web request targets a file classified as a web shell by AV or strong YARA evidence",
                            "high",
                        )
                        if "chronosift_web_outcome" in df.columns:
                            df.iat[i, df.columns.get_loc("chronosift_web_outcome")] = (
                                "confirmed_follow_on" if successful_response else "attempt"
                            )
                if "luhn" in web_access_tags and http_method == "GET" and successful_response:
                    emit_web_context(
                        "web_sensitive_file_download",
                        "Successful web response served a file carrying Luhn-sensitive content",
                        "high",
                    )
                if web_upload_tags & {"av", "yara"}:
                    emit_web_context(
                        "web_malicious_file_upload",
                        "Web upload request names a file with antivirus or strong YARA support",
                        "high",
                    )

    def _apply_web_attack_mapping_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
    ) -> None:
        """Map web evidence to ATT&CK without turning probes into outcomes."""
        indicator_vals = _column_values_or_none(df, "chronosift_web_attack_indicators")
        category_vals = _column_values_or_none(df, "chronosift_web_file_categories")
        source_ip_vals = _column_values_or_none(df, "chronosift_web_source_ip")
        method_vals = _column_values_or_none(df, "chronosift_web_method")
        endpoint_vals = _column_values_or_none(df, "chronosift_web_endpoint")
        status_vals = _column_values_or_none(df, "chronosift_web_status_code")
        upload_outcome_vals = _column_values_or_none(df, "chronosift_web_upload_outcome")
        technique_col = df.columns.get_loc("chronosift_attack_techniques") if "chronosift_attack_techniques" in df.columns else None

        for row_i in range(len(df)):
            indicators = {
                token for token in _safe_str(indicator_vals[row_i]).split("|") if token
            }
            categories = {
                token for token in _safe_str(category_vals[row_i]).split("|") if token
            }
            existing_signals = signal_map.get(row_i, {}) or {}
            if not indicators and not any(
                float(existing_signals.get(name, 0.0) or 0.0) > 0.0
                for name in (
                    "web_sqli_attempt", "web_sqli_probable_success",
                    "web_confirmed_webshell_access", "web_malicious_file_upload",
                    "web_sensitive_file_download",
                )
            ):
                continue
            signals = self._sparse_signal_dict(signal_map, row_i)
            techniques: Set[str] = set()
            expl = self._sparse_explain_list(explain_map, row_i)

            def emit_mapping(
                signal_name: str,
                technique_id: str,
                description: str,
                confidence: str,
            ) -> None:
                signals[signal_name] = max(float(signals.get(signal_name, 0.0) or 0.0), 1.0)
                techniques.add(technique_id)
                expl.append({
                    "rule_id": signal_name.upper(),
                    "description": description,
                    "confidence": confidence,
                    "evidence_type": "mapping",
                    "signals": [signal_name],
                    "evidence": {
                        "attack_technique_id": technique_id,
                        "http_method": _safe_str(method_vals[row_i]).strip(),
                        "canonical_endpoint": _safe_str(endpoint_vals[row_i]).strip(),
                        "http_response_code": _normalise_integral_metadata_value(status_vals[row_i]),
                        "attack_indicators": "|".join(sorted(indicators)),
                        "file_categories": "|".join(sorted(categories)),
                        "source_ip": _safe_str(source_ip_vals[row_i]).strip(),
                    },
                })

            # An injection probe is evidence that someone tested the parameter,
            # not that anything was exploited. It is deliberately excluded from
            # exploit_indicators below so it cannot raise the scored
            # exploit_public_facing_app signal; it carries its own low weight
            # and is only emitted when no stronger web evidence exists on the
            # row, so a full SQLi payload is never counted twice.
            if "injection_probe" in indicators:
                stronger_evidence = (
                    any(token.startswith("sqli:") for token in indicators)
                    or bool(indicators & {
                        "path_traversal", "local_file_inclusion",
                        "remote_file_inclusion", "command_injection",
                        "webshell_command_parameter",
                    })
                    or any(
                        float(signals.get(name, 0.0) or 0.0) > 0.0
                        for name in ("web_sqli_attempt", "web_sqli_probable_success")
                    )
                )
                if not stronger_evidence:
                    signals["web_injection_probe"] = max(
                        float(signals.get("web_injection_probe", 0.0) or 0.0), 1.0
                    )
                    expl.append({
                        "rule_id": "WEB_INJECTION_PROBE",
                        "description": (
                            "Request parameter contains quote/metacharacter breakout probing "
                            "without valid injection syntax; evidence of an attempt only"
                        ),
                        "confidence": "low",
                        "evidence_type": "contextual",
                        "signals": ["web_injection_probe"],
                        "evidence": {
                            "attack_technique_id": "T1190",
                            "http_method": _safe_str(method_vals[row_i]).strip(),
                            "canonical_endpoint": _safe_str(endpoint_vals[row_i]).strip(),
                            "http_response_code": _normalise_integral_metadata_value(status_vals[row_i]),
                            "attack_indicators": "|".join(sorted(indicators)),
                            "source_ip": _safe_str(source_ip_vals[row_i]).strip(),
                        },
                    })
                    # Record the technique through the same zero-weight mapping
                    # path as every other label, so the mitre_t1190 signal and
                    # the chronosift_attack_techniques column cannot disagree.
                    emit_mapping(
                        "mitre_t1190",
                        "T1190",
                        "Injection probing maps to Exploit Public-Facing Application as an attempt; no exploitation is asserted",
                        "low",
                    )

            exploit_indicators = {
                "path_traversal", "local_file_inclusion", "remote_file_inclusion",
                "command_injection",
            }
            has_exploit_syntax = bool(
                indicators & exploit_indicators
                or any(token.startswith("sqli:") for token in indicators)
                or float(signals.get("web_sqli_attempt", 0.0) or 0.0) > 0.0
            )
            if has_exploit_syntax:
                signals["exploit_public_facing_app"] = max(
                    float(signals.get("exploit_public_facing_app", 0.0) or 0.0), 1.0
                )
                emit_mapping(
                    "mitre_t1190",
                    "T1190",
                    "Web exploitation syntax maps to Exploit Public-Facing Application; outcome remains separately qualified",
                    "medium" if float(signals.get("web_sqli_probable_success", 0.0) or 0.0) > 0.0 else "low",
                )

            probable_sqli = float(signals.get("web_sqli_probable_success", 0.0) or 0.0) > 0.0
            database_collection_syntax = bool({"sqli:schema_enumeration", "sqli:file_access"} & indicators)
            if probable_sqli and database_collection_syntax:
                emit_mapping(
                    "mitre_t1213_006",
                    "T1213.006",
                    "Probable successful SQL injection includes database enumeration or file-access syntax",
                    "medium",
                )

            if float(signals.get("web_confirmed_webshell_access", 0.0) or 0.0) > 0.0 and "webshell" in categories:
                emit_mapping(
                    "mitre_t1505_003",
                    "T1505.003",
                    "A web-accessible file is independently classified as a web shell",
                    "high",
                )

            if (
                float(signals.get("web_malicious_file_upload", 0.0) or 0.0) > 0.0
                and _safe_str(upload_outcome_vals[row_i]).strip() == "accepted"
            ):
                emit_mapping(
                    "mitre_t1105",
                    "T1105",
                    "Inbound web upload names a file with independent malicious-content evidence",
                    "high",
                )

            if float(signals.get("web_sensitive_file_download", 0.0) or 0.0) > 0.0 and _ip_scope(source_ip_vals[row_i]) == "public":
                signals["web_external_sensitive_transfer"] = max(
                    float(signals.get("web_external_sensitive_transfer", 0.0) or 0.0), 1.0
                )
                expl.append({
                    "rule_id": "WEB_EXTERNAL_SENSITIVE_TRANSFER",
                    "description": "Sensitive file was served successfully to a public source address; no exfiltration ATT&CK technique is asserted without channel context",
                    "confidence": "high",
                    "evidence_type": "contextual",
                    "signals": ["web_external_sensitive_transfer"],
                    "evidence": {"source_ip": _safe_str(source_ip_vals[row_i]).strip()},
                })

            if technique_col is not None and techniques:
                existing = {
                    token for token in _safe_str(df.iat[row_i, technique_col]).split("|") if token
                }
                df.iat[row_i, technique_col] = "|".join(sorted(existing | techniques))

    def _apply_web_sqli_signals_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
    ) -> None:
        """Identify SQLi attempts and response-size evidence of probable success."""
        if len(df) == 0:
            return

        method_vals = _column_values_or_none(df, "chronosift_web_method")
        path_vals = _column_values_or_none(df, "chronosift_web_request_target")
        endpoint_vals = _column_values_or_none(df, "chronosift_web_endpoint")
        host_vals = _column_values_or_none(df, "chronosift_web_host")
        status_vals = _column_values_or_none(df, "chronosift_web_status_code")
        response_bytes_vals = _column_values_or_none(df, "chronosift_web_response_bytes")
        actor_ip_vals = _column_values_or_none(df, "chronosift_web_source_ip")
        ua_vals = _column_values_or_none(df, "chronosift_web_user_agent")

        thresholds = self.detection_thresholds_cfg or {}
        baseline_min_samples = max(1, int(thresholds.get("web_sqli_baseline_min_samples", 2)))
        response_ratio = max(1.0, float(thresholds.get("web_sqli_response_ratio", 1.5)))
        response_delta = max(0, int(thresholds.get("web_sqli_response_delta_bytes", 2048)))
        response_minimum = max(0, int(thresholds.get("web_sqli_response_min_bytes", 4096)))
        absolute_large = max(
            response_minimum,
            int(thresholds.get("web_sqli_absolute_large_response_bytes", 65536)),
        )

        row_context: Dict[int, Dict[str, Any]] = {}
        baseline_by_endpoint: Dict[Tuple[str, str, str], List[int]] = {}
        for row_i in range(len(df)):
            http_path = _safe_str(path_vals[row_i]).strip()
            if not http_path:
                continue
            endpoint = _safe_str(endpoint_vals[row_i]).strip()
            method = _safe_str(method_vals[row_i]).strip().upper()
            host = _safe_str(host_vals[row_i]).strip().lower()
            indicators = _http_sqli_indicators(http_path)
            status_code = _normalise_integral_metadata_value(status_vals[row_i])
            response_bytes = _normalise_integral_metadata_value(response_bytes_vals[row_i])
            context = {
                "method": method,
                "host": host,
                "http_path": http_path,
                "endpoint": endpoint or "",
                "indicators": indicators,
                "status_code": status_code,
                "response_bytes": response_bytes,
            }
            row_context[row_i] = context
            if (
                endpoint
                and not indicators
                and status_code is not None
                and 200 <= status_code < 300
                and response_bytes is not None
                and response_bytes >= 0
            ):
                baseline_by_endpoint.setdefault((host, method, endpoint.casefold()), []).append(response_bytes)

        for row_i, context in row_context.items():
            indicators = context["indicators"]
            if not indicators:
                continue
            endpoint_key = (context["host"], context["method"], context["endpoint"].casefold())
            baseline_values = baseline_by_endpoint.get(endpoint_key, [])
            baseline_median: Optional[float] = None
            anomaly_threshold = float(absolute_large)
            if len(baseline_values) >= baseline_min_samples:
                baseline_median = float(np.median(np.asarray(baseline_values, dtype=np.float64)))
                anomaly_threshold = max(
                    float(response_minimum),
                    baseline_median * response_ratio,
                    baseline_median + float(response_delta),
                )
            status_code = context["status_code"]
            response_bytes = context["response_bytes"]
            successful_response = status_code is not None and 200 <= status_code < 300
            response_anomaly = (
                successful_response
                and response_bytes is not None
                and float(response_bytes) >= anomaly_threshold
            )

            sig = self._sparse_signal_dict(signal_map, row_i)
            expl = self._sparse_explain_list(explain_map, row_i)

            def emit(signal_name: str, description: str, confidence: str) -> None:
                sig[signal_name] = max(float(sig.get(signal_name, 0.0) or 0.0), 1.0)
                expl.append({
                    "rule_id": signal_name.upper(),
                    "description": description,
                    "confidence": confidence,
                    "evidence_type": "contextual",
                    "signals": [signal_name],
                    "evidence": {
                        "http_method": context["method"],
                        "http_path": context["http_path"][:500],
                        "canonical_endpoint": context["endpoint"],
                        "sqli_indicators": "|".join(indicators),
                        "http_response_code": status_code,
                        "http_response_bytes": response_bytes,
                        "baseline_response_median": baseline_median,
                        "baseline_sample_count": len(baseline_values),
                        "response_anomaly_threshold": round(anomaly_threshold, 3),
                        "actor_ip": _safe_str(actor_ip_vals[row_i]).strip(),
                        "http_request_user_agent": _safe_str(ua_vals[row_i])[:240],
                    },
                })

            emit(
                "web_sqli_attempt",
                "Decoded web request contains high-confidence SQL injection syntax",
                "medium",
            )
            if "chronosift_web_outcome" in df.columns:
                df.iat[row_i, df.columns.get_loc("chronosift_web_outcome")] = "attempt"
            if response_anomaly:
                emit(
                    "web_sqli_response_anomaly",
                    "Successful SQLi-shaped request returned substantially more content than the endpoint baseline",
                    "medium",
                )
                emit(
                    "web_sqli_probable_success",
                    "SQL injection syntax plus a successful anomalous response indicates probable exploitation",
                    "medium",
                )
                if "chronosift_web_outcome" in df.columns:
                    df.iat[row_i, df.columns.get_loc("chronosift_web_outcome")] = "probable_success"

    def _apply_file_lifecycle_signals_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
        contextual_cache: Optional[Dict[Tuple[Any, ...], np.ndarray]] = None,
        retain_zero_weight_generic_signals: bool = True,
    ) -> None:
        if len(df) == 0 or not isinstance(df.index, pd.DatetimeIndex):
            return

        required = {"timestamp_desc"}
        if not required.issubset(set(df.columns)):
            return

        nrows = len(df)
        timestamp_desc_vals = _contextual_text_array(df, contextual_cache, "timestamp_desc")
        file_paths = _contextual_file_paths(df, contextual_cache)
        path_lower = _contextual_path_lower(df, contextual_cache)
        kinds = _contextual_timestamp_kinds(df, contextual_cache)
        file_exts = np.full(nrows, "", dtype=object)
        web_root_flags = np.zeros(nrows, dtype=bool)
        suspicious_web_flags = np.zeros(nrows, dtype=bool)
        sensitive_flags = np.zeros(nrows, dtype=bool)
        dump_flags = np.zeros(nrows, dtype=bool)
        host_vals = _contextual_text_array(df, contextual_cache, "hostname")
        host_lower = _contextual_text_array(df, contextual_cache, "hostname", lower=True)
        parser_vals = _contextual_text_array(df, contextual_cache, "parser")
        message_vals = _contextual_text_array(df, contextual_cache, "message")
        message_lower = _contextual_text_array(df, contextual_cache, "message", lower=True)
        size_vals = _column_values_or_none(df, "file_size")
        alloc_vals = _column_values_or_none(df, "is_allocated")
        web_script_exts = set(self._detection_terms("web_script_extensions"))
        web_content_exts = set(self._detection_terms("web_content_extensions"))
        web_root_patterns = tuple(tok.replace("\\", "/") for tok in self._taxonomy_patterns("web_root_patterns"))
        sensitive_path_patterns = tuple(tok.replace("\\", "/") for tok in self._taxonomy_patterns("sensitive_path_patterns"))
        database_dump_patterns = tuple(tok.replace("\\", "/") for tok in self._taxonomy_patterns("database_dump_patterns"))
        database_dump_extensions = set(self._detection_terms("database_dump_extensions"))
        archive_extensions = set(self._detection_terms("archive_extensions"))
        emit_file_created = bool(retain_zero_weight_generic_signals) or float(
            self.weights.get("file_created", 0.0) or 0.0
        ) != 0.0
        emit_file_modified = bool(retain_zero_weight_generic_signals) or float(
            self.weights.get("file_modified", 0.0) or 0.0
        ) != 0.0
        emit_file_deleted = bool(retain_zero_weight_generic_signals) or float(
            self.weights.get("file_deleted", 0.0) or 0.0
        ) != 0.0

        file_exts[:] = np.fromiter(
            (os.path.splitext(path)[1] if path else "" for path in path_lower),
            dtype=object,
            count=nrows,
        )
        basenames = np.fromiter(
            (os.path.basename(path) if path else "" for path in path_lower),
            dtype=object,
            count=nrows,
        )
        web_root_flags[:] = _text_array_contains_any(path_lower, web_root_patterns)
        suspicious_web_flags[:] = web_root_flags & np.isin(file_exts, tuple(web_script_exts))
        sensitive_flags[:] = _text_array_contains_any(path_lower, sensitive_path_patterns)
        dump_flags[:] = (
            np.isin(file_exts, tuple(database_dump_extensions))
            | _text_array_contains_any(basenames, database_dump_patterns)
            | _text_array_contains_any(message_lower, database_dump_patterns)
        )
        del basenames

        for row_i in range(nrows):
            path = file_paths[row_i]
            if not path:
                continue
            kind = kinds[row_i]
            sig = signal_map.get(row_i)
            expl = explain_map.get(row_i)

            def ensure():
                nonlocal sig, expl
                if sig is None:
                    sig = self._sparse_signal_dict(signal_map, row_i)
                if expl is None:
                    expl = self._sparse_explain_list(explain_map, row_i)
                return sig, expl

            alloc_val = alloc_vals[row_i]
            alloc_bool = None if _is_null(alloc_val) else bool(alloc_val)

            if kind == "create":
                if emit_file_created:
                    sig, expl = ensure()
                    sig["file_created"] = max(float(sig.get("file_created", 0.0) or 0.0), 1.0)
                    expl.append({
                        "rule_id": "FILE_CREATED",
                        "description": "File creation-like timestamp observed",
                        "confidence": "low",
                        "evidence_type": "direct",
                        "signals": ["file_created"],
                        "evidence": {"path": path, "timestamp_desc": timestamp_desc_vals[row_i][:120]},
                    })
                if suspicious_web_flags[row_i]:
                    sig, expl = ensure()
                    sig["web_executable_file_created"] = max(float(sig.get("web_executable_file_created", 0.0) or 0.0), 1.0)
                    expl.append({
                        "rule_id": "WEB_EXECUTABLE_FILE_CREATED",
                        "description": "Executable web content created under a web root",
                        "confidence": "medium",
                        "evidence_type": "direct",
                        "signals": ["web_executable_file_created"],
                        "evidence": {"path": path, "parser": parser_vals[row_i], "hostname": host_vals[row_i]},
                    })
                if file_exts[row_i] in archive_extensions:
                    sig, expl = ensure()
                    sig["archive_created"] = max(float(sig.get("archive_created", 0.0) or 0.0), 1.0)
                    expl.append({
                        "rule_id": "ARCHIVE_CREATED",
                        "description": "Archive creation artefact observed",
                        "confidence": "medium",
                        "evidence_type": "direct",
                        "signals": ["archive_created"],
                        "evidence": {"path": path, "file_size": size_vals[row_i]},
                    })
                if dump_flags[row_i]:
                    sig, expl = ensure()
                    sig["database_dump_candidate"] = max(float(sig.get("database_dump_candidate", 0.0) or 0.0), 1.0)
                    expl.append({
                        "rule_id": "DATABASE_DUMP_CANDIDATE",
                        "description": "Database dump-like file artefact observed",
                        "confidence": "medium",
                        "evidence_type": "direct",
                        "signals": ["database_dump_candidate"],
                        "evidence": {"path": path, "message": message_vals[row_i][:200]},
                    })

            elif kind == "modify":
                if emit_file_modified:
                    sig, expl = ensure()
                    sig["file_modified"] = max(float(sig.get("file_modified", 0.0) or 0.0), 1.0)
                    expl.append({
                        "rule_id": "FILE_MODIFIED",
                        "description": "File modification-like timestamp observed",
                        "confidence": "low",
                        "evidence_type": "direct",
                        "signals": ["file_modified"],
                        "evidence": {"path": path, "timestamp_desc": timestamp_desc_vals[row_i][:120]},
                    })
                if web_root_flags[row_i] and file_exts[row_i] in web_content_exts:
                    sig, expl = ensure()
                    sig["defacement_candidate"] = max(float(sig.get("defacement_candidate", 0.0) or 0.0), 1.0)
                    expl.append({
                        "rule_id": "DEFACEMENT_CANDIDATE",
                        "description": "Web content modified under a web root",
                        "confidence": "medium",
                        "evidence_type": "direct",
                        "signals": ["defacement_candidate"],
                        "evidence": {"path": path, "hostname": host_vals[row_i]},
                    })

            elif kind == "delete" or (alloc_bool is False and file_exts[row_i]):
                if emit_file_deleted:
                    sig, expl = ensure()
                    sig["file_deleted"] = max(float(sig.get("file_deleted", 0.0) or 0.0), 1.0)
                    expl.append({
                        "rule_id": "FILE_DELETED",
                        "description": "File deletion-like artefact observed",
                        "confidence": "low",
                        "evidence_type": "direct",
                        "signals": ["file_deleted"],
                        "evidence": {"path": path, "timestamp_desc": timestamp_desc_vals[row_i][:120], "is_allocated": alloc_bool},
                    })

            if sensitive_flags[row_i]:
                sig, expl = ensure()
                sig["sensitive_file_access"] = max(float(sig.get("sensitive_file_access", 0.0) or 0.0), 1.0)
                expl.append({
                    "rule_id": "SENSITIVE_FILE_ACCESS",
                    "description": "Sensitive path artefact observed",
                    "confidence": "medium",
                    "evidence_type": "direct",
                    "signals": ["sensitive_file_access"],
                    "evidence": {"path": path, "timestamp_desc": timestamp_desc_vals[row_i][:120]},
                })

        short_lived_window = pd.Timedelta(str(self.detection_thresholds_cfg.get("short_lived_file_window", "2h")))
        suspicious_temp_tokens = tuple(tok.lower() for tok in self._detection_terms("suspicious_temp_web_name_tokens"))
        create_candidates: Dict[Tuple[str, str], Tuple[int, pd.Timestamp]] = {}
        for row_i in range(nrows):
            path = file_paths[row_i]
            if not path:
                continue
            host = host_lower[row_i]
            key = (host, path_lower[row_i])
            kind = kinds[row_i]
            if kind == "create":
                create_candidates[key] = (row_i, df.index[row_i])
                continue
            if kind != "delete":
                continue
            prior = create_candidates.get(key)
            if prior is None:
                continue
            create_i, create_ts = prior
            delta = df.index[row_i] - create_ts
            suspicious = suspicious_web_flags[create_i] or suspicious_web_flags[row_i] or (
                file_exts[row_i] in web_script_exts and any(tok in os.path.basename(path).lower() for tok in suspicious_temp_tokens)
            )
            if delta <= short_lived_window and suspicious:
                sig = self._sparse_signal_dict(signal_map, row_i)
                expl = self._sparse_explain_list(explain_map, row_i)
                sig["short_lived_file"] = max(float(sig.get("short_lived_file", 0.0) or 0.0), 1.0)
                expl.append({
                    "rule_id": "SHORT_LIVED_FILE",
                    "description": "Suspicious file was created and deleted within a bounded window",
                    "confidence": "medium",
                    "evidence_type": "direct",
                    "signals": ["short_lived_file"],
                    "evidence": {
                        "path": path,
                        "create_timestamp": create_ts.isoformat(),
                        "delete_timestamp": df.index[row_i].isoformat(),
                        "lifetime_seconds": int(delta.total_seconds()),
                    },
                })

        os_update_patterns = tuple(
            p.lower().replace("\\", "/") for p in self._taxonomy_patterns("os_update_path_patterns")
        )

        mod_events: Dict[Tuple[str, str], List[Tuple[int, pd.Timestamp]]] = {}
        for row_i in range(nrows):
            if kinds[row_i] != "modify" or not file_paths[row_i]:
                continue
            host = host_lower[row_i]
            parent = os.path.dirname(path_lower[row_i])
            if any(pat in parent for pat in os_update_patterns):
                continue
            mod_events.setdefault((host, parent), []).append((row_i, df.index[row_i]))

        mass_window = pd.Timedelta(str(self.detection_thresholds_cfg.get("mass_file_modification_window", "10m")))
        mass_threshold = int(self.detection_thresholds_cfg.get("mass_file_modification_threshold", 25))
        for key, events in mod_events.items():
            left = 0
            for right, (row_i, ts_now) in enumerate(events):
                while left < right and (ts_now - events[left][1]) > mass_window:
                    left += 1
                if (right - left + 1) >= mass_threshold:
                    sig = self._sparse_signal_dict(signal_map, row_i)
                    expl = self._sparse_explain_list(explain_map, row_i)
                    sig["mass_file_modification"] = max(float(sig.get("mass_file_modification", 0.0) or 0.0), 1.0)
                    expl.append({
                        "rule_id": "MASS_FILE_MODIFICATION",
                        "description": "Large number of file modifications observed within a bounded window",
                        "confidence": "medium",
                        "evidence_type": "direct",
                        "signals": ["mass_file_modification"],
                        "evidence": {
                            "host": key[0],
                            "directory": key[1],
                            "window_seconds": int(mass_window.total_seconds()),
                            "count_in_window": int(right - left + 1),
                        },
                    })
                    break

        ransom_ext_window = pd.Timedelta(str(self.detection_thresholds_cfg.get("ransom_extension_burst_window", "15m")))
        ransom_ext_threshold = int(self.detection_thresholds_cfg.get("ransom_extension_burst_threshold", 6))
        ransom_ext_tokens = tuple(self._detection_terms("ransom_extension_tokens"))
        ransom_events: Dict[str, List[Tuple[int, pd.Timestamp, str]]] = {}
        for row_i in range(nrows):
            if kinds[row_i] not in {"create", "modify"} or not file_paths[row_i]:
                continue
            host = host_lower[row_i]
            norm_path = path_lower[row_i]
            parent = os.path.dirname(norm_path)
            if any(pat in parent for pat in os_update_patterns):
                continue
            base = os.path.basename(norm_path)
            matched_ext = next((tok for tok in ransom_ext_tokens if base.endswith(tok)), None)
            if not matched_ext:
                continue
            ransom_events.setdefault(host, []).append((row_i, df.index[row_i], matched_ext))

        for host, events in ransom_events.items():
            left = 0
            ext_counts: Dict[str, int] = {}
            for right, (row_i, ts_now, ext_now) in enumerate(events):
                ext_counts[ext_now] = ext_counts.get(ext_now, 0) + 1
                while left < right and (ts_now - events[left][1]) > ransom_ext_window:
                    _, _, ext_left = events[left]
                    ext_counts[ext_left] = ext_counts.get(ext_left, 0) - 1
                    if ext_counts[ext_left] <= 0:
                        ext_counts.pop(ext_left, None)
                    left += 1
                count_in_window = right - left + 1
                if count_in_window >= ransom_ext_threshold:
                    sig = self._sparse_signal_dict(signal_map, row_i)
                    expl = self._sparse_explain_list(explain_map, row_i)
                    sig["ransomware_extension_burst"] = max(float(sig.get("ransomware_extension_burst", 0.0) or 0.0), 1.0)
                    expl.append({
                        "rule_id": "RANSOMWARE_EXTENSION_BURST",
                        "description": "Burst of ransomware-style encrypted file extensions observed within a bounded window",
                        "confidence": "medium",
                        "evidence_type": "direct",
                        "signals": ["ransomware_extension_burst"],
                        "evidence": {
                            "host": host,
                            "window_seconds": int(ransom_ext_window.total_seconds()),
                            "count_in_window": int(count_in_window),
                            "extensions": ",".join(sorted(ext_counts.keys()))[:240],
                        },
                    })
                    break

    def _apply_timestomping_detection_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
        contextual_cache: Optional[Dict[Tuple[Any, ...], np.ndarray]] = None,
    ) -> None:
        """Detect T1070.006 timestomping by comparing MFT $STANDARD_INFORMATION
        and $FILE_NAME creation timestamps for the same file.  When $SI creation
        is earlier than $FN creation by a meaningful margin the file's visible
        timestamps have likely been back-dated."""
        if len(df) == 0:
            return
        if "parser" not in df.columns or "timestamp_desc" not in df.columns:
            return

        nrows = len(df)
        parser_vals = _contextual_text_array(df, contextual_cache, "parser", lower=True)
        timestamp_desc_vals = _contextual_text_array(df, contextual_cache, "timestamp_desc", lower=True)
        path_keys = _contextual_path_lower(df, contextual_cache)

        si_creation: Dict[str, List[Tuple[int, pd.Timestamp]]] = {}
        fn_creation: Dict[str, List[Tuple[int, pd.Timestamp]]] = {}

        mft_rows = np.flatnonzero(_text_array_contains_any(parser_vals, ("mft",)))
        for row_i in mft_rows:
            parser_s = parser_vals[row_i]
            if "mft" not in parser_s:
                continue
            td = timestamp_desc_vals[row_i]
            if "creation" not in td and "birth" not in td:
                continue
            path_key = path_keys[row_i]
            if not path_key:
                continue
            ts = df.index[row_i]

            is_fn = "$file_name" in td or "$fn" in td or "file name" in td
            is_si = "$standard_information" in td or "$si" in td or "standard information" in td
            if not is_fn and not is_si:
                # If the timestamp_desc does not specify the attribute, try
                # to infer from the broader description. Default: ambiguous,
                # skip this row to avoid false positives.
                continue

            if is_si:
                si_creation.setdefault(path_key, []).append((row_i, ts))
            elif is_fn:
                fn_creation.setdefault(path_key, []).append((row_i, ts))

        min_delta = pd.Timedelta("1s")

        # ── Archive-extraction false-positive dampening ────────────────
        # When files are extracted from archives (ZIP/RAR/7z/tar), Windows
        # sets $SI creation to the original timestamp from inside the
        # archive while $FN creation reflects the actual extraction time.
        # This produces the same $FN > $SI pattern as timestomping.
        #
        # Heuristic 1: OS-update / installer paths are excluded outright.
        # Heuristic 2: If ≥ BULK_THRESHOLD files in the same parent
        #   directory all show $FN > $SI, it is almost certainly bulk
        #   extraction rather than targeted anti-forensics.  Those hits
        #   are downgraded to confidence "low" and flagged as likely
        #   archive extraction.

        os_update_patterns = tuple(
            p.lower().replace("\\", "/") for p in self._taxonomy_patterns("os_update_path_patterns")
        )
        BULK_THRESHOLD = 5

        # First pass: collect all candidate hits and their parent directories
        candidates: List[Tuple[str, int, pd.Timestamp, pd.Timestamp]] = []  # (path_key, si_row_i, si_ts, fn_ts)
        parent_counts: Dict[str, int] = {}

        for path_key, si_entries in si_creation.items():
            fn_entries = fn_creation.get(path_key)
            if not fn_entries:
                continue
            earliest_si = min(si_entries, key=lambda x: x[1])
            earliest_fn = min(fn_entries, key=lambda x: x[1])
            si_row_i, si_ts = earliest_si
            fn_row_i, fn_ts = earliest_fn
            if fn_ts - si_ts > min_delta:
                # Exclude OS-update/installer paths entirely
                if any(pat in path_key for pat in os_update_patterns):
                    continue
                candidates.append((path_key, si_row_i, si_ts, fn_ts))
                # Extract parent directory for bulk-extraction grouping.
                # Files with no directory separator (bare filenames) use a
                # sentinel that cannot collide with real directory paths,
                # preventing unrelated rootless-path files from aggregating.
                parent = path_key.rsplit("/", 1)[0] if "/" in path_key else f"__rootless__{path_key}"
                parent_counts[parent] = parent_counts.get(parent, 0) + 1

        # Second pass: emit signals with appropriate confidence
        for path_key, si_row_i, si_ts, fn_ts in candidates:
            parent = path_key.rsplit("/", 1)[0] if "/" in path_key else f"__rootless__{path_key}"
            bulk_extraction_likely = parent_counts.get(parent, 0) >= BULK_THRESHOLD

            sig = self._sparse_signal_dict(signal_map, si_row_i)
            expl = self._sparse_explain_list(explain_map, si_row_i)
            sig["timestomping"] = max(float(sig.get("timestomping", 0.0) or 0.0), 1.0)

            if bulk_extraction_likely:
                expl.append({
                    "rule_id": "TIMESTOMPING",
                    "description": (
                        "MFT $STANDARD_INFORMATION creation predates $FILE_NAME creation (T1070.006); "
                        "however, multiple files in the same directory show this pattern, suggesting "
                        "archive extraction or file copy rather than targeted timestomping"
                    ),
                    "confidence": "low",
                    "evidence_type": "direct",
                    "signals": ["timestomping"],
                    "evidence": {
                        "path": path_key,
                        "si_creation": si_ts.isoformat(),
                        "fn_creation": fn_ts.isoformat(),
                        "delta_seconds": int((fn_ts - si_ts).total_seconds()),
                        "bulk_extraction_dampened": True,
                        "directory_hit_count": parent_counts.get(parent, 0),
                    },
                })
            else:
                expl.append({
                    "rule_id": "TIMESTOMPING",
                    "description": "MFT $STANDARD_INFORMATION creation predates $FILE_NAME creation, indicating timestamp manipulation (T1070.006)",
                    "confidence": "high",
                    "evidence_type": "direct",
                    "signals": ["timestomping"],
                    "evidence": {
                        "path": path_key,
                        "si_creation": si_ts.isoformat(),
                        "fn_creation": fn_ts.isoformat(),
                        "delta_seconds": int((fn_ts - si_ts).total_seconds()),
                    },
                })

    def _apply_persistence_and_config_signals_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
        contextual_cache: Optional[Dict[Tuple[Any, ...], np.ndarray]] = None,
    ) -> None:
        if len(df) == 0:
            return

        # Vectorised file path coalesce and timestamp kind classification
        file_paths = _contextual_file_paths(df, contextual_cache)
        path_lower = _contextual_path_lower(df, contextual_cache)
        kinds = _contextual_timestamp_kinds(df, contextual_cache)
        timestamp_desc_vals = _contextual_text_array(df, contextual_cache, "timestamp_desc")
        parser_vals = _contextual_text_array(df, contextual_cache, "parser")
        parser_lower = _contextual_text_array(df, contextual_cache, "parser", lower=True)
        host_vals = _contextual_text_array(df, contextual_cache, "hostname")
        message_vals = _contextual_text_array(df, contextual_cache, "message")
        message_lower = _contextual_text_array(df, contextual_cache, "message", lower=True)
        actor_cmd_vals = _column_values_or_none(df, "actor_cmd")
        command_line_vals = _column_values_or_none(df, "command_line")
        xml_lower = _contextual_text_array(df, contextual_cache, "xml_string", lower=True)
        event_vals = _contextual_text_array(df, contextual_cache, "event_identifier")
        target_user_vals = _contextual_text_array(df, contextual_cache, "target_user_name")
        group_lower = _contextual_text_array(df, contextual_cache, "group_name", lower=True)
        winlogon_value_tokens = self._detection_terms("winlogon_persistence_value_tokens")
        firewall_message_tokens = self._detection_terms("firewall_message_tokens")
        firewall_change_tokens = self._detection_terms("firewall_change_tokens")
        defender_disable_tokens = self._detection_terms("defender_disable_tokens")
        account_created_event_ids = self._detection_event_ids("account_created")
        account_created_message_tokens = self._detection_terms("account_created_message_tokens")
        windows_privileged_group_tokens = self._detection_terms("windows_privileged_group_tokens")
        privileged_group_change_event_ids = self._detection_event_ids("privileged_group_change")
        cron_path_patterns = tuple(tok.replace("\\", "/") for tok in self._taxonomy_patterns("cron_path_patterns"))
        firewall_path_patterns = tuple(tok.replace("\\", "/") for tok in self._taxonomy_patterns("firewall_path_patterns"))
        group_policy_path_patterns = tuple(tok.replace("\\", "/") for tok in self._taxonomy_patterns("group_policy_path_patterns"))
        winlogon_path_patterns = tuple(tok.replace("\\", "/") for tok in self._taxonomy_patterns("winlogon_path_patterns"))
        com_hijack_path_patterns = tuple(tok.replace("\\", "/") for tok in self._taxonomy_patterns("com_hijack_path_patterns"))
        service_config_patterns = tuple(tok.replace("\\", "/") for tok in self._taxonomy_patterns("service_config_patterns"))

        for row_i in range(len(df)):
            path = file_paths[row_i]
            path_l = path_lower[row_i]
            kind = kinds[row_i]
            parser = parser_lower[row_i]
            parser_text = parser_vals[row_i]
            message = message_vals[row_i]
            message_l = message_lower[row_i]
            xml_l = xml_lower[row_i]
            event_id = event_vals[row_i]
            target_user = target_user_vals[row_i]
            group_name = group_lower[row_i]
            host = host_vals[row_i]
            signals = signal_map.get(row_i)
            explain = explain_map.get(row_i)
            registry_write_context = (
                kind in {"create", "modify", "delete"}
                or any(tok in message_l for tok in ("value set", "set value", "modified", "changed", "deleted", "created", "added"))
            )

            def ensure():
                nonlocal signals, explain
                if signals is None:
                    signals = self._sparse_signal_dict(signal_map, row_i)
                if explain is None:
                    explain = self._sparse_explain_list(explain_map, row_i)
                return signals, explain

            cron_path = bool(path_l and any(tok in path_l for tok in cron_path_patterns))
            if cron_path and kind in {"create", "modify", "delete"}:
                signals, explain = ensure()
                signals["cron_persistence"] = max(float(signals.get("cron_persistence", 0.0) or 0.0), 1.0)
                explain.append({
                    "rule_id": "CRON_PERSISTENCE",
                    "description": "Cron configuration artefact changed",
                    "confidence": "medium",
                    "evidence_type": "direct",
                    "signals": ["cron_persistence"],
                    "evidence": {"path": path, "timestamp_desc": timestamp_desc_vals[row_i][:120]},
                })

            if path_l and any(tok in path_l for tok in firewall_path_patterns) and kind in {"create", "modify", "delete"}:
                signals, explain = ensure()
                signals["firewall_modified"] = max(float(signals.get("firewall_modified", 0.0) or 0.0), 1.0)
                explain.append({
                    "rule_id": "FIREWALL_MODIFIED",
                    "description": "Firewall configuration artefact changed",
                    "confidence": "medium",
                    "evidence_type": "direct",
                    "signals": ["firewall_modified"],
                    "evidence": {"path": path, "timestamp_desc": timestamp_desc_vals[row_i][:120], "hostname": host},
                })

            if path_l and any(tok in path_l for tok in group_policy_path_patterns) and kind in {"create", "modify", "delete"}:
                signals, explain = ensure()
                signals["group_policy_modified"] = max(float(signals.get("group_policy_modified", 0.0) or 0.0), 1.0)
                explain.append({
                    "rule_id": "GROUP_POLICY_MODIFIED",
                    "description": "Group policy artefact changed",
                    "confidence": "medium",
                    "evidence_type": "direct",
                    "signals": ["group_policy_modified"],
                    "evidence": {"path": path, "timestamp_desc": timestamp_desc_vals[row_i][:120], "hostname": host},
                })

            if path_l and any(tok in path_l for tok in winlogon_path_patterns) and registry_write_context:
                if any(tok in message_l for tok in winlogon_value_tokens) or any(tok in path_l for tok in winlogon_value_tokens):
                    signals, explain = ensure()
                    signals["winlogon_helper_persistence"] = max(float(signals.get("winlogon_helper_persistence", 0.0) or 0.0), 1.0)
                    explain.append({
                        "rule_id": "WINLOGON_HELPER_PERSISTENCE",
                        "description": "Winlogon helper registry value modified (T1547.004)",
                        "confidence": "high",
                        "evidence_type": "direct",
                        "signals": ["winlogon_helper_persistence"],
                        "evidence": {
                            "path": path,
                            "parser": parser_text,
                            "message": message[:240],
                            "hostname": host,
                        },
                    })

            if path_l and any(tok in path_l for tok in com_hijack_path_patterns) and registry_write_context:
                inprocserver_hit = "inprocserver" in path_l or "inprocserver" in message_l
                treatas_hit = "treatas" in path_l or "treatas" in message_l
                if inprocserver_hit or treatas_hit:
                    signals, explain = ensure()
                    signals["com_hijack_persistence"] = max(float(signals.get("com_hijack_persistence", 0.0) or 0.0), 1.0)
                    explain.append({
                        "rule_id": "COM_HIJACK_PERSISTENCE",
                        "description": "COM CLSID InprocServer32 or TreatAs registry modification detected (T1546.015)",
                        "confidence": "medium",
                        "evidence_type": "direct",
                        "signals": ["com_hijack_persistence"],
                        "evidence": {
                            "path": path,
                            "parser": parser_text,
                            "message": message[:240],
                            "hostname": host,
                        },
                    })

            if ((path_l and any(tok in path_l for tok in service_config_patterns)) and kind in {"create", "modify", "delete"}) or (
                parser == "winreg/windows_services" and registry_write_context
            ):
                signals, explain = ensure()
                signals["service_configuration_changed"] = max(float(signals.get("service_configuration_changed", 0.0) or 0.0), 1.0)
                explain.append({
                    "rule_id": "SERVICE_CONFIGURATION_CHANGED",
                    "description": "Service configuration artefact changed",
                    "confidence": "medium",
                    "evidence_type": "direct",
                    "signals": ["service_configuration_changed"],
                    "evidence": {
                        "path": path,
                        "parser": parser_text,
                        "timestamp_desc": timestamp_desc_vals[row_i][:120],
                        "hostname": host,
                    },
                })

            if any(tok in message_l for tok in firewall_message_tokens) and any(tok in message_l for tok in firewall_change_tokens):
                signals, explain = ensure()
                signals["firewall_modified"] = max(float(signals.get("firewall_modified", 0.0) or 0.0), 1.0)
                explain.append({
                    "rule_id": "FIREWALL_MODIFIED",
                    "description": "Firewall configuration change indicated by log message",
                    "confidence": "medium",
                    "evidence_type": "direct",
                    "signals": ["firewall_modified"],
                    "evidence": {"message": message[:240], "hostname": host},
                })

            # Defender disablement: require a write/change context to avoid
            # false positives from read-only registry queries or re-enable
            # events.  Message-string tokens (e.g. "realtime protection
            # disabled") are self-qualifying, so they fire on any event.
            # Registry-value-name tokens (e.g. "disableantispyware") must
            # coincide with a create/modify timestamp_desc or a registry-
            # write parser to count as an actual disablement.
            _combined_text = message_l + " " + xml_l + " " + path_l
            _is_write_context = kind in {"create", "modify"} or (parser.startswith("winreg") and registry_write_context)
            _defender_hit = False
            for tok in defender_disable_tokens:
                if tok not in _combined_text:
                    continue
                # Multi-word tokens are descriptive log messages — self-qualifying.
                if " " in tok:
                    _defender_hit = True
                    break
                # Single-word tokens are registry value names — require write context.
                if _is_write_context:
                    _defender_hit = True
                    break
            if _defender_hit:
                signals, explain = ensure()
                signals["defender_disabled"] = max(float(signals.get("defender_disabled", 0.0) or 0.0), 1.0)
                explain.append({
                    "rule_id": "DEFENDER_DISABLED",
                    "description": "Defender disablement or real-time protection deactivation observed",
                    "confidence": "high",
                    "evidence_type": "direct",
                    "signals": ["defender_disabled"],
                    "evidence": {"message": message[:240], "path": path, "hostname": host},
                })

            if event_id in account_created_event_ids or any(tok in message_l for tok in account_created_message_tokens):
                signals, explain = ensure()
                signals["account_created"] = max(float(signals.get("account_created", 0.0) or 0.0), 1.0)
                explain.append({
                    "rule_id": "ACCOUNT_CREATED",
                    "description": "Account creation artefact observed",
                    "confidence": "medium",
                    "evidence_type": "direct",
                    "signals": ["account_created"],
                    "evidence": {"target_user": target_user, "message": message[:240], "event_identifier": event_id, "hostname": host},
                })

            privileged_text = " ".join(part for part in (group_name, message_l, xml_l) if part)
            privileged_group = any(tok in privileged_text for tok in windows_privileged_group_tokens)
            if event_id in privileged_group_change_event_ids and privileged_group:
                signals, explain = ensure()
                signals["privileged_account_created"] = max(float(signals.get("privileged_account_created", 0.0) or 0.0), 1.0)
                explain.append({
                    "rule_id": "PRIVILEGED_ACCOUNT_CREATED",
                    "description": "Account added to a privileged or remote-access group",
                    "confidence": "high",
                    "evidence_type": "direct",
                    "signals": ["privileged_account_created"],
                    "evidence": {"target_user": target_user, "group_name": group_name, "event_identifier": event_id, "hostname": host},
                })

        sched_rows: Dict[Tuple[str, str], List[Tuple[int, pd.Timestamp]]] = {}
        sched_window = pd.Timedelta(str(self.detection_thresholds_cfg.get("repeated_scheduled_exec_window", "10m")))
        sched_threshold = int(self.detection_thresholds_cfg.get("repeated_scheduled_exec_threshold", 3))
        for row_i in range(len(df)):
            existing = signal_map.get(row_i) or {}
            if not existing.get("scheduled_exec") and not existing.get("privileged_scheduled_exec"):
                continue
            cmd = _extract_scheduled_command_text_values(
                actor_cmd=actor_cmd_vals[row_i],
                command_line=command_line_vals[row_i],
                message=message_vals[row_i],
            ).strip().lower()
            if not cmd:
                continue
            host = _safe_str(host_vals[row_i]).strip().lower()
            sched_rows.setdefault((host, cmd), []).append((row_i, df.index[row_i]))

        for key, events in sched_rows.items():
            left = 0
            for right, (row_i, ts_now) in enumerate(events):
                while left < right and (ts_now - events[left][1]) > sched_window:
                    left += 1
                if (right - left + 1) >= sched_threshold:
                    signals = self._sparse_signal_dict(signal_map, row_i)
                    explain = self._sparse_explain_list(explain_map, row_i)
                    signals["repeated_scheduled_exec"] = max(float(signals.get("repeated_scheduled_exec", 0.0) or 0.0), 1.0)
                    explain.append({
                        "rule_id": "REPEATED_SCHEDULED_EXEC",
                        "description": "Repeated scheduled command execution observed within a bounded window",
                        "confidence": "medium",
                        "evidence_type": "direct",
                        "signals": ["repeated_scheduled_exec"],
                        "evidence": {
                            "hostname": key[0],
                            "command": key[1][:240],
                            "count_in_window": int(right - left + 1),
                            "window_seconds": int(sched_window.total_seconds()),
                        },
                    })
                    break

    def _apply_deadbox_direct_signals_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
        contextual_cache: Optional[Dict[Tuple[Any, ...], np.ndarray]] = None,
    ) -> None:
        if len(df) == 0:
            return

        nrows = len(df)
        file_paths = _contextual_file_paths(df, contextual_cache)
        path_lower = _contextual_path_lower(df, contextual_cache)
        timestamp_desc_vals = _contextual_text_array(df, contextual_cache, "timestamp_desc")
        kinds = _contextual_timestamp_kinds(df, contextual_cache)
        filename_vals = _column_values_or_none(df, "filename")
        actor_cmd_vals = _contextual_text_array(df, contextual_cache, "actor_cmd")
        cmdline_vals = _contextual_text_array(df, contextual_cache, "command_line")
        message_vals = _contextual_text_array(df, contextual_cache, "message")
        message_lower = _contextual_text_array(df, contextual_cache, "message", lower=True)
        http_request_vals = _contextual_text_array(df, contextual_cache, "http_request")
        http_headers_lower = _contextual_text_array(df, contextual_cache, "http_headers", lower=True)
        web_upload_names_vals = _contextual_text_array(df, contextual_cache, "chronosift_web_upload_names", lower=True)
        url_column = "actor_url" if "actor_url" in df.columns else "url"
        url_vals = _contextual_text_array(df, contextual_cache, url_column)
        host_vals = _contextual_text_array(df, contextual_cache, "hostname")
        event_vals = _contextual_text_array(df, contextual_cache, "event_identifier")
        target_user_vals = _contextual_text_array(df, contextual_cache, "target_user_name")
        group_vals = _contextual_text_array(df, contextual_cache, "group_name")
        group_lower = _contextual_text_array(df, contextual_cache, "group_name", lower=True)
        member_name_vals = _contextual_text_array(df, contextual_cache, "member_name")
        member_name_lower = _contextual_text_array(df, contextual_cache, "member_name", lower=True)
        share_name_vals = _contextual_text_array(df, contextual_cache, "share_name")
        share_name_lower = _contextual_text_array(df, contextual_cache, "share_name", lower=True)
        share_local_path_vals = _contextual_text_array(df, contextual_cache, "share_local_path")
        relative_target_vals = _contextual_text_array(df, contextual_cache, "relative_target_name")
        relative_target_lower = _contextual_text_array(df, contextual_cache, "relative_target_name", lower=True)
        actor_lower = _contextual_text_array(df, contextual_cache, "actor_principal", lower=True)
        auth_protocol_lower = _contextual_text_array(df, contextual_cache, "auth_protocol", lower=True)
        auth_outcome_lower = _contextual_text_array(df, contextual_cache, "auth_outcome", lower=True)
        logon_type_vals = _contextual_text_array(df, contextual_cache, "logon_type")
        workstation_vals = _contextual_text_array(df, contextual_cache, "workstation_name")
        workstation_lower = _contextual_text_array(df, contextual_cache, "workstation_name", lower=True)
        auth_pkg_lower = _contextual_text_array(df, contextual_cache, "authentication_package", lower=True)
        parser_lower = _contextual_text_array(df, contextual_cache, "parser", lower=True)
        xml_lower = _contextual_text_array(df, contextual_cache, "xml_string", lower=True)
        password_store_message_tokens = self._detection_terms("password_store_message_tokens")
        password_store_path_tokens = self._detection_terms("password_store_path_tokens")
        credential_copy_command_tokens = self._detection_terms("credential_copy_command_tokens")
        file_discovery_command_tokens = self._detection_terms("file_discovery_command_tokens")
        remote_discovery_command_tokens = self._detection_terms("remote_discovery_command_tokens")
        system_owner_discovery_command_tokens = self._detection_terms("system_owner_discovery_command_tokens")
        cleanup_command_tokens = self._detection_terms("cleanup_command_tokens")
        service_stop_command_tokens = self._detection_terms("service_stop_command_tokens")
        admin_share_tokens = self._detection_terms("admin_share_tokens")
        windows_remote_admin_pipe_tokens = self._detection_terms("windows_remote_admin_pipe_tokens")
        web_upload_tokens = self._detection_terms("web_upload_tokens")
        web_script_extensions = self._detection_terms("web_script_extensions")
        web_upload_endpoint_tokens = self._detection_terms("web_upload_endpoint_tokens")
        remote_service_message_tokens = self._detection_terms("remote_service_message_tokens")
        application_protocol_tokens = self._detection_terms("application_protocol_tokens")
        windows_privileged_group_tokens = self._detection_terms("windows_privileged_group_tokens")
        account_access_removed_message_tokens = self._detection_terms("account_access_removed_message_tokens")
        webshell_name_tokens = self._detection_terms("webshell_name_tokens")
        recovery_inhibit_command_tokens = self._detection_terms("recovery_inhibit_command_tokens")
        credential_dump_command_tokens = self._detection_terms("credential_dump_command_tokens")
        service_stopped_event_ids = self._detection_event_ids("service_stopped")
        share_access_event_ids = self._detection_event_ids("share_access")
        explicit_credential_logon_event_ids = self._detection_event_ids("explicit_credential_logon")
        account_disabled_event_ids = self._detection_event_ids("account_disabled")
        account_deleted_event_ids = self._detection_event_ids("account_deleted")
        group_removal_change_event_ids = self._detection_event_ids("group_removal_change")
        systemd_unit_extensions = self._detection_terms("systemd_unit_extensions")
        service_config_patterns = tuple(tok.replace("\\", "/") for tok in self._taxonomy_patterns("service_config_patterns"))
        web_root_patterns = tuple(tok.replace("\\", "/") for tok in self._taxonomy_patterns("web_root_patterns"))
        log_artifact_tokens = tuple(tok.replace("\\", "/") for tok in self._detection_terms("log_artifact_tokens"))
        web_log_parser_tokens = self._detection_terms("web_log_parser_tokens")
        admin_share_suffixes = ("\\c$", "\\admin$", "\\ipc$", "\\print$", "\\netlogon", "\\sysvol")
        web_script_extensions_set = set(web_script_extensions)
        systemd_unit_extensions_set = set(systemd_unit_extensions)

        direct_candidates = np.zeros(nrows, dtype=bool)
        if signal_map:
            existing_rows = np.fromiter(
                (row_i for row_i in signal_map.keys() if 0 <= row_i < nrows),
                dtype=np.int64,
            )
            direct_candidates[existing_rows] = True

        path_candidate_tokens = tuple(dict.fromkeys((
            *service_config_patterns,
            *password_store_path_tokens,
            *log_artifact_tokens,
            *web_root_patterns,
            "/authorized_keys", "lsass", "/ntds.dit", "\\ntds.dit",
        )))
        direct_candidates |= _text_array_contains_any(path_lower, path_candidate_tokens)

        message_candidate_tokens = tuple(dict.fromkeys((
            *recovery_inhibit_command_tokens,
            *credential_dump_command_tokens,
            *password_store_message_tokens,
            *credential_copy_command_tokens,
            *file_discovery_command_tokens,
            *remote_discovery_command_tokens,
            *system_owner_discovery_command_tokens,
            *cleanup_command_tokens,
            *service_stop_command_tokens,
            *admin_share_tokens,
            *windows_remote_admin_pipe_tokens,
            *web_upload_tokens,
            *remote_service_message_tokens,
            *application_protocol_tokens,
            *account_access_removed_message_tokens,
            *webshell_name_tokens,
            "systemctl enable", "systemctl link", "systemctl preset", "daemon-reload",
            "systemctl start", "systemctl restart", "../", "..\\", "/etc/passwd",
            "cmd=", "exec=", "shell=", "multipart/form-data", "stopped", "sshd", "\\",
        )))
        direct_candidates |= _text_array_contains_any(message_lower, message_candidate_tokens)
        direct_candidates |= actor_cmd_vals != ""
        direct_candidates |= cmdline_vals != ""
        direct_candidates |= url_vals != ""
        direct_candidates |= http_request_vals != ""
        direct_candidates |= web_upload_names_vals != ""
        direct_candidates |= auth_protocol_lower != ""
        direct_candidates |= auth_outcome_lower != ""
        direct_candidates |= logon_type_vals != ""
        relevant_event_ids = (
            service_stopped_event_ids
            | share_access_event_ids
            | explicit_credential_logon_event_ids
            | account_disabled_event_ids
            | account_deleted_event_ids
            | group_removal_change_event_ids
        )
        if relevant_event_ids:
            direct_candidates |= np.isin(event_vals, tuple(relevant_event_ids))
        direct_candidates |= _text_array_contains_any(parser_lower, web_log_parser_tokens)

        for row_i in np.flatnonzero(direct_candidates):
            path = file_paths[row_i]
            path_l = path_lower[row_i]
            kind = kinds[row_i]
            actor_cmd = actor_cmd_vals[row_i]
            cmdline = cmdline_vals[row_i]
            message = message_vals[row_i]
            message_l = message_lower[row_i]
            url_text = url_vals[row_i]
            url_evidence = url_text[:240]
            combined = " ".join(part for part in (actor_cmd, cmdline, message, url_text) if part).lower()
            combined_norm = combined.replace("\\ ", " ")
            host = host_vals[row_i]
            actor = actor_lower[row_i]
            event_id = event_vals[row_i]
            target_user = target_user_vals[row_i]
            group_name = group_vals[row_i]
            group_name_l = group_lower[row_i]
            member_name = member_name_vals[row_i]
            member_name_l = member_name_lower[row_i]
            share_name = share_name_vals[row_i]
            share_local_path = share_local_path_vals[row_i]
            relative_target_name = relative_target_vals[row_i]
            share_name_l = share_name_lower[row_i]
            relative_target_name_l = relative_target_lower[row_i]
            auth_protocol = auth_protocol_lower[row_i]
            auth_outcome = auth_outcome_lower[row_i]
            logon_type = logon_type_vals[row_i]
            workstation_name = workstation_vals[row_i]
            workstation_name_l = workstation_lower[row_i]
            auth_package = auth_pkg_lower[row_i]
            parser = parser_lower[row_i]
            xml_l = xml_lower[row_i]
            web_log_parser = bool(parser and any(tok in parser for tok in web_log_parser_tokens))
            existing = signal_map.get(row_i) or {}

            def emit(signal_name: str, description: str, confidence: str, evidence: Dict[str, Any]) -> None:
                sig = self._sparse_signal_dict(signal_map, row_i)
                if float(sig.get(signal_name, 0.0) or 0.0) >= 1.0:
                    return
                sig[signal_name] = 1.0
                expl = self._sparse_explain_list(explain_map, row_i)
                expl.append({
                    "rule_id": signal_name.upper(),
                    "description": description,
                    "confidence": confidence,
                    "evidence_type": "direct",
                    "signals": [signal_name],
                    "evidence": evidence,
                })

            systemd_unit_path_hit = bool(
                path_l
                and any(tok in path_l for tok in service_config_patterns)
                and os.path.splitext(path_l)[1] in systemd_unit_extensions_set
            )
            if systemd_unit_path_hit and kind in {"create", "modify", "delete"}:
                emit(
                    "systemd_service_persistence",
                    "Systemd unit artefact changed under a service manager path",
                    "high",
                    {"path": path, "timestamp_desc": timestamp_desc_vals[row_i][:120], "hostname": host},
                )
            else:
                persistent_systemd_cmd = any(tok in combined for tok in ("systemctl enable", "systemctl link", "systemctl preset", "daemon-reload"))
                transient_systemd_cmd = any(tok in combined for tok in ("systemctl start", "systemctl restart"))
                systemd_unit_ref = any(ext in combined for ext in systemd_unit_extensions) or any(
                    tok in combined for tok in ("/etc/systemd/", "/lib/systemd/system/", "/usr/lib/systemd/system/", "/run/systemd/system/")
                )
                if combined and (persistent_systemd_cmd or (transient_systemd_cmd and systemd_unit_ref)):
                    emit(
                        "systemd_service_persistence",
                        "Systemd enablement or unit-management semantics observed in command or log text",
                        "medium",
                        {"command": actor_cmd[:240], "message": message[:240], "hostname": host},
                    )

            if path_l.endswith("/authorized_keys") and kind in {"create", "modify", "delete"}:
                signal_name = "authorized_keys_root_persistence" if "/root/" in path_l else "authorized_keys_persistence"
                emit(
                    signal_name,
                    "SSH authorized_keys artefact changed",
                    "high" if signal_name == "authorized_keys_root_persistence" else "medium",
                    {"path": path, "timestamp_desc": timestamp_desc_vals[row_i][:120], "actor_user": actor},
                )

            if float(existing.get("exec_system_binary_in_user_path", 0.0) or 0.0) > 0.0:
                emit(
                    "masquerading",
                    "Trusted or system binary name executed from an unexpected user-writable or suspicious path",
                    "medium",
                    {"path": path, "command": actor_cmd[:240], "hostname": host},
                )

            if combined and any(tok in combined for tok in recovery_inhibit_command_tokens):
                emit(
                    "inhibit_system_recovery",
                    "System recovery inhibition command semantics observed",
                    "high",
                    {"command": actor_cmd[:240], "message": message[:240], "hostname": host},
                )

            if combined and any(tok in combined for tok in credential_dump_command_tokens):
                emit(
                    "credential_dumping",
                    "Credential dumping command semantics observed",
                    "medium",
                    {"command": actor_cmd[:240], "message": message[:240], "path": path},
                )
            elif path_l and ("lsass" in path_l or path_l.endswith("/ntds.dit") or path_l.endswith("\\ntds.dit")) and kind in {"create", "modify"}:
                emit(
                    "credential_dumping",
                    "Credential-store or dump artefact created or modified",
                    "low",
                    {"path": path, "timestamp_desc": timestamp_desc_vals[row_i][:120]},
                )

            password_store_message_hit = any(tok in combined_norm for tok in password_store_message_tokens)
            credential_copy_hit = any(tok in combined_norm for tok in credential_copy_command_tokens)
            if path_l and any(tok in path_l for tok in password_store_path_tokens) and kind in {"access", "modify", "create"}:
                emit(
                    "password_store_access",
                    "Password-store or credential-container artefact was accessed or changed",
                    "low",
                    {"path": path, "timestamp_desc": timestamp_desc_vals[row_i][:120], "kind": kind},
                )
            elif password_store_message_hit and credential_copy_hit:
                emit(
                    "password_store_access",
                    "Command semantics indicate password-store or credential-container copying or staging",
                    "medium",
                    {"command": actor_cmd[:240], "message": message[:240]},
                )

            has_cmd_context = bool(actor_cmd or cmdline)
            discovery_command = (actor_cmd or cmdline)[:240]
            file_discovery_hit = has_cmd_context and any(tok in combined for tok in file_discovery_command_tokens)
            remote_discovery_hit = has_cmd_context and any(tok in combined for tok in remote_discovery_command_tokens)
            identity_discovery_hit = has_cmd_context and any(tok in combined for tok in system_owner_discovery_command_tokens)
            discovery_category_count = int(bool(file_discovery_hit)) + int(bool(remote_discovery_hit)) + int(bool(identity_discovery_hit))
            multi_command_discovery = any(sep in combined for sep in ("&&", "||", ";", " | "))
            high_fidelity_file_discovery = any(tok in combined for tok in ("find ", "tree ", "locate ", "grep "))
            high_fidelity_identity_discovery = any(tok in combined for tok in ("uname -a", "ipconfig", "ifconfig"))

            if file_discovery_hit and (discovery_category_count >= 2 or multi_command_discovery or high_fidelity_file_discovery):
                emit(
                    "file_and_directory_discovery",
                    "File or directory discovery command semantics observed",
                    "low",
                    {"command": discovery_command, "message": message[:240]},
                )

            if remote_discovery_hit:
                emit(
                    "remote_system_discovery",
                    "Remote-system discovery command semantics observed",
                    "low",
                    {"command": discovery_command, "message": message[:240]},
                )

            if identity_discovery_hit and (discovery_category_count >= 2 or multi_command_discovery or high_fidelity_identity_discovery):
                emit(
                    "system_owner_user_discovery",
                    "System owner or host identity discovery command semantics observed",
                    "low",
                    {"command": discovery_command, "message": message[:240]},
                )

            if combined and any(tok in combined for tok in cleanup_command_tokens):
                emit(
                    "indicator_removal_on_host",
                    "Cleanup or log/history clearing command semantics observed",
                    "medium",
                    {"command": actor_cmd[:240], "message": message[:240]},
                )
            elif kind == "delete" and path_l and any(tok in path_l for tok in log_artifact_tokens):
                emit(
                    "indicator_removal_on_host",
                    "Log or shell-history artefact deletion observed",
                    "medium",
                    {"path": path, "timestamp_desc": timestamp_desc_vals[row_i][:120]},
                )

            if combined and any(tok in combined for tok in service_stop_command_tokens):
                emit(
                    "service_stop",
                    "Service or process termination command semantics observed (T1489)",
                    "medium",
                    {"command": actor_cmd[:240], "message": message[:240], "hostname": host},
                )
            elif event_id in service_stopped_event_ids and "stopped" in message_l:
                emit(
                    "service_stop",
                    "Windows Service Control Manager reports service entered stopped state (T1489)",
                    "low",
                    {"event_identifier": event_id, "message": message[:240], "hostname": host},
                )

            unc_match = _UNC_PATH_RE.search(actor_cmd) or _UNC_PATH_RE.search(cmdline) or _UNC_PATH_RE.search(message)
            if combined and any(tok in combined for tok in admin_share_tokens):
                emit(
                    "smb_admin_share",
                    "Administrative share path observed in command, message, or URL text",
                    "medium",
                    {"command": actor_cmd[:240], "message": message[:240], "url": url_evidence},
                )
            elif unc_match:
                emit(
                    "smb_admin_share",
                    "UNC administrative share pattern observed",
                    "medium",
                    {"command": actor_cmd[:240], "message": message[:240], "unc_path": unc_match.group(0)[:240]},
                )
            elif event_id in share_access_event_ids and (
                any(tok in share_name_l for tok in admin_share_tokens)
                or share_name_l.endswith(admin_share_suffixes)
            ):
                emit(
                    "smb_admin_share",
                    "Windows share-access event references an administrative or lateral-movement share",
                    "medium",
                    {
                        "event_identifier": event_id,
                        "share_name": share_name[:240],
                        "share_local_path": share_local_path[:240],
                        "relative_target_name": relative_target_name[:240],
                    },
                )
            remote_admin_pipe = event_id in share_access_event_ids and any(
                tok in relative_target_name_l for tok in windows_remote_admin_pipe_tokens
            )
            admin_share_event = event_id in share_access_event_ids and (
                any(tok in share_name_l for tok in admin_share_tokens)
                or share_name_l.endswith(admin_share_suffixes)
            )
            if admin_share_event or remote_admin_pipe:
                emit(
                    "external_remote_service",
                    "Windows share-access semantics indicate remote administrative service or named-pipe activity",
                    "medium" if remote_admin_pipe else "low",
                    {
                        "event_identifier": event_id,
                        "share_name": share_name[:240],
                        "relative_target_name": relative_target_name[:240],
                        "share_local_path": share_local_path[:240],
                    },
                )
            elif auth_outcome == "success" and logon_type == "3" and (
                float(existing.get("auth_service_logon", 0.0) or 0.0) > 0.0
                or float(existing.get("auth_newcredentials_logon", 0.0) or 0.0) > 0.0
                or (
                    float(existing.get("lateral_movement_indicator", 0.0) or 0.0) > 0.0
                    and auth_package in {"ntlm", "negotiate"}
                )
                or (
                    auth_package in {"ntlm", "negotiate"}
                    and bool(workstation_name)
                )
            ):
                emit(
                    "smb_admin_share",
                    "Network logon semantics and lateral-movement context suggest SMB or administrative share use",
                    "low",
                    {
                        "event_identifier": event_id,
                        "logon_type": logon_type,
                        "target_user": target_user,
                        "authentication_package": auth_package,
                        "workstation_name": workstation_name,
                    },
                )

            upload_hint = any(tok in combined for tok in web_upload_tokens)
            header_l = http_headers_lower[row_i]
            request_semantics = web_log_parser or bool(url_text) or bool(http_request_vals[row_i])
            http_path = ""
            http_method = ""
            if request_semantics:
                http_sem = _extract_http_request_semantics(message, http_request_vals[row_i], url_text)
                http_path = _safe_str(http_sem.get("path")).strip().lower()
                http_method = _safe_str(http_sem.get("method")).strip().upper()
            _path_check = http_path or path_l or ""
            web_script_target = bool(_path_check) and any(
                _path_check.endswith(ext) or f"{ext}?" in _path_check for ext in web_script_extensions
            )
            upload_names = [name for name in web_upload_names_vals[row_i].split("|") if name]
            upload_name = upload_names[0] if upload_names else ""
            upload_endpoint = any(tok in http_path for tok in web_upload_endpoint_tokens)
            upload_request = (
                upload_hint
                or bool(upload_names)
                or http_method == "PUT"
                or "multipart/form-data" in header_l
                or (http_method == "POST" and upload_endpoint)
            )
            if request_semantics and upload_request and not upload_names:
                upload_name = _safe_str(
                    _extract_http_upload_name(
                        message,
                        http_request_vals[row_i],
                        url_text,
                        http_path,
                    )
                ).strip().lower()
                if upload_name:
                    upload_names = [upload_name]
            uploaded_script = any(
                name.endswith(ext) for name in upload_names for ext in web_script_extensions
            )
            suspicious_web_exec = "cmd=" in combined or "exec=" in combined or "shell=" in combined
            if request_semantics and upload_request and (uploaded_script or (http_method == "PUT" and web_script_target)):
                emit(
                    "exploit_public_facing_app",
                    "Web-log request shows file-upload semantics targeting an executable web script",
                    "high",
                    {
                        "message": message[:240],
                        "url": url_evidence,
                        "parser": parser,
                        "http_method": http_method,
                        "http_path": http_path[:240],
                        "upload_name": upload_name[:120],
                        "upload_names": "|".join(upload_names)[:480],
                    },
                )
            elif combined and ("../" in combined or "..\\" in combined or "/etc/passwd" in combined or suspicious_web_exec):
                emit(
                    "exploit_public_facing_app",
                    "Web request or log text contains public-facing application exploitation indicators",
                    "medium" if request_semantics else "low",
                    {
                        "message": message[:240],
                        "url": url_evidence,
                        "parser": parser,
                        "http_method": http_method,
                        "http_path": http_path[:240],
                    },
                )
            elif (
                float(existing.get("web_exploitation_hint", 0.0) or 0.0) > 0.0
                or float(existing.get("web_sqli_probable_success", 0.0) or 0.0) > 0.0
            ):
                emit(
                    "exploit_public_facing_app",
                    "Suspicious web request path indicators suggest public-facing exploitation",
                    "low",
                    {"url": url_evidence, "message": message[:240]},
                )

            windows_remote_service = auth_protocol == "windows-network" and (
                event_id in share_access_event_ids
                or float(existing.get("smb_admin_share", 0.0) or 0.0) > 0.0
                or float(existing.get("auth_newcredentials_logon", 0.0) or 0.0) > 0.0
                or float(existing.get("auth_ntlm_remote", 0.0) or 0.0) > 0.0
            )
            if auth_outcome == "success" and (
                (auth_protocol in {"ssh", "rdp"} and (
                    parser.startswith("winevt")
                    or "sshd" in combined
                    or any(tok in combined for tok in remote_service_message_tokens)
                ))
                or windows_remote_service
            ):
                emit(
                    "external_remote_service",
                    "Successful remote-service access semantics observed",
                    "low",
                    {
                        "auth_protocol": auth_protocol,
                        "target_user": target_user or actor,
                        "event_identifier": event_id,
                        "share_name": share_name[:240],
                    },
                )

            if (auth_outcome == "success" or event_id in explicit_credential_logon_event_ids) and (
                float(existing.get("auth_newcredentials_logon", 0.0) or 0.0) > 0.0
                or float(existing.get("auth_ntlm_remote", 0.0) or 0.0) > 0.0
                or event_id in explicit_credential_logon_event_ids
            ):
                emit(
                    "alternate_auth_material",
                    "Authentication semantics suggest alternate credential material, explicit credentials, or NTLM-based access",
                    "low",
                    {"event_identifier": event_id, "logon_type": logon_type, "auth_protocol": auth_protocol},
                )

            if combined and any(tok in combined for tok in application_protocol_tokens):
                emit(
                    "application_layer_protocol",
                    "Application-layer protocol indicator observed in command, URL, or message text",
                    "low",
                    {"command": actor_cmd[:240], "url": url_evidence, "message": message[:240]},
                )
            elif float(existing.get("data_transfer_tool_exec", 0.0) or 0.0) > 0.0 or float(existing.get("large_http_transfer", 0.0) or 0.0) > 0.0:
                emit(
                    "application_layer_protocol",
                    "Transfer tooling or HTTP transfer suggests application-layer protocol use",
                    "low",
                    {"command": actor_cmd[:240], "url": url_evidence},
                )

            privileged_text = " ".join(part for part in (message_l, combined, xml_l, member_name_l, workstation_name_l) if part)
            privileged_group_removed = event_id in group_removal_change_event_ids and any(
                tok in " ".join(part for part in (group_name_l, privileged_text) if part)
                for tok in windows_privileged_group_tokens
            )
            if (
                event_id in account_disabled_event_ids
                or event_id in account_deleted_event_ids
                or event_id in group_removal_change_event_ids
                or any(tok in privileged_text for tok in account_access_removed_message_tokens)
            ):
                emit(
                    "account_access_removal",
                    "Account disablement, deletion, or privilege removal semantics observed",
                    "medium" if (
                        event_id in (account_disabled_event_ids | account_deleted_event_ids)
                        or privileged_group_removed
                    ) else "low",
                    {
                        "event_identifier": event_id,
                        "target_user": target_user or member_name,
                        "member_name": member_name,
                        "message": message[:240],
                        "group_name": group_name[:120],
                    },
                )

            if path_l and any(tok in path_l for tok in web_root_patterns) and os.path.splitext(path_l)[1] in web_script_extensions_set:
                base = os.path.basename(path_l)
                suspicious_name = any(tok in base for tok in webshell_name_tokens)
                suspicious_upload_path = upload_hint or "multipart/form-data" in combined
                if suspicious_name or suspicious_upload_path or float(existing.get("referenced_file_yara_hit", 0.0) or 0.0) > 0.0 or float(existing.get("referenced_file_av_hit", 0.0) or 0.0) > 0.0:
                    emit(
                        "webshell_artifact",
                        "Executable script under a web root exhibits web-shell-like naming or malware support",
                        "medium",
                        {"path": path, "filename": filename_vals[row_i], "message": message[:240]},
                    )

    def _apply_deadbox_temporal_composites_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
    ) -> None:
        if len(df) == 0 or not isinstance(df.index, pd.DatetimeIndex):
            return

        download_window = pd.Timedelta(str(self.detection_thresholds_cfg.get("download_exec_window", "2h")))
        webshell_window = pd.Timedelta(str(self.detection_thresholds_cfg.get("webshell_activity_window", "30m")))
        auto_exfil_window = pd.Timedelta(str(self.detection_thresholds_cfg.get("automated_exfiltration_window", "30m")))
        auto_exfil_threshold = int(self.detection_thresholds_cfg.get("automated_exfiltration_threshold", 2))
        credential_window = pd.Timedelta(str(self.detection_thresholds_cfg.get("credential_collection_window", "1h")))
        credential_copy_tokens = self._detection_terms("credential_copy_command_tokens")
        password_store_tokens = self._detection_terms("password_store_message_tokens")
        ransom_note_name_tokens = self._detection_terms("ransom_note_name_tokens")
        web_execution_context_tokens = (
            "/var/www/",
            "/srv/www/",
            "inetpub",
            "wwwroot",
            ".php",
            ".aspx",
            ".jsp",
            ".jspx",
            ".ashx",
        )

        filename_vals = df["filename"].values if "filename" in df.columns else np.array([None] * len(df), dtype=object)
        # Hostname is unreliable in dead-box images: blank, inconsistent, or
        # filled with crud.  Use a single global sentinel so all events
        # correlate as one host (which is the ground truth for a single image).
        # The raw hostname is kept only for evidence/explain output.
        _DEADBOX_HOST_SENTINEL = "__deadbox__"
        host_vals = df["hostname"].values if "hostname" in df.columns else np.array([None] * len(df), dtype=object)
        message_vals = df["message"].values if "message" in df.columns else np.array([None] * len(df), dtype=object)
        cmdline_vals = df["command_line"].values if "command_line" in df.columns else np.array([None] * len(df), dtype=object)
        # Vectorised file path coalesce
        path_vals = _best_effort_file_path_vectorised(df).to_numpy(copy=False)
        path_norm = [_safe_str(v).strip().lower().replace("\\", "/") for v in path_vals]
        filename_lower = [_safe_str(v).strip().lower() for v in filename_vals]
        message_lower = [_safe_str(v).strip().lower() for v in message_vals]
        cmdline_lower = [_safe_str(v).strip().lower() for v in cmdline_vals]

        download_events: Dict[Tuple[str, str], List[Tuple[int, pd.Timestamp]]] = {}
        webshell_events: Dict[str, List[Tuple[int, pd.Timestamp]]] = {}
        transfer_events: Dict[str, List[Tuple[int, pd.Timestamp, Set[str]]]] = {}
        archive_events: Dict[str, List[Tuple[int, pd.Timestamp, Set[str]]]] = {}
        copy_stage_events: Dict[str, List[Tuple[int, pd.Timestamp, Set[str]]]] = {}
        sensitive_events: Dict[str, List[Tuple[int, pd.Timestamp]]] = {}
        impact_support_events: Dict[str, List[Tuple[int, pd.Timestamp]]] = {}
        ransom_note_events: Dict[str, List[Tuple[int, pd.Timestamp]]] = {}

        # Pre-compute per-row derived values in pass 1 and cache for reuse in pass 2,
        # avoiding redundant _safe_str / os.path.basename / label-extraction calls.
        n_rows = len(df)
        _cached_host = [None] * n_rows
        _cached_path = [None] * n_rows
        _cached_base = [None] * n_rows
        _cached_combined_norm = [None] * n_rows
        _cached_password_labels: List[Set[str]] = [set()] * n_rows
        _cached_dump_labels: List[Set[str]] = [set()] * n_rows
        ts_vals = list(df.index)

        for row_i in range(n_rows):
            signals = signal_map.get(row_i) or {}
            host = _DEADBOX_HOST_SENTINEL
            path = path_norm[row_i]
            base = os.path.basename(path) if path else os.path.basename(filename_lower[row_i])
            ts = ts_vals[row_i]
            combined = " ".join(part for part in (
                message_lower[row_i],
                cmdline_lower[row_i],
                path,
                base,
            ) if part)
            combined_norm = combined.replace("\\ ", " ")
            password_labels = self._extract_password_store_labels(path, base, combined_norm)
            dump_labels = self._extract_credential_dump_labels(path, base, combined_norm)
            artifact_labels = password_labels | dump_labels

            _cached_host[row_i] = host
            _cached_path[row_i] = path
            _cached_base[row_i] = base
            _cached_combined_norm[row_i] = combined_norm
            _cached_password_labels[row_i] = password_labels
            _cached_dump_labels[row_i] = dump_labels

            if float(signals.get("browser_download", 0.0) or 0.0) > 0.0 and base:
                download_events.setdefault((host, base), []).append((row_i, ts))
            if float(signals.get("webshell_artifact", 0.0) or 0.0) > 0.0:
                webshell_events.setdefault(host, []).append((row_i, ts))
            if (
                float(signals.get("transfer_execution", 0.0) or 0.0) > 0.0
                or float(signals.get("data_transfer_tool_exec", 0.0) or 0.0) > 0.0
                or float(signals.get("staging_then_transfer", 0.0) or 0.0) > 0.0
                or float(signals.get("large_http_transfer", 0.0) or 0.0) > 0.0
            ):
                transfer_events.setdefault(host, []).append((row_i, ts, set(artifact_labels)))
            if (
                float(signals.get("archive_created", 0.0) or 0.0) > 0.0
                or float(signals.get("large_archive_created", 0.0) or 0.0) > 0.0
            ):
                archive_events.setdefault(host, []).append((row_i, ts, set(artifact_labels)))
            if any(tok in combined_norm for tok in credential_copy_tokens) and (
                any(tok in combined_norm for tok in password_store_tokens)
                or float(signals.get("credential_dumping", 0.0) or 0.0) > 0.0
                or float(signals.get("password_store_access", 0.0) or 0.0) > 0.0
            ):
                copy_stage_events.setdefault(host, []).append((row_i, ts, set(artifact_labels)))
            if float(signals.get("sensitive_file_access", 0.0) or 0.0) > 0.0 or float(signals.get("password_store_access", 0.0) or 0.0) > 0.0:
                sensitive_events.setdefault(host, []).append((row_i, ts))
            if (
                float(signals.get("defender_disabled", 0.0) or 0.0) > 0.0
                or float(signals.get("inhibit_system_recovery", 0.0) or 0.0) > 0.0
                or float(signals.get("suspicious_execution", 0.0) or 0.0) > 0.0
            ):
                impact_support_events.setdefault(host, []).append((row_i, ts))
            if base and any(tok in base for tok in ransom_note_name_tokens) and path:
                ransom_note_events.setdefault(host, []).append((row_i, ts))

        # ── Build sorted timestamp indices for O(log n) window lookups ─────
        # For each accumulator, extract per-host sorted timestamp arrays so
        # pass 2 can use bisect instead of linear scans.  This converts O(n²)
        # temporal window checks into O(n log n) overall.

        def _build_ts_index_2(events_dict):
            """Build {host: sorted_ts_list} from 2-tuple accumulators."""
            return {k: [t for _, t in v] for k, v in events_dict.items()}

        def _build_ts_index_3(events_dict):
            """Build {host: sorted_ts_list} from 3-tuple accumulators."""
            return {k: [t for _, t, _ in v] for k, v in events_dict.items()}

        download_ts_idx = _build_ts_index_2(download_events)
        webshell_ts_idx = _build_ts_index_2(webshell_events)
        transfer_ts_idx = _build_ts_index_3(transfer_events)
        archive_ts_idx = _build_ts_index_3(archive_events)
        follow_on_events: Dict[str, List[Tuple[int, pd.Timestamp, Set[str]]]] = {}
        for host_key in set(archive_events) | set(transfer_events):
            combined_events = list(archive_events.get(host_key, ()))
            combined_events.extend(transfer_events.get(host_key, ()))
            combined_events.sort(key=lambda event: event[1])
            follow_on_events[host_key] = combined_events
        follow_on_ts_idx = _build_ts_index_3(follow_on_events)
        copy_stage_ts_idx = _build_ts_index_3(copy_stage_events)
        sensitive_ts_idx = _build_ts_index_2(sensitive_events)
        impact_support_ts_idx = _build_ts_index_2(impact_support_events)
        ransom_note_ts_idx = _build_ts_index_2(ransom_note_events)

        def _any_in_window_before(ts_idx, events_dict, key, ts, window):
            """Check if any event with key exists in [ts - window, ts].  O(log n)."""
            sorted_ts = ts_idx.get(key)
            if not sorted_ts:
                return False, None
            lo = bisect.bisect_left(sorted_ts, ts - window)
            hi = bisect.bisect_right(sorted_ts, ts)
            if lo < hi:
                ev = events_dict[key][lo]
                return True, ev
            return False, None

        def _any_in_window_after(ts_idx, events_dict, key, ts, window):
            """Check if any event with key exists in [ts, ts + window].  O(log n)."""
            sorted_ts = ts_idx.get(key)
            if not sorted_ts:
                return False, None
            lo = bisect.bisect_left(sorted_ts, ts)
            hi = bisect.bisect_right(sorted_ts, ts + window)
            if lo < hi:
                ev = events_dict[key][lo]
                return True, ev
            return False, None

        def _count_in_window_before(ts_idx, key, ts, window):
            """Count events with key in [ts - window, ts].  O(log n)."""
            sorted_ts = ts_idx.get(key)
            if not sorted_ts:
                return 0
            lo = bisect.bisect_left(sorted_ts, ts - window)
            hi = bisect.bisect_right(sorted_ts, ts)
            return hi - lo

        def _has_labelled_follow_on_bisect(
            events_dict,
            ts_idx,
            host_key: str,
            labels: Set[str],
            start_ts,
        ) -> bool:
            """Check labelled 3-tuple events in [start_ts, start_ts + credential_window].  O(log n + k_window)."""
            sorted_ts = ts_idx.get(host_key)
            if not sorted_ts:
                return False
            lo = bisect.bisect_left(sorted_ts, start_ts)
            hi = bisect.bisect_right(sorted_ts, start_ts + credential_window)
            candidates = events_dict.get(host_key, [])
            for idx in range(lo, hi):
                _, _, ev_labels = candidates[idx]
                if not labels or ev_labels.intersection(labels):
                    return True
            return False

        def _has_staged_then_exfil_bisect(host_key: str, labels: Set[str], start_ts) -> bool:
            """Check staged → exfil chain using bisect.  O(log n + k_window × log n).

            Both the copy-stage event AND the subsequent archive/transfer event
            must match the requested artifact labels (when labels are provided)
            to avoid correlating unrelated host-level coincidences.
            """
            cs_sorted_ts = copy_stage_ts_idx.get(host_key)
            if not cs_sorted_ts:
                return False
            cs_lo = bisect.bisect_left(cs_sorted_ts, start_ts)
            cs_hi = bisect.bisect_right(cs_sorted_ts, start_ts + credential_window)
            cs_events = copy_stage_events.get(host_key, [])
            for cs_idx in range(cs_lo, cs_hi):
                _, stage_ts, stage_labels = cs_events[cs_idx]
                if labels and not stage_labels.intersection(labels):
                    continue
                # Check archive or transfer after stage_ts within credential_window.
                # Require the exfil hop to also carry matching artifact labels.
                sorted_ts = follow_on_ts_idx.get(host_key)
                if not sorted_ts:
                    continue
                ex_lo = bisect.bisect_left(sorted_ts, stage_ts)
                ex_hi = bisect.bisect_right(sorted_ts, stage_ts + credential_window)
                host_events = follow_on_events.get(host_key, [])
                for ex_idx in range(ex_lo, ex_hi):
                    _, _, exfil_labels = host_events[ex_idx]
                    if not labels or exfil_labels.intersection(labels):
                        return True
            return False

        def _any_follow_on_unlabelled_bisect(host_key: str, start_ts) -> bool:
            """Fallback: any archive/transfer/copy event in [start_ts, start_ts + credential_window].  O(log n)."""
            for ts_index in (follow_on_ts_idx, copy_stage_ts_idx):
                sorted_ts = ts_index.get(host_key)
                if not sorted_ts:
                    continue
                lo = bisect.bisect_left(sorted_ts, start_ts)
                hi = bisect.bisect_right(sorted_ts, start_ts + credential_window)
                if lo < hi:
                    return True
            return False

        for row_i in range(n_rows):
            signals = signal_map.get(row_i) or {}
            host = _cached_host[row_i]  # sentinel for correlation keying
            raw_hostname = _safe_str(host_vals[row_i]).strip()  # original for evidence
            path = _cached_path[row_i]
            base = _cached_base[row_i]
            ts = ts_vals[row_i]
            combined_norm = _cached_combined_norm[row_i]
            password_labels = _cached_password_labels[row_i]
            dump_labels = _cached_dump_labels[row_i]

            def emit(signal_name: str, description: str, confidence: str, evidence: Dict[str, Any]) -> None:
                sig = self._sparse_signal_dict(signal_map, row_i)
                if float(sig.get(signal_name, 0.0) or 0.0) >= 1.0:
                    return
                sig[signal_name] = 1.0
                expl = self._sparse_explain_list(explain_map, row_i)
                expl.append({
                    "rule_id": signal_name.upper(),
                    "description": description,
                    "confidence": confidence,
                    "evidence_type": "contextual",
                    "signals": [signal_name],
                    "evidence": evidence,
                })

            execution_like = any(float(signals.get(name, 0.0) or 0.0) > 0.0 for name in (
                "suspicious_execution",
                "prefetch_execution",
                "amcache_execution",
                "execution_lolbin",
                "execution_interpreter",
            ))

            if base and execution_like:
                found, ev = _any_in_window_before(download_ts_idx, download_events, (host, base), ts, download_window)
                if found:
                    dl_ts = ev[1]
                    emit(
                        "user_execution_after_download",
                        "Downloaded item was executed within a bounded window",
                        "medium",
                        {"filename": base, "download_timestamp": dl_ts.isoformat(), "execution_timestamp": ts.isoformat(), "hostname": raw_hostname},
                    )
                    emit(
                        "ingress_tool_transfer",
                        "Downloaded or retrieved tool was subsequently executed",
                        "medium",
                        {"filename": base, "download_timestamp": dl_ts.isoformat(), "execution_timestamp": ts.isoformat(), "hostname": raw_hostname},
                    )

            if float(signals.get("web_exploitation_hint", 0.0) or 0.0) > 0.0 or float(signals.get("exploit_public_facing_app", 0.0) or 0.0) > 0.0:
                found, ev = _any_in_window_before(webshell_ts_idx, webshell_events, host, ts, webshell_window)
                if found:
                    ws_ts = ev[1]
                    emit(
                        "webshell_activity",
                        "Web-shell-like file artefact and suspicious web request activity co-occurred within a bounded window",
                        "high",
                        {"hostname": raw_hostname, "artifact_timestamp": ws_ts.isoformat(), "request_timestamp": ts.isoformat()},
                    )

            web_execution_context = any(tok in combined_norm for tok in web_execution_context_tokens)
            if execution_like and (web_execution_context or self._looks_like_web_root_path(path)):
                found, ev = _any_in_window_before(webshell_ts_idx, webshell_events, host, ts, webshell_window)
                if found:
                    ws_ts = ev[1]
                    emit(
                        "web_upload_execution_chain",
                        "Web-root script artefact was followed by suspicious execution within a bounded window",
                        "medium",
                        {"hostname": raw_hostname, "artifact_timestamp": ws_ts.isoformat(), "execution_timestamp": ts.isoformat()},
                    )

            ransomware_source = (
                float(signals.get("mass_file_modification", 0.0) or 0.0) > 0.0
                or float(signals.get("ransomware_extension_burst", 0.0) or 0.0) > 0.0
                or float(signals.get("yara_ransomware", 0.0) or 0.0) > 0.0
                or float(signals.get("av_ransomware", 0.0) or 0.0) > 0.0
            )
            if ransomware_source:
                found, ev = _any_in_window_before(impact_support_ts_idx, impact_support_events, host, ts, download_window)
                if found:
                    support_ts = ev[1]
                    emit(
                        "ransomware_impact",
                        "Ransomware-like activity followed defense impairment, recovery inhibition, or suspicious execution within a bounded window",
                        "medium",
                        {
                            "hostname": raw_hostname,
                            "mass_file_modification": float(signals.get("mass_file_modification", 0.0) or 0.0) > 0.0,
                            "ransomware_extension_burst": float(signals.get("ransomware_extension_burst", 0.0) or 0.0) > 0.0,
                            "yara_ransomware": float(signals.get("yara_ransomware", 0.0) or 0.0) > 0.0,
                            "av_ransomware": float(signals.get("av_ransomware", 0.0) or 0.0) > 0.0,
                            "support_timestamp": support_ts.isoformat(),
                        },
                    )
                else:
                    found_note, ev_note = _any_in_window_after(ransom_note_ts_idx, ransom_note_events, host, ts, download_window)
                    if found_note:
                        note_ts = ev_note[1]
                        emit(
                            "ransomware_impact",
                            "Ransomware-like file-change activity was followed by likely ransom-note creation within a bounded window",
                            "medium",
                            {
                                "hostname": raw_hostname,
                                "mass_file_modification": float(signals.get("mass_file_modification", 0.0) or 0.0) > 0.0,
                                "ransomware_extension_burst": float(signals.get("ransomware_extension_burst", 0.0) or 0.0) > 0.0,
                                "yara_ransomware": float(signals.get("yara_ransomware", 0.0) or 0.0) > 0.0,
                                "av_ransomware": float(signals.get("av_ransomware", 0.0) or 0.0) > 0.0,
                                "ransom_note_timestamp": note_ts.isoformat(),
                            },
                        )

            transfer_count = _count_in_window_before(transfer_ts_idx, host, ts, auto_exfil_window)
            sensitive_found, _ = _any_in_window_before(sensitive_ts_idx, sensitive_events, host, ts, auto_exfil_window)
            sensitive_support = sensitive_found
            suspicious_transfer_support = (
                float(signals.get("suspicious_execution", 0.0) or 0.0) > 0.0
                or float(signals.get("application_layer_protocol", 0.0) or 0.0) > 0.0
            )
            if transfer_count >= auto_exfil_threshold and (
                sensitive_support
                or suspicious_transfer_support
                or float(signals.get("staging_then_transfer", 0.0) or 0.0) > 0.0
                or float(signals.get("cross_border_transfer", 0.0) or 0.0) > 0.0
            ):
                emit(
                    "automated_exfiltration",
                    "Repeated transfer behaviour co-occurred with sensitive access, staging, or exfiltration context within a bounded window",
                    "low",
                    {"hostname": raw_hostname, "count_in_window": transfer_count, "window_seconds": int(auto_exfil_window.total_seconds())},
                )

            credential_source = (
                float(signals.get("credential_dumping", 0.0) or 0.0) > 0.0
                or float(signals.get("yara_offensive_tool", 0.0) or 0.0) > 0.0
                or float(signals.get("av_offensive_tool", 0.0) or 0.0) > 0.0
            )
            if credential_source:
                has_follow_on_collection = (
                    _has_labelled_follow_on_bisect(copy_stage_events, copy_stage_ts_idx, host, dump_labels, ts)
                    or _has_labelled_follow_on_bisect(follow_on_events, follow_on_ts_idx, host, dump_labels, ts)
                    or _has_staged_then_exfil_bisect(host, dump_labels, ts)
                    or (not dump_labels and _any_follow_on_unlabelled_bisect(host, ts))
                )
                if has_follow_on_collection:
                    emit(
                        "credential_dump_collection",
                        "Credential-dumping or offensive-tool YARA evidence was followed by copying, archiving, or transfer activity within a bounded window",
                        "medium",
                        {"hostname": raw_hostname, "credential_timestamp": ts.isoformat(), "window_seconds": int(credential_window.total_seconds())},
                    )

            if float(signals.get("password_store_access", 0.0) or 0.0) > 0.0:
                has_follow_on_exfil = (
                    _has_labelled_follow_on_bisect(copy_stage_events, copy_stage_ts_idx, host, password_labels, ts)
                    or _has_labelled_follow_on_bisect(follow_on_events, follow_on_ts_idx, host, password_labels, ts)
                    or _has_staged_then_exfil_bisect(host, password_labels, ts)
                    or (not password_labels and _any_follow_on_unlabelled_bisect(host, ts))
                )
                if has_follow_on_exfil:
                    emit(
                        "password_store_exfil_chain",
                        "Password-store access was followed by copy, archive, or transfer activity within a bounded window",
                        "medium",
                        {"hostname": raw_hostname, "password_store_timestamp": ts.isoformat(), "window_seconds": int(credential_window.total_seconds())},
                    )

            if (
                float(signals.get("sensitive_file_access", 0.0) or 0.0) > 0.0
                or float(signals.get("password_store_access", 0.0) or 0.0) > 0.0
            ) and (
                float(signals.get("archive_created", 0.0) or 0.0) > 0.0
                or float(signals.get("large_archive_created", 0.0) or 0.0) > 0.0
                or float(signals.get("repeated_scheduled_exec", 0.0) or 0.0) > 0.0
            ):
                emit(
                    "automated_collection",
                    "Sensitive access combined with archiving or repeated scheduled execution suggests automated collection",
                    "low",
                    {"hostname": raw_hostname, "path": path_vals[row_i]},
                )

    def _inject_av_signal_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
    ) -> None:
        if "av_hit" not in df.columns:
            return
        av_vals = df["av_hit"].to_numpy(copy=False)
        filenames = _column_values_or_none(df, "filename")
        avsig_vals = _column_values_or_none(df, "av_signature")
        for i in range(len(df)):
            if _is_null(av_vals[i]) or not bool(av_vals[i]):
                continue

            sig = self._sparse_signal_dict(signal_map, i)
            expl = self._sparse_explain_list(explain_map, i)

            # Parse ClamAV signature for category-aware scoring
            raw_sig = _safe_str(avsig_vals[i]).strip()
            parsed = parse_clamav_signature(raw_sig) if raw_sig else None

            if parsed and parsed.forensic_category == AV_CAT_PUA:
                # PUA/adware/coinminer: dampen av_hit, emit av_pua instead
                sig["av_pua"] = 1.0
                expl.append({
                    "rule_id": "AV_PUA",
                    "description": "Potentially Unwanted Application detected by antivirus",
                    "confidence": "low",
                    "evidence_type": "direct",
                    "signals": ["av_pua"],
                    "evidence": {
                        "filename": _safe_str(filenames[i]),
                        "av_signature": raw_sig,
                        "platform": parsed.platform,
                        "category": parsed.category_token,
                        "family": parsed.family,
                    },
                })
            else:
                # Non-PUA: emit full-weight av_hit
                sig["av_hit"] = 1.0
                signals_emitted = ["av_hit"]

                # Emit category-specific signal
                if parsed and parsed.forensic_category:
                    cat_signal = AV_CATEGORY_SIGNALS.get(parsed.forensic_category)
                    if cat_signal and cat_signal != "av_pua":
                        sig[cat_signal] = 1.0
                        signals_emitted.append(cat_signal)

                expl.append({
                    "rule_id": "AV_HIT",
                    "description": f"Antivirus detection: {parsed.forensic_category if parsed else 'unknown'}" if parsed else "Antivirus hit present",
                    "confidence": "high",
                    "evidence_type": "direct",
                    "signals": signals_emitted,
                    "evidence": {
                        "filename": _safe_str(filenames[i]),
                        "av_signature": raw_sig if raw_sig else None,
                        "platform": parsed.platform if parsed else None,
                        "category": parsed.category_token if parsed else None,
                        "family": parsed.family if parsed else None,
                        "forensic_category": parsed.forensic_category if parsed else None,
                    },
                })

    def _inject_yara_signal_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
    ) -> None:
        if "yara_match_count" not in df.columns:
            return

        yara_idx = self.yara_metadata_index  # required since v2.31

        # Pre-filter: only iterate rows with yara_match_count > 0
        ymc_arr = pd.to_numeric(df["yara_match_count"], errors="coerce").fillna(0).to_numpy()
        candidate_rows = np.flatnonzero(ymc_arr > 0)
        if len(candidate_rows) == 0:
            return

        ym_vals = df["yara_match"].values if "yara_match" in df.columns else np.array([None] * len(df))

        for i in candidate_rows:
            match_count = int(ymc_arr[i])

            sig = self._sparse_signal_dict(signal_map, i)
            expl = self._sparse_explain_list(explain_map, i)

            # ── Category-aware YARA scoring (metadata required) ──────────
            rule_names = extract_yara_rule_names(ym_vals[i])
            if not rule_names:
                # yara_match_count > 0 but rule names couldn't be parsed
                yhs = float(min(1.0, match_count / 3.0))
                sig["yara_hit_strength"] = yhs
                expl.append({
                    "rule_id": "YARA_HIT_STRENGTH",
                    "description": "Bounded YARA support derived from yara_match_count (rule names unavailable)",
                    "confidence": "medium",
                    "evidence_type": "direct",
                    "signals": ["yara_hit_strength"],
                    "evidence": {
                        "yara_match_count": match_count,
                        "yara_hit_strength": yhs,
                    },
                })
                continue

            # Classify each matched rule
            category_hits: Dict[str, List[str]] = {}  # category → [rule_names]
            best_score: int = 0
            non_cert_count: int = 0
            for rn in rule_names:
                meta = yara_idx.get(rn)
                if meta:
                    cat = meta.category
                    rule_score = meta.score
                else:
                    # Rule not in index — classify from name alone
                    cat = _classify_yara_rule(rn)
                    rule_score = 75
                category_hits.setdefault(cat, []).append(rn)
                if cat != YARA_CAT_CERTIFICATE:
                    non_cert_count += 1
                    best_score = max(best_score, rule_score)

            # Recompute yara_hit_strength excluding certificate blocklist matches.
            # Saturates at 3 non-certificate hits, matching the legacy formula.
            refined_strength = float(min(1.0, non_cert_count / 3.0)) if non_cert_count > 0 else 0.0

            # Score multiplier from YARA Forge score (60-100 → 0.6-1.0)
            score_multiplier = max(0.6, min(1.0, best_score / 100.0)) if best_score > 0 else 1.0

            # Emit refined yara_hit_strength (with score multiplier applied)
            if refined_strength > 0.0:
                sig["yara_hit_strength"] = refined_strength * score_multiplier
                expl.append({
                    "rule_id": "YARA_HIT_STRENGTH",
                    "description": "Category-aware YARA support (certificate blocklist excluded, score-weighted)",
                    "confidence": "medium" if score_multiplier >= 0.75 else "low",
                    "evidence_type": "direct",
                    "signals": ["yara_hit_strength"],
                    "evidence": {
                        "yara_match_count": len(rule_names),
                        "non_certificate_count": non_cert_count,
                        "yara_hit_strength": refined_strength * score_multiplier,
                        "best_yara_score": best_score,
                        "score_multiplier": round(score_multiplier, 3),
                        "rule_names": rule_names[:10],  # cap for evidence readability
                    },
                })

            # Emit category-specific signals
            for cat, cat_rules in category_hits.items():
                signal_name = YARA_CATEGORY_SIGNALS.get(cat)
                if not signal_name:
                    continue
                sig[signal_name] = 1.0
                expl.append({
                    "rule_id": f"YARA_{cat.upper()}",
                    "description": f"YARA Forge {cat.replace('_', ' ')} detection",
                    "confidence": "high" if best_score >= 80 else "medium",
                    "evidence_type": "direct",
                    "signals": [signal_name],
                    "evidence": {
                        "category": cat,
                        "rule_count": len(cat_rules),
                        "rule_names": cat_rules[:5],
                    },
                })

    def _apply_profile_signals_and_multipliers_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
    ) -> None:
        emit_quiet = bool(self.profiling_cfg.get("emit_quiet_time_signal", True))
        quiet_thresh = float(self.profiling_cfg.get("quiet_threshold", 0.80))
        if "hour_rarity" not in df.columns:
            return

        hour_rarity_vals = df["hour_rarity"].values
        hour_bins = df["hour_of_week"].values if "hour_of_week" in df.columns else np.array([None] * len(df), dtype=object)

        quiet_hours = df.attrs.get("_chronosift_quiet_hours_profile")
        if quiet_hours is None and "_quiet_hours_profile" in df.columns and len(df):
            try:
                quiet_hours = df["_quiet_hours_profile"].iloc[0]
            except Exception:
                quiet_hours = None

        # Build candidate set: rows with existing signals + rows that might be quiet-hour hits
        _signal_rows = set(signal_map.keys())
        if emit_quiet:
            # All rows are candidates when quiet-hour detection is enabled
            _candidate_iter = range(len(df))
        else:
            # Only rows that already carry signals benefit from multipliers
            _candidate_iter = sorted(_signal_rows)

        for i in _candidate_iter:
            r = float(hour_rarity_vals[i]) if not _is_null(hour_rarity_vals[i]) else 0.0
            hb = hour_bins[i]

            quiet_hit = False
            if emit_quiet:
                if quiet_hours is not None and pd.notna(hb):
                    quiet_hit = int(hb) in quiet_hours
                else:
                    quiet_hit = r >= quiet_thresh

            sig = signal_map.get(i)
            if sig is None and not quiet_hit:
                continue

            if sig is None:
                sig = self._sparse_signal_dict(signal_map, i)

            if quiet_hit:
                sig["quiet_time_event"] = float(sig.get("quiet_time_event", 0.0)) + 1.0

            applied_signal_targets: Set[str] = set()
            emitted_multiplier_notes: Set[Tuple[str, str]] = set()

            for pm in self.profile_multipliers:
                mval = 1.0 + pm.k * r
                applied_targets: List[str] = []
                for target in pm.applies_to:
                    if target in applied_signal_targets:
                        continue
                    if target in sig and isinstance(sig[target], (int, float)):
                        sig[target] = float(sig[target]) * mval
                        applied_targets.append(target)
                        applied_signal_targets.add(target)

                if applied_targets:
                    target_key = ",".join(sorted(applied_targets))
                    note_key = (str(pm.mid), target_key)
                    if note_key not in emitted_multiplier_notes:
                        expl = self._sparse_explain_list(explain_map, i)
                        expl.append({
                            "rule_id": pm.mid,
                            "description": "Profile multiplier applied (m = 1 + k * hour_rarity)",
                            "confidence": "medium",
                            "evidence_type": "profiling",
                            "evidence": {
                                "hour_rarity": r,
                                "k": pm.k,
                                "multiplier": mval,
                                "signals": target_key,
                                "targets": target_key,
                            },
                        })
                        emitted_multiplier_notes.add(note_key)

        _delete_columns_inplace(df, ["_quiet_hours_profile"])
        df.attrs.pop("_chronosift_quiet_hours_profile", None)

    def _apply_private_ip_continuity_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
        carried_last: Optional[Dict[tuple, Dict[str, Any]]] = None,
    ) -> None:
        cfg = (getattr(self, "private_ip_continuity_cfg", {}) or {})
        key_by = [str(k).strip() for k in (cfg.get("key_by") or ["actor_principal"]) if str(k).strip()]
        if not key_by:
            key_by = ["actor_principal"]
        ip_field = "src_ip" if "src_ip" in df.columns else "ip_address"
        required = {ip_field, *key_by}
        if not required.issubset(set(df.columns)):
            return
        if not bool(cfg.get("enabled", True)):
            return
        lookback = parse_lookback(cfg.get("lookback", "24h"))
        prefix_v4 = int(cfg.get("subnet_prefix_v4", 24))
        prefix_v6 = int(cfg.get("subnet_prefix_v6", 64))

        key_vals = [_normalised_text_array(df, k) for k in key_by]
        ip_vals = _normalised_text_array(df, ip_field)
        times = df.index

        groups: Dict[Tuple[str, ...], List[int]] = {}
        for i in range(len(df)):
            actor = tuple(col[i] for col in key_vals)
            if all(not part for part in actor):
                continue
            groups.setdefault(actor, []).append(i)

        last: Dict[tuple, Dict[str, Any]] = carried_last if carried_last is not None else {}

        for actor, idxs in groups.items():
            prev_state = last.get(actor)
            if prev_state is not None:
                prev_idx = prev_state.get("idx")
                prev_ip = prev_state.get("ip")
                prev_scope = prev_state.get("scope")
                prev_subnet = prev_state.get("subnet")
                prev_ts = prev_state.get("ts")
            else:
                prev_idx = None
                prev_ip = None
                prev_scope = None
                prev_subnet = None
                prev_ts = None

            for row_i in idxs:
                cur_ip = ip_vals[row_i]
                cur_scope = _ip_scope(cur_ip)
                if not cur_scope:
                    continue

                cur_subnet = _ip_subnet_label(cur_ip, prefix_v4=prefix_v4, prefix_v6=prefix_v6)
                t_now = times[row_i]

                if prev_scope is not None and (prev_idx is not None or prev_ts is not None):
                    ref_time = times[prev_idx] if prev_idx is not None else prev_ts
                    delta = t_now - ref_time
                    if delta <= lookback and cur_ip != prev_ip:
                        sig = self._sparse_signal_dict(signal_map, row_i)
                        expl = self._sparse_explain_list(explain_map, row_i)

                        def emit(name: str, desc: str, conf: str, extra: Dict[str, Any]) -> None:
                            sig[name] = max(float(sig.get(name, 0.0)), 1.0)
                            evidence = {
                                "actor_principal": "|".join(actor),
                                "previous_ip": prev_ip,
                                "current_ip": cur_ip,
                                "delta_seconds": int(delta.total_seconds()),
                            }
                            evidence.update(extra)
                            expl.append({
                                "rule_id": name.upper(),
                                "description": desc,
                                "confidence": conf,
                                "evidence_type": "contextual",
                                "signals": [name],
                                "evidence": evidence,
                            })

                        if prev_scope == "private" and cur_scope == "private":
                            emit("user_changed_private_ip", "Same actor observed from a different private IP within continuity window", "low", {})
                            if prev_subnet and cur_subnet and prev_subnet != cur_subnet:
                                emit("user_crossed_private_subnet", "Same actor crossed private subnet within continuity window", "medium", {"previous_subnet": prev_subnet, "current_subnet": cur_subnet})
                        elif prev_scope == "private" and cur_scope == "public":
                            emit("user_private_to_public_ip", "Same actor moved from private to public IP within continuity window", "low", {"previous_scope": "private", "current_scope": "public"})
                        elif prev_scope == "public" and cur_scope == "private":
                            emit("user_public_to_private_ip", "Same actor moved from public to private IP within continuity window", "low", {"previous_scope": "public", "current_scope": "private"})

                prev_idx = row_i
                prev_ip = cur_ip
                prev_scope = cur_scope
                prev_subnet = cur_subnet
                prev_ts = t_now

            # Persist final state for cross-partition continuity
            if prev_ip is not None:
                last[actor] = {
                    "idx": None,  # Not valid across partitions
                    "ip": prev_ip,
                    "scope": prev_scope,
                    "subnet": prev_subnet,
                    "ts": prev_ts,
                }

    def _get_signal_value_sparse(self, signal_map: Dict[int, Dict[str, Any]], row_i: int, name: str) -> float:
        signals = signal_map.get(row_i, {})
        v = signals.get(name, 0.0)
        try:
            return float(v) if isinstance(v, (int, float)) else 0.0
        except Exception:
            return 0.0

    def _is_temporal_eligible_signal(self, name: str) -> bool:
        sig = str(name).strip().lower()
        if not sig:
            return False
        return sig not in self.temporal_ineligible_signals

    def _temporal_emit_sparse(
        self,
        tr: TemporalRule,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
        row_i: int,
        key_tuple: Tuple[str, ...],
    ) -> None:
        sig = self._sparse_signal_dict(signal_map, row_i)
        expl = self._sparse_explain_list(explain_map, row_i)

        for es in tr.emit_signals:
            if isinstance(es.value, (int, float)):
                cur = sig.get(es.name, 0.0)
                if not isinstance(cur, (int, float)):
                    cur = 0.0
                sig[es.name] = float(min(1.0, float(cur) + float(es.value)))
            else:
                if es.name not in sig:
                    sig[es.name] = es.value
                else:
                    cur = sig[es.name]
                    if isinstance(cur, list):
                        cur.append(es.value)
                    else:
                        sig[es.name] = [cur, es.value]

        expl.append({
            "rule_id": tr.rule_id,
            "description": tr.description,
            "confidence": tr.confidence,
            "evidence_type": "temporal",
            "signals": [str(es.name).strip() for es in tr.emit_signals if str(es.name).strip()],
            "evidence": {
                "temporal": tr.mode,
                "key_by": ",".join(tr.key_by),
                "key": "|".join(key_tuple),
                "lookback_seconds": int(tr.lookback.total_seconds()),
            },
        })

    def _apply_temporal_rules_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
    ) -> None:
        if not self.temporal_rules or len(df) == 0:
            return
        if not isinstance(df.index, pd.DatetimeIndex):
            return

        cols_present = set(df.columns)
        nrows = len(df)
        time_values_ns = df.index.asi8

        needed_signals: Set[str] = set()
        for tr in self.temporal_rules:
            temporal_inputs: List[str] = []
            if tr.mode == "cooccur":
                temporal_inputs = [need.signal for need in tr.cooccur_all if getattr(need, "signal", None)]
            elif tr.mode == "sequence":
                temporal_inputs = [step.signal for step in tr.sequence if getattr(step, "signal", None)]
            if temporal_inputs and not all(self._is_temporal_eligible_signal(sig) for sig in temporal_inputs):
                continue
            needed_signals.update(temporal_inputs)

        signal_hit_flags: Dict[str, bytearray] = {
            name: bytearray(nrows) for name in needed_signals if name
        }
        signal_has_hits: Set[str] = set()

        def _signal_positive(value: Any) -> bool:
            if _is_null(value):
                return False
            if isinstance(value, (int, float)):
                try:
                    return float(value) > 0.0
                except (TypeError, ValueError):
                    return False
            try:
                return bool(value)
            except (TypeError, ValueError):
                return False

        def _refresh_needed_signal_hits(row_i: int) -> None:
            if not signal_hit_flags or not (0 <= row_i < nrows):
                return
            signals = signal_map.get(row_i, {})
            if not isinstance(signals, dict):
                return
            for name, value in signals.items():
                flags = signal_hit_flags.get(name)
                if flags is None:
                    continue
                if _signal_positive(value):
                    flags[row_i] = 1
                    signal_has_hits.add(name)

        if signal_hit_flags:
            for pos in signal_map.keys():
                _refresh_needed_signal_hits(pos)

        normalised_col_cache: Dict[str, np.ndarray] = {}
        normalised_code_cache: Dict[str, np.ndarray] = {}
        group_cache: Dict[Tuple[str, ...], Optional[TemporalGroupPlan]] = {}

        def _normalised_values(col: str) -> np.ndarray:
            cached = normalised_col_cache.get(col)
            if cached is not None:
                return cached
            values = df[col].astype("string").fillna("").str.strip()
            placeholder_mask = values.str.lower().isin(PLACEHOLDER_STRINGS)
            if bool(placeholder_mask.any()):
                values = values.mask(placeholder_mask, "")
            arr = values.to_numpy(dtype=object, na_value="")
            normalised_col_cache[col] = arr
            return arr

        def _normalised_codes(col: str) -> np.ndarray:
            cached = normalised_code_cache.get(col)
            if cached is not None:
                return cached
            values = _normalised_values(col)
            codes, _ = pd.factorize(values, sort=False)
            codes = codes.astype(np.int64, copy=False)
            empty_mask = values == ""
            if bool(np.any(empty_mask)):
                codes[empty_mask] = -1
            normalised_code_cache[col] = codes
            return codes

        def _group_plan(key_by_tuple: Tuple[str, ...]) -> Optional[TemporalGroupPlan]:
            if key_by_tuple in group_cache:
                return group_cache[key_by_tuple]
            if not key_by_tuple or any(k not in cols_present for k in key_by_tuple):
                group_cache[key_by_tuple] = None
                return None

            key_code_columns = [_normalised_codes(k) for k in key_by_tuple]
            valid_mask = np.ones(nrows, dtype=bool)
            for codes in key_code_columns:
                valid_mask &= codes >= 0

            valid_rows = np.flatnonzero(valid_mask)
            if valid_rows.size == 0:
                plan = TemporalGroupPlan(
                    ordered_rows=np.empty(0, dtype=np.int64),
                    group_slices=[],
                    groups_seen=0,
                    largest_group=0,
                )
                group_cache[key_by_tuple] = plan
                return plan

            valid_code_columns = [codes[valid_rows] for codes in key_code_columns]
            order = np.arange(valid_rows.size, dtype=np.int64)
            for valid_codes in reversed(valid_code_columns):
                order = order[np.argsort(valid_codes[order], kind="stable")]

            ordered_rows = valid_rows[order]
            ordered_code_columns = [valid_codes[order] for valid_codes in valid_code_columns]
            group_start_mask = np.zeros(ordered_rows.size, dtype=bool)
            group_start_mask[0] = True
            for ordered_codes in ordered_code_columns:
                group_start_mask[1:] |= ordered_codes[1:] != ordered_codes[:-1]

            group_starts = np.flatnonzero(group_start_mask)
            group_ends = np.empty_like(group_starts)
            if group_starts.size > 1:
                group_ends[:-1] = group_starts[1:]
            group_ends[-1] = ordered_rows.size

            key_value_columns = [_normalised_values(k) for k in key_by_tuple]
            group_slices: List[Tuple[int, int, Tuple[str, ...]]] = []
            largest_group = 0
            for idx, start in enumerate(group_starts):
                end = int(group_ends[idx])
                start = int(start)
                first_row = int(ordered_rows[start])
                key_tuple = tuple(str(col_values[first_row]) for col_values in key_value_columns)
                group_slices.append((start, end, key_tuple))
                if (end - start) > largest_group:
                    largest_group = end - start

            plan = TemporalGroupPlan(
                ordered_rows=ordered_rows,
                group_slices=group_slices,
                groups_seen=len(group_slices),
                largest_group=largest_group,
            )
            group_cache[key_by_tuple] = plan
            return plan

        for tr in self.temporal_rules:
            rule_start = time.perf_counter()
            emitted = 0
            temporal_inputs: List[str] = []
            if tr.mode == "cooccur":
                temporal_inputs = [need.signal for need in tr.cooccur_all if getattr(need, "signal", None)]
            elif tr.mode == "sequence":
                temporal_inputs = [step.signal for step in tr.sequence if getattr(step, "signal", None)]
            if temporal_inputs and not all(self._is_temporal_eligible_signal(sig) for sig in temporal_inputs):
                continue

            key_by_tuple = tuple(str(k).strip() for k in tr.key_by if str(k).strip())
            if not key_by_tuple:
                continue

            group_plan = _group_plan(key_by_tuple)
            if group_plan is None:
                continue

            ordered_rows = group_plan.ordered_rows
            group_slices = group_plan.group_slices
            groups_seen = group_plan.groups_seen
            largest_group = group_plan.largest_group
            lookback_ns = pd.Timedelta(tr.lookback).value

            if tr.mode == "cooccur":
                needs = [need for need in tr.cooccur_all if getattr(need, "signal", None)]
                need_names = [need.signal for need in needs]
                if needs and all(name in signal_has_hits for name in need_names):
                    need_flags = [signal_hit_flags[name] for name in need_names]
                    need_counts = [max(int(getattr(need, "min_count", 1)), 1) for need in needs]

                    for start, end, key_tuple in group_slices:
                        left = 0
                        counts = [0] * len(need_flags)
                        idxs = ordered_rows[start:end]
                        for right, row_pos in enumerate(idxs):
                            row_i = int(row_pos)
                            t_now = time_values_ns[row_i]
                            while left < right and (t_now - time_values_ns[int(idxs[left])]) > lookback_ns:
                                left_row = int(idxs[left])
                                for need_i, flags in enumerate(need_flags):
                                    if flags[left_row]:
                                        counts[need_i] -= 1
                                left += 1

                            for need_i, flags in enumerate(need_flags):
                                if flags[row_i]:
                                    counts[need_i] += 1

                            matched = True
                            for need_i, min_count in enumerate(need_counts):
                                if counts[need_i] < min_count:
                                    matched = False
                                    break
                            if matched:
                                self._temporal_emit_sparse(tr, signal_map, explain_map, row_i, key_tuple)
                                _refresh_needed_signal_hits(row_i)
                                emitted += 1

            elif tr.mode == "sequence":
                expanded_steps: List[str] = []
                for step in tr.sequence:
                    if not getattr(step, "signal", None):
                        continue
                    expanded_steps.extend([step.signal] * max(int(getattr(step, "min_count", 1)), 1))

                if expanded_steps and all(name in signal_has_hits for name in set(expanded_steps)):
                    step_flags = [signal_hit_flags[name] for name in expanded_steps]
                    last_step = len(step_flags) - 1

                    for start, end, key_tuple in group_slices:
                        left = 0
                        latest_start = [-1] * len(step_flags)
                        idxs = ordered_rows[start:end]

                        for right, row_pos in enumerate(idxs):
                            row_i = int(row_pos)
                            t_now = time_values_ns[row_i]
                            while left < right and (t_now - time_values_ns[int(idxs[left])]) > lookback_ns:
                                left += 1

                            for step_i in range(last_step, -1, -1):
                                if not step_flags[step_i][row_i]:
                                    continue
                                if step_i == 0:
                                    if right > latest_start[0]:
                                        latest_start[0] = right
                                else:
                                    prev_start = latest_start[step_i - 1]
                                    if prev_start >= 0 and prev_start > latest_start[step_i]:
                                        latest_start[step_i] = prev_start

                            if step_flags[last_step][row_i] and latest_start[last_step] >= left:
                                self._temporal_emit_sparse(tr, signal_map, explain_map, row_i, key_tuple)
                                _refresh_needed_signal_hits(row_i)
                                emitted += 1

            elif tr.mode == "first_seen_value":
                if tr.field and tr.field in cols_present:
                    field_values = _normalised_values(tr.field)

                    for start, end, key_tuple in group_slices:
                        left = 0
                        seen_counts: Dict[str, int] = {}
                        idxs = ordered_rows[start:end]

                        for right, row_pos in enumerate(idxs):
                            row_i = int(row_pos)
                            t_now = time_values_ns[row_i]
                            while left < right and (t_now - time_values_ns[int(idxs[left])]) > lookback_ns:
                                old_val = field_values[int(idxs[left])]
                                if old_val:
                                    remaining = seen_counts.get(old_val, 0) - 1
                                    if remaining > 0:
                                        seen_counts[old_val] = remaining
                                    else:
                                        seen_counts.pop(old_val, None)
                                left += 1

                            cur_val = field_values[row_i]
                            if cur_val:
                                if seen_counts.get(cur_val, 0) == 0:
                                    self._temporal_emit_sparse(tr, signal_map, explain_map, row_i, key_tuple)
                                    _refresh_needed_signal_hits(row_i)
                                    emitted += 1
                                seen_counts[cur_val] = seen_counts.get(cur_val, 0) + 1

            elif tr.mode == "change_detected":
                if tr.field and tr.field in cols_present:
                    field_values = _normalised_values(tr.field)

                    for start, end, key_tuple in group_slices:
                        left = 0
                        recent_non_empty: List[int] = []
                        head = 0
                        idxs = ordered_rows[start:end]

                        for right, row_pos in enumerate(idxs):
                            row_i = int(row_pos)
                            t_now = time_values_ns[row_i]
                            while left < right and (t_now - time_values_ns[int(idxs[left])]) > lookback_ns:
                                old_val = field_values[int(idxs[left])]
                                if old_val and head < len(recent_non_empty) and recent_non_empty[head] == left:
                                    head += 1
                                left += 1

                            cur_val = field_values[row_i]
                            if cur_val:
                                if head < len(recent_non_empty):
                                    prev_row_i = int(idxs[recent_non_empty[-1]])
                                    prev_val = field_values[prev_row_i]
                                    if prev_val and cur_val != prev_val:
                                        self._temporal_emit_sparse(tr, signal_map, explain_map, row_i, key_tuple)
                                        _refresh_needed_signal_hits(row_i)
                                        emitted += 1
                                recent_non_empty.append(right)
                                if head == len(recent_non_empty):
                                    recent_non_empty = []
                                    head = 0
                                elif head > 1024 and head * 2 >= len(recent_non_empty):
                                    recent_non_empty = recent_non_empty[head:]
                                    head = 0

            elapsed = time.perf_counter() - rule_start
            logger.info(
                "Temporal rule stats | rule=%s mode=%s groups=%d largest_group=%d emitted=%d time=%.2fs",
                tr.rule_id,
                tr.mode,
                groups_seen,
                largest_group,
                emitted,
                elapsed,
            )

    def _apply_impossible_travel_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
        carried_last: Optional[Dict[tuple, Dict[str, Any]]] = None,
    ) -> None:
        cfg = self.impossible_travel_cfg or {}
        if not cfg.get("enabled", True):
            return

        key_by = cfg.get("key_by") or ["actor_principal"]
        key_by = [str(k) for k in key_by if str(k).strip()]
        if not key_by:
            key_by = ["actor_principal"]

        success_keys = cfg.get("success_signal_keys") or []
        success_keys = [str(k) for k in success_keys if str(k).strip()]

        min_distance_km = float(cfg.get("min_distance_km", 200.0))
        min_time_seconds = float(cfg.get("min_time_seconds", 60.0))
        velocity_kmh_threshold = float(cfg.get("velocity_kmh_threshold", 900.0))

        ip_field = "src_ip" if "src_ip" in df.columns else "ip_address"
        required = {ip_field, "geo_latitude", "geo_longitude", "geo_country_iso"}
        required.update(key_by)
        for col in required:
            if col not in df.columns:
                return

        df["travel_distance_km"] = math.nan
        df["travel_dt_hours"] = math.nan
        df["travel_velocity_kmh"] = math.nan
        df["travel_from_country"] = None
        df["travel_to_country"] = None
        df["travel_from_ip"] = None

        travel_distance_loc = df.columns.get_loc("travel_distance_km")
        travel_dt_loc = df.columns.get_loc("travel_dt_hours")
        travel_velocity_loc = df.columns.get_loc("travel_velocity_kmh")
        travel_from_country_loc = df.columns.get_loc("travel_from_country")
        travel_to_country_loc = df.columns.get_loc("travel_to_country")
        travel_from_ip_loc = df.columns.get_loc("travel_from_ip")

        idx_values = list(df.index)
        ip_values = df[ip_field].tolist()
        lat_values = df["geo_latitude"].tolist()
        lon_values = df["geo_longitude"].tolist()
        country_values = df["geo_country_iso"].tolist()
        key_columns = [df[k].tolist() for k in key_by]

        auth_positions = sorted(
            pos for pos, signals in signal_map.items()
            if 0 <= pos < len(df) and _signals_indicate_auth_success(signals, success_keys)
        )
        if not auth_positions:
            return

        last: Dict[tuple, Dict[str, Any]] = carried_last if carried_last is not None else {}

        for pos in auth_positions:
            key = tuple(_safe_str(col[pos]) for col in key_columns)
            if all(part == "" for part in key):
                continue

            lat = lat_values[pos]
            lon = lon_values[pos]
            if lat is None or lon is None:
                continue
            try:
                lat = float(lat)
                lon = float(lon)
            except Exception:
                continue
            if pd.isna(lat) or pd.isna(lon):
                continue

            ts = idx_values[pos]
            prev = last.get(key)
            if prev:
                dt_seconds = (ts - prev["ts"]).total_seconds()
                if dt_seconds >= min_time_seconds:
                    dist_km = _haversine_km(prev["lat"], prev["lon"], lat, lon)
                    if dist_km >= min_distance_km:
                        vel_kmh = (dist_km / dt_seconds) * 3600.0
                        if vel_kmh >= velocity_kmh_threshold:
                            sig = self._sparse_signal_dict(signal_map, pos)
                            expl = self._sparse_explain_list(explain_map, pos)
                            sig["impossible_travel"] = 1
                            df.iat[pos, travel_distance_loc] = dist_km
                            df.iat[pos, travel_dt_loc] = dt_seconds / 3600.0
                            df.iat[pos, travel_velocity_loc] = vel_kmh
                            df.iat[pos, travel_from_country_loc] = prev.get("country")
                            df.iat[pos, travel_to_country_loc] = country_values[pos]
                            df.iat[pos, travel_from_ip_loc] = prev.get("ip")
                            expl.append({
                                "rule_id": "IMPOSSIBLE_TRAVEL",
                                "description": "Velocity exceeds threshold between consecutive successful logons for same actor",
                                "confidence": "high",
                                "evidence_type": "contextual",
                                "signals": ["impossible_travel"],
                                "evidence": {
                                    "distance_km": round(dist_km, 3),
                                    "dt_hours": round(dt_seconds / 3600.0, 4),
                                    "velocity_kmh": round(vel_kmh, 1),
                                    "from_ip": prev.get("ip"),
                                    "to_ip": ip_values[pos],
                                    "from_country": prev.get("country"),
                                    "to_country": country_values[pos],
                                    "threshold_kmh": velocity_kmh_threshold,
                                    "min_distance_km": min_distance_km,
                                    "key_by": "|".join(key_by),
                                    "actor_key": "|".join(key),
                                },
                            })

            last[key] = {
                "ts": ts,
                "lat": lat,
                "lon": lon,
                "country": country_values[pos],
                "ip": ip_values[pos],
            }

    def _apply_geo_continuity_sparse(
        self,
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
        carried_state: Optional[Dict[tuple, Dict[str, Any]]] = None,
    ) -> None:
        if len(df) == 0:
            return

        cfg = self.impossible_travel_cfg or {}
        key_by = cfg.get("key_by") or ["actor_principal"]
        key_by = [str(k) for k in key_by if str(k).strip()]
        if not key_by:
            key_by = ["actor_principal"]

        success_keys = cfg.get("success_signal_keys") or []
        success_keys = [str(k) for k in success_keys if str(k).strip()]

        required = set(key_by) | {"geo_country_iso", "geo_asn"}
        for col in required:
            if col not in df.columns:
                return

        has_city = "geo_city_name" in df.columns

        if "geo_new_country" not in df.columns:
            df["geo_new_country"] = False
        if "geo_new_asn" not in df.columns:
            df["geo_new_asn"] = False
        if "geo_boundary_crossing" not in df.columns:
            df["geo_boundary_crossing"] = False
        if "geo_new_city" not in df.columns:
            df["geo_new_city"] = False

        key_columns = [_normalised_text_array(df, k) for k in key_by]
        # Vectorised string cleaning — produce object-dtype numpy arrays (None, not pd.NA)
        _country_s = df["geo_country_iso"].astype("string").fillna("").str.strip().str.upper()
        country_values = np.where(_country_s.ne("").to_numpy(), _country_s.to_numpy(dtype=object, copy=False, na_value=None), None)
        _asn_s = df["geo_asn"].astype("string").fillna("").str.strip()
        asn_values = np.where(_asn_s.ne("").to_numpy(), _asn_s.to_numpy(dtype=object, copy=False, na_value=None), None)
        if has_city:
            _city_s = df["geo_city_name"].astype("string").fillna("").str.strip()
            city_values = np.where(_city_s.ne("").to_numpy(), _city_s.to_numpy(dtype=object, copy=False, na_value=None), None)
        else:
            city_values = np.array([None] * len(df), dtype=object)
        ip_field = "src_ip" if "src_ip" in df.columns else ("ip_address" if "ip_address" in df.columns else None)
        ip_values = _normalised_text_array(df, ip_field) if ip_field else np.array([None] * len(df), dtype=object)

        state = carried_state if carried_state is not None else {}

        auth_positions = sorted(
            pos for pos, signals in signal_map.items()
            if 0 <= pos < len(df) and _signals_indicate_auth_success(signals, success_keys)
        )
        if not auth_positions:
            return

        # Cache column locations for .iat[] writes inside the loop
        _loc_new_country = df.columns.get_loc("geo_new_country")
        _loc_new_asn = df.columns.get_loc("geo_new_asn")
        _loc_new_city = df.columns.get_loc("geo_new_city")
        _loc_boundary = df.columns.get_loc("geo_boundary_crossing")

        for pos in auth_positions:
            key = tuple(col[pos] for col in key_columns)
            if all(part == "" for part in key):
                continue

            country = country_values[pos]
            asn = asn_values[pos]
            if not country and not asn:
                continue

            entry = state.setdefault(
                key,
                {
                    "seen_countries": set(),
                    "seen_asns": set(),
                    "seen_cities": set(),
                    "last_country": None,
                    "last_ip": None,
                },
            )

            sig = None
            expl = None

            def ensure():
                nonlocal sig, expl
                if sig is None:
                    sig = self._sparse_signal_dict(signal_map, pos)
                if expl is None:
                    expl = self._sparse_explain_list(explain_map, pos)
                return sig, expl

            if country and country not in entry["seen_countries"]:
                df.iat[pos, _loc_new_country] = True
                if entry["seen_countries"]:
                    sig, expl = ensure()
                    sig["new_country"] = max(float(sig.get("new_country", 0.0) or 0.0), 1.0)
                    expl.append({
                        "rule_id": "NEW_COUNTRY",
                        "description": "Successful remote authentication from a country not previously seen for the actor",
                        "confidence": "high",
                        "evidence_type": "contextual",
                        "signals": ["new_country"],
                        "evidence": {
                            "geo_country_iso": country,
                            "previous_countries": "|".join(sorted(entry["seen_countries"]))[:240],
                            "ip_address": ip_values[pos],
                            "key_by": "|".join(key_by),
                            "actor_key": "|".join(key),
                        },
                    })
                entry["seen_countries"].add(country)

            if asn and asn not in entry["seen_asns"]:
                df.iat[pos, _loc_new_asn] = True
                if entry["seen_asns"]:
                    sig, expl = ensure()
                    sig["new_asn"] = max(float(sig.get("new_asn", 0.0) or 0.0), 1.0)
                    expl.append({
                        "rule_id": "NEW_ASN",
                        "description": "Successful remote authentication from an ASN not previously seen for the actor",
                        "confidence": "high",
                        "evidence_type": "contextual",
                        "signals": ["new_asn"],
                        "evidence": {
                            "geo_asn": asn,
                            "previous_asns": "|".join(sorted(entry["seen_asns"]))[:240],
                            "ip_address": ip_values[pos],
                            "key_by": "|".join(key_by),
                            "actor_key": "|".join(key),
                        },
                    })
                entry["seen_asns"].add(asn)

            city = city_values[pos]
            if city and city not in entry["seen_cities"]:
                df.iat[pos, _loc_new_city] = True
                if entry["seen_cities"]:
                    sig, expl = ensure()
                    sig["new_city"] = max(float(sig.get("new_city", 0.0) or 0.0), 1.0)
                    expl.append({
                        "rule_id": "NEW_CITY",
                        "description": "Successful remote authentication from a city not previously seen for the actor",
                        "confidence": "medium",
                        "evidence_type": "contextual",
                        "signals": ["new_city"],
                        "evidence": {
                            "geo_city_name": city,
                            "geo_country_iso": country or "",
                            "previous_cities": "|".join(sorted(entry["seen_cities"]))[:240],
                            "ip_address": ip_values[pos],
                            "key_by": "|".join(key_by),
                            "actor_key": "|".join(key),
                        },
                    })
                entry["seen_cities"].add(city)

            prev_country = entry.get("last_country")
            if country and prev_country and country != prev_country:
                df.iat[pos, _loc_boundary] = True
                sig, expl = ensure()
                sig["boundary_crossing"] = max(float(sig.get("boundary_crossing", 0.0) or 0.0), 1.0)
                expl.append({
                    "rule_id": "BOUNDARY_CROSSING",
                    "description": "Consecutive successful remote authentications crossed a country boundary for the same actor",
                    "confidence": "high",
                    "evidence_type": "contextual",
                    "signals": ["boundary_crossing"],
                        "evidence": {
                            "from_country": prev_country,
                            "to_country": country,
                            "from_ip": _safe_str(entry.get("last_ip")),
                            "to_ip": ip_values[pos],
                            "key_by": "|".join(key_by),
                            "actor_key": "|".join(key),
                        },
                })

            if country:
                entry["last_country"] = country
            if ip_field:
                entry["last_ip"] = ip_values[pos]

    def ensure_required_fields(self, df: pd.DataFrame) -> pd.DataFrame:
        out = df

        # Enrichment-owned fields are created by dedicated enrichment stages and
        # should not be pre-created here as placeholders. Doing so can collide
        # with authoritative enrichment results during later joins.
        enrichment_fields = {
            "geo_city_geoname_id",
            "geo_city_name",
            "geo_country_iso",
            "geo_latitude",
            "geo_longitude",
            "geo_asn",
            "yara_match_count",
            "av_hit",
            "luhn_hit",
            "nsrl_application_type",
            "nsrl_is_os_component",
        }

        needed = [
            col
            for col in sorted(self.required_fields)
            if col and col not in enrichment_fields
        ]
        out = _ensure_object_columns(out, needed)

        return out

    # -------------------------------------------------------------------------
    # Required field collection
    # -------------------------------------------------------------------------

    def _collect_required_fields(self) -> Set[str]:
        fields: Set[str] = set()

        # Normalisation inputs
        for spec in (self.normalisation or []):
            src = str(spec.get("from", "")).strip()
            if src:
                fields.add(src)
            if str(spec.get("method", "")).strip() == "coalesce":
                for f in (spec.get("fields", []) or []):
                    ff = str(f).strip()
                    if ff:
                        fields.add(ff)

        def add_conditions(conds: List[Condition]) -> None:
            for c in conds:
                if c.field:
                    fields.add(c.field)

        for r in self.rules:
            add_conditions(r.scope_any)
            add_conditions(r.scope_all)
            add_conditions(r.when_any)
            add_conditions(r.when_all)
            for evf in r.evidence_fields:
                if evf:
                    fields.add(evf)

        for tr in self.temporal_rules:
            for k in tr.key_by:
                if k:
                    fields.add(k)
                if tr.field:
                    fields.add(tr.field)

        aliased = set()
        for field in list(fields):
            for alias in self.schema_aliases.get(field, ()):
                if alias:
                    aliased.add(alias)
        fields.update(aliased)

        return fields

    # -------------------------------------------------------------------------
    # Normalisation
    # -------------------------------------------------------------------------

    def _apply_normalisation(
        self,
        df: pd.DataFrame,
        selected_names: Optional[Set[str]] = None,
    ) -> pd.DataFrame:
        out = df

        # Normalisation creates canonical actor/file/network columns from the
        # heterogeneous source schema. Rules should prefer these derived fields
        # over parser-specific raw names whenever the semantics match.
        for spec in self.normalisation:
            name = str(spec.get("name", "")).strip()
            if not name:
                continue
            if selected_names is not None and name not in selected_names:
                continue

            method = str(spec.get("method", "")).strip()

            if method == "coalesce":
                fields = [str(f).strip() for f in (spec.get("fields", []) or []) if str(f).strip()]
                # Earlier extraction and schema aliasing can populate canonical
                # fields before normalisation runs. Preserve that value as the
                # highest-priority coalesce input so the semantic layer does not
                # erase structured data when a specific source field is absent.
                if not fields:
                    out = _ensure_object_columns(out, [name])
                    continue
                source_fields = [f for f in fields if f != name]
                ensure_fields = [name] + source_fields
                out = _ensure_object_columns(out, ensure_fields)
                if not source_fields:
                    continue

                missing = out[name].astype("string").fillna("").str.strip().eq("")
                if not bool(missing.any()):
                    continue

                if bool((~missing).any()):
                    filled = _coalesce_first_meaningful_for_mask(out, source_fields, missing)
                    out.loc[missing, name] = filled.to_numpy(copy=False)
                else:
                    out[name] = _coalesce_first_meaningful(out, source_fields)

            elif method == "regex_first":
                src = str(spec.get("from", "")).strip()
                pattern = spec.get("pattern", "")
                group = int(spec.get("group", 0))
                flags = int(spec.get("flags", 0))
                if not src or src not in out.columns:
                    out = _ensure_object_columns(out, [name])
                    continue
                # Vectorised: compile once, extract via pandas C-level loop.
                # Wrap the pattern in a capturing group if group==0 (whole match)
                # so str.extract returns the full match rather than requiring a
                # named/numbered sub-group.
                compiled = re.compile(pattern, flags)
                if group == 0 and compiled.groups == 0:
                    # No capturing groups in the pattern — wrap it so str.extract works
                    extract_rx = re.compile("(" + pattern + ")", flags)
                else:
                    extract_rx = compiled
                derived = out[src].astype("string").str.extract(extract_rx, expand=False)
                if name in out.columns:
                    existing = out[name].astype("string")
                    missing = existing.fillna("").str.strip().eq("")
                    if bool(missing.any()):
                        out.loc[missing, name] = derived.loc[missing]
                else:
                    out[name] = derived

            elif method == "file_extension":
                src = str(spec.get("from", "")).strip()
                if not src or src not in out.columns:
                    out = _ensure_object_columns(out, [name])
                    continue
                # Vectorised: extract last dot-delimited extension via pandas str ops
                s = out[src].astype("string").fillna("").str.strip()
                ext = s.str.extract(r'(\.[^./\\]{1,11})$', expand=False).str.lower()
                out[name] = ext

            elif method == "ipv4_first":
                src = str(spec.get("from", "")).strip()
                if not src or src not in out.columns:
                    out = _ensure_object_columns(out, [name])
                    continue
                out[name] = normalise_ipv4_first_series(out[src])

            elif method == "yara_match_count":
                src = str(spec.get("from", "")).strip() or "yara_match"
                if src not in out.columns:
                    out[src] = None
                out[name] = normalise_yara_match_count_series(out[src])

            else:
                out = _ensure_object_columns(out, [name])

        return out

    # -------------------------------------------------------------------------
    # IP recovery (structured-first)
    # -------------------------------------------------------------------------

    def _recover_ip_address(self, df: pd.DataFrame) -> pd.DataFrame:
        out = df
        # Recovery is intentionally structured-first: preserve parser-provided
        # `ip_address`, then mine parser-specific structured fields, then fall
        # back to guarded text extraction. This keeps detections deterministic
        # while avoiding expensive free-text scanning on every row.
        # Ensure required columns exist.
        out = _ensure_object_columns(out, (
            "ip_address",
            "parser",
            "xml_string",
            "strings",
            "url",
            "http_request",
            "http_headers",
            "http_request_referer",
            "http_request_user_agent",
            "message",
            "text",
            "rdp_client_address",
            "client_address",
            "source_network_address",
        ))
        # Recover only where missing/placeholder.
        missing = out["ip_address"].map(_is_null)
        missing_mask = missing.to_numpy(dtype=bool, copy=False)
        if missing_mask.any():
            pending_pos = np.flatnonzero(missing_mask)
            recovered = pd.Series(pd.NA, index=pd.RangeIndex(len(pending_pos)), dtype="string")

            def _prefilter_text_positions(local_pos: np.ndarray, field: str, require_context: bool = False) -> np.ndarray:
                if len(local_pos) == 0:
                    return local_pos
                values = out[field].iloc[pending_pos[local_pos]].astype("string").fillna("")
                ip_like = values.str.contains(_IP_LITERAL_CANDIDATE_RE.pattern, regex=True, na=False).to_numpy(dtype=bool, copy=False)
                if require_context:
                    with warnings.catch_warnings():
                        warnings.filterwarnings(
                            "ignore",
                            message="This pattern is interpreted as a regular expression, and has match groups.*",
                            category=UserWarning,
                        )
                        ctx = values.str.contains(_NET_CONTEXT_RE.pattern, regex=True, na=False).to_numpy(dtype=bool, copy=False)
                    ip_like &= ctx
                if not bool(ip_like.any()):
                    return np.empty(0, dtype=np.int64)
                return local_pos[np.flatnonzero(ip_like)]

            parser_vals = out["parser"].iloc[pending_pos].astype("string").fillna("").str.lower()
            evtx_mask = parser_vals.str.startswith(("winevt", "winevtx")).to_numpy(dtype=bool, copy=False)
            if evtx_mask.any():
                # Windows EVTX data commonly hides remote/client IPs in XML
                # EventData rather than in a dedicated `ip_address` column.
                evtx_pos = np.flatnonzero(evtx_mask)
                for field_name in ("rdp_client_address", "client_address", "source_network_address"):
                    unresolved_evtx = recovered.iloc[evtx_pos].isna().to_numpy(dtype=bool, copy=False)
                    if not unresolved_evtx.any():
                        break
                    field_pos = evtx_pos[unresolved_evtx]
                    recovered.iloc[field_pos] = (
                        out[field_name]
                        .iloc[pending_pos[field_pos]]
                        .map(_normalise_ip_literal)
                        .astype("string")
                        .to_numpy(copy=False)
                    )
                unresolved_evtx = recovered.iloc[evtx_pos].isna().to_numpy(dtype=bool, copy=False)
                if unresolved_evtx.any():
                    evtx_xml_pos = evtx_pos[unresolved_evtx]
                    recovered.iloc[evtx_xml_pos] = (
                        out["xml_string"]
                        .iloc[pending_pos[evtx_xml_pos]]
                        .map(_extract_ip_from_evtx_xml)
                        .astype("string")
                        .to_numpy(copy=False)
                    )
                unresolved_evtx = recovered.iloc[evtx_pos].isna().to_numpy(dtype=bool, copy=False)
                if unresolved_evtx.any():
                    evtx_strings_pos = evtx_pos[unresolved_evtx]
                    recovered.iloc[evtx_strings_pos] = (
                        out["strings"]
                        .iloc[pending_pos[evtx_strings_pos]]
                        .map(_extract_ip_from_strings_field)
                        .astype("string")
                        .to_numpy(copy=False)
                    )

            for fld in ("url", "http_request", "http_headers", "http_request_referer", "http_request_user_agent"):
                unresolved = recovered.isna().to_numpy(dtype=bool, copy=False)
                if not unresolved.any():
                    break
                unresolved_pos = np.flatnonzero(unresolved)
                candidate_pos = _prefilter_text_positions(unresolved_pos, fld, require_context=False)
                if len(candidate_pos) == 0:
                    continue
                recovered.iloc[candidate_pos] = (
                    out[fld]
                    .iloc[pending_pos[candidate_pos]]
                    .map(_extract_ip_from_text_field)
                    .astype("string")
                    .to_numpy(copy=False)
                )

            for fld in ("message", "text"):
                unresolved = recovered.isna().to_numpy(dtype=bool, copy=False)
                if not unresolved.any():
                    break
                unresolved_pos = np.flatnonzero(unresolved)
                candidate_pos = _prefilter_text_positions(unresolved_pos, fld, require_context=True)
                if len(candidate_pos) == 0:
                    continue
                recovered.iloc[candidate_pos] = (
                    out[fld]
                    .iloc[pending_pos[candidate_pos]]
                    .map(lambda v: _extract_ip_from_text_field(v, require_context=True))
                    .astype("string")
                    .to_numpy(copy=False)
                )

            resolved_mask = recovered.notna().to_numpy(dtype=bool, copy=False)
            if resolved_mask.any():
                ip_col_loc = out.columns.get_loc("ip_address")
                resolved_pos = pending_pos[resolved_mask]
                resolved_vals = recovered.iloc[np.flatnonzero(resolved_mask)].to_numpy(copy=False)
                out.iloc[resolved_pos, ip_col_loc] = resolved_vals
        return out

    # -------------------------------------------------------------------------
    # Profiling: dataset-wide hour-of-week rarity
    # -------------------------------------------------------------------------

    def _apply_hour_of_week_profiling(self, df: pd.DataFrame, profile_manifest: Optional[Dict[str, Any]] = None) -> pd.DataFrame:
        out = df

        dt_all = _ensure_datetime_series(out)
        how_all = _hour_of_week(dt_all)
        out["hour_of_week"] = how_all

        if profile_manifest:
            profile = {int(k): float(v) for k, v in (profile_manifest.get("profile", {}) or {}).items()}
            quiet_hours = frozenset(int(x) for x in (profile_manifest.get("quiet_hours", []) or []))
            _profile_arr = np.zeros(168, dtype=np.float64)
            for _k, _v in profile.items():
                _profile_arr[int(_k)] = float(_v)
            _valid = how_all.notna()
            _idx = how_all.to_numpy(dtype=np.float64, na_value=0.0).astype(np.intp)
            np.clip(_idx, 0, 167, out=_idx)
            out["hour_rarity"] = np.where(_valid.to_numpy(), _profile_arr[_idx], 0.0)
            out.attrs["_chronosift_quiet_hours_profile"] = quiet_hours
            out.attrs["_chronosift_profile_metadata"] = {
                "selection_mode": profile_manifest.get("selection_mode"),
                "used_filtered_subset": bool(profile_manifest.get("used_filtered_subset", False)),
                "source_event_count": int(profile_manifest.get("source_event_count", 0) or 0),
                "selected_event_count": int(profile_manifest.get("selected_event_count", 0) or 0),
            }
            return out

        alpha = float(self.profiling_cfg.get("smoothing_alpha", 1.0))
        min_profile_events = int(self.profiling_cfg.get("min_profile_events", 100))

        profile_df = _select_profile_events(out)
        if len(profile_df) < min_profile_events:
            profile_df = out

        if len(profile_df) < min_profile_events:
            out["hour_rarity"] = 0.0
            out.attrs["_chronosift_quiet_hours_profile"] = frozenset()
            return out

        quiet_quantile = float(self.profiling_cfg.get("quiet_quantile", 0.10))
        profile, quiet_hours = _compute_hour_of_week_profile(
            profile_df,
            alpha=alpha,
            quiet_quantile=quiet_quantile,
        )

        _profile_arr = np.zeros(168, dtype=np.float64)
        for _k, _v in profile.items():
            _profile_arr[int(_k)] = float(_v)
        _valid = how_all.notna()
        _idx = how_all.to_numpy(dtype=np.float64, na_value=0.0).astype(np.intp)
        np.clip(_idx, 0, 167, out=_idx)
        out["hour_rarity"] = np.where(_valid.to_numpy(), _profile_arr[_idx], 0.0)
        out.attrs["_chronosift_quiet_hours_profile"] = frozenset(quiet_hours)
        return out


    def _parse_profile_multipliers(self, raw: List[Dict[str, Any]]) -> List[ProfileMultiplier]:
        parsed: List[ProfileMultiplier] = []
        for m in raw:
            mid = str(m.get("id", "")).strip()
            if not mid:
                continue
            applies = set(str(s).strip() for s in (m.get("applies_to_signals", []) or []) if str(s).strip())
            if not applies:
                continue
            k = float(m.get("k", 0.0))
            parsed.append(ProfileMultiplier(mid=mid, applies_to=applies, k=k))
        return parsed


    # -------------------------------------------------------------------------
    # Parsing rules
    # -------------------------------------------------------------------------

    def _parse_condition(self, raw: Dict[str, Any]) -> Condition:
        return Condition(field=str(raw.get("field", "")), op=str(raw.get("op", "")), value=raw.get("value", None))

    def _parse_rules(self, raw_rules: List[Dict[str, Any]]) -> List[Rule]:
        parsed: List[Rule] = []
        for rr in raw_rules:
            rid = str(rr.get("id", "")).strip()
            if not rid:
                continue

            scope = rr.get("scope", {}) or {}
            scope_any = [self._parse_condition(c) for c in (scope.get("any", []) or [])]
            scope_all = [self._parse_condition(c) for c in (scope.get("all", []) or [])]

            when = rr.get("when", {}) or {}
            when_any = [self._parse_condition(c) for c in (when.get("any", []) or [])]
            when_all = [self._parse_condition(c) for c in (when.get("all", []) or [])]

            emit = rr.get("emit", {}) or {}
            emit_signals = [EmitSignal(name=str(s.get("name", "")), value=s.get("value", 1))
                            for s in (emit.get("signals", []) or [])]

            emit_modifiers = [Modifier(
                target_signal=str(m.get("target_signal", "")),
                op=str(m.get("op", "")),
                value=float(m.get("value", 1.0)),
            ) for m in (emit.get("modifiers", []) or [])]

            evidence_fields = [str(e.get("field", "")).strip()
                               for e in (emit.get("evidence", []) or []) if str(e.get("field", "")).strip()]

            parsed.append(Rule(
                rule_id=rid,
                description=str(rr.get("description", "")).strip(),
                priority=int(rr.get("priority", 0)),
                scope_any=scope_any,
                scope_all=scope_all,
                when_any=when_any,
                when_all=when_all,
                emit_signals=emit_signals,
                emit_modifiers=emit_modifiers,
                evidence_fields=evidence_fields,
                confidence=str(rr.get("confidence", "medium")),
            ))

        parsed.sort(key=lambda r: r.priority, reverse=True)
        return parsed

    def _parse_temporal_rules(self, raw_tr: List[Dict[str, Any]]) -> List[TemporalRule]:
        parsed: List[TemporalRule] = []
        for tr in raw_tr:
            rid = str(tr.get("id", "")).strip()
            if not rid:
                continue

            key_by = [str(k).strip() for k in (tr.get("key_by", []) or []) if str(k).strip()]
            if not key_by:
                continue

            lookback = parse_lookback(tr.get("lookback", "0h"))
            desc = str(tr.get("description", "")).strip()
            prio = int(tr.get("priority", 0))
            conf = str(tr.get("confidence", "medium"))

            mode = ""
            seq: List[TemporalNeed] = []
            co_all: List[TemporalNeed] = []
            fld: Optional[str] = None

            if "sequence" in tr:
                mode = "sequence"
                for step in (tr.get("sequence", []) or []):
                    seq.append(TemporalNeed(signal=str(step.get("signal", "")),
                                            min_count=int(step.get("min_count", 1))))
            elif "cooccur" in tr:
                mode = "cooccur"
                all_part = (tr.get("cooccur", {}) or {}).get("all", []) or []
                for need in all_part:
                    co_all.append(TemporalNeed(signal=str(need.get("signal", "")),
                                               min_count=int(need.get("min_count", 1))))
            elif "condition" in tr:
                cond = tr.get("condition", {}) or {}
                kind = str(cond.get("kind", "")).strip()
                if kind == "first_seen_value":
                    mode = "first_seen_value"
                    fld = str(cond.get("field", "")).strip() or None
                elif kind == "change_detected":
                    mode = "change_detected"
                    fld = str(cond.get("field", "")).strip() or None
                else:
                    continue
            else:
                continue

            emit = tr.get("emit", {}) or {}
            emit_signals = [EmitSignal(name=str(s.get("name", "")), value=s.get("value", 1))
                            for s in (emit.get("signals", []) or [])]
            if not emit_signals:
                continue

            parsed.append(TemporalRule(
                rule_id=rid,
                description=desc,
                priority=prio,
                key_by=key_by,
                lookback=lookback,
                mode=mode,
                sequence=seq,
                cooccur_all=co_all,
                field=fld,
                emit_signals=emit_signals,
                confidence=conf,
            ))

        parsed.sort(key=lambda r: r.priority, reverse=True)
        return parsed

    # -------------------------------------------------------------------------
    # Per-event evaluation (tuple-based for performance)
    # -------------------------------------------------------------------------

    def _get_field_tuple(self, row: Any, field: str) -> Any:
        return getattr(row, field, None)

    def _cond_match_tuple(self, row: Any, cond: Condition) -> bool:
        if not cond.field or not cond.op or cond.op not in OP_MAP:
            return False
        field_val = self._get_field_tuple(row, cond.field)
        op_func = OP_MAP[cond.op]
        try:
            if cond.op == "exists":
                return op_func(field_val)
            if cond.op == "regex":
                return op_func(field_val, cond.value)
            if cond.op in ("in", "in_ci"):
                return op_func(field_val, cond.value or [])
            if cond.op in ("contains", "contains_ci"):
                return op_func(field_val, str(cond.value))
            if cond.op in ("lt", "lte", "gt", "gte"):
                return op_func(field_val, cond.value)
            return op_func(field_val, cond.value)
        except Exception:
            return False

    def _conds_all_tuple(self, row: Any, conds: List[Condition]) -> bool:
        return all(self._cond_match_tuple(row, c) for c in conds) if conds else True

    def _conds_any_tuple(self, row: Any, conds: List[Condition]) -> bool:
        return any(self._cond_match_tuple(row, c) for c in conds) if conds else True

    def _rule_matches_tuple(self, row: Any, rule: Rule) -> bool:
        if not self._conds_all_tuple(row, rule.scope_all):
            return False
        if rule.scope_any and not self._conds_any_tuple(row, rule.scope_any):
            return False
        if not self._conds_all_tuple(row, rule.when_all):
            return False
        if rule.when_any and not self._conds_any_tuple(row, rule.when_any):
            return False
        return True

    def _eval_row_tuple(self, row: Any) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        signals: Dict[str, Any] = {}
        explain: List[Dict[str, Any]] = []
        modifiers: List[Modifier] = []

        for rule in self.rules:
            if not self._rule_matches_tuple(row, rule):
                continue

            for es in rule.emit_signals:
                if not es.name:
                    continue
                if isinstance(es.value, (int, float)):
                    signals[es.name] = float(signals.get(es.name, 0.0)) + float(es.value)
                else:
                    if es.name not in signals:
                        signals[es.name] = es.value
                    else:
                        cur = signals[es.name]
                        if isinstance(cur, list):
                            cur.append(es.value)
                        else:
                            signals[es.name] = [cur, es.value]

            modifiers.extend(rule.emit_modifiers)

            ev: Dict[str, str] = {}
            for f in rule.evidence_fields:
                v = self._get_field_tuple(row, f)
                if not _is_null(v):
                    s = _safe_str(v)
                    ev[f] = _truncate_evidence_text(s)

            explain.append({
                "rule_id": rule.rule_id,
                "description": rule.description,
                "confidence": rule.confidence,
                "evidence": ev,
            })

        # Apply modifiers deterministically after rule emissions
        for mod in modifiers:
            if mod.op != "multiply" or not mod.target_signal:
                continue
            if mod.target_signal not in signals:
                continue
            try:
                signals[mod.target_signal] = float(signals[mod.target_signal]) * float(mod.value)
                explain.append({
                    "rule_id": "MODIFIER",
                    "description": f"Modifier applied: multiply {mod.value} to {mod.target_signal}",
                    "confidence": "high",
                    "evidence_type": "direct",
                    "evidence": {
                        "target_signal": mod.target_signal,
                        "multiplier": float(mod.value),
                    },
                })
            except Exception:
                continue

        return signals, explain

    def _eval_atomic_rules_sparse_legacy(
        self,
        df: pd.DataFrame,
    ) -> Tuple[Dict[int, Dict[str, Any]], Dict[int, List[Dict[str, Any]]]]:
        signal_map: Dict[int, Dict[str, Any]] = {}
        explain_map: Dict[int, List[Dict[str, Any]]] = {}

        for i, row in enumerate(df.itertuples(index=False, name="ChronoRow")):
            signals, explain = self._eval_row_tuple(row)
            if signals:
                signal_map[i] = signals
            if explain:
                explain_map[i] = explain

        return signal_map, explain_map

    def _eval_atomic_rules_sparse(
        self,
        df: pd.DataFrame,
    ) -> Tuple[Dict[int, Dict[str, Any]], Dict[int, List[Dict[str, Any]]]]:
        nrows = len(df)
        if nrows == 0 or not self.rules:
            return {}, {}

        signal_map: Dict[int, Dict[str, Any]] = {}
        explain_map: Dict[int, List[Dict[str, Any]]] = {}
        modifier_map: Dict[int, List[Modifier]] = {}

        raw_cache: Dict[str, pd.Series] = {}
        text_cache: Dict[str, pd.Series] = {}
        lower_cache: Dict[str, pd.Series] = {}
        strip_lower_cache: Dict[str, pd.Series] = {}
        numeric_cache: Dict[str, pd.Series] = {}
        null_mask_cache: Dict[str, np.ndarray] = {}
        evidence_cache: Dict[str, np.ndarray] = {}
        condition_cache: Dict[Tuple[str, str, str], np.ndarray] = {}

        def _field_series(field: str) -> pd.Series:
            ser = raw_cache.get(field)
            if ser is None:
                if field in df.columns:
                    ser = df[field]
                else:
                    ser = pd.Series(pd.NA, index=df.index, dtype=object)
                raw_cache[field] = ser
            return ser

        def _text_series(field: str) -> pd.Series:
            ser = text_cache.get(field)
            if ser is None:
                raw = _field_series(field).astype("string")
                stripped = raw.str.strip()
                placeholder_mask = stripped.str.lower().isin(PLACEHOLDER_STRINGS)
                ser = raw.mask(stripped.eq("") | placeholder_mask, "")
                text_cache[field] = ser
            return ser

        def _lower_text_series(field: str) -> pd.Series:
            ser = lower_cache.get(field)
            if ser is None:
                ser = _text_series(field).str.lower()
                lower_cache[field] = ser
            return ser

        def _strip_lower_text_series(field: str) -> pd.Series:
            ser = strip_lower_cache.get(field)
            if ser is None:
                ser = _text_series(field).str.strip().str.lower()
                strip_lower_cache[field] = ser
            return ser

        def _numeric_series(field: str) -> pd.Series:
            ser = numeric_cache.get(field)
            if ser is None:
                ser = pd.to_numeric(_field_series(field), errors="coerce")
                numeric_cache[field] = ser
            return ser

        def _semantic_null_mask(field: str) -> np.ndarray:
            mask = null_mask_cache.get(field)
            if mask is None:
                raw = _field_series(field)
                if str(raw.dtype) == "string" or pd.api.types.is_object_dtype(raw.dtype):
                    mask = _text_series(field).eq("").to_numpy(dtype=bool, copy=False)
                else:
                    mask = pd.isna(raw).to_numpy(dtype=bool, copy=False)
                null_mask_cache[field] = mask
            return mask

        def _condition_mask(cond: Condition) -> np.ndarray:
            key = (str(cond.field), str(cond.op), repr(cond.value))
            cached = condition_cache.get(key)
            if cached is not None:
                return cached

            field = str(cond.field or "").strip()
            op = str(cond.op or "").strip()
            if not field or not op or op not in OP_MAP:
                mask = np.zeros(nrows, dtype=bool)
                condition_cache[key] = mask
                return mask

            try:
                if op == "exists":
                    mask = ~_semantic_null_mask(field)
                elif op == "eq":
                    series = _field_series(field)
                    mask = series.eq(cond.value).fillna(False).to_numpy(dtype=bool, copy=False) & ~_semantic_null_mask(field)
                elif op == "in":
                    series = _field_series(field)
                    mask = series.isin(cond.value or []).fillna(False).to_numpy(dtype=bool, copy=False) & ~_semantic_null_mask(field)
                elif op == "in_ci":
                    needles = {str(v).strip().lower() for v in (cond.value or []) if str(v).strip()}
                    if needles:
                        mask = _strip_lower_text_series(field).isin(needles).fillna(False).to_numpy(dtype=bool, copy=False)
                    else:
                        mask = np.zeros(nrows, dtype=bool)
                elif op == "contains":
                    needle = str(cond.value)
                    if needle:
                        mask = _text_series(field).str.contains(needle, regex=False, na=False).to_numpy(dtype=bool, copy=False)
                    else:
                        mask = np.zeros(nrows, dtype=bool)
                elif op == "contains_ci":
                    needle = str(cond.value).lower()
                    if needle:
                        mask = _lower_text_series(field).str.contains(needle, regex=False, na=False).to_numpy(dtype=bool, copy=False)
                    else:
                        mask = np.zeros(nrows, dtype=bool)
                elif op == "regex":
                    pattern = str(cond.value or "")
                    if pattern:
                        with warnings.catch_warnings():
                            warnings.filterwarnings(
                                "ignore",
                                message="This pattern is interpreted as a regular expression, and has match groups.*",
                                category=UserWarning,
                            )
                            mask = _text_series(field).str.contains(pattern, regex=True, na=False).to_numpy(dtype=bool, copy=False)
                    else:
                        mask = np.zeros(nrows, dtype=bool)
                elif op == "lt":
                    mask = (_numeric_series(field) < float(cond.value)).fillna(False).to_numpy(dtype=bool, copy=False)
                elif op == "lte":
                    mask = (_numeric_series(field) <= float(cond.value)).fillna(False).to_numpy(dtype=bool, copy=False)
                elif op == "gt":
                    mask = (_numeric_series(field) > float(cond.value)).fillna(False).to_numpy(dtype=bool, copy=False)
                elif op == "gte":
                    mask = (_numeric_series(field) >= float(cond.value)).fillna(False).to_numpy(dtype=bool, copy=False)
                else:
                    mask = np.zeros(nrows, dtype=bool)
            except Exception:
                mask = np.zeros(nrows, dtype=bool)

            condition_cache[key] = mask
            return mask

        def _rule_mask(rule: Rule) -> np.ndarray:
            mask = np.ones(nrows, dtype=bool)

            for cond in rule.scope_all:
                mask &= _condition_mask(cond)
                if not bool(mask.any()):
                    return mask

            if rule.scope_any:
                any_mask = np.zeros(nrows, dtype=bool)
                for cond in rule.scope_any:
                    any_mask |= _condition_mask(cond)
                mask &= any_mask
                if not bool(mask.any()):
                    return mask

            for cond in rule.when_all:
                mask &= _condition_mask(cond)
                if not bool(mask.any()):
                    return mask

            if rule.when_any:
                any_mask = np.zeros(nrows, dtype=bool)
                for cond in rule.when_any:
                    any_mask |= _condition_mask(cond)
                mask &= any_mask

            return mask

        for rule in self.rules:
            match_mask = _rule_mask(rule)
            if not bool(match_mask.any()):
                continue

            positions = np.flatnonzero(match_mask)
            evidence_fields = [f for f in rule.evidence_fields if f]

            for pos in positions:
                row_i = int(pos)
                signals = signal_map.get(row_i)

                if signals is None and rule.emit_signals:
                    signals = {}
                    signal_map[row_i] = signals

                if signals is not None:
                    for es in rule.emit_signals:
                        if not es.name:
                            continue
                        if isinstance(es.value, (int, float)):
                            signals[es.name] = float(signals.get(es.name, 0.0)) + float(es.value)
                        else:
                            if es.name not in signals:
                                signals[es.name] = es.value
                            else:
                                cur = signals[es.name]
                                if isinstance(cur, list):
                                    cur.append(es.value)
                                else:
                                    signals[es.name] = [cur, es.value]

                if rule.emit_modifiers:
                    modifier_map.setdefault(row_i, []).extend(rule.emit_modifiers)

                ev: Dict[str, str] = {}
                for field in evidence_fields:
                    values = evidence_cache.get(field)
                    if values is None:
                        if field in df.columns:
                            values = df[field].to_numpy(dtype=object, copy=False)
                        else:
                            values = np.full(nrows, None, dtype=object)
                        evidence_cache[field] = values
                    value = values[row_i]
                    if not _is_null(value):
                        s = _safe_str(value)
                        ev[field] = _truncate_evidence_text(s)

                explain_map.setdefault(row_i, []).append({
                    "rule_id": rule.rule_id,
                    "description": rule.description,
                    "confidence": rule.confidence,
                    "evidence": ev,
                })

        for row_i, modifiers in modifier_map.items():
            signals = signal_map.get(row_i)
            if not signals:
                continue
            explain = explain_map.setdefault(row_i, [])
            for mod in modifiers:
                if mod.op != "multiply" or not mod.target_signal:
                    continue
                if mod.target_signal not in signals:
                    continue
                try:
                    signals[mod.target_signal] = float(signals[mod.target_signal]) * float(mod.value)
                    explain.append({
                        "rule_id": "MODIFIER",
                        "description": f"Modifier applied: multiply {mod.value} to {mod.target_signal}",
                        "confidence": "high",
                        "evidence_type": "direct",
                        "evidence": {
                            "target_signal": mod.target_signal,
                            "multiplier": float(mod.value),
                        },
                    })
                except Exception:
                    continue

        return signal_map, explain_map

    # -------------------------------------------------------------------------
    # Temporal rules
    # -------------------------------------------------------------------------

    
    # -------------------------------------------------------------------------
    # Impossible travel
    # -------------------------------------------------------------------------

    # -------------------------------------------------------------------------
    # Scoring
    # -------------------------------------------------------------------------

    def _score_signals(self, signals: Dict[str, Any]) -> float:
        total = 0.0
        for sig, val in signals.items():
            sig_key = str(sig).strip().lower()
            if sig_key not in self.weights:
                continue
            if isinstance(val, (int, float)):
                total += float(val) * float(self.weights[sig_key])
        return float(min(total, self.max_event_score))

    @staticmethod
    def _subset_sparse_state(
        df: pd.DataFrame,
        signal_map: Dict[int, Dict[str, Any]],
        explain_map: Dict[int, List[Dict[str, Any]]],
        mask: pd.Series,
        columns: Optional[List[str]] = None,
    ) -> Tuple[pd.DataFrame, Dict[int, Dict[str, Any]], Dict[int, List[Dict[str, Any]]], Dict[int, int]]:
        """Subset a frame and remap sparse state from old row positions to new row positions."""
        if len(mask) != len(df):
            raise ValueError("Mask length must match DataFrame length")
        mask_array = mask.to_numpy(dtype=bool, copy=False) if hasattr(mask, "to_numpy") else np.asarray(mask, dtype=bool)
        selected_old = np.flatnonzero(mask_array)
        cols = [c for c in (columns or []) if c in df.columns] if columns else None
        # Slice from an attrs-free shallow wrapper so pandas does not propagate
        # large sparse-state attrs during boolean indexing on big partitions.
        source = _drop_dataframe_attrs(df)
        if cols is not None:
            col_positions = [source.columns.get_loc(c) for c in cols]
            sub = source.iloc[selected_old, col_positions]
        else:
            sub = source.iloc[selected_old]
        new_signal_map: Dict[int, Dict[str, Any]] = {}
        new_explain_map: Dict[int, List[Dict[str, Any]]] = {}
        old_to_new: Dict[int, int] = {}
        for new_i, old_i in enumerate(selected_old.tolist()):
            old_i = int(old_i)
            old_to_new[old_i] = new_i
            if old_i in signal_map:
                new_signal_map[new_i] = signal_map[old_i]
            if old_i in explain_map:
                new_explain_map[new_i] = explain_map[old_i]
        for attr_name, attr_value in (df.attrs or {}).items():
            if attr_name == "chronosift_sparse":
                continue
            sub.attrs[attr_name] = attr_value
        sparse_attrs = dict((df.attrs.get("chronosift_sparse", {}) or {}))
        sparse_attrs["signal_map"] = new_signal_map
        sparse_attrs["explain_map"] = new_explain_map
        sub.attrs["chronosift_sparse"] = sparse_attrs
        return sub, new_signal_map, new_explain_map, old_to_new

    @staticmethod
    def _merge_sparse_contextual_updates(
        full_df: pd.DataFrame,
        full_signal_map: Dict[int, Dict[str, Any]],
        full_explain_map: Dict[int, List[Dict[str, Any]]],
        candidate_df: pd.DataFrame,
        old_to_new: Dict[int, int],
    ) -> pd.DataFrame:
        """Merge candidate contextual updates back into the full atomic result."""
        cand_sparse = candidate_df.attrs.get("chronosift_sparse", {}) or {}
        cand_signal_map = cand_sparse.get("signal_map", {}) or {}
        cand_explain_map = cand_sparse.get("explain_map", {}) or {}

        for old_i, new_i in old_to_new.items():
            if new_i in cand_signal_map:
                full_signal_map[old_i] = cand_signal_map[new_i]
            elif old_i in full_signal_map:
                full_signal_map.pop(old_i, None)
            if new_i in cand_explain_map:
                full_explain_map[old_i] = cand_explain_map[new_i]
            elif old_i in full_explain_map:
                full_explain_map.pop(old_i, None)

        # Invariant: old_to_new keys are in ascending positional order (built by
        # _subset_sparse_state iterating sorted selected_old), matching
        # candidate_df row order. The iloc assignment below depends on this.
        old_positions = list(old_to_new.keys())
        assert old_positions == sorted(old_positions), (
            "_merge_sparse_contextual_updates requires old_to_new keys in ascending order"
        )
        for col in [
            "travel_distance_km", "travel_dt_hours", "travel_velocity_kmh",
            "travel_from_country", "travel_to_country", "travel_from_ip",
            "geo_new_country", "geo_new_asn", "geo_boundary_crossing",
            "geo_new_city",
        ]:
            if col in candidate_df.columns:
                if col not in full_df.columns:
                    full_df[col] = pd.NA
                full_df.iloc[old_positions, full_df.columns.get_loc(col)] = candidate_df[col].to_numpy()

        full_df.attrs.setdefault("chronosift_sparse", {})
        full_df.attrs["chronosift_sparse"]["signal_map"] = full_signal_map
        full_df.attrs["chronosift_sparse"]["explain_map"] = full_explain_map
        return full_df

    @staticmethod
    def _build_candidate_window_mask(
        df: pd.DataFrame,
        score_col: str = "chronosift_score",
        threshold: float = 0.0,
        window: Union[str, timedelta] = "30m",
        actor_cols: Optional[List[str]] = None,
        base_mask: Optional[pd.Series] = None,
    ) -> pd.Series:
        """Return a boolean mask retaining signalled rows and nearby context windows."""
        if not isinstance(df.index, pd.DatetimeIndex):
            raise ValueError("Candidate reduction requires a DatetimeIndex.")

        td = parse_lookback(window) if isinstance(window, str) else window
        actor_cols = actor_cols or []

        if base_mask is None:
            if score_col not in df.columns:
                raise ValueError(f"Missing score column: {score_col!r}")
            base = df[score_col].fillna(0).astype(float) > float(threshold)
        else:
            if len(base_mask) != len(df):
                raise ValueError("Base mask length must match DataFrame length")
            if isinstance(base_mask, pd.Series):
                base = pd.Series(base_mask.to_numpy(dtype=bool, copy=False), index=df.index)
            else:
                base = pd.Series([bool(x) for x in base_mask], index=df.index, dtype=bool)

        if not base.any():
            return pd.Series(False, index=df.index)

        index = df.index
        window_delta = pd.Timedelta(td)
        base_arr = base.to_numpy(dtype=bool, copy=False)
        mask_arr = base_arr.copy()

        for timestamp in index[base_arr].unique():
            left = index.searchsorted(timestamp - window_delta, side="left")
            right = index.searchsorted(timestamp + window_delta, side="right")
            mask_arr[left:right] = True

        mask = pd.Series(mask_arr, index=index)

        for col in actor_cols:
            if col not in df.columns:
                continue
            norm_col = df[col].astype("string").fillna("").str.strip()
            vals = set(v for v in norm_col[base].values if v)
            if vals:
                mask |= norm_col.isin(vals)

        return mask

    def process_parquet_dataset_partitioned(
        self,
        dataset_root: str,
        output_root: str,
        overlap: str = "24h",
        materialise_event_columns: bool = False,
        materialise_explain_columns: bool = True,
        geoip_city_db: Optional[str] = None,
        geoip_asn_db: Optional[str] = None,
        av_csv_path: Optional[str] = None,
        luhn_csv_path: Optional[str] = None,
        nsrl_parquet_path: Optional[str] = None,
        candidate_threshold: float = 0.0,
        candidate_window: str = "30m",
        profile_manifest: Optional[Dict[str, Any]] = None,
        file_hit_manifest: Optional[Dict[str, Any]] = None,
        profile_manifest_path: Optional[str] = None,
        file_hit_manifest_path: Optional[str] = None,
        output_mode: str = "full",
        row_id_col: str = CHRONOSIFT_ROW_ID_COLUMN,
        clean_output_root: Optional[bool] = None,
        telemetry_jsonl_path: Optional[str] = None,
        retain_zero_weight_lifecycle_signals: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Process a Hive-partitioned parquet dataset month-by-month using a staged pipeline:
          1) full partition atomic pass
          2) full non-temporal contextual pass
          3) candidate-reduced temporal/stateful pass when safe

        Base parquet is treated as immutable evidence. In sidecar mode this
        method writes only derived ChronoSift/enrichment columns keyed by
        `chronosift_row_id`, while overlap rows are used solely for temporal
        context and never emitted into the output month twice.

        Partition mode omits generic zero-weight file lifecycle signals and
        their explanations by default. Set
        ``retain_zero_weight_lifecycle_signals=True`` for compatibility exports;
        specialised/scored lifecycle detections are always retained.
        """
        reports: List[Dict[str, Any]] = []
        output_mode = str(output_mode or "full").strip().lower()
        if output_mode not in {"full", "sidecar"}:
            raise ValueError(f"Unsupported output_mode: {output_mode!r}")

        if clean_output_root is None:
            clean_output_root = True

        telemetry = _TelemetryWriter(telemetry_jsonl_path)
        telemetry.open()
        telemetry.emit(
            "run_start",
            dataset_root=str(dataset_root),
            output_root=str(output_root),
            output_mode=output_mode,
            overlap=str(overlap),
            retain_zero_weight_lifecycle_signals=bool(retain_zero_weight_lifecycle_signals),
        )
        try:
            output_root_path = Path(output_root)
            if clean_output_root and output_root_path.exists():
                if output_root_path.is_dir():
                    shutil.rmtree(output_root_path, ignore_errors=True)
                else:
                    output_root_path.unlink(missing_ok=True)
                _invalidate_dataset_columns_cache(str(output_root_path))
            elif output_root_path.exists() and not output_root_path.is_dir():
                raise ValueError(f"Output path must be a directory-compatible parquet dataset path: {output_root!r}")

            if not output_root_path.exists():
                output_root_path.mkdir(parents=True, exist_ok=True)

            base_dataset_columns = set(_duckdb_dataset_columns(dataset_root))

            if output_mode == "sidecar" and row_id_col not in base_dataset_columns:
                raise ValueError(
                    f"Base dataset {dataset_root!r} does not contain required sidecar key column {row_id_col!r}. "
                    "Add a persistent row-id column during base parquet creation before using sidecar output."
                )

            logger.info("Pipeline stage: preparing profile manifest")
            with telemetry.stage("prepare_profile_manifest"):
                # Profiling manifests are dataset-level state. Persisting them
                # keeps reruns focused on engine work instead of recomputation.
                if profile_manifest is None:
                    if profile_manifest_path and Path(profile_manifest_path).exists():
                        profile_manifest = load_profile_manifest(profile_manifest_path)
                    else:
                        profile_manifest = build_global_hour_of_week_manifest(
                            dataset_root,
                            profiling_cfg=(self.profiling_cfg or {}),
                        )
                        if profile_manifest_path:
                            save_profile_manifest(profile_manifest, profile_manifest_path)

            logger.info("Pipeline stage: preparing referenced-file hit manifest")
            with telemetry.stage("prepare_file_hit_manifest"):
                # Referenced-file propagation is intentionally precomputed once
                # because rediscovering it partition-by-partition is expensive
                # on large corpora and adds no new information.
                if file_hit_manifest is None:
                    if file_hit_manifest_path and Path(file_hit_manifest_path).exists():
                        file_hit_manifest = load_file_hit_manifest(file_hit_manifest_path)
                        if int(file_hit_manifest.get("schema_version", 0) or 0) < 4:
                            logger.info(
                                "Referenced-file manifest predates classification-preserving web identity; rebuilding %s",
                                file_hit_manifest_path,
                            )
                            file_hit_manifest = build_global_referenced_file_hit_manifest(
                                dataset_root,
                                av_csv_path=av_csv_path,
                                luhn_csv_path=luhn_csv_path,
                                referenced_file_cfg=self.referenced_file_cfg,
                                yara_metadata_index=self.yara_metadata_index,
                            )
                            save_file_hit_manifest(file_hit_manifest, file_hit_manifest_path)
                    else:
                        file_hit_manifest = build_global_referenced_file_hit_manifest(
                            dataset_root,
                            av_csv_path=av_csv_path,
                            luhn_csv_path=luhn_csv_path,
                            referenced_file_cfg=self.referenced_file_cfg,
                            yara_metadata_index=self.yara_metadata_index,
                        )
                        if file_hit_manifest_path:
                            save_file_hit_manifest(file_hit_manifest, file_hit_manifest_path)

            logger.info("Pipeline stage: preparing NSRL lookup source")
            with telemetry.stage("prepare_nsrl_lookup_source"):
                nsrl_cache_df = _ensure_nsrl_cache(
                    nsrl_parquet_path=nsrl_parquet_path,
                )

            geo_continuity_state: Dict[tuple, Dict[str, Any]] = {}
            impossible_travel_state: Dict[tuple, Dict[str, Any]] = {}
            ip_continuity_state: Dict[tuple, Dict[str, Any]] = {}

            for year, month, _part_path in iter_hive_year_month_partitions(dataset_root):
                logger.info("Pipeline stage: processing partition %04d-%02d", year, month)
                month_start = pd.Timestamp(year=year, month=month, day=1, tz="UTC")
                if month == 12:
                    month_end = pd.Timestamp(year=year + 1, month=1, day=1, tz="UTC")
                else:
                    month_end = pd.Timestamp(year=year, month=month + 1, day=1, tz="UTC")

                partition_fields = {"year": int(year), "month": int(month)}
                telemetry.emit("partition_start", **partition_fields)

                logger.info("Pipeline stage: loading partition window")
                atomic_columns = self._atomic_required_columns()
                if output_mode == "sidecar":
                    # Sidecar mode still needs the stable join key during the
                    # atomic/contextual pipeline even though the original base
                    # columns are not rewritten. This keeps the output narrow
                    # while allowing downstream DuckDB joins back to base data.
                    atomic_columns = sorted(set(atomic_columns) | {row_id_col})
                with telemetry.stage("load_partition_window", **partition_fields):
                    df = load_plaso_parquet_timerange(
                        dataset_root,
                        start=month_start,
                        end=month_end,
                        overlap=overlap,
                        columns=atomic_columns,
                    )
                if len(df) == 0:
                    logger.info("Pipeline stage: partition %04d-%02d has no rows after load", year, month)
                    telemetry.emit("partition_end", rows_loaded=0, rows_written=0, candidate_rows=0, **partition_fields)
                    continue

                logger.info("Pipeline stage: running atomic stage for partition %04d-%02d", year, month)
                with telemetry.stage("atomic_stage", rows_loaded=int(len(df)), **partition_fields):
                    # Atomic processing is the single-event rule layer. Keeping
                    # it distinct from contextual work makes stage telemetry and
                    # rule tuning far easier to interpret.
                    atomic = self.apply_atomic(
                        df,
                        apply_profiling=True,
                        enforce_required_fields=True,
                        geoip_city_db=geoip_city_db,
                        geoip_asn_db=geoip_asn_db,
                        av_csv_path=av_csv_path,
                        luhn_csv_path=luhn_csv_path,
                        nsrl_parquet_path=nsrl_parquet_path,
                        nsrl_cache_df=nsrl_cache_df,
                        materialise_event_columns=False,
                        profile_manifest=profile_manifest,
                    )

                sparse = atomic.attrs.get("chronosift_sparse", {}) or {}
                signal_map = sparse.get("signal_map", {}) or {}
                explain_map = sparse.get("explain_map", {}) or {}

                logger.info("Pipeline stage: running contextual stage for partition %04d-%02d", year, month)
                with telemetry.stage("contextual_non_temporal_stage", rows_loaded=int(len(atomic)), **partition_fields):
                    logger.info("Contextual stage: loading sparse state")
                    self._apply_non_temporal_contextual_sparse(
                        atomic,
                        signal_map,
                        explain_map,
                        apply_profiling=True,
                        file_hit_manifest=file_hit_manifest,
                        retain_zero_weight_lifecycle_signals=retain_zero_weight_lifecycle_signals,
                    )
                    atomic.loc[:, "chronosift_score"] = self._score_signal_map_sparse(
                        len(atomic),
                        signal_map,
                        index=atomic.index,
                        df=atomic,
                    )

                candidate_rows = 0
                if self.impossible_travel_cfg or self.private_ip_continuity_cfg or self.temporal_rules:
                    with telemetry.stage("contextual_temporal_stage", rows_loaded=int(len(atomic)), **partition_fields):
                        if self._temporal_candidate_reduction_safe():
                            # Candidate reduction is now anchored to temporal prerequisites rather
                            # than atomic score so contextual-only detections are still preserved.
                            temporal_base_mask = self._temporal_candidate_base_mask(atomic, signal_map)
                            temporal_window = self._temporal_candidate_window(candidate_window)
                            candidate_mask = self._build_candidate_window_mask(
                                atomic,
                                window=temporal_window,
                                actor_cols=[],
                                base_mask=temporal_base_mask,
                            )
                            candidate_rows = int(candidate_mask.sum())
                            logger.info(
                                "Pipeline stage: built candidate mask for partition %04d-%02d with %d candidate rows",
                                year,
                                month,
                                candidate_rows,
                            )

                            if candidate_rows == len(atomic):
                                self._apply_temporal_contextual_sparse(
                                    atomic,
                                    signal_map,
                                    explain_map,
                                    geo_continuity_state=geo_continuity_state,
                                    impossible_travel_state=impossible_travel_state,
                                    ip_continuity_state=ip_continuity_state,
                                )
                            elif candidate_rows > 0:
                                temporal_columns = self._temporal_required_columns()
                                candidate_df, candidate_signal_map, candidate_explain_map, old_to_new = self._subset_sparse_state(
                                    atomic,
                                    signal_map,
                                    explain_map,
                                    candidate_mask,
                                    columns=temporal_columns,
                                )
                                self._apply_temporal_contextual_sparse(
                                    candidate_df,
                                    candidate_signal_map,
                                    candidate_explain_map,
                                    geo_continuity_state=geo_continuity_state,
                                    impossible_travel_state=impossible_travel_state,
                                    ip_continuity_state=ip_continuity_state,
                                )
                                atomic = self._merge_sparse_contextual_updates(
                                    atomic, signal_map, explain_map, candidate_df, old_to_new
                                )
                        else:
                            candidate_rows = int(len(atomic))
                            logger.info(
                                "Pipeline stage: candidate reduction disabled for partition %04d-%02d due to stateful temporal requirements",
                                year,
                                month,
                            )
                            self._apply_temporal_contextual_sparse(
                                atomic,
                                signal_map,
                                explain_map,
                                geo_continuity_state=geo_continuity_state,
                                impossible_travel_state=impossible_travel_state,
                                ip_continuity_state=ip_continuity_state,
                            )

                        atomic.loc[:, "chronosift_score"] = self._score_signal_map_sparse(
                            len(atomic),
                            signal_map,
                            index=atomic.index,
                            df=atomic,
                        )

                logger.info("Pipeline stage: trimming overlap and preparing output for partition %04d-%02d", year, month)
                # Timerange loads include overlap rows so temporal state can look
                # across partition boundaries. Only the core month is written
                # back out, otherwise sidecar rows would be duplicated.
                core_mask = (atomic.index >= month_start) & (atomic.index < month_end)
                with telemetry.stage("prepare_output_partition", candidate_rows=int(candidate_rows), **partition_fields):
                    if materialise_event_columns:
                        logger.info("Pipeline stage: materialising review columns for partition %04d-%02d", year, month)
                        sparse = atomic.attrs.get("chronosift_sparse", {}) or {}
                        core_columns = list(atomic.columns)
                        if output_mode == "sidecar":
                            # Sidecar mode does not need the full event-width core
                            # frame just to materialise sparse columns. Restrict
                            # this subset to the eventual sidecar payload plus the
                            # few canonical fields needed for explain normalisation.
                            core_columns = _sidecar_materialisation_columns(atomic, row_id_col=row_id_col)
                        core, core_signal_map, core_explain_map, _ = self._subset_sparse_state(
                            atomic,
                            sparse.get("signal_map", {}) or {},
                            sparse.get("explain_map", {}) or {},
                            core_mask,
                            columns=core_columns,
                        )
                        self._materialise_sparse_event_columns(
                            core,
                            core_signal_map,
                            core_explain_map,
                            materialise_explain_columns=materialise_explain_columns,
                        )
                    else:
                        core = _drop_dataframe_attrs(atomic).loc[core_mask]
                    if output_mode == "sidecar":
                        # Sidecar output is intentionally minimal: retain only
                        # the stable row key plus derived ChronoSift/enrichment
                        # fields. The preserved base parquet remains the source
                        # of truth for original event columns.
                        core_to_write = _prepare_sidecar_output_frame(
                            core,
                            row_id_col=row_id_col,
                        )
                    else:
                        core_to_write = core
                out_path = str(Path(output_root))
                logger.info("Pipeline stage: writing output parquet for partition %04d-%02d", year, month)
                with telemetry.stage("write_output_partition", rows_written=int(len(core_to_write)), **partition_fields):
                    report = write_time_partitioned_parquet(
                        core_to_write,
                        out_path,
                        compression="zstd",
                        row_group_size=250_000,
                        max_rows_per_file=500_000,
                        index=True,
                        normalise=False,
                        nested_columns_encoding="arrow",
                    )
                logger.info("Pipeline stage: completed partition %04d-%02d", year, month)
                reports.append({
                    "year": year,
                    "month": month,
                    "rows_loaded": int(len(df)),
                    "candidate_rows": int(candidate_rows),
                    "rows_written": int(len(core_to_write)),
                    "output": out_path,
                    "output_mode": output_mode,
                    "retain_zero_weight_lifecycle_signals": bool(retain_zero_weight_lifecycle_signals),
                    "report": report,
                })
                telemetry.emit(
                    "partition_end",
                    rows_loaded=int(len(df)),
                    rows_written=int(len(core_to_write)),
                    candidate_rows=int(candidate_rows),
                    **partition_fields,
                )

            telemetry.emit("run_end", partitions=len(reports), rows_written=int(sum(int(r.get("rows_written", 0)) for r in reports)))
            return reports
        finally:
            telemetry.close()



def _parquet_dataset_glob(path: str) -> str:
    return str(Path(path) / "**/*.parquet") if Path(path).is_dir() else str(path)


def _dataset_cache_path(path: str) -> str:
    return str(Path(path).resolve())


def _dataset_columns_cache_key(path: str) -> Tuple[str, Tuple[Any, ...]]:
    p = Path(path)
    cache_path = _dataset_cache_path(path)

    if not p.exists():
        return cache_path, ("missing",)

    st = p.stat()
    kind = "file" if p.is_file() else "dir"
    return cache_path, (kind, int(st.st_mtime_ns), int(st.st_ctime_ns))


def _invalidate_dataset_columns_cache(path: str) -> None:
    cache_path = _dataset_cache_path(path)
    stale_keys = [key for key in ChronoSiftEngine._dataset_columns_cache if key[0] == cache_path]
    for key in stale_keys:
        ChronoSiftEngine._dataset_columns_cache.pop(key, None)


def _cleanup_partition_output_tree(
    outdir: Path,
    target_partitions: Set[Tuple[int, int]],
) -> None:
    for year_dir in outdir.glob("year=*"):
        if not year_dir.is_dir():
            continue
        try:
            year = int(str(year_dir.name).split("=", 1)[1])
        except Exception:
            continue

        for month_dir in year_dir.glob("month=*"):
            if not month_dir.is_dir():
                continue
            try:
                month = int(str(month_dir.name).split("=", 1)[1])
            except Exception:
                continue

            if (year, month) not in target_partitions:
                continue

            for stale_part in month_dir.glob("part-*.parquet"):
                try:
                    stale_part.unlink()
                except FileNotFoundError:
                    continue

        try:
            if year_dir.exists() and not any(year_dir.iterdir()):
                year_dir.rmdir()
        except Exception:
            pass


def _is_sidecar_output_column(column: str) -> bool:
    # Sidecar output is defined by semantic ownership, not by a frozen schema
    # snapshot. Prefix-based matching lets new derived fields flow into the
    # sidecar without updating multiple allowlists across the codebase.
    if not column or column in {"year", "month"}:
        return False
    if column in CHRONOSIFT_SIDECAR_COLUMNS:
        return True
    return column.startswith(CHRONOSIFT_SIDECAR_PREFIXES)


def _sidecar_output_columns(
    df: pd.DataFrame,
    row_id_col: str = CHRONOSIFT_ROW_ID_COLUMN,
) -> List[str]:
    if row_id_col not in df.columns:
        raise ValueError(
            f"Sidecar output requires a persistent row-id column {row_id_col!r} in the base parquet dataset."
        )

    # Sidecar datasets should contain only stable join keys and derived output.
    # That keeps writes small and lets readers decide later which base columns
    # to join back in for review or export.
    sidecar_cols = [
        str(col)
        for col in df.columns
        if str(col) != row_id_col and _is_sidecar_output_column(str(col))
    ]
    if not sidecar_cols:
        raise ValueError(
            "No sidecar output columns were identified. "
            "This usually means the base parquet already contains the derived ChronoSift columns "
            "or the frame was not materialised as expected."
        )
    return [row_id_col] + sidecar_cols


def _prepare_sidecar_output_frame(
    df: pd.DataFrame,
    row_id_col: str = CHRONOSIFT_ROW_ID_COLUMN,
) -> pd.DataFrame:
    # Slice from an attrs-free wrapper first. Clearing attrs after the slice is
    # too late for large partitions because pandas may already have propagated
    # the sparse-state metadata during `loc`.
    out = _drop_dataframe_attrs(df).loc[:, _sidecar_output_columns(df, row_id_col=row_id_col)]
    if getattr(out, "attrs", None):
        # Keep sidecar writes free of sparse-state attrs; embedding those maps in
        # parquet metadata caused a catastrophic write-path regression on large
        # Windows runs, even though it was not the only end-to-end bottleneck.
        out = pd.DataFrame(out, copy=False)
        out.attrs = {}
    return out


def _sidecar_materialisation_columns(
    df: pd.DataFrame,
    row_id_col: str = CHRONOSIFT_ROW_ID_COLUMN,
) -> List[str]:
    cols = list(_sidecar_output_columns(df, row_id_col=row_id_col))
    # Explain normalisation still needs canonical actor/IP fields even if they
    # are not all emitted as sidecar columns yet.
    for extra in ("actor_principal", "src_ip", "ip_address", "hour_rarity"):
        if extra in df.columns and extra not in cols:
            cols.append(extra)
    return cols


def _merge_sidecar_columns(
    base_df: pd.DataFrame,
    sidecar_df: pd.DataFrame,
    row_id_col: str = CHRONOSIFT_ROW_ID_COLUMN,
) -> pd.DataFrame:
    # This pandas join is the semantic fallback for environments that do not use
    # the preferred DuckDB path. Keep its behaviour aligned with the SQL join so
    # tests and ad hoc analysis see the same merged view.
    if len(base_df) == 0 or len(sidecar_df) == 0:
        return base_df
    if row_id_col not in base_df.columns:
        raise ValueError(f"Base DataFrame is missing sidecar join key {row_id_col!r}")
    if row_id_col not in sidecar_df.columns:
        raise ValueError(f"Sidecar DataFrame is missing sidecar join key {row_id_col!r}")

    sidecar_cols = [
        str(c)
        for c in sidecar_df.columns
        if str(c) != row_id_col and str(c) not in {"year", "month"}
    ]
    if not sidecar_cols:
        return base_df

    if bool(sidecar_df[row_id_col].duplicated().any()):
        raise ValueError(f"Sidecar join key {row_id_col!r} must be unique per row")

    overlap = [c for c in sidecar_cols if c in base_df.columns]
    if overlap:
        _delete_columns_inplace(base_df, overlap)

    # The sidecar key is expected to be unique and stable for the life of the
    # base dataset. We join on that key instead of on timestamps so duplicate
    # times and parser anomalies cannot corrupt alignment.
    sidecar_indexed = sidecar_df.set_index(row_id_col)
    return base_df.join(sidecar_indexed[sidecar_cols], on=row_id_col, how="left")


def _get_duckdb_connection():
    if ChronoSiftEngine._duckdb_conn is None:
        ChronoSiftEngine._duckdb_conn = duckdb.connect()
    return ChronoSiftEngine._duckdb_conn


def _dataset_datetime_column(path: str) -> Optional[str]:
    available = set(_duckdb_dataset_columns(path))

    for c in ("datetime", "date_time", "__index_level_0__", "index"):
        if c in available:
            return c
    return None


def _empty_projected_frame(require_datetime: bool = True) -> pd.DataFrame:
    if require_datetime:
        return pd.DataFrame(index=pd.DatetimeIndex([], tz="UTC", name="datetime"))
    return pd.DataFrame()


def _stable_sort_datetime_frame(
    df: pd.DataFrame,
    row_id_col: str = CHRONOSIFT_ROW_ID_COLUMN,
) -> pd.DataFrame:
    """Return a DatetimeIndex frame with a stable tie-break for duplicate timestamps."""
    if len(df) <= 1 or not isinstance(df.index, pd.DatetimeIndex):
        return df
    if df.index.is_monotonic_increasing and not df.index.has_duplicates:
        return df

    sort_meta = pd.DataFrame(
        {"__chronosift_dt_sort": df.index.asi8},
        index=pd.RangeIndex(len(df)),
    )
    sort_cols = ["__chronosift_dt_sort"]
    if row_id_col in df.columns:
        row_ids = df[row_id_col]
        if pd.api.types.is_numeric_dtype(row_ids.dtype):
            sort_meta["__chronosift_row_id_sort"] = pd.to_numeric(row_ids, errors="coerce").to_numpy(copy=False)
        else:
            sort_meta["__chronosift_row_id_sort"] = row_ids.astype("string").fillna("").to_numpy(copy=False)
        sort_cols.append("__chronosift_row_id_sort")

    order = sort_meta.sort_values(sort_cols, kind="mergesort").index.to_numpy(dtype=np.int64, copy=False)
    if np.array_equal(order, np.arange(len(df), dtype=np.int64)):
        return df
    return df.iloc[order]


def _restore_datetime_index(df: pd.DataFrame) -> pd.DataFrame:
    """Ensure a timezone-aware DatetimeIndex after parquet loading."""
    if isinstance(df.index, pd.DatetimeIndex):
        if df.index.tz is None:
            raise ValueError("DatetimeIndex must be timezone-aware (UTC expected)")
        if df.index.hasnans:
            raise ValueError("DatetimeIndex contains NaT values")
        return _stable_sort_datetime_frame(df)

    for idx_col in ("datetime", "date_time", "__index_level_0__", "index"):
        if idx_col in df.columns:
            dt = pd.to_datetime(df[idx_col], errors="coerce", utc=True)
            valid = dt.notna()
            df = df.loc[valid]
            dt = dt.loc[valid]
            df = df.set_index(dt).drop(columns=[idx_col], errors="ignore")
            df.index.name = "datetime"
            if df.index.tz is None:
                raise ValueError("DatetimeIndex must be timezone-aware (UTC expected)")
            if df.index.hasnans:
                raise ValueError("DatetimeIndex contains NaT values")
            return _stable_sort_datetime_frame(df)

    raise ValueError("Parquet dataset must already include a datetime index or recoverable datetime column")



def _duckdb_read_parquet_df(
    path: str,
    columns: Optional[List[str]] = None,
    where_sql: str = "",
    params: Optional[List[Any]] = None,
    require_datetime: bool = True,
) -> pd.DataFrame:
    """Read a hive-partitioned parquet dataset with DuckDB, projecting only required columns."""
    dataset_glob = _parquet_dataset_glob(path)
    available = set(_duckdb_dataset_columns(path))

    explicit_projection = columns is not None
    scan_cols: Optional[List[str]] = None
    if explicit_projection:
        scan_cols = [str(c) for c in columns if str(c) in available]

    if require_datetime and explicit_projection:
        dt_col = _dataset_datetime_column(path)
        if dt_col:
            if dt_col not in scan_cols:
                scan_cols.insert(0, dt_col)

    if explicit_projection and scan_cols == []:
        return _empty_projected_frame(require_datetime=require_datetime)

    select_sql = "*"
    if scan_cols is not None:
        select_sql = ", ".join('"' + str(c).replace('"', '""') + '"' for c in scan_cols)

    sql = f"SELECT {select_sql} FROM read_parquet(?, hive_partitioning=1, union_by_name=1)"
    if where_sql:
        sql += f" WHERE {where_sql}"

    con = _get_duckdb_connection()
    df = _restore_stable_nested_payloads(
        con.execute(sql, [dataset_glob] + (params or [])).fetch_df()
    )

    if require_datetime:
        return _restore_datetime_index(df)
    return df


def _duckdb_quote_ident(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def _duckdb_sql_string(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _unique_preserve_order(items: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _duckdb_read_joined_parquet_df(
    base_path: str,
    sidecar_path: str,
    *,
    base_columns: Optional[List[str]] = None,
    sidecar_columns: Optional[List[str]] = None,
    base_where_sql: str = "",
    base_params: Optional[List[Any]] = None,
    sidecar_where_sql: str = "",
    sidecar_params: Optional[List[Any]] = None,
    require_datetime: bool = True,
    row_id_col: str = CHRONOSIFT_ROW_ID_COLUMN,
) -> pd.DataFrame:
    # Join inside DuckDB instead of materialising both datasets into pandas.
    # Projection, filtering, and the join all happen before DataFrame creation,
    # which is a major part of why sidecar mode scales on large corpora.
    base_schema = _duckdb_dataset_columns(base_path)
    sidecar_schema = _duckdb_dataset_columns(sidecar_path)
    base_available = set(base_schema)
    sidecar_available = set(sidecar_schema)

    if row_id_col not in base_available:
        raise ValueError(f"Base dataset {base_path!r} missing join key {row_id_col!r}")
    if row_id_col not in sidecar_available:
        raise ValueError(f"Sidecar dataset {sidecar_path!r} missing join key {row_id_col!r}")

    if base_columns is None:
        base_result_cols = list(base_schema)
    else:
        base_result_cols = [str(c) for c in base_columns if str(c) in base_available]

    if require_datetime:
        dt_col = _dataset_datetime_column(base_path)
        if dt_col and dt_col not in base_result_cols:
            base_result_cols.insert(0, dt_col)

    if sidecar_columns is None:
        sidecar_result_cols = [
            str(c)
            for c in sidecar_schema
            if str(c) not in {row_id_col, "year", "month"}
        ]
    else:
        sidecar_result_cols = [
            str(c)
            for c in sidecar_columns
            if str(c) in sidecar_available and str(c) not in {row_id_col, "year", "month"}
        ]

    base_result_cols = _unique_preserve_order(base_result_cols)
    sidecar_result_cols = _unique_preserve_order(sidecar_result_cols)

    if not sidecar_result_cols:
        return _duckdb_read_parquet_df(
            base_path,
            columns=base_result_cols,
            where_sql=base_where_sql,
            params=base_params,
            require_datetime=require_datetime,
        )

    base_source_cols = _unique_preserve_order(base_result_cols + [row_id_col])
    sidecar_source_cols = _unique_preserve_order(sidecar_result_cols + [row_id_col])

    # Sidecar values override same-named columns from the base dataset. This
    # allows a sidecar rerun to replace derived fields without mutating the base
    # parquet or forcing readers to resolve conflicts themselves.
    base_result_cols = [c for c in base_result_cols if c not in sidecar_result_cols]

    select_parts = [f'b.{_duckdb_quote_ident(c)} AS {_duckdb_quote_ident(c)}' for c in base_result_cols]
    select_parts.extend(
        f's.{_duckdb_quote_ident(c)} AS {_duckdb_quote_ident(c)}' for c in sidecar_result_cols
    )
    if not select_parts:
        return _empty_projected_frame(require_datetime=require_datetime)

    base_sql = (
        f"SELECT {', '.join(_duckdb_quote_ident(c) for c in base_source_cols)} "
        f"FROM read_parquet(?, hive_partitioning=1, union_by_name=1)"
    )
    if base_where_sql:
        base_sql += f" WHERE {base_where_sql}"

    sidecar_sql = (
        f"SELECT {', '.join(_duckdb_quote_ident(c) for c in sidecar_source_cols)} "
        f"FROM read_parquet(?, hive_partitioning=1, union_by_name=1)"
    )
    if sidecar_where_sql:
        sidecar_sql += f" WHERE {sidecar_where_sql}"

    # Use a CTE so the sidecar parquet is scanned only once — both
    # the duplicate-key guard and the LEFT JOIN read from the same CTE.
    rid_q = _duckdb_quote_ident(row_id_col)
    sidecar_glob = _parquet_dataset_glob(sidecar_path)
    sidecar_params_list = sidecar_params or []

    con = _get_duckdb_connection()

    # Lightweight duplicate probe: GROUP BY + HAVING + LIMIT 1 — stops at the
    # first duplicate without counting all of them.
    dup_probe_sql = (
        f"SELECT {rid_q} FROM ({sidecar_sql}) "
        f"GROUP BY {rid_q} HAVING COUNT(*) > 1 LIMIT 1"
    )
    dup_row = con.execute(dup_probe_sql, [sidecar_glob] + sidecar_params_list).fetchone()
    if dup_row is not None:
        raise ValueError(
            f"Sidecar join key {row_id_col!r} must be unique per row "
            f"(duplicate value {dup_row[0]!r} found in DuckDB path)"
        )

    sql = (
        f"WITH _sc AS ({sidecar_sql}) "
        f"SELECT {', '.join(select_parts)} "
        f"FROM ({base_sql}) AS b "
        f"LEFT JOIN _sc AS s "
        f"ON b.{rid_q} = s.{rid_q}"
    )
    # Parameter order must match SQL ?-placeholder order: the CTE (_sc) is
    # the sidecar and appears first, then the base subquery appears second.
    params = [sidecar_glob] + sidecar_params_list + [_parquet_dataset_glob(base_path)] + (base_params or [])
    df = _restore_stable_nested_payloads(con.execute(sql, params).fetch_df())

    if require_datetime:
        return _restore_datetime_index(df)
    return df


def _duckdb_dataset_columns(path: str) -> List[str]:
    cache_key = _dataset_columns_cache_key(path)
    cached = ChronoSiftEngine._dataset_columns_cache.get(cache_key)
    if cached is not None:
        return cached

    dataset_glob = _parquet_dataset_glob(path)
    con = _get_duckdb_connection()
    rows = con.execute(
        "DESCRIBE SELECT * FROM read_parquet(?, hive_partitioning=1, union_by_name=1)",
        [dataset_glob],
    ).fetchall()

    cols = [str(r[0]) for r in rows]
    _invalidate_dataset_columns_cache(path)
    ChronoSiftEngine._dataset_columns_cache[cache_key] = cols
    return cols



def _load_reduced_parquet_dataset(
    path: str,
    desired_columns: List[str],
    require_datetime: bool = True,
) -> pd.DataFrame:
    """Load only a reduced subset of columns while preserving a DatetimeIndex."""
    desired = [str(c) for c in desired_columns if str(c).strip()]

    available = set(_duckdb_dataset_columns(path))
    cols: List[str] = [c for c in desired if c in available]
    if require_datetime:
        dt_col = _dataset_datetime_column(path)
        if dt_col and dt_col not in cols:
            cols.insert(0, dt_col)
    return _duckdb_read_parquet_df(
        path,
        columns=cols,
        require_datetime=require_datetime,
    )



def load_plaso_parquet_dataset(path: str, columns: Optional[List[str]] = None) -> pd.DataFrame:
    """
    Load a partitioned Plaso-derived Parquet dataset.

    The parquet dataset is assumed to have already been normalised before write:
      - timezone-aware datetime index
      - invalid timestamps removed
      - chronological sort applied
      - Hive-style year/month partitioning on disk
    """
    return _duckdb_read_parquet_df(path, columns=columns)



def _empty_hour_of_week_manifest(alpha: float, quiet_quantile: float) -> Dict[str, Any]:
    return {
        "profile": {},
        "quiet_hours": [],
        "alpha": alpha,
        "quiet_quantile": quiet_quantile,
        "selection_mode": "empty",
        "used_filtered_subset": False,
        "source_event_count": 0,
        "selected_event_count": 0,
        "selection_filters": [],
    }


def _hour_of_week_manifest_from_counts(
    counts: pd.Series,
    alpha: float,
    quiet_quantile: float,
    selection_mode: str = "filtered",
    used_filtered_subset: bool = True,
    source_event_count: int = 0,
    selected_event_count: int = 0,
    selection_filters: Optional[List[str]] = None,
) -> Dict[str, Any]:
    total = float(counts.sum())
    if total <= 0.0:
        return _empty_hour_of_week_manifest(alpha=alpha, quiet_quantile=quiet_quantile)

    alpha = max(float(alpha), 1e-12)
    denom = total + 168.0 * alpha
    p = (counts + alpha) / denom
    surprisal = pd.Series(-np.log(p.to_numpy()), index=p.index)
    s_min = float(surprisal.min())
    s_max = float(surprisal.max())
    if s_max > s_min:
        s_norm = (surprisal - s_min) / (s_max - s_min)
    else:
        s_norm = surprisal * 0.0

    threshold = float(p.quantile(float(quiet_quantile)))
    quiet_hours = set(int(i) for i, pv in p.items() if float(pv) <= threshold)
    profile = {int(i): float(v) for i, v in s_norm.items()}
    return {
        "profile": profile,
        "quiet_hours": sorted(int(x) for x in quiet_hours),
        "alpha": alpha,
        "quiet_quantile": quiet_quantile,
        "selection_mode": selection_mode,
        "used_filtered_subset": bool(used_filtered_subset),
        "source_event_count": int(source_event_count),
        "selected_event_count": int(selected_event_count or total),
        "selection_filters": list(selection_filters or []),
    }


def build_global_hour_of_week_manifest(
    dataset_root: str,
    profiling_cfg: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a dataset-wide hour-of-week profiling manifest using reduced columns."""
    cfg = profiling_cfg or {}
    alpha = float(cfg.get("smoothing_alpha", 1.0))
    quiet_quantile = float(cfg.get("quiet_quantile", 0.10))
    min_profile_events = int(cfg.get("min_profile_events", 100))
    selection_filters: List[str] = []
    exclude_parser_contains = [str(x).strip() for x in (cfg.get("exclude_parser_contains") or []) if str(x).strip()]
    exclude_filename_contains = [str(x).strip() for x in (cfg.get("exclude_filename_contains") or []) if str(x).strip()]
    exclude_nsrl_app_contains = [str(x).strip() for x in (cfg.get("exclude_nsrl_application_type_contains") or []) if str(x).strip()]

    available = set(_duckdb_dataset_columns(dataset_root))
    dt_col = _dataset_datetime_column(dataset_root)

    if not dt_col:
        return _empty_hour_of_week_manifest(alpha=alpha, quiet_quantile=quiet_quantile)

    dataset_glob = _parquet_dataset_glob(dataset_root)
    con = _get_duckdb_connection()

    def _fetch_counts(where_parts: Optional[List[str]]) -> Tuple[pd.Series, int]:
        where_sql = ""
        if where_parts:
            where_sql = " WHERE " + " AND ".join(where_parts)
        sql = (
            f'SELECT '
            f'CAST((((EXTRACT(dow FROM "{dt_col}") + 6) % 7) * 24) + EXTRACT(hour FROM "{dt_col}") AS INTEGER) AS how, '
            f'COUNT(*) AS n '
            f'FROM read_parquet(?, hive_partitioning=1, union_by_name=1)'
            f'{where_sql} '
            f'GROUP BY 1 ORDER BY 1'
        )
        rows = con.execute(sql, [dataset_glob]).fetchall()
        counts = pd.Series(0.0, index=range(168), dtype="float64")
        total_rows = 0
        for how, n in rows:
            if how is None:
                continue
            hi = int(how)
            if 0 <= hi < 168:
                counts.iat[hi] = float(n)
                total_rows += int(n)
        return counts, total_rows

    filtered_where_parts: List[str] = []
    if "parser" in available:
        filtered_where_parts.append("regexp_matches(coalesce(\"parser\", ''), '(?:mft|usnjrnl|filestat)', 'i')")
        selection_filters.append("parser:mft|usnjrnl|filestat")
        for token in exclude_parser_contains:
            filtered_where_parts.append(f"position({_duckdb_sql_string(token.lower())} in coalesce(lower(\"parser\"), '')) = 0")
            selection_filters.append(f"exclude:parser contains {token}")

    if "nsrl_is_os_component" in available:
        filtered_where_parts.append("NOT coalesce(try_cast(\"nsrl_is_os_component\" AS BOOLEAN), FALSE)")
        selection_filters.append("exclude:nsrl_is_os_component")
    elif "nsrl_application_type" in available:
        for token in (exclude_nsrl_app_contains or ["Operating System"]):
            filtered_where_parts.append(f"position({_duckdb_sql_string(token.lower())} in coalesce(lower(\"nsrl_application_type\"), '')) = 0")
            selection_filters.append(f"exclude:nsrl_application_type contains {token}")
    if "filename" in available:
        for token in exclude_filename_contains:
            filtered_where_parts.append(f"position({_duckdb_sql_string(token.lower())} in coalesce(lower(\"filename\"), '')) = 0")
            selection_filters.append(f"exclude:filename contains {token}")

    total_counts, total_rows = _fetch_counts([])
    source_event_count = int(total_counts.sum())

    counts, total_rows = _fetch_counts(filtered_where_parts)
    filters_were_requested = bool(filtered_where_parts)
    used_filtered_subset = bool(filters_were_requested and total_rows >= min_profile_events)
    if total_rows < min_profile_events and filters_were_requested:
        counts, total_rows = _fetch_counts([])
        used_filtered_subset = False
        selection_filters = ["fallback:filters_not_applied"]

    if total_rows >= min_profile_events:
        if used_filtered_subset:
            _sel_mode = "filtered"
        elif filters_were_requested:
            _sel_mode = "fallback_full_dataset"
        else:
            _sel_mode = "unfiltered"
        return _hour_of_week_manifest_from_counts(
            counts,
            alpha=alpha,
            quiet_quantile=quiet_quantile,
            selection_mode=_sel_mode,
            used_filtered_subset=used_filtered_subset,
            source_event_count=source_event_count,
            selected_event_count=total_rows,
            selection_filters=selection_filters,
        )

    return _empty_hour_of_week_manifest(alpha=alpha, quiet_quantile=quiet_quantile)



def _web_relevant_yara_rule_names(
    value: Any,
    yara_metadata_index: Optional[Dict[str, YaraRuleMeta]],
    referenced_file_cfg: Optional[Dict[str, Any]],
) -> bool:
    """Return whether any named YARA hit meets the configured web threshold."""
    return bool(_web_relevant_yara_rule_evidence(value, yara_metadata_index, referenced_file_cfg))


def _web_relevant_yara_rule_evidence(
    value: Any,
    yara_metadata_index: Optional[Dict[str, YaraRuleMeta]],
    referenced_file_cfg: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Return category and quality metadata for web-relevant YARA hits."""
    cfg = referenced_file_cfg or {}
    minimum_score = int(cfg.get("web_yara_min_score", 75))
    minimum_quality = int(cfg.get("web_yara_min_quality", 70))
    allowed_categories = {
        _safe_str(category).strip().lower()
        for category in cfg.get(
            "web_yara_categories",
            (
                YARA_CAT_OFFENSIVE_TOOL,
                YARA_CAT_RANSOMWARE,
                YARA_CAT_WEBSHELL,
                YARA_CAT_APT,
                YARA_CAT_EXPLOIT,
                YARA_CAT_MALWARE,
            ),
        )
        if _safe_str(category).strip()
    }
    names = extract_yara_rule_names(value)
    if not names:
        return []
    metadata_index = yara_metadata_index or {}
    evidence: List[Dict[str, Any]] = []
    for rule_name in names:
        meta = metadata_index.get(rule_name)
        if meta is None:
            meta = YaraRuleMeta(category=_classify_yara_rule(rule_name))
        if (
            meta.score >= minimum_score
            and meta.quality >= minimum_quality
            and meta.category in allowed_categories
        ):
            evidence.append({
                "rule": rule_name,
                "category": meta.category,
                "score": int(meta.score),
                "quality": int(meta.quality),
            })
    return evidence


def _empty_file_identity() -> Dict[str, Any]:
    return {
        "hit_types": set(),
        "av_signatures": set(),
        "av_categories": set(),
        "av_families": set(),
        "yara_rules": set(),
        "yara_categories": set(),
        "yara_rule_metadata": {},
    }


def _normalise_file_identity(value: Any) -> Dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    out = _empty_file_identity()
    for key in (
        "hit_types", "av_signatures", "av_categories", "av_families",
        "yara_rules", "yara_categories",
    ):
        raw = source.get(key, ()) or ()
        if isinstance(raw, str):
            raw = [raw]
        out[key].update(_safe_str(item).strip() for item in raw if _safe_str(item).strip())
    metadata = source.get("yara_rule_metadata", {}) or {}
    if isinstance(metadata, list):
        metadata = {
            _safe_str(item.get("rule")).strip(): item
            for item in metadata
            if isinstance(item, dict) and _safe_str(item.get("rule")).strip()
        }
    for rule_name, raw_meta in metadata.items():
        rule = _safe_str(rule_name).strip()
        if not rule:
            continue
        meta = raw_meta if isinstance(raw_meta, dict) else {}
        out["yara_rule_metadata"][rule] = {
            "category": _safe_str(meta.get("category")).strip() or YARA_CAT_MALWARE,
            "score": int(meta.get("score", 75) or 75),
            "quality": int(meta.get("quality", 70) or 70),
        }
    return out


def _merge_file_identity(target: Dict[str, Any], source: Any) -> Dict[str, Any]:
    normalised = _normalise_file_identity(source)
    for key in (
        "hit_types", "av_signatures", "av_categories", "av_families",
        "yara_rules", "yara_categories",
    ):
        target.setdefault(key, set()).update(normalised[key])
    target.setdefault("yara_rule_metadata", {}).update(normalised["yara_rule_metadata"])
    return target


def _serialise_file_identity(value: Any) -> Dict[str, Any]:
    normalised = _normalise_file_identity(value)
    return {
        key: sorted(normalised[key])
        for key in (
            "hit_types", "av_signatures", "av_categories", "av_families",
            "yara_rules", "yara_categories",
        )
    } | {
        "yara_rule_metadata": {
            rule: dict(meta)
            for rule, meta in sorted(normalised["yara_rule_metadata"].items())
        }
    }


def _finalise_referenced_file_hit_manifest(
    hit_map: Dict[str, Set[str]],
    basename_map: Dict[str, Set[str]],
    strong_yara_paths: Set[str],
    referenced_file_cfg: Optional[Dict[str, Any]],
    file_identity_map: Optional[Dict[str, Dict[str, Any]]] = None,
    hash_path_map: Optional[Dict[str, Set[str]]] = None,
) -> Dict[str, Any]:
    """Add URL and upload-name aliases to the legacy filesystem hit maps."""
    cfg = referenced_file_cfg or {}
    document_roots = tuple(cfg.get("web_document_roots") or DEFAULT_WEB_DOCUMENT_ROOTS)
    web_path_map: Dict[str, Set[str]] = {}
    web_basename_map: Dict[str, Set[str]] = {}
    web_identity_map: Dict[str, Dict[str, Any]] = {}
    web_basename_identity_map: Dict[str, Dict[str, Any]] = {}
    normalised_file_identity_map = {
        str(path): _normalise_file_identity(identity)
        for path, identity in (file_identity_map or {}).items()
    }
    hash_hit_map: Dict[str, Set[str]] = {}
    hash_identity_map: Dict[str, Dict[str, Any]] = {}
    for file_hash, paths in (hash_path_map or {}).items():
        for path in paths:
            tags = hit_map.get(path, set()) or set()
            if not tags:
                continue
            hash_hit_map.setdefault(file_hash, set()).update(tags)
            _merge_file_identity(
                hash_identity_map.setdefault(file_hash, _empty_file_identity()),
                normalised_file_identity_map.get(path),
            )
            hash_identity_map[file_hash]["hit_types"].update(tags)
    for filesystem_path, original_tags in hit_map.items():
        web_tags = {tag for tag in original_tags if tag in {"av", "luhn"}}
        if "yara" in original_tags and filesystem_path in strong_yara_paths:
            web_tags.add("yara")
        if not web_tags:
            continue
        for alias in _web_path_aliases_for_filesystem_path(filesystem_path, document_roots):
            alias_key = alias.casefold()
            web_path_map.setdefault(alias_key, set()).update(web_tags)
            basename = _basename_from_reference_path(alias).casefold()
            if basename:
                web_basename_map.setdefault(basename, set()).update(web_tags)
            identity = _normalise_file_identity(normalised_file_identity_map.get(filesystem_path))
            identity["hit_types"].update(web_tags)
            _merge_file_identity(web_identity_map.setdefault(alias_key, _empty_file_identity()), identity)
            if basename:
                _merge_file_identity(
                    web_basename_identity_map.setdefault(basename, _empty_file_identity()),
                    identity,
                )
    return {
        "schema_version": 4,
        "hit_map": hit_map,
        "basename_map": basename_map,
        "web_path_map": web_path_map,
        "web_basename_map": web_basename_map,
        "file_identity_map": normalised_file_identity_map,
        "web_identity_map": web_identity_map,
        "web_basename_identity_map": web_basename_identity_map,
        "hash_hit_map": hash_hit_map,
        "hash_identity_map": hash_identity_map,
    }


def build_global_referenced_file_hit_manifest(
    dataset_root: str,
    av_csv_path: Optional[str] = None,
    luhn_csv_path: Optional[str] = None,
    referenced_file_cfg: Optional[Dict[str, Any]] = None,
    yara_metadata_index: Optional[Dict[str, YaraRuleMeta]] = None,
) -> Dict[str, Any]:
    """Build a dataset-wide referenced-file hit manifest using reduced columns."""
    hit_map: Dict[str, Set[str]] = {}
    basename_map: Dict[str, Set[str]] = {}
    strong_yara_paths: Set[str] = set()
    file_identity_map: Dict[str, Dict[str, Any]] = {}
    hash_path_map: Dict[str, Set[str]] = {}
    available = set(_duckdb_dataset_columns(dataset_root))

    if "filename" not in available:
        return _finalise_referenced_file_hit_manifest(
            hit_map, basename_map, strong_yara_paths, referenced_file_cfg
        )

    derive_av = bool(av_csv_path) and "sha256_hash" in available
    derive_luhn = bool(luhn_csv_path) and "sha256_hash" in available
    use_existing_av = "av_hit" in available
    use_existing_luhn = "luhn_hit" in available
    use_existing_yara = "yara_match_count" in available
    derive_yara = (not use_existing_yara) and ("yara_match" in available)

    if not any([use_existing_av, use_existing_luhn, use_existing_yara, derive_av, derive_luhn, derive_yara]):
        return _finalise_referenced_file_hit_manifest(
            hit_map, basename_map, strong_yara_paths, referenced_file_cfg
        )

    def _accumulate_hits(
        filenames: np.ndarray,
        av_vals: np.ndarray,
        luhn_vals: np.ndarray,
        ymc_vals: np.ndarray,
    ) -> None:
        for i in range(len(filenames)):
            fname = filenames[i]
            if not fname:
                continue
            tags: Set[str] = set()
            if _truthy_like(av_vals[i]):
                tags.add("av")
            if _truthy_like(luhn_vals[i]):
                tags.add("luhn")
            try:
                if float(ymc_vals[i]) > 0:
                    tags.add("yara")
            except Exception:
                pass
            if not tags:
                continue
            hit_map.setdefault(fname, set()).update(tags)
            file_identity_map.setdefault(fname, _empty_file_identity())["hit_types"].update(tags)
            base = _basename_from_reference_path(fname)
            if base:
                basename_map.setdefault(base, set()).update(tags)

    # Fast path: the dataset already contains the materialised hit columns used by contextual replay.
    if not (derive_av or derive_luhn or derive_yara):
        hit_predicates: List[str] = []
        if use_existing_av:
            hit_predicates.append("COALESCE(CAST(av_hit AS INTEGER), 0) <> 0")
        if use_existing_luhn:
            hit_predicates.append("COALESCE(CAST(luhn_hit AS INTEGER), 0) <> 0")
        if use_existing_yara:
            hit_predicates.append("COALESCE(CAST(yara_match_count AS DOUBLE), 0) > 0")

        if not hit_predicates:
            return _finalise_referenced_file_hit_manifest(
                hit_map, basename_map, strong_yara_paths, referenced_file_cfg
            )

        dataset_glob = _parquet_dataset_glob(dataset_root)
        con = _get_duckdb_connection()

        hash_select = "UPPER(TRIM(CAST(sha256_hash AS VARCHAR)))" if "sha256_hash" in available else "NULL"
        sql = f"""
            SELECT
                filename,
                {hash_select} AS file_hash,
                MAX(CASE WHEN {"COALESCE(CAST(av_hit AS INTEGER), 0) <> 0" if use_existing_av else "FALSE"} THEN 1 ELSE 0 END) AS has_av,
                MAX(CASE WHEN {"COALESCE(CAST(luhn_hit AS INTEGER), 0) <> 0" if use_existing_luhn else "FALSE"} THEN 1 ELSE 0 END) AS has_luhn,
                MAX(CASE WHEN {"COALESCE(CAST(yara_match_count AS DOUBLE), 0) > 0" if use_existing_yara else "FALSE"} THEN 1 ELSE 0 END) AS has_yara
            FROM read_parquet(?, hive_partitioning=1, union_by_name=1)
            WHERE filename IS NOT NULL
              AND ({' OR '.join(hit_predicates)})
            GROUP BY filename, file_hash
        """

        cur = con.execute(sql, [dataset_glob])
        while True:
            rows = cur.fetchmany(100000)
            if not rows:
                break
            for fname_raw, file_hash, has_av, has_luhn, has_yara in rows:
                fname = _normalise_reference_path(fname_raw)
                if not fname:
                    continue
                tags: Set[str] = set()
                if _truthy_like(has_av):
                    tags.add("av")
                if _truthy_like(has_luhn):
                    tags.add("luhn")
                if _truthy_like(has_yara):
                    tags.add("yara")
                if not tags:
                    continue
                hit_map.setdefault(fname, set()).update(tags)
                if file_hash and re.fullmatch(r"[0-9A-F]{64}", _safe_str(file_hash)):
                    hash_path_map.setdefault(_safe_str(file_hash), set()).add(fname)
                file_identity_map.setdefault(fname, _empty_file_identity())["hit_types"].update(tags)
                base = _basename_from_reference_path(fname)
                if base:
                    basename_map.setdefault(base, set()).update(tags)
        if "av_signature" in available and use_existing_av:
            av_sql = f"""
                SELECT filename, av_signature
                FROM read_parquet(?, hive_partitioning=1, union_by_name=1)
                WHERE filename IS NOT NULL
                  AND COALESCE(CAST(av_hit AS INTEGER), 0) <> 0
                  AND av_signature IS NOT NULL
            """
            av_cur = con.execute(av_sql, [dataset_glob])
            while True:
                rows = av_cur.fetchmany(100000)
                if not rows:
                    break
                for fname_raw, av_signature in rows:
                    fname = _normalise_reference_path(fname_raw)
                    signature = _safe_str(av_signature).strip()
                    if not fname or not signature:
                        continue
                    meta = parse_clamav_signature(signature)
                    identity = file_identity_map.setdefault(fname, _empty_file_identity())
                    identity["av_signatures"].add(signature)
                    identity["av_categories"].add(meta.forensic_category)
                    if meta.family:
                        identity["av_families"].add(meta.family)
        if "yara_match" in available:
            yara_sql = f"""
                SELECT filename, yara_match
                FROM read_parquet(?, hive_partitioning=1, union_by_name=1)
                WHERE filename IS NOT NULL
                  AND COALESCE(CAST(yara_match_count AS DOUBLE), 0) > 0
            """
            yara_cur = con.execute(yara_sql, [dataset_glob])
            while True:
                rows = yara_cur.fetchmany(100000)
                if not rows:
                    break
                for fname_raw, yara_match in rows:
                    fname = _normalise_reference_path(fname_raw)
                    yara_evidence = _web_relevant_yara_rule_evidence(
                        yara_match, yara_metadata_index, referenced_file_cfg
                    )
                    if fname and yara_evidence:
                        strong_yara_paths.add(fname)
                        identity = file_identity_map.setdefault(fname, _empty_file_identity())
                        for rule_meta in yara_evidence:
                            rule = _safe_str(rule_meta.get("rule")).strip()
                            category = _safe_str(rule_meta.get("category")).strip()
                            if rule:
                                identity["yara_rules"].add(rule)
                                identity["yara_rule_metadata"][rule] = {
                                    "category": category or YARA_CAT_MALWARE,
                                    "score": int(rule_meta.get("score", 75) or 75),
                                    "quality": int(rule_meta.get("quality", 70) or 70),
                                }
                            if category:
                                identity["yara_categories"].add(category)
        elif bool((referenced_file_cfg or {}).get("web_yara_allow_unnamed", False)):
            strong_yara_paths.update(path for path, tags in hit_map.items() if "yara" in tags)
        return _finalise_referenced_file_hit_manifest(
            hit_map, basename_map, strong_yara_paths, referenced_file_cfg, file_identity_map, hash_path_map
        )

    av_hash_hits = _load_hash_hit_set_from_csv(av_csv_path, "av_hit") if derive_av else set()
    luhn_hash_hits = _load_hash_hit_set_from_csv(luhn_csv_path, "luhn_hit") if derive_luhn else set()

    desired_columns: List[str] = ["filename"]
    if use_existing_av and "av_hit" not in desired_columns:
        desired_columns.append("av_hit")
    if use_existing_luhn and "luhn_hit" not in desired_columns:
        desired_columns.append("luhn_hit")
    if use_existing_yara and "yara_match_count" not in desired_columns:
        desired_columns.append("yara_match_count")
    if derive_yara and "yara_match" not in desired_columns:
        desired_columns.append("yara_match")
    if use_existing_yara and "yara_match" in available and "yara_match" not in desired_columns:
        desired_columns.append("yara_match")
    if use_existing_av and "av_signature" in available and "av_signature" not in desired_columns:
        desired_columns.append("av_signature")
    if "sha256_hash" in available and "sha256_hash" not in desired_columns:
        desired_columns.append("sha256_hash")

    for year, month, _part_path in iter_hive_year_month_partitions(dataset_root):
        chunk = load_plaso_parquet_partitions(
            dataset_root,
            [(year, month)],
            columns=desired_columns,
            require_datetime=False,
        )
        if len(chunk) == 0 or "filename" not in chunk.columns:
            continue
        norm_filenames = _normalise_reference_path_series(chunk["filename"]).to_numpy(dtype=object, copy=False)

        if "sha256_hash" in chunk.columns:
            norm_hash = _normalise_hash_series(chunk["sha256_hash"]) if "sha256_hash" in chunk.columns else pd.Series(pd.NA, index=chunk.index, dtype="string")
        else:
            norm_hash = None

        av_existing = None
        if use_existing_av and "av_hit" in chunk.columns:
            av_existing = chunk["av_hit"].map(_truthy_like).to_numpy(dtype=bool, copy=False)
        av_derived = None
        if derive_av and norm_hash is not None:
            av_derived = norm_hash.isin(av_hash_hits).to_numpy(dtype=bool, copy=False)
        if av_existing is not None and av_derived is not None:
            av_vals = av_existing | av_derived
        elif av_existing is not None:
            av_vals = av_existing
        elif av_derived is not None:
            av_vals = av_derived
        else:
            av_vals = np.zeros(len(chunk), dtype=bool)

        luhn_existing = None
        if use_existing_luhn and "luhn_hit" in chunk.columns:
            luhn_existing = chunk["luhn_hit"].map(_truthy_like).to_numpy(dtype=bool, copy=False)
        luhn_derived = None
        if derive_luhn and norm_hash is not None:
            luhn_derived = norm_hash.isin(luhn_hash_hits).to_numpy(dtype=bool, copy=False)
        if luhn_existing is not None and luhn_derived is not None:
            luhn_vals = luhn_existing | luhn_derived
        elif luhn_existing is not None:
            luhn_vals = luhn_existing
        elif luhn_derived is not None:
            luhn_vals = luhn_derived
        else:
            luhn_vals = np.zeros(len(chunk), dtype=bool)

        if use_existing_yara and "yara_match_count" in chunk.columns:
            ymc_vals = chunk["yara_match_count"].to_numpy(copy=False)
        elif derive_yara and "yara_match" in chunk.columns:
            ymc_vals = normalise_yara_match_count_series(chunk["yara_match"]).to_numpy(copy=False)
        else:
            ymc_vals = np.zeros(len(chunk), dtype=np.int64)

        _accumulate_hits(
            norm_filenames,
            av_vals,
            luhn_vals,
            ymc_vals,
        )

        # Index hashes for hit-carrying rows only.  Accumulating every hashed
        # row built a dataset-wide sha256 -> filenames dict that was retained
        # across all partitions, while `_finalise_referenced_file_hit_manifest`
        # discards everything without a hit anyway.  The DuckDB fast path above
        # applies the same restriction through its WHERE clause.
        if norm_hash is not None:
            hash_rows = (
                np.asarray(av_vals, dtype=bool)
                | np.asarray(luhn_vals, dtype=bool)
                | (pd.to_numeric(pd.Series(ymc_vals), errors="coerce").fillna(0).to_numpy() > 0)
            )
            hash_values = norm_hash.to_numpy(dtype=object, copy=False)
            for i in np.flatnonzero(hash_rows):
                fname = norm_filenames[i]
                file_hash_text = _safe_str(hash_values[i]).strip().upper()
                if fname and re.fullmatch(r"[0-9A-F]{64}", file_hash_text):
                    hash_path_map.setdefault(file_hash_text, set()).add(fname)

        if "av_signature" in chunk.columns:
            av_signatures = chunk["av_signature"].to_numpy(copy=False)
            for i in np.flatnonzero(np.asarray(av_vals, dtype=bool)):
                fname = norm_filenames[i]
                signature = _safe_str(av_signatures[i]).strip()
                if not fname or not signature:
                    continue
                meta = parse_clamav_signature(signature)
                identity = file_identity_map.setdefault(fname, _empty_file_identity())
                identity["av_signatures"].add(signature)
                identity["av_categories"].add(meta.forensic_category)
                if meta.family:
                    identity["av_families"].add(meta.family)

        if "yara_match" in chunk.columns:
            yara_values = chunk["yara_match"].to_numpy(copy=False)
            for i in np.flatnonzero(np.asarray(ymc_vals, dtype=float) > 0):
                fname = norm_filenames[i]
                yara_evidence = _web_relevant_yara_rule_evidence(
                    yara_values[i], yara_metadata_index, referenced_file_cfg
                )
                if fname and yara_evidence:
                    strong_yara_paths.add(fname)
                    identity = file_identity_map.setdefault(fname, _empty_file_identity())
                    for rule_meta in yara_evidence:
                        rule = _safe_str(rule_meta.get("rule")).strip()
                        category = _safe_str(rule_meta.get("category")).strip()
                        if rule:
                            identity["yara_rules"].add(rule)
                            identity["yara_rule_metadata"][rule] = {
                                "category": category or YARA_CAT_MALWARE,
                                "score": int(rule_meta.get("score", 75) or 75),
                                "quality": int(rule_meta.get("quality", 70) or 70),
                            }
                        if category:
                            identity["yara_categories"].add(category)

    return _finalise_referenced_file_hit_manifest(
        hit_map, basename_map, strong_yara_paths, referenced_file_cfg, file_identity_map, hash_path_map
    )


def _serialise_profile_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(manifest or {})
    if "profile" in out and isinstance(out["profile"], dict):
        out["profile"] = {str(k): float(v) for k, v in out["profile"].items()}
    if "quiet_hours" in out:
        out["quiet_hours"] = [int(x) for x in (out.get("quiet_hours") or [])]
    return out


def _deserialise_profile_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(manifest or {})
    if "profile" in out and isinstance(out["profile"], dict):
        out["profile"] = {int(k): float(v) for k, v in out["profile"].items()}
    if "quiet_hours" in out:
        out["quiet_hours"] = [int(x) for x in (out.get("quiet_hours") or [])]
    return out


def save_profile_manifest(manifest: Dict[str, Any], path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(_serialise_profile_manifest(manifest), indent=2, sort_keys=True), encoding="utf-8")


def load_profile_manifest(path: str) -> Dict[str, Any]:
    return _deserialise_profile_manifest(json.loads(Path(path).read_text(encoding="utf-8")))


def _serialise_file_hit_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    hit_map = {str(k): sorted(str(x) for x in v) for k, v in (manifest or {}).get("hit_map", {}).items()}
    basename_map = {str(k): sorted(str(x) for x in v) for k, v in (manifest or {}).get("basename_map", {}).items()}
    web_path_map = {str(k): sorted(str(x) for x in v) for k, v in (manifest or {}).get("web_path_map", {}).items()}
    web_basename_map = {str(k): sorted(str(x) for x in v) for k, v in (manifest or {}).get("web_basename_map", {}).items()}
    file_identity_map = {
        str(k): _serialise_file_identity(v)
        for k, v in (manifest or {}).get("file_identity_map", {}).items()
    }
    web_identity_map = {
        str(k): _serialise_file_identity(v)
        for k, v in (manifest or {}).get("web_identity_map", {}).items()
    }
    web_basename_identity_map = {
        str(k): _serialise_file_identity(v)
        for k, v in (manifest or {}).get("web_basename_identity_map", {}).items()
    }
    hash_hit_map = {str(k): sorted(str(x) for x in v) for k, v in (manifest or {}).get("hash_hit_map", {}).items()}
    hash_identity_map = {
        str(k): _serialise_file_identity(v)
        for k, v in (manifest or {}).get("hash_identity_map", {}).items()
    }
    return {
        "schema_version": int((manifest or {}).get("schema_version", 1) or 1),
        "hit_map": hit_map,
        "basename_map": basename_map,
        "web_path_map": web_path_map,
        "web_basename_map": web_basename_map,
        "file_identity_map": file_identity_map,
        "web_identity_map": web_identity_map,
        "web_basename_identity_map": web_basename_identity_map,
        "hash_hit_map": hash_hit_map,
        "hash_identity_map": hash_identity_map,
    }


def _deserialise_file_hit_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    hit_map = {str(k): set(v or []) for k, v in (manifest or {}).get("hit_map", {}).items()}
    basename_map = {str(k): set(v or []) for k, v in (manifest or {}).get("basename_map", {}).items()}
    web_path_map = {str(k): set(v or []) for k, v in (manifest or {}).get("web_path_map", {}).items()}
    web_basename_map = {str(k): set(v or []) for k, v in (manifest or {}).get("web_basename_map", {}).items()}
    file_identity_map = {
        str(k): _normalise_file_identity(v)
        for k, v in (manifest or {}).get("file_identity_map", {}).items()
    }
    web_identity_map = {
        str(k): _normalise_file_identity(v)
        for k, v in (manifest or {}).get("web_identity_map", {}).items()
    }
    web_basename_identity_map = {
        str(k): _normalise_file_identity(v)
        for k, v in (manifest or {}).get("web_basename_identity_map", {}).items()
    }
    hash_hit_map = {str(k): set(v or []) for k, v in (manifest or {}).get("hash_hit_map", {}).items()}
    hash_identity_map = {
        str(k): _normalise_file_identity(v)
        for k, v in (manifest or {}).get("hash_identity_map", {}).items()
    }
    return {
        "schema_version": int((manifest or {}).get("schema_version", 1) or 1),
        "hit_map": hit_map,
        "basename_map": basename_map,
        "web_path_map": web_path_map,
        "web_basename_map": web_basename_map,
        "file_identity_map": file_identity_map,
        "web_identity_map": web_identity_map,
        "web_basename_identity_map": web_basename_identity_map,
        "hash_hit_map": hash_hit_map,
        "hash_identity_map": hash_identity_map,
    }


def save_file_hit_manifest(manifest: Dict[str, Any], path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(_serialise_file_hit_manifest(manifest), indent=2, sort_keys=True), encoding="utf-8")


def load_file_hit_manifest(path: str) -> Dict[str, Any]:
    return _deserialise_file_hit_manifest(json.loads(Path(path).read_text(encoding="utf-8")))

def _ensure_nsrl_cache(
    nsrl_parquet_path: Optional[str] = None,
) -> Optional[pd.DataFrame]:
    """
    Load NSRL enrichment from parquet when supplied.

    Returns a lightweight descriptor so runtime lookups can be resolved through a
    reusable DuckDB relation without materialising the full cache into pandas.
    NSRL requires a pre-converted parquet file since v2.31.
    """
    if nsrl_parquet_path:
        return _make_nsrl_cache_descriptor(nsrl_parquet_path)
    return None

def iter_hive_year_month_partitions(dataset_root: str) -> List[Tuple[int, int, str]]:
    """Return discovered Hive-style year/month partition directories."""
    root = Path(dataset_root)
    out: List[Tuple[int, int, str]] = []

    for year_dir in root.glob("year=*"):
        try:
            year = int(year_dir.name.split("=", 1)[1])
        except Exception:
            continue

        for month_dir in year_dir.glob("month=*"):
            try:
                month = int(month_dir.name.split("=", 1)[1])
            except Exception:
                continue
            out.append((year, month, str(month_dir)))

    out.sort(key=lambda x: (x[0], x[1]))
    return out

def load_plaso_parquet_partitions(
    path: str,
    year_month: List[Tuple[int, int]],
    columns: Optional[List[str]] = None,
    require_datetime: bool = True,
) -> pd.DataFrame:
    """Load only selected year/month partitions from a Hive-partitioned parquet dataset."""
    if not year_month:
        return _duckdb_read_parquet_df(path, columns=columns, require_datetime=require_datetime)

    cols = list(columns) if columns is not None else None
    if require_datetime and cols is not None:
        dt_col = _dataset_datetime_column(path)
        if dt_col and dt_col not in cols:
            cols.insert(0, dt_col)

    clauses: List[str] = []
    params: List[Any] = []
    for year, month in year_month:
        clauses.append("(year = ? AND month = ?)")
        params.extend([int(year), int(month)])

    where_sql = " OR ".join(clauses)
    return _duckdb_read_parquet_df(
        path,
        columns=cols,
        where_sql=where_sql,
        params=params,
        require_datetime=require_datetime,
    )



def load_plaso_parquet_timerange(
    path: str,
    start: Optional[pd.Timestamp] = None,
    end: Optional[pd.Timestamp] = None,
    overlap: str = "0h",
    columns: Optional[List[str]] = None,
) -> pd.DataFrame:
    """Load only the partitions covering a time range, with optional overlap for temporal/context rules."""
    if start is None and end is None:
        return load_plaso_parquet_dataset(path, columns=columns)

    td = parse_lookback(overlap)

    if start is not None:
        start = pd.Timestamp(start)
        start = start.tz_localize("UTC") if start.tzinfo is None else start.tz_convert("UTC")
        start = start - td
    if end is not None:
        end = pd.Timestamp(end)
        end = end.tz_localize("UTC") if end.tzinfo is None else end.tz_convert("UTC")
        end = end + td

    if start is None:
        start = end
    if end is None:
        end = start

    months: List[Tuple[int, int]] = []
    cur = pd.Timestamp(year=start.year, month=start.month, day=1, tz="UTC")
    stop = pd.Timestamp(year=end.year, month=end.month, day=1, tz="UTC")
    while cur <= stop:
        months.append((int(cur.year), int(cur.month)))
        if cur.month == 12:
            cur = pd.Timestamp(year=cur.year + 1, month=1, day=1, tz="UTC")
        else:
            cur = pd.Timestamp(year=cur.year, month=cur.month + 1, day=1, tz="UTC")

    cols = list(columns) if columns is not None else None
    dt_col = _dataset_datetime_column(path)

    if cols is not None and dt_col and dt_col not in cols:
        cols.insert(0, dt_col)

    clauses: List[str] = []
    params: List[Any] = []
    for year, month in months:
        clauses.append("(year = ? AND month = ?)")
        params.extend([int(year), int(month)])

    where_parts: List[str] = []
    if clauses:
        where_parts.append("(" + " OR ".join(clauses) + ")")
    if dt_col and start is not None:
        where_parts.append(f'"{dt_col}" >= ?')
        params.append(start.to_pydatetime())
    if dt_col and end is not None:
        where_parts.append(f'"{dt_col}" <= ?')
        params.append(end.to_pydatetime())

    return _duckdb_read_parquet_df(
        path,
        columns=cols,
        where_sql=" AND ".join(where_parts),
        params=params,
        require_datetime=True,
    )


def _joined_base_columns(
    columns: Optional[List[str]],
    row_id_col: str,
) -> Tuple[Optional[List[str]], bool]:
    if columns is None:
        return None, False
    joined = list(columns)
    added_row_id = row_id_col not in joined
    if added_row_id:
        joined.append(row_id_col)
    return joined, added_row_id


def _joined_sidecar_columns(
    sidecar_columns: Optional[List[str]],
    row_id_col: str,
) -> Optional[List[str]]:
    if sidecar_columns is None:
        return None
    cols = list(sidecar_columns)
    if row_id_col not in cols:
        cols.insert(0, row_id_col)
    return cols


def load_plaso_parquet_dataset_with_sidecar(
    base_path: str,
    sidecar_path: str,
    columns: Optional[List[str]] = None,
    sidecar_columns: Optional[List[str]] = None,
    row_id_col: str = CHRONOSIFT_ROW_ID_COLUMN,
) -> pd.DataFrame:
    base_columns, drop_row_id = _joined_base_columns(columns, row_id_col=row_id_col)
    merged = _duckdb_read_joined_parquet_df(
        base_path,
        sidecar_path,
        base_columns=base_columns,
        sidecar_columns=_joined_sidecar_columns(sidecar_columns, row_id_col=row_id_col),
        require_datetime=True,
        row_id_col=row_id_col,
    )
    if drop_row_id:
        _delete_columns_inplace(merged, [row_id_col])
    return merged


def load_plaso_parquet_partitions_with_sidecar(
    base_path: str,
    sidecar_path: str,
    year_month: List[Tuple[int, int]],
    columns: Optional[List[str]] = None,
    sidecar_columns: Optional[List[str]] = None,
    row_id_col: str = CHRONOSIFT_ROW_ID_COLUMN,
) -> pd.DataFrame:
    base_columns, drop_row_id = _joined_base_columns(columns, row_id_col=row_id_col)
    if not year_month:
        return load_plaso_parquet_dataset_with_sidecar(
            base_path,
            sidecar_path,
            columns=columns,
            sidecar_columns=sidecar_columns,
            row_id_col=row_id_col,
        )

    clauses: List[str] = []
    params: List[Any] = []
    for year, month in year_month:
        clauses.append("(year = ? AND month = ?)")
        params.extend([int(year), int(month)])

    where_sql = " OR ".join(clauses)
    merged = _duckdb_read_joined_parquet_df(
        base_path,
        sidecar_path,
        base_columns=base_columns,
        sidecar_columns=_joined_sidecar_columns(sidecar_columns, row_id_col=row_id_col),
        base_where_sql=where_sql,
        base_params=params,
        sidecar_where_sql=where_sql,
        sidecar_params=params,
        require_datetime=True,
        row_id_col=row_id_col,
    )
    if drop_row_id:
        _delete_columns_inplace(merged, [row_id_col])
    return merged


def load_plaso_parquet_timerange_with_sidecar(
    base_path: str,
    sidecar_path: str,
    start: Optional[pd.Timestamp] = None,
    end: Optional[pd.Timestamp] = None,
    overlap: str = "0h",
    columns: Optional[List[str]] = None,
    sidecar_columns: Optional[List[str]] = None,
    row_id_col: str = CHRONOSIFT_ROW_ID_COLUMN,
) -> pd.DataFrame:
    base_columns, drop_row_id = _joined_base_columns(columns, row_id_col=row_id_col)
    if start is None and end is None:
        return load_plaso_parquet_dataset_with_sidecar(
            base_path,
            sidecar_path,
            columns=columns,
            sidecar_columns=sidecar_columns,
            row_id_col=row_id_col,
        )

    td = parse_lookback(overlap)

    if start is not None:
        start = pd.Timestamp(start)
        start = start.tz_localize("UTC") if start.tzinfo is None else start.tz_convert("UTC")
        start = start - td
    if end is not None:
        end = pd.Timestamp(end)
        end = end.tz_localize("UTC") if end.tzinfo is None else end.tz_convert("UTC")
        end = end + td

    if start is None:
        start = end
    if end is None:
        end = start

    months: List[Tuple[int, int]] = []
    cur = pd.Timestamp(year=start.year, month=start.month, day=1, tz="UTC")
    stop = pd.Timestamp(year=end.year, month=end.month, day=1, tz="UTC")
    while cur <= stop:
        months.append((int(cur.year), int(cur.month)))
        if cur.month == 12:
            cur = pd.Timestamp(year=cur.year + 1, month=1, day=1, tz="UTC")
        else:
            cur = pd.Timestamp(year=cur.year, month=cur.month + 1, day=1, tz="UTC")

    def _build_where_sql(path: str) -> Tuple[str, List[Any]]:
        dt_col = _dataset_datetime_column(path)
        clauses: List[str] = []
        params: List[Any] = []
        for year, month in months:
            clauses.append("(year = ? AND month = ?)")
            params.extend([int(year), int(month)])

        where_parts: List[str] = []
        if clauses:
            where_parts.append("(" + " OR ".join(clauses) + ")")
        if dt_col and start is not None:
            where_parts.append(f'{_duckdb_quote_ident(dt_col)} >= ?')
            params.append(start.to_pydatetime())
        if dt_col and end is not None:
            where_parts.append(f'{_duckdb_quote_ident(dt_col)} <= ?')
            params.append(end.to_pydatetime())
        return " AND ".join(where_parts), params

    base_where_sql, base_params = _build_where_sql(base_path)
    sidecar_where_sql, sidecar_params = _build_where_sql(sidecar_path)
    merged = _duckdb_read_joined_parquet_df(
        base_path,
        sidecar_path,
        base_columns=base_columns,
        sidecar_columns=_joined_sidecar_columns(sidecar_columns, row_id_col=row_id_col),
        base_where_sql=base_where_sql,
        base_params=base_params,
        sidecar_where_sql=sidecar_where_sql,
        sidecar_params=sidecar_params,
        require_datetime=True,
        row_id_col=row_id_col,
    )
    if drop_row_id:
        _delete_columns_inplace(merged, [row_id_col])
    return merged


def _to_json_text(value):
    """Convert dict/list payloads to JSON text; preserve missing values."""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    try:
        if pd.isna(value):
            return pd.NA
    except (TypeError, ValueError):
        pass
    return str(value)


PARQUET_NESTED_COLUMNS = ("chronosift_signals", "chronosift_explain")
PARQUET_SIGNAL_MAP_TYPE = pa.map_(pa.string(), pa.float64())
PARQUET_EXPLAIN_LIST_TYPE = pa.list_(pa.string())
PARQUET_NESTED_FALLBACK_EXCEPTIONS = (
    pa.ArrowInvalid,
    pa.ArrowTypeError,
    pa.ArrowNotImplementedError,
    TypeError,
    ValueError,
)


def _to_parquet_json_text(value: Any) -> Any:
    """Fallback JSON serialisation for nested payload columns when Arrow inference fails."""
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, default=str)
    if value is None:
        return pd.NA
    try:
        if pd.isna(value):
            return pd.NA
    except Exception:
        pass
    return str(value)


def _serialise_json_text_series(series: pd.Series, serializer) -> pd.Series:
    """Serialise only non-null positions to JSON text, preserving nulls cheaply."""
    mask = series.notna().to_numpy(dtype=bool, copy=False)
    if not bool(mask.any()):
        return pd.Series(pd.NA, index=series.index, dtype="string")
    positions = np.flatnonzero(mask)
    result = pd.Series(pd.NA, index=series.index, dtype="string")
    serialised = [serializer(value) for value in series.iloc[positions].to_numpy(copy=False)]
    result.iloc[positions] = pd.array(serialised, dtype="string")
    return result


def _classify_non_null_object_values(values: np.ndarray) -> Tuple[bool, Dict[type, int]]:
    """Classify non-null object values in one pass for parquet normalisation."""
    type_counts: Dict[type, int] = {}
    for value in values:
        value_type = type(value)
        if value_type in (dict, list, tuple):
            return True, {}
        type_counts[value_type] = type_counts.get(value_type, 0) + 1
    return False, type_counts


def _prepare_nested_columns_json_fallback(
    df: pd.DataFrame,
    columns: Iterable[str],
) -> pd.DataFrame:
    """Serialise selected nested payload columns to JSON text without copying untouched columns."""
    # JSON text is the schema-stability fallback, not the preferred encoding.
    # Arrow nested columns preserve richer structure whenever they can be
    # written consistently across files.
    out = pd.DataFrame(df, copy=False)
    out.attrs = {}
    for col in columns:
        if col not in out.columns:
            continue
        series = out[col]
        if series.notna().any():
            out[col] = _serialise_json_text_series(series, _to_parquet_json_text)
        else:
            out[col] = series.astype("string")
    return out


def _parse_nested_json_value(value: Any) -> Any:
    """Decode an already-serialised nested payload while preserving ordinary strings."""
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    if not stripped or stripped[0] not in "[{":
        return value
    try:
        return json.loads(stripped)
    except (TypeError, ValueError, json.JSONDecodeError):
        return value


def _normalise_signal_map_for_arrow(value: Any) -> Optional[Dict[str, float]]:
    """Return one deterministic signal map suitable for Arrow MAP<string,double>."""
    value = _parse_nested_json_value(value)
    if value is None:
        return None
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    if not isinstance(value, dict):
        raise TypeError(f"chronosift_signals must be a mapping, got {type(value).__name__}")

    normalised: Dict[str, float] = {}
    for raw_name, raw_value in sorted(value.items(), key=lambda item: str(item[0])):
        if raw_value is None:
            continue
        if isinstance(raw_value, (bool, int, float, np.integer, np.floating)):
            normalised[str(raw_name)] = float(raw_value)
            continue
        raise TypeError(
            "chronosift_signals values must be numeric for stable Arrow map encoding; "
            f"signal {raw_name!r} has {type(raw_value).__name__}"
        )
    return normalised


def _normalise_explain_list_for_arrow(value: Any) -> Optional[List[str]]:
    """Encode variable explanation objects as canonical JSON inside a stable Arrow list."""
    value = _parse_nested_json_value(value)
    if value is None:
        return None
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    if not isinstance(value, (list, tuple)):
        raise TypeError(f"chronosift_explain must be a list, got {type(value).__name__}")
    return [
        json.dumps(item, sort_keys=True, ensure_ascii=False, default=str)
        for item in value
    ]


def _prepare_nested_columns_stable_arrow(df: pd.DataFrame) -> pd.DataFrame:
    """
    Give ChronoSIFT's variable payloads deterministic cross-file Arrow types.

    Signals are a queryable ``MAP<string,double>`` instead of an inferred
    struct whose fields depend on the signals present in one partition.
    Explanation entries retain their complete variable evidence as canonical
    JSON strings inside a stable ``LIST<string>`` column.
    """
    out = pd.DataFrame(df, copy=False)
    out.attrs = {}
    if "chronosift_signals" in out.columns:
        values = [_normalise_signal_map_for_arrow(value) for value in out["chronosift_signals"].to_numpy(copy=False)]
        out["chronosift_signals"] = pd.Series(
            pd.array(values, dtype=pd.ArrowDtype(PARQUET_SIGNAL_MAP_TYPE)),
            index=out.index,
        )
    if "chronosift_explain" in out.columns:
        values = [_normalise_explain_list_for_arrow(value) for value in out["chronosift_explain"].to_numpy(copy=False)]
        out["chronosift_explain"] = pd.Series(
            pd.array(values, dtype=pd.ArrowDtype(PARQUET_EXPLAIN_LIST_TYPE)),
            index=out.index,
        )
    return out


def _restore_stable_nested_payloads(df: pd.DataFrame) -> pd.DataFrame:
    """Restore stable Parquet payloads to the in-memory dict/list API."""
    if "chronosift_signals" in df.columns:
        df["chronosift_signals"] = df["chronosift_signals"].map(_parse_nested_json_value)

    if "chronosift_explain" in df.columns:
        def restore_explain(value: Any) -> Any:
            decoded = _parse_nested_json_value(value)
            if isinstance(decoded, np.ndarray):
                decoded = decoded.tolist()
            if not isinstance(decoded, (list, tuple)):
                return decoded
            return [_parse_nested_json_value(item) for item in decoded]

        df["chronosift_explain"] = df["chronosift_explain"].map(restore_explain)
    return df


def _drop_dataframe_attrs(df: pd.DataFrame) -> pd.DataFrame:
    """Return a shallow DataFrame wrapper with attrs cleared to avoid parquet metadata bloat."""
    if not getattr(df, "attrs", None):
        return df
    # pandas persists DataFrame.attrs into parquet metadata. For ChronoSift that
    # can include large sparse signal/explain maps attached during processing,
    # which inflates sidecar files dramatically and makes large runs pathological.
    out = pd.DataFrame(df, copy=False)
    out.attrs = {}
    return out


def _write_parquet_subchunk(
    subchunk: pd.DataFrame,
    outfile: Path,
    parquet_kwargs: Dict[str, Any],
    *,
    nested_columns_encoding: str = "arrow",
) -> str:
    """
    Write a parquet subchunk with deterministic Arrow types for explain/signals.

    Signal dictionaries become Arrow maps, while variable explanation objects
    become canonical JSON entries inside an Arrow list. The legacy JSON-column
    fallback remains only as a last-resort compatibility path.
    """
    subchunk = _drop_dataframe_attrs(subchunk)
    if nested_columns_encoding == "json_text":
        nested_cols = [c for c in PARQUET_NESTED_COLUMNS if c in subchunk.columns]
        if nested_cols:
            fallback_chunk = _prepare_nested_columns_json_fallback(subchunk, nested_cols)
            fallback_chunk.to_parquet(outfile, **parquet_kwargs)
            return "json_fallback"

    nested_cols = [c for c in PARQUET_NESTED_COLUMNS if c in subchunk.columns]
    stable_chunk = _prepare_nested_columns_stable_arrow(subchunk) if nested_cols else subchunk
    try:
        stable_chunk.to_parquet(outfile, **parquet_kwargs)
        return "nested"
    except PARQUET_NESTED_FALLBACK_EXCEPTIONS as exc:
        if not nested_cols:
            raise
        logger.warning(
            "Write stage: Arrow nested encoding failed for %s (%s); falling back to JSON text for %s",
            outfile,
            exc.__class__.__name__,
            ",".join(nested_cols),
        )
        try:
            outfile.unlink(missing_ok=True)
        except Exception:
            pass
        fallback_chunk = _prepare_nested_columns_json_fallback(subchunk, nested_cols)
        fallback_chunk.to_parquet(outfile, **parquet_kwargs)
        return "json_fallback"

# -----------------------------
# Normalise columns for parquet
# -----------------------------

def normalise_for_parquet(df: pd.DataFrame, verbose: bool = True) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Convert timestamp to UTC datetime, set as index, sort, and
    add partition columns year/month.

    Assumes 'timestamp' is microseconds since epoch.
    """
    # Forensic timelines regularly contain implausible-but-parseable timestamps.
    # The policy here is to preserve those rows as evidence and only drop values
    # that cannot be converted into datetimes at all.

    changes: list[dict[str, str]] = []
    nested_parquet_cols = set(PARQUET_NESTED_COLUMNS)

    if "timestamp" not in df.columns:
        raise KeyError("Input chunk does not contain a 'timestamp' column")

    df["datetime"] = pd.to_datetime(
        df["timestamp"],
        unit="us",
        errors="coerce",
        utc=True,
    )

    # Drop rows where timestamp could not be parsed
    df = df.dropna(subset=["datetime"])

    # Normalise to datetime index
    df = df.set_index("datetime")
    df = _stable_sort_datetime_frame(df)

    # Partition columns must be regular columns, derived from the index
    # datetime64[us] can represent forensic timestamps far beyond year 32767.
    # Preserve those rows and use Int32 for the corresponding partition value.
    df["year"] = pd.Series(df.index.year, index=df.index, dtype="Int32")
    df["month"] = pd.Series(df.index.month, index=df.index, dtype="Int8")

    # PID stays as existing column, coerced to string
    if "pid" in df.columns:
        before = str(df["pid"].dtype)
        df["pid"] = df["pid"].astype("string")
        changes.append({
            "column": "pid",
            "action": "coerce_string",
            "detail": f"{before} -> string",
        })

    # Normalise remaining object columns
    for col in df.columns:
        if str(df[col].dtype) != "object":
            continue

        if col in nested_parquet_cols:
            changes.append({
                "column": col,
                "action": "preserve_nested_object",
                "detail": "leave nested payload for Arrow parquet fast-path; JSON fallback happens at write time",
            })
            continue

        series = df[col]
        non_null = series.dropna()

        if non_null.empty:
            df[col] = series.astype("string")
            changes.append({
                "column": col,
                "action": "empty_object_to_string",
                "detail": "object column with only missing values after prior cleanup",
            })
            continue

        has_nested_payload, type_counts = _classify_non_null_object_values(non_null.to_numpy(copy=False))

        if has_nested_payload:
            before = str(series.dtype)
            df[col] = _serialise_json_text_series(series, _to_json_text)
            changes.append({
                "column": col,
                "action": "json_text_object",
                "detail": f"{before} -> string(JSON text for list/dict/tuple payloads)",
            })
            continue

        if len(type_counts) == 1 and str in type_counts:
            df[col] = series.astype("string")
            changes.append({
                "column": col,
                "action": "stringify",
                "detail": "object[str] -> string",
            })
        elif len(type_counts) == 1 and bool in type_counts:
            df[col] = series.astype("boolean")
            changes.append({
                "column": col,
                "action": "bool_normalise",
                "detail": "object[bool] -> boolean",
            })
        elif len(type_counts) == 1 and int in type_counts:
            df[col] = pd.to_numeric(series, errors="coerce").astype("Int64")
            changes.append({
                "column": col,
                "action": "int_normalise",
                "detail": "object[int] -> Int64",
            })
        elif len(type_counts) == 1 and float in type_counts:
            df[col] = pd.to_numeric(series, errors="coerce")
            changes.append({
                "column": col,
                "action": "float_normalise",
                "detail": "object[float] -> float",
            })
        else:
            df[col] = series.astype("string")
            changes.append({
                "column": col,
                "action": "fallback_string",
                "detail": f"mixed object types {list(type_counts)} -> string",
            })


    report = pd.DataFrame(changes, columns=["column", "action", "detail"])

    if verbose:
        print("\nNormalisation complete.")
        print(f"Rows:    {len(df):,}")
        print(f"Columns: {len(df.columns):,}")
        print("\nDtypes:")
        print(df.dtypes.astype(str).value_counts().to_string())
        if not report.empty:
            print("\nChanges made:")
            print(report.to_string(index=False))

    return df, report


def _get_partition_datetime_series(
    df: pd.DataFrame,
    datetime_col: str | None = None,
    unix_ts_col: str | None = None,
    utc: bool = True,
) -> pd.Series:
    """
    Return a datetime Series to use for partitioning.

    Priority:
    1. Explicit datetime_col
    2. DatetimeIndex
    3. Explicit unix_ts_col interpreted as seconds since epoch
    4. A column named 'timestamp' interpreted as microseconds since epoch
    """
    if datetime_col is not None:
        dt = pd.to_datetime(df[datetime_col], errors="coerce", utc=utc)
        return pd.Series(dt, index=df.index, name="_partition_dt")

    if isinstance(df.index, pd.DatetimeIndex):
        dt = df.index
        if utc and dt.tz is None:
            dt = dt.tz_localize("UTC")
        elif utc and dt.tz is not None:
            dt = dt.tz_convert("UTC")
        return pd.Series(dt, index=df.index, name="_partition_dt")

    if unix_ts_col is not None:
        dt = pd.to_datetime(df[unix_ts_col], unit="s", errors="coerce", utc=utc)
        return pd.Series(dt, index=df.index, name="_partition_dt")

    if "timestamp" in df.columns:
        dt = pd.to_datetime(df["timestamp"], unit="us", errors="coerce", utc=utc)
        return pd.Series(dt, index=df.index, name="_partition_dt")

    raise ValueError(
        "Could not determine partition datetime. Provide datetime_col or unix_ts_col, "
        "or use a DatetimeIndex."
    )


def write_time_partitioned_parquet(
    df: pd.DataFrame,
    outdir: str | Path,
    *,
    datetime_col: str | None = None,
    unix_ts_col: str | None = None,
    compression: str = "zstd",
    row_group_size: int = 250_000,
    max_rows_per_file: int = 500_000,
    index: bool = True,
    normalise: bool = True,
    nested_columns_encoding: str = "arrow",
    verbose: bool = True,
) -> pd.DataFrame:
    """
    Normalise a DataFrame and write it as year/month partitioned Parquet files.

    Parameters
    ----------
    datetime_col:
        Column to parse as datetime for partitioning.
    unix_ts_col:
        Unix timestamp column in seconds for partitioning.
    compression:
        Parquet compression codec. 'zstd' is the recommended default.
    row_group_size:
        Parquet row group size.
    max_rows_per_file:
        If a month contains more rows than this, it is split into multiple files.
    index:
        Whether to store the DataFrame index in Parquet.
    normalise:
        Whether to run normalisation first.
    nested_columns_encoding:
        How to write nested payload columns such as signals/explain. Use
        ``"json_text"`` to serialise them to stable JSON strings across files.
    """
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    logger.info("Write stage: preparing partitioned parquet output under %s", outdir)
    if normalise:
        df2, report = normalise_for_parquet(df, verbose=verbose)
    else:
        df2 = df
        report = pd.DataFrame(columns=["column", "action", "detail"])

    # Large sparse-state attrs must not survive into partition filtering,
    # grouping, or subchunk slicing. Clearing them only at the final parquet
    # write boundary is too late because pandas may already have propagated
    # the metadata during `loc`, `groupby`, or `iloc`.
    df2 = _drop_dataframe_attrs(df2)

    part_dt = _get_partition_datetime_series(
        df2,
        datetime_col=datetime_col,
        unix_ts_col=unix_ts_col,
        utc=True,
    )

    valid_mask = part_dt.notna()
    invalid_count = int((~valid_mask).sum())

    if invalid_count:
        if verbose:
            print(f"\nDropping {invalid_count:,} rows with invalid partition datetime")
        df2 = _drop_dataframe_attrs(df2).loc[valid_mask]
        part_dt = part_dt.loc[valid_mask]

    part_year_col = "__chronosift_part_year"
    part_month_col = "__chronosift_part_month"
    total_files = 0
    nested_write_count = 0
    json_fallback_count = 0
    try:
        df2[part_year_col] = part_dt.dt.year.astype("Int64")
        df2[part_month_col] = part_dt.dt.month.astype("Int64")

        target_partitions: Set[Tuple[int, int]] = set()
        if len(df2):
            target_partitions = {
                (int(year), int(month))
                for year, month in df2[[part_year_col, part_month_col]].drop_duplicates().itertuples(index=False, name=None)
                if pd.notna(year) and pd.notna(month)
            }
        _cleanup_partition_output_tree(outdir, target_partitions)

        grouped = df2.groupby([part_year_col, part_month_col], sort=True)

        for (year, month), chunk in grouped:
            partdir = outdir / f"year={int(year):04d}" / f"month={int(month):02d}"
            partdir.mkdir(parents=True, exist_ok=True)

            chunk = _drop_dataframe_attrs(chunk).drop(columns=[part_year_col, part_month_col])

            nrows = len(chunk)
            nparts = max(1, math.ceil(nrows / max_rows_per_file))

            for i in range(nparts):
                start = i * max_rows_per_file
                end = min((i + 1) * max_rows_per_file, nrows)
                subchunk = _drop_dataframe_attrs(chunk).iloc[start:end]

                outfile = partdir / f"part-{i:05d}.parquet"
                parquet_kwargs: Dict[str, Any] = {
                    "engine": "pyarrow",
                    "compression": compression,
                    "row_group_size": min(int(row_group_size), len(subchunk)),
                    "index": index,
                    "use_dictionary": True,
                    "write_statistics": True,
                }
                if compression == "zstd":
                    parquet_kwargs["compression_level"] = 3

                write_mode = _write_parquet_subchunk(
                    subchunk,
                    outfile,
                    parquet_kwargs,
                    nested_columns_encoding=nested_columns_encoding,
                )
                if write_mode == "nested":
                    nested_write_count += 1
                else:
                    json_fallback_count += 1
                total_files += 1

                if verbose:
                    size_mb = outfile.stat().st_size / (1024 * 1024)
                    logger.debug(
                        "Wrote %s  rows=%s  size=%.2f MiB",
                        outfile,
                        f"{len(subchunk):,}",
                        size_mb,
                    )
    finally:
        _delete_columns_inplace(df2, [part_year_col, part_month_col])

    if verbose:
        logger.debug("Done. Wrote %s Parquet file(s) under %s", f"{total_files:,}", outdir)
    logger.info(
        "Write stage: chunk encoding summary nested=%d json_fallback=%d",
        nested_write_count,
        json_fallback_count,
    )
    _invalidate_dataset_columns_cache(str(outdir))
        
    logger.info("Write stage: complete for %s", outdir)
    return report
