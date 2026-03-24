#!/usr/bin/env python3
"""Reusable analyzer for Vault counters activity API JSON payloads.

Produces a comprehensive markdown report including:
- Executive summary with key findings
- Top namespace breakdown with distribution analysis
- Authentication method breakdown
- Monthly growth trends with ASCII visualisation
- Per-month top contributors and auth mix
- Secret sync usage
- Data-driven key insights and recommendations
"""

import argparse
import json
import sys
from calendar import monthrange
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class CLIError(Exception):
    """Raised for user-facing CLI errors."""


def validate_input_file(path: Path, label: str) -> None:
    if not path.exists():
        raise CLIError(f"{label} not found: {path}")
    if not path.is_file():
        raise CLIError(f"{label} is not a file: {path}")


def prepare_output_path(path: Path, label: str) -> None:
    if path.exists() and path.is_dir():
        raise CLIError(f"Cannot write {label}: output path is a directory: {path}")

    parent = path.parent
    if parent.exists() and not parent.is_dir():
        raise CLIError(f"Cannot write {label}: parent path is not a directory: {parent}")

    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CLIError(f"Cannot create parent directory for {label} {path}: {exc}") from exc


def load_payload(input_file: Path) -> Dict[str, Any]:
    try:
        with input_file.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        raise CLIError(
            f"Failed to parse JSON in {input_file} at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    except OSError as exc:
        raise CLIError(f"Failed to read input JSON {input_file}: {exc}") from exc


def pct(part: int, whole: int) -> float:
    return (part / whole * 100) if whole else 0.0


def fmt_pct(part: int, whole: int) -> str:
    return f"{pct(part, whole):.1f}%"


def friendly_month(iso: str) -> str:
    """'2025-06' -> 'Jun 2025'."""
    try:
        dt = datetime.strptime(iso[:7], "%Y-%m")
        return dt.strftime("%b %Y")
    except ValueError:
        return iso[:7]


def flatten_namespace_paths_from_new_clients(months: Iterable[Dict[str, Any]]) -> set:
    paths = set()
    for month in months:
        for ns in month.get("new_clients", {}).get("namespaces", []):
            paths.add(ns.get("namespace_path", ""))
    return paths


def by_namespace_looks_masked(by_namespace: List[Dict[str, Any]]) -> bool:
    paths = [ns.get("namespace_path", "") for ns in by_namespace if ns.get("namespace_path")]
    if not paths:
        return False
    masked_patterns = ("ns-XXX", "ns-id", "XXXXX")
    masked_count = sum(1 for p in paths if any(token in p for token in masked_patterns))
    return (masked_count / len(paths)) >= 0.6


KNOWN_AUTH_TYPES = (
    "kubernetes",
    "approle",
    "userpass",
    "ns_token",
    "token",
    "ldap",
    "oidc",
    "jwt",
    "cert",
    "azure",
    "aws",
    "gcp",
)


def canonical_auth_type(value: str) -> Optional[str]:
    name = value.strip().strip("/").lower()
    if not name:
        return None
    for known in KNOWN_AUTH_TYPES:
        if name == known or name.startswith(f"{known}-") or name.startswith(f"{known}_"):
            return known
    return name


def get_auth_type(mount: Dict[str, Any]) -> str:
    mount_type = canonical_auth_type(str(mount.get("mount_type", "")))
    if mount_type:
        return mount_type
    mount_path = str(mount.get("mount_path", "")).strip().strip("/")
    if mount_path.startswith("auth/"):
        first_component = mount_path.replace("auth/", "", 1).split("/", 1)[0]
        inferred = canonical_auth_type(first_component)
        if inferred:
            return inferred
    return "unknown"


def get_count(counts: Dict[str, Any], *keys: str) -> int:
    for key in keys:
        if key in counts:
            return safe_int(counts.get(key, 0), 0)
    return 0


AUTH_DISPLAY_NAMES = {
    "jwt": "JWT",
    "oidc": "OIDC",
    "kubernetes": "Kubernetes",
    "approle": "AppRole",
    "ldap": "LDAP",
    "token": "Token",
    "ns_token": "NS Token",
    "kv": "KV",
    "cert": "TLS Cert",
    "aws": "AWS",
    "azure": "Azure",
    "gcp": "GCP",
    "userpass": "Userpass",
}


def auth_display(name: str) -> str:
    return AUTH_DISPLAY_NAMES.get(name.lower(), name)


def display_namespace(path: str, trim_trailing: bool = False) -> str:
    value = str(path or "")
    if trim_trailing:
        value = value.rstrip("/")
    return value or "(root)"


def parse_timestamp(value: str) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z") and "." in text:
        left, frac = text[:-1].split(".", 1)
        text = f"{left}.{(frac + '000000')[:6]}+00:00"
    elif text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def month_end_timestamp(month: str) -> Optional[datetime]:
    try:
        year, month_num = [int(part) for part in month.split("-", 1)]
        last_day = monthrange(year, month_num)[1]
    except (TypeError, ValueError):
        return None
    return datetime(year, month_num, last_day, 23, 59, 59, tzinfo=timezone.utc)


def is_last_month_partial(monthly: List[Dict[str, Any]], end_time: str) -> bool:
    if not monthly:
        return False
    end_dt = parse_timestamp(end_time)
    last_month = monthly[-1].get("month", "")
    month_end = month_end_timestamp(last_month)
    if end_dt is None or month_end is None:
        return False
    if end_dt.strftime("%Y-%m") != last_month:
        return False
    return end_dt < month_end


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze(data: Dict[str, Any], top_namespaces: int, top_mounts: int, top_growth: int) -> Dict[str, Any]:
    payload = data.get("data", {})
    total = payload.get("total", {})
    months = payload.get("months", [])
    by_namespace = payload.get("by_namespace", [])

    masked = by_namespace_looks_masked(by_namespace)
    real_paths = flatten_namespace_paths_from_new_clients(months)

    # --- Namespace stats ---
    ns_stats: List[Dict[str, Any]] = []
    mount_stats: List[Dict[str, Any]] = []
    auth_stats: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"clients": 0, "entity_clients": 0, "namespaces": set(), "mounts": 0}
    )

    for ns in by_namespace:
        counts = ns.get("counts", {})
        ns_path = ns.get("namespace_path", "")
        ns_stats.append({
            "namespace_id": ns.get("namespace_id", ""),
            "path": ns_path,
            "clients": get_count(counts, "clients"),
            "entity_clients": get_count(counts, "entity_clients"),
            "non_entity_clients": get_count(counts, "non_entity_clients"),
            "secret_syncs": get_count(counts, "secret_syncs"),
            "distinct_entities": get_count(counts, "distinct_entities"),
            "non_entity_tokens": get_count(counts, "non_entity_tokens"),
        })

        for mount in ns.get("mounts", []):
            mc = mount.get("counts", {})
            mp = mount.get("mount_path", "")
            mt = get_auth_type(mount)
            item = {
                "namespace": ns_path,
                "mount_path": mp,
                "mount_type": mt,
                "clients": get_count(mc, "clients"),
                "entity_clients": get_count(mc, "entity_clients"),
                "distinct_entities": get_count(mc, "distinct_entities"),
            }
            mount_stats.append(item)
            if mp.startswith("auth/"):
                auth_stats[mt]["clients"] += item["clients"]
                auth_stats[mt]["entity_clients"] += item["entity_clients"]
                auth_stats[mt]["namespaces"].add(ns_path)
                auth_stats[mt]["mounts"] += 1

    ns_stats.sort(key=lambda x: x["clients"], reverse=True)
    mount_stats.sort(key=lambda x: x["clients"], reverse=True)
    auth_sorted = sorted(auth_stats.items(), key=lambda x: x[1]["clients"], reverse=True)
    total_auth_clients = sum(x[1]["clients"] for x in auth_sorted)

    # --- Monthly analysis ---
    monthly_new: List[Dict[str, Any]] = []
    growth_by_namespace: Dict[str, int] = defaultdict(int)
    # Also accumulate per-namespace breakdowns from monthly data (for masked fallback)
    ns_id_map: Dict[str, str] = {}  # namespace_path -> namespace_id from monthly data
    monthly_ns_entity: Dict[str, int] = defaultdict(int)
    monthly_ns_non_entity: Dict[str, int] = defaultdict(int)
    monthly_ns_syncs: Dict[str, int] = defaultdict(int)
    monthly_auth_stats: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"clients": 0, "entity_clients": 0, "namespaces": set(), "mounts": set()}
    )
    monthly_mount_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"clients": 0, "entity_clients": 0})
    cumulative_new = 0
    prev_month_new: Optional[int] = None

    for month in months:
        ts = str(month.get("timestamp", ""))[:10]
        new_counts = month.get("new_clients", {}).get("counts", {})
        new_clients = get_count(new_counts, "clients")
        cumulative_new += new_clients
        mom_change = None if prev_month_new is None else (new_clients - prev_month_new)
        prev_month_new = new_clients

        auth_breakdown: Dict[str, int] = defaultdict(int)
        top_ns: List[Dict[str, Any]] = []
        # Collect namespace_id from cumulative namespaces (covers all active namespaces)
        for ns in month.get("namespaces", []):
            ns_path = ns.get("namespace_path", "")
            ns_id = ns.get("namespace_id", "")
            if ns_id and ns_path not in ns_id_map:
                ns_id_map[ns_path] = ns_id

        for ns in month.get("new_clients", {}).get("namespaces", []):
            ns_path = ns.get("namespace_path", "")
            ns_id = ns.get("namespace_id", "")
            if ns_id and ns_path not in ns_id_map:
                ns_id_map[ns_path] = ns_id
            c = get_count(ns.get("counts", {}), "clients")
            top_ns.append({"path": ns_path, "clients": c})
            growth_by_namespace[ns_path] += c
            monthly_ns_entity[ns_path] += get_count(ns.get("counts", {}), "entity_clients")
            monthly_ns_non_entity[ns_path] += get_count(ns.get("counts", {}), "non_entity_clients")
            monthly_ns_syncs[ns_path] += get_count(ns.get("counts", {}), "secret_syncs")
            for m in ns.get("mounts", []):
                mp = str(m.get("mount_path", ""))
                mt = get_auth_type(m)
                mc = get_count(m.get("counts", {}), "clients")
                me = get_count(m.get("counts", {}), "entity_clients")
                if mp.startswith("auth/"):
                    auth_breakdown[mt] += mc
                    monthly_auth_stats[mt]["clients"] += mc
                    monthly_auth_stats[mt]["entity_clients"] += me
                    monthly_auth_stats[mt]["namespaces"].add(ns_path)
                    monthly_auth_stats[mt]["mounts"].add(f"{ns_path}::{mp}")
                mount_key = f"{ns_path}::{mp}"
                monthly_mount_stats[mount_key]["clients"] += mc
                monthly_mount_stats[mount_key]["entity_clients"] += me

        top_ns.sort(key=lambda x: x["clients"], reverse=True)
        monthly_new.append({
            "month": ts[:7],
            "clients": new_clients,
            "entity_clients": get_count(new_counts, "entity_clients"),
            "non_entity_clients": get_count(new_counts, "non_entity_clients"),
            "secret_syncs": get_count(new_counts, "secret_syncs"),
            "cumulative_new": cumulative_new,
            "mom_change": mom_change,
            "top_namespaces": top_ns[:10],
            "auth_breakdown": dict(auth_breakdown),
        })

    growth_sorted = sorted(growth_by_namespace.items(), key=lambda x: x[1], reverse=True)
    total_growth = sum(v for _, v in growth_sorted)

    # --- Masked fallback: rebuild stats from monthly data with real paths ---
    if masked and real_paths:
        ns_stats = []
        for path, clients in growth_sorted:
            ns_stats.append({
                "namespace_id": ns_id_map.get(path, ""),
                "path": path,
                "clients": clients,
                "entity_clients": monthly_ns_entity.get(path, 0),
                "non_entity_clients": monthly_ns_non_entity.get(path, 0),
                "secret_syncs": monthly_ns_syncs.get(path, 0),
                "distinct_entities": 0,
                "non_entity_tokens": 0,
            })
        # ns_stats already sorted by clients descending (via growth_sorted)

        # Rebuild auth stats with real namespace paths
        auth_sorted = sorted(monthly_auth_stats.items(), key=lambda x: x[1]["clients"], reverse=True)
        # Convert mounts sets to counts
        for _, stats in auth_sorted:
            stats["mounts"] = len(stats["mounts"])
        total_auth_clients = sum(x[1]["clients"] for x in auth_sorted)

        # Rebuild mount stats from monthly data
        mount_stats = []
        for key, counts in monthly_mount_stats.items():
            parts = key.split("::", 1)
            ns_path = parts[0] if len(parts) > 0 else ""
            mp = parts[1] if len(parts) > 1 else ""
            mt = get_auth_type({"mount_path": mp}) if mp.startswith("auth/") else ""
            mount_stats.append({
                "namespace": ns_path,
                "mount_path": mp,
                "mount_type": mt,
                "clients": counts["clients"],
                "entity_clients": counts["entity_clients"],
                "distinct_entities": 0,
            })
        mount_stats.sort(key=lambda x: x["clients"], reverse=True)

    # --- Secret sync namespaces ---
    sync_ns = [ns for ns in ns_stats if ns["secret_syncs"] > 0]

    # --- Namespace distribution ---
    all_ns = ns_stats
    total_clients = get_count(total, "clients")
    distribution = []
    for threshold in [5, 10, 20, 50]:
        if threshold <= len(all_ns):
            top_c = sum(ns["clients"] for ns in all_ns[:threshold])
            distribution.append({"label": f"Top {threshold}", "namespaces": threshold, "clients": top_c})
    if len(all_ns) > 50:
        remaining = len(all_ns) - 50
    elif distribution:
        remaining = len(all_ns) - distribution[-1]["namespaces"]
    else:
        remaining = len(all_ns)
    remaining_clients = total_clients - (distribution[-1]["clients"] if distribution else 0)
    distribution.append({"label": f"Remaining {remaining}", "namespaces": remaining, "clients": remaining_clients})

    low_usage = len([ns for ns in all_ns if 0 < ns["clients"] <= 5])
    zero_ns = len([ns for ns in all_ns if ns["clients"] == 0])
    last_month_partial = is_last_month_partial(monthly_new, payload.get("end_time", ""))

    return {
        "period": {
            "start_time": payload.get("start_time", ""),
            "end_time": payload.get("end_time", ""),
            "months": len(months),
            "namespaces": len(ns_stats),
        },
        "total": {
            "clients": total_clients,
            "entity_clients": get_count(total, "entity_clients"),
            "non_entity_clients": get_count(total, "non_entity_clients"),
            "acme_clients": get_count(total, "acme_clients"),
            "secret_syncs": get_count(total, "secret_syncs"),
            "distinct_entities": get_count(total, "distinct_entities"),
            "non_entity_tokens": get_count(total, "non_entity_tokens"),
        },
        "validation": {"by_namespace_masked": masked, "new_clients_paths": real_paths},
        "top_namespaces": ns_stats[:top_namespaces],
        "all_namespaces": ns_stats,
        "distribution": distribution,
        "low_usage_ns": low_usage,
        "zero_ns": zero_ns,
        "top_mounts": mount_stats[:top_mounts],
        "auth_methods": auth_sorted,
        "total_auth_clients": total_auth_clients,
        "monthly_new": monthly_new,
        "last_month_partial": last_month_partial,
        "sync_namespaces": sync_ns,
        "top_growth": growth_sorted[:top_growth],
        "total_growth": total_growth,
        "input_file": "",  # set by caller
    }


# ---------------------------------------------------------------------------
# Markdown renderer - comprehensive report
# ---------------------------------------------------------------------------

def render_markdown(summary: Dict[str, Any]) -> str:
    o: List[str] = []
    p = summary["period"]
    t = summary["total"]
    v = summary["validation"]
    top_ns = summary["top_namespaces"]
    auth = summary["auth_methods"]
    monthly = summary["monthly_new"]
    growth = summary["top_growth"]
    dist = summary["distribution"]
    sync_ns = summary["sync_namespaces"]
    last_month_partial = summary["last_month_partial"]
    total_clients = t["clients"]
    now = datetime.now()
    today = f"{now.day} {now.strftime('%B %Y')}"  # portable; %-d fails on Windows

    start_friendly = friendly_month(p["start_time"])
    end_friendly = friendly_month(p["end_time"])

    # ---- Header ----
    o.append("# Vault Client Utilization Analysis")
    o.append("")
    o.append(f"**Report Period:** {start_friendly} - {end_friendly} ({p['months']} months)  ")
    o.append(f"**Generated:** {today}")
    o.append("")
    o.append("---")
    o.append("")

    # ---- Executive Summary ----
    o.append("## Executive Summary")
    o.append("")
    o.append("| Metric | Value |")
    o.append("|--------|------:|")
    o.append(f"| **Total Clients** | {total_clients:,} |")
    entity_pct = fmt_pct(t["entity_clients"], total_clients)
    o.append(f"| Entity Clients | {t['entity_clients']:,} ({entity_pct}) |")
    o.append(f"| Non-Entity Clients | {t['non_entity_clients']:,} ({fmt_pct(t['non_entity_clients'], total_clients)}) |")
    o.append(f"| Secret Syncs | {t['secret_syncs']:,} |")
    o.append(f"| ACME Clients | {t['acme_clients']:,} |")
    o.append(f"| Total Namespaces | {p['namespaces']} |")
    o.append("")

    # Key Findings - data-driven
    o.append("### Key Findings")
    o.append("")
    findings = _generate_key_findings(summary)
    for i, finding in enumerate(findings, 1):
        o.append(f"{i}. {finding}")
    o.append("")
    o.append("---")
    o.append("")

    # ---- Top Namespaces ----
    o.append(f"## Top {len(top_ns)} Namespaces by Client Count")
    o.append("")
    o.append("| Rank | Namespace | Namespace ID | Clients | % of Total |")
    o.append("|------|-----------|--------------|--------:|----------:|")
    top_n_total = 0
    for i, ns in enumerate(top_ns, 1):
        top_n_total += ns["clients"]
        o.append(f"| {i} | {display_namespace(ns['path'])} | {ns['namespace_id']} | {ns['clients']:,} | {fmt_pct(ns['clients'], total_clients)} |")
    o.append("")
    o.append(f"**Top {len(top_ns)} = {top_n_total:,} clients ({fmt_pct(top_n_total, total_clients)} of total)**")
    o.append("")

    # Namespace Distribution
    o.append("### Namespace Distribution")
    o.append("")
    o.append("| Segment | Namespaces | Clients | % of Total |")
    o.append("|---------|----------:|--------:|----------:|")
    for d in dist:
        o.append(f"| {d['label']} | {d['namespaces']} | {d['clients']:,} | {fmt_pct(d['clients'], total_clients)} |")
    o.append("")
    low = summary["low_usage_ns"] + summary["zero_ns"]
    total_ns = p["namespaces"]
    if low > 0:
        o.append(f"**Long tail observation:** {low} namespaces ({round(pct(low, total_ns))}%) have 5 or fewer clients")
    o.append("")
    o.append("---")
    o.append("")

    # ---- Auth Methods ----
    o.append("## Authentication Methods Breakdown")
    o.append("")
    o.append("| Auth Method | Clients | % of Total | Namespaces | Mounts |")
    o.append("|-------------|--------:|----------:|----------:|-------:|")
    tac = summary["total_auth_clients"]
    for a_name, a_stats in auth:
        display = auth_display(a_name)
        a_pct = fmt_pct(a_stats["clients"], tac)
        bold = a_stats["clients"] / tac > 0.10 if tac else False
        if bold:
            o.append(f"| **{display}** | {a_stats['clients']:,} | **{a_pct}** | {len(a_stats['namespaces'])} | {a_stats['mounts']} |")
        else:
            o.append(f"| {display} | {a_stats['clients']:,} | {a_pct} | {len(a_stats['namespaces'])} | {a_stats['mounts']} |")
    o.append("")

    # Auth analysis bullets
    o.append("### Analysis")
    o.append("")
    for a_name, a_stats in auth:
        if a_stats["clients"] / tac > 0.05 if tac else False:
            display = auth_display(a_name)
            o.append(f"- **{display}** accounts for {fmt_pct(a_stats['clients'], tac)} of clients ({a_stats['clients']:,} across {len(a_stats['namespaces'])} namespaces)")
    o.append("")

    top_mounts = [m for m in summary["top_mounts"] if m["clients"] > 0]
    if top_mounts:
        o.append(f"### Top {len(top_mounts)} Mounts by Client Count")
        o.append("")
        o.append("| Rank | Namespace | Mount Path | Auth Method | Clients | % of Total |")
        o.append("|------|-----------|------------|-------------|--------:|----------:|")
        for i, m in enumerate(top_mounts, 1):
            method = auth_display(m["mount_type"]) if m["mount_path"].startswith("auth/") else "-"
            o.append(
                f"| {i} | {display_namespace(m['namespace'])} | `{m['mount_path']}` | {method} | {m['clients']:,} | {fmt_pct(m['clients'], total_clients)} |"
            )
        o.append("")
    o.append("---")
    o.append("")

    # ---- Monthly Growth ----
    o.append("## Monthly Growth Analysis")
    o.append("")
    o.append("### Client Growth Trend")
    o.append("")
    o.append("| Month | New Clients | Cumulative | MoM Change |")
    o.append("|-------|------------:|------------:|-----------:|")
    last_month = monthly[-1] if monthly else None
    for m in monthly:
        fm = friendly_month(m["month"])
        mom = "-" if m["mom_change"] is None else f"{m['mom_change']:+,}"
        partial = ""
        if m is last_month and last_month_partial:
            partial = "*"
        o.append(f"| {fm}{partial} | {m['clients']:,} | {m['cumulative_new']:,} | {mom} |")
    o.append("")

    # check if last month is partial
    if last_month and last_month_partial:
        lm = friendly_month(last_month["month"])
        o.append(f"*{lm} is likely partial month data")
        o.append("")

    # ASCII bar chart
    o.append("### Growth Visualisation")
    o.append("")
    o.append("```")
    max_new = max((m["clients"] for m in monthly), default=1) or 1
    peak_idx = max(range(len(monthly)), key=lambda i: monthly[i]["clients"]) if monthly else 0
    bar_width = 44
    for i, m in enumerate(monthly):
        fm = friendly_month(m["month"])
        bar_len = round(m["clients"] / max_new * bar_width)
        bar = "\u2588" * bar_len
        suffix = ""
        if i == peak_idx and m["clients"] == max_new:
            suffix = "  (Peak)"
        if i == len(monthly) - 1 and last_month_partial:
            suffix = " (partial)"
        o.append(f"{fm:<10}{bar} {m['clients']:,}{suffix}")
    o.append("```")
    o.append("")
    o.append("---")
    o.append("")

    # ---- New Client Sources by Month ----
    o.append("## New Client Sources by Month")
    o.append("")
    o.append("### Top Contributing Namespaces per Month")
    o.append("")
    o.append("| Month | #1 Contributor (%) | #2 Contributor (%) |")
    o.append("|-------|-------------------|-------------------|")
    for m in monthly:
        fm = friendly_month(m["month"])
        top2 = m["top_namespaces"][:2]
        cells = []
        for ns in top2:
            p_val = fmt_pct(ns["clients"], m["clients"])
            cells.append(f"{display_namespace(ns['path'], trim_trailing=True)} ({p_val})")
        while len(cells) < 2:
            cells.append("-")
        o.append(f"| {fm} | {cells[0]} | {cells[1]} |")
    o.append("")

    # When by_namespace is real, rank namespaces by summed monthly new clients as a separate growth view.
    # In the masked fallback the namespace table above is already built from the same numbers.
    if growth and not (v["by_namespace_masked"] and v["new_clients_paths"]):
        total_growth = summary["total_growth"]
        o.append(f"### Top {len(growth)} Namespaces by New Clients")
        o.append("")
        o.append("| Rank | Namespace | New Clients | % of New |")
        o.append("|------|-----------|------------:|---------:|")
        for i, (path, clients) in enumerate(growth, 1):
            o.append(f"| {i} | {display_namespace(path)} | {clients:,} | {fmt_pct(clients, total_growth)} |")
        o.append("")

    # Detect leadership shift
    if len(monthly) >= 3:
        first_leaders = [m["top_namespaces"][0]["path"] if m["top_namespaces"] else "" for m in monthly[:len(monthly)//2]]
        last_leaders = [m["top_namespaces"][0]["path"] if m["top_namespaces"] else "" for m in monthly[len(monthly)//2:]]
        first_common = max(set(first_leaders), key=first_leaders.count) if first_leaders else ""
        last_common = max(set(last_leaders), key=last_leaders.count) if last_leaders else ""
        if first_common and last_common and first_common != last_common:
            # Find when the shift happened
            for m in monthly:
                if m["top_namespaces"] and m["top_namespaces"][0]["path"] == last_common:
                    shift_month = friendly_month(m["month"])
                    o.append(
                        f"**Key Insight:** Leadership in new client generation shifted from "
                        f"`{display_namespace(first_common, trim_trailing=True)}` to "
                        f"`{display_namespace(last_common, trim_trailing=True)}` starting {shift_month}."
                    )
                    o.append("")
                    break

    # Auth Method Mix per month
    o.append("### Auth Method Mix per Month (New Clients)")
    o.append("")
    # Determine the top 3 auth methods + Other
    all_auth_keys: Dict[str, int] = defaultdict(int)
    for m in monthly:
        for ak, av in m["auth_breakdown"].items():
            all_auth_keys[ak] += av
    top_auth_keys = [k for k, _ in sorted(all_auth_keys.items(), key=lambda x: x[1], reverse=True)[:3]]
    header_names = [auth_display(k) for k in top_auth_keys] + ["Other"]
    o.append("| Month | " + " | ".join(header_names) + " |")
    o.append("|-------" + "|-----:" * len(header_names) + "|")

    for m in monthly:
        fm = friendly_month(m["month"])
        total_m = m["clients"]
        row = [fm]
        other = total_m
        for k in top_auth_keys:
            c = m["auth_breakdown"].get(k, 0)
            other -= c
            row.append(fmt_pct(c, total_m))
        row.append(fmt_pct(max(other, 0), total_m))
        o.append("| " + " | ".join(row) + " |")
    o.append("")

    # Highlight any notable auth trend
    if len(monthly) >= 3 and len(top_auth_keys) >= 3:
        k3 = top_auth_keys[2]  # 3rd auth method
        first_pct = pct(monthly[0]["auth_breakdown"].get(k3, 0), monthly[0]["clients"]) if monthly[0]["clients"] else 0
        peak_val = 0
        peak_month = ""
        for m in monthly:
            auth_pct_val = pct(m["auth_breakdown"].get(k3, 0), m["clients"]) if m["clients"] else 0
            if auth_pct_val > peak_val:
                peak_val = auth_pct_val
                peak_month = friendly_month(m["month"])
        if peak_val > first_pct + 3:
            o.append(f"**Trend:** {auth_display(k3)} auth peaked at {peak_val:.1f}% in {peak_month}.")
            o.append("")

    o.append("---")
    o.append("")

    # ---- Secret Syncs ----
    o.append("## Secret Syncs")
    o.append("")
    if sync_ns:
        if len(sync_ns) == 1:
            o.append(f"Only **{len(sync_ns)} namespace** uses Vault Secrets Sync:")
        else:
            o.append(f"**{len(sync_ns)} namespaces** use Vault Secrets Sync:")
        for ns in sync_ns:
            o.append(f"- `{display_namespace(ns['path'])}`: {ns['secret_syncs']} secret syncs")
        o.append("")
        o.append(f"Secret syncs total **{t['secret_syncs']:,}** across {len(sync_ns)} of {p['namespaces']} namespaces.")
    else:
        o.append("No namespaces recorded Vault Secrets Sync activity in this period.")
    o.append("")
    o.append("---")
    o.append("")

    # ---- Key Insights & Recommendations ----
    o.append("## Key Insights & Discussion Points")
    o.append("")
    o.append("*These points are generated from the numbers above using simple rules. Validate them with the account team or customer before presenting them as conclusions.*")
    o.append("")
    insights = _generate_insights(summary)
    for i, (title, body_lines) in enumerate(insights, 1):
        o.append(f"### {i}. {title}")
        for line in body_lines:
            o.append(line)
        o.append("")

    o.append("---")
    o.append("")

    # ---- Data Notes ----
    o.append("## Data Notes")
    o.append("")
    o.append(f"- **Report Period:** {p['start_time'][:10]} to {p['end_time'][:10]} (billing period)")
    o.append("- **Data Source:** Vault Activity Log API (`sys/internal/counters/activity`)")
    if last_month and last_month_partial:
        lm = friendly_month(last_month["month"])
        o.append(f"- **{lm}:** Partial month data (report generated {today})")
    if v["by_namespace_masked"] and v["new_clients_paths"]:
        o.append(f"- **Namespace Paths:** Extracted from monthly breakdown (top-level `by_namespace` was anonymised)")
    o.append("")
    o.append("---")
    o.append("")
    if summary.get("input_file"):
        o.append(f"*Report generated from {Path(summary['input_file']).name}*")
    else:
        o.append("*Report generated by analyze_vault_utilization.py*")
    o.append("")

    return "\n".join(o)


# ---------------------------------------------------------------------------
# Data-driven insight generators
# ---------------------------------------------------------------------------

MACHINE_AUTH = {"kubernetes", "approle", "cert", "aws", "azure", "gcp", "jwt"}
HUMAN_AUTH = {"ldap", "oidc", "userpass", "okta", "radius", "github", "saml"}
TOKEN_AUTH = {"token", "ns_token"}


def auth_usage_note(name: str) -> List[str]:
    """Describe what a dominant auth method usually implies, without asserting more than the data shows."""
    if name in MACHINE_AUTH:
        lines = ["- The largest group of clients are workloads or pipelines rather than people"]
        if name == "jwt":
            lines.append("- JWT is often CI/CD (for example GitLab or GitHub Actions); confirm which issuers are configured")
        return lines
    if name in HUMAN_AUTH:
        return [
            "- The largest group of clients are likely people signing in interactively",
            "- Check whether workloads are borrowing human auth methods instead of a machine method",
        ]
    if name in TOKEN_AUTH:
        return [
            "- Clients are mostly created directly from tokens rather than an auth method",
            "- Review where tokens are minted and whether an auth method would give better identity tracking",
        ]
    return ["- Confirm how this auth method is used before drawing conclusions"]


def growth_trend(months: List[Dict[str, Any]]) -> Optional[Tuple[str, float, float]]:
    """Compare average new clients in the first and second half of the period."""
    if len(months) < 4:
        return None
    half = len(months) // 2
    first = sum(m["clients"] for m in months[:half]) / half
    second = sum(m["clients"] for m in months[half:]) / (len(months) - half)
    if first == 0:
        return ("increasing" if second > 0 else "flat", first, second)
    change = (second - first) / first
    if change > 0.15:
        label = "accelerating"
    elif change < -0.15:
        label = "slowing"
    else:
        label = "steady"
    return (label, first, second)


def comparable_months(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    monthly = summary["monthly_new"]
    return monthly[:-1] if summary["last_month_partial"] and len(monthly) > 1 else monthly


def growing_third_auth(summary: Dict[str, Any]) -> Optional[Tuple[str, float, float]]:
    auth = summary["auth_methods"]
    months = comparable_months(summary)
    if len(auth) < 3 or len(months) < 2:
        return None
    k3 = auth[2][0]
    first_pct = pct(months[0]["auth_breakdown"].get(k3, 0), months[0]["clients"])
    last_pct = pct(months[-1]["auth_breakdown"].get(k3, 0), months[-1]["clients"])
    if last_pct > first_pct + 1:
        return (k3, first_pct, last_pct)
    return None


def _generate_key_findings(summary: Dict[str, Any]) -> List[str]:
    """Generate 4-6 bullet key findings from data."""
    findings: List[str] = []
    t = summary["total"]
    total_clients = t["clients"]
    top_ns = summary["top_namespaces"]
    auth = summary["auth_methods"]
    tac = summary["total_auth_clients"]
    dist = summary["distribution"]

    if len(top_ns) >= 2:
        top2_pct = round(pct(top_ns[0]["clients"] + top_ns[1]["clients"], total_clients))
        n1 = display_namespace(top_ns[0]["path"], trim_trailing=True)
        n2 = display_namespace(top_ns[1]["path"], trim_trailing=True)
        findings.append(f"**Top two namespaces drive {top2_pct}% of all usage** (`{n1}` and `{n2}`)")

    if auth:
        top_auth_name, top_auth_stats = auth[0]
        top_auth_pct = round(pct(top_auth_stats["clients"], tac))
        findings.append(f"**{auth_display(top_auth_name)} is the most used auth method** with {top_auth_pct}% of auth-method clients")

    for d in dist:
        if d["label"] == "Top 20":
            top20_pct = round(pct(d["clients"], total_clients))
            prefix = "High concentration: " if top20_pct >= 50 else ""
            findings.append(f"**{prefix}Top 20 namespaces represent {top20_pct}% of total clients**")
            break

    growing = growing_third_auth(summary)
    if growing:
        k3, first_pct, last_pct = growing
        findings.append(
            f"**{auth_display(k3)} share of new clients is rising**, from {first_pct:.1f}% to {last_pct:.1f}% between the first and last full month"
        )

    trend = growth_trend(comparable_months(summary))
    if trend:
        label, first, second = trend
        findings.append(f"**New-client growth is {label}**: about {first:,.0f}/month in the first half vs {second:,.0f}/month in the second half")

    entity_pct = pct(t["entity_clients"], total_clients)
    if total_clients:
        if entity_pct >= 95:
            findings.append(f"**{entity_pct:.1f}% of clients are entity clients**, so non-entity tokens are a small share")
        elif entity_pct < 80:
            findings.append(f"**Non-entity tokens are {100 - entity_pct:.1f}% of clients**, which is worth reviewing")

    return findings


def _generate_insights(summary: Dict[str, Any]) -> List[Tuple[str, List[str]]]:
    """Generate Key Insights & Discussion Points sections."""
    insights: List[Tuple[str, List[str]]] = []
    t = summary["total"]
    total_clients = t["clients"]
    top_ns = summary["top_namespaces"]
    auth = summary["auth_methods"]
    tac = summary["total_auth_clients"]

    if len(top_ns) >= 2:
        top2_pct = fmt_pct(top_ns[0]["clients"] + top_ns[1]["clients"], total_clients)
        n1 = display_namespace(top_ns[0]["path"], trim_trailing=True)
        n2 = display_namespace(top_ns[1]["path"], trim_trailing=True)
        insights.append(("Usage Concentration", [
            f"The top two namespaces (`{n1}` and `{n2}`) account for **{top2_pct} of all clients**. Worth discussing:",
            "- What these teams use Vault for, and whether their growth will continue",
            "- How much of the license count depends on them",
        ]))

    if auth:
        top_auth_name, top_auth_stats = auth[0]
        display = auth_display(top_auth_name)
        insights.append((f"{display} Is the Main Auth Method", [
            f"**{fmt_pct(top_auth_stats['clients'], tac)} of auth-method clients use {display}** ({top_auth_stats['mounts']} mounts across {len(top_auth_stats['namespaces'])} namespaces). This usually means:",
            *auth_usage_note(top_auth_name),
        ]))

    growing = growing_third_auth(summary)
    if growing:
        k3, first_pct, last_pct = growing
        display = auth_display(k3)
        insights.append((f"{display} Share Rising", [
            f"{display} went from **{first_pct:.1f}% to {last_pct:.1f}%** of new clients between the first and last full month:",
            "- Find out which teams are onboarding with it",
            "- Check whether each pipeline or user creates one identity or many",
        ]))

    low = summary["low_usage_ns"] + summary["zero_ns"]
    total_ns = summary["period"]["namespaces"]
    if low > 0 and total_ns > 0:
        insights.append(("Long Tail of Low-Usage Namespaces", [
            f"**{low} of {total_ns} namespaces ({round(pct(low, total_ns))}%) have 5 or fewer clients**:",
            "- Some may be new, test or inactive namespaces",
            "- Consider whether consolidation or cleanup is useful",
        ]))

    if total_clients:
        entity_pct_val = pct(t["entity_clients"], total_clients)
        if entity_pct_val >= 90:
            insights.append(("Mostly Entity Clients", [
                f"**{entity_pct_val:.1f}% of clients are entity clients** and {t['non_entity_clients']:,} are non-entity tokens:",
                "- Most access goes through auth methods that map to identities",
            ]))
        else:
            insights.append(("Non-Entity Token Usage", [
                f"**{100 - entity_pct_val:.1f}% of clients ({t['non_entity_clients']:,}) are non-entity tokens**:",
                "- Find where tokens are created directly (for example `vault token create` or orphan tokens)",
                "- Moving them to an auth method improves identity tracking",
            ]))

    months = comparable_months(summary)
    trend = growth_trend(months)
    if months:
        avg_new = sum(m["clients"] for m in months) / len(months)
        low_new = min(m["clients"] for m in months)
        high_new = max(m["clients"] for m in months)
        lines = [f"Between {low_new:,} and {high_new:,} new clients per full month (average {avg_new:,.0f}):"]
        if trend:
            label, first, second = trend
            lines.append(f"- The trend is **{label}**: {first:,.0f}/month in the first half vs {second:,.0f}/month in the second half")
        lines.append(
            f"- At the average rate, 12 more months would add roughly {round(avg_new * 12):,} new clients. This is a simple run-rate, not a forecast"
        )
        insights.append(("Growth Trajectory", lines))

    return insights


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze Vault counters activity JSON payload and produce a comprehensive markdown report.")
    parser.add_argument("input_json", type=Path, help="Path to counters activity JSON file")
    parser.add_argument("-o", "--output", type=Path, help="Path to write the markdown report (default: stdout)")
    parser.add_argument("--top-namespaces", type=int, default=20, help="Top namespaces to display (default: 20)")
    parser.add_argument("--top-mounts", type=int, default=30, help="Top mounts to display (default: 30)")
    parser.add_argument("--top-growth", type=int, default=20, help="Top growth contributors (default: 20)")
    args = parser.parse_args()
    for option in ("top_namespaces", "top_mounts", "top_growth"):
        if getattr(args, option) < 1:
            parser.error(f"--{option.replace('_', '-')} must be >= 1")
    return args


def main() -> int:
    args = parse_args()

    try:
        validate_input_file(args.input_json, "Input JSON")
        if args.output:
            prepare_output_path(args.output, "markdown report")

        payload = load_payload(args.input_json)
        summary = analyze(payload, args.top_namespaces, args.top_mounts, args.top_growth)
        summary["input_file"] = str(args.input_json)

        report = render_markdown(summary)

        if args.output:
            args.output.write_text(report, encoding="utf-8")
            print(f"Report written to: {args.output}", file=sys.stderr)
        else:
            print(report)
    except CLIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error: failed to write output: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
