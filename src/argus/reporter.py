from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from argus import paths


# ---------------- Utilities ----------------

def _reports_dir() -> Path:
    paths.ensure_dirs()
    if hasattr(paths, "reports_dir"):
        try:
            p = Path(paths.reports_dir())  # type: ignore[attr-defined]
            p.mkdir(parents=True, exist_ok=True)
            return p
        except Exception:
            pass
    p = Path.home() / ".local/share/argus/reports"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _safe(s: str) -> str:
    return "".join(ch if (ch.isalnum() or ch in ("-", "_")) else "_" for ch in (s or ""))


def _load_details(details_json: str) -> Dict[str, Any]:
    if not details_json:
        return {}
    try:
        d = json.loads(details_json)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _kv_from_msg(msg: str) -> Dict[str, str]:
    """
    Parse key=value pairs inside messages like:
    'Service unhealthy: cron.service (active=inactive, sub=dead, state=enabled, ...)'
    """
    out: Dict[str, str] = {}
    for k, v in re.findall(r"\b([a-z_]+)\s*=\s*([^,\)\s]+)", msg or "", flags=re.IGNORECASE):
        out[k.lower()] = v
    return out


def _journal_tail_unit(unit: str, n: int = 3) -> List[str]:
    """
    Best-effort journald tail for a unit.
    Will return [] if journalctl isn't accessible (permissions, not installed, etc).
    """
    unit = (unit or "").strip()
    if not unit:
        return []
    try:
        r = subprocess.run(
            ["journalctl", "-u", unit, "-b", "--no-pager", "-n", str(n), "-o", "short"],
            capture_output=True,
            text=True,
            timeout=1.5,
        )
        if r.returncode != 0:
            return []
        lines = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
        return lines[-n:]
    except Exception:
        return []


def _kb_to_mb(kb: int) -> int:
    return int(kb // 1024)


# ---------------- Why / Evidence ----------------

def _why_for_event(code: str, msg: str, details_json: str = "") -> str:
    code_u = (code or "").upper()
    d = _load_details(details_json)
    kv = _kv_from_msg(msg or "")

    # HEALTH
    if code_u == "HEA-01":
        return "CPU temperature stayed ≥85°C for ≥30s (clears when ≤80°C for ≥60s)."
    if code_u == "HEA-02":
        return "CPU temperature stayed ≥95°C for ≥10s (clears when ≤90°C for ≥60s)."
    if code_u == "HEA-03":
        return "Disk usage exceeded the threshold for 2 consecutive checks (85% WARNING / 95% CRITICAL)."

    if code_u == "HEA-04":
        unit_state = str(d.get("unit_file_state") or d.get("state") or kv.get("state") or "unknown").lower()
        active = str(d.get("active_state") or kv.get("active") or "unknown").lower()
        sub = str(d.get("sub_state") or kv.get("sub") or "unknown").lower()
        result = str(d.get("result") or kv.get("result") or "unknown").lower()

        return (
            "A tracked systemd service was detected as unhealthy. "
            f"Expected-to-run state was derived from systemd (enabled/state='{unit_state}'). "
            f"Runtime status was active='{active}', sub='{sub}', result='{result}'. "
            "ARGUS triggers when a monitored unit is enabled but not running/healthy, "
            "or when systemd reports a failure state."
        )

    if code_u == "HEA-05":
        thr = d.get("thresholds") or {}
        wm = thr.get("warn_mem_avail_pct", 10)
        cm = thr.get("crit_mem_avail_pct", 5)
        ws = thr.get("warn_swap_used_pct", 70)
        cs = thr.get("crit_swap_used_pct", 90)
        wo = thr.get("warn_swapout_ps", 200)
        co = thr.get("crit_swapout_ps", 1000)

        return (
            "Memory pressure detected using MemAvailable + swap activity. "
            f"Triggers when MemAvailable ≤ {wm}% (WARNING) / ≤ {cm}% (CRITICAL), "
            f"or SwapUsed ≥ {ws}% (WARNING) / ≥ {cs}% (CRITICAL), "
            f"or swapout ≥ {wo} pages/s (WARNING) / ≥ {co} pages/s (CRITICAL). "
            "High swapout usually means thrashing and a sluggish/frozen desktop."
        )

    # SECURITY
    if code_u == "SEC-01":
        return (
            "Repeated SSH authentication failures from the same source within a short time window "
            "(LAN may be downgraded; localhost is INFO)."
        )
    if code_u == "SEC-02":
        return "Successful login correlated to previous SSH failures from the same IP within 10 minutes."
    if code_u == "SEC-03":
        return "Unusual sudo usage (first-seen user+command window) with escalation rules for suspicious context."
    if code_u == "SEC-04":
        return (
            "A new listening service was detected (first-seen window); severity depends on bind scope "
            "and sensitive ports."
        )
    if code_u == "SEC-05":
        return "Integrity change detected on a critical config/auth file (hash changed with debounce)."

    return "(rule details coming soon)"


def _evidence_for_event(code: str, entity: str, msg: str, details_json: str = "") -> List[str]:
    out: List[str] = []
    c = (code or "").upper()
    m = msg or ""
    ent = entity or ""
    d = _load_details(details_json)
    kv = _kv_from_msg(m)

    # HEALTH
    if c in ("HEA-01", "HEA-02"):
        mm = re.search(r"(\d{2,3})\s*°C", m)
        if mm:
            out.append(f"Observed CPU temp: {mm.group(1)}°C")
        if ent:
            out.append(f"Sensor/entity: {ent}")
        out.append("Source: thermal provider (sysfs /sys/class/thermal when available)")
        return out[:5]

    if c == "HEA-03":
        if ent:
            out.append(f"Mount: {ent}")
        mm = re.search(r"(\d{1,3})\s*%", m)
        if mm:
            out.append(f"Used: {mm.group(1)}%")
        out.append("Source: filesystem stats (statvfs)")
        return out[:5]

    if c == "HEA-04":
        unit = (d.get("unit") or d.get("name") or ent or "").strip() or "(unknown unit)"
        active = str(d.get("active_state") or kv.get("active") or "unknown")
        sub = str(d.get("sub_state") or kv.get("sub") or "unknown")
        enabled = str(d.get("unit_file_state") or d.get("state") or kv.get("state") or "unknown")
        result = str(d.get("result") or kv.get("result") or "unknown")
        status = str(d.get("status") or d.get("exit_status") or kv.get("status") or "unknown")
        restarts = str(d.get("restarts") or d.get("n_restarts") or kv.get("restarts") or "unknown")

        out.append(f"Unit: {unit}")
        out.append(f"Enabled/state: {enabled}")
        out.append(f"Active/Sub: {active}/{sub}")
        out.append(f"Result/Status: {result}/{status}")
        out.append(f"Restarts: {restarts}")

        j = _journal_tail_unit(unit, n=3)
        if j:
            for ln in j:
                if len(out) >= 5:
                    break
                out.append(f"journal: {ln}")

        return out[:5]

    if c == "HEA-05":
        mem_total_kb = int(d.get("mem_total_kb") or 0)
        mem_av_kb = int(d.get("mem_available_kb") or 0)
        mem_av_pct = d.get("mem_available_pct")

        swap_total_kb = int(d.get("swap_total_kb") or 0)
        swap_used_kb = int(d.get("swap_used_kb") or 0)
        swap_used_pct = d.get("swap_used_pct")

        swapin_ps = d.get("swapin_ps")
        swapout_ps = d.get("swapout_ps")

        if mem_total_kb > 0:
            out.append(
                f"MemAvailable: {float(mem_av_pct or 0.0):.2f}% ({_kb_to_mb(mem_av_kb)}MB/{_kb_to_mb(mem_total_kb)}MB)"
            )
        if swap_total_kb > 0:
            out.append(
                f"SwapUsed: {float(swap_used_pct or 0.0):.2f}% ({_kb_to_mb(swap_used_kb)}MB/{_kb_to_mb(swap_total_kb)}MB)"
            )
        if swapout_ps is not None:
            out.append(f"swapout: {float(swapout_ps):.2f} pages/s")
        if swapin_ps is not None:
            out.append(f"swapin: {float(swapin_ps):.2f} pages/s")

        # if we still have room, show top process (compressed)
        tps = d.get("top_processes")
        if isinstance(tps, list) and tps:
            # show only the biggest one (keep evidence compact)
            tp0 = tps[0] if isinstance(tps[0], dict) else None
            if isinstance(tp0, dict):
                pid = tp0.get("pid")
                name = tp0.get("name") or "?"
                rss_kb = int(tp0.get("rss_kb") or 0)
                out.append(f"Top RSS: pid={pid} {name} rss={_kb_to_mb(rss_kb)}MB")

        # always show source line if space
        if len(out) < 5:
            out.append("Source: /proc/meminfo + /proc/vmstat (+ /proc/<pid>/status for top RSS)")

        return out[:5]

    # SECURITY
    if c == "SEC-01":
        ipm = re.search(r"\b(?:da|from)\s+([0-9a-fA-F\.:]+)\b", m)
        if ipm:
            out.append(f"Source IP: {ipm.group(1)}")
        nm = re.search(r"\b(\d+)\s+(?:tentativi|attempts)\b", m, re.IGNORECASE)
        if nm:
            out.append(f"Failed attempts: {nm.group(1)}")
        out.append("Source: journald (sshd/auth)")
        return out[:5]

    if c == "SEC-02":
        um = re.search(r"\buser=([^\s\)]+)", m)
        if um:
            out.append(f"User: {um.group(1)}")
        ipm = re.search(r"\b(?:da|from)\s+([0-9a-fA-F\.:]+)\b", m)
        if ipm:
            out.append(f"Source IP: {ipm.group(1)}")
        nm = re.search(r"\b(?:dopo|after)\s+(\d+)\s+(?:tentativi|attempts)\b", m, re.IGNORECASE)
        if nm:
            out.append(f"Prior failures: {nm.group(1)}")
        out.append("Source: journald (sshd/auth)")
        return out[:5]

    if c == "SEC-03":
        if ent:
            out.append(f"User: {ent}")
        cm = re.search(r"Sudo command:\s*([^\(]+)", m)
        if cm:
            out.append(f"Command: {cm.group(1).strip()}")
        tm = re.search(r"\btty=([^\s\)]+)", m)
        if tm:
            out.append(f"TTY: {tm.group(1)}")
        rm = re.search(r"\brunas=([^\s\),]+)", m)
        if rm:
            out.append(f"Run-as: {rm.group(1)}")
        out.append("Source: journald (sudo)")
        return out[:5]

    if c == "SEC-04":
        pm = re.search(r":\s*([^\s]+)\s+(?:su|on)\s+([^:\s]+):(\d+)/(\w+)", m, re.IGNORECASE)
        if pm:
            out.append(f"Process: {pm.group(1)}")
            out.append(f"Listener: {pm.group(2)}:{pm.group(3)}/{pm.group(4)}")
        bm = re.search(r"\[(LOCAL|LAN|GLOBAL)\]", m, re.IGNORECASE)
        if bm:
            out.append(f"Bind scope: {bm.group(1).upper()}")
        sm = re.search(r"\bservice=([^\)]+)\)", m)
        if sm:
            out.append(f"Service hint: {sm.group(1)}")
        out.append("Source: listener scan (ss/netstat equivalent)")
        return out[:5]

    if c == "SEC-05":
        pm = re.search(r"(?:modificato|changed):\s*([^\s]+)", m, re.IGNORECASE)
        if pm:
            out.append(f"Path: {pm.group(1)}")
        hm = re.search(r"\bold=([0-9a-f]{8,})\b.*\bnew=([0-9a-f]{8,})\b", m, re.IGNORECASE)
        if hm:
            out.append(f"SHA256 old: {hm.group(1)}")
            out.append(f"SHA256 new: {hm.group(2)}")
        out.append("Source: integrity watcher (sha256 + debounce)")
        return out[:5]

    return out[:5]


# ---------------- Advice ----------------

ADVICE: Dict[str, List[str]] = {
    # SECURITY
    "SEC-01": [
        "If it wasn't you: change passwords / rotate SSH keys, and disable SSH if not needed.",
        "Block the source IP (ufw/nftables) and review SSH exposure (port, allowlist).",
        "Inspect auth logs to see targeted usernames and frequency.",
    ],
    "SEC-02": [
        "Confirm the login was yours (IP, time, user).",
        "If suspicious: change password / revoke keys and terminate active sessions.",
        "Review follow-up activity and sudo usage (SEC-03).",
    ],
    "SEC-03": [
        "If it wasn't you: change password and review local users/accounts.",
        "Check what the sudo command did and what changed on the system.",
        "If high-risk: audit /etc/passwd, sudoers, cron, systemctl changes.",
    ],
    "SEC-04": [
        "Confirm the service is expected (process + port + bind scope).",
        "If not expected: close the port or disable the service immediately.",
        "If expected: add to Trust (allowlist) to reduce noise.",
    ],
    "SEC-05": [
        "Verify what changed and whether it matches planned maintenance/updates.",
        "If suspicious: restore secure config and rotate credentials if needed.",
        "Correlate with login/sudo activity (SEC-02 / SEC-03).",
    ],
    # HEALTH
    "HEA-01": [
        "Reduce CPU load and verify airflow/fans are working.",
        "Check cooling (dust / thermal paste / fan curves / pump if AIO).",
        "If recurring: investigate background processes and sustained temps.",
    ],
    "HEA-02": [
        "Stop heavy workloads immediately and confirm temperature drops.",
        "Check cooling hardware (fan/pump) and ensure proper contact/airflow.",
        "If it stays critical: shut down to prevent damage.",
    ],
    "HEA-03": [
        "Free up disk space to avoid failures (updates, logs, services).",
        "Find the biggest directories/files (du / ncdu) and remove what’s not needed.",
        "If unexpected growth: investigate logs, runaway processes, snapshots.",
    ],
    "HEA-04": [
        "Check the unit/service status and recent errors (systemctl status / journalctl).",
        "Verify configuration, dependencies, and any recent changes/deploys.",
        "If critical: temporarily stop/disable to stabilize while investigating.",
    ],
    "HEA-05": [
        "Identify the top memory consumer (htop) and close/kill it to stop thrashing.",
        "Check swap + OOM events (free -h, swapon --show, journalctl -k -b | grep -i oom).",
        "If recurring: reduce background apps/VMs, consider increasing RAM/swap or tuning swappiness.",
    ],
}


# ---------------- Rendering ----------------

def render_markdown(event: Dict[str, Any]) -> str:
    ts = datetime.fromtimestamp(int(event["ts"])).strftime("%Y-%m-%d %H:%M:%S")
    code = str(event.get("code") or "").upper()
    sev = str(event.get("severity") or "INFO").upper()
    ent = str(event.get("entity") or "")
    msg = str(event.get("message") or "").strip()
    details_json = str(event.get("details_json") or "")

    actions = ADVICE.get(code, [])
    if not actions:
        actions = [
            "Confirm whether this was expected.",
            "If unexpected: inspect logs around the timestamp.",
            "Apply mitigation steps appropriate for this event type.",
        ]
    actions = (actions + ["(n/a)", "(n/a)", "(n/a)"])[:3]

    why = _why_for_event(code, msg, details_json)
    evidence = _evidence_for_event(code, ent, msg, details_json)

    lines: List[str] = []
    lines.append(f"# ARGUS Report — {code} ({sev})")
    lines.append("")
    lines.append(f"- Time: {ts}")
    if ent:
        lines.append(f"- Entity: {ent}")
    lines.append("")
    lines.append("## What happened")
    lines.append(msg if msg else "(n/a)")
    lines.append("")
    lines.append("## Why this triggered")
    lines.append(why)
    lines.append("")
    lines.append("## What to do now")
    lines.append(f"1) {actions[0]}")
    lines.append(f"2) {actions[1]}")
    lines.append(f"3) {actions[2]}")
    lines.append("")
    lines.append("## Details")
    lines.append(f"- event_id: {event.get('id')}")
    lines.append(f"- code: {code}")
    lines.append(f"- severity: {sev}")
    lines.append("")
    lines.append("## Evidence")
    if evidence:
        for ev in evidence[:5]:
            lines.append(f"- {ev}")
    else:
        lines.append("- (no evidence available)")
    lines.append("")
    return "\n".join(lines)


def write_report(event: Dict[str, Any]) -> Tuple[str, str]:
    """
    Create MD + JSON report. Returns (md_path, json_path).
    """
    rep_dir = _reports_dir()
    ts = datetime.fromtimestamp(int(event["ts"])).strftime("%Y-%m-%d_%H%M%S")
    code = _safe(str(event.get("code") or "EVT").upper())
    eid = int(event.get("id") or 0)

    md_path = rep_dir / f"report_{ts}_{code}_{eid}.md"
    js_path = rep_dir / f"report_{ts}_{code}_{eid}.json"

    md = render_markdown(event)
    md_path.write_text(md, encoding="utf-8")

    msg = str(event.get("message") or "")
    ent = str(event.get("entity") or "")
    details_json = str(event.get("details_json") or "")

    payload = {
        "report_version": 2,
        "id": eid,
        "ts": int(event["ts"]),
        "code": str(event.get("code") or "").upper(),
        "severity": str(event.get("severity") or "").upper(),
        "message": msg,
        "entity": ent,
        "details_json": details_json,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "why": _why_for_event(str(event.get("code") or ""), msg, details_json),
        "evidence": _evidence_for_event(str(event.get("code") or ""), ent, msg, details_json),
        "actions": ADVICE.get(str(event.get("code") or "").upper(), []),
    }
    js_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    return str(md_path), str(js_path)


def list_saved_reports(code: str | None = None) -> List[Dict[str, Any]]:
    """
    List already-saved reports from the reports directory (JSON payloads).
    Returns a list sorted by event timestamp desc.
    """
    rep_dir = _reports_dir()
    code_u = (code or "").upper().strip()

    items: List[Dict[str, Any]] = []
    for p in rep_dir.glob("report_*.json"):
        try:
            payload = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue

        c = str(payload.get("code") or "").upper()
        if code_u and c != code_u:
            continue

        ts = int(payload.get("ts") or 0)
        dt = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "?"
        sev = str(payload.get("severity") or "").upper() or "?"
        ent = str(payload.get("entity") or "")

        md = p.with_suffix(".md")
        items.append(
            {
                "ts": ts,
                "time": dt,
                "code": c,
                "severity": sev,
                "entity": ent,
                "md_path": str(md) if md.exists() else "",
                "json_path": str(p),
                "file": p.name,
            }
        )

    items.sort(key=lambda x: x.get("ts", 0), reverse=True)
    return items
