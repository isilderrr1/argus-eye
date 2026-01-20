from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from argus import paths


ADVICE: Dict[str, List[str]] = {
    "SEC-01": [
        "Se non sei tu: cambia password e disabilita SSH se non serve.",
        "Blocca l’IP (ufw/nftables) e verifica utenti/chiavi SSH.",
        "Controlla report/log per capire username provati e frequenza.",
    ],
    "SEC-02": [
        "Verifica se l’accesso era tuo (IP, orario, user).",
        "Se sospetto: cambia password e chiudi le sessioni attive.",
        "Controlla comandi recenti e attività sudo (SEC-03).",
    ],
    "SEC-03": [
        "Se non sei tu: cambia password e verifica account/local users.",
        "Controlla cosa ha fatto quel comando e cosa è cambiato nel sistema.",
        "Se high-risk: verifica /etc/passwd, sudoers, cron, systemctl, ecc.",
    ],
    "SEC-04": [
        "Verifica se il servizio è voluto (programma e porta).",
        "Se non serve: chiudi porta o disabilita il servizio.",
        "Se è voluto: premi T per Trust (allowlist) e riduci rumore.",
    ],
    "SEC-05": [
        "Se non sei tu: verifica subito cosa è cambiato nel file.",
        "Controlla aggiornamenti/maintenance e attività sudo correlate (SEC-03).",
        "Ripristina configurazione sicura e ruota credenziali se necessario.",
    ],
    "HEA-01": [
        "Riduci carichi e controlla ventole/dissipatore.",
        "Verifica curve ventole e pasta termica.",
        "Se persiste: indaga processi e airflow del case.",
    ],
    "HEA-02": [
        "Chiudi carichi subito; verifica dissipazione.",
        "Se non scende: spegni per evitare danni.",
        "Controlla pompa/ventole/sensori e carichi anomali.",
    ],
    "HEA-03": [
        "Libera spazio (cache, download, log).",
        "Trova i top file/dir che occupano di più.",
        "Assicurati che aggiornamenti non siano bloccati.",
    ],
    "HEA-04": [
        "Controlla lo stato della unit e gli ultimi errori.",
        "Verifica config e dipendenze del servizio.",
        "Se critico: disabilita temporaneamente per stabilizzare.",
    ],
    "HEA-05": [
        "Salva lavoro subito: possibili errori disco/FS.",
        "Controlla SMART e log kernel/journal.",
        "Esegui fsck (se applicabile) e pianifica backup.",
    ],
}


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


def render_markdown(event: Dict[str, Any]) -> str:
    ts = datetime.fromtimestamp(int(event["ts"])).strftime("%Y-%m-%d %H:%M:%S")
    code = str(event.get("code") or "")
    sev = str(event.get("severity") or "INFO").upper()
    ent = str(event.get("entity") or "")
    msg = str(event.get("message") or "").strip()

    actions = ADVICE.get(code, [])
    if not actions:
        actions = ["(azioni consigliate: in arrivo)", "(azioni consigliate: in arrivo)", "(azioni consigliate: in arrivo)"]
    else:
        actions = (actions + ["(n/a)", "(n/a)", "(n/a)"])[:3]

    lines: List[str] = []
    lines.append(f"# ARGUS Report — {code} ({sev})")
    lines.append("")
    lines.append(f"- Time: {ts}")
    if ent:
        lines.append(f"- Entity: {ent}")
    lines.append("")
    lines.append("## Cosa è successo")
    lines.append(msg if msg else "(n/a)")
    lines.append("")
    lines.append("## Cosa fare ora")
    lines.append(f"1) {actions[0]}")
    lines.append(f"2) {actions[1]}")
    lines.append(f"3) {actions[2]}")
    lines.append("")
    lines.append("## Dettagli")
    lines.append(f"- event_id: {event.get('id')}")
    lines.append(f"- code: {code}")
    lines.append(f"- severity: {sev}")
    lines.append("")
    lines.append("## Evidenze")
    lines.append("- (max 5 righe: in v1 le aggiungiamo quando centralizziamo collectors/engine)")
    lines.append("")
    return "\n".join(lines)


def write_report(event: Dict[str, Any]) -> Tuple[str, str]:
    """
    Crea report MD + JSON. Ritorna (md_path, json_path).
    """
    rep_dir = _reports_dir()
    ts = datetime.fromtimestamp(int(event["ts"])).strftime("%Y-%m-%d_%H%M%S")
    code = _safe(str(event.get("code") or "EVT"))
    eid = int(event.get("id") or 0)

    md_path = rep_dir / f"report_{ts}_{code}_{eid}.md"
    js_path = rep_dir / f"report_{ts}_{code}_{eid}.json"

    md = render_markdown(event)
    md_path.write_text(md, encoding="utf-8")

    payload = {
        "id": eid,
        "ts": int(event["ts"]),
        "code": str(event.get("code") or ""),
        "severity": str(event.get("severity") or ""),
        "message": str(event.get("message") or ""),
        "entity": str(event.get("entity") or ""),
        "details_json": str(event.get("details_json") or ""),
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "actions": ADVICE.get(str(event.get("code") or ""), []),
    }
    js_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    return str(md_path), str(js_path)
