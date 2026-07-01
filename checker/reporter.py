"""Output formatting for the CLI. The web dashboard uses its own JSON
responses directly (see dashboard/routes.py) — this module is CLI-only.
"""
import csv
import io
import json
from typing import Any, Dict, List, Optional

RISK_ANSI = {
    "HIGH": "\033[91m",     # red
    "MEDIUM": "\033[93m",   # yellow
    "LOW": "\033[92m",      # green
    "UNKNOWN": "\033[90m",  # grey
}
RESET_ANSI = "\033[0m"


def report(results: List[Dict[str, Any]], fmt: str = "table", outfile: Optional[str] = None) -> None:
    if fmt == "json":
        text = json.dumps(results, indent=2)
    elif fmt == "csv":
        text = _to_csv(results)
    else:
        text = _to_table(results)

    if outfile:
        with open(outfile, "w") as fh:
            fh.write(text + "\n")
    else:
        print(text)


def _to_table(results: List[Dict[str, Any]]) -> str:
    header = f"{'IP':<20}{'RISK':<10}SOURCES"
    lines = [header, "-" * len(header)]

    for result in results:
        if not result.get("valid", True):
            lines.append(f"{result['ip']:<20}{'INVALID':<10}{result.get('error', '')}")
            continue

        risk = result["overall_risk"]
        color = RISK_ANSI.get(risk, "")
        source_summary = ", ".join(f"{s['source']}:{s['risk']}" for s in result["sources"])
        lines.append(f"{result['ip']:<20}{color}{risk:<10}{RESET_ANSI}{source_summary}")

    return "\n".join(lines)


def _to_csv(results: List[Dict[str, Any]]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ip", "valid", "overall_risk", "source_details", "error"])

    for result in results:
        if not result.get("valid", True):
            writer.writerow([result["ip"], False, "", "", result.get("error", "")])
            continue

        source_summary = "; ".join(f"{s['source']}:{s['risk']}" for s in result["sources"])
        writer.writerow([result["ip"], True, result["overall_risk"], source_summary, ""])

    return buf.getvalue()
