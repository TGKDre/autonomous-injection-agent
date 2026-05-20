#!/usr/bin/env python3
"""
run_attacker.py -- Autonomous Red-Team Agent
============================================
Launches AutonomousAttackerAgent against a sandboxed target and writes
timestamped JSON + Markdown reports to reports/.

Usage:
    python run_attacker.py --target http://localhost:5050
                           --model anthropic/claude-haiku-4-5-20251001
                           [--turns 20]
"""

import argparse
import json
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="http://localhost:5050")
    p.add_argument("--model", default="anthropic/claude-haiku-4-5-20251001")
    p.add_argument("--turns", type=int, default=20)
    p.add_argument("--output", default="reports")
    return p.parse_args()


def main():
    args = parse_args()
    provider, model = (
        args.model.split("/", 1) if "/" in args.model
        else ("anthropic", args.model)
    )

    console.print(Panel(
        f"[bold]{args.model}[/bold]  target: {args.target}",
        title="Autonomous Red-Team Agent", border_style="red"
    ))

    import agents.attacker_agent as aa
    aa.MAX_TURNS = args.turns
    from agents.attacker_agent import AutonomousAttackerAgent

    agent = AutonomousAttackerAgent(args.target, provider=provider, model=model)
    console.print(f"  [yellow]->[/yellow] Launching assessment, max turns: {args.turns}\n")
    result = agent.run()

    findings = result.get("findings", [])
    summary = result.get("summary", {})
    compromises = [f for f in findings if f.get("compromised")]

    table = Table(title="Results", box=box.HEAVY_HEAD, show_lines=True)
    for col in ["Surface", "Category", "Payload (trunc)", "Outcome", "Signals"]:
        table.add_column(col, min_width=12)
    for f in findings[-25:]:
        comp = "[red]COMP[/red]" if f.get("compromised") else "[green]SAFE[/green]"
        pl = f.get("payload", "")[:50]
        table.add_row(
            f.get("surface", ""), f.get("category", ""), pl, comp,
            ", ".join(f.get("signals", []))[:40]
        )
    console.print(table)
    console.print(Panel(
        f"Turns: {result['turns']}  |  "
        f"Payloads: {summary.get('payloads_sent', len(findings))}  |  "
        f"Compromises: {summary.get('compromises', len(compromises))}  |  "
        f"CSR: {summary.get('csr', 0)}%",
        title="Summary", border_style="yellow"
    ))

    Path(args.output).mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    slug = args.model.replace("/", "_").replace("-", "_")
    json_path = f"{args.output}/attack_{slug}_{ts}.json"
    md_path = f"{args.output}/attack_{slug}_{ts}.md"

    with open(json_path, "w") as fh:
        json.dump(result, fh, indent=2)

    md = f"""# Attack Report: {result['model']}
**Target:** {result['target']}  **Run ID:** {result['run_id']}  
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}

## Summary
| Metric | Value |
|---|---|
| Turns | {result['turns']} |
| Payloads Sent | {summary.get('payloads_sent', len(findings))} |
| Compromises | {summary.get('compromises', len(compromises))} |
| CSR | {summary.get('csr', 0)}% |

## Findings
| Surface | Category | Outcome | Signals |
|---|---|---|---|
"""
    for f in findings:
        out = "COMP" if f.get("compromised") else "SAFE"
        md += (f"| `{f.get('surface','')}` | {f.get('category','')} "
               f"| {out} | {', '.join(f.get('signals',[]))[:60]} |\n")

    with open(md_path, "w") as fh:
        fh.write(md)

    console.print(f"  JSON: {json_path}")
    console.print(f"  MD:   {md_path}")


if __name__ == "__main__":
    main()
