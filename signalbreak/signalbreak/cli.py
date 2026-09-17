from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .extract import analyze_file
from .lineage import analyze_cluster, cluster
from .models import SampleEvidence
from .report import render_html
from .yara import scan_yara

console = Console()


def _load_samples(root: Path) -> list[SampleEvidence]:
    files = sorted(p for p in root.rglob("*") if p.is_file() and not p.name.startswith("."))
    samples: list[SampleEvidence] = []
    for path in files:
        if path.suffix.lower() in {".json", ".yara", ".yar", ".md", ".txt"}:
            continue
        try:
            samples.append(analyze_file(path))
        except OSError as exc:
            console.print(f"[yellow]skip[/yellow] {path}: {exc}")
    return samples


def _load_snapshots(root: Path) -> list[SampleEvidence]:
    return [SampleEvidence.from_dict(json.loads(p.read_text(encoding="utf-8"))) for p in sorted(root.rglob("*.snapshot.json"))]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SignalBreak — static detection-resilience analysis")
    parser.add_argument("path", type=Path, help="Directory containing samples or *.snapshot.json fixtures")
    parser.add_argument("--out", type=Path, default=Path("signalbreak-report.html"), help="HTML report path")
    parser.add_argument("--json", dest="json_out", type=Path, help="Optional JSON results path")
    parser.add_argument("--rules", type=Path, help="Optional directory of YARA rules")
    parser.add_argument("--threshold", type=float, default=0.62, help="Lineage similarity threshold (default: 0.62)")
    parser.add_argument("--snapshots", action="store_true", help="Read safe static-evidence snapshots instead of files")
    args = parser.parse_args(argv)

    if not args.path.exists():
        console.print(f"[red]error[/red] path does not exist: {args.path}")
        return 2

    samples = _load_snapshots(args.path) if args.snapshots else _load_samples(args.path)
    if not samples:
        console.print("[red]No analyzable samples found.[/red]")
        return 1

    if args.rules:
        hits, yara_strings = scan_yara(samples, args.rules)
        for sample in samples:
            sample.yara_rules |= hits.get(sample.sha256, set())
            sample.yara_strings |= yara_strings.get(sample.sha256, set())

    groups = cluster(samples, threshold=args.threshold)
    analyses = [analyze_cluster(group, f"L{i:02d}") for i, group in enumerate(groups, 1)]

    table = Table(title="SignalBreak lineages")
    table.add_column("Lineage")
    table.add_column("Samples", justify="right")
    table.add_column("Signal Persistence Index", justify="right")
    table.add_column("Stable anchors")
    for item in analyses:
        table.add_row(item.cluster_id, str(len(item.samples)), f"{item.signal_persistence * 100:.0f}%", ", ".join(item.anchors) or "—")
    console.print(table)

    render_html(samples, analyses, args.out)
    console.print(f"[green]report[/green] {args.out}")

    if args.json_out:
        payload = {
            "samples": [s.to_dict() for s in samples],
            "lineages": [
                {
                    "id": a.cluster_id,
                    "sample_count": len(a.samples),
                    "signal_persistence": a.signal_persistence,
                    "anchors": a.anchors,
                    "churn": a.churn,
                    "metrics": [{"category": m.category, "stability": m.stability, "interpretation": m.interpretation} for m in a.metrics],
                    "notes": a.notes,
                }
                for a in analyses
            ],
        }
        args.json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"[green]json[/green] {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
