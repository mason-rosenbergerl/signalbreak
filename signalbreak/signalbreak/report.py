from __future__ import annotations

import html
import json
from pathlib import Path

from .lineage import ClusterAnalysis
from .models import SampleEvidence


def _pct(x: float) -> str:
    return f"{x * 100:.0f}%"


def render_html(samples: list[SampleEvidence], analyses: list[ClusterAnalysis], out: Path) -> None:
    total = len(samples)
    clusters = len(analyses)
    avg = sum(a.signal_persistence for a in analyses) / clusters if clusters else 0.0
    cards = []
    for analysis in analyses:
        rows = "".join(
            f"<tr><td>{html.escape(m.category)}</td><td><b>{_pct(m.stability)}</b></td><td>{html.escape(m.interpretation)}</td></tr>"
            for m in analysis.metrics
        )
        sample_rows = "".join(
            f"<tr><td>{html.escape(Path(s.path).name)}</td><td><code>{s.sha256[:12]}</code></td><td>{html.escape(', '.join(sorted(s.capabilities)) or '—')}</td><td>{len(s.yara_rules)}</td></tr>"
            for s in analysis.samples
        )
        notes = "".join(f"<li>{html.escape(n)}</li>" for n in analysis.notes)
        cards.append(
            f"""
            <section class='cluster'>
              <div class='cluster-head'><div><span class='eyebrow'>LINEAGE {html.escape(analysis.cluster_id)}</span><h2>{len(analysis.samples)} related samples</h2></div><div class='metric-pill'>Signal Persistence Index <strong>{_pct(analysis.signal_persistence)}</strong></div></div>
              <div class='grid'>
                <div class='panel'><h3>Evidence stability</h3><table><thead><tr><th>Evidence</th><th>Stability</th><th>Meaning</th></tr></thead><tbody>{rows}</tbody></table></div>
                <div class='panel'><h3>What survives?</h3><div class='chips'>{''.join(f'<span>{html.escape(x)}</span>' for x in analysis.anchors) or '<span class="muted">No strong anchors</span>'}</div><h3 class='sub'>What churns?</h3><div class='chips warn'>{''.join(f'<span>{html.escape(x)}</span>' for x in analysis.churn) or '<span class="muted">Low observed churn</span>'}</div><ul>{notes}</ul></div>
              </div>
              <div class='panel'><h3>Sample lineage</h3><table><thead><tr><th>File</th><th>SHA-256</th><th>Capabilities</th><th>YARA hits</th></tr></thead><tbody>{sample_rows}</tbody></table></div>
            </section>
            """
        )

    payload = json.dumps([s.to_dict() for s in samples], indent=2)
    doc = f"""<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>SignalBreak Detection Resilience Report</title>
<style>
:root {{ --bg:#081018; --panel:#0f1a25; --line:#203242; --text:#e7eef5; --muted:#91a2b3; --accent:#68d7c2; --warn:#f3b56a; }}
* {{ box-sizing:border-box }} body {{ margin:0; background:radial-gradient(circle at top left,#122538 0,#081018 42%); color:var(--text); font:14px/1.5 Inter,ui-sans-serif,system-ui,sans-serif; }}
main {{ max-width:1200px; margin:0 auto; padding:48px 24px 80px; }}
.kicker,.eyebrow {{ color:var(--accent); text-transform:uppercase; letter-spacing:.14em; font-weight:700; font-size:11px; }}
h1 {{ font-size:44px; line-height:1.05; max-width:780px; margin:10px 0 12px; }}
.lede {{ color:var(--muted); max-width:820px; font-size:17px; }}
.stats {{ display:grid; grid-template-columns:repeat(3,1fr); gap:14px; margin:30px 0 44px; }}
.stat,.panel,.cluster {{ background:rgba(15,26,37,.86); border:1px solid var(--line); border-radius:16px; box-shadow:0 12px 45px rgba(0,0,0,.18); }}
.stat {{ padding:22px; }} .stat b {{ display:block; font-size:30px; margin-top:4px; }}
.cluster {{ padding:22px; margin:22px 0; }} .cluster-head {{ display:flex; justify-content:space-between; align-items:flex-start; gap:20px; }}
h2 {{ margin:6px 0 18px; font-size:28px }} h3 {{ margin:0 0 13px; font-size:15px }} .sub {{ margin-top:22px; }}
.metric-pill {{ border:1px solid var(--line); border-radius:999px; padding:10px 14px; color:var(--muted); white-space:nowrap; }} .metric-pill strong {{ color:var(--text); margin-left:6px; }}
.grid {{ display:grid; grid-template-columns:1.35fr .9fr; gap:14px; margin-bottom:14px; }} .panel {{ padding:18px; }}
table {{ width:100%; border-collapse:collapse; }} th,td {{ text-align:left; padding:11px 10px; border-bottom:1px solid var(--line); vertical-align:top; }} th {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.08em; }} code {{ color:var(--accent); }}
.chips {{ display:flex; flex-wrap:wrap; gap:7px; }} .chips span {{ border:1px solid #2b6c63; border-radius:999px; padding:6px 9px; color:#b7f6eb; background:#0c2724; }} .chips.warn span {{ border-color:#74562d; color:#ffd99f; background:#281d0d; }} .muted {{ color:var(--muted)!important; border-color:var(--line)!important; background:transparent!important; }} li {{ margin:8px 0; color:var(--muted); }}
.footer {{ color:var(--muted); font-size:12px; margin-top:30px; }}
@media(max-width:800px) {{ .stats,.grid {{ grid-template-columns:1fr; }} .cluster-head {{ flex-direction:column; }} h1 {{ font-size:36px; }} }}
</style></head>
<body><main>
<div class='kicker'>Static detection engineering</div><h1>SignalBreak</h1>
<p class='lede'>A static detection-resilience report: related samples are compared as a lineage so analysts can see which evidence survives variant drift—and which detection signals age out.</p>
<div class='stats'><div class='stat'><span class='eyebrow'>Samples</span><b>{total}</b></div><div class='stat'><span class='eyebrow'>Lineages</span><b>{clusters}</b></div><div class='stat'><span class='eyebrow'>Avg. Signal Persistence Index</span><b>{_pct(avg)}</b></div></div>
{''.join(cards)}
<p class='footer'>Generated by SignalBreak. Analysis is static-only; no sample was executed or modified.</p>
<script type='application/json' id='signalbreak-data'>{html.escape(payload)}</script>
</main></body></html>"""
    out.write_text(doc, encoding="utf-8")
