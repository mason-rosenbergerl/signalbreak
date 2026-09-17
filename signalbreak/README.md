# SignalBreak

### Static detection-resilience analysis for malware variants

**SignalBreak asks a different question from a normal malware scanner:**

> **When a malware family changes, which detection signals survive—and which ones quietly age out?**

Instead of treating suspicious files as isolated objects, SignalBreak builds **static lineage hypotheses** from a folder of samples. It measures evidence stability across related samples, highlights durable anchors, and exposes high-churn evidence that is likely to be brittle for detection engineering.

It is designed as a **defender-side research and QA tool**. Samples are never executed and SignalBreak does not generate modified binaries or evasion payloads.

---

## Why I built it

Most lightweight malware projects stop at `hash → entropy → strings → imports → YARA → verdict`.

That is useful for triage, but it leaves a detection-engineering question unanswered: **what happens when the next variant arrives?**

SignalBreak treats a malware family more like a software codebase under change. Stable evidence is treated as a potential long-lived anchor; high-churn evidence is treated as a warning that a detection may age poorly.

This idea is motivated by a real defensive problem: packing, encoded content, and indicator removal are specifically used to change file signatures or hide static artifacts. MITRE ATT&CK documents these as forms of obfuscation/evasion. ([T1027.002](https://attack.mitre.org/techniques/T1045/), [T1027.005](https://attack.mitre.org/techniques/T1027/), [T1027.013](https://attack.mitre.org/techniques/T1027/013/))

---

## What makes it different

SignalBreak is **not** another malware scanner, family classifier, or automatic YARA generator.

Its main output is a **Detection Resilience Profile**:

- **Lineage hypotheses** — structurally related samples are grouped without relying on identical hashes.
- **Evidence stability** — capabilities, imports, sections, IOCs, and strings are measured for cross-variant stability.
- **Signal Persistence Index** — a 0–100 index representing how much non-hash evidence remains stable across a lineage.
- **Stable anchors** — evidence categories that persist across variants.
- **Churn warnings** — evidence categories that change so much they should not be trusted alone.
- **Optional YARA enrichment** — if YARA is installed, rules and matched identifiers are attached to each sample.
- **Analyst-ready HTML** — produces a polished standalone report suitable for a detection review or case notebook.

The project intentionally avoids executing malware and intentionally does not mutate samples to demonstrate bypasses.

---

## Example output

The included safe snapshots are synthetic and contain no executable malware.

```text
$ signalbreak fixtures --snapshots

                 SignalBreak lineages
┏━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Lineage ┃ Samples ┃ Signal Persistence Index ┃ Stable anchors        ┃
┡━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ L01     │       3 │             57% │ capabilities, imports  │
└─────────┴─────────┴────────────────┴─────────────────────────┘

report signalbreak-report.html
```

Open the generated HTML report to see the lineage dashboard.

---

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

# Analyze a directory of files
signalbreak ./samples --out report.html --json results.json

# Run the included safe demo snapshots
signalbreak ./fixtures --snapshots --out demo.html
```

### Optional YARA support

```bash
pip install -e '.[yara]'
signalbreak ./samples --rules ./rules --out report.html
```

---

## Architecture

```text
                  ┌──────────────────────────┐
                  │ Suspicious sample folder │
                  └────────────┬─────────────┘
                               │
                               ▼
                 ┌──────────────────────────┐
                 │ Static evidence extractor │
                 │ PE · imports · strings   │
                 │ entropy · IOCs · sections │
                 └────────────┬─────────────┘
                              │
                    evidence fingerprints
                              │
                              ▼
                 ┌──────────────────────────┐
                 │ Lineage graph / clustering│
                 └────────────┬─────────────┘
                              │
                              ▼
                 ┌──────────────────────────┐
                 │ Drift + resilience engine│
                 │ stability · churn ·       │
                 │ signal persistence          │
                 └────────────┬─────────────┘
                              │
                              ▼
                 ┌──────────────────────────┐
                 │ Analyst report            │
                 │ durable anchors · aging   │
                 │ signals · YARA context    │
                 └──────────────────────────┘
```

---

## Practical use in a security team

A detection engineer can use SignalBreak when several related samples arrive over time. Rather than writing a new rule from scratch for every hash, the analyst can see which static evidence remains consistent across the lineage and which evidence is changing rapidly.

That supports rule review questions such as:

- Is our current detection anchored on evidence that appears in every observed variant?
- Are strings carrying most of the similarity while imports/capabilities stay stable?
- Which categories are changing quickly enough that a signature based on them may age poorly?
- Did a newer sample introduce a capability that older detections never represented?

SignalBreak is intentionally an **analysis aid**, not a verdict engine. Human review is still required before operational detection changes.

---

## Safety model

SignalBreak is built around a static-only workflow:

- no process execution
- no sandboxing
- no network calls by the core engine
- no downloading of malware
- no binary mutation or packing tools
- safe synthetic fixtures for tests and demos

For real-world malware research, use an isolated analysis environment and follow your organization's handling procedures.

---

## Roadmap

The project is intentionally small enough to understand but structured like a real security engineering codebase. Planned work includes:

1. **Temporal lineage** — incorporate acquisition timestamps when available and visualize capability drift over time.
2. **Detection dependency analysis** — connect YARA matches to the evidence categories they depend on.
3. **Baseline-aware scoring** — compare suspicious lineages against an organization-specific benign corpus.
4. **Rule regression mode** — fail CI when a detection loses coverage across a maintained sample corpus.
5. **Evidence provenance** — record exactly which parser/rule produced every finding.

---

## Relationship to MalScan

SignalBreak is deliberately complementary to my **MalScan** static malware triage project.

MalScan answers: **“What does this individual file contain?”**

SignalBreak answers: **“What changes—and what stays stable—across the files we believe belong together?”**

Together they form a stronger static-analysis story without requiring dynamic malware execution.

---

## Author

**Mason Rosenberger**  
Cybersecurity & Global Policy — Indiana University

GitHub: [mason-rosenbergerl](https://github.com/mason-rosenbergerl)
