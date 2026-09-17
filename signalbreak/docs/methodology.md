# Methodology

SignalBreak is a research-oriented measurement tool, not a malware classifier. The goal is to quantify **static evidence drift** inside groups of related samples.

## 1. Static evidence model

Each sample becomes a `SampleEvidence` record containing:

- capabilities inferred from selected Windows APIs and static string patterns
- imported APIs
- IOCs
- extracted strings
- PE section metadata and permissions
- whole-file Shannon entropy
- optional YARA rule hits

Cryptographic hashes are retained for identity, but they are intentionally excluded from similarity because a changed hash tells us almost nothing about lineage.

## 2. Pairwise similarity

SignalBreak computes a weighted similarity score:

```text
32% capability similarity
28% import similarity
16% section/permission similarity
10% entropy proximity
 8% IOC similarity
 6% string similarity
```

The idea is deliberate: behavior-like structural evidence gets more weight than strings, because strings are cheap to change and can produce noisy relationships.

The default lineage threshold is `0.62`. Samples connected above the threshold are grouped into a lineage component.

## 3. Evidence stability

For each lineage and evidence category, SignalBreak computes the mean pairwise Jaccard similarity.

```text
stability(A) = mean(Jaccard(sample_i, sample_j))
```

A high value means the category is conserved across the observed lineage. A low value means the category churns heavily.

The thresholds used for interpretation are:

- `>= 0.80`: stable across the cluster
- `0.50–0.79`: partially conserved
- `< 0.50`: high-churn evidence

These are engineering heuristics, not statistical confidence intervals.

## 4. Signal Persistence Index

The **Signal Persistence Index** is the average stability of the non-hash evidence categories:

```text
SPI = mean(capabilities, imports, sections, IOCs, strings stability)
```

This is a compact dashboard metric, not a probability and not an actual time-based half-life. A lineage with a low SPI is exhibiting more static evidence drift in the observed corpus.

## 5. Safety boundary

SignalBreak does not generate altered malware samples or attempt to discover a smallest modification that bypasses a detector. It measures observed drift in samples provided by the analyst.

That boundary is intentional: the useful defensive question is **which evidence remains reliable as a family changes**, without turning the project into an evasion generator.

## 6. What this does not prove

A static similarity relationship does not prove a shared malware author, campaign, family, or behavior. Likewise, a stable import does not prove that the function was actually reached at runtime.

SignalBreak should therefore be used as an analyst-assistance and detection-review tool, with conclusions validated using additional evidence when available.
