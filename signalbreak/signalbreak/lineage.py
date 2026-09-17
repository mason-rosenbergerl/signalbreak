from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
from typing import Iterable

from .models import SampleEvidence


def jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    union = a | b
    return len(a & b) / len(union) if union else 1.0


def section_profile(sample: SampleEvidence) -> set[str]:
    return {f"{s.name}:{s.executable}:{s.writable}" for s in sample.sections}


def similarity(a: SampleEvidence, b: SampleEvidence) -> float:
    """Weighted similarity emphasizing behavior-like evidence over names/hashes."""
    import_sim = jaccard(a.imports, b.imports)
    cap_sim = jaccard(a.capabilities, b.capabilities)
    section_sim = jaccard(section_profile(a), section_profile(b))
    ioc_sim = jaccard(a.iocs, b.iocs)
    entropy_sim = max(0.0, 1.0 - abs(a.overall_entropy - b.overall_entropy) / 8.0)
    # Strings are deliberately low weight because they churn easily under obfuscation.
    string_sim = jaccard(a.strings, b.strings)
    return (
        0.32 * cap_sim
        + 0.28 * import_sim
        + 0.16 * section_sim
        + 0.10 * entropy_sim
        + 0.08 * ioc_sim
        + 0.06 * string_sim
    )


def cluster(samples: list[SampleEvidence], threshold: float = 0.62) -> list[list[SampleEvidence]]:
    if not samples:
        return []
    graph: dict[int, set[int]] = {i: set() for i in range(len(samples))}
    for i, j in combinations(range(len(samples)), 2):
        if similarity(samples[i], samples[j]) >= threshold:
            graph[i].add(j)
            graph[j].add(i)
    clusters: list[list[SampleEvidence]] = []
    unseen = set(graph)
    while unseen:
        root = unseen.pop()
        stack = [root]
        members = [root]
        while stack:
            cur = stack.pop()
            for nxt in graph[cur]:
                if nxt in unseen:
                    unseen.remove(nxt)
                    stack.append(nxt)
                    members.append(nxt)
        clusters.append([samples[i] for i in members])
    return sorted(clusters, key=lambda c: (-len(c), c[0].sha256))


@dataclass(slots=True)
class DriftMetric:
    category: str
    stability: float
    interpretation: str


@dataclass(slots=True)
class ClusterAnalysis:
    cluster_id: str
    samples: list[SampleEvidence]
    metrics: list[DriftMetric]
    anchors: list[str]
    churn: list[str]
    notes: list[str]

    @property
    def signal_persistence(self) -> float:
        # A practical proxy: median pairwise stability across evidence categories.
        stable = [m.stability for m in self.metrics if m.category != "hash"]
        return sum(stable) / len(stable) if stable else 0.0


def analyze_cluster(samples: list[SampleEvidence], cluster_id: str) -> ClusterAnalysis:
    categories: dict[str, list[set[str]]] = {
        "capabilities": [s.capabilities for s in samples],
        "imports": [s.imports for s in samples],
        "sections": [section_profile(s) for s in samples],
        "iocs": [s.iocs for s in samples],
        "strings": [s.strings for s in samples],
    }
    metrics: list[DriftMetric] = []
    for category, values in categories.items():
        if len(values) == 1:
            stability = 1.0
        else:
            pair_scores = [jaccard(a, b) for a, b in combinations(values, 2)]
            stability = sum(pair_scores) / len(pair_scores)
        if stability >= 0.80:
            meaning = "stable across the cluster"
        elif stability >= 0.50:
            meaning = "partially conserved; useful with corroboration"
        else:
            meaning = "high-churn evidence; weak as a family anchor"
        metrics.append(DriftMetric(category, stability, meaning))

    anchors: list[str] = []
    churn: list[str] = []
    for metric in metrics:
        if metric.stability >= 0.75:
            anchors.append(metric.category)
        elif metric.stability < 0.45:
            churn.append(metric.category)

    notes: list[str] = []
    if "strings" in churn:
        notes.append("String evidence changes heavily; static string signatures are likely to age quickly across variants.")
    if "imports" in anchors:
        notes.append("Import evidence is comparatively stable and can provide durable capability anchors.")
    if "capabilities" in anchors:
        notes.append("Capability categories remain consistent across the lineage, suggesting behavior-level continuity.")
    if len(samples) >= 3:
        notes.append("The cluster is large enough to observe drift rather than treating one sample as representative.")

    return ClusterAnalysis(cluster_id, samples, metrics, anchors, churn, notes)
