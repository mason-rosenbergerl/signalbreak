from signalbreak.lineage import analyze_cluster, jaccard, similarity
from signalbreak.models import SampleEvidence


def sample(name, caps, imports, strings):
    return SampleEvidence(
        path=name, sha256=name, file_size=1000, file_type="snapshot",
        overall_entropy=7.0, capabilities=set(caps), imports=set(imports),
        strings=set(strings), iocs=set(), sections=[],
    )


def test_jaccard():
    assert jaccard({"a", "b"}, {"b", "c"}) == 1 / 3


def test_related_samples_score_high():
    a = sample("a", ["network", "process"], ["WinHttpOpen", "VirtualAlloc"], ["powershell"])
    b = sample("b", ["network", "process"], ["WinHttpOpen", "VirtualAlloc"], ["different"])
    assert similarity(a, b) > 0.70


def test_cluster_marks_strings_as_churn():
    samples = [
        sample("a", ["network", "process"], ["WinHttpOpen"], ["alpha"]),
        sample("b", ["network", "process"], ["WinHttpOpen"], ["bravo"]),
        sample("c", ["network", "process"], ["WinHttpOpen"], ["charlie"]),
    ]
    result = analyze_cluster(samples, "L01")
    assert "capabilities" in result.anchors
    assert "imports" in result.anchors
    assert "strings" in result.churn
    assert result.signal_persistence > 0.70
