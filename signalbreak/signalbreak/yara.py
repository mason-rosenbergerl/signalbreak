from __future__ import annotations

from pathlib import Path

from .models import SampleEvidence


def scan_yara(samples: list[SampleEvidence], rule_dir: Path) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Optional YARA enrichment. Returns rule hits and matched string identifiers by SHA-256."""
    try:
        import yara
    except ImportError:
        return {}, {}

    files = sorted(rule_dir.glob("*.yar")) + sorted(rule_dir.glob("*.yara"))
    if not files:
        return {}, {}
    source = "\n".join(f.read_text(encoding="utf-8") for f in files)
    try:
        rules = yara.compile(source=source)
    except yara.Error:
        return {}, {}

    hits: dict[str, set[str]] = {}
    strings: dict[str, set[str]] = {}
    for sample in samples:
        try:
            matches = rules.match(sample.path)
        except Exception:
            continue
        hit_names = {m.rule for m in matches}
        ids = set()
        for match in matches:
            for item in getattr(match, "strings", []):
                # yara-python versions differ: newer versions return StringMatch objects;
                # older versions can return tuples. Support both shapes.
                ident = getattr(item, "identifier", None)
                if ident is None and isinstance(item, tuple) and len(item) >= 2:
                    ident = item[1]
                if ident:
                    ids.add(str(ident))
        if hit_names:
            hits[sample.sha256] = hit_names
        if ids:
            strings[sample.sha256] = ids
    return hits, strings
