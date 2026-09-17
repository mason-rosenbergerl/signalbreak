from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class SectionEvidence:
    name: str
    virtual_size: int = 0
    raw_size: int = 0
    entropy: float = 0.0
    executable: bool = False
    writable: bool = False

    @property
    def size_ratio(self) -> float:
        if self.raw_size == 0:
            return 0.0
        return self.virtual_size / self.raw_size


@dataclass(slots=True)
class SampleEvidence:
    path: str
    sha256: str
    file_size: int
    file_type: str = "unknown"
    overall_entropy: float = 0.0
    imports: set[str] = field(default_factory=set)
    capabilities: set[str] = field(default_factory=set)
    iocs: set[str] = field(default_factory=set)
    strings: set[str] = field(default_factory=set)
    sections: list[SectionEvidence] = field(default_factory=list)
    yara_rules: set[str] = field(default_factory=set)
    yara_strings: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["imports"] = sorted(self.imports)
        out["capabilities"] = sorted(self.capabilities)
        out["iocs"] = sorted(self.iocs)
        out["strings"] = sorted(self.strings)
        out["yara_rules"] = sorted(self.yara_rules)
        out["yara_strings"] = sorted(self.yara_strings)
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SampleEvidence":
        sections = [SectionEvidence(**s) for s in data.get("sections", [])]
        return cls(
            path=str(data["path"]),
            sha256=str(data["sha256"]),
            file_size=int(data.get("file_size", 0)),
            file_type=str(data.get("file_type", "snapshot")),
            overall_entropy=float(data.get("overall_entropy", 0.0)),
            imports=set(data.get("imports", [])),
            capabilities=set(data.get("capabilities", [])),
            iocs=set(data.get("iocs", [])),
            strings=set(data.get("strings", [])),
            sections=sections,
            yara_rules=set(data.get("yara_rules", [])),
            yara_strings=set(data.get("yara_strings", [])),
            metadata=dict(data.get("metadata", {})),
        )
