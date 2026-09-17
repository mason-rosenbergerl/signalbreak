from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path

from .models import SampleEvidence, SectionEvidence

try:
    import pefile
except ImportError:  # pragma: no cover
    pefile = None

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
PS_RE = re.compile(r"\bpowershell(?:\.exe)?\b|\bIEX\b|FromBase64String|EncodedCommand", re.I)
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")
WIN_IMPORT_CAPS = {
    "VirtualAlloc": "memory-allocation",
    "VirtualProtect": "memory-protection",
    "WriteProcessMemory": "process-injection",
    "CreateRemoteThread": "process-injection",
    "OpenProcess": "process-access",
    "WinExec": "process-execution",
    "CreateProcessA": "process-execution",
    "CreateProcessW": "process-execution",
    "URLDownloadToFileA": "download",
    "URLDownloadToFileW": "download",
    "WinHttpOpen": "network-communication",
    "WinHttpConnect": "network-communication",
    "InternetOpenA": "network-communication",
    "InternetOpenW": "network-communication",
    "RegSetValueExA": "registry-modification",
    "RegSetValueExW": "registry-modification",
    "CryptEncrypt": "encryption",
    "CryptDecrypt": "decryption",
}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _extract_strings(data: bytes, min_len: int = 5) -> set[str]:
    found: set[str] = set()
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    for m in ascii_re.finditer(data):
        try:
            found.add(m.group().decode("ascii", errors="ignore"))
        except UnicodeDecodeError:
            continue
    # UTF-16LE strings are common in Windows binaries.
    utf16_re = re.compile((rb"(?:[\x20-\x7e]\x00){%d,}" % min_len))
    for m in utf16_re.finditer(data):
        try:
            text = m.group().decode("utf-16le", errors="ignore")
            if text:
                found.add(text)
        except UnicodeDecodeError:
            continue
    return found


def _extract_iocs(strings: set[str]) -> set[str]:
    joined = "\n".join(strings)
    iocs = set(URL_RE.findall(joined))
    iocs |= set(IP_RE.findall(joined))
    for item in DOMAIN_RE.findall(joined):
        if not item.lower().endswith((".dll", ".exe", ".sys")):
            iocs.add(item)
    return iocs


def analyze_file(path: Path) -> SampleEvidence:
    data = path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    strings = _extract_strings(data)
    imports: set[str] = set()
    capabilities: set[str] = set()
    sections: list[SectionEvidence] = []

    if data[:2] == b"MZ":
        file_type = "PE"
    else:
        file_type = "binary"

    if file_type == "PE" and pefile is not None:
        try:
            pe = pefile.PE(data=data, fast_load=False)
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                dll = entry.dll.decode(errors="ignore") if entry.dll else "unknown"
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode(errors="ignore")
                        imports.add(f"{dll}:{name}")
                        cap = WIN_IMPORT_CAPS.get(name)
                        if cap:
                            capabilities.add(cap)
            for s in pe.sections:
                name = s.Name.rstrip(b"\x00").decode(errors="ignore") or "<unnamed>"
                sec_data = s.get_data()[: max(0, min(len(s.get_data()), 2_000_000))]
                chars = int(s.Characteristics)
                sections.append(
                    SectionEvidence(
                        name=name,
                        virtual_size=int(s.Misc_VirtualSize),
                        raw_size=int(s.SizeOfRawData),
                        entropy=shannon_entropy(sec_data),
                        executable=bool(chars & 0x20000000),
                        writable=bool(chars & 0x80000000),
                    )
                )
        except Exception as exc:
            file_type = "PE-unparsed"
            capabilities.add("pe-parse-failed")
            parse_error = str(exc)
        else:
            parse_error = ""
    else:
        parse_error = ""

    if any(PS_RE.search(s) for s in strings):
        capabilities.add("powershell")
    if any(BASE64_RE.fullmatch(s.strip()) for s in strings):
        capabilities.add("encoded-content")

    iocs = _extract_iocs(strings)
    return SampleEvidence(
        path=str(path),
        sha256=sha256,
        file_size=len(data),
        file_type=file_type,
        overall_entropy=shannon_entropy(data),
        imports=imports,
        capabilities=capabilities,
        iocs=iocs,
        strings=strings,
        sections=sections,
        metadata={"parse_error": parse_error},
    )
