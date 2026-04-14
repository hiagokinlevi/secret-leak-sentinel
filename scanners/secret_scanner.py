import os
import re
import json
import math
from typing import List, Dict

# Basic curated regex patterns
REGEX_DETECTORS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "generic_api_key": re.compile(r"(?i)(api[_-]?key|token|secret)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?"),
    "private_key": re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
}

ENTROPY_THRESHOLD = 4.5
MIN_ENTROPY_LENGTH = 20


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0

    entropy = 0.0
    length = len(data)

    for x in set(data):
        p_x = data.count(x) / length
        entropy -= p_x * math.log2(p_x)

    return entropy


def extract_strings(line: str) -> List[str]:
    return re.findall(r"[A-Za-z0-9+/=_\-]{20,}", line)


def detect_regex(line: str) -> List[Dict]:
    findings = []

    for name, pattern in REGEX_DETECTORS.items():
        if pattern.search(line):
            findings.append({
                "detector": f"regex:{name}",
                "confidence": 0.9
            })

    return findings


def detect_entropy(line: str) -> List[Dict]:
    findings = []

    for token in extract_strings(line):
        if len(token) < MIN_ENTROPY_LENGTH:
            continue

        entropy = shannon_entropy(token)
        if entropy >= ENTROPY_THRESHOLD:
            findings.append({
                "detector": "entropy",
                "confidence": min(1.0, entropy / 6.0)
            })

    return findings


def scan_file(path: str) -> List[Dict]:
    findings = []

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f, start=1):
                detectors = []
                detectors.extend(detect_regex(line))
                detectors.extend(detect_entropy(line))

                for d in detectors:
                    findings.append({
                        "file": path,
                        "line": i,
                        "detector": d["detector"],
                        "confidence": round(d["confidence"], 3)
                    })
    except Exception:
        pass

    return findings


def scan_path(root_path: str) -> List[Dict]:
    results = []

    for root, dirs, files in os.walk(root_path):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "venv", ".venv"}]

        for file in files:
            full_path = os.path.join(root, file)
            results.extend(scan_file(full_path))

    return results


def scan_path_json(root_path: str) -> str:
    return json.dumps(scan_path(root_path), indent=2)
