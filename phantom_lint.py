#!/usr/bin/env python3
"""
Phantom-Lint: Static analysis scanner for Trojan Source (CVE-2021-42574),
mixed-script homographs, and invisible Unicode prompt-injection smuggling.
"""

import argparse
import json
import os
import re
import sys
import unicodedata
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set


BIDI_CODEPOINTS: Dict[int, str] = {
    0x061C: "ARABIC LETTER MARK",
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
}

ZERO_WIDTH_CODEPOINTS: Dict[int, str] = {
    0x034F: "COMBINING GRAPHEME JOINER",
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
    0x3164: "HANGUL FILLER",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE",
    0xFFA0: "HALFWIDTH HANGUL FILLER",
}

DEFAULT_EXCLUDED_DIRS: Set[str] = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
}

TOKEN_PATTERN = re.compile(r"\b\w+\b", re.UNICODE)


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    file_path: str
    line: int
    column: int
    description: str
    decoded_payload: Optional[str] = None


def identify_script(char: str) -> str:
    """Return the broad Unicode script family for an alphabetic character."""
    try:
        name = unicodedata.name(char)
    except ValueError:
        return "UNKNOWN"

    for script in ("LATIN", "CYRILLIC", "GREEK", "ARABIC", "HEBREW"):
        if script in name:
            return script
    return "OTHER"


def scan_line(line_text: str, line_number: int, file_path: str) -> List[Finding]:
    """Inspect a single line of text for all supported Unicode threat classes."""
    findings: List[Finding] = []
    tag_buffer: List[str] = []
    tag_start_col: Optional[int] = None

    for idx, char in enumerate(line_text, start=1):
        cp = ord(char)

        # Check for Unicode Tag Block smuggling (U+E0000 to U+E007F)
        if 0xE0000 <= cp <= 0xE007F:
            if tag_start_col is None:
                tag_start_col = idx
            if 0xE0020 <= cp <= 0xE007E:
                tag_buffer.append(chr(cp - 0xE0000))
            else:
                tag_buffer.append("?")
            continue
        elif tag_start_col is not None:
            decoded = "".join(tag_buffer)
            findings.append(
                Finding(
                    rule_id="THREAT-02",
                    category="UNICODE_TAG_SMUGGLING",
                    severity="CRITICAL",
                    file_path=file_path,
                    line=line_number,
                    column=tag_start_col,
                    description=(
                        f"Invisible Unicode Tag block sequence detected "
                        f"({len(tag_buffer)} codepoints)."
                    ),
                    decoded_payload=decoded,
                )
            )
            tag_buffer.clear()
            tag_start_col = None

        # Check for Trojan Source Bidirectional Overrides
        if cp in BIDI_CODEPOINTS:
            findings.append(
                Finding(
                    rule_id="THREAT-01",
                    category="BIDI_OVERRIDE",
                    severity="HIGH",
                    file_path=file_path,
                    line=line_number,
                    column=idx,
                    description=(
                        f"Bidirectional control character U+{cp:04X} "
                        f"({BIDI_CODEPOINTS[cp]}) detected."
                    ),
                )
            )

        # Check for Zero-Width characters (allow BOM at line 1, col 1)
        elif cp in ZERO_WIDTH_CODEPOINTS:
            if cp == 0xFEFF and line_number == 1 and idx == 1:
                continue
            findings.append(
                Finding(
                    rule_id="THREAT-02",
                    category="ZERO_WIDTH_CHARACTER",
                    severity="MEDIUM",
                    file_path=file_path,
                    line=line_number,
                    column=idx,
                    description=(
                        f"Invisible character U+{cp:04X} "
                        f"({ZERO_WIDTH_CODEPOINTS[cp]}) detected."
                    ),
                )
            )

        # Check for Variation Selectors Supplement (U+E0100 to U+E01EF)
        elif 0xE0100 <= cp <= 0xE01EF:
            findings.append(
                Finding(
                    rule_id="THREAT-02",
                    category="VARIATION_SELECTOR_SMUGGLING",
                    severity="HIGH",
                    file_path=file_path,
                    line=line_number,
                    column=idx,
                    description=(
                        f"Supplementary variation selector U+{cp:04X} "
                        f"detected (potential byte smuggling)."
                    ),
                )
            )

    # Flush trailing Unicode Tag buffer if line ended with tag characters
    if tag_start_col is not None:
        decoded = "".join(tag_buffer)
        findings.append(
            Finding(
                rule_id="THREAT-02",
                category="UNICODE_TAG_SMUGGLING",
                severity="CRITICAL",
                file_path=file_path,
                line=line_number,
                column=tag_start_col,
                description=(
                    f"Invisible Unicode Tag block sequence detected "
                    f"({len(tag_buffer)} codepoints)."
                ),
                decoded_payload=decoded,
            )
        )

    # Check tokens for mixed-script homographs (e.g., Latin + Cyrillic)
    for match in TOKEN_PATTERN.finditer(line_text):
        token = match.group(0)
        if token.isascii():
            continue

        scripts: Set[str] = set()
        for ch in token:
            if ch.isalpha():
                script = identify_script(ch)
                if script in ("LATIN", "CYRILLIC", "GREEK"):
                    scripts.add(script)

        if "LATIN" in scripts and len(scripts) >= 2:
            sorted_scripts = ", ".join(sorted(scripts))
            findings.append(
                Finding(
                    rule_id="THREAT-03",
                    category="MIXED_SCRIPT_HOMOGRAPH",
                    severity="HIGH",
                    file_path=file_path,
                    line=line_number,
                    column=match.start() + 1,
                    description=(
                        f"Token '{token}' mixes scripts: {sorted_scripts}."
                    ),
                )
            )

    return findings


def scan_text(content: str, file_path: str = "<memory>") -> List[Finding]:
    """Scan a complete multi-line string and return all security findings."""
    findings: List[Finding] = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        findings.extend(scan_line(line, line_num, file_path))
    return findings


def is_binary_file(path: Path) -> bool:
    """Heuristic check to skip binary files containing null bytes."""
    try:
        with path.open("rb") as handle:
            chunk = handle.read(2048)
            return b"\x00" in chunk
    except OSError:
        return True


def iter_target_files(root_path: Path) -> Iterable[Path]:
    """Yield non-binary files from a file or directory path."""
    if root_path.is_file():
        if not is_binary_file(root_path):
            yield root_path
        return

    for root, dirs, files in os.walk(root_path):
        dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDED_DIRS]
        for file_name in sorted(files):
            candidate = Path(root) / file_name
            if not is_binary_file(candidate):
                yield candidate


def scan_path(target: Path) -> List[Finding]:
    """Scan a file or directory recursively."""
    all_findings: List[Finding] = []
    for file_path in iter_target_files(target):
        try:
            text = file_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        all_findings.extend(scan_text(text, str(file_path)))
    return all_findings


def format_text_report(findings: List[Finding]) -> str:
    """Render findings as a human-readable CLI report."""
    if not findings:
        return "Scan complete. Zero suspicious Unicode patterns detected."

    lines: List[str] = []
    affected_files: Set[str] = set()

    for item in findings:
        affected_files.add(item.file_path)
        lines.append(
            f"[{item.severity}] {item.rule_id} ({item.category}) "
            f"at {item.file_path}:{item.line}:{item.column}"
        )
        lines.append(f"  Description : {item.description}")
        if item.decoded_payload:
            lines.append(f"  Decoded Text: \"{item.decoded_payload}\"")
        lines.append("")

    lines.append(
        f"Scan complete. Findings: {len(findings)} "
        f"across {len(affected_files)} file(s)."
    )
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Phantom-Lint: Detect Trojan Source overrides, homographs, "
            "and invisible Unicode prompt injections."
        )
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="File or directory path to scan (default: current directory).",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text).",
    )
    args = parser.parse_args(argv)

    target_path = Path(args.target)
    if not target_path.exists():
        print(f"Error: Target path '{args.target}' does not exist.", file=sys.stderr)
        return 2

    findings = scan_path(target_path)

    if args.format == "json":
        payload = {
            "total_findings": len(findings),
            "findings": [asdict(f) for f in findings],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(format_text_report(findings))

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
