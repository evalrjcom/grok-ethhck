#!/usr/bin/env python3
"""
mitre_linux_analyzer.py
MITRE ATT&CK Linux Binary Analyzer & Attack Toolchain Builder

Reads Linux ELF binaries, extracts structural, import, and string indicators,
maps them to MITRE ATT&CK techniques, and builds a scored attack tool chain.

For defensive analysis, malware triage, and authorized security research.
"""

import argparse
import json
import math
import os
import re
import struct
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# ATT&CK Technique Catalog (Linux-relevant subset)
# ---------------------------------------------------------------------------
TECHNIQUES = {
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactics": ["Defense Evasion"],
        "indicators": ["high_entropy", "packed", "stripped", "upx", "encrypted_strings"],
    },
    "T1027.004": {
        "name": "Compile After Delivery",
        "tactics": ["Defense Evasion"],
        "indicators": ["gcc", "clang", "compiler"],
    },
    "T1059.004": {
        "name": "Unix Shell",
        "tactics": ["Execution"],
        "indicators": ["execve", "system", "popen", "shell", "/bin/sh", "/bin/bash"],
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactics": ["Command and Control"],
        "indicators": ["curl", "wget", "socket", "connect", "download"],
    },
    "T1543.002": {
        "name": "Systemd Service",
        "tactics": ["Persistence", "Privilege Escalation"],
        "indicators": ["systemd", ".service", "/etc/systemd"],
    },
    "T1574.006": {
        "name": "Dynamic Linker Hijacking",
        "tactics": ["Persistence", "Privilege Escalation", "Defense Evasion"],
        "indicators": ["ld.so.preload", "LD_PRELOAD", "dlopen", "dlsym"],
    },
    "T1622": {
        "name": "Debugger Evasion",
        "tactics": ["Defense Evasion", "Discovery"],
        "indicators": ["ptrace", "TracerPid", "/proc/self/status", "PTRACE_TRACEME"],
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactics": ["Discovery"],
        "indicators": ["uname", "getuid", "gethostname", "/proc/"],
    },
    "T1070.004": {
        "name": "File Deletion",
        "tactics": ["Defense Evasion"],
        "indicators": ["unlink", "remove", "shred", "rm -rf"],
    },
    "T1573": {
        "name": "Encrypted Channel",
        "tactics": ["Command and Control"],
        "indicators": ["ssl", "tls", "openssl", "aes", "encrypt", "decrypt"],
    },
    "T1055": {
        "name": "Process Injection",
        "tactics": ["Defense Evasion", "Privilege Escalation"],
        "indicators": ["ptrace", "process_vm_writev", "memfd_create"],
    },
    "T1547.006": {
        "name": "Kernel Modules and Extensions",
        "tactics": ["Persistence", "Privilege Escalation"],
        "indicators": ["insmod", "modprobe", ".ko", "kernel module"],
    },
    "T1222.002": {
        "name": "Linux and Mac File and Directory Permissions Modification",
        "tactics": ["Defense Evasion"],
        "indicators": ["chmod", "chown", "setuid", "setgid"],
    },
    "T1014": {
        "name": "Rootkit",
        "tactics": ["Defense Evasion"],
        "indicators": ["rootkit", "hide", "syscall hook", "lkm"],
    },
    "T1053.003": {
        "name": "Cron",
        "tactics": ["Persistence", "Privilege Escalation"],
        "indicators": ["cron", "crontab", "/etc/cron"],
    },
}

# Ordered tool-chain stages (tactic progression)
CHAIN_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# ---------------------------------------------------------------------------
# ELF / Binary helpers
# ---------------------------------------------------------------------------
def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    for c in freq:
        if c:
            p = c / len(data)
            ent -= p * math.log2(p)
    return round(ent, 3)


def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=30)
    except Exception:
        return ""


def parse_elf_header_pure(path: str) -> dict:
    """Minimal pure-Python ELF header parser (fallback)."""
    info = {"valid": False, "arch": "unknown", "type": "unknown", "entry": 0}
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            if magic != b"\x7fELF":
                return info
            info["valid"] = True
            ei_class = f.read(1)[0]
            info["class"] = "ELF64" if ei_class == 2 else "ELF32"
            f.seek(16)
            e_type = struct.unpack("<H", f.read(2))[0]
            info["type"] = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}.get(e_type, str(e_type))
            f.seek(18)
            e_machine = struct.unpack("<H", f.read(2))[0]
            machines = {3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64", 8: "MIPS"}
            info["arch"] = machines.get(e_machine, f"machine_{e_machine}")
            if ei_class == 2:
                f.seek(24)
                info["entry"] = struct.unpack("<Q", f.read(8))[0]
            else:
                f.seek(24)
                info["entry"] = struct.unpack("<I", f.read(4))[0]
    except Exception:
        pass
    return info


def extract_with_readelf(path: str) -> dict:
    """Use readelf when available for richer data."""
    result = {
        "symbols": [],
        "dynamic": [],
        "sections": [],
        "needed": [],
        "readelf_available": False,
    }
    out = run_cmd(["readelf", "-h", path])
    if not out:
        return result
    result["readelf_available"] = True

    # Dynamic symbols / imports
    dyn = run_cmd(["readelf", "-d", path])
    for line in dyn.splitlines():
        if "NEEDED" in line:
            m = re.search(r"\[(.+?)\]", line)
            if m:
                result["needed"].append(m.group(1))
        if "RPATH" in line or "RUNPATH" in line:
            result["dynamic"].append(line.strip())

    # Symbol table (imports)
    syms = run_cmd(["readelf", "-s", "--dyn-syms", path])
    for line in syms.splitlines():
        if "FUNC" in line or "UND" in line:
            parts = line.split()
            if len(parts) >= 8:
                name = parts[-1]
                if name and name != "Name":
                    result["symbols"].append(name)

    # Sections
    secs = run_cmd(["readelf", "-S", path])
    for line in secs.splitlines():
        if line.strip().startswith("[") and "]" in line:
            result["sections"].append(line.strip())

    return result


def extract_strings(path: str, min_len=5) -> list:
    out = run_cmd(["strings", "-n", str(min_len), path])
    return [s.strip() for s in out.splitlines() if s.strip()] if out else []


def analyze_file_entropy(path: str) -> dict:
    """Compute overall and per-section entropy (simple full-file)."""
    try:
        data = Path(path).read_bytes()
        return {
            "size": len(data),
            "entropy": entropy(data),
            "high_entropy": entropy(data) > 7.0,
        }
    except Exception:
        return {"size": 0, "entropy": 0.0, "high_entropy": False}


# ---------------------------------------------------------------------------
# Mapping engine
# ---------------------------------------------------------------------------
def map_indicators(symbols: list, strings: list, entropy_info: dict, elf_info: dict) -> dict:
    found = defaultdict(list)
    all_text = " ".join(symbols + strings).lower()

    for tid, tech in TECHNIQUES.items():
        for ind in tech["indicators"]:
            if ind.lower() in all_text or ind.lower() in " ".join(symbols).lower():
                found[tid].append(ind)
        # Special structural checks
        if tid == "T1027" and entropy_info.get("high_entropy"):
            found[tid].append("high_entropy_section")
        if tid == "T1222.002" and os.access(path if "path" in dir() else "", os.X_OK):
            # setuid check done outside
            pass

    # Deduplicate evidence
    mapped = {}
    for tid, evidence in found.items():
        if evidence:
            mapped[tid] = {
                "name": TECHNIQUES[tid]["name"],
                "tactics": TECHNIQUES[tid]["tactics"],
                "evidence": sorted(set(evidence)),
                "score": min(len(set(evidence)) * 2, 10),
            }
    return mapped


def build_toolchain(mapped: dict) -> list:
    """Build ordered attack tool chain from matched techniques."""
    by_tactic = defaultdict(list)
    for tid, info in mapped.items():
        for tactic in info["tactics"]:
            by_tactic[tactic].append({
                "id": tid,
                "name": info["name"],
                "score": info["score"],
                "evidence": info["evidence"],
            })

    chain = []
    for tactic in CHAIN_ORDER:
        if tactic in by_tactic:
            # Sort by score descending within tactic
            techs = sorted(by_tactic[tactic], key=lambda x: -x["score"])
            for t in techs:
                chain.append({
                    "stage": tactic,
                    "technique": t["id"],
                    "name": t["name"],
                    "score": t["score"],
                    "evidence": t["evidence"],
                })
    return chain


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------
def analyze(path: str) -> dict:
    if not os.path.isfile(path):
        return {"error": f"File not found: {path}"}

    elf = parse_elf_header_pure(path)
    readelf_data = extract_with_readelf(path)
    strings = extract_strings(path)
    ent = analyze_file_entropy(path)

    # setuid / setgid
    st = os.stat(path)
    setuid = bool(st.st_mode & 0o4000)
    setgid = bool(st.st_mode & 0o2000)

    symbols = readelf_data.get("symbols", [])
    needed = readelf_data.get("needed", [])

    mapped = map_indicators(symbols + needed, strings, ent, elf)

    # Extra structural mappings
    if setuid or setgid:
        mapped.setdefault("T1222.002", {
            "name": TECHNIQUES["T1222.002"]["name"],
            "tactics": TECHNIQUES["T1222.002"]["tactics"],
            "evidence": ["setuid" if setuid else "setgid"],
            "score": 6,
        })

    chain = build_toolchain(mapped)

    return {
        "file": path,
        "size": ent["size"],
        "entropy": ent["entropy"],
        "high_entropy": ent["high_entropy"],
        "elf": elf,
        "needed_libs": needed,
        "symbol_count": len(symbols),
        "string_count": len(strings),
        "setuid": setuid,
        "setgid": setgid,
        "mapped_techniques": mapped,
        "attack_toolchain": chain,
        "summary": {
            "technique_count": len(mapped),
            "highest_score": max((m["score"] for m in mapped.values()), default=0),
            "primary_tactics": sorted({t for m in mapped.values() for t in m["tactics"]}),
        },
    }


def print_report(result: dict, show_chain: bool = True):
    if "error" in result:
        print(f"[!] {result['error']}")
        return

    print(f"\n{'='*60}")
    print(f" MITRE ATT&CK Linux Binary Analyzer")
    print(f"{'='*60}")
    print(f" File          : {result['file']}")
    print(f" Size          : {result['size']} bytes")
    print(f" Entropy       : {result['entropy']} {'(HIGH)' if result['high_entropy'] else ''}")
    print(f" ELF Class     : {result['elf'].get('class', 'n/a')}")
    print(f" Architecture  : {result['elf'].get('arch', 'n/a')}")
    print(f" Type          : {result['elf'].get('type', 'n/a')}")
    print(f" Entry Point   : {hex(result['elf'].get('entry', 0))}")
    print(f" SetUID/SetGID : {result['setuid']}/{result['setgid']}")
    print(f" Needed libs   : {', '.join(result['needed_libs'][:8]) or 'none'}")
    print(f" Symbols       : {result['symbol_count']}")
    print(f" Strings       : {result['string_count']}")

    print(f"\n[+] Mapped ATT&CK Techniques ({result['summary']['technique_count']}):")
    if not result["mapped_techniques"]:
        print("    None detected (benign or insufficient indicators)")
    for tid, info in sorted(result["mapped_techniques"].items()):
        print(f"    {tid:12} {info['name']}")
        print(f"               Tactics: {', '.join(info['tactics'])}")
        print(f"               Score: {info['score']}/10 | Evidence: {', '.join(info['evidence'][:5])}")

    if show_chain and result["attack_toolchain"]:
        print(f"\n[+] Suggested Attack Tool Chain:")
        stage = None
        for step in result["attack_toolchain"]:
            if step["stage"] != stage:
                stage = step["stage"]
                print(f"\n  --- {stage} ---")
            print(f"    {step['technique']}  {step['name']}  (score {step['score']})")
            print(f"             evidence: {', '.join(step['evidence'][:4])}")

    print(f"\n[+] Summary: {result['summary']['technique_count']} techniques | "
          f"max score {result['summary']['highest_score']} | "
          f"tactics: {', '.join(result['summary']['primary_tactics'])}")
    print("="*60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK Linux Binary Analyzer & Attack Toolchain Builder"
    )
    parser.add_argument("binary", help="Path to Linux ELF binary")
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    parser.add_argument("--chain", action="store_true", help="Include full attack tool chain (default)")
    parser.add_argument("--no-chain", action="store_true", help="Suppress tool chain")
    args = parser.parse_args()

    result = analyze(args.binary)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print_report(result, show_chain=not args.no_chain)


if __name__ == "__main__":
    main()
