# grok-ethhck

**MITRE ATT&CK Linux Binary Analyzer & Attack Toolchain Builder**

A static analysis tool that reads Linux ELF binaries and maps observed characteristics, imports, strings, and structural features to MITRE ATT&CK techniques. It then constructs a plausible attack tool chain (kill-chain style sequence) based on the binary's capabilities.

Designed for ethical hacking labs, malware triage, defensive research, and understanding how Linux binaries map to adversary tactics.

## Features

- ELF header, section, and dynamic symbol parsing (via `readelf` or pure-Python fallback)
- String extraction and entropy analysis
- Rule-based mapping of indicators → ATT&CK techniques (T1027, T1059.004, T1543.002, T1622, T1574.006, T1105, etc.)
- Scored attack tool chain generation (Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → C2 → Impact)
- JSON and human-readable reports
- No heavy external dependencies beyond standard Linux tools (`readelf`, `strings`)

## Usage

```bash
# Basic analysis
python3 mitre_linux_analyzer.py /path/to/binary

# JSON output
python3 mitre_linux_analyzer.py /path/to/binary --json

# Full report with suggested tool chain
python3 mitre_linux_analyzer.py /path/to/binary --chain
```

## Example Output

```
[+] Binary: suspicious_elf
[+] Architecture: x86-64
[+] Linked: dynamic
[+] High entropy sections: .text (7.8), .data (7.2)
[+] Suspicious imports: ptrace, socket, connect, execve
[+] Mapped techniques:
    T1027     Obfuscated Files or Information
    T1622     Debugger Evasion
    T1059.004 Unix Shell
    T1105     Ingress Tool Transfer
    T1573     Encrypted Channel
[+] Suggested Attack Tool Chain:
    1. T1203 Exploitation for Client Execution (or dropper)
    2. T1027 Obfuscated payload
    3. T1059.004 Unix Shell execution
    4. T1543.002 Systemd Service (persistence)
    5. T1573 Encrypted C2
```

## Installation

No install required. Requires Python 3.8+ and standard `binutils` tools.

```bash
git clone https://github.com/evalrjcom/grok-ethhck.git
cd grok-ethhck
python3 mitre_linux_analyzer.py $(which bash) --chain
```

## Ethical Use

This tool is for defensive analysis, security research, and authorized labs only. Do not use against systems you do not own or have explicit permission to test.

## MITRE ATT&CK

Mappings are derived from the [Linux Matrix](https://attack.mitre.org/matrices/enterprise/linux/). Technique IDs and names follow official ATT&CK nomenclature.

## License

MIT
