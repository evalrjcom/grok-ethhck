# Example usage and test notes

## Test against system binaries

```bash
# Analyze bash
python3 mitre_linux_analyzer.py /bin/bash --chain

# Analyze a typical dynamic binary
python3 mitre_linux_analyzer.py /usr/bin/curl --json | head -50

# Analyze python interpreter
python3 mitre_linux_analyzer.py $(which python3)
```

## Expected observations

- `/bin/bash` typically maps to T1059.004 (Unix Shell) and T1082 (System Information Discovery)
- High-entropy packed malware will strongly trigger T1027
- Binaries importing `ptrace` will map to T1622 and T1055
- Presence of `systemd` strings suggests T1543.002 persistence potential

## Extending mappings

Edit the `TECHNIQUES` dictionary in `mitre_linux_analyzer.py` or the companion `attack_mappings.json` to add new indicators or techniques. Keep evidence rules simple and auditable for lab use.
