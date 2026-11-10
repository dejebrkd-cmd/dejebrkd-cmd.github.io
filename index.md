# Meridian Security Research

Independent security research practice working on vulnerability research, malware
analysis, and detection engineering.

## Focus areas

| Area | What we do |
|---|---|
| **Vulnerability research** | Memory-safety and logic flaws in open-source software; reproduce in isolated labs, produce patches and advisories. |
| **Malware analysis** | Sample triage, loader deobfuscation, C2 protocol reconstruction, IOC extraction. |
| **Detection engineering** | Sigma / YARA / EDR rules validated against real attacker techniques, with measured false-positive rates. |

## Recent writeups

| Date | Title | Topic |
|---|---|---|
| 2026-10 | [Bypassing the eBPF verifier through pointer arithmetic](writeups/ebpf-verifier-pointer-arithmetic.md) | Linux kernel, eBPF, CVE-class analysis |
| 2026-10 | [Detecting DNS-over-HTTPS C2 without TLS interception](writeups/doh-c2-detection.md) | Network detection, malware C2 |
| 2026-09 | [Sigma rule engineering for LSASS memory access](writeups/lsass-access-sigma.md) | Windows detection, credential dumping |

## Working boundary

All analysis is performed in isolated lab environments against systems we own or
are explicitly authorized to test. Third-party findings are reported through
coordinated disclosure — see [disclosure policy](disclosure.md).

## Contact

Open an issue on any repository, or use the contact address in the disclosure
policy.

---

*Sample handling: every artifact is hashed (SHA-256), logged, and stored with a
chain-of-custody record. Malware is executed only inside snapshot-restored VMs on
an isolated VLAN with no inbound connectivity.*
