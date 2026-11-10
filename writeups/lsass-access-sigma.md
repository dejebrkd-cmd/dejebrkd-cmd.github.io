# Sigma rule engineering for LSASS memory access

*Published 2026-09 — Windows detection, credential dumping.*

## Why the obvious rule fails

The textbook rule is "alert when a process opens `lsass.exe` with
`PROCESS_VM_READ`". It produces noise everywhere because EDR agents, backup
software, and Windows Defender itself all read LSASS memory legitimately.

```
every EDR agent      → opens lsass with VM_READ
every backup agent   → same
Windows Defender     → same (PPL-protected, still logs the open)
```

The rule as written is technically correct and operationally useless. What
separates malicious access is not the requested right — it is the **combination**
of the caller's provenance, the granted access mask, and what happens after.

## The three signals that carry the decision

### 1. GrantedAccess mask, not requested

| Mask | Meaning | Seen in |
|---|---|---|
| `0x1010` | `PROCESS_QUERY_LIMITED_INFORMATION` + `VM_READ` | EDR inventory, benign |
| `0x1410` | adds `PROCESS_QUERY_INFORMATION` | some backup agents |
| **`0x1FFFFF`** | `PROCESS_ALL_ACCESS` | almost always tooling |
| `0x143A` | the classic mimikatz mask | credential dumping |
| `0x0A` | `VM_READ` + `VM_WRITE` patterns via handle duplication | injection |

The `0x143A` mask (`PROCESS_VM_READ | PROCESS_QUERY_INFORMATION |
PROCESS_VM_WRITE | ...`) is narrow enough to be worth a direct rule.

### 2. Caller is unsigned or lives in user-writable space

```
C:\Users\...\*.exe        running from a user profile
%TEMP%\...\*.dll          module loaded from temp
unsigned + VM_READ        the case worth alerting on
```

### 3. What the caller does next

A benign reader closes the handle and exits. A credential dumper reads a large
region in a tight loop, often followed by an outbound connection or a file write
of a few hundred KB.

That sequence — `open lsass` → `bulk read` → `egress/file write` — is the
correlation the rule should be built on.

## Rule 1: the narrow mask rule

```yaml
title: LSASS Access with Credential Dumping Mask
id: 5f2a8c31-7d94-4b6e-a1c8-3e0d9b5f7a12
status: stable
description: >
  A process requested PROCESS_VM_READ plus PROCESS_QUERY_INFORMATION against
  lsass.exe — the access pattern used by credential dumping tools.
references:
  - https://attack.mitre.org/techniques/T1003/001/
logsource:
  product: windows
  category: process_access
detection:
  target:
    TargetImage|endswith: '\lsass.exe'
  mask:
    GrantedAccess:
      - '0x143a'
      - '0x1438'
      - '0x1fffff'
  filter_known:
    SourceImage|endswith:
      - '\MsMpEng.exe'
      - '\csrss.exe'
      - '\wininit.exe'
      - '\services.exe'
  condition: target and mask and not filter_known
fields:
  - SourceImage
  - GrantedAccess
  - CallTrace
falsepositives:
  - Administrative troubleshooting with Process Explorer (documented exception)
level: high
```

`GrantedAccess` in Sysmon EventID 10 is logged as the granted mask, not the
requested one — which is why this rule is stable across EDR products.

## Rule 2: the sequence rule

```yaml
title: LSASS Read Followed by Credential-Store-Access Pattern
id: 8b4e1f92-6c37-4a05-b8d2-1f7a3c9e5b60
status: experimental
description: >
  Correlates an lsass access with a subsequent outbound connection or a
  file write of credential-dump size within the same process tree.
logsource:
  product: windows
detection:
  lsass_access:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess:
      - '0x1010'
      - '0x1410'
      - '0x143a'
  egress:
    Initiated: 'true'
    DestinationIsIpv6: 'false'
  timeframe: 5m
  condition: lsass_access | count() by SourceImage > 0 and egress | count() by Image > 0
falsepositives:
  - EDR agent that reads LSASS and also beacons to its console
level: medium
```

The false-positive note is real: this rule will fire on your own EDR agent unless
the agent's image is excluded at the top. In practice I run it with the EDR agent
excluded and accept the residual.

## Measuring false positives honestly

A rule with no false-positive measurement is a guess. The method I use:

```
1. Run the rule over 14 days of a lab golden-image fleet (Windows 10/11, 6 hosts)
2. Run the same rule over a deliberately noisy host (dev workstation with
   Process Explorer, Wireshark, Sysinternals suite installed)
3. Record: alerts/day, distinct SourceImage values, and for each, the reason
```

Result for Rule 1 on that dataset:

| Host set | Alerts / 14d | Distinct images | Verified FP |
|---|---|---|---|
| Golden image fleet | 0 | – | – |
| Dev workstation | 3 | procexp64.exe (3) | 3 |

Which is why `procexp64.exe` belongs in a documented exception list rather than
in the rule body — the rule stays honest and the exception is auditable.

## Testing the rule, not just writing it

```yaml
# tests/rule1.yml — atomic-style test against a lab VM
test:
  name: LSASS read with 0x143A mask
  steps:
    - run: ./lab-lsass-reader.exe --mask 0x143A --target lsass.exe
      expect: rule fires within 10s
  teardown:
    - kill: lab-lsass-reader.exe
```

`lab-lsass-reader.exe` is a small binary I built for the lab. It opens the target
with a configurable mask, reads a fixed region, and exits — enough to exercise
the rule without being a credential stealer. This is the piece that makes rule
development reproducible instead of anecdotal.

## Scope

All testing happens on local VMs I control, with the reader tool built for this
purpose. It reads a fixed buffer and discards it; it does not parse, store, or
transmit credentials.
