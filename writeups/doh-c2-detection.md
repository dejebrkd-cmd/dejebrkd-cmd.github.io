# Detecting DNS-over-HTTPS C2 without TLS interception

*Published 2026-10 — network detection engineering.*

## Problem

A loader that beacons through DNS-over-HTTPS (DoH) defeats most network detection
for two reasons:

- the payload is inside TLS, so SNI + hostname rules see only `dns.google` or a
  CDN front;
- the queries go to a resolver, not to an attacker-owned hostname, so threat-intel
  domain matching returns nothing.

Blocking DoH wholesale breaks legitimate traffic. The detection has to work on
metadata the endpoint still exposes.

## What is actually observable

| Layer | What remains | Why it is enough |
|---|---|---|
| TLS SNI | resolver hostname | narrows to a short allow-list |
| TLS certificate | resolver's real cert | DoH endpoints present a fixed cert; a proxy front does not |
| Timing | beacon interval variance | C2 jitter is machine-shaped, human browsing is not |
| Volume | request/response size distribution | a tunnel puts the payload in one direction |
| Endpoint process | which process opened the connection | generic browsers already use DoH; a loader usually is not one |

The pivot is the last row: **DoH from a process that is not a browser** has very
few benign explanations.

## Detection: process-aware DoH egress

Sigma rule for the endpoint side (Sysmon EventID 22 / 3):

```yaml
title: DoH Egress From Non-Browser Process
id: 4b1c2f7e-8d3a-4e21-9f55-6c1a2d7e9b03
status: experimental
description: >
  A process other than a known browser or the OS resolver opened a connection to
  a public DoH endpoint. Legitimate DoH clients are limited to browsers,
  the system resolver, and admin tooling.
logsource:
  category: network_connection
  product: windows
detection:
  doh_dest:
    DestinationHostname|endswith:
      - 'dns.google'
      - 'cloudflare-dns.com'
      - 'dns.quad9.net'
      - 'mozilla.cloudflare-dns.com'
  benign_client:
    Image|endswith:
      - '\chrome.exe'
      - '\msedge.exe'
      - '\firefox.exe'
      - '\svchost.exe'
      - '\dnscrypt-proxy.exe'
  filter_signed:
    Signed: 'true'
    SignatureStatus: 'Valid'
  condition: doh_dest and not benign_client and not filter_signed
fields:
  - Image
  - DestinationHostname
  - DestinationPort
  - Initiated
falsepositives:
  - New browser builds with different binary names
  - Developer tooling that queries DoH directly (documented exception list)
level: medium
```

The `filter_signed` clause is what keeps this usable: unsigned binaries reaching
for a DoH resolver are the interesting case, and the false-positive rate in a
normal fleet is low enough to leave it enabled.

## Detection: tunnel shape

For a confirmed suspect process, the shape test separates a beacon from normal
DoH:

```
requests per hour        ~60 (1/min) and jittered
request payload size     narrow distribution, mean ~= 120-200 bytes
response payload size    bimodal: small ack, occasional large transfer
session length           persistent, hours
```

A browser talking DoH looks the opposite: bursty, wide size distribution,
sessions that end when the tab closes.

Sigma for the volume shape — this one is correlation-based, so it needs a
SIEM that supports aggregation:

```yaml
title: Sustained Low-Volume DoH Session to Single Resolver
id: 9c3d5a11-2b7e-4f60-8a1d-5e9f3b2c7d41
status: experimental
logsource:
  category: network_connection
  product: windows
detection:
  doh_dest:
    DestinationHostname|endswith:
      - 'dns.google'
      - 'cloudflare-dns.com'
  timeframe: 1h
  condition: doh_dest | count(DestinationHostname) by Image > 30
falsepositives:
  - Browser with a pinned DoH configuration and a busy tab
level: low
```

## Validation

I validate against a lab beacon I wrote (configurable interval, jitter, and
padding) rather than against a live family:

```
                    rule fires?
beacon @ 60s, 0% jitter ....... yes  (count threshold)
beacon @ 60s, 30% jitter ...... yes
browser, 8 tabs, DoH on ....... no   (benign_client filter)
signed updater using DoH ...... no   (filter_signed)
unsigned tool, 3 requests ..... no   (count threshold)
```

Measured on 72 hours of lab traffic: 0 false positives with the process filter
active, 2 false positives without it (both were unsigned telemetry agents that
documented DoH use).

## Why not TLS interception

Interception solves the visibility problem by creating a larger one: certificate
pinning breaks, privacy expectations break, and the interception appliance
becomes the weakest link. Metadata detection gets the same answer without
touching payload.

## Reproducing

```bash
# lab beacon (own implementation, loopback-only by default)
./lab-doh-beacon --resolver https://dns.google/dns-query --interval 60 --jitter 0.3

# capture the process/network events
# then replay the resulting JSON through the Sigma backend of choice
sigma convert -t splunk doh-egress.yml
```

## Scope

The beacon, the resolver, and the SIEM all run on a local lab segment. No capture
or connection is made to infrastructure outside it.
