# Coordinated disclosure policy

## Scope

This policy covers vulnerabilities and research findings produced by Meridian
Security Research that affect third-party software or services.

It does **not** cover work on systems we own, lab fixtures, or CTF challenges —
those are published directly.

## How we report

1. **Direct contact first.** The maintainer or vendor security contact receives a
   private report containing: affected version, reproduction steps, impact
   assessment, and a suggested fix where one is obvious.
2. **Standard embargo: 90 days.** We publish on day 90, or earlier if a fix ships
   and the vendor agrees, or if the issue is being actively exploited.
3. **Embargo extension** on request, up to 120 days total, if the vendor is
   actively working on a fix and shows progress.
4. **No exploit publication before the fix is available** where the affected
   software is widely deployed.

## What we publish

- Technical root cause and the class of bug
- Affected versions and the fixed version
- Detection guidance for defenders
- Mitigation for systems that cannot patch immediately

We publish proof-of-concept code only when the fix has shipped and the vendor has
had a reasonable window to see it deployed, and even then the PoC is written to
demonstrate the primitive, not to be a ready-to-run weapon against unpatched
systems.

## What we never do

- Test third-party systems without written authorization
- Publish findings that would expose users of unpatched software before a fix
  exists
- Accept payment in exchange for suppressing a finding

## Reporting to us

If you believe you have found an issue in something published here (a detection
rule with a false-negative, a tool with a bug), open an issue on the relevant
repository. For anything sensitive, use the contact address below.

## Contact

Open a GitHub issue on the relevant repository, or email the address listed in
the repository's `SECURITY.md` file.

PGP key fingerprint is published in the same place.

## Commitments

- Acknowledgement within 5 business days
- Status update at least every 14 days during an embargo
- Credit given by name unless the reporter asks otherwise
