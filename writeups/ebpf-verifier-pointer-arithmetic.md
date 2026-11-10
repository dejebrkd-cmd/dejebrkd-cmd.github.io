# Bypassing the eBPF verifier through pointer arithmetic

*Published 2026-10 — vulnerability class analysis, not a specific CVE claim.*

## Summary

The eBPF verifier is the security boundary between unprivileged BPF bytecode and
the kernel. Its correctness depends on tracking the provenance of every register
value through the program. When the verifier's abstract interpretation of a value
diverges from what the JIT-compiled code actually computes at runtime, the
difference becomes an out-of-bounds read or write primitive.

This note describes the general shape of that class of bug and the verification
method I use to find it, rather than a single disclosure.

## The trust boundary

```
user bytecode
    │
    ▼
┌──────────────┐   reject on doubt
│  verifier    │ ──────────────────► EACCES (load denied)
└──────┬───────┘
       │ accepted: type checked, bounds tracked
       ▼
┌──────────────┐
│  JIT compiler│  ← the verifier's model must match this
└──────┬───────┘
       │
       ▼
   kernel memory
```

Two properties have to hold simultaneously:

1. **Soundness of bounds** — for every path the verifier explored, the runtime
   value stays within the track range.
2. **Completeness of exploration** — no path exists that the verifier did not
   explore but the CPU can reach.

A bug lives in the gap between them.

## Where the gap opens

Three patterns account for most of the verifier bypasses I have reproduced:

### 1. Range narrowing after a re-read

The verifier tracks `rX` as `[0, 8]` after a range check. If the program re-reads
the same stack slot through a different path and the verifier carries the old
range into the new value, the runtime value can exceed `8`.

```
r6 = *(u64 *)(r10 - 24)      ; verifier: r6 in [0, 8]  (from earlier check)
... branch ...
r6 = *(u64 *)(r10 - 24)      ; runtime: whatever the helper wrote here
r1 = r6                      ; verifier still assumes [0, 8]
r2 = *(u64 *)(r1 + 0)        ; OOB by up to (real value - 8)
```

The fix class is always the same: invalidate tracked ranges on any write that the
verifier did not model.

### 2. 32-bit write, 64-bit read

A `BPF_ALU` operation on the 32-bit sub-register zero-extends, but a partial
stack write does not. Mixing the two gives a value whose upper 32 bits are
attacker-controlled while the verifier believes them zero.

```
*(u32 *)(r10 - 4) = r1       ; writes 4 bytes, upper 4 bytes of slot untouched
r2 = *(u64 *)(r10 - 4)       ; reads 8 — upper bits are stale kernel data
```

If those stale bits came from a previous kernel stack frame, that is an
information leak; if they came from a controlled helper argument, it is an
arbitrary value.

### 3. Bounds on a pointer, not on the offset

The verifier sometimes checks the pointer's base range but tracks the offset
separately. An arithmetic operation that overflows the offset's signed range
wraps it negative without tripping the check.

## Verification method

I do not fuzz the verifier directly — finding a bypass by random bytecode has a
signal-to-noise ratio too low to be useful. The loop is:

```
1. Enumerate every place the verifier *writes* a tracked type
   (grep the type-check functions in verifier.c for the branch that returns true)
2. For each, ask: what runtime path reaches the same instruction with a
   different value than the verifier's model?
3. Build the smallest bytecode that takes the runtime path.
4. Run it under a kernel built with CONFIG_BPF_JIT_ALWAYS_ON=y and KASAN,
   with the verifier log enabled (-v in bpftool prog load).
5. Compare the verifier log's computed ranges against the actual value read
   by the program (instrument with bpf_trace_printk at the sink).
```

Step 5 is where the divergence becomes evidence rather than a guess: the verifier
log states the range it believes, and the tracepoint prints the real one. When
those disagree at the sink instruction, the primitive is confirmed.

## Reproducing in a lab

```bash
# kernel with KASAN + JIT always on
qemu-system-x86_64 -kernel bzImage -append "console=ttyS0 kasan_multi_shot" ...

# load the candidate program and capture the verdict
bpftool prog load ./poc.o /sys/fs/bpf/poc type socket_filter -d -v 2>verifier.log

# if accepted, attach and observe the sink
bpftool prog tracelog
```

If the program loads but the tracepoint shows a value outside the logged range,
that is the finding.

## Disclosure

Findings of this class are reported to the kernel BPF maintainers via
`bpf@vger.kernel.org` with the reproducer and the verifier log diff. Embargo
follows the standard kernel policy; credit is given unless the reporter declines.

## Notes on scope

Everything above happens on a local QEMU instance booting a kernel I built.
No production system, and no third-party kernel, is involved at any step.
