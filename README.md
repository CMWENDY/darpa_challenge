# DARPA Demo3 – Netfilter WMI Analysis (nf_tables_api.c)

**Focus Module:** Linux Kernel – `netfilter`  
**File of Interest:** `net/netfilter/nf_tables_api.c`  
**Technique:** Manual WMI identification + KLEE symbolic execution harness  

---

## Overview

For the DARPA Demo3 challenge, the task was to manually identify potential Weird Machine Instructions (WMIs) inside selected Linux kernel modules and then build symbolic execution harnesses to detect full Weird Machine Programs (WMPs).

For this phase, I focused only on **netfilter**, specifically logic inspired by:

```bash
net/netfilter/nf_tables_api.c
```

The goal was to model and detect a **complete weird machine chain**:

```bash
WMI-1 → WMI-2 → WMI-3 → WMI-4
```

All four stages must occur in order on the same execution path for a successful chain.

I was able to trigger multiple individual WMIs, but I did **not** successfully obtain the full ordered chain in a single execution path.


---

## Weird Machine Chain Definition

### WMI-1: Use-After-Free
- A Netfilter object is freed.
- A stale pointer to that object is later accessed.

### WMI-2: Type Confusion
- The freed chunk is reallocated as a different object type.
- It is accessed through the stale pointer.

### WMI-3: Arbitrary / Double Free
- The same chunk is freed again or freed via an incompatible destructor path.

### WMI-4: Write-What-Where / Control Flow Impact
- Attacker-controlled data overwrites a function pointer or sensitive field.
- The corrupted pointer is invoked or influences control flow.

Success condition:
All four must occur in order on the same execution path.

---

## Manual Analysis (nf_tables_api.c Inspiration)

I focused on lifecycle patterns around:

- `nft_expr` allocation and destruction
- rule installation / removal
- error unwind paths
- commit / abort logic
- function pointer evaluation (`expr->eval`)

Key reasoning:

- Error paths during rule creation can free `nft_expr` objects.
- Pointers may remain stored in rule structures.
- Heap grooming could allow reallocation of the same slab.
- Function pointers inside `nft_expr` make good control targets.
- Double free / invalid free patterns are realistic under race or improper state cleanup.

The harness models this behavior using a shadow heap.

---
## What Worked

- Successfully modeled stale pointer creation.
- Successfully detected UAF.
- Successfully detected double free.
- Successfully modeled function pointer overwrite.
- Successfully detected overlapping control structure writes.
- KLEE explored multiple symbolic paths.

---

## What Did Not Work

- The full ordered chain condition was never satisfied.
- WMI-2 and WMI-3 ordering constraints were difficult to enforce.
- Ensuring that all stages occurred on the same symbolic path proved challenging.
- Heap grooming modeling was simplified and may not fully reflect slab allocator reuse behavior.
- The final assertion requiring full chain activation was never triggered.

---

## Additional Observations

- The most promising primitive was the `expr->eval` function pointer.
- Error unwind paths remain the most realistic entry point.
- Heap reuse modeling likely needs to be more accurate (slab cache behavior).
- More realistic modeling of destructor logic could help force WMI-3 after type confusion.

---

## Exploit Goal

The intended exploit goal was:

- Control flow hijack through corrupted `eval` pointer.
- Demonstrate RIP control.
- Model privilege escalation primitive.

The harness includes a `win_eval()` function to simulate control-flow hijack, but the full chain condition was not reached.

---

## Conclusion

This phase demonstrates:

- Working symbolic detection of individual Weird Machine Instructions.
- A structured attempt at chaining.
- Documented modeling of netfilter-inspired object lifecycle.
- Clear negative result for full chain completion.

The work shows partial weird machine primitives but does **not** demonstrate a complete Weird Machine Program in `nf_tables_api.c`.

Further work would focus on:

- More realistic allocator modeling.
- Better destructor simulation.
- Modeling commit/abort races.
- Expanding into `io_uring` and `binder` modules.

---

## Status

- **Netfilter WMI identification:** Partial Success  
- **Full ordered WMI chain:** Not Achieved
