
## Harness Design

**File:** `nft_wmi_harness.c`

The harness:

- Models `struct nft_expr`.
- Models `struct nft_rule`.
- Wraps `malloc` / `free` with shadow heap tracking.
- Tracks WMI state using a global bitmask.
- Forces KLEE to generate a test case only if a full chain is reached.

### Shadow Heap

Each allocation stores:

- Pointer
- Size
- Allocation state
- `type_id`
- Taint status

This allows modeling of:

- Use-after-free
- Type confusion
- Double free
- Overlapping control structure writes

---

## Build and Run

### Compile to LLVM Bitcode

```bash
clang -emit-llvm -c -g nft_wmi_harness.c -o nft_wmi_harness.bc
```

### Run KLEE

```bash
klee --posix-runtime nft_wmi_harness.bc
```

---

## LLM Usage Documentation

An LLM was used to support the design and refinement of the symbolic execution harness.

### The LLM Was Used To:

- Help formalize WMI chain definitions.
- Structure detection logic.
- Enforce strict ordering constraints between WMIs.
- Refine symbolic pointer modeling.
- Avoid direct fatal C memory crashes inside KLEE.
- Improve shadow heap tracking logic.

### Iterative Refinement Process

Each iteration involved:

- Tightening chain constraints.
- Reducing false positives.
- Ensuring state-based gating between WMIs.
- Forcing KLEE assertions only on full chain success.

### Prompt Refinement Goals

Prompts were refined to:

- Enforce exact ordered chaining.
- Require same-path state tracking.
- Remove independent WMI triggers.
- Prevent unrelated paths from incorrectly satisfying success conditions.

Despite multiple refinements, a full ordered WMI chain was not achieved on a single execution path.
