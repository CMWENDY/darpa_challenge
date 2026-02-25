## KLEE Results

KLEE produced:

- Use-After-Free detections  
- Double free detections  
- Arbitrary free attempts  
- Write-What-Where detection  
- Multiple generated paths and test cases  

### From the Run

```
[WMI-1/3 DETECTED] Double free on pointer
[WMI-1 DETECTED] Use-After-Free dereference!
[WMI-4 DETECTED] Symbolic data written to overlapping control structure.
```

### Summary

```
KLEE: done: completed paths = 4
KLEE: done: generated tests = 8
```

---

## Important

Although individual WMIs were detected, I did **not** achieve:

```
WMI-1 → WMI-2 → WMI-3 → WMI-4
```

in the required strict order on the same execution path.

This phase does **not** demonstrate a full Weird Machine Program success.
