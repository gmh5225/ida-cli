# Counterfactual Patching Methodology

Systematic approach to proving causal relationships between input fields and program behavior through single-variable mutation.

## Core Principle

**Change one variable at a time. Observe the effect. Build causal chains.**

Each patch experiment answers: "Does field X at offset Y control branch Z that produces error code W?"

## Workflow

```
1. Establish baseline
   → Execute with real inputs → record r0, CPI amounts

2. Form hypothesis (from static analysis)
   → "Field at offset 0x1234 controls the vault owner check"

3. Mutate ONE variable
   → Change only that field in the input buffer
   → Re-execute

4. Observe r0 change
   → Did error code change as predicted?
   → Did CPI amounts change?

5. Record causal link
   → field_offset → branch_address → error_code

6. Repeat for next hypothesis
```

## What to Patch

| Variable | How to Patch | What to Observe |
|---|---|---|
| **Account owner** | Replace 32-byte owner field | Owner check error codes |
| **Account pubkey** | Replace 32-byte pubkey | PDA / authority validation |
| **Direction byte** | Flip 0↔1 in instruction_data | Swap direction routing |
| **Amount** | Modify u64 in instruction_data | Slippage / overflow checks |
| **Slot / timestamp** | Modify sysvar Clock data | Time-gated logic |
| **Account data fields** | Modify pool state bytes | Fee / capacity / threshold checks |
| **Lamports** | Modify lamports field | Rent / balance checks |

## Rules

1. **Single variable only** — never change two things at once; you can't attribute the effect
2. **Record before AND after** — baseline r0 and patched r0
3. **Verify reversibility** — restore original value, confirm baseline r0 returns
4. **Track the chain** — map `(field, offset) → (branch address, condition) → (r0 error code)`
5. **Boundary test** — after confirming the happy path, try edge cases (0, MAX, off-by-one)

## Error Code Transition Matrix

Build a matrix as you patch:

```
| Patch | Expected r0 | Actual r0 | Branch Address | Confirmed? |
|-------|-------------|-----------|----------------|------------|
| owner[0] = wrong | 0x400000000 | 0x400000000 | 0x1234 | ✅ |
| amount = 0 | some error | 0xFADED | 0x5678 | ✅ |
| direction = 2 | invalid | 0xBADC0DE3 | 0x9ABC | ✅ |
```

## Common Pitfalls

- **Patching multiple variables**: breaks causal reasoning entirely
- **Not recording baseline**: can't compare without reference point
- **Ignoring alignment**: patching in the middle of a field may cause deserialization failure, not the expected logic error
- **Confusing symptoms with causes**: an error code change might be from a downstream check, not the field you patched — verify with breakpoints

## Integration with Dynamic Debugging

The most effective pattern combines patching with breakpoints:

1. Set breakpoint at the candidate comparison instruction (from IDA static analysis)
2. Run with original input → record register values at breakpoint
3. Patch the suspected field
4. Run again → observe changed register values at same breakpoint
5. If the comparison now takes the other branch → causal link confirmed

## Output Format

After completing all patches for a function, document as:

```rust
/// Error code mapping for <DexName> swap dispatch
///
/// | r0 Value | Meaning | Trigger Condition |
/// |----------|---------|-------------------|
/// | 0x000000000 | Success | Valid swap executed |
/// | 0xFADED | Invalid amount | amount == 0 or overflow |
/// | 0xBADC0DE3 | Wrong direction | direction byte ∉ {0, 1} |
/// | 0x400000000 | Invalid account | account owner mismatch |
```
