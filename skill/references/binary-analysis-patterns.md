# Binary Analysis Patterns

Common reverse engineering workflows and patterns for IDA Pro.

## Malware Analysis

### Triage Workflow

1. **Binary overview**: Check sections, imports, strings, entropy
2. **Import analysis**: Identify suspicious API calls (crypto, network, process injection)
3. **String analysis**: Extract URLs, IPs, registry keys, file paths
4. **Entry point analysis**: Trace from `main` / `DllMain` / `TLS callbacks`
5. **Control flow**: Map decision trees, anti-analysis checks
6. **Payload extraction**: Identify decryption routines, dump decoded buffers

### Identify Suspicious API Calls

```python
SUSPICIOUS_APIS = {
    "injection": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                  "NtMapViewOfSection", "QueueUserAPC"],
    "persistence": ["RegSetValueEx", "CreateService", "SchTask",
                    "SetWindowsHookEx"],
    "evasion": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                "NtQueryInformationProcess", "GetTickCount", "Sleep"],
    "crypto": ["CryptEncrypt", "CryptDecrypt", "BCryptEncrypt",
               "CryptHashData", "CryptDeriveKey"],
    "network": ["InternetOpen", "HttpSendRequest", "WSAStartup",
                "connect", "send", "recv", "getaddrinfo"],
    "file_ops": ["CreateFile", "WriteFile", "DeleteFile", "MoveFile",
                 "CopyFile"],
}

for category, apis in SUSPICIOUS_APIS.items():
    for api_name in apis:
        func = db.functions.get_function_by_name(api_name)
        if func:
            callers = list(db.xrefs.calls_to_ea(func.start_ea))
            if callers:
                print(f"[{category}] {api_name} called from {len(callers)} locations")
                for ea in callers[:5]:
                    caller_func = db.functions.get_at(ea)
                    if caller_func:
                        print(f"  {db.functions.get_name(caller_func)} @ {ea:#x}")
```

### Extract C2 / URLs from Strings

```python
import re

patterns = {
    "URL": re.compile(r"https?://[\w./-]+", re.I),
    "IP": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    "Domain": re.compile(r"\b[\w-]+\.(com|net|org|io|xyz|top|ru|cn)\b", re.I),
    "Registry": re.compile(r"HKEY_[\w\\]+", re.I),
    "FilePath": re.compile(r"[A-Z]:\\[\w\\.-]+", re.I),
}

for s in db.strings:
    try:
        content = str(s)
        for name, pattern in patterns.items():
            if pattern.search(content):
                print(f"[{name}] {s.address:#x}: {content[:100]}")
    except:
        continue
```

### XOR Decryption Loop Detection

```python
for func in db.functions:
    has_xor = False
    has_loop = False
    instructions = list(db.functions.get_instructions(func))

    for insn in instructions:
        mnem = db.instructions.get_mnemonic(insn)
        if mnem == "xor":
            operands = db.instructions.get_operands(insn)
            if len(operands) >= 2:
                # Skip xor reg, reg (zeroing pattern)
                op1 = operands[0].get_info()
                op2 = operands[1].get_info()
                if str(op1) != str(op2):
                    has_xor = True

    flowchart = db.functions.get_flowchart(func)
    if flowchart and len(flowchart) > 1:
        for block in flowchart:
            if block.count_successors() > 0:
                # Check for back edges (loops)
                for succ_ea in range(block.start_ea, block.end_ea):
                    for xref in db.xrefs.from_ea(succ_ea):
                        if xref.to_ea < block.start_ea:
                            has_loop = True

    if has_xor and has_loop:
        name = db.functions.get_name(func)
        print(f"[CRYPTO?] {name} @ {func.start_ea:#x} - XOR + loop detected")
```

### High Entropy Section Detection

```python
import math

def entropy(data):
    if not data:
        return 0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0
    for f in freq:
        if f > 0:
            p = f / len(data)
            ent -= p * math.log2(p)
    return ent

for seg in db.segments:
    name = db.segments.get_name(seg)
    size = db.segments.get_size(seg)
    if size > 0 and size < 10_000_000:  # Skip huge segments
        data = db.bytes.get_bytes_at(seg.start_ea, size=min(size, 65536))
        if data:
            ent = entropy(data)
            packed = "⚠️ PACKED/ENCRYPTED" if ent > 7.0 else ""
            print(f"{name}: entropy={ent:.2f} size={size} {packed}")
```

---

## Vulnerability Research

### Stack Buffer Overflow Candidates

```python
DANGEROUS_FUNCS = ["strcpy", "strcat", "sprintf", "gets", "scanf",
                   "vsprintf", "lstrcpy", "lstrcpyA", "lstrcpyW",
                   "memcpy", "memmove", "RtlCopyMemory"]

for fname in DANGEROUS_FUNCS:
    func = db.functions.get_function_by_name(fname)
    if func:
        callers = list(db.xrefs.calls_to_ea(func.start_ea))
        print(f"\n{fname}: {len(callers)} call sites")
        for ea in callers:
            caller = db.functions.get_at(ea)
            if caller:
                caller_name = db.functions.get_name(caller)
                print(f"  {caller_name} @ {ea:#x}")
```

### Format String Vulnerabilities

```python
FORMAT_FUNCS = ["printf", "fprintf", "sprintf", "snprintf",
                "wprintf", "swprintf", "syslog"]

for fname in FORMAT_FUNCS:
    func = db.functions.get_function_by_name(fname)
    if func:
        for ea in db.xrefs.calls_to_ea(func.start_ea):
            # Check if format string is a variable (not constant)
            insn = db.instructions.get_at(ea)
            if insn:
                operands = db.instructions.get_operands(insn)
                # If first arg is not a string literal → potential vuln
                for xref in db.xrefs.from_ea(ea):
                    s = db.strings.get_at(xref.to_ea)
                    if s and "%" in str(s):
                        print(f"[FMT] {fname} @ {ea:#x}: format = \"{s}\"")
```

### Integer Overflow in Allocation

```python
ALLOC_FUNCS = ["malloc", "calloc", "realloc", "HeapAlloc",
               "VirtualAlloc", "GlobalAlloc", "LocalAlloc",
               "operator new", "operator new[]"]

for fname in ALLOC_FUNCS:
    func = db.functions.get_function_by_name(fname)
    if func:
        for ea in db.xrefs.calls_to_ea(func.start_ea):
            caller = db.functions.get_at(ea)
            if caller:
                # Check for arithmetic before allocation
                for i in range(5):  # Look at 5 instructions before call
                    prev = db.instructions.get_previous(ea - i if i > 0 else ea)
                    if prev:
                        mnem = db.instructions.get_mnemonic(prev)
                        if mnem in ("mul", "imul", "shl", "add"):
                            print(f"[INT_OVERFLOW?] {fname} @ {ea:#x}, "
                                  f"arithmetic ({mnem}) before alloc in "
                                  f"{db.functions.get_name(caller)}")
```

---

## Firmware Analysis

### Identify Base Address

```python
# Look for self-referencing pointers to guess base address
import struct

# Read first 0x10000 bytes and look for pointer patterns
data = db.bytes.get_bytes_at(db.minimum_ea, size=0x10000)
if data:
    candidates = {}
    for i in range(0, len(data) - 4, 4):
        val = struct.unpack_little_endian("<I", data[i:i+4])[0]
        base_guess = val & 0xFFFF0000
        if 0x08000000 <= base_guess <= 0x20000000:  # Common ARM bases
            candidates[base_guess] = candidates.get(base_guess, 0) + 1

    for base, count in sorted(candidates.items(), key=lambda x: -x[1])[:5]:
        print(f"Base candidate: {base:#x} (confidence: {count} refs)")
```

### Peripheral Register Mapping (ARM)

```python
# Common ARM Cortex-M peripheral bases
PERIPHERALS = {
    0x40000000: "TIM2",    0x40000400: "TIM3",
    0x40004400: "USART2",  0x40004800: "USART3",
    0x40005400: "I2C1",    0x40005800: "I2C2",
    0x40010000: "AFIO",    0x40010800: "GPIOA",
    0x40010C00: "GPIOB",   0x40011000: "GPIOC",
    0x40013800: "USART1",  0x40020000: "DMA1",
    0x40021000: "RCC",     0x40022000: "FLASH",
    0xE000E000: "SCS",     0xE000E100: "NVIC",
    0xE000ED00: "SCB",     0xE000E010: "SysTick",
}

for addr, name in PERIPHERALS.items():
    refs = list(db.xrefs.to_ea(addr))
    if refs:
        db.names.set_name(addr, f"PERIPH_{name}")
        print(f"{name} ({addr:#x}): {len(refs)} references")
```

---

## General Patterns

### Function Complexity Report

```python
import json
from pathlib import Path

report = []
for func in db.functions:
    name = db.functions.get_name(func)
    size = func.end_ea - func.start_ea
    flowchart = db.functions.get_flowchart(func)
    blocks = len(flowchart) if flowchart else 0
    edges = sum(b.count_successors() for b in flowchart) if flowchart else 0
    complexity = edges - blocks + 2 if blocks > 0 else 1

    callers = len(db.functions.get_callers(func))
    callees = len(db.functions.get_callees(func))

    report.append({
        "name": name, "address": f"{func.start_ea:#x}",
        "size": size, "blocks": blocks, "complexity": complexity,
        "callers": callers, "callees": callees,
    })

report.sort(key=lambda x: x["complexity"], reverse=True)

# Top 20 most complex
for r in report[:20]:
    print(f"CC={r['complexity']:3d} blocks={r['blocks']:3d} "
          f"size={r['size']:6d} {r['name']}")

Path("/tmp/complexity_report.json").write_text(json.dumps(report, indent=2))
```

### Diff Two Binaries (Patch Analysis)

```python
# Compare function lists between two analysis sessions
# Run on patched binary, compare against baseline JSON
import json
from pathlib import Path

baseline = json.loads(Path("/tmp/baseline_functions.json").read_text())
baseline_set = {f["name"]: f for f in baseline}

current = {}
for func in db.functions:
    name = db.functions.get_name(func)
    size = func.end_ea - func.start_ea
    current[name] = {"name": name, "start": func.start_ea, "size": size}

# Find new/removed/changed
for name in current:
    if name not in baseline_set:
        print(f"[NEW] {name} @ {current[name]['start']:#x}")
    elif current[name]["size"] != baseline_set[name].get("size", 0):
        print(f"[CHANGED] {name}: size {baseline_set[name].get('size',0)} -> {current[name]['size']}")

for name in baseline_set:
    if name not in current:
        print(f"[REMOVED] {name}")
