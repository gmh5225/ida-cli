# IDAPython Legacy SDK Cheatsheet

Use when IDA Domain API is unavailable (IDA < 9.1) or for features not yet in Domain API.

## Core Modules

| Module | Purpose |
|--------|---------|
| `idaapi` | Core API, database access, types |
| `idautils` | Utility functions (iterations, searches) |
| `idc` | IDC compatibility layer |
| `ida_bytes` | Byte/data manipulation |
| `ida_funcs` | Function management |
| `ida_name` | Name/label operations |
| `ida_segment` | Segment operations |
| `ida_xref` | Cross-references |
| `ida_hexrays` | Hex-Rays decompiler |
| `ida_search` | Search operations |
| `ida_struct` | Structure management |
| `ida_enum` | Enumeration management |
| `ida_nalt` | Netnode alt values |
| `ida_ua` | Instruction decoding |
| `ida_gdl` | Graph/flowchart |
| `ida_typeinf` | Type information |
| `ida_frame` | Stack frame variables |
| `ida_dbg` | Built-in debugger control |
| `ida_idd` | Debugger interface details |
| `ida_entry` | Entry point management |
| `ida_loader` | File loading |
| `ida_kernwin` | UI interaction |

## Functions

```python
import ida_funcs, idautils, idc

# Iterate all functions
for ea in idautils.Functions():
    name = idc.get_func_name(ea)
    func = ida_funcs.get_func(ea)
    print(f"{name}: {ea:#x} - {func.end_ea:#x}")

# Get function at address
func = ida_funcs.get_func(ea)
name = ida_funcs.get_func_name(ea)

# Create/delete function
ida_funcs.add_func(start_ea, end_ea)
ida_funcs.del_func(ea)

# Rename function
idc.set_name(ea, "new_name", idc.SN_NOWARN)

# Function flags
func.flags & ida_funcs.FUNC_NORET   # No return
func.flags & ida_funcs.FUNC_LIB     # Library function
func.flags & ida_funcs.FUNC_THUNK   # Thunk function
```

## Decompilation (Hex-Rays)

```python
import ida_hexrays

# Decompile function
cfunc = ida_hexrays.decompile(ea)
if cfunc:
    print(cfunc)  # Print pseudocode

    # Access AST
    for item in cfunc.treeitems:
        if item.op == ida_hexrays.cot_call:
            print(f"Call at {item.ea:#x}")

# Check Hex-Rays availability
if ida_hexrays.init_hexrays_plugin():
    print("Hex-Rays available")
```

## Cross-References

```python
import idautils

# Code refs TO address
for ref in idautils.CodeRefsTo(ea, flow=False):
    print(f"Code ref from {ref:#x}")

# Code refs FROM address
for ref in idautils.CodeRefsFrom(ea, flow=False):
    print(f"Code ref to {ref:#x}")

# Data refs TO/FROM
for ref in idautils.DataRefsTo(ea):
    print(f"Data ref from {ref:#x}")

for ref in idautils.DataRefsFrom(ea):
    print(f"Data ref to {ref:#x}")

# All xrefs TO
for xref in idautils.XrefsTo(ea, flags=0):
    print(f"{xref.frm:#x} -> {xref.to:#x} type={xref.type}")
```

## Bytes and Data

```python
import ida_bytes, idc

# Read
byte = ida_bytes.get_byte(ea)
word = ida_bytes.get_word(ea)
dword = ida_bytes.get_dword(ea)
qword = ida_bytes.get_qword(ea)
data = ida_bytes.get_bytes(ea, size)

# Write
ida_bytes.put_byte(ea, val)
ida_bytes.put_word(ea, val)
ida_bytes.put_dword(ea, val)

# Patch (with undo)
ida_bytes.patch_byte(ea, val)
ida_bytes.patch_word(ea, val)
ida_bytes.patch_dword(ea, val)
ida_bytes.revert_byte(ea)

# Get original (pre-patch)
orig = ida_bytes.get_original_byte(ea)

# Create data
idc.create_byte(ea)
idc.create_word(ea)
idc.create_dword(ea)
idc.create_qword(ea)
ida_bytes.create_strlit(ea, length, idc.STRTYPE_C)
```

## Strings

```python
import idautils, idc

# Iterate all strings
for s in idautils.Strings():
    print(f"{s.ea:#x}: {str(s)}")

# Get string at address
string = idc.get_strlit_contents(ea, -1, idc.STRTYPE_C)
if string:
    print(string.decode('utf-8', errors='replace'))
```

## Segments

```python
import ida_segment, idautils

# Iterate segments
for seg_ea in idautils.Segments():
    seg = ida_segment.getseg(seg_ea)
    name = ida_segment.get_segm_name(seg)
    print(f"{name}: {seg.start_ea:#x} - {seg.end_ea:#x}")

# Find segment
seg = ida_segment.get_segm_by_name(".text")

# Segment properties
perm = seg.perm  # ida_segment.SFL_* flags
bitness = seg.bitness  # 0=16, 1=32, 2=64
```

## Structures

```python
import ida_struct, idc

# Create struct
sid = ida_struct.add_struc(-1, "MyStruct", False)
sptr = ida_struct.get_struc(sid)

# Add members
ida_struct.add_struc_member(sptr, "field1", 0, idc.FF_DWORD, None, 4)
ida_struct.add_struc_member(sptr, "field2", 4, idc.FF_BYTE, None, 32)

# Get struct by name
sid = ida_struct.get_struc_id("MyStruct")
sptr = ida_struct.get_struc(sid)
size = ida_struct.get_struc_size(sptr)

# Iterate members
for i in range(sptr.memqty):
    member = sptr.get_member(i)
    name = ida_struct.get_member_name(member.id)
    offset = member.soff
    print(f"  +{offset:#x}: {name}")
```

## Enumerations

```python
import ida_enum

# Create enum
eid = ida_enum.add_enum(-1, "MyEnum", 0)

# Add members
ida_enum.add_enum_member(eid, "VALUE_A", 0)
ida_enum.add_enum_member(eid, "VALUE_B", 1)
ida_enum.add_enum_member(eid, "VALUE_C", 2)

# Get enum
eid = ida_enum.get_enum("MyEnum")
size = ida_enum.get_enum_size(eid)
```

## Search

```python
import ida_search, idc

# Search for bytes
ea = ida_search.find_binary(start_ea, end_ea, "55 48 89 E5",
                            16, ida_search.SEARCH_DOWN)

# Search for text
ea = ida_search.find_text(start_ea, 0, 0, "error",
                          ida_search.SEARCH_DOWN)

# Search for immediate value
ea = ida_search.find_imm(start_ea, ida_search.SEARCH_DOWN, 0x1234)
```

## Instructions

```python
import ida_ua, idautils, idc

# Decode instruction
insn = ida_ua.insn_t()
ida_ua.decode_insn(insn, ea)
mnem = insn.get_canon_mnem()

# Iterate instructions in function
for ea in idautils.FuncItems(func_ea):
    mnem = idc.print_insn_mnem(ea)
    op1 = idc.print_operand(ea, 0)
    op2 = idc.print_operand(ea, 1)
    print(f"{ea:#x}: {mnem} {op1}, {op2}")

# Disassembly text
disasm = idc.GetDisasm(ea)
disasm = idc.generate_disasm_line(ea, 0)
```

## Comments

```python
import idc

# Regular comment
idc.set_cmt(ea, "my comment", False)
cmt = idc.get_cmt(ea, False)

# Repeatable comment
idc.set_cmt(ea, "repeated", True)

# Function comment
idc.set_func_cmt(ea, "func comment", False)
```

## Names and Labels

```python
import idc, ida_name

# Set name
idc.set_name(ea, "my_label", idc.SN_NOWARN)

# Get name
name = idc.get_name(ea)
name = ida_name.get_name(ea)

# Demangle
demangled = ida_name.demangle_name(mangled, 0)

# Get all names
import idautils
for ea, name in idautils.Names():
    print(f"{ea:#x}: {name}")
```

## Scripting / Batch Mode

```bash
# Run script headless (idat = text mode)
idat -A -S"script.py" binary.exe

# With arguments
idat -A -S"script.py arg1 arg2" binary.exe

# Analysis only, then quit
idat -A -B binary.exe
```

In script:

```python
import idc
idc.auto_wait()           # Wait for auto-analysis
# ... your analysis ...
idc.qexit(0)              # Exit IDA
```

## Useful Patterns

### Export All Functions to JSON

```python
import json, idautils, idc

functions = []
for ea in idautils.Functions():
    functions.append({
        "name": idc.get_func_name(ea),
        "start": f"{ea:#x}",
        "end": f"{ida_funcs.get_func(ea).end_ea:#x}"
    })

with open("/tmp/functions.json", "w") as f:
    json.dump(functions, f, indent=2)
```

### Find Crypto Constants

```python
import ida_search

CRYPTO_CONSTANTS = {
    "AES S-Box": "63 7C 77 7B F2 6B 6F C5",
    "SHA-256 Init": "67 E6 09 6A 85 AE 67 BB",
    "RC4 Init": "00 01 02 03 04 05 06 07",
}

for name, pattern in CRYPTO_CONSTANTS.items():
    ea = ida_search.find_binary(0, idc.BADADDR, pattern, 16,
                                 ida_search.SEARCH_DOWN)
    if ea != idc.BADADDR:
        print(f"Found {name} at {ea:#x}")
        idc.set_name(ea, f"crypto_{name.replace(' ', '_').lower()}")
```

---

## Stack Frame Variables

```python
import ida_frame, ida_funcs, ida_typeinf, idaapi

func = ida_funcs.get_func(ea)
if not func:
    raise ValueError("No function at address")

# Get stack frame as tinfo_t
frame_tif = ida_typeinf.tinfo_t()
ida_frame.get_func_frame(frame_tif, func)

# Iterate stack variables (UDM = User Defined Member)
for i in range(frame_tif.get_udt_nmembers()):
    udm = ida_typeinf.udm_t()
    frame_tif.get_udm_by_idx(udm, i)
    name = udm.name
    offset = udm.offset // 8  # Bits to bytes
    size = udm.size // 8
    type_name = udm.type.dstr()
    print(f"  [{offset:#x}] {name}: {type_name} ({size} bytes)")

# Create stack variable
tif = ida_typeinf.tinfo_t()
ida_typeinf.parse_decl(tif, None, "int myvar;", 0)
ida_frame.define_stkvar(func, "my_local", offset, tif)

# Delete stack variable
udm = ida_typeinf.udm_t()
idx, _ = frame_tif.get_udm("my_local")
frame_tif.get_udm_by_idx(udm, idx)
offset = udm.offset // 8
size = udm.size // 8
ida_frame.delete_frame_members(func, offset, offset + size)

# Check if offset is function argument
if ida_frame.is_funcarg_off(func, offset):
    print("This is a function argument, not a local")

# Get frame size
frame_size = ida_frame.get_frame_size(func)
local_size = ida_frame.get_frame_locals_size(func)
arg_size = ida_frame.get_frame_args_size(func)
```

## Instruction Sequence Search

```python
import ida_ua, idautils, idc, ida_search

def find_insn_sequence(start_ea, end_ea, pattern):
    """Find instruction sequences matching a pattern.
    
    pattern: list of (mnemonic, [operand_patterns...]) or (mnemonic, None)
    Returns list of match start addresses.
    
    Example: find_insn_sequence(0, BADADDR, [
        ("push", ["rbp"]),
        ("mov", ["rbp", "rsp"]),
    ])
    """
    results = []
    ea = start_ea
    while ea < end_ea and ea != idc.BADADDR:
        # Try to match pattern starting at this address
        match_ea = ea
        matched = True
        curr = ea
        for mnem_pat, op_pats in pattern:
            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, curr)
            if length == 0:
                matched = False
                break
            mnem = insn.get_canon_mnem().lower()
            if mnem != mnem_pat.lower():
                matched = False
                break
            if op_pats:
                for i, op_pat in enumerate(op_pats):
                    if op_pat is None:
                        continue
                    actual = idc.print_operand(curr, i).lower()
                    if op_pat.lower() not in actual:
                        matched = False
                        break
            if not matched:
                break
            curr = idc.next_head(curr)
        if matched:
            results.append(match_ea)
        ea = idc.next_head(ea)
    return results

# Usage examples:
# Find all function prologues
prologues = find_insn_sequence(0, idc.BADADDR, [
    ("push", ["rbp"]),
    ("mov", ["rbp", "rsp"]),
])

# Find all call-then-test patterns (common error checking)
call_test = find_insn_sequence(text_start, text_end, [
    ("call", None),
    ("test", ["eax", "eax"]),
    ("jz", None),
])

# Find specific byte patterns (simpler)
ea = ida_search.find_binary(0, idc.BADADDR, "55 48 89 E5", 16,
                            ida_search.SEARCH_DOWN)
while ea != idc.BADADDR:
    print(f"Match at {ea:#x}")
    ea = ida_search.find_binary(ea + 1, idc.BADADDR, "55 48 89 E5", 16,
                                ida_search.SEARCH_DOWN)
```

## Type Inference (Hex-Rays)

```python
import ida_hexrays, ida_typeinf, idc

# Infer types using Hex-Rays decompiler
def infer_function_types(ea):
    """Use Hex-Rays to infer variable types in a function."""
    cfunc = ida_hexrays.decompile(ea)
    if not cfunc:
        return None

    results = {"args": [], "locals": []}
    
    # Function signature (return type + params)
    func_type = cfunc.type.dstr()
    results["signature"] = func_type

    # Local variables with inferred types
    for lvar in cfunc.get_lvars():
        info = {
            "name": lvar.name,
            "type": lvar.type().dstr(),
            "is_arg": lvar.is_arg_var,
            "is_stk": lvar.is_stk_var(),
            "width": lvar.width,
        }
        if lvar.is_arg_var:
            results["args"].append(info)
        else:
            results["locals"].append(info)
    return results

# Apply inferred type to a function
def apply_type(ea, type_str):
    """Apply a C type declaration to a function or global."""
    tif = ida_typeinf.tinfo_t()
    if ida_typeinf.parse_decl(tif, None, f"{type_str};", 0):
        ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
        return True
    return False

# Apply type from decompiler
apply_type(func_ea, "int __fastcall my_func(int a, char *b)")

# Set local variable type in decompiler
def set_lvar_type(func_ea, var_name, type_str):
    """Set type of a local variable in decompiled output."""
    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        return False
    for lvar in cfunc.get_lvars():
        if lvar.name == var_name:
            tif = ida_typeinf.tinfo_t()
            if ida_typeinf.parse_decl(tif, None, f"{type_str} x;", 0):
                lvar.set_lvar_type(tif)
                cfunc.build_c_tree()  # Rebuild
                return True
    return False

# Declare C types in local type library
ida_typeinf.parse_decl(None, None, """
struct MyPacket {
    uint32_t magic;
    uint16_t version;
    uint16_t length;
    uint8_t data[0];
};
""", ida_typeinf.PT_TYP)
```

## Export Functions

```python
import json, idautils, idc, ida_funcs, ida_hexrays

# Export all functions to JSON
def export_functions_json(output_path):
    """Export all functions with metadata to JSON."""
    functions = []
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        entry = {
            "name": idc.get_func_name(ea),
            "start": f"{ea:#x}",
            "end": f"{func.end_ea:#x}",
            "size": func.end_ea - ea,
            "flags": [],
        }
        if func.flags & ida_funcs.FUNC_NORET:
            entry["flags"].append("noreturn")
        if func.flags & ida_funcs.FUNC_LIB:
            entry["flags"].append("library")
        if func.flags & ida_funcs.FUNC_THUNK:
            entry["flags"].append("thunk")

        # Try to get type signature
        tif = ida_typeinf.tinfo_t()
        if ida_typeinf.get_tinfo(tif, ea):
            entry["prototype"] = tif.dstr()

        functions.append(entry)

    with open(output_path, "w") as f:
        json.dump(functions, f, indent=2)
    print(f"Exported {len(functions)} functions to {output_path}")

# Export as C header
def export_c_header(output_path, func_eas=None):
    """Export function prototypes as C header."""
    if func_eas is None:
        func_eas = list(idautils.Functions())

    with open(output_path, "w") as f:
        f.write("// Auto-generated function prototypes\n")
        f.write(f"// Binary: {idc.get_input_file_path()}\n\n")
        for ea in func_eas:
            tif = ida_typeinf.tinfo_t()
            if ida_typeinf.get_tinfo(tif, ea):
                name = idc.get_func_name(ea)
                f.write(f"// {ea:#x}\n")
                f.write(f"{tif.dstr().replace('__fastcall', '')} {name};\n\n")

# Export decompiled pseudocode
def export_pseudocode(output_dir, func_eas=None):
    """Export decompiled code for each function."""
    from pathlib import Path
    out = Path(output_dir)
    out.mkdir(exist_ok=True)
    if func_eas is None:
        func_eas = list(idautils.Functions())
    for ea in func_eas:
        name = idc.get_func_name(ea)
        try:
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                (out / f"{name}.c").write_text(str(cfunc))
        except:
            pass

# Batch rename (common pattern)
def batch_rename(renames: dict):
    """Rename multiple items. renames = {addr_or_name: new_name}"""
    for target, new_name in renames.items():
        if isinstance(target, str):
            ea = idc.get_name_ea_simple(target)
        else:
            ea = target
        if ea != idc.BADADDR:
            idc.set_name(ea, new_name, idc.SN_NOWARN | idc.SN_FORCE)
```

## IDA Built-in Debugger (`ida_dbg`)

```python
import ida_dbg, ida_idd, idaapi

# --- Process Control ---
# Start debugging
idaapi.start_process("", "", "")   # path, args, cwd
ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)  # Wait for stop

# Continue / Step
idaapi.continue_process()
idaapi.step_into()
idaapi.step_over()
idaapi.run_to(target_ea)           # Run until address
idaapi.exit_process()

# Check state
ip = ida_dbg.get_ip_val()          # Current instruction pointer
if ip is None:
    print("Debugger not running")

# --- Breakpoints ---
# Add/remove
idaapi.add_bpt(ea, 0, idaapi.BPT_SOFT)   # Software breakpoint
idaapi.add_bpt(ea, 4, idaapi.BPT_RDWR)   # Hardware r/w watchpoint
idaapi.del_bpt(ea)

# Enable/disable
idaapi.enable_bpt(ea, True)
idaapi.enable_bpt(ea, False)

# List all breakpoints
for i in range(ida_dbg.get_bpt_qty()):
    bpt = ida_dbg.bpt_t()
    if ida_dbg.getn_bpt(i, bpt):
        enabled = bool(bpt.flags & ida_dbg.BPT_ENABLED)
        print(f"BP {bpt.ea:#x} enabled={enabled}")

# Conditional breakpoint
bpt = ida_dbg.bpt_t()
if ida_dbg.get_bpt(ea, bpt):
    bpt.condition = "RAX == 0"
    ida_dbg.update_bpt(bpt)

# --- Registers ---
# Get all registers (current thread)
tid = ida_dbg.get_current_thread()
regvals = ida_dbg.get_reg_vals(tid)
dbg = ida_idd.get_dbg()
for i, rv in enumerate(regvals):
    reg_info = dbg.regs(i)
    try:
        val = rv.pyval(reg_info.dtype)
        if isinstance(val, int):
            print(f"{reg_info.name} = {val:#x}")
    except ValueError:
        pass

# Read specific register
rax = ida_dbg.get_reg_val("RAX")
rip = ida_dbg.get_reg_val("RIP")

# Set register
ida_dbg.set_reg_val("RAX", 0x42)

# --- Memory (debugged process) ---
# Read
data = ida_dbg.dbg_read_memory(addr, size)

# Write
ida_dbg.dbg_write_memory(addr, bytes_data)

# --- Stack Trace ---
# Get call stack
trace = ida_dbg.collect_stack_trace(tid)
if trace:
    for i in range(trace.size()):
        frame = trace[i]
        print(f"  {frame.callea:#x}")

# --- Threads ---
threads = ida_dbg.get_thread_qty()
for i in range(threads):
    tid = ida_dbg.getn_thread(i)
    name = ida_dbg.get_thread_name(tid)
    print(f"Thread {tid}: {name}")

# Switch thread
ida_dbg.select_thread(tid)

# --- Event loop (for automation) ---
def debug_until(target_ea, max_events=1000):
    """Run debugger until target address is hit."""
    idaapi.start_process("", "", "")
    for _ in range(max_events):
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
        ip = ida_dbg.get_ip_val()
        if ip == target_ea:
            return True
        idaapi.continue_process()
    return False
```
