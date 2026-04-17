# IDA Domain API Complete Reference

IDA Domain API for IDA Pro 9.1+. Always prefer over legacy IDAPython SDK.

**Online docs**: https://ida-domain.docs.hex-rays.com/llms.txt

## Opening a Database

```python
from ida_domain import Database
from ida_domain.database import IdaCommandOptions

opts = IdaCommandOptions(auto_analysis=True, new_database=False)
with Database.open("path/to/binary", opts, save_on_close=True) as db:
    pass
```

### Key Database Properties

```python
db.minimum_ea       # Start address
db.maximum_ea       # End address
db.metadata         # Database metadata
db.architecture     # Target architecture
db.functions        # All functions (iterable)
db.strings          # All strings (iterable)
db.segments         # Memory segments
db.names            # Symbols and labels
db.entries          # Entry points
db.types            # Type definitions
db.comments         # All comments
db.xrefs            # Cross-reference utilities
db.bytes            # Byte manipulation
db.instructions     # Instruction access
```

---

## Functions

### Iterating

```python
for func in db.functions:
    print(db.functions.get_name(func))

count = len(db.functions)
```

### Finding

```python
func = db.functions.get_at(0x401000)
func = db.functions.get_function_by_name("main")
func = db.functions.get_next(ea)

for func in db.functions.get_between(start_ea, end_ea):
    print(func.start_ea)
```

### Properties

```python
name = db.functions.get_name(func)
signature = db.functions.get_signature(func)
flags = db.functions.get_flags(func)  # FunctionFlags
db.functions.is_far(func)
db.functions.does_return(func)
```

### Code

```python
lines = db.functions.get_disassembly(func, remove_tags=True)
pseudocode = db.functions.get_pseudocode(func, remove_tags=True)
microcode = db.functions.get_microcode(func, remove_tags=True)
```

### Analysis

```python
for insn in db.functions.get_instructions(func):
    print(insn.ea)

flowchart = db.functions.get_flowchart(func)
for block in flowchart:
    print(f"Block: {block.start_ea:#x} - {block.end_ea:#x}")

callers = db.functions.get_callers(func)
callees = db.functions.get_callees(func)

for chunk in db.functions.get_chunks(func):
    print(f"Chunk: {chunk.start_ea:#x}, main={chunk.is_main}")

for data_ea in db.functions.get_data_items(func):
    print(f"Data at {data_ea:#x}")
```

### Local Variables

```python
lvars = db.functions.get_local_variables(func)
for lvar in lvars:
    print(f"{lvar.name}: {lvar.type_str}, arg={lvar.is_argument}")

lvar = db.functions.get_local_variable_by_name(func, "result")

refs = db.functions.get_local_variable_references(func, lvar)
for ref in refs:
    print(f"Line {ref.line_number}: {ref.access_type} in {ref.context}")
```

### Modifying

```python
db.functions.set_name(func, "new_name")
db.functions.set_comment(func, "This function does X", repeatable=False)
db.functions.create(ea)
db.functions.remove(ea)
```

---

## Instructions

### Iterating

```python
for insn in db.instructions:
    print(db.instructions.get_disassembly(insn))

for insn in db.instructions.get_between(start_ea, end_ea):
    print(insn.ea)
```

### Getting

```python
insn = db.instructions.get_at(ea)
insn = db.instructions.get_previous(ea)
```

### Properties

```python
disasm = db.instructions.get_disassembly(insn)
mnemonic = db.instructions.get_mnemonic(insn)
db.instructions.is_valid(insn)
```

### Control Flow

```python
db.instructions.is_call_instruction(insn)
db.instructions.is_indirect_jump_or_call(insn)
db.instructions.breaks_sequential_flow(insn)
```

### Operands

```python
count = db.instructions.get_operands_count(insn)
operands = db.instructions.get_operands(insn)

for op in operands:
    info = op.get_info()
    print(f"Operand {op.number}: {op.type.name}")

    if isinstance(op, RegisterOperand):
        print(f"  Register: {op.get_register_name()}")
    elif isinstance(op, ImmediateOperand):
        print(f"  Value: 0x{op.get_value():x}")
    elif isinstance(op, MemoryOperand):
        if op.is_direct_memory():
            print(f"  Memory: 0x{op.get_address():x}")
```

---

## Segments

### Iterating

```python
for segment in db.segments:
    name = db.segments.get_name(segment)
    size = db.segments.get_size(segment)
    print(f"{name}: {segment.start_ea:#x} - {segment.end_ea:#x}")

count = len(db.segments)
```

### Finding

```python
seg = db.segments.get_at(0x401000)       # By address
seg = db.segments.get_by_name(".text")   # By name
```

### Properties

```python
name = db.segments.get_name(segment)
size = db.segments.get_size(segment)
bitness = db.segments.get_bitness(segment)   # 16, 32, 64
seg_class = db.segments.get_class(segment)    # "CODE", "DATA"
```

### Creating

```python
from ida_domain.segments import PredefinedClass, AddSegmentFlags

seg = db.segments.add(
    seg_para=0, start_ea=0x1000, end_ea=0x2000,
    seg_name="MySegment", seg_class=PredefinedClass.CODE
)
seg = db.segments.append(seg_para=0, seg_size=0x1000, seg_name="NewSeg")
```

### Modifying

```python
from ida_domain.segments import SegmentPermissions, AddressingMode

db.segments.set_name(segment, "new_name")
db.segments.set_permissions(segment, SegmentPermissions.READ | SegmentPermissions.EXEC)
db.segments.add_permissions(segment, SegmentPermissions.WRITE)
db.segments.remove_permissions(segment, SegmentPermissions.WRITE)
db.segments.set_addressing_mode(segment, AddressingMode.BIT64)
db.segments.set_comment(segment, "Code section", repeatable=False)
```

---

## Strings

### Iterating

```python
for string in db.strings:
    print(f"{string.address:#x}: {string}")

first_string = db.strings[0]
count = len(db.strings)
```

### Finding

```python
string = db.strings.get_at(0x402000)

for s in db.strings.get_between(start_ea, end_ea):
    print(s.contents)
```

### Properties

```python
string.address       # Address
string.length        # Length in characters
string.type          # StringType enum
string.encoding      # Internal encoding
string.contents      # UTF-8 bytes
str(string)          # Decoded string
```

### Rebuilding

```python
from ida_domain.strings import StringListConfig, StringType

config = StringListConfig(
    string_types=[StringType.C, StringType.C_16],
    min_len=3, only_ascii_7bit=False
)
db.strings.rebuild(config)
db.strings.clear()
```

---

## Cross-References (Xrefs)

### References TO

```python
for xref in db.xrefs.to_ea(target_ea):
    print(f"{xref.from_ea:#x} -> {xref.to_ea:#x} ({xref.type.name})")

for ea in db.xrefs.code_refs_to_ea(target_ea, flow=False):
    print(f"Code ref from {ea:#x}")

for ea in db.xrefs.data_refs_to_ea(target_ea):
    print(f"Data ref from {ea:#x}")

for ea in db.xrefs.calls_to_ea(func_ea):
    print(f"Called from {ea:#x}")

for caller in db.xrefs.get_callers(func_ea):
    print(f"Called from {caller.name} at {caller.ea:#x}")
```

### References FROM

```python
for xref in db.xrefs.from_ea(source_ea):
    print(f"{xref.from_ea:#x} -> {xref.to_ea:#x}")

for ea in db.xrefs.code_refs_from_ea(source_ea):
    print(f"Code ref to {ea:#x}")

for ea in db.xrefs.calls_from_ea(source_ea):
    print(f"Calls {ea:#x}")
```

### Data Access

```python
for ea in db.xrefs.reads_of_ea(data_ea):
    print(f"Read by {ea:#x}")

for ea in db.xrefs.writes_to_ea(data_ea):
    print(f"Written by {ea:#x}")
```

### XrefInfo Properties

```python
xref.is_call     # Call reference
xref.is_jump     # Jump reference
xref.is_read     # Data read
xref.is_write    # Data write
xref.is_flow     # Ordinary flow
xref.user        # User-defined
```

---

## Names

### Iterating

```python
for ea, name in db.names:
    print(f"{ea:#x}: {name}")
count = len(db.names)
```

### Getting / Setting

```python
name = db.names.get_at(0x401000)
ea, name = db.names[0]

from ida_domain.names import SetNameFlags
db.names.set_name(ea, "my_function")
db.names.force_name(ea, "func")     # Creates func_2 if exists
db.names.delete(ea)
```

### Properties

```python
db.names.is_valid_name("my_name")
db.names.is_public_name(ea)
db.names.is_weak_name(ea)
db.names.make_name_public(ea)
db.names.make_name_non_public(ea)
```

### Demangling

```python
from ida_domain.names import DemangleFlags
demangled = db.names.get_demangled_name(ea)
demangled = db.names.demangle_name("?main@@YAXXZ")
```

---

## Types

### Getting

```python
tinfo = db.types.get_by_name("MyStruct")
tinfo = db.types.get_at(ea)

for tinfo in db.types:
    print(tinfo)
```

### Parsing

```python
db.types.parse_declarations(None, "struct Point { int x; int y; };")
tinfo = db.types.parse_one_declaration(None, "int (*callback)(void*)", "callback_t")
errors = db.types.parse_header_file(library, Path("header.h"))
```

### Applying

```python
from ida_domain.types import TypeApplyFlags
db.types.apply_at(tinfo, ea, flags=TypeApplyFlags.DEFINITE)
```

### Details

```python
details = db.types.get_details(tinfo)
print(details.name, details.size, details.attributes)

if details.udt:      # struct/union
    print(details.udt.num_members)
if details.func:     # function type
    print(details.func.attributes)
```

### Type Libraries

```python
lib = db.types.load_library(Path("types.til"))
lib = db.types.create_library(Path("new.til"), "My Types")
db.types.import_type(source_lib, "MyStruct")
db.types.export_type(dest_lib, "MyStruct")
db.types.save_library(lib, Path("output.til"))
db.types.unload_library(lib)
```

---

## Bytes

### Reading

```python
byte = db.bytes.get_byte_at(ea)
word = db.bytes.get_word_at(ea)
dword = db.bytes.get_dword_at(ea)
qword = db.bytes.get_qword_at(ea)
data = db.bytes.get_bytes_at(ea, size=16)
original = db.bytes.get_original_bytes_at(ea, size=16)
string = db.bytes.get_string_at(ea)
cstring = db.bytes.get_cstring_at(ea, max_length=256)
```

### Writing

```python
db.bytes.set_byte_at(ea, 0x90)
db.bytes.set_word_at(ea, 0x1234)
db.bytes.set_dword_at(ea, 0x12345678)
db.bytes.set_qword_at(ea, 0x123456789ABCDEF0)
db.bytes.set_bytes_at(ea, b"\x90\x90\x90")
```

### Patching (with history)

```python
db.bytes.patch_byte_at(ea, 0x90)
db.bytes.patch_bytes_at(ea, data)
db.bytes.revert_byte_at(ea)
orig = db.bytes.get_original_byte_at(ea)
```

### Searching

```python
from ida_domain.bytes import SearchFlags

ea = db.bytes.find_bytes_between(b"\x55\x89\xe5", start_ea, end_ea)
addresses = db.bytes.find_binary_sequence(b"\x90\x90")
ea = db.bytes.find_text_between("error", flags=SearchFlags.DOWN)
ea = db.bytes.find_immediate_between(0x1234)
```

### Creating Data Items

```python
from ida_domain.strings import StringType

db.bytes.create_byte_at(ea, count=4)
db.bytes.create_word_at(ea)
db.bytes.create_dword_at(ea, count=10)  # Array
db.bytes.create_qword_at(ea)
db.bytes.create_float_at(ea)
db.bytes.create_double_at(ea)
db.bytes.create_string_at(ea, string_type=StringType.C)
db.bytes.create_struct_at(ea, count=1, tid=struct_tid)
```

### Querying Properties

```python
size = db.bytes.get_data_size_at(ea)
db.bytes.is_value_initialized_at(ea)
db.bytes.is_code_at(ea)
db.bytes.is_data_at(ea)
db.bytes.is_head_at(ea)
db.bytes.is_unknown_at(ea)
disasm = db.bytes.get_disassembly_at(ea)
```

### Navigation

```python
next_head = db.bytes.get_next_head(ea)
prev_head = db.bytes.get_previous_head(ea)
next_addr = db.bytes.get_next_address(ea)
prev_addr = db.bytes.get_previous_address(ea)
```

---

## Comments

### Regular

```python
from ida_domain.comments import CommentKind

info = db.comments.get_at(ea, CommentKind.REGULAR)
if info:
    print(info.comment)

db.comments.set_at(ea, "Important", CommentKind.REGULAR)
db.comments.set_at(ea, "Shows everywhere", CommentKind.REPEATABLE)
db.comments.delete_at(ea, CommentKind.ALL)
```

### Iterating

```python
for info in db.comments:
    print(f"{info.ea:#x}: {info.comment}")

for info in db.comments.get_all(CommentKind.ALL):
    print(f"{info.ea:#x} (repeatable={info.repeatable}): {info.comment}")
```

### Extra (Anterior/Posterior)

```python
from ida_domain.comments import ExtraCommentKind

db.comments.set_extra_at(ea, 0, "Before line", ExtraCommentKind.ANTERIOR)
db.comments.set_extra_at(ea, 0, "After line", ExtraCommentKind.POSTERIOR)
comment = db.comments.get_extra_at(ea, 0, ExtraCommentKind.ANTERIOR)
db.comments.delete_extra_at(ea, 0, ExtraCommentKind.ANTERIOR)
```

---

## Entries

### Iterating

```python
for entry in db.entries:
    print(f"{entry.ordinal}: {entry.name} at {entry.address:#x}")

count = len(db.entries)
```

### Finding

```python
entry = db.entries.get_at(ea)
entry = db.entries.get_by_ordinal(1)
entry = db.entries.get_by_name("main")
```

### Modifying

```python
db.entries.add(address=ea, name="new_entry", ordinal=10)
db.entries.rename(ordinal=10, new_name="renamed")
db.entries.set_forwarder(ordinal=10, forwarder_name="other.dll!func")
```

---

## Flowchart

```python
from ida_domain.flowchart import FlowChartFlags

flowchart = db.functions.get_flowchart(func)
for block in flowchart:
    print(f"Block {block.start_ea:#x} - {block.end_ea:#x}")
    successors = block.count_successors()
    predecessors = block.count_predecessors()

    for insn in block:
        print(f"  {insn.ea:#x}")
```

---

## Common Patterns

### Find All Calls to a Function

```python
func = db.functions.get_function_by_name("malloc")
if func:
    for caller in db.xrefs.get_callers(func.start_ea):
        print(f"Called from {caller.name} at {caller.ea:#x}")
```

### Auto-Rename by String References

```python
for func in db.functions:
    for insn in db.functions.get_instructions(func):
        for xref in db.xrefs.from_ea(insn.ea):
            string = db.strings.get_at(xref.to_ea)
            if string and "error" in str(string).lower():
                db.functions.set_name(func, f"func_with_error_{func.start_ea:x}")
                break
```

### Cyclomatic Complexity

```python
func = db.functions.get_at(ea)
flowchart = db.functions.get_flowchart(func)
total_edges = sum(block.count_successors() for block in flowchart)
complexity = total_edges - len(flowchart) + 2
print(f"Cyclomatic complexity: {complexity}")
```

### Export All Pseudocode

```python
for func in db.functions:
    name = db.functions.get_name(func)
    try:
        pseudocode = db.functions.get_pseudocode(func)
        print(f"// {name}")
        for line in pseudocode:
            print(line)
    except RuntimeError:
        print(f"// Could not decompile {name}")
```

### String Cross-References

```python
for string in db.strings:
    refs = list(db.xrefs.to_ea(string.address))
    if refs:
        print(f'"{string}" referenced from:')
        for xref in refs:
            print(f"  {xref.from_ea:#x}")
```

---

## Enum Reference

Key enums used across the API:

| Enum | Values |
|------|--------|
| `XrefType` | `CODE_NEAR`, `CODE_FAR`, `DATA_OFFSET`, `DATA_WRITE`, `DATA_READ`, `DATA_STRUCT`, `ORDINARY_FLOW` |
| `FunctionFlags` | `NORET`, `FAR`, `LIB`, `STATIC`, `FRAME`, `FUZZY_SP`, `THUNK` |
| `OperandType` | `VOID`, `REGISTER`, `MEMORY`, `PHRASE`, `DISPLACEMENT`, `IMMEDIATE`, `FAR`, `NEAR` |
| `StringType` | `C`, `C_16`, `C_32`, `PASCAL`, `PASCAL_16`, `LEN2`, `LEN4`, `LEN2_16` |
| `SegmentPermissions` | `READ`, `WRITE`, `EXEC` |
| `CommentKind` | `REGULAR`, `REPEATABLE`, `ALL` |
| `FlowChartFlags` | `NORMAL`, `NO_EXTERNAL` |

---

## Legacy API Note

When using legacy IDAPython (pre-9.1 or when Domain API is unavailable), see [idapython-cheatsheet.md](idapython-cheatsheet.md). Always prefer Domain API when possible.
