# Headless API

**Always prefer the IDA Domain API** over the legacy IDAPython SDK when available (IDA 9.1+).

## API Architecture (IDA 9.0+)

```
┌──────────────────────────────────┐  ← Recommended (IDA 9.1+)
│  ida-domain  (pip install)       │  Pythonic: db.functions, db.xrefs
├──────────────────────────────────┤
│  idapro module  (from IDA dir)   │  Python binding for idalib
├──────────────────────────────────┤
│  idalib  (C++ shared library)    │  Embedded IDA kernel, no GUI
└──────────────────────────────────┘
```

- **ida-domain** — High-level Pythonic API (`pip install ida-domain`), requires IDA 9.1+
- **idapro** — Low-level Python module (`pip install .` from `$IDADIR/idalib/python`), exposes full IDAPython SDK headlessly
- **idalib** — C++ library (`idalib.hpp`), embed IDA engine in any C++ app

All three work **headlessly** without IDA GUI. Use `ida-domain` when possible, fall back to `idapro` for full SDK access.

## Quick Start — IDA Domain API

```bash
pip install ida-domain
```

Requires IDA Pro 9.1+ and `IDADIR` environment variable.

```python
from ida_domain import Database
from ida_domain.database import IdaCommandOptions

opts = IdaCommandOptions(auto_analysis=True, new_database=False)
with Database.open("binary", opts) as db:
    print(f"Architecture: {db.architecture}, {len(db.functions)} functions")
    for func in db.functions:
        name = db.functions.get_name(func)
        print(f"  {name}: {func.start_ea:#x} - {func.end_ea:#x}")
```

## Headless Execution

```bash
uv run python run.py script.py -f /path/to/binary
uv run python run.py -c "print(f'Functions: {len(db.functions)}')" -f binary
```

Flags: `--save` (save mods), `--timeout 0` (no timeout), `--no-wrap` (skip auto-wrapping).

## Quick Start — idalib (idapro module)

```bash
cd /path/to/IDA/idalib/python && pip install .
python /path/to/IDA/py-activate-idalib.py
export IDADIR="/Applications/IDA Pro.app/Contents/MacOS"
```

```python
import idapro  # MUST be the very first import!
idapro.open_database("binary.exe", auto_analysis=True)

import ida_funcs, idc, idautils
for ea in idautils.Functions():
    print(f"{idc.get_func_name(ea)}: {ea:#x}")

import ida_hexrays
cfunc = ida_hexrays.decompile(ea)
if cfunc:
    print(str(cfunc))

idapro.close_database()
```

## Key db Object Reference

| Accessor | Purpose |
|----------|---------|
| `db.functions` | Function enumeration, decompilation, callers/callees |
| `db.strings` | String detection and search |
| `db.xrefs` | Cross-references (code, data, call, read/write) |
| `db.bytes` | Read/write/patch bytes, search patterns |
| `db.instructions` | Instruction decode, operands, control flow |
| `db.segments` | Memory segments (name, perms, class) |
| `db.names` | Symbols, labels, demangling |
| `db.types` | Type system, struct/enum, TIL libraries |
| `db.comments` | Regular/repeatable/extra comments |
| `db.entries` | Entry points / exports |
| `db.heads` | Head iteration (instruction/data heads) |

## Common Anti-Patterns

```python
# WRONG: calling methods on func object
func.get_callers()              # AttributeError!
# RIGHT: call on db.functions
db.functions.get_callers(func)

# WRONG: old xref API
db.xrefs.get_xrefs_to(addr)    # AttributeError!
# RIGHT: new xref API
db.xrefs.to_ea(addr)

# WRONG: no error handling on decompile
lines = db.functions.get_pseudocode(func)
# RIGHT: always wrap in try-except
try:
    lines = db.functions.get_pseudocode(func)
except RuntimeError:
    pass
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `IDADIR not set` | `export IDADIR=/Applications/IDA\ Pro.app/Contents/MacOS` |
| Script timeout | Use `--timeout 0` for long analyses |
| Decompilation fails | Wrap in `try-except RuntimeError`; check Hex-Rays license |
| AttributeError on func | Call methods on `db.functions`, not on func object |
| `ModuleNotFoundError: idapro` | Run `py-activate-idalib.py` and set `IDADIR` |
| `import idapro` not first | `import idapro` **must** be the very first import statement |
| IDB locked / "database is locked" / "idb is already opened" | Previous IDA process didn't exit cleanly. Run `pkill -f ida` or `kill <pid>` to kill the stale process, then retry `open_idb`. No need to ask the user |
