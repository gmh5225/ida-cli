# ida-mcp

Headless IDA Pro MCP server for AI-assisted binary analysis, powered by [idalib](https://docs.hex-rays.com/release-notes/9_0#idalib-the-idapro-library).

## Overview

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes 73 IDA Pro tools — decompilation, disassembly, cross-references, type reconstruction, IDAPython scripting, and more — to any MCP-compatible AI client. Runs entirely headless via idalib; no GUI required.

Ships with an [OpenCode](https://opencode.ai) AI skill (`skill/`) for structured reverse engineering workflows.

## Prerequisites

- IDA Pro 9.2+ with valid license and Hex-Rays decompiler
- Rust 1.77+ (if building from source)

## Getting Started

### Build from Source

See [docs/BUILDING.md](docs/BUILDING.md).

### Platform Setup

#### macOS

Standard IDA installations in `/Applications` work automatically:
```bash
claude mcp add ida -- ida-mcp
```

If you see `Library not loaded: @rpath/libida.dylib`, set `DYLD_LIBRARY_PATH`:
```bash
claude mcp add ida -e DYLD_LIBRARY_PATH='/path/to/IDA.app/Contents/MacOS' -- ida-mcp
```

Supported paths (auto-detected):
- `/Applications/IDA Professional 9.3.app/Contents/MacOS`
- `/Applications/IDA Home 9.3.app/Contents/MacOS`
- `/Applications/IDA Essential 9.3.app/Contents/MacOS`
- `/Applications/IDA Professional 9.2.app/Contents/MacOS`

#### Linux

Standard IDA installations are auto-detected:
```bash
claude mcp add ida -- ida-mcp
```

If you see library loading errors, set `IDADIR`:
```bash
claude mcp add ida -e IDADIR='/path/to/ida' -- ida-mcp
```

Supported paths (auto-detected):
- `/opt/idapro-9.3`, `/opt/idapro-9.2`
- `$HOME/idapro-9.3`, `$HOME/idapro-9.2`
- `/usr/local/idapro-9.3`, `/usr/local/idapro-9.2`

### Runtime Requirements

| Platform | Library | Fallback Configuration |
|----------|---------|------------------------|
| macOS    | `libida.dylib` | `DYLD_LIBRARY_PATH` |
| Linux    | `libida.so`    | `IDADIR` or `LD_LIBRARY_PATH` |
| Windows  | `ida.dll`      | Add IDA dir to `PATH` |

## Quick Start

```python
# Open a binary
open_idb(path: "~/samples/target.elf")

# List functions
list_functions(limit: 50)

# Decompile with Hex-Rays
decompile(address: "0x100000f00")

# Disassemble a function by name
disasm_by_name(name: "main", count: 40)

# Cross-references
xrefs_to(address: "0x100001234")

# Run IDAPython
run_script(code: "import idautils\nfor f in idautils.Functions():\n    print(hex(f), idc.get_func_name(f))")

# Discover tools
tool_catalog(query: "cross references")
```

### Key Tools

| Tool | Purpose |
|------|---------|
| `open_idb` | Open binary or `.i64` database |
| `decompile` | Hex-Rays decompilation |
| `decompile_structured` | Structured decompilation with type info |
| `disasm_by_name` | Disassemble by function name |
| `list_functions` | Enumerate all functions |
| `xrefs_to` / `xrefs_from` | Cross-references |
| `build_callgraph` | Call graph construction |
| `rename_symbol` | Rename functions/globals |
| `batch_rename` | Bulk rename operations |
| `declare_c_type` / `apply_type` | Type reconstruction |
| `run_script` | Execute IDAPython scripts |
| `search_pseudocode` | Search across decompiled code |

Use `tool_catalog` / `tool_help` to discover the full set of 73 tools.

### IDAPython Scripting

`run_script` executes Python code in the open database via IDA's IDAPython engine.

```python
# Inline script
run_script(code: "import idautils\nfor f in idautils.Functions():\n    print(hex(f))")

# Run a .py file from disk
run_script(file: "/path/to/analysis_script.py")

# With timeout (default 120s, max 600s)
run_script(code: "import ida_bytes; print(ida_bytes.get_bytes(0x1000, 16).hex())",
           timeout_secs: 30)
```

All `ida_*` modules, `idc`, and `idautils` are available. See the [IDAPython API reference](https://python.docs.hex-rays.com).

### CLI Client

`ida-cli` provides direct access via Unix socket — no MCP protocol needed:

```bash
ida-cli --path target.elf list-functions --limit 20
ida-cli --path target.elf decompile-function --address 0x1234
ida-cli --path target.elf rename-symbol --address 0x1234 --new-name parse_header
ida-cli --path target.elf build-callgraph --roots 0x1234 --max-depth 3

# Multiple files in parallel (each gets its own worker process)
ida-cli --path a.elf list-functions &
ida-cli --path b.elf list-functions &
wait
```

## AI Skill

The `skill/` directory contains an [OpenCode](https://opencode.ai) skill with structured RE methodologies, tool reference, and workflow templates. Copy it to your OpenCode skills directory to use:

```bash
cp -r skill/ ~/.config/opencode/skills/ida/
```

## Docs

- [docs/TOOLS.md](docs/TOOLS.md) — Tool catalog and discovery workflow
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md) — Stdio vs Streamable HTTP
- [docs/BUILDING.md](docs/BUILDING.md) — Build from source
- [docs/TESTING.md](docs/TESTING.md) — Running tests

## License

MIT
