# ida-mcp-skill

IDA Pro MCP server for Solana program reverse engineering, designed to work with [OpenCode](https://opencode.ai) AI skills.

## Overview

This is a headless IDA Pro MCP server optimized for analyzing Solana sBPF programs. It powers the `ida-pro`, `solana-sbpf`, and `solana-sbpf-reverse` skills in OpenCode for end-to-end Solana RE workflows.

## Prerequisites

- IDA Pro 9.3+ (or 9.2) with valid license and Hex-Rays decompiler
- Rust 1.77+ (if building from source)

## Getting Started

### Build from Source

See [docs/BUILDING.md](docs/BUILDING.md).

### Platform Setup

#### macOS

Standard IDA installations in `/Applications` work automatically:
```bash
claude mcp add ida -- ida-mcp-skill
```

If you see `Library not loaded: @rpath/libida.dylib`, set `DYLD_LIBRARY_PATH`:
```bash
claude mcp add ida -e DYLD_LIBRARY_PATH='/path/to/IDA.app/Contents/MacOS' -- ida-mcp-skill
```

Supported paths (auto-detected):
- `/Applications/IDA Professional 9.3.app/Contents/MacOS`
- `/Applications/IDA Home 9.3.app/Contents/MacOS`
- `/Applications/IDA Essential 9.3.app/Contents/MacOS`
- `/Applications/IDA Professional 9.2.app/Contents/MacOS`

#### Linux

Standard IDA installations are auto-detected:
```bash
claude mcp add ida -- ida-mcp-skill
```

If you see library loading errors, set `IDADIR`:
```bash
claude mcp add ida -e IDADIR='/path/to/ida' -- ida-mcp-skill
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

### Configure OpenCode

Add the MCP server to Claude Code:
```bash
claude mcp add ida -- ida-mcp-skill
```

Then load the Solana RE skills:
```
load_skills: ["ida-pro", "solana-sbpf", "solana-sbpf-reverse"]
```

## Solana RE Workflow

```
# Open a Solana program .so file
open_idb(path: "~/samples/program.so")

# List all functions
list_functions(limit: 50)

# Disassemble the swap instruction handler
disasm_by_name(name: "process_swap", count: 40)

# Decompile with Hex-Rays
decompile(address: "0x100000f00")

# Run IDAPython for custom Solana analysis
run_script(code: "import idautils\nfor f in idautils.Functions():\n    print(hex(f), idc.get_func_name(f))")

# Discover available tools
tool_catalog(query: "cross references")
```

### Key Tools for Solana Programs

| Tool | Purpose |
|------|---------|
| `open_idb` | Open `.so` / `.i64` Solana program file |
| `decompile` | Hex-Rays decompilation of a function |
| `decompile_structured` | Structured decompilation with type info |
| `disasm_by_name` | Disassemble by function name |
| `list_functions` | Enumerate all functions |
| `xrefs_to` | Find all callers of an address |
| `xrefs_from` | Find all callees from an address |
| `run_script` | Execute IDAPython for custom analysis |
| `rename_lvar` | Rename local variables |
| `set_lvar_type` | Set local variable types |
| `set_decompiler_comment` | Add decompiler comments |

### IDAPython Scripting

`run_script` executes Python code in the open database via IDA's IDAPython engine.

```
# Inline script
run_script(code: "import idautils\nfor f in idautils.Functions():\n    print(hex(f))")

# Run a .py file from disk
run_script(file: "/path/to/analysis_script.py")

# With timeout (default 120s, max 600s)
run_script(code: "import ida_bytes; print(ida_bytes.get_bytes(0x1000, 16).hex())",
           timeout_secs: 30)
```

All `ida_*` modules, `idc`, and `idautils` are available. See the [IDAPython API reference](https://python.docs.hex-rays.com).

---

Use `tool_catalog`/`tool_help` to discover the full tool set without dumping the entire list into context.

## Docs

- [docs/TOOLS.md](docs/TOOLS.md) - Tool catalog and discovery workflow
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md) - Stdio vs Streamable HTTP
- [docs/BUILDING.md](docs/BUILDING.md) - Build from source
- [docs/TESTING.md](docs/TESTING.md) - Running tests

## License

MIT Copyright (c) 2026 **pingzi**
