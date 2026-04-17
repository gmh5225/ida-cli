# IDA Plugin Development & Packaging

Developing, packaging, and publishing IDA Pro plugins for the Plugin Manager (IDA 9.0+).

## Plugin Architecture

### Entry Point Pattern

Every plugin needs a `PLUGIN_ENTRY()` function. Use a wrapper entry point for environment checks:

```python
# foo_entry.py — Safe entry point with environment detection
import logging, os
import ida_kernwin

logger = logging.getLogger(__name__)

def should_load():
    """Returns True if IDA 9.2+ is running interactively."""
    if not ida_kernwin.is_idaq():
        return False
    if os.environ.get("IDA_IS_INTERACTIVE") != "1":
        return False
    kernel_version = tuple(
        int(part) for part in ida_kernwin.get_kernel_version().split(".")
        if part.isdigit()
    ) or (0,)
    if kernel_version < (9, 2):
        logger.warning("IDA too old (must be 9.2+): %s", ida_kernwin.get_kernel_version())
        return False
    return True

if should_load():
    from foo import foo_plugin_t
    def PLUGIN_ENTRY():
        return foo_plugin_t()
else:
    import ida_idaapi
    class foo_nop_plugin_t(ida_idaapi.plugin_t):
        flags = ida_idaapi.PLUGIN_HIDE | ida_idaapi.PLUGIN_UNL
        wanted_name = "foo disabled"
        comment = "foo is disabled for this IDA version"
        help = ""
        wanted_hotkey = ""
        def init(self):
            return ida_idaapi.PLUGIN_SKIP

    def PLUGIN_ENTRY():
        return foo_nop_plugin_t()
```

### plugin_t + plugmod_t Lifecycle

```python
# foo.py — Main plugin implementation
import ida_idaapi, ida_auto
import logging

logger = logging.getLogger(__name__)

class foo_plugmod_t(ida_idaapi.plugmod_t):
    """Per-database plugin module (created for each opened database)."""

    def __init__(self):
        # IDA doesn't call init() for plugmod_t, only plugin_t
        self.init()

    def init(self):
        """Called once when plugin loads. Set up hooks, state, UI."""
        if not ida_auto.auto_is_ok():
            logger.debug("waiting for auto-analysis...")
            ida_auto.auto_wait()
            logger.debug("auto-analysis complete")
        # Register hooks, load state, etc.

    def run(self, arg):
        """Called when user invokes plugin via Edit > Plugins > ..."""
        pass

    def term(self):
        """Cleanup: unhook handlers, save state, release resources."""
        pass


class foo_plugin_t(ida_idaapi.plugin_t):
    """Plugin entry point (singleton across IDA session)."""
    flags = ida_idaapi.PLUGIN_MULTI  # One plugmod_t per database
    help = "Description of what this plugin does"
    comment = ""
    wanted_name = "Foo"
    wanted_hotkey = ""

    def init(self):
        return foo_plugmod_t()
```

**Key flags:**
- `PLUGIN_MULTI` — Create separate `plugmod_t` per database (recommended)
- `PLUGIN_HIDE` — Don't show in menus
- `PLUGIN_UNL` — Unload after `init()` returns `PLUGIN_SKIP`

---

## Hook Registration

Create pairwise register/unregister helpers; call from `init()`/`term()`:

```python
class my_plugmod_t(ida_idaapi.plugmod_t):
    def __init__(self):
        self.idb_hooks = None
        self.ui_hooks = None
        self.init()

    def register_hooks(self):
        self.idb_hooks = MyIDBHooks()
        self.idb_hooks.hook()
        self.ui_hooks = MyUIHooks()
        self.ui_hooks.hook()

    def unregister_hooks(self):
        if self.idb_hooks:
            self.idb_hooks.unhook()
        if self.ui_hooks:
            self.ui_hooks.unhook()

    def init(self):
        self.register_hooks()

    def term(self):
        self.unregister_hooks()  # Reverse order
```

### Available Hook Classes

| Hook Class | Events |
|-----------|--------|
| `ida_kernwin.UI_Hooks` | UI events, screen_ea_changed, widget focus, popups |
| `ida_idaapi.IDB_Hooks` | Database changes: renamed, type changed, func added/deleted |
| `ida_idaapi.IDP_Hooks` | Processor events: ev_get_bg_color, ev_out_mnem, ev_ana_insn |
| `ida_kernwin.View_Hooks` | Viewer events: view_click, view_curpos, view_activated |
| `ida_hexrays.Hexrays_Hooks` | Decompiler: maturity_t stages, microcode events |

---

## UI Patterns

### Respond to Address & Selection Changes

```python
class UILocationHook(ida_kernwin.UI_Hooks):
    def screen_ea_changed(self, ea, prev_ea):
        if ea == prev_ea:
            return
        v = ida_kernwin.get_current_viewer()
        if ida_kernwin.get_widget_type(v) not in (
            ida_kernwin.BWN_HEXVIEW, ida_kernwin.BWN_DISASM,
        ):
            return
        has_range, start, end = ida_kernwin.read_range_selection(v)
        if not has_range:
            self.on_address_change(ea)
        else:
            self.on_selection_change(start, end)

    def on_address_change(self, ea):
        pass  # Override

    def on_selection_change(self, start, end):
        pass  # Override
```

### User-Defined Prefix (Disassembly Line Markers)

```python
class FooPrefix(ida_lines.user_defined_prefix_t):
    ICON = " β "

    def __init__(self, marks: set[int]):
        super().__init__(len(self.ICON))
        self.marks = marks

    def get_user_defined_prefix(self, ea, insn, lnnum, indent, line):
        if ea in self.marks:
            return ida_lines.COLSTR(self.ICON, ida_lines.SCOLOR_SYMBOL)
        return " " * len(self.ICON)

# Install: simply construct it
prefixer = FooPrefix({0x401000, 0x401050})
ida_kernwin.request_refresh(ida_kernwin.IWID_DISASM)

# Uninstall: set to None and refresh
prefixer = None
ida_kernwin.request_refresh(ida_kernwin.IWID_DISASM)
```

### Viewer Hints (Hover Popups)

```python
class FooHints(ida_kernwin.UI_Hooks):
    def __init__(self, notes: dict[int, str]):
        super().__init__()
        self.notes = notes

    def get_custom_viewer_hint(self, viewer, place):
        if not place:
            return
        ea = place.toea()
        note = self.notes.get(ea)
        if note:
            return (f"note: {note}", 1)  # (text, num_lines)

# Usage
hints = FooHints({0x401000: "Entry point", 0x401050: "Suspicious call"})
hints.hook()
```

### Override Disassembly Rendering

```python
import ctypes

class ColorHooks(idaapi.IDP_Hooks):
    def ev_get_bg_color(self, color, ea):
        """Color disassembly lines dynamically."""
        mnem = ida_ua.print_insn_mnem(ea)
        if mnem in ("call", "CALL"):
            bgcolor = ctypes.cast(int(color), ctypes.POINTER(ctypes.c_int))
            bgcolor[0] = 0xDDDDDD  # Light gray
            return 1
        return 0

    def ev_out_mnem(self, ctx):
        """Override mnemonic rendering."""
        if ctx.insn.get_canon_mnem() == "call":
            ctx.out_custom_mnem("CALL")
            return 1
        return 0
```

### Context Menu Actions

```python
class MyAction(ida_kernwin.action_handler_t):
    ACTION_NAME = "myplugin:do_thing"
    ACTION_LABEL = "Send to MyPlugin"

    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        self.plugin.handle(ea)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

# Register
ida_kernwin.register_action(ida_kernwin.action_desc_t(
    MyAction.ACTION_NAME, MyAction.ACTION_LABEL, MyAction(plugin),
    "Ctrl+Shift+F", "Send current address to MyPlugin", -1
))
# Attach to right-click menu
ida_kernwin.attach_action_to_popup(widget, None, MyAction.ACTION_NAME)

# Unregister in term()
ida_kernwin.unregister_action(MyAction.ACTION_NAME)
```

### Custom Viewers

```python
class foo_viewer_t(ida_kernwin.simplecustviewer_t):
    TITLE = "Foo"

    def Create(self):
        if not super().Create(self.TITLE):
            return False
        self.render()
        return True

    def render(self):
        self.ClearLines()
        self.AddLine("=== Foo Viewer ===")
        # Add address-tagged line (clickable)
        self.AddLine(ida_lines.COLSTR(
            ida_lines.tag_addr(0x401000) + "sub_401000",
            ida_lines.SCOLOR_CNAME
        ))

    def OnDblClick(self, shift):
        """Handle double-click — jump to address."""
        line = self.GetCurrentLine()
        # Parse tagged line for address...
        return True

# Show viewer
viewer = foo_viewer_t()
viewer.Create()
viewer.Show()
```

### Find Widgets by Prefix

```python
def find_next_available_caption(prefix: str) -> str:
    """Find first available 'Foo-A' through 'Foo-Z' caption."""
    assert prefix.endswith("-")
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        caption = f"{prefix}{letter}"
        if ida_kernwin.find_widget(caption) is None:
            return caption
    raise RuntimeError("All 26 instances in use")
```

---

## State Persistence (Netnodes)

Store plugin state within the IDB file using netnodes:

```python
import ida_netnode
import pydantic, zlib

OUR_NETNODE = "$ com.example.myplugin"

class State(pydantic.BaseModel):
    bookmarks: list[int] = []
    notes: dict[str, str] = {}

    def to_json(self):
        return self.model_dump_json()

    @classmethod
    def from_json(cls, json_str: str):
        return cls.model_validate_json(json_str)


def save_state(state: State):
    buf = zlib.compress(state.to_json().encode("utf-8"))
    node = ida_netnode.netnode(OUR_NETNODE)
    node.setblob(buf, 0, "I")

def load_state() -> State:
    node = ida_netnode.netnode(OUR_NETNODE)
    if not node:
        return State()
    buf = node.getblob(0, "I")
    if not buf:
        return State()
    return State.from_json(zlib.decompress(buf).decode("utf-8"))
```

Save on UI close/save events:

```python
class SaveHooks(ida_kernwin.UI_Hooks):
    def __init__(self, state):
        super().__init__()
        self.state = state

    def preprocess_action(self, action):
        if action in ("CloseBase", "QuitIDA", "SaveBase"):
            save_state(self.state)
        return 0
```

---

## Cross-Plugin Communication (IDC Functions)

Expose plugin functionality to scripts and other plugins:

```python
import ida_expr

class my_plugmod_t(ida_idaapi.plugmod_t):
    def __init__(self):
        self.data = []
        self.init()

    def register_idc_func(self):
        data = self.data

        def my_get_data(index: int) -> str:
            return data[index] if 0 <= index < len(data) else ""

        def my_add_data(value: str) -> int:
            data.append(value)
            return len(data)

        ida_expr.add_idc_func("myplugin_get_data", my_get_data, (ida_expr.VT_LONG,))
        ida_expr.add_idc_func("myplugin_add_data", my_add_data, (ida_expr.VT_STR,))

    def unregister_idc_func(self):
        ida_expr.del_idc_func("myplugin_get_data")
        ida_expr.del_idc_func("myplugin_add_data")

    def init(self):
        self.register_idc_func()

    def term(self):
        self.unregister_idc_func()
```

Callers:

```python
import idc
idc.eval_idc('myplugin_add_data("hello")')
result = idc.eval_idc('myplugin_get_data(0)')
```

Parameter types: `VT_STR`, `VT_LONG`, `VT_FLOAT`.

---

## Plugin Settings (ida-settings)

```python
import ida_settings

# Get setting (must be called from plugin_t or plugmod_t context)
api_key = ida_settings.get_current_plugin_setting("api_key")

# For hooks/callbacks, capture settings instance first:
class MyPlugmod(ida_idaapi.plugmod_t):
    def run(self, arg):
        self.settings = ida_settings.get_current_plugin_settings()
        self.hooks = MyHooks(self.settings)
        self.hooks.hook()

class MyHooks(ida_kernwin.UI_Hooks):
    def __init__(self, settings):
        super().__init__()
        self.settings = settings
    # Use self.settings.get_setting("key") in hook methods
```

Available APIs: `get/set/has/del/list(_current)_plugin_setting(s)`.

---

## Plugin Packaging

### ida-plugin.json Manifest

Required file in plugin root directory:

```json
{
  "IDAMetadataDescriptorVersion": 1,
  "plugin": {
    "name": "my-plugin",
    "version": "1.0.0",
    "entryPoint": "my_plugin.py",
    "description": "One-line description",
    "license": "MIT",
    "idaVersions": ">=9.0",
    "platforms": ["windows-x86_64", "linux-x86_64", "macos-x86_64", "macos-aarch64"],
    "categories": ["malware-analysis"],
    "keywords": ["analysis", "automation"],
    "pythonDependencies": ["requests>=2.0", "pydantic>=2"],
    "urls": {
      "repository": "https://github.com/org/my-plugin"
    },
    "authors": [
      {"name": "Author Name", "email": "author@example.com"}
    ],
    "settings": [
      {
        "key": "api_key",
        "type": "string",
        "required": true,
        "name": "API Key",
        "documentation": "Your API key for the service"
      }
    ]
  }
}
```

### Required Fields

| Field | Description |
|-------|-------------|
| `IDAMetadataDescriptorVersion` | Always `1` |
| `plugin.name` | Unique ID (ASCII, digits, hyphens, underscores) |
| `plugin.version` | Semver `x.y.z` (no `v` prefix) |
| `plugin.entryPoint` | Entry point filename |
| `plugin.urls.repository` | GitHub URL |
| `plugin.authors` OR `plugin.maintainers` | At least one with `email` |

### Valid Categories

```
disassembly-and-processor-modules    file-parsers-and-loaders
decompilation                         debugging-and-tracing
deobfuscation                         collaboration-and-productivity
integration-with-third-parties-interoperability
api-scripting-and-automation          ui-ux-and-visualization
malware-analysis                      vulnerability-research-and-exploit-development
other
```

### PEP 723 Inline Dependencies

Set `"pythonDependencies": "inline"`, then in your entry point:

```python
# /// script
# dependencies = [
#     "requests>=2.0",
#     "pydantic>=2"
# ]
# ///
```

---

## Publishing

### Steps

1. **Tag & Release**: `git tag v1.0.0 && git push --tags`, create GitHub Release with ZIP
2. **Auto-indexing**: Indexer runs daily, discovers repos with `ida-plugin.json`
3. **Explicit registration** (optional): Add repo URL to `HexRaysSA/plugin-repository` → `known-repositories.txt`

### HCLI Commands

```bash
hcli plugin list                         # Available plugins
hcli plugin list --installed             # Installed plugins
hcli plugin search <query>               # Search
hcli plugin install <name>               # Install
hcli plugin install <name>==1.0.0        # Specific version
hcli plugin upgrade <name>               # Upgrade
hcli plugin uninstall <name>             # Uninstall
hcli plugin config <name> set <k> <v>    # Configure
hcli plugin config <name> get <k>        # Read config
hcli plugin lint /path/to/plugin         # Validate
```

---

## Best Practices

- **Logging**: Use `logging.*`, never `print()`. Don't configure logging from plugins
- **Settings**: Use `ida-settings` library, not custom config files
- **GUI check**: Guard GUI code with `ida_kernwin.is_idaq()`
- **Auto-analysis**: Call `ida_auto.auto_wait()` before accessing analysis results
- **Cleanup**: Always unhook and unregister in `term()` (reverse order of registration)
- **Netnode naming**: Use reverse domain notation: `"$ com.example.myplugin"`

## Resources

- [Plugin Repository](https://plugins.hex-rays.com/)
- [HCLI Documentation](https://hcli.docs.hex-rays.com/)
- [Plugin Repository Source](https://github.com/HexRaysSA/plugin-repository)
- [HCLI Source](https://github.com/HexRaysSA/ida-hcli)
- [ida-settings Library](https://github.com/williballenthin/ida-settings)
