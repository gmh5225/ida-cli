# MCP 工具速查

IDA MCP 服务器提供 73 个工具。下面列出高频工具的参数 schema。**其余工具用 `tool_catalog`/`tool_help` 动态发现。**

## 数据库

```
open_idb(path: "<file>")
  → .i64 恢复会话 | 任何原生二进制
  → 可选: load_debug_info: true
  → 返回 db_handle + close_token

open_sbpf(path: "<program_id>.so")
  → Solana sBPF .so 专用：sbpf-interpreter LLVM AOT + open + source map 一步完成
  → 需要可用的 sbpf-interpreter（默认路径：~/.config/opencode/skills/sbpf-trace/bin/sbpf-interpreter）
  → 返回 db_handle + close_token
  → 非 Solana 文件一律用 open_idb

close_idb(close_token: "<token>")
  → 分析结束时调用，保存所有标注
```

## 反编译

```
decompile_function(address: "0x1000")                    // 地址或函数名均可
  → C 伪代码

decompile_structured(address: "0x1000", max_depth: 20, include_types: true)
  → JSON AST（ctree），每个节点有 op 字段
  → 用于程序化分析算术链

batch_decompile(addresses: ["0x1000", "0x2000", "0x3000"])
  → 批量反编译，减少往返

get_pseudocode_at(address: "0x1000", end_address: "0x1020")
  → 只看特定地址范围的伪代码

diff_pseudocode(addr1: "0x1000", addr2: "0x2000")
  → 两个函数伪代码逐行 diff + similarity_ratio
```

## 反汇编

```
disassemble(address: "0x1000", count: 20)
disassemble_function(name: "func_name", count: 50)
disassemble_function_at(address: "0x1000", count: 200)
```

## 调用图与控制流

```
build_callgraph(roots: ["<addr>"], max_depth: 3, max_nodes: 256)
get_callees(address: "<addr>")
get_callers(address: "<addr>")
find_control_flow_paths(start: "0x1000", end: "0x2000", max_depth: 5)
get_basic_blocks(address: "0x1000")
```

## 交叉引用

```
get_xrefs_to(address: "<addr>")
get_xrefs_from(address: "<addr>")
get_xrefs_to_string(query: "swap", limit: 10)
get_xrefs_to_struct_field(name: "MyStruct", member_name: "field", limit: 25)
```

## 函数与符号

```
list_functions(filter: "main", offset: 0, limit: 50)
get_function_by_name(name: "target_func")
get_function_at_address(address: "0x1000")
get_function_prototype(address: "0x1000")
  → 返回函数原型声明字符串
batch_lookup_functions(names: ["main", "printf", "malloc"])
```

## 标注（持久化到 .i64）

```
rename_symbol(address: "<addr>", name: "new_name")
rename_symbol(current_name: "sub_1511C", name: "decrypt_payload")

batch_rename(renames: [{"address": "0x1000", "name": "new_name"}, ...])
  → 批量重命名，返回每条成功/失败状态

rename_local_variable(func_address: "<addr>", lvar_name: "v1", new_name: "buffer")
set_local_variable_type(func_address: "<addr>", lvar_name: "v1", type_str: "uint64_t")

set_function_prototype(address: "0x1000", prototype: "int64_t __fastcall func(Config *cfg)")
  → 设置函数原型（apply_decl_type）

set_function_comment(address: "0x1000", comment: "main swap handler", repeatable: false)
  → 设置函数级注释

rename_stack_variable(func_address: "0x1000", var_name: "v1", new_name: "amount_in")
  → 重命名栈变量

set_stack_variable_type(func_address: "0x1000", var_name: "amount_in", type_str: "uint64_t")
  → 设置栈变量类型

declare_c_type(decl: "struct Config { int magic; char key[32]; };", replace: true)
apply_type(name: "func_name", decl: "int64_t __fastcall process(Config *cfg, int len)")
apply_type(name: "func_name", stack_offset: -16, decl: "int local_var;")

set_comment(address: "0x1000", comment: "XOR key", repeatable: false)
set_decompiler_comment(func_address: "0x1000", address: "0x1010", comment: "decrypt loop")
  // itp=69 行尾注释（默认），itp=74 块注释
```

## 搜索

```
search_bytes(pattern: "6E 00 00 00", limit: 100)   // 注意小端序!
search_text(targets: "0x0F00000000", kind: "imm")
search_text(targets: "password", kind: "text")
search_pseudocode(pattern: "malloc", limit: 10)
search_instructions(patterns: ["MUL", "UDIV"], limit: 5)
search_instruction_operands(patterns: ["#0x6E"], limit: 5)
list_strings(query: "error", limit: 20)
list_strings(filter: "http", offset: 0, limit: 100)
```

## 内存读取

```
read_bytes(address: "0x1000", size: 32)
read_byte/read_word/read_dword/read_qword(address: "0x1000")
read_string(address: "0x1000")
read_global_variable(query: "g_flag")
scan_memory_table(base_address: "0x1000", stride: 8, count: 16)  // vtable/函数指针表
convert_number(inputs: ["0x989680", 1234])
```

## 元数据

```
list_segments()
list_imports()            // 导入符号
list_exports()            // 导出符号
list_entry_points()
get_address_info(address: "0x1000")
get_analysis_status()    // auto_is_ok
get_database_info()      // 架构、文件类型、函数数量
```

## 类型与结构体

```
list_structs(filter: "config", limit: 50)
get_struct_info(name: "Config")
read_struct_at_address(address: "0x1000", name: "Config")
search_structs(query: "state", limit: 20)
list_local_types(query: "struct", limit: 50)
infer_type(name: "func_name")
get_stack_frame(address: "0x1000")
create_stack_variable(name: "func", offset: -16, var_name: "local", decl: "int local;")
list_enums(filter: "Error", offset: 0, limit: 50)
  → 列出所有枚举类型
create_enum(decl: "enum SwapError { InvalidAmount = 0, SlippageExceeded = 1 };")
  → 创建枚举类型
```

## 编辑与 Patch

```
patch_bytes(address: "0x1000", bytes: "90 90 90 90")
patch_assembly(address: "0x1000", line: "nop")
```

## 脚本

```
run_script(code: "import idautils\nfor f in idautils.Functions():\n    print(hex(f))")
run_script(file: "/path/to/script.py")
run_script(code: "...", timeout_secs: 300)   // 默认 120s，最大 600s
```

## 动态调试

所有调试工具都接受可选参数 `db_handle` 用于多数据库场景（指定操作哪个 IDB 的调试会话）。

### 调试器加载与进程管理

```
dbg_load_debugger(debugger: "mac", is_remote: true)
  → debugger: "mac" (macOS) / "linux" / "win32"
  → is_remote: true 使用远程调试服务器（mac_server_arm 等）
  → 必须在 start_process/attach_process 之前调用

dbg_start_process(path: "/path/to/binary", args: "", timeout: 30)
  → 启动目标进程并附加调试器
  → macOS: 使用 posix_spawn(POSIX_SPAWN_START_SUSPENDED) + attach 方案
  → 返回 pid, port, event_code (11=PROCESS_ATTACHED), ip

dbg_attach_process(pid: 12345, timeout: 15)
  → 附加到已运行的进程
  → 返回 pid, port, event_code, ip

dbg_detach_process(timeout: 10)
  → 分离调试器，目标进程继续运行
  → 返回 detached: true, server_cleaned: true

dbg_exit_process(timeout: 10)
  → 终止目标进程并清理调试服务器
  → 返回 exited: true, server_cleaned: true
```

### 断点

```
dbg_add_breakpoint(address: "0x1000")
  → 使用 IDB 地址；调试期间 IDA 自动处理 ASLR rebase
  → type: 4 = software breakpoint

dbg_del_breakpoint(address: "0x1000")

dbg_enable_breakpoint(address: "0x1000", enable: true/false)

dbg_list_breakpoints()
  → 返回所有断点列表（地址、类型、enabled、条件）
```

### 执行控制

```
dbg_continue(timeout: 10)
  → 继续执行直到断点/异常/超时
  → event_code: 5=BREAKPOINT, 6=STEP, 2=PROCESS_EXITED, 0=TIMEOUT

dbg_step_into(timeout: 10)
  → 单步进入（遇到 BL/CALL 进入子函数）

dbg_step_over(timeout: 10)
  → 单步跨过（BL/CALL 不进入）

dbg_step_until_ret(timeout: 10)
  → 执行直到当前函数返回

dbg_run_to(address: "0x1000", timeout: 10)
  → 运行到指定地址（临时断点）
```

### 寄存器与内存

```
dbg_get_registers()
  → 返回所有寄存器值（ARM64: X0-X30, SP, PC, LR, D0-D31, Q0-Q15, ...）
  → ip 和 sp 额外顶层返回

dbg_set_register(register_name: "X0", value: "0x42")

dbg_read_memory(address: "0x1000", size: 64)
  → 返回 hex + ascii 表示

dbg_write_memory(address: "0x1000", data: "DEADBEEF")
  → hex 字符串写入，返回 bytes_written

dbg_get_memory_info()
  → 枚举内存区域
  → ⚠️ mac_server_arm 不支持（返回 code=-6），这是 Hex-Rays 已知限制
```

### 线程

```
dbg_list_threads()
  → 返回线程列表（id, index, name）+ current_thread

dbg_select_thread(thread_id: 12345)
  → 切换当前线程

dbg_get_state()
  → 返回调试状态：DSTATE_SUSP (-1), DSTATE_NOTASK (0), DSTATE_RUN (1)
  → 包含 ip, sp, current_thread, thread_count, remote_debug_server 信息

dbg_wait_event(timeout_ms: 100)
  → 等待调试事件（不继续执行）
```

### 调试期间的地址 rebase（重要）

调试期间，ASLR 导致 IDB 地址被 rebase。例如 IDB 中 `main` 在 `0x100000348`，运行时可能在 `0x1000d0348`。

- **按名称操作**的工具（`disassemble_function(name: "main")`）不受影响
- **按地址操作**的工具必须使用 rebase 后的地址（从 `dbg_get_state`/`dbg_get_registers` 的 `ip` 获取）
- 断点可以用 IDB 地址设置，IDA 自动 rebase
- `list_functions` 在调试期间返回 rebase 后的地址

## 动态发现（不确定用什么工具时）

```
tool_catalog(query: "find all callers of a function")
tool_help(name: "decompile_structured")
```

> **规则**：上面没列出的工具，先 `tool_catalog` 搜索，再 `tool_help` 查参数。不要猜参数。
