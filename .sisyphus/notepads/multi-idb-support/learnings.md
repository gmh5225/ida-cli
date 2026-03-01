# Learnings — multi-idb-support

## [2026-02-27] Initial Session

### Project Structure
- `src/ida/` — IMMUTABLE: request.rs (oneshot channels), loop_impl.rs, handlers/*
- `src/server/mod.rs` — ServerMode enum, handler dispatch
- `src/server/requests.rs` — ~35 request structs, ~26 need db_handle
- `src/router/` — NEW module to create
- `main.rs` — Entry point, Command enum

### Key Constraints
- `IdaRequest` contains `oneshot::Sender` — NOT serializable
- Worker must run `run_ida_loop` on main thread (IDA requires it)
- IDA console messages must be DISABLED in worker to keep stdout pure JSON
- Worker child process must use `kill_on_drop(true)`

### Conventions Observed
- schemars annotations: `#[schemars(description = "...")]`
- serde aliases pattern: `#[serde(alias = "...")]`
- Error types: `ToolError` from `src/error.rs`
- Logging: tracing with stderr (stdout reserved for MCP/JSON-RPC)

### Handle ID Generation
- Simple hex: `format!("{:016x}", rand_u64)` — no new deps

### Path Deduplication Strategy
- Use `std::fs::canonicalize()` before inserting into path→handle map
- Return existing handle if same canonical path already open

## [2026-02-28] Fixture Creation

### Test Fixtures Created
- `test/fixtures/mini.c` — Simple binary with `add()` and `main()` functions
- `test/fixtures/mini2.c` — Different binary with `helper()` and `main()` functions
- Compiled with: `cc -O0 -g` (debug symbols, no optimization)
- Both are Mach-O 64-bit arm64 executables (17KB each)
- `.gitignore` already configured: tracks `*.c` and `*.py`, ignores binaries and `.dSYM`

### Fixture Verification
```bash
$ file test/fixtures/mini test/fixtures/mini2
test/fixtures/mini:  Mach-O 64-bit executable arm64
test/fixtures/mini2: Mach-O 64-bit executable arm64
```

Ready for multi-IDB testing with different function signatures.

## [2026-02-28] Phase 0 Probe Results

### Single-Process Probe
- **Result**: TIMEOUT on second `idalib.open()` call
- **Interpretation**: idalib blocks indefinitely when attempting to open a second database without closing the first
- **Proof**: API is NOT thread-safe and does NOT support concurrent database handles within a single process

### Multi-Process Concurrency Probe
- **Result**: Both processes exit 0 (success)
- **Interpretation**: IDA license allows TWO SEPARATE ida-mcp processes to run concurrently
- **Evidence**: 
  - Process 1: Opened mini, 2 functions, completed in 10s
  - Process 2: Opened mini2, 2 functions, completed in 10s
  - No license conflicts, no "already in use" errors

### Phase 0 Conclusion: ✅ GO
**Architecture Decision**: Multi-process worker model is VIABLE
- Each worker = separate process + separate IDA instance
- License supports concurrent workers (no conflicts)
- Within a worker: serialize IDA access with mutex/lock
- Between workers: independent processes (no shared state)

### Implications for Phase 1
1. **Worker mode**: Spawn separate process per worker (not threads)
2. **Serialization**: Use `tokio::sync::Mutex` for IDA state within worker
3. **Stdout**: Disable IDA console messages in worker to keep JSON-RPC clean
4. **Handle management**: Each worker maintains its own open IDB handle

## [2026-02-28] Phase 2 RouterState Implementation

### ToolError Variant Mapping
- `NoDatabaseOpen` — exists ✅
- `InvalidParams(String)` — exists ✅ (NOT `InvalidArguments`)
- `IdaError(String)` — exists ✅ (NOT `IDAError`)
- `WorkerClosed` — exists ✅
- `Timeout(u64)` — exists ✅
- `Busy` — exists (not used in router)

### Tokio Features Required
- Added `"process"`, `"io-util"`, `"time"` to tokio features in Cargo.toml
- `process` needed for `tokio::process::{Child, ChildStdin, Command}`
- `io-util` needed for `AsyncBufReadExt`, `AsyncWriteExt`, `BufReader`, `BufWriter`
- `time` needed for `tokio::time::timeout`

### RouterState Architecture
- `Arc<Mutex<RouterInner>>` pattern for shared mutable state
- Background reader task per worker (tokio::spawn) reads stdout lines
- oneshot channels for request/response correlation by req_id
- Path dedup via `std::fs::canonicalize()` → `path_to_handle` HashMap
- Close token → handle mapping for secure close operations

## [2026-02-28] Phase 2 Integration Test

### Test Design
- `test/payloads/multi.jsonl`: MCP JSON-RPC payload for open→open→close→close flow
- `test-multi` target in `test/justfile`: builds both `mini` and `mini2` fixtures
- Test verifies: 2 unique `db_handle` values, no errors, `close_idb` succeeds
- Phase 2 only routes `open_idb` and `close_idb` through router; other tools (list_functions etc.) still go through main process worker — deferred to Phase 3

### Verification Gotchas
- `db_handle` appears in escaped JSON: `\"db_handle\": \"<hex>\"` — use `grep -o 'db_handle[^,}]*'` not `rg -o '"db_handle"...'`
- `set -euo pipefail` + `grep -c` returning 0 matches exits with code 1 → use `grep -qE pattern || true` instead
- Both `close_idb` calls may race and close the same active handle (mini2) — second close on empty map silently succeeds
- Worker mini may remain open until server shutdown (acceptable for Phase 2; explicit `db_handle` routing fixes this in Phase 3)

### Close Race Condition
- Two `close_idb` requests without tokens both grab active handle before either completes
- Both close mini2 (the active), leaving mini orphaned until shutdown
- Acceptable behavior for Phase 2; Phase 3 adds explicit `db_handle` to close_idb requests

## [2026-02-28] Phase 3 & 4 Completion

### Phase 3: db_handle Parameter Injection
- Modified all ~26 request handlers to accept optional `db_handle` parameter
- `route_or_err()` helper routes requests through `router.route_request(handle, method, params)`
- Handlers now call `route_or_err()` instead of direct `run_ida_loop()` calls
- All tools now support multi-IDB: `list_functions(db_handle="...")`, `disasm_by_name(db_handle="...")`, etc.
- Backward compatible: single-IDB mode works without db_handle (routes to active handle)

### Phase 4: Error Handling & Cleanup
- **Task 17 ✅**: Worker crash handling — background reader task handles EOF (Ok(0)) by cancelling pending requests
- **Task 18 ✅**: Per-handle close tokens — generated in `spawn_worker()` and stored in `token_to_handle` map
- **Task 19 ✅**: HTTP mode db_handle enforcement — `route_or_err()` checks `worker_count() > 1` and returns error if handle is missing
- **Task 20 ✅**: Router shutdown — `shutdown_all()` called on SIGTERM in main.rs (lines 332, 358)

### Phase 4 Test Results
- `cargo build --release` ✅ (14.59s)
- `cargo test --lib` ✅ (38 passed, 2 ignored)
- `just test` ✅ (stdio single-IDB test)
- `just test-multi` ✅ (multi-IDB test with 2 unique db_handles)

### Key Implementation Details
- `route_or_err()` enforcement: simple check `if handle.is_none() && worker_count > 1 → error`
- Works for both HTTP and stdio multi-IDB modes (no mode-specific logic needed)
- Worker EOF handling: when stdout closes, cancel all pending requests with "Worker exited unexpectedly"
- Close tokens: format `"{now:x}-{pid:x}-{nonce:x}"` for secure close operations

### Multi-IDB Support Complete
All 4 phases implemented and tested:
- Phase 0: Verified multi-process concurrency is viable ✅
- Phase 1: Worker subprocess mode with JSON-RPC ✅
- Phase 2: Router core with multi-IDB support ✅
- Phase 3: db_handle parameter injection ✅
- Phase 4: Error handling and cleanup ✅

Commit: `32b90f7 feat(multi-idb): phase 4 - error handling and cleanup`

## [2026-02-28] Phase 5: Make Router Default

### Changes
- Removed `--multi` flag from `ServeArgs` and `ServeHttpArgs`
- `run_server()` now delegates directly to `run_server_multi()` (router mode is the only path)
- `run_server_http()` always creates `RouterState` (no longer `Option<RouterState>`)
- Updated `test/justfile` to remove `--multi` from `test-multi` recipe
- Updated `docs/TRANSPORTS.md` with multi-IDB usage examples

### Backward Compatibility
- Single IDB workflow unchanged: router handles single worker transparently
- `db_handle` remains optional for single-IDB use (active handle fallback)
- Old single-IDB stdio code path removed (was redundant with router mode)

### Test Results
- `cargo build --release` ✅
- `cargo test --lib` ✅ (38 passed, 2 ignored)
- `just test` ✅ (stdio single-IDB — backward compatible)
- `just test-multi` ✅ (multi-IDB with 2 unique db_handles)

## [2026-02-28] HTTP close_token 引用计数化

### 行为变化
- `IdaWorker` 不再使用单一 owner token，改为 `DbRefTracker(HashSet<String>)` 持有多个活跃 token。
- HTTP/SSE 模式每次 `open_idb` 都会下发新的 `close_token`，即使同一路径数据库已打开也会给新调用方独立引用。
- `close_idb(token)` 先释放引用：若剩余引用数 > 0，仅返回引用释放提示，不执行真实 close。
- 仅当最后一个引用释放（remaining == 0）时，才调用 worker `close()` 并清空 token 集合。

### 验证结果
- `cargo build` 通过（0 errors）。
- `cargo test` 通过：`76 passed; 0 failed; 2 ignored`。
