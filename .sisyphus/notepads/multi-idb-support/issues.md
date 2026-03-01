# Issues — multi-idb-support

## [2026-02-27] Known Issues / Risks

### CRITICAL (go/no-go)
- [x] IDA license concurrency: Phase 0 multi-process probe PASSED ✅
  - Single-process: idalib.open() blocks on second database (no concurrent handles)
  - Multi-process: Both ida-mcp processes exit 0 (license allows concurrent workers)
  - Decision: GO to Phase 1 — use separate process per worker

### HIGH
- Worker stdout pollution: IDA console messages can corrupt JSON-RPC stream. Must `idalib::enable_console_messages(false)` in serve-worker mode.
- Single-process serialization: Within a worker, IDA access must be serialized (mutex/lock) since idalib blocks on concurrent opens

### MEDIUM  
- Large responses: BufReader default 8KB buffer may truncate MB-level JSON. Need to test/handle.
- Worker startup latency: ~1-2s per open_idb is acceptable but should be measured.

### LOW
- std::env::current_exe() reliability on some Linux systems. May need fallback to PATH lookup.

## [2026-02-28] New Observations

### LOW
- `DbRefTracker::has_token/count` and `IdaWorker::has_db_ref/db_ref_count` are currently unused in-tree and emit `dead_code` warnings in build/test. Functionality is correct; warnings can be removed later by wiring these helpers into runtime checks or tests.
