# Decisions — multi-idb-support

## [2026-02-27] Architectural Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Handle ID | `format!("{:016x}", rand_u64)` | No new deps |
| HTTP mode | Option A (require db_handle when multiple IDBs) | Simpler, recommended by doc |
| Duplicate open | Return existing handle | Avoids IDA file lock conflicts |
| IDA console | Disable in worker mode | Keep stdout pure JSON-RPC |
| Worker kill | `kill_on_drop(true)` | Avoid orphan processes |
| Path dedup | `canonicalize()` before lookup | Handle symlinks correctly |
| open_dsc | Out of scope for Phase 0-5 | Too complex, planned as follow-up |
| Worker auto-restart | NOT implemented | Safety concern: could corrupt data |

## [2026-02-28] Runtime Token Ownership Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| close token model | Reference-counted set (`HashSet<String>`) | Support multiple concurrent HTTP clients safely |
| token issuance | Always issue a new token per HTTP/Routed open | Same DB can be shared while preserving per-client close rights |
| close behavior | `close_idb` releases token first, closes only at ref=0 | Prevent one client from terminating active sessions of others |
| post-close cleanup | Clear all refs after actual close succeeds | Avoid stale tokens after DB teardown |
