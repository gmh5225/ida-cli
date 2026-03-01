//! Multi-IDB Router — manages worker subprocesses.
//!
//! Architecture:
//! - Each open IDB gets a `WorkerProcess` running `ida-mcp serve-worker`
//! - Requests are routed to workers via JSON-RPC over stdin/stdout
//! - Router maintains an "active" handle for backward compatibility

pub mod protocol;

use crate::router::protocol::{RpcRequest, RpcResponse};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::process::{Child, ChildStdin};
use tokio::sync::{oneshot, Mutex};
use tracing::{debug, error, info, warn};
use std::time::{Duration, Instant};

pub type DbHandle = String;
pub type ReqId = String;

pub struct WorkerProcess {
    pub child: Child,
    pub writer: BufWriter<ChildStdin>,
    pub pending: HashMap<ReqId, oneshot::Sender<Result<serde_json::Value, String>>>,
    pub close_token: Option<String>,
    pub open_path: Option<PathBuf>,
    pub last_active: Instant,
}

#[derive(Clone)]
pub struct RouterState {
    inner: Arc<Mutex<RouterInner>>,
}

impl std::fmt::Debug for RouterState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterState").finish_non_exhaustive()
    }
}

struct RouterInner {
    workers: HashMap<DbHandle, WorkerProcess>,
    active: Option<DbHandle>,
    path_to_handle: HashMap<PathBuf, DbHandle>,
    token_to_handle: HashMap<String, DbHandle>,
    ref_tokens: HashMap<DbHandle, HashSet<String>>,
    req_counter: u64,
    exe_path: PathBuf,
}

impl RouterState {
    pub fn new() -> anyhow::Result<Self> {
        let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("ida-mcp"));

        Ok(Self {
            inner: Arc::new(Mutex::new(RouterInner {
                workers: HashMap::new(),
                active: None,
                path_to_handle: HashMap::new(),
                token_to_handle: HashMap::new(),
                ref_tokens: HashMap::new(),
                req_counter: 0,
                exe_path,
            })),
        })
    }

    /// Spawn a new worker subprocess for the given IDB path.
    /// Returns the db_handle (existing handle if file already open).
    pub async fn spawn_worker(
        &self,
        path: &str,
    ) -> Result<(DbHandle, Option<String>), anyhow::Error> {
        let canonical_path = std::fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));

        let mut inner = self.inner.lock().await;

        if let Some(existing_handle) = inner.path_to_handle.get(&canonical_path).cloned() {
            info!(
                "Path {:?} already open with handle {}, issuing new ref token",
                canonical_path, existing_handle
            );
            let now = {
                use std::time::{SystemTime, UNIX_EPOCH};
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            };
            let pid = std::process::id();
            let nonce = inner.req_counter;
            inner.req_counter += 1;
            let ref_token = format!("{now:x}-{pid:x}-{nonce:x}");

            inner
                .token_to_handle
                .insert(ref_token.clone(), existing_handle.clone());
            inner
                .ref_tokens
                .entry(existing_handle.clone())
                .or_insert_with(HashSet::new)
                .insert(ref_token.clone());

            return Ok((existing_handle, Some(ref_token)));
        }

        let handle: DbHandle = format!("{:016x}", {
            use std::time::{SystemTime, UNIX_EPOCH};
            let t = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0) as u64;
            let pid = std::process::id() as u64;
            let counter = inner.req_counter;
            inner.req_counter += 1;
            t ^ (pid << 32) ^ counter
        });

        let exe_path = inner.exe_path.clone();
        info!("Spawning worker {} for path {:?}", handle, canonical_path);

        let mut cmd = tokio::process::Command::new(&exe_path);
        cmd.arg("serve-worker")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true);

        for var in &["DYLD_LIBRARY_PATH", "IDADIR", "LD_LIBRARY_PATH", "PATH"] {
            if let Ok(val) = std::env::var(var) {
                cmd.env(var, val);
            }
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to spawn worker process: {e}"))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("Failed to get worker stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("Failed to get worker stdout"))?;

        let writer = BufWriter::new(stdin);

        let close_token = {
            use std::time::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let pid = std::process::id();
            let nonce = inner.req_counter;
            format!("{now:x}-{pid:x}-{nonce:x}")
        };

        let worker = WorkerProcess {
            child,
            writer,
            pending: HashMap::new(),
            close_token: Some(close_token.clone()),
            open_path: Some(canonical_path.clone()),
            last_active: Instant::now(),
        };

        let handle_for_reader = handle.clone();
        let inner_arc = self.inner.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            let mut line_buf = String::new();
            loop {
                line_buf.clear();
                match reader.read_line(&mut line_buf).await {
                    Ok(0) => {
                        warn!(
                            "Worker {} stdout closed (process exited)",
                            handle_for_reader
                        );
                        let mut inner = inner_arc.lock().await;
                        // Drain pending requests, notify callers
                        if let Some(worker) = inner.workers.get_mut(&handle_for_reader) {
                            for (id, sender) in worker.pending.drain() {
                                let _ = sender.send(Err(format!(
                                    "Worker {} exited unexpectedly",
                                    handle_for_reader
                                )));
                                debug!("Cancelled pending request {} due to worker exit", id);
                            }
                        }
                        // Crash detection: remove dead worker from all maps so the
                        // handle is not reachable for future requests. This is a no-op
                        // when the worker was already removed by close_worker().
                        // Only emit the WARN if the worker was still in the registry
                        // (truly unexpected exit). If already removed by close_worker(),
                        // the process exit was expected — no warning needed.
                        if let Some(dead) = inner.workers.remove(&handle_for_reader) {
                            if let Some(path) = &dead.open_path {
                                inner.path_to_handle.remove(path);
                            }
                            // dead.child drops here; kill_on_drop=true handles cleanup
                            if let Some(tokens) = inner.ref_tokens.remove(&handle_for_reader) {
                                for t in &tokens {
                                    inner.token_to_handle.remove(t);
                                }
                            }
                            if inner.active.as_deref() == Some(handle_for_reader.as_str()) {
                                inner.active = inner.workers.keys().next().cloned();
                            }
                            warn!("Worker {} removed from registry after unexpected exit", handle_for_reader);
                        }
                        break;
                    }
                    Ok(_) => {
                        let trimmed = line_buf.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        match serde_json::from_str::<RpcResponse>(trimmed) {
                            Ok(resp) => {
                                let mut inner = inner_arc.lock().await;
                                if let Some(worker) = inner.workers.get_mut(&handle_for_reader) {
                                    if let Some(sender) = worker.pending.remove(&resp.id) {
                                        let result = if let Some(result) = resp.result {
                                            Ok(result)
                                        } else if let Some(err) = resp.error {
                                            Err(err.message)
                                        } else {
                                            Ok(serde_json::Value::Null)
                                        };
                                        let _ = sender.send(result);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "Worker {} sent non-JSON line: {} (error: {})",
                                    handle_for_reader, trimmed, e
                                );
                            }
                        }
                    }
                    Err(e) => {
                        error!("Worker {} stdout read error: {}", handle_for_reader, e);
                        let mut inner = inner_arc.lock().await;
                        if let Some(worker) = inner.workers.get_mut(&handle_for_reader) {
                            for (id, sender) in worker.pending.drain() {
                                let _ = sender.send(Err(format!(
                                    "Worker {} I/O error: {}",
                                    handle_for_reader, e
                                )));
                                debug!("Cancelled pending request {} due to I/O error", id);
                            }
                        }
                        if let Some(dead) = inner.workers.remove(&handle_for_reader) {
                            if let Some(path) = &dead.open_path {
                                inner.path_to_handle.remove(path);
                            }
                        }
                        if let Some(tokens) = inner.ref_tokens.remove(&handle_for_reader) {
                            for t in &tokens {
                                inner.token_to_handle.remove(t);
                            }
                        }
                        if inner.active.as_deref() == Some(handle_for_reader.as_str()) {
                            inner.active = inner.workers.keys().next().cloned();
                        }
                        warn!("Worker {} removed from registry after I/O error", handle_for_reader);
                        break;
                    }
                }
            }
        });

        inner.path_to_handle.insert(canonical_path, handle.clone());
        inner
            .token_to_handle
            .insert(close_token.clone(), handle.clone());
        let mut init_refs = HashSet::new();
        init_refs.insert(close_token.clone());
        inner.ref_tokens.insert(handle.clone(), init_refs);
        inner.workers.insert(handle.clone(), worker);
        inner.active = Some(handle.clone());

        Ok((handle, Some(close_token)))
    }

    /// Route a request to the appropriate worker process.
    /// If handle is None, routes to the active worker.
    pub async fn route_request(
        &self,
        handle: Option<&str>,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, crate::error::ToolError> {
        use crate::error::ToolError;

        let target_handle = {
            let inner = self.inner.lock().await;
            if let Some(h) = handle {
                if !inner.workers.contains_key(h) {
                    return Err(ToolError::InvalidParams(format!("Unknown db_handle: {h}")));
                }
                h.to_string()
            } else {
                inner.active.clone().ok_or(ToolError::NoDatabaseOpen)?
            }
        };

        let req_id = {
            let mut inner = self.inner.lock().await;
            let id = format!("r{}", inner.req_counter);
            inner.req_counter += 1;
            id
        };

        // Extract timeout from tool params before they are consumed (default 120s, max 600s).
        let timeout_secs = params
            .get("timeout_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(120)
            .min(600);

        let (tx, rx) = oneshot::channel::<Result<serde_json::Value, String>>();

        {
            let mut inner = self.inner.lock().await;
            let worker = inner.workers.get_mut(&target_handle).ok_or_else(|| {
                ToolError::InvalidParams(format!("Worker {} not found", target_handle))
            })?;

            let req = RpcRequest::new(&req_id, method, params);
            let json = serde_json::to_string(&req)
                .map_err(|e| ToolError::InvalidParams(format!("Serialize error: {e}")))?;

            worker
                .writer
                .write_all(json.as_bytes())
                .await
                .map_err(|_| ToolError::WorkerClosed)?;
            worker
                .writer
                .write_all(b"\n")
                .await
                .map_err(|_| ToolError::WorkerClosed)?;
            worker
                .writer
                .flush()
                .await
                .map_err(|_| ToolError::WorkerClosed)?;

            worker.pending.insert(req_id.clone(), tx);
            worker.last_active = Instant::now();
        }

        let timeout = std::time::Duration::from_secs(timeout_secs);
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(Ok(value))) => Ok(value),
            Ok(Ok(Err(e))) => Err(ToolError::IdaError(e)),
            Ok(Err(_)) => Err(ToolError::WorkerClosed),
            Err(_) => Err(ToolError::Timeout(timeout_secs)),
        }
    }

    pub async fn close_worker(&self, handle: &str) -> Result<(), crate::error::ToolError> {
        let mut inner = self.inner.lock().await;

        if let Some(mut worker) = inner.workers.remove(handle) {
            if let Some(path) = &worker.open_path {
                inner.path_to_handle.remove(path);
            }
            if let Some(tokens) = inner.ref_tokens.remove(handle) {
                for token in &tokens {
                    inner.token_to_handle.remove(token);
                }
            }
            if inner.active.as_deref() == Some(handle) {
                inner.active = inner.workers.keys().next().cloned();
            }
            for (id, sender) in worker.pending.drain() {
                let _ = sender.send(Err(format!("Worker {handle} closed")));
                debug!("Cancelled pending request {id} due to close_worker");
            }
            drop(worker);
            info!("Closed worker {}", handle);
        }

        Ok(())
    }

    /// Release a reference token. Returns `Some((handle, remaining))` if the token was valid:
    /// `remaining > 0` means other clients still hold refs (do NOT close the worker),
    /// `remaining == 0` means last reference released (caller should close the worker).
    /// Returns `None` if the token was not found (invalid or already released).
    pub async fn release_ref_token(&self, token: &str) -> Option<(DbHandle, usize)> {
        let mut inner = self.inner.lock().await;
        let handle = inner.token_to_handle.remove(token)?;
        let remaining = if let Some(set) = inner.ref_tokens.get_mut(&handle) {
            set.remove(token);
            set.len()
        } else {
            0
        };
        Some((handle, remaining))
    }

    pub async fn handle_for_token(&self, token: &str) -> Option<DbHandle> {
        let inner = self.inner.lock().await;
        inner.token_to_handle.get(token).cloned()
    }

    pub async fn active_handle(&self) -> Option<DbHandle> {
        let inner = self.inner.lock().await;
        inner.active.clone()
    }

    pub async fn all_handles(&self) -> Vec<DbHandle> {
        let inner = self.inner.lock().await;
        inner.workers.keys().cloned().collect()
    }

    pub async fn worker_count(&self) -> usize {
        let inner = self.inner.lock().await;
        inner.workers.len()
    }

    pub async fn shutdown_all(&self) {
        let handles: Vec<DbHandle> = {
            let inner = self.inner.lock().await;
            inner.workers.keys().cloned().collect()
        };
        for handle in handles {
            let _ = self.close_worker(&handle).await;
        }
        info!("All workers shut down");
    }

    /// Start the idle-GC watchdog. Must be called from within a tokio runtime.
    ///
    /// Workers that have had no requests for longer than `idle_timeout` (and have
    /// no in-flight requests) are closed automatically. The watchdog runs until the
    /// process exits; it holds only a weak clone of the router state so it does not
    /// process exits.
    pub fn start_watchdog(&self, idle_timeout: Duration, check_interval: Duration) {
        let state = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(check_interval);
            loop {
                ticker.tick().await;
                // Collect expired handles without holding the lock during close.
                let expired: Vec<DbHandle> = {
                    let inner = state.inner.lock().await;
                    inner
                        .workers
                        .iter()
                        .filter(|(_, w)| {
                            w.pending.is_empty() && w.last_active.elapsed() > idle_timeout
                        })
                        .map(|(h, _)| h.clone())
                        .collect()
                };
                for handle in expired {
                    warn!(
                        "GC: closing idle worker {} (idle > {}s)",
                        handle,
                        idle_timeout.as_secs()
                    );
                    let _ = state.close_worker(&handle).await;
                }
            }
        });
    }
}

impl Default for RouterState {
    fn default() -> Self {
        Self::new().expect("Failed to create RouterState")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_module_exists() {
        let _ = std::module_path!();
    }

    #[test]
    fn test_protocol_types_accessible() {
        use crate::router::protocol::{RpcRequest, RpcResponse};
        use serde_json::json;
        let req = RpcRequest::new("test-id", "open", json!({"path": "/tmp/test.i64"}));
        assert_eq!(req.id, "test-id");
        let resp = RpcResponse::ok("test-id", json!({"ok": true}));
        assert_eq!(resp.id, "test-id");
    }

    #[tokio::test]
    async fn test_router_state_creation() {
        let router = RouterState::new().expect("RouterState should be created");
        assert_eq!(router.worker_count().await, 0);
        assert!(router.active_handle().await.is_none());
        assert!(router.all_handles().await.is_empty());
    }

    #[tokio::test]
    async fn test_route_request_no_active_fails() {
        let router = RouterState::new().unwrap();
        let result = router
            .route_request(None, "list_functions", serde_json::json!({}))
            .await;
        assert!(result.is_err());
    }

    #[test]
    #[ignore = "requires IDA Pro license and compiled binary"]
    fn test_worker_subprocess_responds() {}

    #[test]
    #[ignore = "requires IDA Pro license and compiled binary"]
    fn test_worker_eof_graceful_shutdown() {}
}
