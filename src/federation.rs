use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationNodeConfig {
    pub name: String,
    pub url: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_weight() -> u32 {
    1
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize)]
pub struct FederationNodeStatus {
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub healthy: bool,
    pub ready: bool,
    pub worker_count: Option<u64>,
    pub max_workers: Option<u64>,
    pub route_queue_depth: Option<u64>,
    pub prewarm_queue_depth: Option<u64>,
    pub load_score: Option<f64>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemoteDispatchResult {
    pub node: String,
    pub url: String,
    pub response: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemoteTaskStatus {
    pub node: String,
    pub url: String,
    pub task_id: String,
    pub payload: Value,
}

pub fn load_nodes_from_env() -> Vec<FederationNodeConfig> {
    let path = match std::env::var("IDA_CLI_FEDERATION_CONFIG") {
        Ok(path) => path,
        Err(_) => return Vec::new(),
    };
    load_nodes(&path).unwrap_or_default()
}

pub fn load_nodes(path: &str) -> anyhow::Result<Vec<FederationNodeConfig>> {
    let data = fs::read_to_string(path)?;
    let nodes: Vec<FederationNodeConfig> = serde_json::from_str(&data)?;
    Ok(nodes)
}

pub fn probe_nodes(nodes: &[FederationNodeConfig]) -> Vec<FederationNodeStatus> {
    nodes.iter().map(probe_node).collect()
}

pub fn choose_ready_node(nodes: &[FederationNodeConfig]) -> Option<FederationNodeConfig> {
    choose_ready_nodes(nodes).into_iter().next()
}

pub fn choose_ready_nodes(nodes: &[FederationNodeConfig]) -> Vec<FederationNodeConfig> {
    let mut ready: Vec<(FederationNodeConfig, FederationNodeStatus)> = nodes
        .iter()
        .filter(|node| node.enabled)
        .filter_map(|node| {
            let status = probe_node(node);
            status.ready.then_some((node.clone(), status))
        })
        .collect();
    ready.sort_by(|(lhs_node, lhs_status), (rhs_node, rhs_status)| {
        let lhs = node_rank(lhs_node, lhs_status);
        let rhs = node_rank(rhs_node, rhs_status);
        lhs.partial_cmp(&rhs).unwrap_or(std::cmp::Ordering::Equal)
    });
    ready.into_iter().map(|(node, _)| node).collect()
}

pub fn submit_enqueue(
    node: &FederationNodeConfig,
    payload: &Value,
) -> anyhow::Result<RemoteDispatchResult> {
    let uri: hyper::Uri = node.url.parse()?;
    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("missing host in node url"))?;
    let port = uri.port_u16().unwrap_or(80);
    let response = post_json(host, port, "/enqueuez", payload)?;
    Ok(RemoteDispatchResult {
        node: node.name.clone(),
        url: node.url.clone(),
        response,
    })
}

pub fn fetch_remote_task(
    node: &FederationNodeConfig,
    task_id: &str,
) -> anyhow::Result<RemoteTaskStatus> {
    let uri: hyper::Uri = node.url.parse()?;
    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("missing host in node url"))?;
    let port = uri.port_u16().unwrap_or(80);
    let payload = fetch_json(host, port, &format!("/taskz/{task_id}"))?;
    Ok(RemoteTaskStatus {
        node: node.name.clone(),
        url: node.url.clone(),
        task_id: task_id.to_string(),
        payload,
    })
}

fn probe_node(node: &FederationNodeConfig) -> FederationNodeStatus {
    if !node.enabled {
        return FederationNodeStatus {
            name: node.name.clone(),
            url: node.url.clone(),
            enabled: false,
            healthy: false,
            ready: false,
            worker_count: None,
            max_workers: None,
            route_queue_depth: None,
            prewarm_queue_depth: None,
            load_score: None,
            detail: "disabled".to_string(),
        };
    }

    let uri: hyper::Uri = match node.url.parse() {
        Ok(uri) => uri,
        Err(err) => {
            return FederationNodeStatus {
                name: node.name.clone(),
                url: node.url.clone(),
                enabled: true,
                healthy: false,
                ready: false,
                worker_count: None,
                max_workers: None,
                route_queue_depth: None,
                prewarm_queue_depth: None,
                load_score: None,
                detail: format!("invalid url: {err}"),
            };
        }
    };

    if uri.scheme_str() != Some("http") {
        return FederationNodeStatus {
            name: node.name.clone(),
            url: node.url.clone(),
            enabled: true,
            healthy: false,
            ready: false,
            worker_count: None,
            max_workers: None,
            route_queue_depth: None,
            prewarm_queue_depth: None,
            load_score: None,
            detail: "only http federation urls are currently supported".to_string(),
        };
    }

    let host = match uri.host() {
        Some(host) => host,
        None => {
            return FederationNodeStatus {
                name: node.name.clone(),
                url: node.url.clone(),
                enabled: true,
                healthy: false,
                ready: false,
                worker_count: None,
                max_workers: None,
                route_queue_depth: None,
                prewarm_queue_depth: None,
                load_score: None,
                detail: "missing host".to_string(),
            };
        }
    };
    let port = uri.port_u16().unwrap_or(80);

    let statusz = fetch_json(host, port, "/statusz").ok();
    let healthy = fetch_json(host, port, "/healthz")
        .ok()
        .and_then(|v| v.get("ok").and_then(|v| v.as_bool()))
        .unwrap_or(false);
    let ready = fetch_json(host, port, "/readyz")
        .ok()
        .and_then(|v| v.get("ok").and_then(|v| v.as_bool()))
        .unwrap_or(false);
    let worker_count = statusz
        .as_ref()
        .and_then(|v| v.get("worker_count").and_then(|v| v.as_u64()));
    let max_workers = statusz
        .as_ref()
        .and_then(|v| v.get("max_workers").and_then(|v| v.as_u64()));
    let route_queue_depth = statusz.as_ref().and_then(|v| {
        v.get("route_queue")
            .and_then(|v| v.as_array())
            .map(|items| items.len() as u64)
    });
    let prewarm_queue_depth = statusz.as_ref().and_then(|v| {
        v.get("prewarm_queue")
            .and_then(|v| v.as_array())
            .map(|items| items.len() as u64)
    });
    let load_score = compute_load_score(worker_count, max_workers, route_queue_depth, prewarm_queue_depth);

    FederationNodeStatus {
        name: node.name.clone(),
        url: node.url.clone(),
        enabled: true,
        healthy,
        ready,
        worker_count,
        max_workers,
        route_queue_depth,
        prewarm_queue_depth,
        load_score,
        detail: if healthy || ready {
            "ok".to_string()
        } else {
            "unreachable or unhealthy".to_string()
        },
    }
}

fn compute_load_score(
    worker_count: Option<u64>,
    max_workers: Option<u64>,
    route_queue_depth: Option<u64>,
    prewarm_queue_depth: Option<u64>,
) -> Option<f64> {
    let worker_score = match (worker_count, max_workers) {
        (Some(current), Some(max)) if max > 0 => current as f64 / max as f64,
        _ => return None,
    };
    let route_penalty = route_queue_depth.unwrap_or(0) as f64 / 100.0;
    let prewarm_penalty = prewarm_queue_depth.unwrap_or(0) as f64 / 100.0;
    Some(worker_score + route_penalty + prewarm_penalty)
}

fn node_rank(node: &FederationNodeConfig, status: &FederationNodeStatus) -> f64 {
    let load = status.load_score.unwrap_or(10.0);
    let weight_bonus = (node.weight.max(1) as f64).recip();
    load + weight_bonus
}

fn fetch_json(host: &str, port: u16, path: &str) -> anyhow::Result<serde_json::Value> {
    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept: application/json\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    let body = buf
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("invalid http response"))?;
    Ok(serde_json::from_str(body)?)
}

fn post_json(host: &str, port: u16, path: &str, payload: &Value) -> anyhow::Result<Value> {
    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let body = serde_json::to_vec(payload)?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.write_all(&body)?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    let body = buf
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("invalid http response"))?;
    Ok(serde_json::from_str(body)?)
}
