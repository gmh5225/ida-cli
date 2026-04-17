use serde::{Deserialize, Serialize};
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
    pub detail: String,
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

fn probe_node(node: &FederationNodeConfig) -> FederationNodeStatus {
    if !node.enabled {
        return FederationNodeStatus {
            name: node.name.clone(),
            url: node.url.clone(),
            enabled: false,
            healthy: false,
            ready: false,
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
                detail: "missing host".to_string(),
            };
        }
    };
    let port = uri.port_u16().unwrap_or(80);

    let healthy = fetch_json(host, port, "/healthz")
        .ok()
        .and_then(|v| v.get("ok").and_then(|v| v.as_bool()))
        .unwrap_or(false);
    let ready = fetch_json(host, port, "/readyz")
        .ok()
        .and_then(|v| v.get("ok").and_then(|v| v.as_bool()))
        .unwrap_or(false);

    FederationNodeStatus {
        name: node.name.clone(),
        url: node.url.clone(),
        enabled: true,
        healthy,
        ready,
        detail: if healthy || ready {
            "ok".to_string()
        } else {
            "unreachable or unhealthy".to_string()
        },
    }
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
