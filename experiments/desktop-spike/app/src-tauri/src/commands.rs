use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::json;
use tauri::ipc::{InvokeBody, Request, Response};
use tauri::State;

use crate::protocol::MAX_BODY;
use crate::sidecar::{CoreError, Status, Supervisor};

const METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE"];
const PATH_PREFIXES: &[&str] = &["/api/", "/spike/"];
const ALLOWED_HEADERS: &[&str] = &["content-type", "accept", "x-ciphermoth-entry"];
const MAX_PATH: usize = 8192;
const MAX_HEADER_VALUE: usize = 2048;
const MAX_TIMEOUT_MS: u64 = 120_000;

#[derive(Deserialize)]
struct Meta {
    method: String,
    path: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    headers: Vec<(String, String)>,
    timeout_ms: Option<u64>,
    client_id: Option<String>,
}

fn reject(code: &str, message: &str) -> String {
    serde_json::to_string(&CoreError::new(code, message)).unwrap()
}

fn visible_ascii(value: &str) -> bool {
    value.bytes().all(|b| (0x21..0x7f).contains(&b))
}

fn valid_path(path: &str) -> bool {
    path.len() <= MAX_PATH
        && visible_ascii(path)
        && PATH_PREFIXES.iter().any(|p| path.starts_with(p))
        && !path.contains("//")
        && !path.contains('\\')
        && !path.contains('#')
        && !path.contains('?')
        && path.split('/').all(|segment| {
            let lower = segment.to_ascii_lowercase();
            !matches!(
                lower.as_str(),
                "." | ".." | "%2e" | "%2e%2e" | ".%2e" | "%2e."
            )
        })
}

fn validate(meta: &Meta) -> Result<Vec<(String, String)>, String> {
    if !METHODS.contains(&meta.method.as_str()) {
        return Err(reject("forbidden_method", "method not allowed"));
    }
    if !valid_path(&meta.path) {
        return Err(reject("forbidden_path", "path not allowed"));
    }
    if meta.query.len() > MAX_PATH
        || !(meta.query.is_empty() || visible_ascii(&meta.query))
        || meta.query.contains('#')
    {
        return Err(reject("bad_query", "query not allowed"));
    }
    if meta.client_id.as_ref().is_some_and(|c| c.len() > 64) {
        return Err(reject("bad_client_id", "client id too long"));
    }
    let mut headers = Vec::new();
    for (name, value) in &meta.headers {
        let name = name.to_ascii_lowercase();
        if !ALLOWED_HEADERS.contains(&name.as_str()) {
            return Err(reject("forbidden_header", "header not allowed"));
        }
        if value.len() > MAX_HEADER_VALUE || !value.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            return Err(reject("bad_header", "header value not allowed"));
        }
        headers.push((name, value.clone()));
    }
    Ok(headers)
}

#[tauri::command]
pub async fn core_request(
    request: Request<'_>,
    core: State<'_, Arc<Supervisor>>,
) -> Result<Response, String> {
    let raw_meta = request
        .headers()
        .get("x-core-meta")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| reject("bad_meta", "missing request metadata"))?;
    let meta: Meta = serde_json::from_str(raw_meta)
        .map_err(|_| reject("bad_meta", "invalid request metadata"))?;
    let headers = validate(&meta)?;
    let body = match request.body() {
        InvokeBody::Raw(bytes) => bytes.clone(),
        InvokeBody::Json(serde_json::Value::Null) => Vec::new(),
        InvokeBody::Json(_) => return Err(reject("bad_body", "send raw bytes")),
    };
    if body.len() > MAX_BODY - 64 * 1024 {
        return Err(reject("too_large", "request body too large"));
    }
    let timeout = Duration::from_millis(meta.timeout_ms.unwrap_or(30_000).clamp(1, MAX_TIMEOUT_MS));
    let header = json!({
        "method": meta.method,
        "path": meta.path,
        "query": meta.query,
        "headers": headers,
    });
    let (head, body) = core
        .request(header, body, timeout, meta.client_id)
        .await
        .map_err(|e| serde_json::to_string(&e).unwrap())?;
    let head = serde_json::to_vec(&head).unwrap();
    let mut out = Vec::with_capacity(4 + head.len() + body.len());
    out.extend_from_slice(&(head.len() as u32).to_be_bytes());
    out.extend_from_slice(&head);
    out.extend_from_slice(&body);
    Ok(Response::new(out))
}

#[tauri::command]
pub fn core_cancel(client_id: String, core: State<'_, Arc<Supervisor>>) -> bool {
    core.cancel(&client_id)
}

#[tauri::command]
pub fn core_status(core: State<'_, Arc<Supervisor>>) -> Status {
    core.status()
}

#[tauri::command]
pub fn core_restart(core: State<'_, Arc<Supervisor>>) {
    core.restart();
}

#[cfg(test)]
mod tests {
    use super::valid_path;

    #[test]
    fn path_allowlist() {
        assert!(valid_path("/api/meta"));
        assert!(valid_path("/api/passwords/a%2Fb"));
        assert!(valid_path("/spike/attachments/3"));
        for bad in [
            "/docs",
            "/openapi.json",
            "/spike/../docs",
            "/api//meta",
            "/api/%2E%2E/x",
            "/api/a b",
            "/api/\u{e9}",
            "api/meta",
            "/api/x?y",
            "/api/x#y",
        ] {
            assert!(!valid_path(bad), "{bad}");
        }
    }
}
