//! Локальная служба ZeroTier (запасной путь через интернет).
//!
//! Ключ доступа к её API (`authtoken.secret`) системная настройка копирует в
//! `%LOCALAPPDATA%\Raciya\zt.token`, порт — в `zt.port`. Через API программа узнаёт,
//! напрямую ли идёт связь с сервером, а на компьютере-контроллере сети — меняет её правила.

use serde_json::{json, Value};
use std::time::Duration;

fn credentials() -> Option<(String, u16)> {
    let dir = crate::system::user_dir();
    let token = std::fs::read_to_string(dir.join("zt.token")).ok()?.trim().to_string();
    if token.is_empty() {
        return None;
    }
    let port = std::fs::read_to_string(dir.join("zt.port"))
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok())
        .unwrap_or(9993);
    Some((token, port))
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(Duration::from_secs(3)).build()
}

pub fn get(path: &str) -> Option<Value> {
    let (token, port) = credentials()?;
    let resp = agent().get(&format!("http://127.0.0.1:{port}{path}")).set("X-ZT1-Auth", &token).call().ok()?;
    serde_json::from_str(&resp.into_string().ok()?).ok()
}

fn post(path: &str, body: &Value) -> Result<Value, String> {
    let (token, port) = credentials().ok_or("нет ключа доступа к ZeroTier")?;
    let resp = agent()
        .post(&format!("http://127.0.0.1:{port}{path}"))
        .set("X-ZT1-Auth", &token)
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
        .map_err(|e| format!("ZeroTier: {e}"))?;
    serde_json::from_str(&resp.into_string().map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

/// Правила сети: разрешены только ARP, ping и порт сервера (TCP и UDP, в обе стороны).
pub fn rules_for_port(port: u16) -> Value {
    json!([
        { "type": "MATCH_ETHERTYPE", "not": false, "or": false, "etherType": 2054 }, { "type": "ACTION_ACCEPT" },
        { "type": "MATCH_IP_PROTOCOL", "not": false, "or": false, "ipProtocol": 1 }, { "type": "ACTION_ACCEPT" },
        { "type": "MATCH_IP_DEST_PORT_RANGE", "not": false, "or": false, "start": port, "end": port }, { "type": "ACTION_ACCEPT" },
        { "type": "MATCH_IP_SOURCE_PORT_RANGE", "not": false, "or": false, "start": port, "end": port }, { "type": "ACTION_ACCEPT" },
        { "type": "ACTION_DROP" }
    ])
}

/// Пропускают ли правила сети этот порт (если правила вообще есть).
pub fn rules_allow_port(rules: &Value, port: u16) -> bool {
    let Some(list) = rules.as_array() else { return true };
    if list.is_empty() {
        return true;
    }
    list.iter().any(|r| {
        r["type"] == "MATCH_IP_DEST_PORT_RANGE"
            && r["start"].as_u64().unwrap_or(u64::MAX) <= port as u64
            && r["end"].as_u64().unwrap_or(0) >= port as u64
    })
}

/// Сервер переехал на другой порт. Если этот компьютер — контроллер сети `network`,
/// правила сети меняются сами. `Ok(false)` — контроллер на другом компьютере.
pub fn set_server_port(network: &str, port: u16) -> Result<bool, String> {
    let owned = get("/controller/network")
        .and_then(|v| v.as_array().cloned())
        .map(|ids| ids.iter().any(|id| id.as_str() == Some(network)))
        .unwrap_or(false);
    if !owned {
        return Ok(false);
    }
    post(&format!("/controller/network/{network}"), &json!({ "rules": rules_for_port(port) }))?;
    Ok(true)
}

/// Связь с узлом ZeroTier: `Some(Some(ms))` — напрямую, `Some(None)` — через ретранслятор.
pub fn peer_link(node: &str) -> Option<Option<i64>> {
    let v = get(&format!("/peer/{node}"))?;
    let direct = v["paths"]
        .as_array()
        .map(|p| p.iter().any(|x| x["active"].as_bool().unwrap_or(false)))
        .unwrap_or(false);
    Some(direct.then(|| v["latency"].as_i64().unwrap_or(-1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        let r = rules_for_port(64738);
        assert!(rules_allow_port(&r, 64738));
        assert!(!rules_allow_port(&r, 40738));
        assert!(rules_allow_port(&json!([]), 1));
        assert_eq!(r.as_array().unwrap().len(), 9);
    }
}
