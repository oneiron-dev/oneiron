//! Fresh-vault browser setup through the same owner doors as acceptance.
use std::{fs, path::Path};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use serde_json::{Value, json};
use tokio::time::Instant;
use super::{Result, read, served::{isolated, once}, write_json};

const PACK: &str = "oneiron.browser";
const CONNECTION: &str = "browser-guest";

/// Bootstrap while the vault is stopped; the link never reaches the candidate.
pub(crate) async fn bootstrap(binary: &Path, config: &Path, issuer: &str,
    origin: &str, dir: &Path, browser: &Value, deadline: Instant) -> Result<()> {
    let mut evidence = json!({"pack":PACK,"connection_id":CONNECTION,"browser":browser,
        "status":"started","install_receipt":null,"verify_verdict":null,"stop_cause":null});
    write_json(&dir.join("browser-setup.json"), &evidence)?;
    let mut command = isolated(binary);
    command.args(["token", "bootstrap", "--url", origin, "--lifetime-secs", "86400", "--config"]).arg(config)
        .env("ONEIRON_AUTH_SECRET", issuer);
    let result = once(command, deadline, &dir.join("browser-owner-link.stdout")).await
        .map_err(|e| format!("browser_pack_unavailable:owner_bootstrap:{e}"));
    if let Err(cause) = &result {
        evidence["status"] = json!("failed"); evidence["stop_cause"] = json!(cause);
        write_json(&dir.join("browser-setup.json"), &evidence)?;
    }
    result
}

/// One prepare, one owner approval, one synchronous verify. No retry/poll of a
/// failed check: rc=0 alone is not readiness. Keep every original reply.
pub(crate) async fn install(binary: &Path, client: &reqwest::Client, origin: &str,
    dir: &Path, deadline: Instant) -> Result<()> {
    let path = dir.join("browser-setup.json");
    let mut evidence: Value = read(&path)?;
    let result: Result<()> = async {
        let (bearer, seed) = redeem(client, origin, dir, deadline).await
            .map_err(|e| format!("browser_pack_unavailable:owner_pair:{e}"))?;
        let prepare = api(binary, origin, &bearer, &seed,
            &["call", "vault.packs.setup.prepare"], &json!({"pack":PACK}),
            dir, "browser-pack-prepare", deadline).await
            .map_err(|e| format!("browser_pack_unavailable:prepare:{e}"))?;
        evidence["prepare"] = prepare.clone();
        let (action, state) = grant_card(&prepare)
            .ok_or_else(|| format!("browser_pack_unavailable:grant_card_missing:{prepare}"))?;
        let allowed = api(binary, origin, &bearer, &seed,
            &["raw", "POST", "/v1/owner/packs/setup/answer"],
            &json!({"pack":PACK,"card_action":{"action_id":action,"state":state}}),
            dir, "browser-pack-allow", deadline).await
            .map_err(|e| format!("browser_pack_unavailable:allow:{e}"))?;
        evidence["approval"] = allowed;
        let verdict = api(binary, origin, &bearer, &seed,
            &["call", "vault.packs.setup.verify"],
            &json!({"pack":PACK,"connection":CONNECTION}),
            dir, "browser-pack-verify", deadline).await
            .map_err(|e| format!("browser_guest_unverified:verify:{e}"))?;
        evidence["verify_verdict"] = verdict.clone();
        let view = &verdict["setup"];
        let connection = view["connections"].as_array().and_then(|items|
            items.iter().find(|c| c["id"] == CONNECTION));
        if view["status"] != "active" || view["ready"] != true
            || !connection.is_some_and(|c| c["ready"] == true && c["check"]["state"] == "verified") {
            return Err(format!("browser_guest_unverified:{verdict}"));
        }
        // setup.verify activates the seeded Candidate. Read the actual install
        // receipt rather than replacing its built-in provenance with a put.
        let installed = api(binary, origin, &bearer, &seed,
            &["raw", "GET", "/v1/owner/packs"], &Value::Null,
            dir, "browser-pack-installed", deadline).await
            .map_err(|e| format!("browser_pack_unavailable:install_receipt:{e}"))?;
        let receipt = installed.as_array().and_then(|items| items.iter().find(|p|
            p["pack_name"] == PACK && p["status"] == "active"
                && p["source_id"] == view["source_id"] && p["content_hash"] == view["content_hash"]))
            .ok_or_else(|| format!("browser_pack_unavailable:install_receipt_missing:{installed}"))?;
        evidence["install_receipt"] = receipt.clone();
        Ok(())
    }.await;
    evidence["status"] = json!(if result.is_ok() {"ready"} else {"failed"});
    evidence["stop_cause"] = json!(result.as_ref().err());
    write_json(&path, &evidence)?;
    result
}

fn grant_card(node: &Value) -> Option<(String, Value)> {
    match node {
        Value::Object(object) => {
            if let (Some(actions), Some(state)) = (object.get("actions").and_then(Value::as_array),
                object.get("$state").and_then(Value::as_object)) {
                for action in actions {
                    let id = action["actionId"].as_str().or_else(|| action["action_id"].as_str());
                    if let Some(id) = id.filter(|id| id.starts_with("grant.")) {
                        let mut state = state.clone();
                        for (key, value) in &mut state {
                            if key.starts_with("allow.") { *value = json!({"type":"bool","value":true}); }
                        }
                        return Some((id.into(), Value::Object(state)));
                    }
                }
            }
            object.values().find_map(grant_card)
        }
        Value::Array(items) => items.iter().find_map(grant_card),
        _ => None,
    }
}

async fn api(binary: &Path, origin: &str, bearer: &str, seed: &str, args: &[&str],
    body: &Value, dir: &Path, name: &str, deadline: Instant) -> Result<Value> {
    let input = dir.join(format!("{name}-request.json"));
    write_json(&input, body)?;
    let stdout = dir.join(format!("{name}.stdout"));
    let mut command = isolated(binary);
    command.args(["api", "--base-url", origin]).args(args)
        .env("ONEIRON_SECRET", bearer).env("ONEIRON_BINDING_KEY", seed);
    if !body.is_null() { command.arg("--data").arg(format!("@{}", input.display())); }
    let result = once(command, deadline, &stdout).await;
    let text = fs::read_to_string(&stdout).map_err(|e| e.to_string())?;
    if let Err(cause) = result {
        let stderr = fs::read_to_string(stdout.with_extension("stderr")).map_err(|e| e.to_string())?;
        return Err(format!("{cause}:stdout={text}:stderr={stderr}"));
    }
    serde_json::from_str(&text).map_err(|e| format!("invalid_reply:{e}:{text}"))
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

/// Acceptance's public pairing HTTP exchange, with an async deadline. The API
/// CLI signs later owner calls; the issuer itself is never an HTTP credential.
async fn redeem(client: &reqwest::Client, origin: &str, dir: &Path,
    deadline: Instant) -> Result<(String, String)> {
    let text = fs::read_to_string(dir.join("browser-owner-link.stdout")).map_err(|e| e.to_string())?;
    let link = text.lines().last().ok_or("owner_link_missing")?;
    let (location, fragment) = link.split_once('#').ok_or("owner_link_malformed")?;
    if location != format!("{origin}/pair") { return Err("owner_link_origin_mismatch".into()) }
    let parts: Vec<_> = fragment.split('.').collect();
    if !matches!(parts.len(), 2 | 4) { return Err("owner_link_malformed".into()) }
    let code: String = parts[0].to_ascii_uppercase().chars().map(|c| match c {
        'O'=>'0', 'I'|'L'=>'1', other=>other,
    }).collect();
    let mut seed = [0u8;32]; rand::rngs::OsRng.fill_bytes(&mut seed);
    let key = SigningKey::from_bytes(&seed);
    let binding = key.verifying_key().to_bytes();
    let mut transcript = if parts.len() == 4 { b"oneiron/pairing-binding/pinned/v1\0".to_vec() }
        else { b"oneiron/pairing-binding/v2\0".to_vec() };
    transcript.extend_from_slice(code.as_bytes()); transcript.extend_from_slice(&binding);
    for part in &parts[2..] {
        if part.len() != 64 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("owner_link_pin_malformed".into());
        }
        for pair in part.as_bytes().chunks_exact(2) {
            let byte = u8::from_str_radix(std::str::from_utf8(pair).map_err(|e| e.to_string())?,16)
                .map_err(|_| "owner_link_pin_malformed")?;
            transcript.push(byte);
        }
    }
    transcript.extend_from_slice(parts[1].as_bytes());
    let body = json!({"code":code,"holder_ref":parts[1],"binding_key":hex(&binding),
        "signature":hex(&key.sign(&transcript).to_bytes())});
    let (status, response) = tokio::time::timeout_at(deadline, async {
        let response = client.post(format!("{origin}/v1/core/pairing/redeem")).json(&body)
            .send().await.map_err(|e| e.to_string())?;
        let status = response.status();
        let text = response.text().await.map_err(|e| e.to_string())?;
        Ok::<_, String>((status,text))
    }).await.map_err(|_| "timeout")??;
    // The reply contains the owner slip. Retain it privately, never in a stop row.
    fs::write(dir.join("browser-owner-redeem.json"), &response).map_err(|e| e.to_string())?;
    if !status.is_success() { return Err(format!("owner_redeem_http:{status}")); }
    let paired: Value = serde_json::from_str(&response).map_err(|_| "owner_redeem_malformed")?;
    let token = paired["token"].as_str().filter(|s| s.starts_with("v2.slip."))
        .ok_or("owner_redeem_no_slip")?;
    Ok((token.into(), hex(&seed)))
}
