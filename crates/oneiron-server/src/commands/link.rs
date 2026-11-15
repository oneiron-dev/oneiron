//! `oneiron link`, `oneiron link status` and `oneiron unlink` (L10-16;
//! canon cross-arch-0024 M4.25): thin clients of a running server's
//! `/v1/owner/link`, with the owner's credential as `oneiron api` reads it.
//! Each prints the server's JSON answers; a refusal's body goes to stderr as
//! the server sent it, and the command fails.
//!
//! `oneiron link` asks for the peer, then reads where it stands every few
//! seconds until its machine is live here, the control plane says it
//! failed, or `--wait-secs` pass.

use std::time::{Duration, Instant};

use reqwest::Method;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::api::{normalized_base, signed_binding};
use crate::cli::{LinkArgs, LinkCommand, RunningServerArgs, UnlinkArgs};
use oneiron_vault_contract::BINDING_HEADER;

/// The owner route all three commands ask.
const LINK_PATH: &str = "/v1/owner/link";

/// How often `oneiron link` reads where the peer stands.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// `oneiron link` and `oneiron link status`.
///
/// # Errors
/// A refused or failed call; a peer the control plane says failed, or one
/// that did not enrol within `--wait-secs`.
pub fn link(args: LinkArgs) -> anyhow::Result<()> {
    if let Some(LinkCommand::Status(server)) = &args.command {
        return print(&call(server, Method::GET, None)?);
    }
    let origin = args.origin.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "oneiron link needs --origin: this server's https:// origin as the hosted peer \
             reaches it"
        )
    })?;
    print(&call(
        &args.server,
        Method::POST,
        Some(json!({ "origin": origin })),
    )?)?;
    // A wait past the clock's range has no deadline: it ends when the peer
    // enrols or fails.
    let deadline = Instant::now().checked_add(Duration::from_secs(args.wait_secs));
    loop {
        let status = call(&args.server, Method::GET, None)?;
        if status["machine"]["live"] == Value::Bool(true) {
            return print(&status);
        }
        if status["cloud"]["state"] == "failed" {
            print(&status)?;
            anyhow::bail!("the control plane says the hosted peer failed");
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            print(&status)?;
            anyhow::bail!(
                "the hosted peer did not enrol within {} s; `oneiron link status` shows where \
                 it stands",
                args.wait_secs
            );
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// `oneiron unlink`.
///
/// # Errors
/// A refused or failed call.
pub fn unlink(args: UnlinkArgs) -> anyhow::Result<()> {
    print(&call(&args.server, Method::DELETE, None)?)
}

fn print(value: &Value) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// One call of `method` on the server's `/v1/owner/link`, with `body` as
/// JSON, under the owner's credential and a fresh binding proof for a slip.
fn call(server: &RunningServerArgs, method: Method, body: Option<Value>) -> anyhow::Result<Value> {
    let secret = match std::env::var(&server.secret_env) {
        Ok(secret) => Some(Zeroizing::new(secret)),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("{} is not valid UTF-8; nothing was sent", server.secret_env)
        }
    };
    let binding = secret
        .as_deref()
        .filter(|token| token.starts_with("v2.slip."))
        .map(|token| signed_binding(token, &server.binding_key_env))
        .transpose()?;
    let url = format!("{}{LINK_PATH}", normalized_base(&server.url)?);
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut request = client.request(method, &url);
    if let Some(secret) = &secret {
        request = request.bearer_auth(secret.as_str());
    }
    if let Some(binding) = &binding {
        request = request.header(BINDING_HEADER, binding.as_str());
    }
    if let Some(body) = body {
        request = request
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(&body)?);
    }
    let response = request
        .send()
        .map_err(|error| anyhow::anyhow!("{url}: {error}"))?;
    let status = response.status();
    let text = response.text().unwrap_or_default();
    if !status.is_success() {
        eprintln!("{text}");
        anyhow::bail!("{url} answered {status}");
    }
    serde_json::from_str(&text).map_err(|_| anyhow::anyhow!("{url} answered {status} with no JSON"))
}
