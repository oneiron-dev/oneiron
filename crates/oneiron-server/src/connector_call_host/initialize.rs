//! The same initialize exchange for a send and a replacement task session.

use super::*;

/// A failed initialize may have received an actual session before failing.
/// The original send keeps its error behavior; task recovery can end a new
/// session only after checking that no ledger row kept it.
pub(super) struct InitializeFailure {
    pub(super) sent: Sent,
    pub(super) live: Option<LiveSession>,
}

pub(super) fn check_issuer(issuer: Option<(&Arc<Vault>, EntityId, &str)>) -> Result<(), Sent> {
    let Some((vault, key_ref, tool)) = issuer else {
        return Ok(());
    };
    match vault.connector_issuer_hold(&key_ref, tool) {
        Ok(None) => Ok(()),
        Ok(Some(reason)) => Err(Sent::held(reason)),
        Err(error) => {
            tracing::warn!(%error, "connector issuer binding not read");
            Err(Sent::not_sent(
                OutboundFailureKind::TransportNotStarted,
                None,
            ))
        }
    }
}

pub(super) fn initialize(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    revision: &str,
    protocol: &HeaderValue,
    auth: Option<HeaderValue>,
    capabilities: &RemoteTaskClientCapabilities,
    issuer: Option<(&Arc<Vault>, EntityId, &str)>,
) -> Result<LiveSession, InitializeFailure> {
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": INITIALIZE_ID,
        "method": "initialize",
        "params": {
            "protocolVersion": revision,
            "capabilities": capabilities,
            "clientInfo": { "name": "oneiron", "version": env!("CARGO_PKG_VERSION") },
        },
    });
    let response = post_json(
        client,
        endpoint,
        &initialize,
        auth.as_ref(),
        None,
        Some(HANDSHAKE_TIMEOUT),
    )
    .send()
    .map_err(|_| InitializeFailure {
        sent: Sent::not_sent(OutboundFailureKind::TransportNotStarted, None),
        live: None,
    })?;
    if !response.status().is_success() {
        return Err(InitializeFailure {
            sent: Sent::refused_status(response.status(), response.headers()),
            live: None,
        });
    }
    let live = LiveSession {
        client: client.clone(),
        endpoint: endpoint.to_owned(),
        protocol: protocol.clone(),
        session: response.headers().get(SESSION_HEADER).cloned(),
        auth,
    };
    let initialized = match read_reply(response, INITIALIZE_ID) {
        Ok(Some((message, _))) => message,
        _ => {
            return Err(InitializeFailure {
                sent: Sent::not_sent(OutboundFailureKind::Rejected, None),
                live: Some(live),
            });
        }
    };
    // The owner approved the pinned revision, not one the server substitutes.
    if initialized.get("error").is_some()
        || initialized
            .pointer("/result/protocolVersion")
            .and_then(Value::as_str)
            != Some(revision)
    {
        return Err(InitializeFailure {
            sent: Sent::not_sent(OutboundFailureKind::Rejected, None),
            live: Some(live),
        });
    }
    if let Err(sent) = check_issuer(issuer) {
        return Err(InitializeFailure {
            sent,
            live: Some(live),
        });
    }
    let notification = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
    let sent = match live.post(&notification, Some(HANDSHAKE_TIMEOUT)).send() {
        Ok(response) if response.status().is_success() => return Ok(live),
        Ok(response) => Sent::refused_status(response.status(), response.headers()),
        Err(_) => Sent::not_sent(OutboundFailureKind::TransportNotStarted, None),
    };
    Err(InitializeFailure {
        sent,
        live: Some(live),
    })
}
