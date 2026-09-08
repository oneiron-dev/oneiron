//! Ephemeral presence lane: validation, hub budget, and canonical fan-out frames.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::sync::{EphemeralStore, EphemeralWireState, decode_ephemeral_states};

use crate::protocol::{self, ProtocolError};
use crate::server::SyncServer;

/// Clock skew tolerated for Loro `EphemeralStore` LWW timestamps from clients.
const MAX_EPHEMERAL_FUTURE_SKEW_MS: i64 = 60_000;

/// Hard cap on records decoded from one ephemeral frame, independent of bytes.
const MAX_EPHEMERAL_RECORDS_PER_FRAME: usize = 1024;

/// Flat ephemeral keys are control-plane identifiers, not arbitrary blobs.
const MAX_EPHEMERAL_KEY_BYTES: usize = 256;

pub(super) fn encode_late_join_ephemeral_snapshot(
    server: &SyncServer,
    conn_id: u32,
) -> Option<Vec<u8>> {
    server.ephemeral_store.remove_outdated();
    let snapshot = server.ephemeral_store.encode_all();
    match decode_ephemeral_states(&snapshot) {
        Ok(states) if states.is_empty() => return None,
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(
                conn_id,
                error = protocol::transport_err_msg(e),
                "failed to decode ephemeral snapshot"
            );
            return None;
        }
    }
    if snapshot.len() > server.config.max_ephemeral_snapshot_bytes {
        tracing::warn!(
            conn_id,
            size = snapshot.len(),
            max = server.config.max_ephemeral_snapshot_bytes,
            "ephemeral snapshot exceeds cap; skipping late-join snapshot"
        );
        return None;
    }

    match protocol::encode_ephemeral(&snapshot).into_result() {
        Ok(msg) => Some(msg),
        Err(e) => {
            tracing::warn!(
                conn_id,
                error = protocol::transport_err_msg(e),
                "failed to encode ephemeral snapshot"
            );
            None
        }
    }
}

pub(super) fn validate_ephemeral_payload(
    server: &SyncServer,
    payload: &[u8],
) -> Result<Vec<EphemeralWireState>, ProtocolError> {
    if payload.len() > server.config.max_ephemeral_payload_bytes {
        return Err(ProtocolError::FrameTooLarge {
            size: payload.len(),
            max: server.config.max_ephemeral_payload_bytes,
        });
    }

    let states = decode_ephemeral_states(payload)
        .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
    if states.len() > MAX_EPHEMERAL_RECORDS_PER_FRAME {
        return Err(ProtocolError::InvalidPayload(
            "too many ephemeral records in one frame",
        ));
    }

    let max_timestamp = ephemeral_now_ms().saturating_add(MAX_EPHEMERAL_FUTURE_SKEW_MS);
    for state in &states {
        if state.key.is_empty() {
            return Err(ProtocolError::InvalidPayload("empty ephemeral key"));
        }
        if state.key.len() > MAX_EPHEMERAL_KEY_BYTES {
            return Err(ProtocolError::InvalidPayload("ephemeral key too long"));
        }
        if state.timestamp > max_timestamp {
            return Err(ProtocolError::InvalidPayload(
                "ephemeral timestamp too far in future",
            ));
        }
    }

    Ok(states)
}

pub(super) fn ensure_ephemeral_hub_budget(
    server: &SyncServer,
    payload: &[u8],
    states: &[EphemeralWireState],
) -> Result<(), ProtocolError> {
    let current_snapshot = server.ephemeral_store.encode_all();
    if current_snapshot.len() > server.config.max_ephemeral_snapshot_bytes {
        return Err(ProtocolError::FrameTooLarge {
            size: current_snapshot.len(),
            max: server.config.max_ephemeral_snapshot_bytes,
        });
    }

    let candidate = EphemeralStore::new(server.config.ephemeral_timeout_ms);
    if !current_snapshot.is_empty() {
        candidate
            .apply(&current_snapshot)
            .map_err(|_| ProtocolError::InvalidPayload("invalid ephemeral hub snapshot"))?;
    }
    candidate
        .apply(payload)
        .map_err(|_| ProtocolError::InvalidPayload("invalid ephemeral payload"))?;
    candidate.remove_outdated();

    let candidate_snapshot = candidate.encode_all();
    if candidate_snapshot.len() > server.config.max_ephemeral_snapshot_bytes {
        return Err(ProtocolError::FrameTooLarge {
            size: candidate_snapshot.len(),
            max: server.config.max_ephemeral_snapshot_bytes,
        });
    }

    let mut seen = HashSet::new();
    for state in states {
        if !seen.insert(state.key.as_str()) {
            continue;
        }

        let canonical = candidate.encode(&state.key);
        if canonical.len() > server.config.max_ephemeral_payload_bytes {
            return Err(ProtocolError::FrameTooLarge {
                size: canonical.len(),
                max: server.config.max_ephemeral_payload_bytes,
            });
        }
    }

    Ok(())
}

pub(super) fn canonical_ephemeral_frames(
    server: &SyncServer,
    states: &[EphemeralWireState],
) -> Result<Vec<Vec<u8>>, ProtocolError> {
    let mut seen = HashSet::new();
    let mut frames = Vec::new();
    for state in states {
        if !seen.insert(state.key.clone()) {
            continue;
        }

        let canonical = server.ephemeral_store.encode(&state.key);
        let canonical_states = decode_ephemeral_states(&canonical)
            .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
        if canonical_states.is_empty() {
            continue;
        }
        if canonical.len() > server.config.max_ephemeral_payload_bytes {
            return Err(ProtocolError::FrameTooLarge {
                size: canonical.len(),
                max: server.config.max_ephemeral_payload_bytes,
            });
        }
        let encoded = protocol::encode_ephemeral(&canonical)
            .into_result()
            .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
        frames.push(encoded);
    }

    Ok(frames)
}

fn ephemeral_now_ms() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    millis.min(i64::MAX as u128) as i64
}
