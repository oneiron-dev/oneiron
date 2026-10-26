//! Ephemeral presence lane: validation, hub budget, and canonical fan-out frames.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::authority::PeerMachine;
use oneiron::claim::CallerLocality;
use oneiron::sync::{
    EphemeralStore, EphemeralWireState, decode_ephemeral_states, encode_ephemeral_states,
};

use crate::protocol::{self, ProtocolError};
use crate::server::SyncServer;

mod message_scope;

pub(super) use message_scope::releases_frame;

/// Clock skew tolerated for Loro `EphemeralStore` LWW timestamps from clients.
const MAX_EPHEMERAL_FUTURE_SKEW_MS: i64 = 60_000;

/// Flat ephemeral keys are control-plane identifiers, not arbitrary blobs.
const MAX_EPHEMERAL_KEY_BYTES: usize = 256;

/// The hub's live presence for a socket that just joined, one frame of at
/// most `max_ephemeral_snapshot_bytes` per `next()`: a hub larger than that
/// is sent in parts, never skipped, and no part is built before the last one
/// is sent (rule 5, row 19). A message partial goes only where its
/// conversation may be read now, by the socket's `locality` and the
/// `machine` it proved (FIX 9537).
pub(super) fn late_join_presence(
    server: &SyncServer,
    conn_id: u32,
    locality: CallerLocality,
    machine: PeerMachine,
) -> impl Iterator<Item = Vec<u8>> + '_ {
    let destination = message_scope::joining(server, locality, machine);
    // `keys()` leaves out deletes; a late joiner needs their tombstones too.
    let mut keys = {
        let mut presence = server.presence.lock();
        presence.expire(&server.ephemeral_store);
        decode_ephemeral_states(&server.ephemeral_store.encode_all())
    }
    .map_or_else(
        |e| {
            tracing::warn!(
                conn_id,
                error = protocol::transport_err_msg(e),
                "failed to decode ephemeral snapshot"
            );
            Vec::new()
        },
        |states| states.into_iter().map(|state| state.key).collect(),
    )
    .into_iter();
    let max = server.config.max_ephemeral_snapshot_bytes;
    let mut carry: Vec<EphemeralWireState> = Vec::new();
    let mut carry_bytes = 0;
    std::iter::from_fn(move || {
        loop {
            let mut part = std::mem::take(&mut carry);
            let mut part_bytes = std::mem::take(&mut carry_bytes);
            for key in keys.by_ref() {
                if !message_scope::releases_key(server, &key, &destination) {
                    continue;
                }
                let canonical = server.ephemeral_store.encode(&key);
                let states = match decode_ephemeral_states(&canonical) {
                    Ok(states) => states,
                    Err(e) => {
                        tracing::warn!(
                            conn_id,
                            error = protocol::transport_err_msg(e),
                            "failed to decode ephemeral snapshot"
                        );
                        continue;
                    }
                };
                if !part.is_empty() && part_bytes + canonical.len() > max {
                    carry = states;
                    carry_bytes = canonical.len();
                    break;
                }
                part_bytes += canonical.len();
                part.extend(states);
            }
            if part.is_empty() {
                return None;
            }
            if let Some(frame) = late_join_frame(conn_id, &part) {
                return Some(frame);
            }
        }
    })
}

fn late_join_frame(conn_id: u32, states: &[EphemeralWireState]) -> Option<Vec<u8>> {
    let encoded = encode_ephemeral_states(states)
        .and_then(|payload| protocol::encode_ephemeral(&payload).into_result());
    match encoded {
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

    // The frame's byte bound above bounds its records; their count is
    // never refused (rule 5).
    let states = decode_ephemeral_states(payload)
        .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;

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

/// The size of the hub with this frame applied, which the caller charges to
/// the server's retained-memory line (rule 5: charged, never capped per
/// hub). Each key's canonical frame stays within one frame's bound.
pub(super) fn ephemeral_hub_candidate(
    server: &SyncServer,
    payload: &[u8],
    states: &[EphemeralWireState],
) -> Result<usize, ProtocolError> {
    let current_snapshot = server.ephemeral_store.encode_all();
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

    Ok(candidate_snapshot.len())
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
