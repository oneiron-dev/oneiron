use std::io::Cursor;

use rmpv::Value;

use crate::dreamer_runner::DreamerConsolidationScope;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Domain for phase-2 candidate-bucket hashes (pinned, design D6). The
/// phase-1 partition hash keeps this domain unchanged (DESIGN-PIN A2).
pub const DREAMER_BUCKET_HASH_DOMAIN: &[u8] = b"oneiron:dreamer-bucket:v1";
/// Domain for reflection gap hashes (pinned, design D6).
pub const DREAMER_GAP_HASH_DOMAIN: &[u8] = b"oneiron:dreamer-gap:v1";
/// Domain for deterministic, write-once promotion-candidate claim ids. A
/// candidate's id is a pure function of its identity + the owning attempt so an
/// at-least-once re-run of the same durable step re-mints the SAME id.
pub const DREAMER_CLAIM_ID_HASH_DOMAIN: &[u8] = b"oneiron:dreamer-claim-id:v1";
/// Domain for swarm evidence content hashes (pinned, design D10).
pub const DREAMER_EVIDENCE_HASH_DOMAIN: &[u8] = b"oneiron:dreamer-evidence:v1";
/// A gap not re-observed within this window decays and is never re-surfaced
/// (escalate-or-let-go, never re-nag nightly).
pub const DREAMER_GAP_DECAY_MS: u64 = 14 * 24 * 60 * 60 * 1000;
/// `DreamerAttemptPayload.attempt_type` string for reflection gap-scan child
/// attempts (a payload discriminator, not a new queue kind).
pub const DREAMER_GAP_SCAN_ATTEMPT_TYPE: &str = "dreamer.reflection.gap_scan";
/// `DreamerAttemptPayload.attempt_type` string for ED-04's recurring-substitution
/// miner pass (ONE-1760, ARCH-0056 §4) — a payload discriminator beside the
/// gap scan, not a new queue kind and not a new wake mechanism. The pass rides
/// the landed SessionEnd wake, whose `input` names the ended sitting.
pub const DREAMER_SUBSTITUTION_MINE_ATTEMPT_TYPE: &str = "dreamer.edit_distance.substitution_mine";
/// Documented OPT-IN turn-body key naming the WORLD entity this turn's
/// content belongs to (16-byte MessagePack binary; ILD D4 opt-in precedent).
pub const TURN_BODY_WORLD_REF_KEY: &str = "world_ref";
/// Documented OPT-IN turn-body key naming the active FACET at turn time
/// (16-byte MessagePack binary). Absent = "channel gave no mask signal";
/// extraction may still assign one — it does NOT force the invariant layer.
pub const TURN_BODY_FACET_REF_KEY: &str = "facet_ref";
/// Default bound on ONE Meso round: the scan stops after this many admissible
/// TURNs even when the backlog is larger, and the remainder drains across the
/// following rounds (one capped round per session-close settlement). The cap
/// may cut between ANY two adjacent temporal keys, including two keys sharing
/// one `learned_at` second — the compound watermark records the exact cut.
pub const DEFAULT_MESO_ROUND_TURN_CAP: usize = 500;
/// Domain for the advisory partition-round hash — the exact-batch component of
/// a consolidation attempt's dedupe key (pinned; distinct from the phase-1/2
/// bucket domain so a round hash can never collide with a partition hash).
pub(crate) const DREAMER_PARTITION_ROUND_HASH_DOMAIN: &[u8] = b"oneiron:dreamer-partition-round:v1";

pub(super) const DREAMER_PRIVATE_WATERMARK_PREFIX: &[u8] = b"dreamer:watermark:v1:"; // + scope byte
pub(super) const DREAMER_PRIVATE_CURSOR_PREFIX: &[u8] = b"dreamer:cursor:v1:"; // + scope byte + partition_hash(32)
pub(super) const DREAMER_PRIVATE_GAP_PREFIX: &[u8] = b"dreamer:gap:v1:"; // + gap_hash(32)

/// Seconds-only watermark rows (`{schema_version, last_learned_at}`): decoded
/// as the complete-second boundary `last_turn_id = None`, never re-encoded.
pub(super) const WATERMARK_SCHEMA_VERSION_V1: u64 = 1;
pub(super) const WATERMARK_SCHEMA_VERSION: u64 = 2;
pub(super) const CURSOR_SCHEMA_VERSION: u64 = 1;
pub(super) const GAP_SCHEMA_VERSION: u64 = 1;
pub(super) const PARTITION_PAYLOAD_SCHEMA_VERSION: u64 = 1;

pub(super) const KEY_SCHEMA_VERSION: &str = "schema_version";
pub(super) const KEY_LAST_LEARNED_AT: &str = "last_learned_at";
pub(super) const KEY_LAST_TURN_ID: &str = "last_turn_id";
pub(super) const KEY_LAST_LEDGER_REVISION_HINT: &str = "last_ledger_revision_hint";
pub(super) const KEY_KIND: &str = "kind";
pub(super) const KEY_SUBJECT: &str = "subject";
pub(super) const KEY_EVIDENCE_TURN_REFS: &str = "evidence_turn_refs";
pub(super) const KEY_FIRST_SEEN: &str = "first_seen";
pub(super) const KEY_LAST_SEEN: &str = "last_seen";
pub(super) const KEY_ESCALATIONS: &str = "escalations";
pub(super) const KEY_DECAYED: &str = "decayed";
pub(super) const KEY_CONVERSATION: &str = "conversation_ref";
pub(super) const KEY_WORLD: &str = "world_ref";
pub(super) const KEY_FACET: &str = "facet_ref";
pub(super) const KEY_WATERMARK: &str = "watermark";
pub(super) const KEY_TURNS: &str = "turns";

pub(super) const fn invalid_consolidation(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

pub(super) fn scope_byte(scope: DreamerConsolidationScope) -> u8 {
    match scope {
        DreamerConsolidationScope::Micro => 0,
        DreamerConsolidationScope::Meso => 1,
        DreamerConsolidationScope::Macro => 2,
    }
}

pub(super) fn hash_optional_entity(hasher: &mut blake3::Hasher, entity: Option<&EntityId>) {
    match entity {
        Some(entity) => {
            hasher.update(&[1]);
            hasher.update(entity.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

// ---------------------------------------------------------------------------
// Codec helpers
// ---------------------------------------------------------------------------

pub(super) fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, value)
        .map_err(|_| invalid_consolidation("dreamer consolidation MessagePack encode failed"))?;
    Ok(encoded)
}

pub(super) fn decode_value(raw: &[u8]) -> Result<Value> {
    rmpv::decode::read_value(&mut Cursor::new(raw))
        .map_err(|_| invalid_consolidation("dreamer consolidation MessagePack decode failed"))
}

pub(super) fn expect_map<'v>(
    value: &'v Value,
    context: &'static str,
) -> Result<&'v Vec<(Value, Value)>> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(invalid_consolidation(context)),
    }
}

pub(super) fn expect_key(key: &Value) -> Result<&str> {
    key.as_str().ok_or(invalid_consolidation(
        "dreamer consolidation keys must be strings",
    ))
}
