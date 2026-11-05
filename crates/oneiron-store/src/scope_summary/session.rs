//! A sitting's summary (FIX 7509, ARCH-0026 Dreamer row 4): queued by the
//! sitting's close, written from the turns the sitting retained, and never
//! from its own earlier body (CLM-009).
//!
//! The close only queues it: nothing is read or checked there. The sitting's
//! actor, sources and readability are judged when the attempt runs, and a
//! refusal there is the attempt's failure, never the close's.

use crate::attempt_id::AttemptId;
use crate::consolidation_scope::DreamerConsolidationScope;
use crate::dreamer_attempt_kind::DREAMER_SCOPE_SUMMARY_ATTEMPT_TYPE;
use crate::dreamer_attempt_payload::DreamerAttemptPayload;
use crate::scope_summary::codec::invalid;
use crate::scope_summary::codec::reply_summary;
use crate::write_envelope::WriteActor;
use heed::{RoTxn, RwTxn};
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_MACHINE;
use oneiron_base::registry::ENTITY_TYPE_PERSON;
use oneiron_base::registry::ENTITY_TYPE_TURN;
use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;

/// The declaration key a sitting's summary names its sitting under.
pub const SESSION_KEY: &str = "session";
/// The purpose a sitting's summary takes.
pub const SESSION_PURPOSE: &str = "session_recap";
const SOURCE_SET_DOMAIN: &[u8] = b"oneiron:session-summary-sources:v1";

/// Whether `input` declares a sitting's summary.
pub fn is_session_declaration(input: &Value) -> bool {
    input.as_map().is_some_and(|fields| {
        fields
            .iter()
            .any(|(key, _)| key.as_str() == Some(SESSION_KEY))
    })
}

/// The source set a sitting's summary was written from: its sitting and its
/// TURNs, sorted and once each, so the same set is the same id.
pub fn source_set_id(session: &EntityId, turns: &[EntityId]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SOURCE_SET_DOMAIN);
    hasher.update(session.as_bytes());
    for turn in turns.iter().collect::<std::collections::BTreeSet<_>>() {
        hasher.update(turn.as_bytes());
    }
    *hasher.finalize().as_bytes()
}
