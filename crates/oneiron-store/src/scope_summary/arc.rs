//! A conversation's Arc (FIX 7509 P8, ARCH-0026 Dreamer row 4): one stable
//! summary per conversation path, written from the summary lines of the
//! closed sittings below it (owner SUMMARY-SOURCE = A), never from its own
//! earlier body (CLM-009). Facts and conflicts stay on claims.
//!
//! The Arc's projection identity is its declaration: the scope, purpose and
//! requester, never which sittings lie below it, so a new sitting advances
//! the same projection. What it was written from is its source set
//! ([`super::arc_sources`]), apart from that identity.

use crate::conversation_record::ScopePath;
use crate::conversation_record::ScopeSelector;
use crate::scope_summary::codec::invalid;
use crate::scope_summary::codec::parse_scope;
use crate::write_envelope::WriteActor;
use heed::RwTxn;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;
use std::collections::BTreeSet;

/// The declaration key an Arc names its scope under.
pub const ARC_KEY: &str = "arc";
/// The purpose an Arc takes.
pub const ARC_PURPOSE: &str = "milestone_arc_narrative";

/// Whether `input` declares an Arc.
pub fn is_arc_declaration(input: &Value) -> bool {
    input
        .as_map()
        .is_some_and(|fields| fields.iter().any(|(key, _)| key.as_str() == Some(ARC_KEY)))
}
