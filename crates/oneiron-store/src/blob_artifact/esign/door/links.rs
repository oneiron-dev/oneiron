//! `vault.esign.links.issue` for a narrowed credential (FIX 6403). The mint
//! stays the vault owner's: a world-, facet- or record-scoped credential
//! mints a draft's signing links only when it is the owner's own (self-held,
//! undelegated, a person's, live) and its read lane reaches the draft
//! ([`super::super::lane_scope`]). Its proof authorizes this one mint and
//! no other act; no owner proof is made from it.
use crate::write_envelope::claim_body::lexical_query_hint::ScopedRead;
use oneiron_base::edge::EdgeActorClass;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use std::collections::BTreeMap;

const VERB: &str = "vault.esign.links.issue";

/// The refusal of a caller that is not the vault owner.
pub fn not_owner() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{VERB} is the vault owner's"),
        &["Call it as the vault's owner."],
    )
}

