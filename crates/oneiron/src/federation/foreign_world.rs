//! Where a guest's content lands here (FIX 3497). ARCH-0043: guest content
//! lands in a named foreign WORLD copy, never base. Federation admission
//! rewrites each guest CLAIM's world to the foreign id its source vault and
//! the sender's world derive, and routes the copy into that world's window, so
//! window residence, delivery attribution, FED-04 stale stamping and
//! retained-copy withholding all read the recipient's placement.
//!
//! The id is derived, never stored: a reader that holds a pact and a world id
//! the peer named, such as a courtesy deletion ask, translates it from the
//! fold's pact state alone.

use std::collections::BTreeSet;

use crate::authority::AuthorityFold;
use crate::claim::ClaimBody;
use crate::entity_id::{EntityId, ForeignWorldId, derived_domains};
use crate::error::{Error, Result};

/// How many counter values [`foreign_world_for`] tries before it refuses
/// (Engine ruling, CALLS "FIX 3497 foreign world id"). A derived id falls in
/// the foreign range one time in sixteen, so the bound is never reached.
const FOREIGN_WORLD_COUNTER_BOUND: u64 = 1024;

/// One delivery's authenticated pact context (FIX 321, FIX 3497): the pact a
/// peer's grant delivers through, that pact's consent epoch, and the source
/// vault the fold's pact state names. It comes from the authority fold, never
/// from a body field.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PactDelivery {
    /// The pact the grant's one operative binding names.
    pub(crate) pact: [u8; 32],
    /// That pact's consent epoch.
    pub(crate) epoch: u64,
    /// The peer vault the pact's fold state names.
    pub(crate) source_vault: [u8; 32],
}

/// The foreign WORLD `sender_world` of the vault `source_vault` lands in here.
///
/// [`EntityId::derive`] under [`derived_domains::FOREIGN_WORLD`] over the
/// source vault, the sender's world and a u64 little-endian counter, taking
/// the first counter from 0 whose id is in the foreign range. A derive error
/// is returned, never perturbed into another id. The key is the source vault,
/// not the pact, so one world arriving through two pacts keeps one placement.
pub(crate) fn foreign_world_for(
    source_vault: &[u8; 32],
    sender_world: EntityId,
) -> Result<ForeignWorldId> {
    for counter in 0..FOREIGN_WORLD_COUNTER_BOUND {
        let id = EntityId::derive(
            derived_domains::FOREIGN_WORLD,
            &[
                source_vault,
                sender_world.as_bytes(),
                &counter.to_le_bytes(),
            ],
        )?;
        if let Ok(foreign) = ForeignWorldId::from_entity_id(id) {
            return Ok(foreign);
        }
    }
    Err(Error::InvariantViolation(
        "no derived foreign world id within the counter bound",
    ))
}

/// The foreign WORLD a guest CLAIM in `claim_world` lands in. A sender's base
/// reality (`None`) maps from its reserved base scope id, so guest content is
/// never base here.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) fn guest_claim_world(
    source_vault: &[u8; 32],
    claim_world: Option<EntityId>,
) -> Result<ForeignWorldId> {
    foreign_world_for(
        source_vault,
        claim_world.unwrap_or_else(crate::claim::base_world_id),
    )
}

/// Whether a guest CLAIM is withheld from its delivery rather than remapped:
/// the one policy hook for a CLAIM whose bytes a MACHINE proof binds (CALLS
/// "FIX 3497 signed guest claim"). That is a `machine_signature` in its
/// evidence, or a MACHINE history row. The proof covers the claim's world,
/// this vault cannot sign as the sender's machine, and dropping the proof
/// would pass the sender's signed write off as an unsigned one, so admission
/// keeps the row out, with typed quarantine evidence, and lands the rest.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) fn guest_claim_withheld(body: &ClaimBody) -> bool {
    crate::authority::evidence_without_machine_signature(body) != body.evidence
        || crate::claim::history_store::machine_history_kind(&body.predicate).is_some()
}

/// The foreign WORLD the peer of pact `pact_id` lands its world
/// `sender_world` in here (FIX 3497), for a reader that holds a pact and a
/// world id the peer named, such as a courtesy deletion ask. The source is
/// the peer vault the fold's pact state names; `None` when the fold holds no
/// state for the pact. Nothing the peer signed is rewritten.
///
/// # Errors
///
/// A derive error ([`EntityId::derive`]).
pub fn pact_foreign_world(
    fold: &AuthorityFold,
    pact_id: &[u8; 32],
    sender_world: EntityId,
) -> Result<Option<ForeignWorldId>> {
    fold.federation_pacts
        .get(pact_id)
        .map(|state| foreign_world_for(&state.peer_vault_id, sender_world))
        .transpose()
}

/// The worlds here that a courtesy deletion ask under pact `pact_id` names by
/// `requested`, the requester's own world ids (FIX 3497): each one's foreign
/// WORLD, and base reality as well when the ask names the requester's base,
/// since a guest's non-CLAIM rows other than its WORLD rows are not remapped
/// and sit in base here.
/// `None` (every world the pact delivered) when `requested` is empty. A world
/// that maps to nothing here matches nothing; it never widens the ask.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) fn courtesy_ask_worlds_here(
    fold: &AuthorityFold,
    pact_id: &[u8; 32],
    requested: &[EntityId],
) -> Result<Option<BTreeSet<EntityId>>> {
    if requested.is_empty() {
        return Ok(None);
    }
    let base = crate::claim::base_world_id();
    let mut here = BTreeSet::new();
    for world in requested {
        if let Some(foreign) = pact_foreign_world(fold, pact_id, *world)? {
            here.insert(foreign.entity_id());
        }
        if *world == base {
            here.insert(base);
        }
    }
    Ok(Some(here))
}
