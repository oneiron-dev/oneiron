//! The one judge of a derivation that is not a claim (untangle 6.7a): may an
//! actor settle, link, publish an artifact or archive over a target record
//! now? `vault.derive.commit` asks it for every such item in its own write,
//! and `vault.policy.preflight` asks it to show the same answer before a
//! commit (S64E-JUDGE = A). A claim item asks the shared claim gate instead.
//!
//! The answer reads the actor's live reach, never a frozen copy:
//! - its policy rows must land `Generated` at Auto (the actor ceiling and the
//!   actor-bound `Generated` permit), as [`super::dreamer_landing_verdict_in_txn`]
//!   asks of the Dreamer's archive (X02);
//! - once a host minted its Steward grant, that grant must still stand, name
//!   the verb the item needs (`derive`, or `archive`), and reach the target
//!   record's position. A narrowed or revoked grant refuses from its next
//!   item on. Before a first mint the policy rows decide alone, as before.
//!
//! Each refusal carries a stable reason token in the gate's style
//! ([`DeriveRefusal::token`]).

use std::collections::BTreeSet;

use crate::error::Result;
use crate::federation::grant_scope::{STEWARD_ARCHIVE_VERB, STEWARD_DERIVE_VERB};
use crate::federation::{Scope, ScopeAxis};
use crate::store::Store;
use crate::{EntityId, WriteActor};

/// What a derivation item asks to do to its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeriveCapability {
    /// Settle, supersede, link or publish an artifact: the Steward `derive`
    /// verb.
    Derive,
    /// Archive, reversibly: the Steward `archive` verb.
    Archive,
}

impl DeriveCapability {
    /// The Steward verb this capability needs.
    pub(crate) const fn verb(self) -> &'static str {
        match self {
            Self::Derive => STEWARD_DERIVE_VERB,
            Self::Archive => STEWARD_ARCHIVE_VERB,
        }
    }
}

/// Why a derivation item was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeriveRefusal {
    /// The actor's policy rows do not land `Generated` at Auto.
    NoLandingRows,
    /// The owner opted the actor out of its Steward grant.
    OptedOut,
    /// Its Steward grant no longer stands (revoked, withdrawn or rewritten).
    GrantGone,
    /// Its Steward grant does not name `derive`.
    GrantLacksDerive,
    /// Its Steward grant does not name `archive`.
    GrantLacksArchive,
    /// The target record is gone, or lies outside the grant's reach.
    OutsideGrant,
}

impl DeriveRefusal {
    /// The stable reason token a commit receipts and a preflight shows.
    pub(crate) const fn token(self) -> &'static str {
        match self {
            Self::NoLandingRows => "gate.deny.derive.no_landing_rows",
            Self::OptedOut => "gate.deny.derive.opted_out",
            Self::GrantGone => "gate.deny.derive.grant_gone",
            Self::GrantLacksDerive => "gate.deny.derive.grant_lacks_derive",
            Self::GrantLacksArchive => "gate.deny.derive.grant_lacks_archive",
            Self::OutsideGrant => "gate.deny.derive.outside_grant",
        }
    }

    const fn lacks(capability: DeriveCapability) -> Self {
        match capability {
            DeriveCapability::Derive => Self::GrantLacksDerive,
            DeriveCapability::Archive => Self::GrantLacksArchive,
        }
    }
}

/// What a derivation item was judged by when it is allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeriveAllowance {
    /// The policy frontier hash it was judged under.
    pub(crate) frontier: [u8; 32],
    /// The Steward grant's id once a host minted it, else
    /// [`super::dreamer_grant::DREAMER_LANDING_ROWS_REF`] (the policy rows).
    pub(crate) grant_ref: String,
}

/// Judges whether `actor` may do `capability` to `target` in `txn` now.
/// `target` is the record the item changes (the claim it settles or
/// archives, the person an artifact is about); `None` for an item with no
/// existing target.
///
/// # Errors
///
/// Storage errors, and a policy manifest that does not resolve.
pub(crate) fn derive_verdict_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
    capability: DeriveCapability,
    target: Option<EntityId>,
) -> Result<std::result::Result<DeriveAllowance, DeriveRefusal>> {
    let policy = super::resolve_policy_manifest(store, txn)?;
    let lands = policy.lands_generated_auto(
        actor.actor_class().gate_actor_class(),
        &actor.entity_ref().to_hex(),
    );
    let grant_ref = match crate::federation::steward_grant_of_in(store, txn, actor.entity_ref())? {
        None => super::dreamer_grant::DREAMER_LANDING_ROWS_REF.to_owned(),
        Some(None) => return Ok(Err(DeriveRefusal::OptedOut)),
        Some(Some(grant)) => {
            let Some(row) = crate::federation::standing_steward_grant_in(
                store,
                txn,
                grant,
                actor.entity_ref(),
            )?
            else {
                return Ok(Err(DeriveRefusal::GrantGone));
            };
            let verb = capability.verb();
            let names_verb = matches!(
                &row.authority_scope.verbs,
                ScopeAxis::Some(verbs) if verbs.contains(verb)
            );
            if !names_verb {
                return Ok(Err(DeriveRefusal::lacks(capability)));
            }
            if let Some(target) = target
                && !reaches_target(store, txn, &row.authority_scope, verb, target)?
            {
                return Ok(Err(DeriveRefusal::OutsideGrant));
            }
            grant.to_hex()
        }
    };
    // What the actor derives lands as `Generated`: its rows (from a minted
    // grant, its `derive` verb) must land that at Auto, as X02 asks of the
    // Dreamer's archive.
    if !lands {
        return Ok(Err(DeriveRefusal::NoLandingRows));
    }
    Ok(Ok(DeriveAllowance {
        frontier: policy.read_frontier_hash()?,
        grant_ref,
    }))
}

/// Whether the grant scope `grant` admits `verb` over the record `target`
/// as it stands in `txn`: a row with no record position, or one gone,
/// admits nothing.
fn reaches_target(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    grant: &Scope,
    verb: &str,
    target: EntityId,
) -> Result<bool> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&store.read(), txn, &target)?
    else {
        return Ok(false);
    };
    let Some(mut record) =
        crate::federation::record_scope::scope_for_blob(store, txn, target, &raw)?
    else {
        return Ok(false);
    };
    record.verbs = ScopeAxis::Some(BTreeSet::from([verb.to_owned()]));
    Ok(grant.admits(verb, &record, &Scope::top()))
}
