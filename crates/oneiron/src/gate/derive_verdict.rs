//! The one judge of a derivation that is not a claim (untangle 6.7a): may an
//! actor settle, link, publish an artifact or archive now? Existing records
//! the item changes are its targets. `vault.derive.commit` asks it for every
//! such item in its own write, and `vault.policy.preflight` asks it to show
//! the same answer before a commit (S64E-JUDGE = A). A claim item asks the
//! shared claim gate instead.
//!
//! The answer reads the actor's live reach, never a frozen copy:
//! - its policy rows must land `Generated` at Auto (the actor ceiling and the
//!   actor-bound `Generated` permit), as [`super::dreamer_landing_verdict_in_txn`]
//!   asks of the Dreamer's archive (X02);
//! - once a Steward grant row stands naming it, every standing row decides
//!   ([`crate::federation::steward_reach_in`]): each must name the verb the
//!   item needs (`derive`, or `archive`), and the meet of their scopes must
//!   reach any target record the item changes. A row another of the owner's
//!   machines stood can only narrow that. A revoked grant refuses from its
//!   next item on; a narrowed grant bounds each verb and target. While no
//!   row stands a base agent's policy rows decide alone, as before;
//! - any other actor holds no Steward grant, so no stored record is in its
//!   reach: it lands what it derives, and an item of its that changes an
//!   existing target is refused. The doors that settle, supersede or archive
//!   a record under a named Grant of its own stay those doors. A topology
//!   judgment is such a door: it asks this judge with no target and stands on
//!   the actor's own `topology_seal` Grant. A SameAs proposal changes neither
//!   of its two claims, so it asks this judge with no target as well, and the
//!   actor's own read decides both ends.
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
    /// The owner opted the actor out of its Steward grant: its standing
    /// rows leave it no verb.
    OptedOut,
    /// A standing Steward grant row of its does not name `derive`.
    GrantLacksDerive,
    /// A standing Steward grant row of its does not name `archive`.
    GrantLacksArchive,
    /// The target record is gone, or lies outside the grant's reach: every
    /// record does, for an actor that holds no Steward grant.
    OutsideGrant,
}

impl DeriveRefusal {
    /// The stable reason token a commit receipts and a preflight shows.
    pub(crate) const fn token(self) -> &'static str {
        match self {
            Self::NoLandingRows => "gate.deny.derive.no_landing_rows",
            Self::OptedOut => "gate.deny.derive.opted_out",
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
    /// The newest standing Steward grant row's id once one stands, else
    /// [`super::dreamer_grant::DREAMER_LANDING_ROWS_REF`] (the policy rows).
    pub(crate) grant_ref: String,
}

/// Judges whether `actor` may do `capability` to `target` in `txn` now.
/// `target` is the record the item changes (the claim it settles or
/// archives, the person an artifact is about); `None` for an item with no
/// existing target to change.
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
    let grant_ref = match crate::federation::steward_reach_in(store, txn, actor.entity_ref())? {
        // The Steward role alone reaches the vault's stored records. A base
        // agent holds it by default, and while no grant row stands for it its
        // policy rows stand for it; any other actor with no grant reaches none.
        None if target.is_some()
            && !crate::federation::holds_system_agent_grant(actor.entity_ref()) =>
        {
            return Ok(Err(DeriveRefusal::OutsideGrant));
        }
        None => super::dreamer_grant::DREAMER_LANDING_ROWS_REF.to_owned(),
        // Every standing row decides, never the newest alone: the verbs are
        // those each row gives, the scope is the meet of the rows' scopes,
        // and the receipt names the newest row.
        Some(reach) => {
            if reach.verbs.is_empty() {
                return Ok(Err(DeriveRefusal::OptedOut));
            }
            let verb = capability.verb();
            if !reach.verbs.contains(verb) {
                return Ok(Err(DeriveRefusal::lacks(capability)));
            }
            if let Some(target) = target
                && !reaches_target(store, txn, &reach.scope, verb, target)?
            {
                return Ok(Err(DeriveRefusal::OutsideGrant));
            }
            reach.grant.to_hex()
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
pub(crate) fn reaches_target(
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
