//! A typed-body fork on the owner's other machines (FIX 12470).
//!
//! An office proposal reaches the owner's other machines (FIX 2691), but the
//! typed fork it names stayed on the machine that opened it, so a review
//! there found no fork and a settlement could not load it; a deck fork's
//! office record stayed there too. A fork now rides the base window beside
//! its body (`sync::typed_body_rows`): its row as this vault holds it, the
//! body's birth, the schema owner's record of the fork, and an open fork's
//! snapshot.
//!
//! Where it lands, the copy is stored as it came, or joined with the copy
//! held here. Two copies are ordered by their versions, each the version
//! vector of the fork's document at its latest authored state: a version
//! vector compares without the other machine's operations. Nothing lands,
//! settles or is authored here. A decision is copied as it was made, and the
//! operations a merge landed reach the body on its own frame (FIX 2458).
//!
//! - Two open copies of one base: the copy whose version holds the other's
//!   stands; two concurrent copies conflict, and both stand. A plain Loro
//!   import would not join them as the schema's own landing does (an XLSX
//!   cell written beside a row insertion keeps its old address), so no copy
//!   is joined here.
//!   Two open copies of different bases, where a reviewed prefix landed on
//!   one: the copy whose base and version both hold the other's stands;
//!   otherwise they conflict.
//! - A merged or discarded copy settles an open one whose work it holds; one
//!   that does not hold all of it conflicts, and the open fork's work stays.
//!   A settled fork never opens again.
//! - Two settled copies of one decision join the actors they erased; any
//!   other difference conflicts.
//! - An open copy whose opener this vault erased goes; a settled copy names
//!   no one where this vault erased an actor. An open fork that names no
//!   opener (a carried head's fork, FIX 2458) stays.
//! - The schema owner's record rides with the typed row, and follows it.
//!
//! A conflict leaves the copy held here standing.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use loro::{Frontiers, LoroDoc, VersionVector};
use serde::{Deserialize, Serialize};

use super::lift::{TypedBodyRows, lift_typed_body_in_txn};
use super::sync_frame::BodyOwner;
use super::{BodyActor, FORK_DOCS, FORKS, HEADS, TypedBodyFork, TypedForkState, require_live};
use crate::Vault;
use crate::deletion::carrier_actor_merged;
use crate::entity_doc::DocumentMerge;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::sync::carrier_parts::Parts;

/// One fork of a typed body as it rides to the owner's other machines: the
/// fork's row as its vault holds it, the birth of the body it forks, the
/// schema owner's record of the fork, and an open fork's document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CarriedFork {
    pub(crate) entity: EntityId,
    pub(crate) fork: EntityId,
    /// The body's birth frontier ([`super::TypedBodyHead::birth`]).
    pub(crate) birth: Vec<u8>,
    pub(crate) record: TypedBodyFork,
    /// The schema owner's exact record of the fork (a deck fork's office
    /// record); empty for none.
    pub(crate) companion: Vec<u8>,
    /// An open fork's document; `None` for a merged or discarded fork.
    pub(crate) snapshot: Option<ForkSnapshot>,
}

/// An open fork's document as a carrier holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ForkSnapshot {
    /// The document's snapshot, the fork's stored bytes, in the carrier.
    Whole(#[serde(with = "oneiron_store::key_custody::head::wire::serde_bytes_vec")] Vec<u8>),
    /// The parts the snapshot rides in, beside the carrier in the same root.
    Parts(Parts),
}

impl CarriedFork {
    /// Whether the row is the fork this carrier names, with a document
    /// exactly while it is open, and a snapshot's parts are one split.
    pub(crate) fn well_formed(&self) -> bool {
        let open = self.record.state == TypedForkState::Open;
        self.record.entity == self.entity
            && self.record.fork == self.fork
            && match &self.snapshot {
                None => !open,
                Some(ForkSnapshot::Whole(_)) => open,
                Some(ForkSnapshot::Parts(parts)) => open && parts.well_formed(),
            }
    }

    /// Whether the carrier names an actor: the fork's opener or the actor
    /// that merged or discarded it, or a schema owner's record, which names
    /// its own.
    #[allow(
        dead_code,
        reason = "the window checkpoint classifier reads it, and KS7-5 drives that classifier"
    )]
    pub(crate) fn names_actor(&self) -> bool {
        let settler = match &self.record.state {
            TypedForkState::Open => BodyActor::Erased,
            TypedForkState::Merged { by, .. } | TypedForkState::Discarded { by, .. } => *by,
        };
        self.record.opener != BodyActor::Erased
            || settler != BodyActor::Erased
            || !self.companion.is_empty()
    }

    /// Whether the fork's opener, or the actor that merged or discarded it,
    /// reads as erased: a copy that named them may stand before this one in
    /// a window's history.
    pub(crate) fn names_erased_actor(&self) -> bool {
        let settler = match &self.record.state {
            TypedForkState::Open => None,
            TypedForkState::Merged { by, .. } | TypedForkState::Discarded { by, .. } => Some(*by),
        };
        self.record.opener == BodyActor::Erased || settler == Some(BodyActor::Erased)
    }

    /// This copy as this vault holds a carried one, as the erase leaves a
    /// fork here (`erase_fork_actor_in_txn`): `None` for an open fork whose
    /// opener this vault erased, which goes with its document and its
    /// owner's record; else naming no one where this vault erased an actor,
    /// the owner's record in the owner's own erased form. Read from this
    /// vault's own hard-delete markers, never from an absent actor, so an
    /// open fork that names no opener stays.
    pub(crate) fn carried_here(
        mut self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        owner: &BodyOwner,
    ) -> Result<Option<Self>> {
        let erased = |actor: &mut BodyActor| -> Result<bool> {
            let gone = match actor.id() {
                Some(id) => vault.carrier_actor_erased_in_txn(txn, &id)?,
                None => false,
            };
            if gone {
                *actor = BodyActor::Erased;
            }
            Ok(gone)
        };
        if erased(&mut self.record.opener)? && self.record.state == TypedForkState::Open {
            return Ok(None);
        }
        if let TypedForkState::Merged { by, .. } | TypedForkState::Discarded { by, .. } =
            &mut self.record.state
        {
            erased(by)?;
        }
        if !self.companion.is_empty() {
            self.companion =
                (owner.erased_fork_companion)(vault, txn, &self.companion)?.unwrap_or_default();
        }
        Ok(Some(self))
    }

    /// Whether this copy holds all of `other`, a copy of the same fork as
    /// this vault holds a carried one ([`Self::carried_here`]): merging
    /// `other` into it changes nothing.
    pub(crate) fn covers(&self, other: &Self, owner: &BodyOwner) -> Result<bool> {
        if self.entity != other.entity || self.fork != other.fork || self.birth != other.birth {
            return Ok(false);
        }
        let plan = plan(self, other);
        Ok(matches!(plan, Plan::Held { .. })
            && companion_step(&plan, &self.companion, &other.companion, owner)?
                == CompanionStep::Keep)
    }

    /// This vault's copy of the same fork, beside this copy's birth: what a
    /// divergence is digested against. `None` when it holds none.
    pub(crate) fn held_here_in_txn(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        owner: &BodyOwner,
    ) -> Result<Option<Self>> {
        match FORKS.get(&vault.store, txn, &(self.entity, self.fork))? {
            Some(record) => carried_of(vault, txn, &self.birth, record, owner).map(Some),
            None => Ok(None),
        }
    }

    /// The open fork's document, read from a whole snapshot.
    fn document(&self) -> Option<LoroDoc> {
        let Some(ForkSnapshot::Whole(bytes)) = &self.snapshot else {
            return None;
        };
        let doc = LoroDoc::from_snapshot(bytes).ok()?;
        doc.set_record_timestamp(true);
        Some(doc)
    }
}

/// `record`, a fork of the body born at `birth`, as it rides: with its
/// document while it is open (`None` where this vault holds none), and its
/// schema owner's record.
fn carried_of(
    vault: &Vault,
    txn: &RoTxn<'_>,
    birth: &[u8],
    record: TypedBodyFork,
    owner: &BodyOwner,
) -> Result<CarriedFork> {
    let key = (record.entity, record.fork);
    let snapshot = if record.state == TypedForkState::Open {
        FORK_DOCS
            .get(&vault.store, txn, &key)?
            .map(ForkSnapshot::Whole)
    } else {
        None
    };
    let companion = (owner.fork_companion)(vault, txn, &key.0, &key.1)?.unwrap_or_default();
    Ok(CarriedFork {
        entity: key.0,
        fork: key.1,
        birth: birth.to_vec(),
        record,
        companion,
        snapshot,
    })
}

/// Every fork of `entity`'s body this vault holds, each as it rides to the
/// owner's other machines, with its schema owner's record from `owner`.
/// Empty when `entity` holds no typed body here or is not live here. An open
/// fork whose document is missing here stays on this machine.
pub(crate) fn carried_forks_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    owner: &BodyOwner,
) -> Result<Vec<CarriedFork>> {
    let Some(head) = HEADS.get(&vault.store, txn, entity)? else {
        return Ok(Vec::new());
    };
    match require_live(&vault.store, txn, entity) {
        Ok(()) => {}
        Err(Error::EntityNotFound) => return Ok(Vec::new()),
        Err(error) => return Err(error),
    }
    let mut forks = Vec::new();
    for (_, record) in FORKS.scan_from(&vault.store, txn, entity.as_bytes())? {
        let carried = carried_of(vault, txn, &head.birth, record, owner)?;
        if carried.well_formed() {
            forks.push(carried);
        } else {
            tracing::warn!(
                entity = %entity.to_hex(),
                fork = %carried.fork.to_hex(),
                "an open typed body fork holds no document here; it stays on this machine"
            );
        }
    }
    Ok(forks)
}

/// What merging a carried copy of a fork into the copy held here does to the
/// held one.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Plan {
    /// The held copy stands. `ahead` when it holds work the carried copy
    /// lacks; else both are one fork, up to the actors they name.
    Held { ahead: bool },
    /// The carried copy replaces the held one, or lands where none is held.
    Take,
    /// The carried copy merged or discarded the open fork held here, and
    /// holds all of its work: the held document goes.
    Settle,
    /// Two settled copies of one decision: the held one, naming no one in
    /// each field either copy names no one.
    EraseActors(TypedBodyFork),
    /// The copies differ otherwise.
    Conflict,
}

/// How `carried` merges into `held`, two copies of one fork.
fn plan(held: &CarriedFork, carried: &CarriedFork) -> Plan {
    let (ours, theirs) = (&held.record, &carried.record);
    if ours == theirs {
        return Plan::Held { ahead: false };
    }
    match (&ours.state, &theirs.state) {
        (TypedForkState::Open, TypedForkState::Open) => {
            if ours.opener != theirs.opener {
                Plan::Conflict
            } else if ours.base == theirs.base {
                if version_covers(&ours.version, &theirs.version) {
                    Plan::Held { ahead: true }
                } else if version_covers(&theirs.version, &ours.version) {
                    Plan::Take
                } else {
                    Plan::Conflict
                }
            } else if ahead_of(held, carried) {
                Plan::Held { ahead: true }
            } else if ahead_of(carried, held) {
                Plan::Take
            } else {
                Plan::Conflict
            }
        }
        (TypedForkState::Open, _) => match held.document() {
            Some(doc) if version_covers_vv(&theirs.version, &doc.oplog_vv()) => Plan::Settle,
            _ => Plan::Conflict,
        },
        // A settled fork never opens again.
        (_, TypedForkState::Open) => {
            if version_covers(&ours.version, &theirs.version) {
                Plan::Held { ahead: true }
            } else {
                Plan::Conflict
            }
        }
        _ => match settled_join(ours, theirs) {
            Some(joined) if joined == *ours => Plan::Held { ahead: false },
            Some(joined) => Plan::EraseActors(joined),
            None => Plan::Conflict,
        },
    }
}

/// Whether version `a` holds every operation version `b` does. A version
/// not recorded (empty) holds none and is held by none, but by another not
/// recorded.
fn version_covers(a: &[u8], b: &[u8]) -> bool {
    if a.is_empty() || b.is_empty() {
        return a.is_empty() && b.is_empty();
    }
    VersionVector::decode(b).is_ok_and(|b| version_covers_vv(a, &b))
}

/// Whether version `a`, encoded, holds every operation `b` does. A version
/// not recorded holds none.
fn version_covers_vv(a: &[u8], b: &VersionVector) -> bool {
    !a.is_empty() && VersionVector::decode(a).is_ok_and(|a| a.includes_vv(b))
}

/// Whether open copy `a`, of another base than `b`'s, holds all of `b`: its
/// version holds `b`'s, and its base holds `b`'s base, read in `a`'s
/// document, which then holds both.
fn ahead_of(a: &CarriedFork, b: &CarriedFork) -> bool {
    version_covers(&a.record.version, &b.record.version)
        && a.document().is_some_and(|doc| {
            let vv = |base: &[u8]| {
                Frontiers::decode(base)
                    .ok()
                    .and_then(|base| doc.frontiers_to_vv(&base))
            };
            matches!(
                (vv(&a.record.base), vv(&b.record.base)),
                (Some(mine), Some(theirs)) if mine.includes_vv(&theirs)
            )
        })
}

/// Two settled copies of one fork as one: the same decision, time and
/// version, naming no one in each field either copy names no one, since an
/// erase wins. `None` when they differ otherwise.
fn settled_join(ours: &TypedBodyFork, theirs: &TypedBodyFork) -> Option<TypedBodyFork> {
    let met = |a: BodyActor, b: BodyActor| carrier_actor_merged(a, b, BodyActor::Erased);
    let state = match (&ours.state, &theirs.state) {
        (
            TypedForkState::Merged { by: a, at, head },
            TypedForkState::Merged {
                by: b,
                at: when,
                head: landed,
            },
        ) if at == when && head == landed => TypedForkState::Merged {
            by: met(*a, *b)?,
            at: *at,
            head: head.clone(),
        },
        (
            TypedForkState::Discarded { by: a, at },
            TypedForkState::Discarded { by: b, at: when },
        ) if at == when => TypedForkState::Discarded {
            by: met(*a, *b)?,
            at: *at,
        },
        _ => return None,
    };
    let joined = TypedBodyFork {
        opener: met(ours.opener, theirs.opener)?,
        state,
        ..ours.clone()
    };
    let other = TypedBodyFork {
        opener: joined.opener,
        state: joined.state.clone(),
        ..theirs.clone()
    };
    (joined == other).then_some(joined)
}

/// What a merge does to the schema owner's record of the fork held here.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CompanionStep {
    Keep,
    Write(Vec<u8>),
    Conflict,
}

/// How `carried`, the owner's record a carried copy brings, merges into
/// `held`, the one held here, as `plan` merges the typed rows: it rides with
/// a typed row that is written whole, stands beside a held row that holds
/// more, and otherwise joins through `owner`, naming no one where either
/// does. A record this vault lacks is written; a carrier without one leaves
/// the held one.
fn companion_step(
    plan: &Plan,
    held: &[u8],
    carried: &[u8],
    owner: &BodyOwner,
) -> Result<CompanionStep> {
    if carried.is_empty() || held == carried {
        return Ok(CompanionStep::Keep);
    }
    if held.is_empty() {
        return Ok(CompanionStep::Write(carried.to_vec()));
    }
    Ok(match plan {
        Plan::Take | Plan::Settle => CompanionStep::Write(carried.to_vec()),
        Plan::Held { ahead: true } => CompanionStep::Keep,
        Plan::Held { ahead: false } | Plan::EraseActors(_) => {
            match (owner.join_fork_companion)(held, carried)? {
                None => CompanionStep::Conflict,
                Some(joined) if joined == held => CompanionStep::Keep,
                Some(joined) => CompanionStep::Write(joined),
            }
        }
        Plan::Conflict => CompanionStep::Conflict,
    })
}

/// What a merge does to the fork's stored document.
enum ForkDocument {
    Keep,
    Put(Vec<u8>),
    Delete,
}

/// The carried open fork's document, when it holds the body's birth and the
/// fork's base, and is the version its row names where the row names one.
fn checked_document(carried: &CarriedFork) -> Option<LoroDoc> {
    let doc = carried.document()?;
    let holds = |frontier: &[u8]| {
        Frontiers::decode(frontier)
            .ok()
            .and_then(|frontier| doc.frontiers_to_vv(&frontier))
            .is_some()
    };
    let versioned = carried.record.version.is_empty()
        || VersionVector::decode(&carried.record.version)
            .is_ok_and(|version| version == doc.oplog_vv());
    let whole = holds(&carried.birth) && holds(&carried.record.base) && versioned;
    whole.then_some(doc)
}

/// The key of fork `key`'s document row after its table's prefix: what the
/// lift names it by.
fn fork_doc_key(key: &(EntityId, EntityId)) -> Vec<u8> {
    let mut row = key.0.as_bytes().to_vec();
    row.extend_from_slice(key.1.as_bytes());
    row
}

/// Merges `carried`, another machine's copy of a fork, into this vault's in
/// the caller's writer, with the schema owner's record through `owner`. It
/// stores the decision already made and the work already done, and nothing
/// else: no fork lands on the body, none is merged, discarded or written
/// through a door, no peer is bound and no receipt recorded. A fork whose
/// body is not live here is refused and never brings it back; one whose body
/// has not landed here, or whose snapshot's parts have not, waits; one of
/// another body birth stands apart. A copy is taken as this vault holds it
/// ([`CarriedFork::carried_here`]); an open one whose opener this vault
/// erased is refused. A stored document is read through the fork lift, as a
/// local fork write's is. Copies that differ past what merges conflict, and
/// the one held here stands.
pub(crate) fn merge_carried_fork_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    carried: &CarriedFork,
    owner: &BodyOwner,
) -> Result<DocumentMerge> {
    let entity = carried.entity;
    if !carried.well_formed() {
        return Ok(DocumentMerge::Refused("not a whole typed body fork"));
    }
    if crate::ports::removed_in_txn(&vault.store, txn, &entity)? {
        return Ok(DocumentMerge::Refused("its body's entity is removed here"));
    }
    match require_live(&vault.store, txn, &entity) {
        Ok(()) => {}
        Err(Error::EntityNotFound) => {
            return Ok(DocumentMerge::Refused("its body's entity is not live here"));
        }
        Err(error) => return Err(error),
    }
    let Some(head) = HEADS.get(&vault.store, txn, &entity)? else {
        return Ok(DocumentMerge::Waiting);
    };
    if head.birth != carried.birth {
        return Ok(DocumentMerge::Refused("a fork of another body birth"));
    }
    if matches!(carried.snapshot, Some(ForkSnapshot::Parts(_))) {
        return Ok(DocumentMerge::Waiting);
    }
    let Some(carried) = carried.clone().carried_here(vault, txn, owner)? else {
        return Ok(DocumentMerge::Refused("its opener is erased here"));
    };
    let key = (entity, carried.fork);
    let held = match FORKS.get(&vault.store, txn, &key)? {
        Some(record) => Some(carried_of(vault, txn, &head.birth, record, owner)?),
        None => None,
    };
    let plan = held
        .as_ref()
        .map_or(Plan::Take, |held| plan(held, &carried));
    let held_companion = held
        .as_ref()
        .map_or(&[][..], |held| held.companion.as_slice());
    let companion = companion_step(&plan, held_companion, &carried.companion, owner)?;
    if plan == Plan::Conflict || companion == CompanionStep::Conflict {
        tracing::warn!(
            entity = %entity.to_hex(),
            fork = %carried.fork.to_hex(),
            "a carried typed body fork diverges from the one held here"
        );
        return Ok(DocumentMerge::Conflict);
    }
    // Every row this merge writes, read and checked before the first write.
    let (record, document) = match plan {
        Plan::Held { .. } => (None, ForkDocument::Keep),
        Plan::Take => match &carried.snapshot {
            Some(ForkSnapshot::Whole(bytes)) => {
                if checked_document(&carried).is_none() {
                    return Ok(DocumentMerge::Refused(
                        "a fork document that does not hold its body's birth, its base or its version",
                    ));
                }
                (
                    Some(carried.record.clone()),
                    ForkDocument::Put(bytes.clone()),
                )
            }
            _ => (Some(carried.record.clone()), ForkDocument::Delete),
        },
        Plan::Settle => (Some(carried.record.clone()), ForkDocument::Delete),
        Plan::EraseActors(joined) => (Some(joined), ForkDocument::Keep),
        Plan::Conflict => return Ok(DocumentMerge::Conflict),
    };
    if let Some(record) = &record {
        FORKS.put(&vault.store, txn, &key, record)?;
    }
    match &document {
        ForkDocument::Keep => {}
        ForkDocument::Put(bytes) => {
            FORK_DOCS.put(&vault.store, txn, &key, bytes)?;
            lift_typed_body_in_txn(vault, txn, TypedBodyRows::ForkDoc, &fork_doc_key(&key))?;
        }
        // As a local merge or discard leaves a settled fork: its row stays,
        // its document goes.
        ForkDocument::Delete => {
            FORK_DOCS.delete(&vault.store, txn, &key)?;
        }
    }
    let wrote_companion = match &companion {
        CompanionStep::Write(bytes) => {
            (owner.adopt_fork_companion)(vault, txn, &key.0, &key.1, bytes)?;
            true
        }
        CompanionStep::Keep | CompanionStep::Conflict => false,
    };
    if record.is_none() && !wrote_companion {
        return Ok(DocumentMerge::Held);
    }
    crate::batch::queue_committed_rows(vault, txn, BTreeSet::from([entity]));
    Ok(DocumentMerge::Written)
}
