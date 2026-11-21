//! The owner's re-derive of sealed rows (READ-LINEAGE step L1-B; Fable
//! design pass 30, section 4.7; READ-LINEAGE-L3 = A).
//!
//! A sealed row (an id on its stored floor names no source here:
//! [`super::floor::sealed_source`], or a policy that does not resolve; or an
//! input it still waits on reads erased: its verdict is sealed, Fable design
//! pass 31) reads to no one, the vault owner included, and a floor only
//! grows, so no act unseals it. What the owner can do is have its fact written again from
//! the sources that resolve now, as a new row born under their floors, which
//! takes the sealed row's place:
//! - a CLAIM is superseded by a current CLAIM that states the same fact and
//!   whose floor names only sources that resolve. The Dreamer admits no
//!   prior head it cannot read, so a fact it learns again lands beside the
//!   sealed CLAIM rather than over it. With no such CLAIM, each TURN whose
//!   words its birth's inputs are is owed a fresh read, so the next wake
//!   learns again what that evidence still says, and a later run closes the
//!   sealed CLAIM over it;
//! - a scope SUMMARY its projection names current is declared again under
//!   its own requester ([`Vault::rederive_scope_summary`]): the next
//!   generation is born under its sources' floors, so one born from an
//!   input this vault erased is sealed again and stays counted, and one
//!   whose sources have not landed yet waits for them
//!   ([`super::source_state`]);
//! - every other row is kept: no generator here writes it again.
//!
//! Only a sealed row that is still current is counted or acted on: a
//! superseded or retracted CLAIM and a replaced summary generation are
//! history. Only counts leave, never a row, its text or its sources.

use std::collections::BTreeSet;

use heed::RoTxn;
use serde::Serialize;

use super::floor::{FloorSource, floor_in, floor_source_in};
use crate::batch::EntityMetadataHeader;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_SUMMARY};
use crate::scope_summary::SummaryGeneration;
use crate::{ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, Vault, WriteActor};

/// What the owner's re-derive of sealed rows did, in counts only
/// ([`Vault::rederive_sealed_rows`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct SealedRowsRederived {
    /// The current sealed rows it found: doctor's "facts hidden: source
    /// unknown" before the act.
    pub sealed: u64,
    /// Sealed CLAIMs closed by a current CLAIM that states the same fact
    /// under sources that resolve.
    pub superseded: u64,
    /// Sealed scope summaries declared again: the Dreamer writes each next
    /// generation.
    pub queued: u64,
    /// Sealed CLAIMs whose evidence TURNs are owed a fresh read: a run after
    /// the next wake closes each one the wake learns again.
    pub owed: u64,
    /// Sealed rows left as they are: no generator here writes them again,
    /// their evidence is gone, or a guard refused the close.
    pub kept: u64,
}

/// What one current sealed row is, for its re-derive.
enum Sealed {
    Claim,
    Summary(WriteActor),
    Other,
}

/// What the re-derive of one sealed row did.
enum Rederived {
    Superseded,
    Queued,
    Owed,
    Kept,
}

/// Whether an id on `floor` names no source here.
fn names_unknown_source(
    vault: &Vault,
    txn: &RoTxn<'_>,
    floor: &BTreeSet<EntityId>,
) -> Result<bool> {
    for source in floor {
        if floor_source_in(vault, txn, source)? == FloorSource::Unknown {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The rows this vault reads to no one, and that are still current: held,
/// a CLAIM still `active`, a scope SUMMARY its projection has not replaced.
/// A row reads to no one when an id on its stored floor names no source, or
/// when its verdict is sealed by an input it waits on that reads erased.
fn current_sealed_rows_in(vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<(EntityId, Sealed)>> {
    let mut sealed_rows = BTreeSet::new();
    for entry in super::DERIVED.iter_from(&vault.store, txn, &[])? {
        let (row, floor) = entry?;
        if names_unknown_source(vault, txn, &floor)? {
            sealed_rows.insert(row);
        }
    }
    for row in super::source_state::rows_with_open_entries_in(&vault.store, txn)? {
        if !sealed_rows.contains(&row)
            && super::verdict_in(vault, txn, &row)? == super::Verdict::Sealed
        {
            sealed_rows.insert(row);
        }
    }
    let mut rows = Vec::new();
    for row in sealed_rows {
        let Some(raw) = vault.get_raw_in(txn, &row)? else {
            continue;
        };
        let sealed = match EntityMetadataHeader::parse(&raw).map(|header| header.entity_type) {
            Some(ENTITY_TYPE_CLAIM) => match vault.get_claim_in_txn(txn, &row) {
                Ok(Some(body)) if body.lifecycle != ClaimLifecycleStatus::Active => continue,
                Ok(Some(_)) => Sealed::Claim,
                Ok(None) | Err(Error::InvalidClaimBody(_) | Error::Record(_)) => Sealed::Other,
                Err(error) => return Err(error),
            },
            Some(ENTITY_TYPE_SUMMARY) => {
                match crate::scope_summary::summary_generation_in(vault, txn, &row)? {
                    SummaryGeneration::Replaced => continue,
                    SummaryGeneration::Current(requester) => Sealed::Summary(requester),
                    SummaryGeneration::Undeclared => Sealed::Other,
                }
            }
            _ => Sealed::Other,
        };
        rows.push((row, sealed));
    }
    Ok(rows)
}

/// A count of rows, as the reports carry it.
fn count(rows: usize) -> Result<u64> {
    u64::try_from(rows).map_err(|_| Error::ArithmeticOverflow("sealed row count"))
}

/// How many rows this vault reads to no one because an id on their stored
/// floor names no source, and that are still current: doctor's "N facts
/// hidden: source unknown" (READ-LINEAGE-L3 = A; design pass 30 section
/// 4.7). One scan of the stored floors; only the count leaves, never a row,
/// its text or its sources. A sealed row a later row took the place of (a
/// superseded or retracted CLAIM, a replaced summary generation) is history
/// and leaves the count.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn facts_hidden_source_unknown_in(vault: &Vault, txn: &RoTxn<'_>) -> Result<u64> {
    count(current_sealed_rows_in(vault, txn)?.len())
}

/// Whether `other` states the fact `sealed` states: one predicate and value
/// about one subject, in one world, relationship scope and scope.
fn states_same_fact(other: &ClaimBody, sealed: &ClaimBody) -> bool {
    other.subject == sealed.subject
        && other.predicate == sealed.predicate
        && other.value == sealed.value
        && other.world == sealed.world
        && other.rel == sealed.rel
        && other.scope == sealed.scope
        && other.scope_facet == sealed.scope_facet
        && other.scope_project == sealed.scope_project
}

/// A refusal of one row's re-derive by a guard of the door it runs through:
/// that row is kept, and the act goes on with the next. The source-trust
/// guard refuses a generated CLAIM superseding user-stated code-revision
/// truth as an artifact error (#10127 review P1).
fn refused(error: &Error) -> bool {
    matches!(
        error,
        Error::Claim(_)
            | Error::Gate(_)
            | Error::InvalidClaimBody(_)
            | Error::Refused(_)
            | Error::LegalHold(_)
            | Error::EntityNotFound
            | Error::Artifact(crate::error::ArtifactError::InvalidCodeArtifactBody(_))
    )
}

impl Vault {
    /// The owner's re-derive of the sealed rows doctor counts as "facts
    /// hidden: source unknown" (READ-LINEAGE L1-B; design pass 30, section
    /// 4.7): each current sealed row is written again from the sources that
    /// resolve now, as a new row that takes its place. A sealed CLAIM is
    /// superseded by a current CLAIM stating its fact under sources that
    /// resolve, or else the TURNs of its evidence are owed a fresh read; a
    /// sealed scope summary is declared again under its own requester
    /// ([`Vault::rederive_scope_summary`]); every other row is kept. The
    /// sealed row itself is never unsealed (a floor only grows). An owner
    /// act: `owner` is revalidated before the scan and again in each write
    /// that closes a CLAIM or owes a read. Only counts come back.
    ///
    /// # Errors
    ///
    /// An owner proof that does not revalidate, and storage failures. A
    /// guard that refuses one row's re-derive keeps that row and counts it
    /// as kept.
    pub fn rederive_sealed_rows(&self, owner: &AuthenticatedOwner) -> Result<SealedRowsRederived> {
        let rows = {
            let rtxn = self.store.env.read_txn()?;
            owner.revalidate_in_txn(self, &rtxn)?;
            current_sealed_rows_in(self, &rtxn)?
        };
        let mut report = SealedRowsRederived {
            sealed: count(rows.len())?,
            ..SealedRowsRederived::default()
        };
        for (row, sealed) in rows {
            let rederived = match sealed {
                Sealed::Claim => self.rederive_sealed_claim(owner, &row)?,
                Sealed::Summary(requester) => match self.rederive_scope_summary(row, requester) {
                    Ok(_) => Rederived::Queued,
                    Err(error) if refused(&error) => Rederived::Kept,
                    Err(error) => return Err(error),
                },
                Sealed::Other => Rederived::Kept,
            };
            let tally = match rederived {
                Rederived::Superseded => &mut report.superseded,
                Rederived::Queued => &mut report.queued,
                Rederived::Owed => &mut report.owed,
                Rederived::Kept => &mut report.kept,
            };
            *tally += 1;
        }
        Ok(report)
    }

    /// The re-derive of the sealed CLAIM `sealed`: superseded by a current
    /// CLAIM stating its fact under sources that resolve, or else its
    /// evidence owed a fresh read.
    fn rederive_sealed_claim(
        &self,
        owner: &AuthenticatedOwner,
        sealed: &EntityId,
    ) -> Result<Rederived> {
        let twin = {
            let rtxn = self.store.env.read_txn()?;
            let Some(body) = self.get_claim_in_txn(&rtxn, sealed)? else {
                return Ok(Rederived::Kept);
            };
            self.readable_twin_in(&rtxn, sealed, &body)?
        };
        if let Some(twin) = twin {
            let at = self.now_recorded_at();
            return match self.supersede_claim_as_owner(owner, &twin, sealed, at) {
                Ok(()) => Ok(Rederived::Superseded),
                Err(error) if refused(&error) => Ok(Rederived::Kept),
                Err(error) => Err(error),
            };
        }
        let mut wtxn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &wtxn)?;
        let mut owed = 0_usize;
        let inputs = crate::store::birth_record::input_rows_in_txn(&self.store, &wtxn, sealed)?;
        for input in inputs {
            let gone =
                crate::ports::TombstoneStoreRead::port_deletion_state(&self.store, &wtxn, &input)?;
            if input == *sealed || gone.deleted {
                continue;
            }
            owed += crate::dreamer_wake::owe_turn_reads_in_txn(&self.store, &mut wtxn, &input)?;
        }
        if owed == 0 {
            return Ok(Rederived::Kept);
        }
        crate::batch::queue_proactivity_change(self, &wtxn);
        wtxn.commit()?;
        self.store.notify_proactivity_changes();
        Ok(Rederived::Owed)
    }

    /// A current CLAIM other than `sealed` that states the fact of `body`
    /// and whose floor names only sources that resolve.
    fn readable_twin_in(
        &self,
        txn: &RoTxn<'_>,
        sealed: &EntityId,
        body: &ClaimBody,
    ) -> Result<Option<EntityId>> {
        let ClaimSubject::Entity(subject) = body.subject else {
            return Ok(None);
        };
        let mut same = Vec::new();
        self.find_claim_for_subject_in_txn(txn, &subject, |id, other| {
            if id != sealed
                && other.lifecycle == ClaimLifecycleStatus::Active
                && states_same_fact(other, body)
            {
                same.push(*id);
            }
            None::<()>
        })?;
        for twin in same {
            let Some(raw) = self.get_raw_in(txn, &twin)? else {
                continue;
            };
            if !names_unknown_source(self, txn, &floor_in(self, txn, &twin, &raw)?)? {
                return Ok(Some(twin));
            }
        }
        Ok(None)
    }
}
