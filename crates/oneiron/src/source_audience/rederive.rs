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
//! history. Doctor counts the current rows that wait beside the sealed ones,
//! by their verdict ([`floor_counts_in`]; pass 31 step L-S5). Only counts
//! leave, never a row, its text or its sources.

use std::collections::BTreeMap;

use heed::RoTxn;
use serde::Serialize;

use super::source_state::{StateReader, Verdict, Wait};
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

/// Doctor's counts of the current rows whose floor is not whole here, by
/// their verdict (Fable design pass 31, step L-S5). Only counts, never a
/// row, its text or its sources.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FloorCounts {
    /// Rows whose verdict is sealed: "N facts hidden: source unknown"
    /// (READ-LINEAGE-L3 = A).
    pub(crate) hidden_source_unknown: u64,
    /// Rows that wait for good on an input deleted before floors were
    /// written, themselves or through an input that does: "N facts whose
    /// source was deleted before tagging" (FLOOR-OLD-FACT-ERASED-INPUT = A).
    pub(crate) source_deleted_before_tagging: u64,
    /// Every other row that waits: "N facts waiting for a source to arrive".
    pub(crate) waiting_for_source: u64,
}

/// What one current row is, for its re-derive.
enum RowKind {
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

/// How one current row whose floor is not whole here reads.
enum NotWhole {
    /// Its verdict is sealed: it reads to no one.
    Sealed(RowKind),
    /// Its verdict waits, for this reason.
    Waiting(Wait),
}

/// What the held row `row` (bytes `raw`) is while it is current: a CLAIM
/// still `active`, a scope SUMMARY its projection has not replaced, or any
/// other row; `None` for history (a superseded or retracted CLAIM, a
/// replaced summary generation).
fn current_kind_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    row: &EntityId,
    raw: &[u8],
) -> Result<Option<RowKind>> {
    Ok(Some(
        match EntityMetadataHeader::parse(raw).map(|header| header.entity_type) {
            Some(ENTITY_TYPE_CLAIM) => match vault.get_claim_in_txn(txn, row) {
                Ok(Some(body)) if body.lifecycle != ClaimLifecycleStatus::Active => {
                    return Ok(None);
                }
                Ok(Some(_)) => RowKind::Claim,
                Ok(None) | Err(Error::InvalidClaimBody(_) | Error::Record(_)) => RowKind::Other,
                Err(error) => return Err(error),
            },
            Some(ENTITY_TYPE_SUMMARY) => {
                match crate::scope_summary::summary_generation_in(vault, txn, row)? {
                    SummaryGeneration::Replaced => return Ok(None),
                    SummaryGeneration::Current(requester) => RowKind::Summary(requester),
                    SummaryGeneration::Undeclared => RowKind::Other,
                }
            }
            _ => RowKind::Other,
        },
    ))
}

/// How `row` reads when it is held, live, current and not whole here, as
/// `reader` judges it.
fn not_whole_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    reader: &mut StateReader<'_, '_>,
    row: &EntityId,
) -> Result<Option<NotWhole>> {
    let Some(raw) = vault.get_raw_in(txn, row)? else {
        return Ok(None);
    };
    if crate::ports::erased_in_txn(&vault.store, txn, row)? {
        return Ok(None);
    }
    let read = match reader.verdict(row, Some(&raw))? {
        Verdict::Whole(_) => return Ok(None),
        Verdict::Sealed => None,
        Verdict::Waiting(wait) => Some(wait),
    };
    let Some(kind) = current_kind_in(vault, txn, row, &raw)? else {
        return Ok(None);
    };
    Ok(Some(match read {
        None => NotWhole::Sealed(kind),
        Some(wait) => NotWhole::Waiting(wait),
    }))
}

/// The held, live rows this vault does not read as whole, and that are
/// still current, each judged by its verdict: sealed rows read to no one,
/// the vault owner included; waiting rows only to an owner who reads every
/// source here. A row reads otherwise than whole by what it stores: an open
/// entry or an old build's wait the migration has not converted (each such
/// row is judged), or a stored floor or a binding that names a source
/// unknown here (`DERIVED`, `RECORDS`: such a row is judged; one whose
/// floor and binding resolve and that holds neither reads whole). No row
/// scan runs at each doctor, which runs at each managed-vault unlock, so
/// two kinds of row are not counted: a row the migration has not judged
/// yet (it is judged one level at each read, and counted once the migration
/// stores its entry or its seal), and a phone row that stores no floor and
/// whose own thread does not resolve here or whose mark names no thread
/// (it reads to no one; oracle case 69).
fn current_not_whole_rows_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
) -> Result<BTreeMap<EntityId, NotWhole>> {
    let store = &vault.store;
    let mut judged = super::source_state::rows_with_open_entries_in(store, txn)?;
    judged.extend(super::floor_migration::rows_with_old_marks_in(store, txn)?);
    // Each source is looked up once: the rows of one mailbox share its
    // policy.
    let mut unknown_sources = BTreeMap::new();
    let mut unknown = |source: &EntityId| -> Result<bool> {
        if let Some(unknown) = unknown_sources.get(source) {
            return Ok(*unknown);
        }
        let unknown = super::floor::floor_source_of_in(store, txn, source)?
            == super::floor::FloorSource::Unknown;
        unknown_sources.insert(*source, unknown);
        Ok(unknown)
    };
    for entry in super::DERIVED.iter_from(store, txn, &[])? {
        let (row, floor) = entry?;
        for source in &floor {
            if unknown(source)? {
                judged.insert(row);
                break;
            }
        }
    }
    for entry in super::RECORDS.iter_from(store, txn, &[])? {
        let (row, policy) = entry?;
        if unknown(&policy)? {
            judged.insert(row);
        }
    }
    let mut reader = StateReader::reader(vault, txn)?;
    let mut rows = BTreeMap::new();
    for row in judged {
        if let Some(read) = not_whole_in(vault, txn, &mut reader, &row)? {
            rows.insert(row, read);
        }
    }
    Ok(rows)
}

/// The current sealed rows, for their re-derive.
fn current_sealed_rows_in(vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<(EntityId, RowKind)>> {
    Ok(current_not_whole_rows_in(vault, txn)?
        .into_iter()
        .filter_map(|(row, read)| match read {
            NotWhole::Sealed(kind) => Some((row, kind)),
            NotWhole::Waiting(_) => None,
        })
        .collect())
}

/// A count of rows, as the reports carry it.
fn count(rows: usize) -> Result<u64> {
    u64::try_from(rows).map_err(|_| Error::ArithmeticOverflow("sealed row count"))
}

/// Doctor's counts of the current rows this vault does not read as whole
/// ([`FloorCounts`]): one judgement by verdict of each row that can read
/// otherwise. A sealed row a later row took the place of (a superseded or
/// retracted CLAIM, a replaced summary generation) is history and leaves
/// the counts. Only the counts leave, never a row, its text or its sources.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn floor_counts_in(vault: &Vault, txn: &RoTxn<'_>) -> Result<FloorCounts> {
    let mut counts = FloorCounts::default();
    for read in current_not_whole_rows_in(vault, txn)?.into_values() {
        let tally = match read {
            NotWhole::Sealed(_) => &mut counts.hidden_source_unknown,
            NotWhole::Waiting(Wait::BeforeFloors) => &mut counts.source_deleted_before_tagging,
            NotWhole::Waiting(Wait::Arrival) => &mut counts.waiting_for_source,
        };
        *tally = tally.saturating_add(1);
    }
    Ok(counts)
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
                RowKind::Claim => self.rederive_sealed_claim(owner, &row)?,
                RowKind::Summary(requester) => match self.rederive_scope_summary(row, requester) {
                    Ok(_) => Rederived::Queued,
                    Err(error) if refused(&error) => Rederived::Kept,
                    Err(error) => return Err(error),
                },
                RowKind::Other => Rederived::Kept,
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
    /// and whose verdict is not sealed (its floor names only sources that
    /// resolve, and no input it waits on reads erased): a whole one first,
    /// which reads now; else one that waits for a source to arrive before
    /// one that waits for good.
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
        let mut reader = StateReader::reader(self, txn)?;
        let mut waiting: Option<(Wait, EntityId)> = None;
        for twin in same {
            let Some(raw) = self.get_raw_in(txn, &twin)? else {
                continue;
            };
            match reader.verdict(&twin, Some(&raw))? {
                Verdict::Whole(_) => return Ok(Some(twin)),
                Verdict::Waiting(wait) if waiting.is_none_or(|(held, _)| wait < held) => {
                    waiting = Some((wait, twin));
                }
                Verdict::Waiting(_) | Verdict::Sealed => {}
            }
        }
        Ok(waiting.map(|(_, twin)| twin))
    }
}
