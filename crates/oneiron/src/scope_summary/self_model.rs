//! A self-model SUMMARY as its own resident reads it (FIX 4570).
//!
//! `self_model` is a seeded summary purpose, not a store of its own. A
//! resident's compaction home wears the SUMMARY its binding names only
//! through this read: the resident's own scoped lane at its own place, the
//! same SUMMARY type check, deletion state, source validation and staleness
//! a summary read honours, the purpose read from the document, and the
//! resident's ownership of the work. The words and the live revision they
//! were read at come from one snapshot (FIX 4817). A SUMMARY that fails any
//! of this is named absent with why; it is never read under the owner's
//! reach, and another resident's self-model is never taken because a broad
//! Grant can read it.

use crate::authority::principal_standing_in_txn;
use crate::batch::secret_scan::LiftedKeys;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory};
use crate::ports::{ClaimReadStatus, PointRead, ScopedReadResult};
use crate::vault::entity_revision::revision_for_mode_in_txn;
use crate::vault::{ReadMode, RevisionRef};
use crate::{EntityId, Vault};
use oneiron_contracts::memory::{MemoryError, MemoryResult};

/// The seeded purpose a self-model SUMMARY carries.
pub(crate) const SELF_MODEL_PURPOSE: &str = "self_model";

/// The verb a Grant lists to name a self-model read through `self.memory.self_model`.
const SELF_MODEL_READ_VERB: &str = "self.memory.self_model";

/// One self-model SUMMARY as its resident reads it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SelfModelRead {
    /// Its current words, masked as the reader reads secrets, and the live
    /// revision of the SUMMARY they were read at.
    Read {
        text: String,
        revision: Option<RevisionRef>,
    },
    /// Why it is not worn: `unreadable`, `stale`, `not_self_model` or
    /// `not_own`.
    Absent(&'static str),
}

/// Whether `resident` owns the self-model work `summary` is: the actor the
/// Dreamer composed it for, or the producer that wrote its body.
fn resident_owns_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    body: &super::ScopeSummaryBody,
    meta: &super::ScopeSummaryMetadata,
    resident: EntityId,
) -> crate::Result<bool> {
    if body.actor == resident.to_hex() {
        return Ok(true);
    }
    let declared = super::derivation::decode(&meta.derivation.request)?;
    let request = super::request::decode_request(vault, txn, &declared)?;
    Ok(request.requester.entity_ref() == resident)
}

impl Memory<'_> {
    /// Reads `summary` as this actor's own self-model (FIX 4570), on its own
    /// scoped SUMMARY lane: a standing, current SUMMARY of purpose
    /// `self_model` that this actor owns, with its words and the revision
    /// they were read at in one snapshot.
    ///
    /// # Errors
    ///
    /// A lane this actor cannot open, or a storage error.
    pub(crate) fn read_self_model_summary(
        &self,
        summary: &EntityId,
    ) -> MemoryResult<SelfModelRead> {
        Ok(self.read_self_model_summary_projected(summary, None)?.value)
    }

    /// [`Self::read_self_model_summary`] with its serving receipt and its verb Grant: the same
    /// scoped read, purpose, ownership and staleness checks in one snapshot, plus the caller's
    /// live Grant listing `self.memory.self_model` checked in that same snapshot, returning the
    /// [`ScopedReadResult`] the compaction caller discards.
    /// The verb `self.memory.self_model` serves this; compaction keeps
    /// calling [`Self::read_self_model_summary`], which checks no additional verb Grant
    /// (the ordinary `read_lane` read grant still applies).
    ///
    /// # Errors
    ///
    /// FORBIDDEN where no live Grant names the caller and lists the verb; a lane this actor
    /// cannot open, or a storage error.
    pub(crate) fn read_self_model_summary_receipted(
        &self,
        summary: &EntityId,
    ) -> MemoryResult<ScopedReadResult<SelfModelRead>> {
        self.read_self_model_summary_projected(summary, Some(SELF_MODEL_READ_VERB))
    }

    /// The read behind [`Self::read_self_model_summary`] and
    /// [`Self::read_self_model_summary_receipted`]: the scoped lane read with the existing
    /// purpose, ownership and staleness checks in one snapshot, and `required_verb`'s live
    /// Grant standing checked first in that same snapshot where `Some`. `None` checks no
    /// additional verb Grant: the compaction path (the ordinary `read_lane` read grant still
    /// applies).
    fn read_self_model_summary_projected(
        &self,
        summary: &EntityId,
        required_verb: Option<&str>,
    ) -> MemoryResult<ScopedReadResult<SelfModelRead>> {
        let resident = self.actor();
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let read = lane.read_projected(&[PointRead::id(*summary)], None, |txn, rows| {
            let vault = self.vault();
            if let Some(verb) = required_verb {
                let standing = principal_standing_in_txn(
                    vault,
                    txn,
                    self.actor(),
                    self.actor_class(),
                    verb,
                )
                .map_err(MemoryError::from)?;
                if standing.is_none() {
                    return Err(MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        format!(
                            "self.memory.self_model takes a live Grant listing {verb}: no live Grant from a live owner names this caller and lists the verb"
                        ),
                        &["Have the owner grant this caller the verb by name."],
                    ));
                }
            }
            let readable = rows.into_iter().next().flatten().is_some_and(|row| {
                row.body.is_some() && row.entity_type == crate::registry::ENTITY_TYPE_SUMMARY
            });
            if !readable {
                return Ok::<_, MemoryError>(SelfModelRead::Absent("unreadable"));
            }
            if crate::ports::stale_in_txn(&vault.store, txn, summary)? {
                return Ok(SelfModelRead::Absent("stale"));
            }
            let (Ok(body), Ok(meta)) = (
                super::doors::summary_in_txn(vault, txn, summary),
                crate::entity_doc::summary_meta_in_txn(vault, txn, summary),
            ) else {
                return Ok(SelfModelRead::Absent("unreadable"));
            };
            if meta.purpose.id != SELF_MODEL_PURPOSE {
                return Ok(SelfModelRead::Absent("not_self_model"));
            }
            if !resident_owns_in(vault, txn, &body, &meta, resident).unwrap_or(false) {
                return Ok(SelfModelRead::Absent("not_own"));
            }
            if super::doors::summary_stale_in_txn(vault, txn, summary)?.is_some() {
                return Ok(SelfModelRead::Absent("stale"));
            }
            let mut text = crate::entity_doc::summary_text_in_txn(vault, txn, summary)?;
            if self.reads_lifted_keys_masked_in_txn(txn)? {
                let keys = LiftedKeys::of_in_txn(&vault.store, txn, [text.as_str()])?;
                if let Some(masked) = keys.masked(&text) {
                    text = masked;
                }
            }
            let revision = revision_for_mode_in_txn(&vault.store, txn, summary, ReadMode::Live)?;
            self.produced_from([*summary]);
            Ok(SelfModelRead::Read { text, revision })
        })?;
        Ok(read)
    }
}
