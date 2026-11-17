//! The native Dreamer attempt binding (untangle 6.9c, RULING S69C-DESIGN
//! item 5): the in-process credential a host's job client calls under while
//! one admitted strength or conflict-settlement attempt holds its lease.
//!
//! Only the engine mints one, from the admitted attempt: it keeps the
//! attempt's lease (owner and generation), the authority stamp the engine
//! recorded for the attempt at enqueue, and the attempt's run. Every call
//! proves again, in the transaction it reads or writes in, that the lease
//! still holds, the attempt is still that facet's job under that stamp, and
//! the Dreamer's Steward read reach and MACHINE binding are live. A binding
//! is never serialized or cloned, and no call it makes succeeds once the
//! lease ends, even while the object lives on.

mod decisions;
mod invocation;

pub use decisions::DreamerDecisionLender;

use std::fmt;
use std::sync::Arc;

use crate::attempt_queue::{AttemptQueue, AttemptRecord, BorrowedAttemptLease};
use crate::claim::ClaimSource;
use crate::derive::{
    DerivationBatch, DerivationItem, DerivationStamp, DeriveCommitInput, DeriveCommitView,
};
use crate::edge::EdgeActorClass;
use crate::federation::{grant_scope, steward_reach_in};
use crate::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_LEASE_REQUIRED, MemoryError, MemoryResult};
use crate::write_envelope::{SourceLineage, WriteActor};
use crate::{Result, Vault};

use super::authority::{DreamerAuthorityStamp, dreamer_facet_for_job_type};
use super::maintenance::{
    CONFLICT_SETTLE_FACET, CONSOLIDATION_STRENGTH_FACET, MAINTENANCE_QUEUE_KIND,
};
use super::{DreamerAdmittedAttempt, decode_dreamer_attempt_payload};

/// The operations one admitted maintenance job may call through its binding.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BoundFacet {
    Strength,
    ConflictSettle,
}

/// One admitted maintenance attempt's live delegation, as the engine minted it.
/// It names identities only; the grant, scope and lease are read live at
/// each call.
pub struct DreamerAttemptBinding {
    /// The vault the attempt was admitted in; the binding acts on no other.
    vault: Arc<Vault>,
    /// The attempt, its lease owner and its lease generation.
    lease: BorrowedAttemptLease,
    /// The authority stamp the engine recorded for the attempt.
    stamp: DreamerAuthorityStamp,
    /// The attempt's recorded run.
    run: Option<String>,
    /// The job facet the binding was minted for.
    facet: BoundFacet,
    /// The host's decision ladder, lent only when the host supplies one.
    lender: Option<Arc<dyn DreamerDecisionLender>>,
}

/// Prints the attempt only: the binding is a credential.
impl fmt::Debug for DreamerAttemptBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "DreamerAttemptBinding {{ attempt: {} }}",
            crate::entity_id::bytes_to_hex_lower(self.lease.attempt().as_bytes())
        )
    }
}

impl Vault {
    /// Mints the binding a host's job client calls under for `admitted`, a
    /// strength or conflict-settlement attempt this vault admitted and whose
    /// lease still holds.
    ///
    /// # Errors
    ///
    /// `LEASE_REQUIRED` when the attempt's lease no longer holds;
    /// `FORBIDDEN` when it is not an admitted facet under the Dreamer's
    /// recorded stamp, or the Dreamer has no live Steward read reach or
    /// MACHINE binding; storage errors.
    pub fn bind_dreamer_attempt(
        self: &Arc<Self>,
        admitted: &DreamerAdmittedAttempt,
    ) -> MemoryResult<DreamerAttemptBinding> {
        let record = &admitted.status.attempt;
        let lease = BorrowedAttemptLease::of(record).ok_or_else(lease_ended)?;
        let facet = bound_facet_for_attempt(record)?.ok_or_else(authority_moved)?;
        let job_type = match facet {
            BoundFacet::Strength => CONSOLIDATION_STRENGTH_FACET,
            BoundFacet::ConflictSettle => CONFLICT_SETTLE_FACET,
        };
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let stamp = self
            .dreamer_attempt_authority_in_txn(&txn, record.id)?
            .filter(|stamp| Some(stamp.facet.as_str()) == dreamer_facet_for_job_type(job_type))
            .ok_or_else(authority_moved)?;
        let binding = DreamerAttemptBinding {
            vault: Arc::clone(self),
            lease,
            stamp,
            run: record.run_id.clone(),
            facet,
            lender: None,
        };
        binding.check_in_txn(&txn)?;
        Ok(binding)
    }
}

impl DreamerAttemptBinding {
    /// Lends the host's decision ladder and learned bands to this attempt.
    #[must_use]
    pub fn lend_decisions(mut self, lender: Arc<dyn DreamerDecisionLender>) -> Self {
        self.lender = Some(lender);
        self
    }

    /// The vault the binding acts on.
    #[must_use]
    pub fn vault(&self) -> &Arc<Vault> {
        &self.vault
    }

    /// The Dreamer, as the attempt's recorded stamp names it.
    #[must_use]
    pub fn actor(&self) -> WriteActor {
        WriteActor::new(self.stamp.actor, EdgeActorClass::System)
    }

    /// Proves the binding in `txn`: the lease holds at its owner and
    /// generation, the attempt is still this facet's job in this run under
    /// this stamp, a standing Steward reach names `read`, and the Dreamer's
    /// MACHINE binding is live. No standing reach is no reach here: the
    /// manifest fallback of an unbound base agent never stands in.
    pub(crate) fn check_in_txn(&self, txn: &heed::RoTxn<'_>) -> MemoryResult<()> {
        let vault = &*self.vault;
        let queue = AttemptQueue::new(vault);
        if !self.lease.holds_in(&queue, txn)? {
            return Err(lease_ended());
        }
        let record = queue
            .get_in_txn(txn, self.lease.attempt())?
            .ok_or_else(lease_ended)?;
        if bound_facet_for_attempt(&record)? != Some(self.facet) || record.run_id != self.run {
            return Err(authority_moved());
        }
        if vault
            .dreamer_attempt_authority_in_txn(txn, self.lease.attempt())?
            .as_ref()
            != Some(&self.stamp)
        {
            return Err(authority_moved());
        }
        let reads = steward_reach_in(&vault.store, txn, self.stamp.actor)?
            .is_some_and(|reach| reach.verbs.contains(grant_scope::STEWARD_READ_VERB));
        if !reads {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "the Dreamer attempt no longer has live Steward read reach",
                &["Stand a Steward grant naming read for the Dreamer, then admit a new attempt."],
            ));
        }
        if !vault.system_agent_binding_live_in(txn, self.stamp.actor)? {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "the Dreamer attempt MACHINE binding is no longer live",
                &["Bind the Dreamer to a live roster key, then admit a new attempt."],
            ));
        }
        Ok(())
    }

    /// [`Self::check_in_txn`] in a read of its own: the early refusal before
    /// a call's hooks run. The call checks again where it reads or writes.
    fn check(&self) -> MemoryResult<()> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        self.check_in_txn(&txn)
    }

    /// Commits `input` as the Dreamer in this attempt and run, admitting
    /// Archive items for strength and Settle items for conflict settlement.
    /// One writer proves the binding before the batch stages. A refused
    /// binding writes no batch, receipt, archive or settlement.
    fn commit(&self, input: DeriveCommitInput) -> MemoryResult<DeriveCommitView> {
        let batch = facet_batch(input, self.facet)?;
        let stamp = DerivationStamp {
            actor: self.actor(),
            run: self.run.clone(),
            attempt: Some(self.lease.attempt()),
            lineage: SourceLineage::of(ClaimSource::Generated),
        };
        let receipt = self.vault.with_write_txn_grouped(|txn| {
            if let Err(refused) = self.check_in_txn(txn) {
                return Ok(Err(refused));
            }
            self.vault.derive_commit_in_txn(txn, &stamp, &batch).map(Ok)
        })??;
        Ok(receipt.into())
    }
}

/// The admitted facet of `record`, if it is a bound maintenance job.
fn bound_facet_for_attempt(record: &AttemptRecord) -> Result<Option<BoundFacet>> {
    if record.kind != MAINTENANCE_QUEUE_KIND {
        return Ok(None);
    }
    Ok(
        match decode_dreamer_attempt_payload(&record.payload)?
            .attempt_type
            .as_str()
        {
            CONSOLIDATION_STRENGTH_FACET => Some(BoundFacet::Strength),
            CONFLICT_SETTLE_FACET => Some(BoundFacet::ConflictSettle),
            _ => None,
        },
    )
}

/// The engine batch of `input`, admitted only when every item belongs to
/// the bound facet.
fn facet_batch(input: DeriveCommitInput, facet: BoundFacet) -> MemoryResult<DerivationBatch> {
    let batch = input.into_batch()?;
    if batch.items.iter().all(|item| {
        matches!(
            (facet, item),
            (BoundFacet::Strength, DerivationItem::Archive(_))
                | (BoundFacet::ConflictSettle, DerivationItem::Settle(_))
        )
    }) {
        Ok(batch)
    } else {
        Err(facet_refused(facet))
    }
}

fn lease_ended() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_LEASE_REQUIRED,
        "the Dreamer attempt lease no longer holds",
        &["Call under the binding of the attempt that now holds the lease."],
    )
}

fn authority_moved() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        "the Dreamer attempt authority no longer matches its recorded binding",
        &[],
    )
}

fn facet_refused(facet: BoundFacet) -> MemoryError {
    let (message, hint) = match facet {
        BoundFacet::Strength => (
            "the Dreamer strength facet does not admit this operation",
            "A strength attempt reads its observations page and commits Archive items only.",
        ),
        BoundFacet::ConflictSettle => (
            "the Dreamer conflict settlement facet does not admit this operation",
            "A conflict settlement attempt pages conflicts, asks ai.verdict and commits Settle items only.",
        ),
    };
    MemoryError::new(MEMORY_CODE_FORBIDDEN, message, &[hint])
}
