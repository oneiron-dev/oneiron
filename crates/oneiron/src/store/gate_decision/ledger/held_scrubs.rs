//! What an erase owes a Gate decision a legal hold keeps (FIX 7993, 7994).
//!
//! An erase reaches the Gate ledger twice: a claim's erase turns every
//! decision bound to the claim, or a bundle citing it, into its retention
//! skeleton, and an actor's erase clears the `actor_ref` of every decision
//! that names it. Each decision lives in one exterior-key partition, its
//! claim's or the claim-free one a bundle shares (`retention`). A legal hold
//! on that partition keeps the decision whole, its claim references and
//! indexes too, and the erase goes on: it owes the decision its scrub in
//! [`PENDING_SCRUB`], in its own transaction. Each due legal-hold pass
//! settles every owed scrub no hold keeps any more, and the erase's overall
//! final row waits on what is still owed (`deletion::receipt_final`). A
//! restore re-derives a hard erase's claim scrubs from its `dt:` markers, so
//! an image cannot bring a cited bundle back whole.

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

use super::super::actor_erase::reseal_gate_decision;
use super::super::orcb;
use super::super::types::{
    GATE_DECISION_LEDGER_VERSION_REDACTED, GateDecisionId, GateDecisionRecord,
};
use super::super::vet::vet_gate_decision_record;
use super::{LEDGER, encode_gate_decision};

/// Which scrub a decision is owed, spelled as its key's first byte so each
/// kind scans apart.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OwedScrub {
    /// The decision is bound to an erased claim, or is a bundle citing one:
    /// it becomes its retention skeleton.
    Claim,
    /// The decision names an erased actor: it names no one.
    Actor,
}

impl OwedScrub {
    const fn tag(self) -> [u8; 1] {
        match self {
            Self::Claim => [0],
            Self::Actor => [1],
        }
    }

    fn of(tag: [u8; 1]) -> Result<Self> {
        match tag {
            [0] => Ok(Self::Claim),
            [1] => Ok(Self::Actor),
            _ => Err(Error::CorruptedIndex("gate decision pending scrub")),
        }
    }
}

/// When the erase that owes a scrub asked. The first erase to owe one keeps
/// its time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingScrub {
    redacted_at: u64,
}

/// Owed scrubs. Key: kind + id16 (erased source) + id16 (decision).
const PENDING_SCRUB: SideTable<([u8; 1], EntityId, GateDecisionId), PendingScrub, Named> =
    SideTable::new(&side_table::GATE_DECISION_PENDING_SCRUB);

/// One owed scrub of a decision, as its row stands.
struct Owed {
    kind: OwedScrub,
    source: EntityId,
    redacted_at: u64,
}

impl Store {
    /// Rewrites every live row for a deleted claim to its retention skeleton
    /// inside the caller's destructive transaction. The claim index is retained
    /// for discovery of skeletons; the grant-ref index is removed because its
    /// source field is scrubbed. Discovery falls back to a full scan until the
    /// durable claim-index backfill has completed. A held key partition keeps
    /// its rows, so every door that tears a held claim (facade, batch, cascade
    /// or replay) is refused here, before anything is rewritten.
    ///
    /// A decision in another partition a hold keeps, a claim-free bundle
    /// citing the claim while that partition is held, is no refusal (FIX
    /// 7994): every decision's own partition is read before anything changes,
    /// a held one keeps its bytes, its claim references and its indexes, and
    /// the erase owes it its skeleton. `true` when anything changed, an owed
    /// scrub included; never whether the erase is complete.
    pub(crate) fn redact_gate_decisions_for_claim_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &[u8; 16],
        redacted_at: u64,
    ) -> Result<bool> {
        self.reject_legal_hold_in_txn(&*wtxn, claim_id)?;
        let id = EntityId::from_bytes(*claim_id)
            .map_err(|_| Error::CorruptedIndex("gate decision claim id"))?;
        let pending = self.pending_gate_consent_in_txn(&*wtxn, &id)?.is_some();
        let mut changed = pending;
        let mut held = Vec::new();
        let mut redact = Vec::new();
        for (record, kept) in self.claim_decisions_in_txn(&*wtxn, claim_id)? {
            changed = true;
            if kept {
                held.push(record.decision_id);
            } else {
                redact.push(record);
            }
        }
        for decision in held {
            self.owe_gate_scrub_in_txn(wtxn, OwedScrub::Claim, &id, decision, redacted_at)?;
        }
        for record in redact {
            self.redact_gate_decision_in_txn(wtxn, record, redacted_at)?;
        }
        // The tray carries the original content binding and can mint a fresh
        // live v0 resolution from a v1 skeleton. Remove it and every index
        // inside this same destructive transaction, before verification. An
        // erasure shows no fresh item, and the open obligation keeps no hash
        // of the erased body.
        self.remove_pending_gate_consent_in_txn(wtxn, &id, crate::store::TrayRemoval::Silent)?;
        self.blank_owner_answer_obligation_item_in_txn(wtxn, &id)?;
        for decision_id in self.verify_claim_erasure_by_scan_in_txn(&*wtxn, claim_id)? {
            if !self.is_unapplied_preflight_decision_in_txn(&*wtxn, decision_id)?
                && !self.claim_scrub_held_in_txn(&*wtxn, &id, decision_id)?
            {
                return Err(Error::CorruptedIndex("gate decision claim erasure"));
            }
        }
        self.stage_erased_claim_key_retirement_in_txn(wtxn, claim_id)?;
        Ok(changed)
    }

    /// The unredacted decisions bound to `claim_id` or citing it, each with
    /// whether a legal hold keeps its own partition, all read before anything
    /// changes.
    fn claim_decisions_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim_id: &[u8; 16],
    ) -> Result<Vec<(GateDecisionRecord, bool)>> {
        let mut records = self.gate_decisions_for_claim_in_txn(txn, claim_id)?;
        records.extend(self.bundle_gate_decisions_for_claim_in_txn(txn, claim_id)?);
        let mut found = Vec::with_capacity(records.len());
        for record in records {
            // Batch preflight stages receipts for *future* ops in this same
            // txn. Their marker is consumed only after their op applies; a
            // delete before that op must not scrub its future receipt.
            if self.is_unapplied_preflight_decision_in_txn(txn, record.decision_id)? {
                continue;
            }
            if record.redacted_at.is_some() {
                if !self
                    .gate_decision_claim_refs_in_txn(txn, record.decision_id)?
                    .is_empty()
                {
                    return Err(Error::CorruptedIndex(
                        "redacted gate decision claim references",
                    ));
                }
                continue;
            }
            let held = self.gate_partition_held_in_txn(txn, record.claim_id.as_ref())?;
            found.push((record, held));
        }
        Ok(found)
    }

    /// `record`, live, as its retention skeleton in place: its grant-ref index
    /// row and its claim references go with its content, and so does every
    /// scrub it was owed. The claim index stays for discovery.
    fn redact_gate_decision_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        mut record: GateDecisionRecord,
        redacted_at: u64,
    ) -> Result<()> {
        self.delete_gate_decision_grant_ref_index_in_txn(wtxn, &record)?;
        self.delete_gate_decision_claim_refs_in_txn(wtxn, record.decision_id)?;
        record.version = GATE_DECISION_LEDGER_VERSION_REDACTED;
        // v0 records a caller's empty class on an auditable denial; v1
        // requires a non-empty retention label.
        if record.actor_class.is_empty() {
            record.actor_class = "unspecified".to_owned();
        }
        record.reason_codes.clear();
        record.receipt_reasons.clear();
        record.system_notices.clear();
        record.actor_ref = None;
        record.grant_ref = None;
        record.diff_handle.clear();
        // An injected clock at epoch zero must still produce a valid v1 row.
        record.redacted_at = Some(redacted_at.max(1));
        vet_gate_decision_record(&record)?;
        LEDGER.put(
            self,
            wtxn,
            &record.decision_id,
            &encode_gate_decision(&record)?,
        )?;
        self.forget_gate_scrubs_of_decision_in_txn(wtxn, record.decision_id)
    }

    /// Owes `decision` the scrub `kind` for erased `source`. A scrub already
    /// owed keeps its first time.
    fn owe_gate_scrub_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        kind: OwedScrub,
        source: &EntityId,
        decision: GateDecisionId,
        redacted_at: u64,
    ) -> Result<()> {
        let key = (kind.tag(), *source, decision);
        if PENDING_SCRUB.contains(self, &*wtxn, &key)? {
            return Ok(());
        }
        PENDING_SCRUB.put(self, wtxn, &key, &PendingScrub { redacted_at })
    }

    /// Owes `decision` the clear of erased actor `actor` while a hold keeps
    /// the decision's partition (FIX 7993).
    pub(in crate::store) fn owe_gate_actor_scrub_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        actor: &EntityId,
        decision: GateDecisionId,
        at: u64,
    ) -> Result<()> {
        self.owe_gate_scrub_in_txn(wtxn, OwedScrub::Actor, actor, decision, at)
    }

    /// Whether erased claim `source` owes `decision` its skeleton while a hold
    /// keeps the decision's own partition: the one residue of a claim's erase
    /// that is no corruption.
    fn claim_scrub_held_in_txn(
        &self,
        txn: &RoTxn<'_>,
        source: &EntityId,
        decision: GateDecisionId,
    ) -> Result<bool> {
        let key = (OwedScrub::Claim.tag(), *source, decision);
        if !PENDING_SCRUB.contains(self, txn, &key)? {
            return Ok(false);
        }
        match self.gate_decision_in_txn(txn, decision)? {
            Some(record) => self.gate_partition_held_in_txn(txn, record.claim_id.as_ref()),
            None => Ok(false),
        }
    }

    /// Drops every scrub `decision` is owed, in the transaction that redacts
    /// or removes it.
    pub(in crate::store) fn forget_gate_scrubs_of_decision_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        decision: GateDecisionId,
    ) -> Result<()> {
        let keys: Vec<_> = PENDING_SCRUB
            .scan_keys(self, &*wtxn, &[])?
            .into_iter()
            .filter(|(_, _, owed)| *owed == decision)
            .collect();
        for key in &keys {
            PENDING_SCRUB.delete(self, wtxn, key)?;
        }
        Ok(())
    }

    /// Whether a decision is still owed a scrub for one of `sources`: a hold
    /// keeps its partition, or its hold lifted and no due pass has settled it
    /// yet. An erase of those ids is not complete while one is
    /// (`deletion::receipt_final`).
    pub(crate) fn gate_scrubs_owed_in_txn(
        &self,
        txn: &RoTxn<'_>,
        sources: &[EntityId],
    ) -> Result<bool> {
        for kind in [OwedScrub::Claim, OwedScrub::Actor] {
            for source in sources {
                let prefix = [&kind.tag()[..], source.as_bytes()].concat();
                let mut owed = PENDING_SCRUB.iter_raw_from(self, txn, &prefix)?;
                if owed.next().transpose()?.is_some() {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Settles, in a due legal-hold pass's transaction, each owed scrub no
    /// legal hold keeps any more: a decision whose partition no hold keeps
    /// takes its skeleton when an erased claim owes it one, else names none of
    /// its erased actors, and what it was owed goes. A decision already gone,
    /// or sealed under a key no one holds any more, owes nothing. Whether
    /// anything settled.
    pub(crate) fn settle_gate_scrubs_in_txn(&self, wtxn: &mut RwTxn<'_>) -> Result<bool> {
        let mut owed: BTreeMap<[u8; 16], Vec<Owed>> = BTreeMap::new();
        for row in PENDING_SCRUB.iter_from(self, &*wtxn, &[])? {
            let ((tag, source, decision), pending) = row?;
            let scrub = Owed {
                kind: OwedScrub::of(tag)?,
                source,
                redacted_at: pending.redacted_at,
            };
            owed.entry(decision.as_bytes()).or_default().push(scrub);
        }
        let custody = self.core.key_custody.local();
        let mut settled = false;
        for (decision, owed) in owed {
            let decision = GateDecisionId::from_bytes(decision);
            let Some(raw) = LEDGER.get(self, &*wtxn, &decision)? else {
                // Its row went first: its claim references go too.
                self.delete_gate_decision_claim_refs_in_txn(wtxn, decision)?;
                self.forget_gate_scrubs_of_decision_in_txn(wtxn, decision)?;
                settled = true;
                continue;
            };
            let mut record = match self.decode_gate_decision_value(decision, &raw) {
                Err(error @ Error::CorruptedIndex("gate decision ORCB")) => {
                    if !orcb::raw_key_retired(custody, &raw)? {
                        return Err(error);
                    }
                    self.forget_gate_scrubs_of_decision_in_txn(wtxn, decision)?;
                    settled = true;
                    continue;
                }
                decoded => decoded?,
            };
            if self.gate_partition_held_in_txn(&*wtxn, record.claim_id.as_ref())? {
                continue;
            }
            let claim = owed
                .iter()
                .filter(|scrub| scrub.kind == OwedScrub::Claim)
                .map(|scrub| scrub.redacted_at)
                .min();
            if record.redacted_at.is_some() {
                // Redacted since: nothing it names is left to clear.
            } else if let Some(redacted_at) = claim {
                self.redact_gate_decision_in_txn(wtxn, record, redacted_at)?;
            } else {
                let names_erased = owed.iter().any(|scrub| {
                    scrub.kind == OwedScrub::Actor
                        && record.actor_ref.as_deref() == Some(scrub.source.to_hex().as_str())
                });
                if names_erased {
                    record.actor_ref = None;
                    let value = reseal_gate_decision(custody, &raw, &record)?;
                    LEDGER.put(self, wtxn, &decision, &value)?;
                }
            }
            self.forget_gate_scrubs_of_decision_in_txn(wtxn, decision)?;
            settled = true;
        }
        Ok(settled)
    }

    /// A restore's Gate claim scrubs for the hard-erased ids `erased`, in its
    /// image-write transaction (FIX 7994): each decision the image brought
    /// back bound to one of them, or a bundle citing one, takes its skeleton
    /// again, or is owed it while a hold keeps its partition. An owed scrub
    /// is live state an image never takes away. Nothing is refused and no
    /// entity erase runs again.
    pub(crate) fn rerun_gate_claim_scrubs_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        erased: &BTreeSet<EntityId>,
        redacted_at: u64,
    ) -> Result<()> {
        for id in erased {
            for (record, held) in self.claim_decisions_in_txn(&*wtxn, id.as_bytes())? {
                if held {
                    let decision = record.decision_id;
                    self.owe_gate_scrub_in_txn(wtxn, OwedScrub::Claim, id, decision, redacted_at)?;
                } else {
                    self.redact_gate_decision_in_txn(wtxn, record, redacted_at)?;
                }
            }
        }
        Ok(())
    }
}
