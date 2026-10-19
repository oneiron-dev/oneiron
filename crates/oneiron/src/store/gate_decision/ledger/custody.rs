//! The ledger's side of the claim custody client: a row decrypted under its
//! claim's key, a new row sealed under it, and an erase's key retirement
//! staged with the redaction.

use heed::RwTxn;

use crate::error::{Error, Result, StoreError};
use crate::store::key_custody::{
    RetireCause, RetirementIntent, retirement_in_txn, stage_retirement_in_txn,
};
use crate::store::{ManifestDbs, Store};

use super::super::orcb;
use super::super::types::{GateDecisionId, GateDecisionRecord};
use super::{LEDGER, decode_gate_decision};

impl Store {
    /// Readers acquire this BEFORE opening an LMDB snapshot. Retirement takes
    /// the write half BEFORE the exterior marker/unlink, so no healthy live
    /// snapshot loses custody between its key check and file open.
    pub(crate) fn gate_custody_read_guard(&self) -> Result<std::sync::RwLockReadGuard<'_, ()>> {
        self.core.key_custody.read_guard()
    }

    /// Decode one row against its key, decrypting only claim-bound ORCB values.
    pub(in crate::store) fn decode_gate_decision_value(
        &self,
        decision_id: GateDecisionId,
        raw: &[u8],
    ) -> Result<GateDecisionRecord> {
        if orcb::is_orcb(raw) {
            let custody = self.core.key_custody.local().ok_or_else(orcb::corrupt)?;
            orcb::decode_hot(custody, decision_id, raw)
        } else {
            decode_gate_decision(raw)
        }
    }

    /// Erase destroys the claim's exterior key in the same act (ARCH-0038
    /// #erasure-completeness): a restored pre-erase image must not decrypt
    /// the rows this erase redacted. The retirement intent commits with the
    /// redaction, marked as an erase's so no later hold can defer it; the
    /// caller's post-commit finisher destroys the key. A future receipt that
    /// batch preflight staged in this transaction stays readable: it moves
    /// to the generation after the retired one before the intent lands.
    pub(super) fn stage_erased_claim_key_retirement_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &[u8; 16],
    ) -> Result<()> {
        if cfg!(not(unix)) {
            // No exterior custody exists here, so no claim key can either.
            return Ok(());
        }
        if self.core.gate_custody_archived() {
            return Err(Error::Store(StoreError::ArchivedVault));
        }
        // Unbound: no key of this vault's was ever published.
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(());
        };
        let subject = orcb::claim_subject(custody, claim_id)?;
        let overflow = || Error::ArithmeticOverflow("gate decision key generation");
        // An earlier erase whose key is not destroyed yet may already have
        // moved kept receipts one generation up.
        let mut through = None;
        let mut generation = custody.first_unretired(&subject)?;
        while custody.published(&subject.at(generation))? {
            through = Some(generation);
            generation = generation.checked_add(1).ok_or_else(overflow)?;
        }
        let pending = retirement_in_txn(self, &*wtxn, &subject)?.map(|intent| intent.through);
        let Some(through) = through.max(pending) else {
            return Ok(());
        };
        let next = through.checked_add(1).ok_or_else(overflow)?;
        for record in self.gate_decisions_for_claim_in_txn(&*wtxn, claim_id)? {
            if record.redacted_at.is_none() {
                LEDGER.put(
                    self,
                    wtxn,
                    &record.decision_id,
                    &orcb::encode_hot_at(custody, &record, next)?,
                )?;
            }
        }
        stage_retirement_in_txn(
            self,
            wtxn,
            &RetirementIntent {
                subject,
                through,
                cause: RetireCause::Erase,
            },
        )
    }
}

/// A claim-bound row's stored value, sealed under its claim's current key in
/// the write target's custody.
pub(super) fn sealed_claim_row_in_txn(
    store: &impl ManifestDbs,
    wtxn: &RwTxn<'_>,
    record: &GateDecisionRecord,
    claim: &[u8; 16],
) -> Result<Vec<u8>> {
    // An archived vault's custody is its replacement's; it mints no key
    // there.
    if store.gate_custody_archived() {
        return Err(Error::Store(StoreError::ArchivedVault));
    }
    let custody = store.key_custody().bind_in_txn(store, wtxn)?;
    // A committed age sweep may still be retiring this partition's
    // exterior key. No new ciphertext may reuse it in that interval.
    if retirement_in_txn(store, wtxn, &orcb::claim_subject(custody, claim)?)?.is_some() {
        return Err(Error::InvalidConfig(
            "gate decision partition is retiring".into(),
        ));
    }
    orcb::encode_hot(custody, record)
}
