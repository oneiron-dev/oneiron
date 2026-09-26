//! Owner-scoped, consume-once ask labels and the policy-owned question-class band.

use super::TaskAskHandle;
use super::ask_record;
use crate::llm::decision::DecisionBand;
use crate::memory::{Memory, MemoryError, MemoryResult, verify_actor_binding};
use crate::skill_optimize::{AskBandLabel, AskBandPolicy};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const BAND: &[u8] = b"tasks.ask.band.v1:";

#[derive(Default, Serialize, Deserialize)]
struct BandState {
    band: DecisionBand,
}
fn key(owner: EntityId, class: &str) -> MemoryResult<Vec<u8>> {
    if class.is_empty() || class.len() > 256 {
        return Err(MemoryError::bad_request("invalid ask question class"));
    }
    Ok([
        BAND,
        owner.as_bytes(),
        &(class.len() as u16).to_be_bytes(),
        class.as_bytes(),
    ]
    .concat())
}
fn read(vault: &Vault, txn: &heed::RoTxn<'_>, key: &[u8]) -> MemoryResult<BandState> {
    let Some(raw) = vault.store.vault_meta.get(txn, key)? else {
        return Ok(BandState::default());
    };
    let state: BandState = rmp_serde::from_slice(&raw)
        .map_err(|_| MemoryError::bad_request("invalid ask band state"))?;
    state.band.validate()?;
    Ok(state)
}

impl Memory<'_> {
    /// A class-scoped routing signal, not approval to perform an effect.
    /// A rule or model produces the predicted probability before this call.
    pub fn tasks_should_ask(&self, class: &str, probability: f64) -> MemoryResult<bool> {
        if !probability.is_finite() || !(0.0..=1.0).contains(&probability) {
            return Err(MemoryError::bad_request("invalid ask probability"));
        }
        Ok(self.tasks_ask_band(class)?.contains(probability))
    }

    pub fn tasks_ask_band(&self, class: &str) -> MemoryResult<DecisionBand> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        Ok(read(self.vault(), &txn, &key(self.actor(), class)?)?.band)
    }

    /// Settle and consume only this owner's labels for this class. The
    /// optimizing skill determines how far the band moves; no hardcoded gain.
    pub fn tasks_optimize_ask_band(
        &self,
        class: &str,
        handles: &[TaskAskHandle],
        policy: &impl AskBandPolicy,
    ) -> MemoryResult<DecisionBand> {
        if handles.len() > 4096 {
            return Err(MemoryError::bad_request("too many ask receipts"));
        }
        let key = key(self.actor(), class)?;
        self.with_verified_actor_write_txn(|txn| {
            let mut state = read(self.vault(), txn, &key)?;
            let mut labels = Vec::new();
            let mut pending = BTreeSet::new();
            for handle in handles {
                let group = ask_record::read_group(self.vault(), txn, handle.group_ref)?
                    .ok_or_else(|| MemoryError::bad_request("unknown ask handle"))?;
                if group.owner != self.actor().to_hex()
                    || group.effective.what.class_key.as_deref() != Some(class)
                {
                    return Err(MemoryError::bad_request(
                        "ask receipt is not in this owner's question class",
                    ));
                }
                let result =
                    super::ask_settlement::read_result(self.vault(), txn, handle.group_ref)?
                        .ok_or_else(|| MemoryError::bad_request("ask has not settled"))?;
                if result.settlement.reason == super::TaskAskSettlementReason::Stale {
                    continue;
                }
                for entry in result.evidence {
                    let word = entry.answer.word_ref;
                    let marker = [key.as_slice(), b":", word.as_bytes().as_slice()].concat();
                    if let Some(changed) = entry.ladder_changed
                        && self.vault().store.vault_meta.get(txn, &marker)?.is_none()
                        && pending.insert(word)
                    {
                        labels.push(AskBandLabel {
                            receipt: result.settlement.reference,
                            word: entry.answer.word_ref,
                            changed,
                            probability: group
                                .effective
                                .what
                                .ladder_answer
                                .as_ref()
                                .and_then(|l| l.probability),
                        });
                    }
                }
            }
            if labels.is_empty() {
                return Ok(state.band);
            }
            let proposed = policy.revise(state.band, &labels)?;
            proposed.validate()?;
            state.band = proposed;
            for word in pending {
                let marker = [key.as_slice(), b":", word.as_bytes().as_slice()].concat();
                self.vault().store.vault_meta.put(txn, &marker, &[1])?;
            }
            self.vault().store.vault_meta.put(
                txn,
                &key,
                &rmp_serde::to_vec_named(&state)
                    .map_err(|_| MemoryError::bad_request("ask band encoding"))?,
            )?;
            Ok(proposed)
        })
    }
}
