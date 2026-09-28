//! Owner-scoped, consume-once ask labels and the policy-owned question-class band.

use super::TaskAskHandle;
use super::ask_record;
use crate::llm::decision::DecisionBand;
use crate::memory::{Memory, MemoryError, MemoryResult, verify_actor_binding};
use crate::side_table::{self, CodecError, Raw, RawValue, SideKey, SideTable};
use crate::skill_optimize::{AskBandLabel, AskBandPolicy};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// One owner/question-class state, plus consumed receipt markers under the same
/// declared prefix. Both key shapes retain their exact stored bytes.
const BAND_STATE: SideTable<BandKey, BandState, Raw> = SideTable::new(&side_table::TASK_ASK_BAND);
const BAND_MARKER: SideTable<MarkerKey, [u8; 1], Raw> = SideTable::new(&side_table::TASK_ASK_BAND);

#[derive(Clone)]
struct BandKey {
    owner: EntityId,
    class: String,
}
impl SideKey for BandKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.owner.as_bytes());
        out.extend_from_slice(&(self.class.len() as u16).to_be_bytes());
        out.extend_from_slice(self.class.as_bytes());
    }
    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let owner = EntityId::from_bytes(bytes.get(..16)?.try_into().ok()?).ok()?;
        let len = usize::from(u16::from_be_bytes(bytes.get(16..18)?.try_into().ok()?));
        let class = bytes.get(18..)?;
        (class.len() == len)
            .then(|| String::from_utf8(class.to_vec()).ok())
            .flatten()
            .map(|class| Self { owner, class })
    }
}
struct MarkerKey {
    band: BandKey,
    word: EntityId,
}
impl SideKey for MarkerKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.band.encode_into(out);
        out.push(b':');
        out.extend_from_slice(self.word.as_bytes());
    }
    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let len = usize::from(u16::from_be_bytes(bytes.get(16..18)?.try_into().ok()?));
        let end = 18usize.checked_add(len)?;
        (bytes.len() == end + 17 && bytes[end] == b':').then_some(Self {
            band: BandKey::decode_key(bytes.get(..end)?)?,
            word: EntityId::from_bytes(bytes.get(end + 1..)?.try_into().ok()?).ok()?,
        })
    }
}
#[derive(Default, Serialize, Deserialize)]
struct BandState {
    band: DecisionBand,
}
impl RawValue for BandState {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        rmp_serde::to_vec_named(self)
            .map_err(|_| CodecError::Value(crate::Error::InvariantViolation("ask band encoding")))
    }
    fn from_raw(raw: &[u8]) -> std::result::Result<Self, CodecError> {
        rmp_serde::from_slice(raw)
            .map_err(|_| CodecError::Value(crate::Error::CorruptedIndex("ask band state")))
    }
}
fn key(owner: EntityId, class: &str) -> MemoryResult<BandKey> {
    if class.is_empty() || class.len() > 256 {
        return Err(MemoryError::bad_request("invalid ask question class"));
    }
    Ok(BandKey {
        owner,
        class: class.to_owned(),
    })
}
fn read(vault: &Vault, txn: &heed::RoTxn<'_>, key: &BandKey) -> MemoryResult<BandState> {
    let Some(state) = BAND_STATE.get(&vault.store, txn, key).map_err(|error| {
        if matches!(
            error.kind(),
            crate::ErrorKind::SideTableRow | crate::ErrorKind::CorruptedIndex
        ) {
            MemoryError::bad_request("invalid ask band state")
        } else {
            MemoryError::from(error)
        }
    })?
    else {
        return Ok(BandState::default());
    };
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
                    let marker = MarkerKey {
                        band: key.clone(),
                        word,
                    };
                    if let Some(changed) = entry.ladder_changed
                        && !BAND_MARKER.contains(&self.vault().store, txn, &marker)?
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
                BAND_MARKER.put(
                    &self.vault().store,
                    txn,
                    &MarkerKey {
                        band: key.clone(),
                        word,
                    },
                    &[1],
                )?;
            }
            BAND_STATE.put(&self.vault().store, txn, &key, &state)?;
            Ok(proposed)
        })
    }
}
