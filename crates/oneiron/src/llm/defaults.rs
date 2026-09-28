//! Vault-local inference defaults. The shipped rows are data, not model bindings.
use super::{CallEnvelope, CallPurpose, ModelId, ModelLocality, ModelTierRef, TierPrecedence};
use crate::{
    Vault,
    error::{Error, Result},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const POLICY_KEY: &[u8] = b"llm:purpose_defaults:v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurposeDefault {
    pub tier: ModelTierRef,
    pub locality: ModelLocality,
}

/// Host-owned admission for a nonlocal extraction request. The table row is
/// only a preference: a host must evaluate the actual request at dispatch.
pub trait ExtractionEgressPredicate: Send + Sync {
    fn permits(&self, request: &super::LlmRequest) -> bool;
}
impl<F: Fn(&super::LlmRequest) -> bool + Send + Sync> ExtractionEgressPredicate for F {
    fn permits(&self, request: &super::LlmRequest) -> bool {
        self(request)
    }
}

/// Speech routing is distinct from the generic `Voice` call purpose: ASR and
/// TTS have separate live and deferred latency and custody requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoiceLane {
    AsrLive,
    AsrBatch,
    TtsLive,
    TtsBatch,
}

/// A host-advertised backend candidate. The selector never relabels a model:
/// its tier and locality travel with its concrete backend identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoiceBackendBinding {
    pub model: ModelId,
    pub tier: ModelTierRef,
    pub locality: ModelLocality,
}

/// Editable voice override precedence. Neither mode permits a holder route
/// wider than the vault row; the owner may disable holder overrides entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoicePrecedence {
    NestedNarrowing,
    VaultOnly,
}

/// True only when the selected route stays inside the owner's extraction pin.
#[must_use]
pub const fn locality_within_extraction_bound(route: ModelLocality, bound: ModelLocality) -> bool {
    locality_rank(route) <= locality_rank(bound)
}

pub(super) const fn locality_rank(locality: ModelLocality) -> u8 {
    match locality {
        ModelLocality::OnDevice => 0,
        ModelLocality::OwnServer => 1,
        ModelLocality::ThirdParty => 2,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurposeDefaultTable {
    pub purposes: BTreeMap<CallPurpose, PurposeDefault>,
    pub voice: BTreeMap<VoiceLane, PurposeDefault>,
    pub voice_precedence: VoicePrecedence,
    /// Owner-authored widest extraction destination. A nonlocal route also
    /// needs a separate host predicate for the actual request before dispatch.
    pub extraction_max_locality: ModelLocality,
}

/// Checked copy of the editable wire rows. Callers cannot index incomplete maps.
#[derive(Debug, Clone)]
pub struct ValidatedPurposeDefaults(PurposeDefaultTable);
impl TryFrom<PurposeDefaultTable> for ValidatedPurposeDefaults {
    type Error = Error;
    fn try_from(table: PurposeDefaultTable) -> Result<Self> {
        table.validate()?;
        Ok(Self(table))
    }
}
impl ValidatedPurposeDefaults {
    pub fn table(&self) -> &PurposeDefaultTable {
        &self.0
    }
}

impl Default for PurposeDefaultTable {
    fn default() -> Self {
        // The initial policy is a checked-in, resident-replaceable data file.
        Self::from_json(include_bytes!("purpose_defaults.json"))
            .expect("shipped purpose defaults must be valid")
    }
}

impl PurposeDefaultTable {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let table: Self =
            serde_json::from_slice(bytes).map_err(|e| Error::InvalidConfig(e.to_string()))?;
        table.validate()?;
        Ok(table)
    }

    pub fn validate(&self) -> Result<()> {
        let builtin = [
            CallPurpose::Extraction,
            CallPurpose::Consolidation,
            CallPurpose::AnswerGen,
            CallPurpose::AutoCheck,
            CallPurpose::ToolRouting,
            CallPurpose::Voice,
            CallPurpose::Eval,
        ];
        let voice = [
            VoiceLane::AsrLive,
            VoiceLane::AsrBatch,
            VoiceLane::TtsLive,
            VoiceLane::TtsBatch,
        ];
        if self.purposes.len() != builtin.len()
            || builtin
                .iter()
                .any(|purpose| !self.purposes.contains_key(purpose))
            || self.voice.len() != voice.len()
            || voice.iter().any(|lane| !self.voice.contains_key(lane))
            || self
                .purposes
                .values()
                .chain(self.voice.values())
                .any(|row| row.tier.as_str().trim().is_empty())
            || locality_rank(self.purposes[&CallPurpose::Extraction].locality)
                > locality_rank(self.extraction_max_locality)
        {
            return Err(Error::InvalidConfig(
                "invalid inference default rows".into(),
            ));
        }
        Ok(())
    }

    pub fn purpose(&self, purpose: &CallPurpose) -> Option<&PurposeDefault> {
        self.purposes.get(purpose)
    }

    pub fn voice(&self, lane: VoiceLane) -> &PurposeDefault {
        &self.voice[&lane]
    }

    /// Choose a concrete speech backend before starting work. Authenticated
    /// per-call/manifest policy, when present, wins over the resident default.
    /// Missing or ambiguous bindings refuse instead of mislabeling a provider.
    pub fn select_voice_backend(
        &self,
        lane: VoiceLane,
        explicit: Option<&PurposeDefault>,
        available: &[VoiceBackendBinding],
    ) -> Result<VoiceBackendBinding> {
        let vault = self.voice(lane);
        let policy = match (self.voice_precedence, explicit) {
            (VoicePrecedence::VaultOnly, _) | (_, None) => vault,
            (VoicePrecedence::NestedNarrowing, Some(override_row)) => {
                if locality_rank(override_row.locality) > locality_rank(vault.locality) {
                    return Err(Error::InvalidConfig(
                        "voice override widens vault route".into(),
                    ));
                }
                override_row
            }
        };
        let mut matching = available
            .iter()
            .filter(|backend| backend.locality == policy.locality && backend.tier == policy.tier);
        let selected = matching
            .next()
            .ok_or_else(|| Error::InvalidConfig("voice route has no matching backend".into()))?;
        if matching.next().is_some() {
            return Err(Error::InvalidConfig("ambiguous voice backend route".into()));
        }
        Ok(selected.clone())
    }

    pub fn precedence(
        &self,
        purpose: &CallPurpose,
        global_default: ModelTierRef,
    ) -> TierPrecedence {
        TierPrecedence {
            per_seat: None,
            vault_policy: None,
            purpose_default: self.purpose(purpose).map(|row| row.tier.clone()),
            global_default,
        }
    }

    pub fn apply(&self, envelope: &mut CallEnvelope) {
        if let Some(policy) = self.purpose(&envelope.purpose) {
            envelope.tier.purpose_default = Some(policy.tier.clone());
        }
    }
}

pub(super) fn read_effective_defaults(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> Result<ValidatedPurposeDefaults> {
    ValidatedPurposeDefaults::try_from(read_stored_defaults(store, txn)?.unwrap_or_default())
}

pub(super) fn read_stored_defaults(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<PurposeDefaultTable>> {
    store
        .vault_meta
        .get(txn, POLICY_KEY)?
        .map(|bytes| PurposeDefaultTable::from_json(&bytes))
        .transpose()
}

impl Vault {
    /// Replace all defaults atomically. An absent row is an invalid policy,
    /// not permission to fall through to an unrelated global tier.
    pub fn set_purpose_default_table(&self, table: &PurposeDefaultTable) -> Result<()> {
        table.validate()?;
        let bytes = serde_json::to_vec(table).map_err(|e| Error::InvalidConfig(e.to_string()))?;
        let mut txn = self.store.env.write_txn()?;
        self.store.vault_meta.put(&mut txn, POLICY_KEY, &bytes)?;
        txn.commit()?;
        Ok(())
    }

    /// The delegated agent door is narrower than the host's owner-authored
    /// setter. Compare and replace inside one write transaction.
    pub(crate) fn set_resident_purpose_default_table(
        &self,
        next: &PurposeDefaultTable,
    ) -> Result<()> {
        next.validate()?;
        let mut txn = self.store.env.write_txn()?;
        let prior = read_effective_defaults(&self.store, &txn)?.table().clone();
        if next.purposes.iter().any(|(key, row)| {
            locality_rank(row.locality) > locality_rank(prior.purposes[key].locality)
        }) || next.voice.iter().any(|(key, row)| {
            locality_rank(row.locality) > locality_rank(prior.voice[key].locality)
        }) || locality_rank(next.extraction_max_locality)
            > locality_rank(prior.extraction_max_locality)
            || (prior.voice_precedence == VoicePrecedence::VaultOnly
                && next.voice_precedence != VoicePrecedence::VaultOnly)
        {
            return Err(Error::InvalidConfig(
                "resident inference locality cannot widen".into(),
            ));
        }
        let bytes = serde_json::to_vec(next).map_err(|e| Error::InvalidConfig(e.to_string()))?;
        self.store.vault_meta.put(&mut txn, POLICY_KEY, &bytes)?;
        txn.commit()?;
        Ok(())
    }

    pub fn purpose_default_table(&self) -> Result<PurposeDefaultTable> {
        let txn = self.store.env.read_txn()?;
        read_effective_defaults(&self.store, &txn).map(|policy| policy.table().clone())
    }

    /// Host speech-route door: read the live vault rows before constructing
    /// ASR/TTS transports. Selection returns a backend identity, not a label.
    pub fn select_voice_backend(
        &self,
        lane: VoiceLane,
        explicit: Option<&PurposeDefault>,
        available: &[VoiceBackendBinding],
    ) -> Result<VoiceBackendBinding> {
        let txn = self.store.env.read_txn()?;
        read_effective_defaults(&self.store, &txn)?
            .table()
            .select_voice_backend(lane, explicit, available)
    }

    pub fn apply_purpose_defaults(&self, envelope: &mut CallEnvelope) -> Result<()> {
        self.purpose_default_table()?.apply(envelope);
        Ok(())
    }
}

impl CallPurpose {
    pub fn default_policy(&self) -> Option<PurposeDefault> {
        PurposeDefaultTable::default().purpose(self).cloned()
    }
}
impl CallEnvelope {
    /// Apply the shipped defaults; a vault with edited rows uses
    /// [`Vault::apply_purpose_defaults`] instead.
    pub fn with_purpose_defaults(mut self) -> Self {
        PurposeDefaultTable::default().apply(&mut self);
        self
    }
}
impl TierPrecedence {
    pub fn for_purpose(purpose: &CallPurpose, global_default: ModelTierRef) -> Self {
        PurposeDefaultTable::default().precedence(purpose, global_default)
    }
}

#[cfg(test)]
#[path = "defaults/tests.rs"]
mod tests;
