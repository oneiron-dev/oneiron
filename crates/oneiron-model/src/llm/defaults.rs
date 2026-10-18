//! Inference defaults as data: the shipped purpose-default table, its validation and the
//! routing rules it implies. The shipped rows are data, not model bindings. `oneiron` stores
//! a vault's edited table and re-exports everything here at `oneiron::llm`.
use super::{CallEnvelope, CallPurpose, ModelId, ModelLocality, ModelTierRef, TierPrecedence};
use oneiron_contracts::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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

/// Exposure rank of a locality: on-device 0, own server 1, third party 2. Public so
/// `oneiron`'s inference admission and voice routing rank routes the same way.
pub const fn locality_rank(locality: ModelLocality) -> u8 {
    match locality {
        ModelLocality::OnDevice => 0,
        ModelLocality::OwnServer => 1,
        ModelLocality::ThirdParty => 2,
    }
}

/// What an agent's own compaction reads (FIX 4465): its retained turns on
/// the cheap compaction route wearing its home, or a fork of its live
/// context. The row picks the model and context per wake; WHO writes is the
/// agent's `memory_profile.compaction_backend`, never this row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfCompactionSource {
    RetainedTurns,
    LiveFork,
}

impl SelfCompactionSource {
    /// The stable name a receipt and a report carry.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RetainedTurns => "retained_turns",
            Self::LiveFork => "live_fork",
        }
    }
}

/// The self-compaction row: the context a self-written compaction reads, the
/// tier it prefers and the widest destination its call may be served at.
/// A delegated edit may not widen `locality`, as with every other row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfCompactionDefault {
    pub source: SelfCompactionSource,
    pub tier: ModelTierRef,
    pub locality: ModelLocality,
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
    /// How an agent that writes its own compaction is served each wake.
    pub self_compaction: SelfCompactionDefault,
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
            || self.self_compaction.tier.as_str().trim().is_empty()
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

    /// The row a self-written compaction is served by, read once per flight.
    pub fn self_compaction(&self) -> &SelfCompactionDefault {
        &self.self_compaction
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
            seat: None,
        }
    }

    pub fn apply(&self, envelope: &mut CallEnvelope) {
        if let Some(policy) = self.purpose(&envelope.purpose) {
            envelope.tier.purpose_default = Some(policy.tier.clone());
        }
    }
}

impl CallPurpose {
    pub fn default_policy(&self) -> Option<PurposeDefault> {
        PurposeDefaultTable::default().purpose(self).cloned()
    }
}
impl CallEnvelope {
    /// Apply the shipped defaults; a vault with edited rows uses
    /// `oneiron::Vault::apply_purpose_defaults` instead.
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
