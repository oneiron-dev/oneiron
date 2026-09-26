//! Vault-local inference defaults. The shipped rows are data, not model bindings.
use super::{CallEnvelope, CallPurpose, ModelLocality, ModelTierRef, TierPrecedence};
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurposeDefaultTable {
    pub purposes: BTreeMap<CallPurpose, PurposeDefault>,
    pub voice: BTreeMap<VoiceLane, PurposeDefault>,
}

impl Default for PurposeDefaultTable {
    fn default() -> Self {
        // The initial policy is a checked-in, resident-replaceable data file.
        serde_json::from_str(include_str!("purpose_defaults.json"))
            .expect("shipped purpose defaults must be valid JSON")
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
            || self.purposes[&CallPurpose::Extraction].locality != ModelLocality::OnDevice
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

    pub fn precedence(
        &self,
        purpose: &CallPurpose,
        global_default: ModelTierRef,
    ) -> TierPrecedence {
        TierPrecedence {
            per_call: None,
            vault_policy: None,
            purpose_default: self.purpose(purpose).map(|row| row.tier.clone()),
            global_default,
        }
    }

    pub fn apply(&self, envelope: &mut CallEnvelope) {
        if let Some(policy) = self.purpose(&envelope.purpose) {
            envelope.tier.purpose_default = Some(policy.tier.clone());
            envelope.locality = policy.locality;
        }
    }
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

    pub fn purpose_default_table(&self) -> Result<PurposeDefaultTable> {
        let txn = self.store.env.read_txn()?;
        read_stored_defaults(&self.store, &txn).map(Option::unwrap_or_default)
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
mod tests {
    use super::*;
    #[test]
    fn every_builtin_resolves_to_its_policy_without_overriding_the_vault() {
        let table = PurposeDefaultTable::default();
        table.validate().unwrap();
        let expected = [
            (
                CallPurpose::Extraction,
                "extraction",
                ModelLocality::OnDevice,
            ),
            (
                CallPurpose::Consolidation,
                "consolidation",
                ModelLocality::OwnServer,
            ),
            (CallPurpose::AnswerGen, "answer", ModelLocality::OnDevice),
            (CallPurpose::AutoCheck, "cheap", ModelLocality::OwnServer),
            (
                CallPurpose::ToolRouting,
                "tiny-fast",
                ModelLocality::OnDevice,
            ),
            (CallPurpose::Voice, "voice", ModelLocality::OnDevice),
            (CallPurpose::Eval, "eval-pinned", ModelLocality::OnDevice),
        ];
        for (purpose, tier_name, locality) in expected {
            let row = table.purpose(&purpose).unwrap();
            assert_eq!(row.tier.as_str(), tier_name);
            assert_eq!(row.locality, locality);
            let mut tier = table.precedence(&purpose, ModelTierRef("global".into()));
            assert_eq!(tier.resolved(), &row.tier);
            tier.vault_policy = Some(ModelTierRef("vault".into()));
            let mut envelope = CallEnvelope {
                scope: Default::default(),
                purpose,
                class: super::super::CallClass::BestEffort,
                tier,
                response_format: super::super::ResponseFormat::Text,
                locality: ModelLocality::ThirdParty,
            };
            table.apply(&mut envelope);
            assert_eq!(envelope.locality, locality);
            assert_eq!(envelope.tier.resolved().as_str(), "vault");
        }
        assert!(
            table
                .purpose(&CallPurpose::Other {
                    name: "custom".into()
                })
                .is_none()
        );
    }

    #[test]
    fn resident_rows_roundtrip_and_change_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
        let mut table = vault.purpose_default_table().unwrap();
        assert_eq!(
            table.voice(VoiceLane::AsrLive).locality,
            ModelLocality::ThirdParty
        );
        assert_eq!(
            table.voice(VoiceLane::AsrBatch).locality,
            ModelLocality::OwnServer
        );
        assert_eq!(
            table.voice(VoiceLane::TtsLive).locality,
            ModelLocality::OwnServer
        );
        assert_eq!(
            table.voice(VoiceLane::TtsBatch).locality,
            ModelLocality::OwnServer
        );
        table
            .purposes
            .get_mut(&CallPurpose::AnswerGen)
            .unwrap()
            .tier = ModelTierRef("resident-answer".into());
        table.voice.get_mut(&VoiceLane::AsrLive).unwrap().tier =
            ModelTierRef("resident-asr".into());
        vault.set_purpose_default_table(&table).unwrap();
        let loaded = vault.purpose_default_table().unwrap();
        assert_eq!(loaded, table);
        assert_eq!(
            loaded
                .precedence(&CallPurpose::AnswerGen, ModelTierRef("global".into()))
                .resolved()
                .as_str(),
            "resident-answer"
        );
        let mut envelope = CallEnvelope {
            scope: Default::default(),
            purpose: CallPurpose::AnswerGen,
            class: super::super::CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AnswerGen,
                ModelTierRef("global".into()),
            ),
            response_format: super::super::ResponseFormat::Text,
            locality: ModelLocality::ThirdParty,
        };
        vault.apply_purpose_defaults(&mut envelope).unwrap();
        assert_eq!(envelope.tier.resolved().as_str(), "resident-answer");
        let mut request = super::super::LlmRequest {
            model: super::super::ModelId::new("test/model@r1").unwrap(),
            envelope: CallEnvelope {
                tier: TierPrecedence::for_purpose(
                    &CallPurpose::AnswerGen,
                    ModelTierRef("global".into()),
                ),
                ..envelope
            },
            messages: vec![],
            tools: vec![],
            params: Default::default(),
            provider_options: Default::default(),
        };
        vault
            .bind_model_role(
                super::super::manifest::ModelRole::GenerativeReasoner,
                &mut request,
            )
            .unwrap();
        assert_eq!(request.envelope.tier.resolved().as_str(), "resident-answer");
        let mut incomplete = table.clone();
        incomplete.purposes.remove(&CallPurpose::Eval);
        assert!(vault.set_purpose_default_table(&incomplete).is_err());
        assert_eq!(vault.purpose_default_table().unwrap(), table);
        let mut unsafe_extraction = table;
        unsafe_extraction
            .purposes
            .get_mut(&CallPurpose::Extraction)
            .unwrap()
            .locality = ModelLocality::ThirdParty;
        assert!(vault.set_purpose_default_table(&unsafe_extraction).is_err());
    }
}
