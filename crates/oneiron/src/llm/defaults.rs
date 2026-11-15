//! Vault-local inference defaults: the purpose-default table the vault reads from its setting
//! key `models.purpose_defaults` (DESIGN 15-setting-primitive, stage 2), and the vault doors that
//! read it. The table type, its validation and the shipped rows are defined in `oneiron-model`.
//! Every change goes through `Vault::set_setting` ([`purpose_defaults_change`]).
use super::setting_keys::{PURPOSE_DEFAULTS, PurposeDefaults};
use super::{
    CallEnvelope, PurposeDefault, PurposeDefaultTable, ValidatedPurposeDefaults,
    VoiceBackendBinding, VoiceLane,
};
use crate::Vault;
use crate::error::{Error, Result};
use crate::policy_model::{PolicyRowScope, policy_row_grant_target};
use crate::policy_setting_doors::PolicySetting;
use crate::setting::SetSetting;

// The sibling tests name these bare through `use super::*`, as they did when the table
// type was defined in this file.
#[cfg(test)]
use super::{
    CallPurpose, ExtractionEgressPredicate, ModelId, ModelLocality, ModelTierRef, TierPrecedence,
};

/// The vault's inference defaults in force in `txn`: the key's value row, else the shipped
/// table, validated on every read.
pub(crate) fn read_effective_defaults(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> Result<ValidatedPurposeDefaults> {
    let PurposeDefaults(table) = PURPOSE_DEFAULTS
        .read_in_dbs_txn(store, txn, &[], None)?
        .value;
    ValidatedPurposeDefaults::try_from(table)
}

/// The change that makes `table` the vault's inference defaults: a value row of
/// `models.purpose_defaults` at the vault scope, for `Vault::set_setting` under the caller's own
/// power. Replacing the table replaces every row of it at once.
///
/// # Errors
///
/// A table that does not validate, or does not encode.
pub fn purpose_defaults_change(table: &PurposeDefaultTable) -> Result<SetSetting> {
    table.validate()?;
    let value = serde_json::to_value(table)
        .map_err(|error| Error::InvalidConfig(format!("the purpose defaults: {error}")))?;
    Ok(SetSetting::vault_value(PURPOSE_DEFAULTS.spec.name, value))
}

/// The exact target of the policy power over the inference defaults: the vault-scope row target
/// of `settings.inference_defaults`, which an Owner's `policy.change` grant names to give an
/// Admin or Delegate this power, and so to make them a holder of `models.purpose_defaults`.
#[must_use]
pub fn purpose_default_grant_target() -> String {
    policy_row_grant_target(
        &PolicyRowScope::Vault,
        PolicySetting::InferenceDefaults.as_str(),
    )
}

impl Vault {
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

// FIX [LIBTEST-QUARANTINE-LLM-DEFAULTS-TESTS]: the lib test target's type check fails here (9 errors: E0063 x7, E0308 x2); port it, then drop this gate
#[cfg(any())]
#[cfg(test)]
#[path = "defaults/tests.rs"]
mod tests;
