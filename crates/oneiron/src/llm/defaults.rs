//! Vault-local inference defaults: the stored, owner-editable purpose-default table and the
//! vault doors that read and replace it. The table type, its validation and the shipped rows
//! are defined in `oneiron-model`.
use super::{
    CallEnvelope, PurposeDefault, PurposeDefaultTable, ValidatedPurposeDefaults,
    VoiceBackendBinding, VoiceLane, VoicePrecedence,
};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{
    Vault,
    error::{Error, Result},
};
use oneiron_model::llm::locality_rank;

// The sibling tests name these bare through `use super::*`, as they did when the table
// type was defined in this file.
#[cfg(test)]
use super::{
    CallPurpose, ExtractionEgressPredicate, ModelId, ModelLocality, ModelTierRef, TierPrecedence,
};

/// The vault's stored purpose-default table, validated on every read. Key: ().
const POLICY: SideTable<(), PurposeDefaultTable, LegacyJson> =
    SideTable::new(&side_table::LLM_PURPOSE_DEFAULTS);

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
    let Some(table) = POLICY.get(store, txn, &())? else {
        return Ok(None);
    };
    table.validate()?;
    Ok(Some(table))
}

impl Vault {
    /// Replace all defaults atomically. An absent row is an invalid policy,
    /// not permission to fall through to an unrelated global tier.
    pub fn set_purpose_default_table(&self, table: &PurposeDefaultTable) -> Result<()> {
        table.validate()?;
        let mut txn = self.store.env.write_txn()?;
        POLICY.put(&self.store, &mut txn, &(), table)?;
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
        POLICY.put(&self.store, &mut txn, &(), next)?;
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

#[cfg(test)]
#[path = "defaults/tests.rs"]
mod tests;
