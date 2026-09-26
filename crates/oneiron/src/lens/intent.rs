//! Vault-scoped lens intent records and the upgrade regeneration door.

use super::{
    LensEvaluatedRevision, LensLoadAction, LensRegenFailure, LensRegenFailurePhase,
    LensRegenOutcome, LensRegenRequest, LensRegenerator, LensVersionStamp, lens_load_action,
    regenerate_lens,
};
use crate::{EntityId, Error, Result, Vault};
use serde::{Deserialize, Serialize};

const KEY_PREFIX: &[u8] = b"lens/intent/v1\0";
/// Bound prompt storage before allocation or dispatch into a model runner.
pub const LENS_INTENT_MAX_BYTES: usize = 16_384;

fn key(id: &EntityId) -> Vec<u8> {
    let mut key = KEY_PREFIX.to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}

/// Per-lens authored source, independent of generated atom trees and shell stamps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LensIntentRecord {
    prompt: String,
}

impl LensIntentRecord {
    pub fn new(prompt: impl Into<String>) -> Result<Self> {
        let record = Self {
            prompt: prompt.into(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn prompt(&self) -> &str {
        &self.prompt
    }

    fn validate(&self) -> Result<()> {
        if self.prompt.trim().is_empty() || self.prompt.len() > LENS_INTENT_MAX_BYTES {
            return Err(Error::InvalidConfig(
                "lens intent prompt must be nonempty and bounded".into(),
            ));
        }
        Ok(())
    }
}

impl Vault {
    /// Store the source intent under the lens identity, not the generated body.
    /// Replacing one lens's intent never changes another's record.
    pub fn put_lens_intent(&self, lens_id: &EntityId, intent: &LensIntentRecord) -> Result<()> {
        intent.validate()?;
        let bytes = rmp_serde::to_vec_named(intent)
            .map_err(|_| Error::InvalidConfig("lens intent encoding failed".into()))?;
        self.with_write_txn(|txn| {
            self.store.vault_meta.put(txn, &key(lens_id), &bytes)?;
            Ok(())
        })
    }

    /// Decode the stored intent strictly; corrupt or missing source never becomes an empty prompt.
    pub fn get_lens_intent(&self, lens_id: &EntityId) -> Result<Option<LensIntentRecord>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &key(lens_id))?
            .map(|bytes| {
                let intent: LensIntentRecord = rmp_serde::from_slice(&bytes)
                    .map_err(|_| Error::CorruptedIndex("lens intent record"))?;
                intent
                    .validate()
                    .map_err(|_| Error::CorruptedIndex("lens intent record"))?;
                Ok(intent)
            })
            .transpose()
    }

    /// On a shell/contract version mismatch, re-run the vault's intent through
    /// the existing fingerprint gate. `None` means the current body needs no work;
    /// all failures carry the unchanged last-good revision for mounting.
    pub fn regenerate_lens_on_upgrade<R: LensRegenerator + ?Sized>(
        &self,
        lens_id: &EntityId,
        regenerator: &R,
        last_good: LensEvaluatedRevision,
    ) -> Option<LensRegenOutcome> {
        if matches!(
            lens_load_action(
                last_good.lens().version_stamp(),
                LensVersionStamp::current()
            ),
            LensLoadAction::MountCurrent
        ) {
            return None;
        }
        let intent = match self.get_lens_intent(lens_id) {
            Ok(Some(intent)) => intent,
            Ok(None) => return Some(rollback(last_good, "lens intent record is missing")),
            Err(_) => return Some(rollback(last_good, "lens intent record cannot be read")),
        };
        Some(regenerate_lens(
            regenerator,
            &LensRegenRequest::new(LensVersionStamp::current(), intent.prompt()),
            last_good,
        ))
    }
}

fn rollback(last_good: LensEvaluatedRevision, message: &str) -> LensRegenOutcome {
    LensRegenOutcome::RolledBack {
        last_good,
        failure: LensRegenFailure::new(LensRegenFailurePhase::SummaryPromptRerun, message),
    }
}
