//! Vault-scoped lens intent records and the upgrade regeneration door.

use super::{
    LensEvaluatedRevision, LensLoadAction, LensRegenDecision, LensRegenFailure,
    LensRegenFailurePhase, LensRegenOutcome, LensRegenRequest, LensRegenerator, LensVersionStamp,
    lens_load_action, regenerate_lens,
};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};
use serde::{Deserialize, Serialize};

/// The authored prompt is separate from generated lens revisions: each lens's
/// index of the `lens/intent` NOTE that holds it (FIX 9896). Key: id16.
pub(super) const INTENTS: SideTable<EntityId, LensIntentIndex, Named> =
    SideTable::new(&side_table::LENS_INTENT);
/// Bound prompt storage before allocation or dispatch into a model runner.
pub const LENS_INTENT_MAX_BYTES: usize = 16_384;

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

/// A lens's stored intent: the ref of the `lens/intent` NOTE holding its
/// authored prompt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LensIntentIndex {
    prompt_ref: String,
}

impl LensIntentIndex {
    pub(super) fn of(prompt_ref: &EntityId) -> Self {
        Self {
            prompt_ref: prompt_ref.to_hex(),
        }
    }
}

impl Vault {
    /// Read the intent through its index; corrupt or missing source never
    /// becomes an empty prompt. `None` when no intent was stored for the
    /// lens, or its prompt NOTE is gone.
    pub fn get_lens_intent(&self, lens_id: &EntityId) -> Result<Option<LensIntentRecord>> {
        let txn = self.store.env.read_txn()?;
        self.lens_intent_in_txn(&txn, lens_id)
    }

    /// [`Self::get_lens_intent`] in the caller's `txn`, decoded as strictly.
    /// The caller admits `lens_id` first.
    pub(crate) fn lens_intent_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        lens_id: &EntityId,
    ) -> Result<Option<LensIntentRecord>> {
        let corrupt = || Error::CorruptedIndex("lens intent record");
        let index = INTENTS.get(&self.store, txn, lens_id).map_err(|error| {
            if error.kind() == crate::error::ErrorKind::SideTableRow {
                corrupt()
            } else {
                error
            }
        })?;
        let Some(index) = index else {
            return Ok(None);
        };
        let prompt_ref = EntityId::from_hex(&index.prompt_ref).map_err(|_| corrupt())?;
        let Some(prompt) = super::artifact::lens_prompt_in(self, txn, &prompt_ref)? else {
            return Ok(None);
        };
        LensIntentRecord::new(prompt).map(Some).map_err(|_| corrupt())
    }

    /// On a shell/contract version mismatch, re-run the vault's intent through
    /// the existing fingerprint gate. `None` means the current body needs no work;
    /// all failures carry the unchanged last-good revision for mounting. The
    /// decision names `lens_id`, the selection it was made against (FIX 9897).
    pub fn regenerate_lens_on_upgrade<R: LensRegenerator + ?Sized>(
        &self,
        lens_id: &EntityId,
        regenerator: &R,
        last_good: LensEvaluatedRevision,
    ) -> Option<LensRegenDecision> {
        if matches!(
            lens_load_action(
                last_good.lens().version_stamp(),
                LensVersionStamp::current()
            ),
            LensLoadAction::MountCurrent
        ) {
            return None;
        }
        let outcome = match self.get_lens_intent(lens_id) {
            Ok(Some(intent)) => regenerate_lens(
                regenerator,
                &LensRegenRequest::new(LensVersionStamp::current(), intent.prompt()),
                last_good,
            ),
            Ok(None) => rollback(last_good, "lens intent record is missing"),
            Err(_) => rollback(last_good, "lens intent record cannot be read"),
        };
        Some(LensRegenDecision {
            active_ref: *lens_id,
            outcome,
        })
    }
}

fn rollback(last_good: LensEvaluatedRevision, message: &str) -> LensRegenOutcome {
    LensRegenOutcome::RolledBack {
        last_good,
        failure: LensRegenFailure::new(LensRegenFailurePhase::SummaryPromptRerun, message),
    }
}
