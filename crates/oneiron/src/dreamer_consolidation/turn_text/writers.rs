//! Whom the extraction transcript labels beside a person TURN's role:
//! an imported turn's source speaker (FIX 15412) or a native person turn's
//! writers (FIX DREAMER-NATIVE-PERSON-TURN-UNATTRIBUTED; ARCH-0043:37).
//! In a shared vault this includes every native person turn; in a personal
//! vault it includes only those its owner did not write alone, judged over
//! every writer, standing or not. A label names only a PERSON that still
//! stands: a deleted, erased or withdrawn one is left out, while its
//! MESSAGE's words stay on the line.

use super::TurnText;
use crate::dreamer_consolidation::call_labels::{CallLabelMap, LabelKind};
use crate::dreamer_runner::{DreamerTurnRole, dreamer_turn_role};
use crate::{EntityId, Result, Vault};

impl TurnText {
    /// The writers of the projected MESSAGEs, distinct, in layout order;
    /// none for inline text. Read only for a TURN with no import stamp. An
    /// imported row's edge names its source speaker instead.
    pub(crate) fn native_writers(&self) -> Vec<EntityId> {
        let mut writers = Vec::new();
        let Some(pins) = &self.messages else {
            return writers;
        };
        for (id, _, _) in &self.layout {
            if let Some(pin) = pins.iter().find(|pin| pin.id == *id) {
                for &author in &pin.authors {
                    if !writers.contains(&author) {
                        writers.push(author);
                    }
                }
            }
        }
        writers
    }
}

/// The labelling rule of one extraction call, read once per call.
pub(crate) struct TurnSpeakers {
    /// Whether the vault is shared: its shared-vault creation row exists
    /// (the row the owner census keys on), whatever preset it runs under.
    shared: bool,
}

impl TurnSpeakers {
    /// Reads the rule in `txn`.
    pub(crate) fn read_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Self> {
        Ok(Self {
            shared: vault.shared_vault_creation_in_txn(txn)?.is_some(),
        })
    }

    /// The PERSONs one TURN's line names beside its role: an imported
    /// turn's source speaker; otherwise, for a native user turn, its
    /// writers, unless the vault is personal and its live owner is the
    /// turn's one writer. An agent's, a counterparty's or a system turn
    /// names none. Each is a PERSON that still stands ([`standing`]). The
    /// owner's exception reads every writer before that filter, so a turn
    /// the owner wrote with a since-deleted PERSON keeps the owner's label
    /// and never reads as the owner's alone (REVIEW-10620 round 2).
    pub(crate) fn people_in(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        speaker: Option<&str>,
        imported: bool,
        text: Option<&TurnText>,
    ) -> Result<Vec<EntityId>> {
        let Some(text) = text else {
            return Ok(Vec::new());
        };
        if let Some(person) = text.source_speaker() {
            return Ok(standing(vault, txn, vec![person]));
        }
        if imported {
            return Ok(Vec::new());
        }
        if !matches!(
            dreamer_turn_role(speaker, &vault.config.assistant_display_names),
            DreamerTurnRole::User
        ) {
            return Ok(Vec::new());
        }
        let writers = text.native_writers();
        if !self.shared
            && let [writer] = writers.as_slice()
            && crate::policy_model::is_live_vault_owner_in_txn(vault, txn, writer)?
        {
            return Ok(Vec::new());
        }
        Ok(standing(vault, txn, writers))
    }
}

/// `people` less each one deleted, erased or withdrawn in `txn`, judged as
/// the model run's source fence judges a source row: a label lists its
/// PERSON among the call's source rows, and the fence refuses the whole
/// call while one of them does not stand, though the turn's words still do
/// (REVIEW-10620 round 1).
fn standing(vault: &Vault, txn: &heed::RoTxn<'_>, mut people: Vec<EntityId>) -> Vec<EntityId> {
    people.retain(|person| !crate::code_run::source_row_withdrawn_in(vault, txn, person));
    people
}

/// The call labels of `people`, each after a space, in order: an already
/// listed PERSON keeps its label, a new one takes the next.
pub(crate) fn speaker_labels(labels: &mut CallLabelMap, people: &[EntityId]) -> String {
    people
        .iter()
        .map(|person| format!(" {}", labels.assign(LabelKind::Entity, *person)))
        .collect()
}
