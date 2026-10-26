//! A hosted submission's withdrawal at the intake (FIX 9855): one helper
//! for a person's erase, a source's withdrawal, an older offer's
//! supersession and a publication marked after its withdrawal.
//!
//! A hosted offer leaves the vault outside any writer: its release is read,
//! its files are published, and only then is the publication marked. So a
//! held row may already sit at the intake when it is withdrawn. Every
//! withdrawal of a hosted row that is held, or was ever published, records
//! an id-only forget control naming it in the withdrawal's own write, and
//! links the row to that control, so a publication marked late finds it
//! forgotten already. A row held with its source code (`source_code`, made
//! in the writer that held it, the code its sealed offer carries) is
//! forgotten by that code and needs no key (`ForgetHosted`), so it is sent
//! even once its generation is orphaned; a row held before the code was
//! kept is forgotten by its raw source under its generation's key, or
//! counted unavailable once that key is gone (FIX 5892).
//!
//! A forget recorded here is local intent: the intake's signed `removed`
//! receipt on its control is the one proof the piece left the intake.

use std::collections::BTreeMap;

use oneiron_vault_contract::conversation_training::TrainingReceiptStatusV2;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{DeletionMarker, TombstoneStoreRead};

use super::anonymous::TrainingTransport;
use super::custody::{self, ControlChange, SubmissionCustody, SubmissionState};
use super::lifecycle::TrainingSubmissionId;
use super::source::TrainingSelection;

/// How one forget names its source: by the code kept on its rows, or by
/// the raw id, coded when the control is signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SourceName {
    Code([u8; 32]),
    Raw(EntityId),
}

/// Whether a hosted submission may be at the intake now: held, so its
/// publication may be under way, or published once, and not removed there
/// yet.
pub(super) fn may_reach_intake(row: &SubmissionCustody) -> bool {
    let removed = row
        .receipt
        .is_some_and(|mark| mark.status == TrainingReceiptStatusV2::Removed);
    row.transport == TrainingTransport::Hosted
        && !removed
        && (row.published_at.is_some() || row.state == SubmissionState::Held)
}

/// Records the id-only forget controls the hosted rows `owed` need, in the
/// caller's write: one per month, generation and source, under that pair's
/// scope, each naming exactly its rows. Each row is linked to its control
/// and written; a row already linked joins none and is written as it is.
/// Returns how many controls it recorded: one that needs an orphaned
/// generation's key records nothing and is counted unavailable
/// ([`custody::record_control_in`]).
pub(super) fn forget_hosted_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    mut owed: Vec<(TrainingSubmissionId, SubmissionCustody)>,
    now: u64,
) -> Result<usize> {
    let mut groups: BTreeMap<(String, u32, SourceName), Vec<usize>> = BTreeMap::new();
    for (at, (_, row)) in owed.iter().enumerate() {
        if row.forget.is_some() || row.transport != TrainingTransport::Hosted {
            continue;
        }
        let name = match row.source_code {
            Some(code) => SourceName::Code(code),
            None => SourceName::Raw(row.source),
        };
        groups
            .entry((row.month.clone(), row.generation, name))
            .or_default()
            .push(at);
    }
    let mut recorded = 0;
    for ((month, generation, name), members) in groups {
        let submissions: Vec<[u8; 16]> = members
            .iter()
            .filter_map(|at| owed.get(*at))
            .map(|(id, _)| id.0)
            .collect();
        let change = match name {
            SourceName::Code(source_code) => ControlChange::ForgetHosted {
                source_code,
                submissions,
            },
            SourceName::Raw(source) => ControlChange::ForgetSource {
                source,
                submissions,
            },
        };
        let Some(control) =
            custody::record_control_in(vault, txn, (&month, generation), change, now)?
        else {
            continue;
        };
        recorded += 1;
        for at in members {
            if let Some((_, row)) = owed.get_mut(at) {
                row.forget = Some(control.0);
            }
        }
    }
    for (id, row) in &owed {
        custody::put_submission_in(vault, txn, *id, row)?;
    }
    Ok(recorded)
}

/// Whether `selection` was overtaken, as `txn` reads it now: its room or a
/// message it selected deleted, archived or stale, or a person whose words
/// it carries deleted or erased. The writer that would hold it holds
/// nothing then, so a selection read before an erase never brings the
/// erased person's id back into custody.
pub(super) fn selection_overtaken_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    selection: &TrainingSelection,
) -> Result<bool> {
    for id in std::iter::once(selection.source).chain(selection.message_ids()) {
        let marker = vault.store.port_deletion_state(txn, &id)?;
        if marker.deleted || marker.archived || marker.stale {
            return Ok(true);
        }
    }
    for person in &selection.persons {
        if vault.store.port_deletion_state(txn, person)?.deleted
            || vault
                .store
                .port_deletion_marked(txn, DeletionMarker::HardDelete, person)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}
