//! Owner restore of archived voice identity rows (SIDE-4b G8/G9).
//!
//! Consent events land only for a live person subject whose key agrees with the event; render
//! decisions land only for their own voice id with a sound version, sequence and kind, and a
//! person subject that is a live person. A withdrawn row installs as a row: the landing never
//! mirrors a withdrawal's deletes, rebuilds no render history, and evicts no targets.

use super::math_keys::digest16;
use super::ref_bank::{VoiceRefSubjectKind, VoiceRenderConsent};
use super::storage_admission::CONSENT;
use crate::Vault;
use crate::batch::export::archive_side_install::{
    ArchivedSideRowOutcome, decode_archived_row, install_archived_row,
};
use crate::batch::export::{
    ArchiveRetainedSideRow, OwnerArchiveRestorePermit, RetainedSideHeldBackReason,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// A voice's current render decision, by voice id: the same declaration the bank writes.
const RENDER_CONSENT: SideTable<String, VoiceRenderConsent, Named> =
    SideTable::new(&side_table::VOICE_REF_RENDER_CONSENT);

/// The bank's per-owner index, written as raw stored-key bytes. The writer's `BankRow::to_raw`
/// stores exactly the indexed row's full stored key, and `Raw` keeps a `Vec<u8>` verbatim, so
/// this handle rebuilds byte-identical index rows for an installed decision.
const OWNER_INDEX: SideTable<(EntityId, Vec<u8>), Vec<u8>, Raw> =
    SideTable::new(&side_table::VOICE_OWNER_REF_OWNER_INDEX);

/// Lands archived voice consent and render consent rows in input order, one outcome per row.
pub(crate) fn land_archived_voice_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    rows: &[ArchiveRetainedSideRow],
) -> Result<Vec<ArchivedSideRowOutcome>> {
    let mut outcomes = Vec::with_capacity(rows.len());
    for row in rows {
        let outcome = match row.source_table.as_str() {
            name if name == side_table::VOICE_IDENTITY_CONSENT.name => {
                land_archived_voice_consent_row_in_txn(vault, txn, permit, row)?
            }
            name if name == side_table::VOICE_REF_RENDER_CONSENT.name => {
                land_archived_voice_render_row_in_txn(vault, txn, permit, row)?
            }
            // The dispatcher never sends a foreign envelope here; without an owning table the
            // envelope has no decoding.
            _ => ArchivedSideRowOutcome::HeldBack(RetainedSideHeldBackReason::InvalidEncoding),
        };
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

/// Lands one archived consent event for a live person subject.
///
/// The key must name the event's subject and its event digest; anything else is a value the
/// writer could never have stored. `recorded_by` is audit-only and installs as archived. A
/// withdrawn event installs as a row and deletes nothing: the prints, samples and bank rows a
/// live withdrawal removes travel in no disposition.
fn land_archived_voice_consent_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    row: &ArchiveRetainedSideRow,
) -> Result<ArchivedSideRowOutcome> {
    let (key, event) = match decode_archived_row(&CONSENT, row) {
        Ok(decoded) => decoded,
        Err(reason) => return Ok(ArchivedSideRowOutcome::HeldBack(reason)),
    };
    let event_digest = digest16(b"voice_identity.consent", event.event_id.as_bytes());
    if key.0 != event.subject_ref || key.1 != event_digest {
        return Ok(ArchivedSideRowOutcome::HeldBack(
            RetainedSideHeldBackReason::InvalidValue,
        ));
    }
    match live_entity_row_in_txn(&vault.store, txn, &event.subject_ref)? {
        LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_PERSON => {}
        LiveEntityRow::Live { .. } => {
            return Ok(ArchivedSideRowOutcome::HeldBack(
                RetainedSideHeldBackReason::WrongEntityKind,
            ));
        }
        LiveEntityRow::Absent | LiveEntityRow::DeletedShell => {
            return Ok(ArchivedSideRowOutcome::HeldBack(
                RetainedSideHeldBackReason::MissingLiveEntity,
            ));
        }
    }
    install_archived_row(&CONSENT, vault, txn, permit, &key, row)
}

/// Lands one archived render decision for its own voice id.
///
/// The key must be the decision's voice id; the decision keeps version 1, a non-zero sequence,
/// and must pass the writer's own decision validator (ids, time, kind/basis). Only a person's
/// voice needs its subject live and a person: a designed voice belongs to its creator of any
/// kind, present or not. `recorded_by` is audit-only, and a missing bank identity is fine: the
/// writer records decisions before the identity is banked. An installed decision is indexed
/// under its subject exactly as the writer indexes it, so erasure finds it; no render history
/// is rebuilt and no target is evicted.
fn land_archived_voice_render_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    row: &ArchiveRetainedSideRow,
) -> Result<ArchivedSideRowOutcome> {
    let (key, consent) = match decode_archived_row(&RENDER_CONSENT, row) {
        Ok(decoded) => decoded,
        Err(reason) => return Ok(ArchivedSideRowOutcome::HeldBack(reason)),
    };
    if key != consent.decision.voice_id {
        return Ok(ArchivedSideRowOutcome::HeldBack(
            RetainedSideHeldBackReason::InvalidEncoding,
        ));
    }
    if consent.version != 1
        || consent.sequence == 0
        || crate::verbs::voice_records::voice_render_decision_validate(&consent.decision).is_err()
    {
        return Ok(ArchivedSideRowOutcome::HeldBack(
            RetainedSideHeldBackReason::InvalidValue,
        ));
    }
    // Person-kind subjects only: a designed voice belongs to its creator of any kind, present
    // or not.
    if consent.decision.subject_kind == VoiceRefSubjectKind::Person {
        match live_entity_row_in_txn(&vault.store, txn, &consent.decision.subject)? {
            LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_PERSON => {}
            LiveEntityRow::Live { .. } => {
                return Ok(ArchivedSideRowOutcome::HeldBack(
                    RetainedSideHeldBackReason::WrongEntityKind,
                ));
            }
            LiveEntityRow::Absent | LiveEntityRow::DeletedShell => {
                return Ok(ArchivedSideRowOutcome::HeldBack(
                    RetainedSideHeldBackReason::MissingLiveEntity,
                ));
            }
        }
    }
    let outcome = install_archived_row(&RENDER_CONSENT, vault, txn, permit, &key, row)?;
    if matches!(outcome, ArchivedSideRowOutcome::Installed) {
        let full_key = RENDER_CONSENT.key_bytes(&key);
        OWNER_INDEX.put(
            &vault.store,
            txn,
            &(consent.decision.subject, full_key.clone()),
            &full_key,
        )?;
    }
    Ok(outcome)
}
