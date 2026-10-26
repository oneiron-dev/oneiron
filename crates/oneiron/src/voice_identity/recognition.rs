//! Recognition material bound to its world and its consented purpose (FIX 10215, FIX 10217).
//! Entry: admit_recognition_candidate_in.
//!
//! A print sits in the world its sources sit in, read from where each source
//! record is ([`crate::federation::record_scope::record_world_in`]), never a
//! world its caller names: base reality when every source is, the one
//! private world when one is. Sources in two private worlds, or one whose
//! world cannot be proven (a source a deletion or an erase removed among
//! them), enroll no print.
//!
//! A match reads a print only where this machine may read the print's world
//! under the world's privacy setting (its My-machines or One-machine read),
//! and a print of base reality reads wherever it read before. It reads a
//! print only for a purpose the print was enrolled for, under its consent
//! event still standing for that purpose, and only while its subject stands
//! undeleted. The same checks run again, in the roster's write, on every
//! print the roster places a speaker by, this run's and those carried from
//! an earlier run, so a withdrawal or an erase while the match computed
//! keeps its stale result out.
//!
//! The material itself (centroid, sample vectors) is not sealed under the
//! world's key here: the world-key code exposes no seal and open for a side
//! table's content, so sealing it waits for one (L04).

use heed::RoTxn;

use super::math_keys::invalid_voice;
use super::storage_admission::{read_active_print, read_consent_event, read_consent_events};
use super::types::{
    VoiceAttributionEvidence, VoiceConsentState, VoiceEnrollmentOrigin, VoiceEnrollmentRequest,
    VoicePrintPurpose, VoicePrintRecordV1, VoiceResolvedSegment, VoiceSessionRosterV1,
};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EntityStoreRead, TombstoneStoreRead};

/// The world an enrollment's print sits in: where its sources sit. `None`
/// is base reality. A source ref that never named a stored record carries
/// no world; one whose record a deletion or an erase removed cannot prove
/// its world (FIX 10215).
pub(super) fn resolve_print_world_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    request: &VoiceEnrollmentRequest,
) -> Result<Option<EntityId>> {
    let mut sources: Vec<EntityId> = request
        .contact_ref
        .iter()
        .chain(request.relationship_ref.iter())
        .copied()
        .collect();
    for sample in &request.samples {
        let origin = match &sample.origin {
            VoiceEnrollmentOrigin::AuthenticatedSoloSession { session_ref, .. } => session_ref,
            VoiceEnrollmentOrigin::ConsentedDiarizedSegment { recording_ref, .. } => recording_ref,
        };
        for named in [&sample.source_ref, origin] {
            if let Ok(id) = EntityId::from_hex(named.trim()) {
                sources.push(id);
            }
        }
    }
    sources.sort_unstable();
    sources.dedup();
    let mut world = None;
    for id in sources {
        let Some(raw) = vault.store.port_entity_raw(txn, &id)? else {
            if vault.store.port_deletion_state(txn, &id)?.deleted {
                return Err(invalid_voice("a voice enrollment source's world cannot be proven"));
            }
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        let body = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
        let placed = crate::federation::record_scope::record_world_in(
            &vault.store,
            txn,
            id,
            header.entity_type,
            body,
        )?
        .ok_or_else(|| invalid_voice("a voice enrollment source's world cannot be proven"))?;
        match (world, placed) {
            (_, None) => {}
            (None, Some(placed)) => world = Some(placed),
            (Some(held), Some(placed)) if held == placed => {}
            (Some(_), Some(_)) => {
                return Err(invalid_voice("voice enrollment sources sit in different worlds"));
            }
        }
    }
    Ok(world)
}

/// Whether this machine may read recognition material of `world` now:
/// base reality everywhere, a private world where its read setting
/// admits this machine.
pub(super) fn recognition_readable_here_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    world: Option<EntityId>,
) -> Result<bool> {
    let Some(world) = world else {
        return Ok(true);
    };
    let Some(machine) = crate::identity::read_machine_id_in_txn(vault, txn)? else {
        return Ok(false);
    };
    crate::authority::world_readable_on_machine_in(
        vault,
        txn,
        world,
        crate::authority::Destination::Machine(machine),
    )
}

/// Whether `subject`'s consent event `consent_event_ref` still grants
/// `purpose`: recorded, a grant covering it, and no withdrawal covering it
/// recorded at or after it.
pub(super) fn consent_live_for_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    subject: &EntityId,
    consent_event_ref: &str,
    purpose: &VoicePrintPurpose,
) -> Result<bool> {
    let Some(event) = read_consent_event(&vault.store, txn, subject, consent_event_ref)? else {
        return Ok(false);
    };
    if event.state != VoiceConsentState::Granted || !event.covers(purpose) {
        return Ok(false);
    }
    Ok(!read_consent_events(&vault.store, txn, subject)?
        .into_iter()
        .any(|later| {
            later.state == VoiceConsentState::Withdrawn
                && later.covers(purpose)
                && later.occurred_at >= event.occurred_at
        }))
}

/// Whether `record` may take part in a match serving `purpose` on this
/// machine now: enrolled for that purpose, its consent still standing for
/// it, its subject not deleted, and its world readable here.
pub(super) fn admit_recognition_candidate_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    record: &VoicePrintRecordV1,
    purpose: &VoicePrintPurpose,
) -> Result<bool> {
    if !record.consented_purposes.contains(purpose) {
        return Ok(false);
    }
    let raw = vault.store.port_entity_raw(txn, &record.subject_ref)?;
    if crate::deletion::row_deletion_marked(
        &vault.store,
        txn,
        &record.subject_ref,
        raw.as_deref(),
    )? {
        return Ok(false);
    }
    Ok(consent_live_for_in(
        vault,
        txn,
        &record.subject_ref,
        &record.consent_event_ref,
        purpose,
    )? && recognition_readable_here_in(vault, txn, record.world_ref)?)
}

/// Checks again, in the roster's write, every print `roster` places a
/// speaker by: still the subject's active print at that generation, in the
/// roster's space, and still admitted for `purpose` here. A withdrawal, an
/// erase or a re-enrollment while the match computed fences this run's
/// result, its first `heard` segments; a segment carried from an earlier run
/// whose print no longer holds leaves the roster (FIX 10217).
pub(super) fn recheck_roster_evidence_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    roster: &mut VoiceSessionRosterV1,
    heard: usize,
    purpose: &VoicePrintPurpose,
) -> Result<()> {
    let segments = std::mem::take(&mut roster.segments);
    for (index, segment) in segments.into_iter().enumerate() {
        if evidence_current_in(vault, txn, &roster.embedding_space_id, &segment, purpose)? {
            roster.segments.push(segment);
        } else if index < heard {
            return Err(invalid_voice(
                "a voice print changed or was withdrawn while matching; not kept",
            ));
        }
    }
    Ok(())
}

/// Whether the print `segment` is placed by, if any, still holds: the
/// subject's active print at that generation, in space `space_id`, admitted
/// for `purpose` here.
fn evidence_current_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    space_id: &str,
    segment: &VoiceResolvedSegment,
    purpose: &VoicePrintPurpose,
) -> Result<bool> {
    let VoiceAttributionEvidence::EnrolledPrint {
        subject_ref,
        print_generation,
        ..
    } = &segment.evidence
    else {
        return Ok(true);
    };
    Ok(match read_active_print(&vault.store, txn, subject_ref)? {
        Some(print) => {
            print.print_generation == *print_generation
                && print.space.space_id == space_id
                && admit_recognition_candidate_in(vault, txn, &print, purpose)?
        }
        None => false,
    })
}
