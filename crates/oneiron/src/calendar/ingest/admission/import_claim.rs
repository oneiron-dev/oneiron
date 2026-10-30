//! Imported-claim admission through the Gate-backed imported-evidence door,
//! and the adapter's own write actor.

use crate::calendar::safeguard::CalendarScreenVerdict;
use crate::entity_id::EntityId;
use crate::entity_id::derived_domains::CALENDAR_ICS_IMPORT_ACTOR;
use crate::ingest::{
    ICS_FEED_SOURCE_ID, ImportedEvidenceAdmission, ImportedEvidenceEntityResolution,
    ImportedEvidenceScreen,
};
use crate::registry::ENTITY_TYPE_MACHINE;
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

/// The evidence entry of a screen that ran; `None` when the dial was off.
pub(super) fn imported_screen(verdict: &CalendarScreenVerdict) -> Option<ImportedEvidenceScreen> {
    let reason_codes = match verdict {
        CalendarScreenVerdict::Skipped => return None,
        CalendarScreenVerdict::Clear => Vec::new(),
        CalendarScreenVerdict::Flagged { reason_codes } => reason_codes.clone(),
        CalendarScreenVerdict::Indeterminate { reason_code } => vec![reason_code.clone()],
    };
    Some(ImportedEvidenceScreen {
        verdict: super::verdict_token(verdict).to_owned(),
        reason_codes,
    })
}

/// Admits one typed-value claim through the Gate-backed imported-evidence
/// door and returns the new claim id. The write actor is the adapter's own
/// MACHINE entity, ensured on first use.
pub(in crate::calendar) fn admit_calendar_import_claim(
    vault: &Vault,
    event_ref: &EntityId,
    predicate: &str,
    value: rmpv::Value,
    source_record_id: &str,
    recorded_at: u64,
) -> crate::Result<EntityId> {
    admit_calendar_import_claim_screened(
        vault,
        event_ref,
        predicate,
        value,
        source_record_id,
        recorded_at,
        None,
    )
}

/// [`admit_calendar_import_claim`] with the screen the admission ran under,
/// kept on the claim's evidence.
pub(super) fn admit_calendar_import_claim_screened(
    vault: &Vault,
    event_ref: &EntityId,
    predicate: &str,
    value: rmpv::Value,
    source_record_id: &str,
    recorded_at: u64,
    screen: Option<ImportedEvidenceScreen>,
) -> crate::Result<EntityId> {
    let actor = ensure_ics_import_actor(vault, recorded_at)?;
    let claim_id = vault.store.clock.entity_id()?;
    let mut admission = ImportedEvidenceAdmission::proposed(
        ICS_FEED_SOURCE_ID,
        claim_id,
        ImportedEvidenceEntityResolution::subject(*event_ref),
        WriteActor::new(actor, crate::edge::EdgeActorClass::System),
        TimeRange {
            start: recorded_at,
            end: recorded_at,
        },
        recorded_at,
    );
    if let Some(screen) = screen {
        admission = admission.with_screen(screen);
    }
    crate::ingest::admit_imported_evidence_claim_typed_for_machine(
        vault,
        predicate,
        value,
        source_record_id,
        &admission,
    )?;
    Ok(claim_id)
}

/// The adapter's write actor: one deterministic MACHINE entity, minted on
/// first use. Imported claims attribute to it as `EdgeActorClass::System`.
pub fn ics_import_actor_id() -> crate::Result<EntityId> {
    EntityId::derive(CALENDAR_ICS_IMPORT_ACTOR, &[])
}

pub(crate) fn ensure_ics_import_actor(vault: &Vault, now: u64) -> crate::Result<EntityId> {
    let id = ics_import_actor_id()?;
    if vault.get_entity_type(&id)? != Some(ENTITY_TYPE_MACHINE) {
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &rmpv::Value::Map(vec![(
                rmpv::Value::from("name"),
                rmpv::Value::from("calendar ICS feed importer"),
            )]),
        )
        .map_err(|_| crate::Error::InvariantViolation("actor body did not encode"))?;
        vault.put_entity(
            &id,
            ENTITY_TYPE_MACHINE,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &body,
        )?;
    }
    Ok(id)
}
