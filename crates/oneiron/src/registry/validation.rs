//! Static validation of entity type bytes, including public-write gates.

use super::registry_table::entity_type_registry_entry;
use super::zones::{EntityClassification, TypeByteZone, zone_of};

/// Zone-aware static entity-type validation. ONE rule, two entry points — the
/// crate's [`validate_entity_type`] is a thin delegate that passes
/// `cfg!(debug_assertions)`, so production and development can never drift.
///
/// Registration-sensitivity is confined to the engine zones 0–125: a byte
/// there passes only if a static kind claims it (dynamic vault registrations
/// are layered on top by `Store::validate_entity_type`). Everything above is
/// decided by the zone alone, so no registry row — static or persisted — can
/// widen it:
///
/// * `128–247` (PackHandle) ALWAYS fails. PackByteMap is deliberately not
///   built here, so a stale persisted registration naming one of these bytes
///   cannot make a write pass.
/// * `126–127` and `248–254` are the two experimental zones: admitted only
///   under `dev`.
/// * `255` is the sentinel and fails in BOTH modes.
pub(crate) fn validate_entity_type_for_mode(
    entity_type: u8,
    dev: bool,
) -> crate::error::Result<()> {
    let invalid = || crate::error::Error::InvalidEntityType(entity_type);
    match zone_of(entity_type) {
        TypeByteZone::Semantic
        | TypeByteZone::Core
        | TypeByteZone::System
        | TypeByteZone::CompiledProduct => entity_type_registry_entry(entity_type)
            .map(|_| ())
            .ok_or_else(invalid),
        TypeByteZone::EngineExperimental | TypeByteZone::PackExperimental => {
            if dev {
                Ok(())
            } else {
                Err(invalid())
            }
        }
        TypeByteZone::PackHandle | TypeByteZone::Sentinel => Err(invalid()),
    }
}

pub(crate) fn validate_entity_type(entity_type: u8) -> crate::error::Result<()> {
    validate_entity_type_for_mode(entity_type, cfg!(debug_assertions))
}

/// Validates an entity type byte for PUBLIC write paths (D5).
///
/// Genuinely unknown bytes fail with [`Error::InvalidEntityType`]; every
/// REGISTERED `Maintenance`-classified kind fails with the distinct
/// [`RegistryError::MaintenanceKindNotWritable`](crate::error::RegistryError::MaintenanceKindNotWritable) — every engine-authored record in the
/// v3 system zone (REDACTION_AUDIT, MODEL, AUTHORITY_LOG, POLICY_MANIFEST,
/// FEDERATION_GRANT, DIAGNOSTIC, CONNECTOR_KEY, PSYCH_PROFILE, ACCESS_GRANT,
/// IDENTITY_TOPOLOGY_EVENT, SECRET_CUSTODY, CHANNEL_IDENTITY,
/// COUNTERPARTY_CONTACT, OUTBOUND_GRANT, PERSONA_SNAPSHOT_EXPORT, COMM_RECORD,
/// SKILL_CONTENT_ANCHOR). Classification, not zone position, is what makes a
/// kind engine-authored — COMPANION_REGISTER shares the zone and stays
/// publicly writable. The canon-reserved system bytes with no engine substrate
/// (SUSPICIOUS_WAKE = 72, CLAIM_CLASS_DESCRIPTOR = 74, SKILL_HUB = 75) still
/// fail with [`Error::InvalidEntityType`] so API-boundary error codes never
/// conflate "unknown byte" with "reserved system kind". SUSPICIOUS_WAKE stays
/// on that list: ONE-1394 spends only byte 69, and a suspicious wake is a
/// DIAGNOSTIC event CLASS rather than an entity kind of its own.
/// Engine-internal writers (the REDACTION_AUDIT receipt writer, the MODEL
/// get-or-create door in `vault.rs`, policy-manifest resolver fixtures,
/// federation-grant substrate writers, the PsychProfile snapshot writer, the
/// identity-topology apply/undo door, and the DIAGNOSTIC door
/// `Vault::emit_diagnostic_event`) bypass this gate via `allow_maintenance`.
///
/// [`Error::InvalidEntityType`]: crate::error::Error::InvalidEntityType
/// [`RegistryError::MaintenanceKindNotWritable`]: crate::error::RegistryError::MaintenanceKindNotWritable
pub(crate) fn validate_public_entity_type(entity_type: u8) -> crate::error::Result<()> {
    let entry = entity_type_registry_entry(entity_type)
        .ok_or(crate::error::Error::InvalidEntityType(entity_type))?;
    if entry.classification == EntityClassification::Maintenance {
        return Err(crate::error::Error::Registry(
            crate::error::RegistryError::MaintenanceKindNotWritable(entity_type),
        ));
    }
    Ok(())
}
