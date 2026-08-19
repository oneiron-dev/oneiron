//! Psych-mirror salience and entropy scoring, plus the stored-profile pack
//! section it feeds.

use std::collections::HashMap;

use crate::Vault;
use crate::claim::ClaimBody;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::psych_profile::{
    PsychMirrorSourceCandidate, PsychProfile, PsychProfileKey, PsychProfileStaleReason,
    PsychProfileState, psych_mirror_text_entropy, psych_profile_entity_id,
};

use super::types::ContextEntity;

const PSYCH_MIRROR_CONTEXT_TEXT_FIELD_ALIASES: [&str; 4] = ["val", "txt", "text", "body"];
const PSYCH_MIRROR_STRUCTURED_TEXT_SEPARATOR: &str = "\n";

/// Builds a Psych Mirror source candidate from an already decoded Claim body.
///
/// The caller supplies the source revision ref explicitly because hydrated
/// context rows intentionally do not carry revision provenance.
///
/// Designed in canon (eiri/context, ARCH-0004, eiri-arch-0016); unwired as of
/// 2026-08-19 — needs wiring/design completion.
pub fn psych_mirror_source_candidate_from_claim(
    source_id: EntityId,
    source_revision_ref: EntityId,
    connectivity: f32,
    learned_at: u64,
    body: &ClaimBody,
) -> Result<PsychMirrorSourceCandidate> {
    PsychMirrorSourceCandidate::new(
        source_id,
        source_revision_ref,
        connectivity,
        crate::claim::psych_mirror_claim_affect_salience(body)?,
        learned_at,
        psych_mirror_claim_value_entropy(body),
    )
}

/// Builds a Psych Mirror source candidate from a hydrated context entity.
///
/// This is a convenience adapter for fixture and API-read paths. It uses the
/// entity score as connectivity and reads projected `sal` plus text-ish fields
/// when present.
///
/// Designed in canon (eiri/context, ARCH-0004, eiri-arch-0016); unwired as of
/// 2026-08-19 — needs wiring/design completion.
pub fn psych_mirror_source_candidate_from_context_entity(
    entity: &ContextEntity,
    source_revision_ref: EntityId,
    learned_at: u64,
) -> Result<PsychMirrorSourceCandidate> {
    let fields = entity.fields.as_ref();
    PsychMirrorSourceCandidate::new(
        entity.id,
        source_revision_ref,
        entity.score,
        fields.map_or(0.0, psych_mirror_context_fields_affect_salience),
        learned_at,
        fields.map_or(0.0, psych_mirror_context_fields_entropy),
    )
}

fn psych_mirror_claim_value_entropy(body: &ClaimBody) -> f32 {
    let mut leaves = Vec::new();
    collect_psych_mirror_text_leaves(&body.value, &mut leaves);
    if leaves.is_empty() {
        0.0
    } else {
        psych_mirror_text_entropy(&leaves.join(PSYCH_MIRROR_STRUCTURED_TEXT_SEPARATOR))
    }
}

fn collect_psych_mirror_text_leaves<'a>(value: &'a rmpv::Value, leaves: &mut Vec<&'a str>) {
    match value {
        rmpv::Value::String(value) => {
            if let Some(text) = value.as_str().filter(|text| !text.is_empty()) {
                leaves.push(text);
            }
        }
        rmpv::Value::Array(values) => {
            for value in values {
                collect_psych_mirror_text_leaves(value, leaves);
            }
        }
        rmpv::Value::Map(entries) => {
            for (_, value) in entries {
                collect_psych_mirror_text_leaves(value, leaves);
            }
        }
        _ => {}
    }
}

fn psych_mirror_context_fields_affect_salience(fields: &HashMap<String, serde_json::Value>) -> f32 {
    fields
        .get(crate::claim::KEY_SAL)
        .and_then(psych_mirror_json_unit_interval)
        .unwrap_or(0.0)
}

fn psych_mirror_context_fields_entropy(fields: &HashMap<String, serde_json::Value>) -> f32 {
    PSYCH_MIRROR_CONTEXT_TEXT_FIELD_ALIASES
        .into_iter()
        .find_map(|key| fields.get(key).and_then(serde_json::Value::as_str))
        .map_or(0.0, psych_mirror_text_entropy)
}

fn psych_mirror_json_unit_interval(value: &serde_json::Value) -> Option<f32> {
    let value = value.as_f64()?;
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Some(value as f32)
    } else {
        None
    }
}

/// Explicit companion section for an opt-in stored PsychProfile lookup.
#[derive(Debug, Clone, PartialEq)]
pub struct PsychProfilePackSection {
    /// Stable companion section key, distinct from serialized entity groups.
    pub section: String,
    /// Stable state discriminant: `missing`, `stale`, or `fresh`.
    pub status: String,
    pub entity_id: EntityId,
    pub key: PsychProfileKey,
    /// Present only for a fresh snapshot.
    pub profile: Option<PsychProfile>,
    /// Present only for a stale snapshot.
    pub stale_reason: Option<PsychProfilePackStaleReason>,
}

/// Detail retained when a stored profile is explicitly stale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PsychProfilePackStaleReason {
    MarkedStale,
    SourceRevisionMismatch {
        expected: Vec<EntityId>,
        actual: Vec<EntityId>,
    },
}

/// Materializes a requested stored-profile companion section.
pub fn psych_profile_pack_section(
    vault: &Vault,
    key: &PsychProfileKey,
) -> Result<PsychProfilePackSection> {
    let state = vault.psych_profile_for(key)?;
    let key = *key;
    let entity_id = psych_profile_entity_id(&key);
    Ok(match state {
        PsychProfileState::Missing => PsychProfilePackSection {
            section: "psych_profile".to_owned(),
            status: "missing".to_owned(),
            entity_id,
            key,
            profile: None,
            stale_reason: None,
        },
        PsychProfileState::Fresh(profile) => PsychProfilePackSection {
            section: "psych_profile".to_owned(),
            status: "fresh".to_owned(),
            entity_id,
            key,
            profile: Some(profile),
            stale_reason: None,
        },
        PsychProfileState::Stale { reason, .. } => {
            let stale_reason = match reason {
                PsychProfileStaleReason::MarkedStale => PsychProfilePackStaleReason::MarkedStale,
                PsychProfileStaleReason::SourceRevisionMismatch { expected, actual } => {
                    PsychProfilePackStaleReason::SourceRevisionMismatch { expected, actual }
                }
            };
            PsychProfilePackSection {
                section: "psych_profile".to_owned(),
                status: "stale".to_owned(),
                entity_id,
                key,
                profile: None,
                stale_reason: Some(stale_reason),
            }
        }
    })
}
