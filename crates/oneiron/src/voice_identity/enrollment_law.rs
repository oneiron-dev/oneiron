//! The law an enrollment is made under, as the trusted host resolved it (FIX 10218).
//! Entry: admit_enrollment_law.
//!
//! The host's legal-policy seam resolves, for each enrollment, which
//! jurisdiction's law applies and whether that law asks a written release
//! before a voiceprint is made. This module holds no law of its own: no
//! jurisdiction table, no default jurisdiction and no statute. A written
//! release counts only when the host links it to the very consent event the
//! enrollment cites; a conversational notice or a settings toggle is never
//! one. The legal context never blocks an enrollment: an unresolved
//! jurisdiction is recorded as unresolved, and a third party's voice whose
//! release is not shown where its law is unresolved or asks one leaves the
//! owner a question owed, marked on the print until a typed question asks it.
//! The owner's own voice is recorded only.

use rmpv::Value;

use super::codec_core::{decode_str, decode_u64, map_entries, required_value, validate_keys};
use super::math_keys::corrupt_voice_row;
use crate::error::Result;

/// Which jurisdiction's law an enrollment is made under, as the host's
/// legal-policy seam resolved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoiceJurisdiction {
    /// The seam resolved none for this enrollment.
    Unresolved,
    /// The jurisdiction the seam names, and whether its law, as the seam
    /// reads it, asks a written release before a voiceprint is made.
    Resolved {
        jurisdiction: String,
        written_release_required: bool,
    },
}

/// A written release the host holds, linked to the consent event it
/// releases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenReleaseRef {
    /// The consent event it releases: the enrollment's own, or it counts for
    /// nothing here.
    pub consent_event_ref: String,
    /// Where the host keeps the signed document.
    pub document_ref: String,
    pub signed_at: u64,
}

/// The law context the trusted host supplies with an enrollment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoiceEnrollmentLegalContext {
    pub jurisdiction: VoiceJurisdiction,
    pub written_release: Option<WrittenReleaseRef>,
}

impl VoiceEnrollmentLegalContext {
    /// A context whose jurisdiction the host did not resolve.
    #[must_use]
    pub const fn unresolved() -> Self {
        Self {
            jurisdiction: VoiceJurisdiction::Unresolved,
            written_release: None,
        }
    }
}

/// What a print keeps of the law it was enrolled under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoicePrintLegalEvidence {
    pub jurisdiction: VoiceJurisdiction,
    /// The written release linked to the print's own consent event, when the
    /// host supplied one; a release naming another event is not kept.
    pub written_release: Option<WrittenReleaseRef>,
    /// A third party's voice whose release is not shown, where its law is
    /// unresolved or asks one: the owner is owed a typed question about it.
    pub owner_ask_owed: bool,
}

/// The legal evidence an enrollment citing `consent_event_ref` keeps, from
/// the host's `context`. `third_party` is a voice that is not the owner's
/// own. Never a refusal.
pub(super) fn admit_enrollment_law(
    context: &VoiceEnrollmentLegalContext,
    consent_event_ref: &str,
    third_party: bool,
) -> VoicePrintLegalEvidence {
    let written_release = context.written_release.clone().filter(|release| {
        release.consent_event_ref == consent_event_ref
            && !release.document_ref.trim().is_empty()
            && release.signed_at > 0
    });
    let release_not_needed = matches!(
        context.jurisdiction,
        VoiceJurisdiction::Resolved {
            written_release_required: false,
            ..
        }
    );
    let owner_ask_owed = third_party && written_release.is_none() && !release_not_needed;
    if owner_ask_owed {
        tracing::info!("a third party's voice enrolled with no written release shown: ask owed");
    }
    VoicePrintLegalEvidence {
        jurisdiction: context.jurisdiction.clone(),
        written_release,
        owner_ask_owed,
    }
}

const LEGAL_KEYS: [&str; 4] = [
    "jurisdiction",
    "written_release_required",
    "written_release",
    "owner_ask_owed",
];

const RELEASE_KEYS: [&str; 3] = ["consent_event_ref", "document_ref", "signed_at"];

/// The print record's `legal` field.
pub(super) fn encode_legal_evidence(evidence: &VoicePrintLegalEvidence) -> Value {
    let (jurisdiction, required) = match &evidence.jurisdiction {
        VoiceJurisdiction::Unresolved => (Value::Nil, Value::Nil),
        VoiceJurisdiction::Resolved {
            jurisdiction,
            written_release_required,
        } => (
            Value::from(jurisdiction.clone()),
            Value::from(*written_release_required),
        ),
    };
    let release = evidence
        .written_release
        .as_ref()
        .map_or(Value::Nil, |release| {
            Value::Map(vec![
                (
                    Value::from(RELEASE_KEYS[0]),
                    Value::from(release.consent_event_ref.clone()),
                ),
                (
                    Value::from(RELEASE_KEYS[1]),
                    Value::from(release.document_ref.clone()),
                ),
                (Value::from(RELEASE_KEYS[2]), Value::from(release.signed_at)),
            ])
        });
    Value::Map(vec![
        (Value::from(LEGAL_KEYS[0]), jurisdiction),
        (Value::from(LEGAL_KEYS[1]), required),
        (Value::from(LEGAL_KEYS[2]), release),
        (
            Value::from(LEGAL_KEYS[3]),
            Value::from(evidence.owner_ask_owed),
        ),
    ])
}

/// [`encode_legal_evidence`]'s inverse; anything else is a corrupt row.
pub(super) fn decode_legal_evidence(value: &Value) -> Result<VoicePrintLegalEvidence> {
    let entries = map_entries(value)?;
    validate_keys(entries, &LEGAL_KEYS)?;
    let jurisdiction = match (
        required_value(entries, LEGAL_KEYS[0])?,
        required_value(entries, LEGAL_KEYS[1])?,
    ) {
        (Value::Nil, Value::Nil) => VoiceJurisdiction::Unresolved,
        (jurisdiction, Value::Boolean(required)) => VoiceJurisdiction::Resolved {
            jurisdiction: decode_str(jurisdiction)?,
            written_release_required: *required,
        },
        _ => return Err(corrupt_voice_row()),
    };
    let written_release = match required_value(entries, LEGAL_KEYS[2])? {
        Value::Nil => None,
        release => {
            let fields = map_entries(release)?;
            validate_keys(fields, &RELEASE_KEYS)?;
            Some(WrittenReleaseRef {
                consent_event_ref: decode_str(required_value(fields, RELEASE_KEYS[0])?)?,
                document_ref: decode_str(required_value(fields, RELEASE_KEYS[1])?)?,
                signed_at: decode_u64(required_value(fields, RELEASE_KEYS[2])?)?,
            })
        }
    };
    let owner_ask_owed = required_value(entries, LEGAL_KEYS[3])?
        .as_bool()
        .ok_or_else(corrupt_voice_row)?;
    Ok(VoicePrintLegalEvidence {
        jurisdiction,
        written_release,
        owner_ask_owed,
    })
}
