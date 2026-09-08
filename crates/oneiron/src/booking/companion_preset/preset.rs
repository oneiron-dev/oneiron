//! Companion preset manifest parsing and the friend-hangout pack-data binding.

use serde::{Deserialize, Serialize};

use crate::booking::{BookingError, EventTypeConfig};

use super::{CompanionProposal, ProposalId};
// -------------------------------------------------------------------------
// The preset
// -------------------------------------------------------------------------
/// Wire version of the preset manifest. A payload carrying any other version
/// fails closed rather than being coerced.
const COMPANION_PRESET_SCHEMA_VERSION: u8 = 1;
/// Bound on a preset id.
const MAX_PRESET_ID_BYTES: usize = 64;
/// How a proposal reaches its participants.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalCarrier {
    MessageLink,
}
/// How a proposal terminates. A soft confirmation is the companion saying "this
/// is the one" — distinct from a business hard commit, which this path has no
/// door onto.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionConfirmationMode {
    SoftViaCompanion,
}
/// The runtime preset: the pack-data row plus the caller-supplied synthetic
/// configuration it runs the shared solver against.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompanionPresetRow {
    pub id: String,
    pub carrier: ProposalCarrier,
    pub confirmation: CompanionConfirmationMode,
    pub synthetic_event_type_config: EventTypeConfig,
    pub personal_hours: bool,
    pub generous_flex: bool,
    pub email_otp_enabled: bool,
    pub group_intersection: bool,
}
/// The pack-data envelope, in the manifest idiom the seeded-roster loader
/// established: a pinned version and a `deny_unknown_fields` body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompanionPresetManifest {
    version: u8,
    preset: CompanionPresetSeed,
}
/// The pack-data row. It declares behaviour and nothing else — no entity id, no
/// type byte, no claim subject.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompanionPresetSeed {
    id: String,
    carrier: ProposalCarrier,
    confirmation: CompanionConfirmationMode,
    personal_hours: bool,
    generous_flex: bool,
    email_otp_enabled: bool,
    group_intersection: bool,
}
/// Parses a companion preset manifest and binds it to the configuration the
/// consumer supplies.
///
/// The row is refused when it declares behaviour this module does not
/// implement. A configuration flag that is silently ignored is a lie the solver
/// would go on to honour as its opposite, so each one is either enforced or
/// documented as un-enforceable:
///
/// - `group_intersection` — the only aggregation implemented here is the
///   authorized intersection, so `false` is refused rather than ignored;
/// - `email_otp_enabled` — there is no OTP path on the companion carrier, so
///   `true` is refused;
/// - `generous_flex` — checkable against the supplied configuration: a declared
///   flex pool with no flex windows is a flag with no effect;
/// - `personal_hours` — a statement about which availability profile the
///   consumer built its configuration from. It is carried as data because this
///   module cannot tell a personal profile from a business one by inspection.
pub fn load_companion_preset(
    json: &[u8],
    synthetic_event_type_config: EventTypeConfig,
) -> Result<CompanionPresetRow, BookingError> {
    let manifest: CompanionPresetManifest = serde_json::from_slice(json).map_err(|error| {
        BookingError::InvalidConfig(format!("companion preset does not parse: {error}"))
    })?;
    if manifest.version != COMPANION_PRESET_SCHEMA_VERSION {
        return Err(BookingError::InvalidConfig(format!(
            "companion preset version must be {COMPANION_PRESET_SCHEMA_VERSION}, got {}",
            manifest.version
        )));
    }
    let seed = manifest.preset;
    validate_preset_id(&seed.id)?;
    synthetic_event_type_config.validate()?;
    if !seed.group_intersection {
        return Err(BookingError::InvalidConfig(
            "companion presets aggregate taps as the authorized intersection only".to_owned(),
        ));
    }
    if seed.email_otp_enabled {
        return Err(BookingError::InvalidConfig(
            "companion presets carry no email OTP step".to_owned(),
        ));
    }
    if seed.generous_flex && synthetic_event_type_config.flex_windows.is_empty() {
        return Err(BookingError::InvalidConfig(
            "companion preset declares generous flex but its configuration has no flex windows"
                .to_owned(),
        ));
    }
    Ok(CompanionPresetRow {
        id: seed.id,
        carrier: seed.carrier,
        confirmation: seed.confirmation,
        synthetic_event_type_config,
        personal_hours: seed.personal_hours,
        generous_flex: seed.generous_flex,
        email_otp_enabled: seed.email_otp_enabled,
        group_intersection: seed.group_intersection,
    })
}
fn validate_preset_id(value: &str) -> Result<(), BookingError> {
    if value.is_empty() || value.len() > MAX_PRESET_ID_BYTES {
        return Err(BookingError::InvalidConfig(format!(
            "companion preset id must be 1..={MAX_PRESET_ID_BYTES} bytes"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(BookingError::InvalidConfig(
            "companion preset id must use only ASCII alnum, '.', '_', or '-'".to_owned(),
        ));
    }
    Ok(())
}
// -------------------------------------------------------------------------
// Friend-hangout booking preset (ONE-1821)
//
// The whole friend-hangout half of the companion booking path is here: an id, a
// loader call, and a message assembly. The machinery it drives is generic and
// product-free above, and the behaviour is pack data, not code.
// -------------------------------------------------------------------------
/// The friend-hangout preset's stable id, matching the pack-data row.
pub const FRIEND_HANGOUT_PRESET_ID: &str = "booking.eiri.friend_hangout.v1";
/// The pack-data row. Behaviour lives in this JSON, not in a Rust branch.
const FRIEND_HANGOUT_PRESET_V1_JSON: &str = include_str!("presets/eiri_friend_hangout_v1.json");
/// Binds the friend-hangout pack row to the caller's synthetic configuration.
///
/// The configuration is supplied rather than looked up: a friend hangout has no
/// booking page, and the personal-hours profile and flex pool are the caller's
/// to build.
pub fn friend_hangout_preset(
    synthetic_event_type_config: EventTypeConfig,
) -> Result<CompanionPresetRow, BookingError> {
    load_companion_preset(
        FRIEND_HANGOUT_PRESET_V1_JSON.as_bytes(),
        synthetic_event_type_config,
    )
}
/// What the hangout message needs: the proposal's opaque id, the carrier
/// reference the generic module produced, and the choice labels to read out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HangoutProposalAssembly {
    pub proposal_id: ProposalId,
    pub message_link: String,
    pub choice_labels: Vec<String>,
}
/// Assembles the message around an EXISTING proposal link.
///
/// No link is minted here and no time is invented: the caller passes the
/// reference `opaque_proposal_message_link` produced, and the labels are the
/// proposal's own.
#[must_use]
pub fn assemble_hangout_proposal_message(
    proposal: &CompanionProposal,
    message_link: String,
) -> HangoutProposalAssembly {
    HangoutProposalAssembly {
        proposal_id: proposal.id,
        message_link,
        choice_labels: proposal
            .choices
            .iter()
            .map(|choice| choice.label.clone())
            .collect(),
    }
}
