//! Host-config loader plus the CA-04 ladder unknown-field guard.

use serde_json::Value as JsonValue;

use super::shape::CampaignPresetData;
use super::validate::{preset_error, validate_preset};
use crate::Result;

// ---------------------------------------------------------------------------
// The loader
// ---------------------------------------------------------------------------

/// Parses and validates JSON supplied by the host pack/config layer.
///
/// The returned value is owned data: nothing is cached, installed, registered,
/// or written. A caller hands this to CA-04's ladder functions, which own every
/// consequence.
///
/// # Errors
///
/// [`Error::InvalidConfig`] naming the first defect found: malformed JSON, an
/// unknown or missing field, an id or version that is not the ratified pair, a
/// ladder CA-04 itself rejects, or any violated content invariant.
pub fn load_campaign_preset(json: &str) -> Result<CampaignPresetData> {
    let value: JsonValue = serde_json::from_str(json)
        .map_err(|err| preset_error(format!("host config is not valid JSON: {err}")))?;
    reject_unknown_ladder_fields(&value["stage_ladder"])?;
    let preset: CampaignPresetData = serde_json::from_value(value)
        .map_err(|err| preset_error(format!("host config is not a valid preset: {err}")))?;
    validate_preset(&preset)?;
    Ok(preset)
}

/// CA-04's ladder-subtree field names, one list per node.
///
/// The lists cannot go quietly stale: the round trip in
/// `consultancy_v1_deserializes_against_ca04_schema` re-loads a SERIALIZED
/// preset, so a field CA-04 adds and this module has not learned is rejected by
/// the very check below, loudly, in that test.
const LADDER_FIELDS: [&str; 5] = [
    "key",
    "stages",
    "transitions",
    "reply_routes",
    "no_show_recovery",
];

const STAGE_FIELDS: [&str; 2] = ["key", "label"];

const TRANSITION_FIELDS: [&str; 4] = ["from", "to", "evidence_class", "owner_attested_allowed"];

const REPLY_ROUTE_FIELDS: [&str; 2] = ["code", "disposition"];

/// `ReplyDisposition` is internally tagged: every variant carries `kind`, and
/// only `promote` carries a `stage`. The admissible set is therefore per-variant
/// rather than the union of both — a `stage` written beside `snooze` is a host
/// that believes it configured a promotion.
const DISPOSITION_FIELDS: [&str; 1] = ["kind"];

const PROMOTE_DISPOSITION_FIELDS: [&str; 2] = ["kind", "stage"];

const NO_SHOW_RECOVERY_FIELDS: [&str; 3] = [
    "same_day_reschedule",
    "bump_after_secs",
    "snooze_after_failed_bump",
];

/// Refuses unknown keys inside the imported ladder subtree.
///
/// This module's own structs deny unknown fields, but CA-04's do not and
/// `stage.rs` is the parent layer's to change. So the promise is kept against the
/// wire TEXT here rather than by reaching into another owner's schema: a host
/// that misspells `bump_after_secs` is told, instead of silently receiving the
/// ratified default it never wrote. If CA-04 ever denies unknown fields itself,
/// this check becomes redundant and should go.
fn reject_unknown_ladder_fields(ladder: &JsonValue) -> Result<()> {
    require_known_fields("stage ladder", ladder, &LADDER_FIELDS)?;
    for stage in members(ladder, "stages") {
        require_known_fields("stage", stage, &STAGE_FIELDS)?;
    }
    for rule in members(ladder, "transitions") {
        require_known_fields("stage transition", rule, &TRANSITION_FIELDS)?;
    }
    for route in members(ladder, "reply_routes") {
        require_known_fields("reply route", route, &REPLY_ROUTE_FIELDS)?;
        let disposition = &route["disposition"];
        let allowed: &[&str] = if disposition["kind"] == "promote" {
            &PROMOTE_DISPOSITION_FIELDS
        } else {
            &DISPOSITION_FIELDS
        };
        require_known_fields("reply disposition", disposition, allowed)?;
    }
    require_known_fields(
        "no-show recovery",
        &ladder["no_show_recovery"],
        &NO_SHOW_RECOVERY_FIELDS,
    )
}

fn require_known_fields(node: &str, value: &JsonValue, allowed: &[&str]) -> Result<()> {
    // A missing or wrongly-TYPED node is serde's rejection to make, and it names
    // the expected type better than this check could.
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    for field in object.keys() {
        if !allowed.contains(&field.as_str()) {
            return Err(preset_error(format!(
                "{node} declares unknown field {field:?}"
            )));
        }
    }
    Ok(())
}

fn members<'a>(value: &'a JsonValue, field: &str) -> &'a [JsonValue] {
    value[field].as_array().map_or(&[], Vec::as_slice)
}
