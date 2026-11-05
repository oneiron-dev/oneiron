//! The restrictive targets whose native door parses more than serde.

use serde_json::Value;

pub(super) fn publisher_identity(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|text| crate::consent::ActorBound::new(text).is_ok())
}

pub(super) fn voice_ref(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|text| crate::memory::voice_actor::valid_id(text).is_ok())
}

pub(super) fn artifact_id(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|text| crate::artifact_hosting::validate_artifact_id(text).is_ok())
}

pub(super) fn live_run_handle(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|text| crate::code_run::live_run::parse_live_run_handle(text).is_some())
}
