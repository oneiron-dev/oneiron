//! The REST shapes of the row-less `/v1/owner` routes from `/backups` through
//! `/owner-signing-keys` that parts A to C left unbound (FIX 11613, 11617):
//! one [`super::bind`] per route, called from [`super::merge_owner_rest_shapes`].

use serde_json::Value;

use crate::api::owner_origin::{
    cut_origin_authority_body_schema, origin_authority_schema, origin_mirror_run_schema,
    origin_mirror_target_schema, push_origin_mirror_body_schema, set_origin_mirror_body_schema,
    set_origin_mirror_strategy_body_schema,
};
use crate::api::owner_routes::browser_takeover_routes::browser_screen_body_schema;
use crate::api::owner_routes::decision_ask_routes::{
    answer_ask_body_schema, decision_ask_schema, host_rule_schema, revoke_rule_body_schema,
};
use crate::api::owner_routes::desktop_takeover_routes::desktop_run_request_body_schema;
use crate::api::owner_routes::machine_routes::{
    machine_answer_schema, remove_machine_body_schema, set_answer_body_schema,
};
use crate::api::owner_routes::owner_key_enrollment_routes::{
    challenge_reply_schema, challenge_request_body_schema, enroll_receipt_schema,
    enroll_request_body_schema,
};
use crate::api::owner_routes::schema::{
    backup_outcome_schema, decide_note_tombstone_body_schema, flip_off_record_body_schema,
    model_catalog_sync_schema, model_catalog_synced_schema, off_record_promoted_schema,
    off_record_saved_schema, off_record_session_schema, promote_off_record_body_schema,
    save_off_record_body_schema, set_model_catalog_body_schema, tombstone_review_schema,
    tombstoned_schema,
};

/// Binds each route's REST shapes.
pub(super) fn merge(spec: &mut Value) {
    super::bind_answer(
        spec,
        "/v1/owner/backups",
        "post",
        backup_outcome_schema(),
        &[],
    );
    super::bind_image_answer(
        spec,
        "/v1/owner/browsers/screen",
        "post",
        browser_screen_body_schema(),
        &[],
    );
    super::bind_image_answer(
        spec,
        "/v1/owner/desktops/screen",
        "post",
        desktop_run_request_body_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/decisions/asks/answer",
        "post",
        answer_ask_body_schema(),
        decision_ask_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/decisions/rules/revoke",
        "post",
        revoke_rule_body_schema(),
        host_rule_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/machines/answer",
        "post",
        set_answer_body_schema(),
        machine_answer_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/machines/remove",
        "post",
        remove_machine_body_schema(),
        machine_answer_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/model-catalog",
        "put",
        set_model_catalog_body_schema(),
        model_catalog_sync_schema(),
        &[],
    );
    super::bind_answer(
        spec,
        "/v1/owner/model-catalog/sync",
        "post",
        model_catalog_synced_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/notes/tombstones/accept",
        "post",
        decide_note_tombstone_body_schema(),
        tombstoned_schema(),
        &[super::CHANGED],
    );
    super::bind(
        spec,
        "/v1/owner/notes/tombstones/decline",
        "post",
        decide_note_tombstone_body_schema(),
        tombstone_review_schema(),
        &[super::CHANGED],
    );
    super::bind(
        spec,
        "/v1/owner/off-record/mode",
        "post",
        flip_off_record_body_schema(),
        off_record_session_schema(),
        &[super::CHANGED],
    );
    super::bind(
        spec,
        "/v1/owner/off-record/promote",
        "post",
        promote_off_record_body_schema(),
        off_record_promoted_schema(),
        &[super::CHANGED],
    );
    super::bind(
        spec,
        "/v1/owner/off-record/save",
        "post",
        save_off_record_body_schema(),
        off_record_saved_schema(),
        &[super::CHANGED],
    );
    super::bind(
        spec,
        "/v1/owner/origin-authority",
        "post",
        cut_origin_authority_body_schema(),
        origin_authority_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/origin-mirror",
        "post",
        set_origin_mirror_body_schema(),
        origin_mirror_target_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/origin-mirror/push",
        "post",
        push_origin_mirror_body_schema(),
        origin_mirror_run_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/origin-mirror/strategy",
        "post",
        set_origin_mirror_strategy_body_schema(),
        origin_mirror_target_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/owner-signing-keys/challenge",
        "post",
        challenge_request_body_schema(),
        challenge_reply_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/owner-signing-keys/enroll",
        "post",
        enroll_request_body_schema(),
        enroll_receipt_schema(),
        &[],
    );
    super::bind_answer(
        spec,
        "/v1/owner/owner-signing-keys/enroll-this-install",
        "post",
        enroll_receipt_schema(),
        &[],
    );
}
