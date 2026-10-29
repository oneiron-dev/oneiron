//! The REST shapes of the row-less `/v1/owner` routes from `/space-posting` through `/worlds/privacy` (FIX 11611 part D):
//! one [`super::bind`] per route, called from [`super::merge_owner_rest_shapes`].

use serde_json::Value;

use crate::api::owner_routes::house_routes::{
    finish_workspace_body_schema, workspace_finished_schema,
};
use crate::api::owner_routes::proactivity_routes::schema::{
    set_stewardship_body_schema, stewardship_rules_schema,
};
use crate::api::owner_routes::space_posting_routes::{
    set_space_posting_body_schema, space_posting_schema,
};
use crate::api::owner_routes::steer_routes::{steer_body_schema, steer_receipt_schema};
use crate::api::owner_routes::vault_key_routes::{
    add_passkey_body_schema, escrow_retirement_schema, remove_wrap_body_schema,
    retire_escrow_body_schema, set_password_body_schema, unlock_body_schema,
    vault_key_report_schema, vault_key_wrap_info_schema, wrap_removed_schema,
};
use crate::api::owner_routes::weave_routes::{
    clear_weave_schedule_body_schema, set_weave_schedule_body_schema, weave_lens_schema,
    weave_link_correction_schema, weave_report_body_schema, weave_report_schema,
    weave_schedule_cleared_schema, weave_schedule_schema, weave_wrong_link_body_schema,
};
use crate::api::owner_routes::widen_proposal_routes::{
    widen_answer_body_schema, widen_proposal_schema,
};
use crate::api::owner_routes::world_privacy_routes::{
    set_widen_unanimity_body_schema, set_world_privacy_body_schema, undo_world_privacy_body_schema,
    widen_unanimity_outcome_schema, world_privacy_answer_body_schema, world_privacy_answer_schema,
    world_privacy_outcome_schema, world_privacy_receipt_schema,
};
use crate::api::owner_routes::world_privacy_work_routes::{
    world_privacy_set_body_schema, world_privacy_work_schema,
};

/// Binds each route's REST shapes.
pub(super) fn merge(spec: &mut Value) {
    super::bind(
        spec,
        "/v1/owner/space-posting",
        "post",
        set_space_posting_body_schema(),
        space_posting_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/steer",
        "post",
        steer_body_schema(),
        steer_receipt_schema(),
        &[super::CHANGED],
    );
    super::bind(
        spec,
        "/v1/owner/stewardship",
        "post",
        set_stewardship_body_schema(),
        stewardship_rules_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/vault-key/remove",
        "post",
        remove_wrap_body_schema(),
        wrap_removed_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/vault-key/retire-escrow",
        "post",
        retire_escrow_body_schema(),
        escrow_retirement_schema(),
        &[],
    );
    super::bind_answer(
        spec,
        "/v1/owner/vault-key/device",
        "post",
        vault_key_wrap_info_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/vault-key/password",
        "post",
        set_password_body_schema(),
        vault_key_wrap_info_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/vault-key/passkeys",
        "post",
        add_passkey_body_schema(),
        vault_key_wrap_info_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/vault-key/unlock",
        "post",
        unlock_body_schema(),
        vault_key_report_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/weave/schedules",
        "put",
        set_weave_schedule_body_schema(),
        weave_schedule_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/weave/schedules/clear",
        "post",
        clear_weave_schedule_body_schema(),
        weave_schedule_cleared_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/weave/link/wrong",
        "post",
        weave_wrong_link_body_schema(),
        weave_link_correction_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/weave/report",
        "post",
        weave_report_body_schema(),
        weave_report_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/weave/lens",
        "post",
        weave_report_body_schema(),
        weave_lens_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/widen-proposals/approve",
        "post",
        widen_answer_body_schema(),
        widen_proposal_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/widen-proposals/decline",
        "post",
        widen_answer_body_schema(),
        widen_proposal_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/workspace/finish",
        "post",
        finish_workspace_body_schema(),
        workspace_finished_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/worlds/privacy/settings",
        "post",
        world_privacy_set_body_schema(),
        world_privacy_work_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/worlds/privacy/reassert",
        "post",
        world_privacy_set_body_schema(),
        world_privacy_work_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/worlds/privacy/set",
        "post",
        set_world_privacy_body_schema(),
        world_privacy_outcome_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/worlds/privacy/proposals/accept",
        "post",
        world_privacy_answer_body_schema(),
        world_privacy_answer_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/worlds/privacy/proposals/decline",
        "post",
        world_privacy_answer_body_schema(),
        world_privacy_answer_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/worlds/privacy/asks/confirm",
        "post",
        world_privacy_answer_body_schema(),
        world_privacy_answer_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/worlds/privacy/asks/decline",
        "post",
        world_privacy_answer_body_schema(),
        world_privacy_answer_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/worlds/privacy/undo",
        "post",
        undo_world_privacy_body_schema(),
        world_privacy_receipt_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/worlds/privacy/widen-unanimity",
        "post",
        set_widen_unanimity_body_schema(),
        widen_unanimity_outcome_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/worlds/privacy/widen-unanimity/off/confirm",
        "post",
        world_privacy_answer_body_schema(),
        widen_unanimity_outcome_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/worlds/privacy/widen-unanimity/off/decline",
        "post",
        world_privacy_answer_body_schema(),
        widen_unanimity_outcome_schema(),
        &[],
    );
}
