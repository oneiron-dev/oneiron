//! The REST shapes of the row-less `/v1/owner` routes from `/secret-scan` through `/skills/judge` (FIX 11611 part D):
//! one [`super::bind`] per route, called from [`super::merge_owner_rest_shapes`].

use serde_json::Value;

use super::bind;
use crate::api::owner_routes::backup_setting_routes::{
    backup_policy_body_schema, backup_setting_schema,
};
use crate::api::owner_routes::learning_setting_routes::{
    clear_learning_setting_body_schema, learning_settings_view_schema,
    put_learning_setting_body_schema,
};
use crate::api::owner_routes::proactivity_routes::schema::{
    label_finding_body_schema, reviewed_finding_schema,
};
use crate::api::owner_routes::recovery_kit_target_routes::secret_anchor::{
    anchor_sign_body_schema, anchor_signed_schema,
};
use crate::api::owner_routes::room_thread_setting_routes::{
    room_thread_change_body_schema, room_thread_settings_schema,
};
use crate::api::owner_routes::schema::{secret_scan_receipt_schema, set_secret_scan_body_schema};
use crate::api::owner_routes::secret_control_routes::pending::{
    pending_release_receipt_schema, release_body_schema,
};
use crate::api::owner_routes::secret_control_routes::{
    custody_reply_schema, rewrap_body_schema, sealed_change_body_schema,
};
use crate::api::owner_routes::secret_found_routes::{
    found_key_body_schema, found_key_settled_schema, grant_found_key_body_schema,
};
use crate::api::owner_routes::secret_lift_routes::{
    secret_lift_close_body_schema, secret_lift_proposal_schema,
};
use crate::api::owner_routes::secret_reveal_routes::{
    answer_reveal_body_schema, owner_reveal_body_schema, reveal_answered_schema,
    revealed_view_schema,
};
use crate::api::owner_routes::secret_use_routes::{
    bind_body_schema, bound_view_schema, unbind_body_schema,
};
use crate::api::owner_routes::skill_judge_routes::{
    bind_goal_project_body_schema, goal_axis_report_schema, goal_revision_schema,
    judge_swap_pick_schema, judge_swap_policy_schema, measure_body_schema, pair_pick_body_schema,
    person_time_total_schema, record_person_time_body_schema, response_pair_pick_schema,
    swap_pick_body_schema, tradeoff_pick_body_schema, tradeoff_resolve_body_schema,
    tradeoff_settled_schema,
};
use crate::owner::secrets::{
    custody_rotated_schema, reenter_kept_value_body_schema, register_secret_body_schema,
    registered_schema, revoke_secret_body_schema, rotate_secret_body_schema,
};

/// Binds each route's REST shapes.
pub(super) fn merge(spec: &mut Value) {
    bind(
        spec,
        "/v1/owner/secret-scan",
        "post",
        set_secret_scan_body_schema(),
        secret_scan_receipt_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/secrets/anchor-sign",
        "post",
        anchor_sign_body_schema(),
        anchor_signed_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/secrets/bind",
        "post",
        bind_body_schema(),
        bound_view_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/secrets/unbind",
        "post",
        unbind_body_schema(),
        bound_view_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/secrets/custody",
        "post",
        sealed_change_body_schema(),
        custody_reply_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/secrets/custody/pending",
        "post",
        release_body_schema(),
        pending_release_receipt_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/secrets/found/delete",
        "post",
        found_key_body_schema(),
        found_key_settled_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/secrets/found/grant",
        "post",
        grant_found_key_body_schema(),
        found_key_settled_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/secrets/found/not-a-secret",
        "post",
        found_key_body_schema(),
        found_key_settled_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/secrets/found/re-enter",
        "post",
        reenter_kept_value_body_schema(),
        found_key_settled_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/secrets/lift/close",
        "post",
        secret_lift_close_body_schema(),
        secret_lift_proposal_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/secrets/register",
        "post",
        register_secret_body_schema(),
        registered_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/secrets/reveal",
        "post",
        owner_reveal_body_schema(),
        revealed_view_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/secrets/reveals/answer",
        "post",
        answer_reveal_body_schema(),
        reveal_answered_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/secrets/revoke",
        "post",
        revoke_secret_body_schema(),
        custody_rotated_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/secrets/rewrap",
        "post",
        rewrap_body_schema(),
        custody_reply_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/secrets/rotate",
        "post",
        rotate_secret_body_schema(),
        custody_rotated_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/self-heal/findings/label",
        "post",
        label_finding_body_schema(),
        reviewed_finding_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/settings/backup",
        "put",
        backup_policy_body_schema(),
        backup_setting_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/settings/learning",
        "post",
        put_learning_setting_body_schema(),
        learning_settings_view_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/settings/learning/clear",
        "post",
        clear_learning_setting_body_schema(),
        learning_settings_view_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/settings/room-threads",
        "post",
        room_thread_change_body_schema(),
        room_thread_settings_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/skills/judge/goal-project",
        "post",
        bind_goal_project_body_schema(),
        goal_revision_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/skills/judge/measure",
        "post",
        measure_body_schema(),
        goal_axis_report_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/skills/judge/pairs/pick",
        "post",
        pair_pick_body_schema(),
        response_pair_pick_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/skills/judge/person-time",
        "post",
        record_person_time_body_schema(),
        person_time_total_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/skills/judge/swap-policy",
        "post",
        judge_swap_policy_schema(),
        judge_swap_policy_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/skills/judge/swaps/pick",
        "post",
        swap_pick_body_schema(),
        judge_swap_pick_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/skills/judge/tradeoff-asks/pick",
        "post",
        tradeoff_pick_body_schema(),
        tradeoff_settled_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/skills/judge/tradeoff-asks/resolve",
        "post",
        tradeoff_resolve_body_schema(),
        tradeoff_settled_schema(),
        &[],
    );
}
