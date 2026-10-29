//! The REST shapes of the row-less `/v1/owner` routes from `/pads` through `/runs` (FIX 11611 part D):
//! one [`super::bind`] per route, called from [`super::merge_owner_rest_shapes`].

use serde_json::Value;

use crate::api::owner_routes::budget_hold_routes::{held_run_body_schema, held_run_view_schema};
use crate::api::owner_routes::diary_routes::diary_read_outcome_schema;
use crate::api::owner_routes::owner_work_routes::owner_work_view_schema;
use crate::api::owner_routes::pad_routes::read_pads_body_schema;
use crate::api::owner_routes::proactivity_routes::schema::{
    action_mode_policy_schema, approve_representation_body_schema,
    decline_representation_body_schema, digest_assembled_schema, representation_approved_schema,
    representation_declined_schema, set_action_mode_body_schema,
};
use crate::api::owner_routes::recovery_kit_target_routes::pad_access::{
    pad_access_answer_schema, pad_access_body_schema,
};
use crate::api::owner_routes::recovery_kit_target_routes::root_doors::{
    anchor_body_schema, confirm_body_schema, issue_body_schema, restore_body_schema,
};
use crate::api::owner_routes::recovery_kit_target_routes::{
    root_work_answer_schema, run_root_request_body_schema,
};
use crate::api::owner_routes::root_routes::{
    pin_root_body_schema, repin_view_schema, root_request_body_schema,
};
use crate::api::owner_routes::schema::{decide_run_body_schema, run_resolved_schema};

/// Binds each route's REST shapes.
pub(super) fn merge(spec: &mut Value) {
    super::bind(
        spec,
        "/v1/owner/pads/read",
        "post",
        read_pads_body_schema(),
        diary_read_outcome_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/proactivity/action-mode",
        "post",
        set_action_mode_body_schema(),
        action_mode_policy_schema(),
        &[],
    );
    super::bind_answer(
        spec,
        "/v1/owner/proactivity/digest/assemble",
        "post",
        digest_assembled_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/recovery-kit/pad-access",
        "post",
        pad_access_body_schema(),
        pad_access_answer_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/representation/approve",
        "post",
        approve_representation_body_schema(),
        representation_approved_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/representation/decline",
        "post",
        decline_representation_body_schema(),
        representation_declined_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/roots/requests",
        "post",
        root_request_body_schema(),
        owner_work_view_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/roots/pin",
        "post",
        pin_root_body_schema(),
        repin_view_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/roots/anchor",
        "post",
        anchor_body_schema(),
        root_work_answer_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/roots/restore",
        "post",
        restore_body_schema(),
        root_work_answer_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/roots/issue",
        "post",
        issue_body_schema(),
        root_work_answer_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/roots/confirm",
        "post",
        confirm_body_schema(),
        root_work_answer_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/roots/requests/run",
        "post",
        run_root_request_body_schema(),
        root_work_answer_schema(),
        &[],
    );
    super::bind(
        spec,
        "/v1/owner/runs/approve",
        "post",
        decide_run_body_schema(),
        run_resolved_schema(),
        &[super::CHANGED],
    );
    super::bind(
        spec,
        "/v1/owner/runs/decline",
        "post",
        decide_run_body_schema(),
        run_resolved_schema(),
        &[super::CHANGED],
    );
    super::bind(
        spec,
        "/v1/owner/runs/hold/resume",
        "post",
        held_run_body_schema(),
        held_run_view_schema(),
        &[],
    );
}
