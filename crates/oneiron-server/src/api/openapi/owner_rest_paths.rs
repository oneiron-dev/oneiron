//! The REST shapes of owner routes that mirror no SDK row (FIX 4782, FIX
//! 10289, FIX 11103, FIX 11611): each body and answer is read from the type
//! the route reads or writes, and each refusal it answers beside the owner
//! door's 403. Bound
//! after the owner table wrote its generic operations, so the document
//! teaches a client the fields the route takes, with no SDK row added.

use serde_json::{Value, json};

use oneiron_contracts::code_run::vault_read::request_schema;

use crate::api::owner_routes::browser_takeover_routes::{
    browser_input_body_schema, browser_input_reply_schema, browser_return_body_schema,
    browser_return_reply_schema, browser_run_request_body_schema, browser_takeover_schema,
};
use crate::api::owner_routes::checkpoint_policy_routes::{
    clear_policy_body_schema, policy_view_schema, select_policy_body_schema,
};
use crate::api::owner_routes::conflict_routes::{
    conflict_settled_schema, revert_settlement_body_schema, review_held_schema,
    review_resumed_schema, review_scope_body_schema, settle_conflict_body_schema,
    settlement_reverted_schema,
};
use crate::api::owner_routes::connector_subscription_routes::{
    revoke_subscription_body_schema, subscription_revoked_schema,
};
use crate::api::owner_routes::desktop_takeover_routes::{
    desktop_input_body_schema, desktop_input_reply_schema, desktop_return_reply_schema,
    desktop_run_request_body_schema, desktop_takeover_schema,
};
use crate::api::owner_routes::diary_routes::{
    diary_grant_body_schema, diary_grant_schema, diary_review_body_schema, diary_review_schema,
};
use crate::api::owner_routes::intent_routes::{intent_stated_schema, state_intent_body_schema};
use crate::api::owner_routes::model_setting_routes::model_settings_schema;
use crate::api::owner_routes::owner_work_routes::{
    bundle_publication_body_schema, owner_work_view_schema,
};
use crate::api::owner_routes::recovery_kit_routes::{
    anchor_advance_body_schema, anchor_advance_schema,
};
use crate::api::owner_routes::schema::{
    cleanup_accepted_schema, cleanup_review_schema, cleanup_settings_body_schema,
    decide_cleanup_body_schema, rehearsal_schema, rehearse_request_body_schema,
    restore_archived_body_schema, revert_cleanup_run_body_schema, run_reverted_schema,
};
use crate::api::owner_routes::wire_health_routes::{
    outcome_recorded_schema, record_outcome_body_schema,
};
use crate::owner::persona::{ExportRequest, Exported};

/// The conflict a route answers when what it was asked on changed in the
/// vault first (`OwnerError::Changed`).
const CHANGED: (&str, &str) = (
    "409",
    "What the request was made on changed in the vault before it was written (`changed_since_review`): read it again and ask again.",
);

/// Binds each owner route's REST shapes.
pub(super) fn merge_owner_rest_shapes(spec: &mut Value) {
    bind(
        spec,
        "/v1/owner/bundles/publications",
        "post",
        bundle_publication_body_schema(),
        owner_work_view_schema(),
        &[
            (
                "400",
                "`home` is not a 32-hex install id, or the body names another field.",
            ),
            CHANGED,
        ],
    );
    bind(
        spec,
        "/v1/owner/persona/export",
        "post",
        request_schema::<ExportRequest>(),
        request_schema::<Exported>(),
        &[
            (
                "400",
                "`subject` is not an entity id, or the card cannot be issued as asked.",
            ),
            (
                "409",
                "The card changed after its preview (`changed_since_review`): preview it again and export that stamp.",
            ),
        ],
    );
    bind(
        spec,
        "/v1/owner/connectors/subscriptions/revoke",
        "post",
        revoke_subscription_body_schema(),
        subscription_revoked_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/custody-anchor",
        "post",
        anchor_advance_body_schema(),
        anchor_advance_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/diary/grants",
        "post",
        diary_grant_body_schema(),
        diary_grant_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/diary/review",
        "post",
        diary_review_body_schema(),
        diary_review_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/intents",
        "post",
        state_intent_body_schema(),
        intent_stated_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/settings/models",
        "post",
        model_settings_schema(),
        model_settings_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/wire-health/outcome",
        "post",
        record_outcome_body_schema(),
        outcome_recorded_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/backups/rehearse",
        "post",
        rehearse_request_body_schema(),
        rehearsal_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/browsers/input",
        "post",
        browser_input_body_schema(),
        browser_input_reply_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/browsers/return",
        "post",
        browser_return_body_schema(),
        browser_return_reply_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/browsers/take",
        "post",
        browser_run_request_body_schema(),
        browser_takeover_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/checkpoint-policy",
        "post",
        select_policy_body_schema(),
        policy_view_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/checkpoint-policy/clear",
        "post",
        clear_policy_body_schema(),
        policy_view_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/cleanup",
        "post",
        cleanup_settings_body_schema(),
        cleanup_review_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/cleanup/accept",
        "post",
        decide_cleanup_body_schema(),
        cleanup_accepted_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/cleanup/reject",
        "post",
        decide_cleanup_body_schema(),
        cleanup_review_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/cleanup/restore",
        "post",
        restore_archived_body_schema(),
        cleanup_review_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/cleanup/revert-run",
        "post",
        revert_cleanup_run_body_schema(),
        run_reverted_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/conflicts/revert",
        "post",
        revert_settlement_body_schema(),
        settlement_reverted_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/conflicts/review",
        "post",
        review_scope_body_schema(),
        review_resumed_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/conflicts/review/revoke",
        "post",
        review_scope_body_schema(),
        review_held_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/conflicts/settle",
        "post",
        settle_conflict_body_schema(),
        conflict_settled_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/desktops/input",
        "post",
        desktop_input_body_schema(),
        desktop_input_reply_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/desktops/return",
        "post",
        desktop_run_request_body_schema(),
        desktop_return_reply_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/desktops/take",
        "post",
        desktop_run_request_body_schema(),
        desktop_takeover_schema(),
        &[],
    );
}

/// Sets one operation's body and answer schemas and adds its refusals, where
/// the owner table already wrote that operation.
fn bind(
    spec: &mut Value,
    path: &str,
    method: &str,
    body: Value,
    answer: Value,
    refusals: &[(&str, &str)],
) {
    let Some(operation) = spec
        .get_mut("paths")
        .and_then(|paths| paths.get_mut(path))
        .and_then(|item| item.get_mut(method))
    else {
        return;
    };
    operation["requestBody"] =
        json!({"required": true, "content": {"application/json": {"schema": body}}});
    let Some(responses) = operation
        .get_mut("responses")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    responses.insert(
        "200".to_owned(),
        json!({
            "description": "The route's typed answer.",
            "content": {"application/json": {"schema": answer}}
        }),
    );
    for (status, description) in refusals {
        responses.insert(
            (*status).to_owned(),
            json!({
                "description": description,
                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ApiError"}}}
            }),
        );
    }
}
