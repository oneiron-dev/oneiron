//! The REST shapes of owner routes that mirror no SDK row (FIX 4782, FIX
//! 10289, FIX 11103, FIX 11611): each body and answer is read from the type
//! the route reads or writes, and each refusal it answers beside the owner
//! door's 403. Bound
//! after the owner table wrote its generic operations, so the document
//! teaches a client the fields the route takes, with no SDK row added.

mod routes_backups_to_signing_keys;
mod routes_coach;
mod routes_connectors;
mod routes_packs;
mod routes_pads_to_runs;
mod routes_secret_scan_to_skills;
mod routes_space_posting_to_worlds;

use serde_json::{Value, json};

use oneiron_contracts::code_run::vault_read::request_schema;

use crate::api::owner_routes::browser_takeover_routes::{
    browser_input_body_schema, browser_input_reply_schema, browser_return_body_schema,
    browser_return_reply_schema, browser_run_request_body_schema, browser_takeover_schema,
};
use crate::api::owner_routes::checkpoint_policy_routes::{
    clear_policy_body_schema, policy_view_schema, select_policy_body_schema,
};
use crate::api::owner_routes::concern_routes::{
    concern_apply_body_schema, concern_apply_outcome_schema, concern_card_summary_schema,
    concern_move_body_schema, concern_move_outcome_schema, concern_outcome_body_schema,
    concern_prompt_inject_body_schema, concern_prompt_inject_outcome_schema,
};
use crate::api::owner_routes::conflict_routes::{
    conflict_settled_schema, revert_settlement_body_schema, review_held_schema,
    review_resumed_schema, review_scope_body_schema, settle_conflict_body_schema,
    settlement_reverted_schema,
};
use crate::api::owner_routes::connector_admission_routes::schema::{
    accept_request_body_schema, admitted_slate_schema, attest_request_body_schema,
    connector_key_schema, enabled_request_body_schema, qualify_request_body_schema,
    refresh_request_body_schema, refreshed_schema, register_request_body_schema, registered_schema,
};
use crate::api::owner_routes::connector_consent_routes::{
    consent_request_body_schema, consented_schema,
};
use crate::api::owner_routes::connector_subscription_routes::{
    channel_subscription_schema, revoke_subscription_body_schema, subscribe_request_body_schema,
    subscription_revoked_schema,
};
use crate::api::owner_routes::conversation_learning_routes::{
    learning_reply_schema, own_reply_schema, set_learning_body_schema, set_own_body_schema,
};
use crate::api::owner_routes::courtesy_delete_routes::{
    courtesy_answer_body_schema, courtesy_incoming_schema, courtesy_send_body_schema,
    courtesy_sent_schema,
};
use crate::api::owner_routes::craft_candidate_routes::{
    craft_answer_body_schema, craft_verdict_schema,
};
use crate::api::owner_routes::desktop_takeover_routes::{
    desktop_input_body_schema, desktop_input_reply_schema, desktop_return_reply_schema,
    desktop_run_request_body_schema, desktop_takeover_schema,
};
use crate::api::owner_routes::diary_routes::{
    diary_grant_body_schema, diary_grant_schema, diary_read_outcome_schema,
    diary_review_body_schema, diary_review_schema, read_diary_body_schema,
};
use crate::api::owner_routes::dreamer_maintenance_routes::{
    applied_maintenance_schema, apply_action_mode_body_schema, maintenance_revert_schema,
    revert_maintenance_body_schema,
};
use crate::api::owner_routes::dreamer_routes::{
    change_reverted_schema, dreamer_pause_body_schema, dreamer_paused_schema,
    revert_change_body_schema,
};
use crate::api::owner_routes::embedding_space_routes::{
    clear_refused_body_schema, embedding_spaces_view_schema,
};
use crate::api::owner_routes::federation_connect_routes::{
    accept_connect_body_schema, connect_accepted_schema, connect_grant_schema,
    connect_offer_schema, mint_grant_body_schema, offer_connect_body_schema,
};
use crate::api::owner_routes::history_routes::{
    erase_history_body_schema, erase_outcome_schema, erased_schema, execute_erase_body_schema,
};
use crate::api::owner_routes::intent_routes::{intent_stated_schema, state_intent_body_schema};
use crate::api::owner_routes::model_setting_routes::model_settings_schema;
use crate::api::owner_routes::owner_work_routes::{
    bundle_publication_body_schema, owner_work_view_schema,
};
use crate::api::owner_routes::peer_confidence_routes::{
    grant_travel_schema, peer_scale_schema, set_grant_travel_body_schema,
    set_peer_scale_body_schema,
};
use crate::api::owner_routes::proactivity_routes::schema::{
    answer_identity_ask_body_schema, identity_settled_schema,
};
use crate::api::owner_routes::recovery_kit_routes::{
    anchor_advance_body_schema, anchor_advance_schema,
};
use crate::api::owner_routes::schema::{
    cleanup_accepted_schema, cleanup_review_schema, cleanup_settings_body_schema,
    decide_cleanup_body_schema, decide_import_body_schema, import_approved_schema,
    import_declined_schema, import_preview_schema, preview_import_body_schema, rehearsal_schema,
    rehearse_request_body_schema, restore_archived_body_schema, revert_cleanup_run_body_schema,
    run_reverted_schema,
};
use crate::api::owner_routes::shared_training_setup_routes::{
    answer_setup_body_schema, setup_reply_schema,
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
    bind(
        spec,
        "/v1/owner/connectors/consent",
        "post",
        consent_request_body_schema(),
        consented_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/connectors/enabled",
        "post",
        enabled_request_body_schema(),
        connector_key_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/connectors/qualify",
        "post",
        qualify_request_body_schema(),
        connector_key_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/connectors/attest",
        "post",
        attest_request_body_schema(),
        connector_key_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/connectors/refresh",
        "post",
        refresh_request_body_schema(),
        refreshed_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/connectors/register",
        "post",
        register_request_body_schema(),
        registered_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/connectors/slate/accept",
        "post",
        accept_request_body_schema(),
        admitted_slate_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/connectors/subscriptions",
        "post",
        subscribe_request_body_schema(),
        channel_subscription_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/conversation-learning",
        "put",
        set_learning_body_schema(),
        learning_reply_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/conversation-learning/me",
        "put",
        set_own_body_schema(),
        own_reply_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/conversation-learning/setup",
        "put",
        answer_setup_body_schema(),
        setup_reply_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/diary/read",
        "post",
        read_diary_body_schema(),
        diary_read_outcome_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/dreamer/maintenance/action-mode/apply",
        "post",
        apply_action_mode_body_schema(),
        applied_maintenance_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/dreamer/maintenance/revert",
        "post",
        revert_maintenance_body_schema(),
        maintenance_revert_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/dreamer/pause",
        "post",
        dreamer_pause_body_schema(),
        dreamer_paused_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/dreamer/resume",
        "post",
        dreamer_pause_body_schema(),
        dreamer_paused_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/dreamer/revert",
        "post",
        revert_change_body_schema(),
        change_reverted_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/embedding-spaces/refused/clear",
        "post",
        clear_refused_body_schema(),
        embedding_spaces_view_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/federation/grant-travel",
        "post",
        set_grant_travel_body_schema(),
        grant_travel_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/federation/peer-confidence",
        "post",
        set_peer_scale_body_schema(),
        peer_scale_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/courtesy-delete/send",
        "post",
        courtesy_send_body_schema(),
        courtesy_sent_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/courtesy-delete/answer",
        "post",
        courtesy_answer_body_schema(),
        courtesy_incoming_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/craft-candidates/answer",
        "post",
        craft_answer_body_schema(),
        craft_verdict_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/federation/connect/grants",
        "post",
        mint_grant_body_schema(),
        connect_grant_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/federation/connect/offer",
        "post",
        offer_connect_body_schema(),
        connect_offer_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/federation/connect/accept",
        "post",
        accept_connect_body_schema(),
        connect_accepted_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/history/erase",
        "post",
        erase_history_body_schema(),
        erase_outcome_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/history/erase/execute",
        "post",
        execute_erase_body_schema(),
        erased_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/identity/asks/answer",
        "post",
        answer_identity_ask_body_schema(),
        identity_settled_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/imports/preview",
        "post",
        preview_import_body_schema(),
        import_preview_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/imports/approve",
        "post",
        decide_import_body_schema(),
        import_approved_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/imports/decline",
        "post",
        decide_import_body_schema(),
        import_declined_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/inbox/concern/outcome",
        "post",
        concern_outcome_body_schema(),
        concern_card_summary_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/inbox/concern/move",
        "post",
        concern_move_body_schema(),
        concern_move_outcome_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/inbox/concern/apply",
        "post",
        concern_apply_body_schema(),
        concern_apply_outcome_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/inbox/concern/apply-prompt-inject",
        "post",
        concern_prompt_inject_body_schema(),
        concern_prompt_inject_outcome_schema(),
        &[],
    );
    routes_backups_to_signing_keys::merge(spec);
    routes_coach::merge(spec);
    routes_connectors::merge(spec);
    routes_packs::merge(spec);
    routes_pads_to_runs::merge(spec);
    routes_secret_scan_to_skills::merge(spec);
    routes_space_posting_to_worlds::merge(spec);
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
    bind_operation(
        spec,
        path,
        method,
        Some(body),
        json_answer(answer),
        refusals,
    );
}

/// [`bind`] for a route that reads no body: the operation declares none
/// (FIX 11613).
fn bind_answer(
    spec: &mut Value,
    path: &str,
    method: &str,
    answer: Value,
    refusals: &[(&str, &str)],
) {
    bind_operation(spec, path, method, None, json_answer(answer), refusals);
}

/// [`bind`] for a route that answers the screen as a PNG image (FIX 11613).
fn bind_image_answer(
    spec: &mut Value,
    path: &str,
    method: &str,
    body: Value,
    refusals: &[(&str, &str)],
) {
    let answer = json!({
        "description": "The screen as a PNG.",
        "content": {"image/png": {"schema": {"type": "string", "format": "binary"}}}
    });
    bind_operation(spec, path, method, Some(body), answer, refusals);
}

/// The 200 response of a route's typed JSON answer.
fn json_answer(answer: Value) -> Value {
    json!({
        "description": "The route's typed answer.",
        "content": {"application/json": {"schema": answer}}
    })
}

/// Writes one operation's request body (or drops it when the route reads
/// none), its 200 response and its refusals.
fn bind_operation(
    spec: &mut Value,
    path: &str,
    method: &str,
    body: Option<Value>,
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
    match body {
        Some(body) => {
            operation["requestBody"] =
                json!({"required": true, "content": {"application/json": {"schema": body}}});
        }
        None => {
            if let Some(operation) = operation.as_object_mut() {
                operation.remove("requestBody");
            }
        }
    }
    let Some(responses) = operation
        .get_mut("responses")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    responses.insert("200".to_owned(), answer);
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
