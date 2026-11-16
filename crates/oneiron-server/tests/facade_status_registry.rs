#![cfg(oneiron_test_support)]
//! The facade's status for every refusal code it names (UC-11): the engine's
//! own arms, the credential-ask refusals, and each door lane's table
//! (browser, `ai.ask_image`, `vault.artifacts.image.edit`, live run, repo),
//! asked in the facade's order. `ai.ask_image`'s table also names
//! `kept_on_device`, `world_route_not_admitted`, `budget_denied`,
//! `invalid_request`, `rate_limited` and `quota_spent`, which the engine's
//! arms answer first. An unnamed code takes 500. Run with:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test facade_status_registry`.

use oneiron_server::test_doors::memory_code_status::facade_status;

/// Each code and the status the facade answers it with.
const PINNED: &[(&str, u16)] = &[
    // The engine's own vocabulary.
    ("BAD_REQUEST", 400),
    ("WRONG_ROOT", 400),
    ("NOT_FOUND", 404),
    ("FORBIDDEN", 403),
    ("LEASE_REQUIRED", 403),
    ("OWNER_BINDING_REQUIRED", 403),
    ("HOST_ACTION_REQUIRES_SUPPORT_GRANT", 403),
    ("OFF_RECORD_ROOM_MANAGEMENT_CONSENT_UNAVAILABLE", 403),
    ("INVALID_STATE", 409),
    ("OFF_RECORD_SESSION_DOOR", 409),
    ("VAULT_LOCKED_SINGLE_WRITER", 409),
    ("AGENT_THREAD_WALK_IN_FORBIDDEN", 409),
    ("IDENTITY_UNSETTLED", 409),
    ("WORLD_RECIPIENT_LIMIT", 409),
    ("WORLD_PLACEMENT_UNVERIFIABLE", 409),
    ("SANDBOX_PROPOSAL_DISK_FLOOR", 507),
    ("BUDGET_SPENT", 402),
    ("PENDING_ASK", 202),
    ("CHECK_IN_PENDING", 202),
    ("PACED_HOLD", 202),
    ("MODEL_UNAVAILABLE", 503),
    ("MODEL_PIN_UNAVAILABLE", 409),
    ("INVENTED_REFERENCE", 422),
    ("HOOK_RESULT_NOT_RETAINED", 409),
    ("INTERNAL_SERVER_ERROR", 500),
    // The OpenAI proxy's codes, which the engine's arms answer.
    ("timeout", 504),
    ("rate_limited", 429),
    ("quota_spent", 429),
    ("upstream_error", 502),
    ("upstream_auth", 502),
    ("label_read", 502),
    ("kept_on_device", 503),
    ("world_route_not_admitted", 503),
    ("recall_failed", 503),
    ("llm_unavailable", 503),
    ("budget_denied", 402),
    ("model_not_found", 404),
    ("connector_auth_required", 401),
    ("memory_withheld", 403),
    ("session_refused", 403),
    ("scope_refused", 403),
    ("verb_unbound", 403),
    ("connector_unregistered", 403),
    ("connector_grant_revoked", 403),
    ("extraction_egress_denied", 403),
    ("n_unsupported", 400),
    ("stream_unsupported", 400),
    ("user_message_required", 400),
    ("invalid_request", 400),
    ("route_selector_forbidden", 400),
    // A render's and a frozen vault's.
    ("render_deadline", 503),
    ("render_memory_floor", 503),
    ("render_disk_floor", 503),
    ("writes_frozen", 503),
    // A credential call settlement's refusals (ARCH-0080 §3 Ask).
    ("CREDENTIAL_MISSING", 403),
    ("CREDENTIAL_REVOKED", 403),
    ("CREDENTIAL_EXPIRED", 403),
    ("CREDENTIAL_CHANGED", 403),
    ("CREDENTIAL_UNAVAILABLE", 409),
    ("SCOPE_REFUSED", 403),
    ("CONTEXT_UNAVAILABLE", 409),
    // The browser doors'.
    ("needs_press", 409),
    ("browser_timeout", 504),
    ("browser_url_refused", 403),
    ("browser_destination_refused", 403),
    ("browser_input_invalid", 422),
    ("browser_secret_refused", 403),
    ("browser_unavailable", 503),
    // `ai.ask_image`'s.
    ("empty_question", 400),
    ("box_reads_whole_image", 400),
    ("contract_not_answered", 400),
    ("invalid_question", 400),
    ("principal_required", 403),
    ("call_not_admitted", 402),
    ("content_filtered", 422),
    ("pixels_missing", 500),
    ("decision_failed", 502),
    ("provider_auth", 502),
    ("empty_response", 502),
    ("provider_unavailable", 502),
    ("no_model_configured", 503),
    ("model_route_not_served", 503),
    // `vault.artifacts.image.edit`'s.
    ("image_not_an_image", 400),
    ("image_no_ops", 400),
    ("image_too_many_ops", 400),
    ("image_bad_request", 400),
    ("image_unknown_verb", 400),
    ("image_schema_mismatch", 400),
    ("image_unsupported", 422),
    ("image_too_large", 413),
    ("image_stale_base", 409),
    ("image_no_node", 503),
    ("image_budget", 503),
    ("image_cancelled", 503),
    ("image_revoked", 503),
    ("image_deadline_exceeded", 503),
    ("image_internal", 500),
    ("image_unnamed", 500),
    // The live-run guard's.
    ("live_run_required", 400),
    ("live_run_invalid", 400),
    ("live_run_unavailable", 403),
    ("live_run_stale", 409),
    ("live_run_busy", 409),
    ("live_run_attached", 409),
    // The repo doors'.
    ("repo_no_membership", 403),
    ("repo_membership_held", 409),
    ("repo_wrong_repo", 403),
    ("repo_wrong_ref", 403),
    ("repo_path_outside_scope", 403),
    ("repo_stale_lease", 409),
    ("repo_lane_unreadable", 403),
    ("repo_review_policy_required", 409),
    ("repo_provenance_required", 409),
    ("repo_publication_policy_required", 409),
    ("repo_work_base_changed", 409),
    // A code no table names.
    ("uc11_unnamed_code", 500),
];

#[test]
fn every_refusal_code_keeps_its_status() {
    let moved: Vec<String> = PINNED
        .iter()
        .filter_map(|&(code, pinned)| {
            let status = facade_status(code);
            (status != pinned).then(|| format!("{code}: pinned {pinned}, answered {status}"))
        })
        .collect();
    assert!(
        moved.is_empty(),
        "codes whose facade status moved: {moved:#?}"
    );
}
