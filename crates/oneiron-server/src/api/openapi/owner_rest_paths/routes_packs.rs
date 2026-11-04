//! The REST shapes of the row-less `/v1/owner` routes under `/packs` (FIX 11611 part D):
//! one [`super::bind`] per route, called from [`super::merge_owner_rest_shapes`].

use serde_json::Value;

use super::{bind, bind_answer};
use crate::api::owner_routes::pack_preview_routes::{
    pack_import_preview_schema, preview_pack_body_schema,
};
use crate::api::owner_routes::pack_routes::hook_proposals::{
    hook_proposal_answer_body_schema, hook_proposal_schema,
};
use crate::api::owner_routes::pack_routes::schema::{
    activation_ask_view_schema, activation_request_body_schema, agent_world_body_schema,
    bind_hooks_body_schema, bound_hooks_schema, consent_row_schema, hook_enabled_body_schema,
    hook_enabled_schema, hook_qualification_schema, import_skill_body_schema,
    install_from_hub_body_schema, organ_build_schema, pack_install_receipt_schema, pack_put_schema,
    pack_setup_reply_schema, put_organ_build_body_schema, put_pack_body_schema,
    qualify_hooks_body_schema, ref_sync_view_schema, restore_skill_body_schema,
    set_ref_sync_body_schema, setup_answer_body_schema, setup_key_body_schema,
    setup_verify_body_schema, skill_row_schema, skill_rows_schema, skill_sync_schema,
    slack_install_link_schema, slack_install_request_body_schema, sync_pack_body_schema,
};
use crate::api::packs::defaults::{
    hub_import_receipt_schema, hub_import_receipts_schema, hub_skill_request_body_schema,
};

/// Binds each route's REST shapes.
pub(super) fn merge(spec: &mut Value) {
    bind(
        spec,
        "/v1/owner/packs",
        "post",
        put_pack_body_schema(),
        pack_put_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/activate",
        "post",
        crate::api::owner_routes::pack_routes::schema::activate_candidate_body_schema(),
        pack_put_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/agent/world",
        "post",
        agent_world_body_schema(),
        pack_put_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/defaults/import",
        "post",
        hub_skill_request_body_schema(),
        hub_import_receipt_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/defaults/restore-skill",
        "post",
        hub_skill_request_body_schema(),
        hub_import_receipt_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/hooks/bind",
        "post",
        bind_hooks_body_schema(),
        bound_hooks_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/hooks/qualify",
        "post",
        qualify_hooks_body_schema(),
        hook_qualification_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/install",
        "post",
        install_from_hub_body_schema(),
        pack_put_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/organs/build",
        "post",
        put_organ_build_body_schema(),
        organ_build_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/preview",
        "post",
        preview_pack_body_schema(),
        pack_import_preview_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/ref-sync",
        "put",
        set_ref_sync_body_schema(),
        ref_sync_view_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/remove",
        "post",
        bind_hooks_body_schema(),
        pack_install_receipt_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/setup/answer",
        "post",
        setup_answer_body_schema(),
        pack_setup_reply_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/setup/prepare",
        "post",
        setup_key_body_schema(),
        pack_setup_reply_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/setup/verify",
        "post",
        setup_verify_body_schema(),
        pack_setup_reply_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/skills/import",
        "post",
        import_skill_body_schema(),
        skill_row_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/skills/restore",
        "post",
        restore_skill_body_schema(),
        skill_row_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/skills/{entity}/activation/approve",
        "post",
        activation_request_body_schema(),
        consent_row_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/skills/{entity}/activation/prepare",
        "post",
        activation_request_body_schema(),
        activation_ask_view_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/slack/install",
        "post",
        slack_install_request_body_schema(),
        slack_install_link_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/sync",
        "post",
        sync_pack_body_schema(),
        pack_put_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/hooks/enabled",
        "post",
        hook_enabled_body_schema(),
        hook_enabled_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/hooks/proposals/approve",
        "post",
        hook_proposal_answer_body_schema(),
        hook_proposal_schema(),
        &[],
    );
    bind(
        spec,
        "/v1/owner/packs/hooks/proposals/discard",
        "post",
        hook_proposal_answer_body_schema(),
        hook_proposal_schema(),
        &[],
    );
    // The four writes below read no body: the entity, if any, travels in the path.
    bind_answer(
        spec,
        "/v1/owner/packs/defaults/restore",
        "post",
        hub_import_receipts_schema(),
        &[],
    );
    bind_answer(
        spec,
        "/v1/owner/packs/skills/restore-defaults",
        "post",
        skill_rows_schema(),
        &[],
    );
    bind_answer(
        spec,
        "/v1/owner/packs/skills/{entity}/sync",
        "post",
        skill_sync_schema(),
        &[],
    );
    bind_answer(
        spec,
        "/v1/owner/packs/skills/{entity}/permissions/approve",
        "post",
        consent_row_schema(),
        &[],
    );
}
