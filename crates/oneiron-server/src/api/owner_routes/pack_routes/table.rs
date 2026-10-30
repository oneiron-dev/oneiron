//! The `/v1/owner` routes [`super`] serves, one row per method and path:
//! the router and the OpenAPI document read this one table (FIX 8931).

use axum::routing::{get, post};

use super::super::{OwnerRoute, OwnerTable, RestShape};
use super::schema::{
    activate_candidate_body_schema, activation_ask_view_schema, activation_request_body_schema,
    agent_world_body_schema, bind_hooks_body_schema, bound_hooks_schema, consent_row_schema,
    hook_enabled_body_schema, hook_enabled_schema, hook_qualification_schema,
    import_skill_body_schema, install_from_hub_body_schema, organ_build_schema,
    pack_install_receipt_schema, pack_put_schema, pack_setup_reply_schema,
    put_organ_build_body_schema, put_pack_body_schema, qualify_hooks_body_schema,
    ref_sync_view_schema, restore_skill_body_schema, set_ref_sync_body_schema,
    setup_answer_body_schema, setup_key_body_schema, setup_verify_body_schema, skill_row_schema,
    skill_rows_schema, skill_sync_schema, slack_install_link_schema,
    slack_install_request_body_schema, sync_pack_body_schema,
};
use super::{
    activate_candidate, approve_skill_activation, approve_skill_permissions, bind_hooks,
    hook_bindings, import_skill, install_from_hub, installed, line_chats, native_mail_identities,
    pack_lenses, pack_organs, place_agent_world, prepare_skill_activation, put, put_organ_build,
    put_pack_lens_component, qualify_hooks, ref_sync, remove_pack, restore_default_skills,
    restore_skill, set_hook_enabled, set_ref_sync, setup_answer, setup_prepare, setup_verify,
    setup_view, skill_receipts, slack_install, slack_manifest, sync_pack, sync_skill,
};

pub(in super::super) fn owner_table() -> OwnerTable {
    let mut table = vec![
        (
            OwnerRoute {
                method: "get",
                path: "/packs",
                summary: "Every active installation.",
                row: None,
                shape: None,
            },
            get(installed),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs",
                summary: "Install a pack folder, or replace the one under its name.",
                row: None,
                shape: Some(RestShape::json(put_pack_body_schema, pack_put_schema)),
            },
            post(put),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/install",
                summary: "Fetch a pack from a configured hub at a pin and install it.",
                row: None,
                shape: Some(RestShape::json(
                    install_from_hub_body_schema,
                    pack_put_schema,
                )),
            },
            post(install_from_hub),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/packs/setup",
                summary: "The owner's guided setup of one pack (OF-378), readable while the pack is still a Candidate.",
                row: None,
                shape: None,
            },
            get(setup_view),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/setup/prepare",
                summary: "Open, or resume, the setup.",
                row: None,
                shape: Some(RestShape::json(
                    setup_key_body_schema,
                    pack_setup_reply_schema,
                )),
            },
            post(setup_prepare),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/setup/answer",
                summary: "One typed answer, or one card action.",
                row: None,
                shape: Some(RestShape::json(
                    setup_answer_body_schema,
                    pack_setup_reply_schema,
                )),
            },
            post(setup_answer),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/setup/verify",
                summary: "Check one connection before the pack uses it.",
                row: None,
                shape: Some(RestShape::json(
                    setup_verify_body_schema,
                    pack_setup_reply_schema,
                )),
            },
            post(setup_verify),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/packs/slack/manifest",
                summary: "The Slack app manifest at this host's public origin, to paste at api.slack.com/apps (OF-519).",
                row: None,
                shape: None,
            },
            get(slack_manifest),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/slack/install",
                summary: "One link that installs the Slack app to the owner's workspace (OF-519).",
                row: None,
                shape: Some(RestShape::json(
                    slack_install_request_body_schema,
                    slack_install_link_schema,
                )),
            },
            post(slack_install),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/packs/hooks",
                summary: "Every hook binding, enabled or not.",
                row: None,
                shape: None,
            },
            get(hook_bindings),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/hooks/bind",
                summary: "The owner's consent binds an installed pack's hooks; a hub install never does by itself.",
                row: None,
                shape: Some(RestShape::json(bind_hooks_body_schema, bound_hooks_schema)),
            },
            post(bind_hooks),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/hooks/qualify",
                summary: "A Candidate hub pack's hooks take their test, a replay over past entries that lands nothing.",
                row: None,
                shape: Some(RestShape::json(
                    qualify_hooks_body_schema,
                    hook_qualification_schema,
                )),
            },
            post(qualify_hooks),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/activate",
                summary: "The owner activates a hub Candidate held for its advisories, or for code that is organs only.",
                row: None,
                shape: Some(RestShape::json(
                    activate_candidate_body_schema,
                    pack_put_schema,
                )),
            },
            post(activate_candidate),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/agent/world",
                summary: "The owner's answer to a travelling AgentPack held for its world (needs_world).",
                row: None,
                shape: Some(RestShape::json(agent_world_body_schema, pack_put_schema)),
            },
            post(place_agent_world),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/hooks/enabled",
                summary: "The owner's dial on one binding.",
                row: None,
                shape: Some(RestShape::json(
                    hook_enabled_body_schema,
                    hook_enabled_schema,
                )),
            },
            post(set_hook_enabled),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/remove",
                summary: "The owner removes an installed pack.",
                row: None,
                shape: Some(RestShape::json(
                    bind_hooks_body_schema,
                    pack_install_receipt_schema,
                )),
            },
            post(remove_pack),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/packs/ref-sync",
                summary: "The ref's stored policy, or null when it follows its installed pin.",
                row: None,
                shape: None,
            },
            get(ref_sync),
        ),
        (
            OwnerRoute {
                method: "put",
                path: "/packs/ref-sync",
                summary: "Set one ref's policy and pin.",
                row: None,
                shape: Some(RestShape::json(
                    set_ref_sync_body_schema,
                    ref_sync_view_schema,
                )),
            },
            axum::routing::put(set_ref_sync),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/sync",
                summary: "Refetch an installed hub pack at its ref's policy and install it.",
                row: None,
                shape: Some(RestShape::json(sync_pack_body_schema, pack_put_schema)),
            },
            post(sync_pack),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/packs/organs",
                summary: "Every organ of an Active installation, with the platforms this vault holds a build for.",
                row: None,
                shape: None,
            },
            get(pack_organs),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/organs/build",
                summary: "Hold one organ build for a staged pack source.",
                row: None,
                shape: Some(RestShape::json(
                    put_organ_build_body_schema,
                    organ_build_schema,
                )),
            },
            post(put_organ_build),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/packs/lenses",
                summary: "Every lens of every Active installation, bound to its skill.",
                row: None,
                shape: None,
            },
            get(pack_lenses),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/sources/{source_id}/lenses/{lens}/component",
                summary: "Hold one lens component build for a staged pack source.",
                row: None,
                shape: None,
            },
            post(put_pack_lens_component),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/skills/import",
                summary: "Import a shipped library skill, or a hub skill at a pin.",
                row: None,
                shape: Some(RestShape::json(import_skill_body_schema, skill_row_schema)),
            },
            post(import_skill),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/skills/restore",
                summary: "Re-import a deleted or retired library skill as a fresh Candidate; an unchanged one is left alone.",
                row: None,
                shape: Some(RestShape::json(restore_skill_body_schema, skill_row_schema)),
            },
            post(restore_skill),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/skills/restore-defaults",
                summary: "Restore every missing or retired embedded default as a fresh Candidate.",
                row: None,
                shape: Some(RestShape::no_body(skill_rows_schema)),
            },
            post(restore_default_skills),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/skills/{entity}/sync",
                summary: "Refetch a hub skill at its ref's stored policy.",
                row: None,
                shape: Some(RestShape::no_body(skill_sync_schema)),
            },
            post(sync_skill),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/skills/{entity}/permissions/approve",
                summary: "The owner's answer to a hub skill's permission ask; it activates the Candidate.",
                row: None,
                shape: Some(RestShape::no_body(consent_row_schema)),
            },
            post(approve_skill_permissions),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/packs/skills/{entity}/receipts",
                summary: "Skill receipts.",
                row: None,
                shape: None,
            },
            get(skill_receipts),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/skills/{entity}/activation/prepare",
                summary: "The immutable held-out activation ask for a hub Candidate.",
                row: None,
                shape: Some(RestShape::json(
                    activation_request_body_schema,
                    activation_ask_view_schema,
                )),
            },
            post(prepare_skill_activation),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/skills/{entity}/activation/approve",
                summary: "The owner's consent to the ask they were shown.",
                row: None,
                shape: Some(RestShape::json(
                    activation_request_body_schema,
                    consent_row_schema,
                )),
            },
            post(approve_skill_activation),
        ),
    ];
    table.extend(line_chats::owner_table());
    table.extend(native_mail_identities::owner_table());
    table
}
