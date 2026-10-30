//! The `/v1/owner` routes [`super`] serves, one row per method and path:
//! the router and the OpenAPI document read this one table (FIX 8931).

use axum::routing::{get, post};

use super::super::{OwnerRoute, OwnerTable};
use super::{
    approve_skill_activation, approve_skill_permissions, bind_hooks, hook_bindings, import_skill,
    install_from_hub, installed, line_chats, pack_organs, place_agent_world,
    prepare_skill_activation, put, put_organ_build, qualify_hooks, ref_sync, remove_pack,
    restore_default_skills, restore_skill, set_hook_enabled, set_ref_sync, setup_answer,
    setup_prepare, setup_verify, setup_view, skill_receipts, slack_install, slack_manifest,
    sync_pack, sync_skill,
};

pub(in super::super) fn owner_table() -> OwnerTable {
    let mut table = vec![
        (
            OwnerRoute {
                method: "get",
                path: "/packs",
                summary: "Every active installation.",
                row: None,
            },
            get(installed),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs",
                summary: "Install a pack folder, or replace the one under its name.",
                row: None,
            },
            post(put),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/install",
                summary: "Fetch a pack from a configured hub at a pin and install it.",
                row: None,
            },
            post(install_from_hub),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/packs/setup",
                summary: "The owner's guided setup of one pack (OF-378), readable while the pack is still a Candidate.",
                row: None,
            },
            get(setup_view),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/setup/prepare",
                summary: "Open, or resume, the setup.",
                row: None,
            },
            post(setup_prepare),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/setup/answer",
                summary: "One typed answer, or one card action.",
                row: None,
            },
            post(setup_answer),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/setup/verify",
                summary: "Check one connection before the pack uses it.",
                row: None,
            },
            post(setup_verify),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/packs/slack/manifest",
                summary: "The Slack app manifest at this host's public origin, to paste at api.slack.com/apps (OF-519).",
                row: None,
            },
            get(slack_manifest),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/slack/install",
                summary: "One link that installs the Slack app to the owner's workspace (OF-519).",
                row: None,
            },
            post(slack_install),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/packs/hooks",
                summary: "Every hook binding, enabled or not.",
                row: None,
            },
            get(hook_bindings),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/hooks/bind",
                summary: "The owner's consent binds an installed pack's hooks; a hub install never does by itself.",
                row: None,
            },
            post(bind_hooks),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/hooks/qualify",
                summary: "A Candidate hub pack's hooks take their test, a replay over past entries that lands nothing.",
                row: None,
            },
            post(qualify_hooks),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/agent/world",
                summary: "The owner's answer to a travelling AgentPack held for its world (needs_world).",
                row: None,
            },
            post(place_agent_world),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/hooks/enabled",
                summary: "The owner's dial on one binding.",
                row: None,
            },
            post(set_hook_enabled),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/remove",
                summary: "The owner removes an installed pack.",
                row: None,
            },
            post(remove_pack),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/packs/ref-sync",
                summary: "The ref's stored policy, or null when it follows its installed pin.",
                row: None,
            },
            get(ref_sync),
        ),
        (
            OwnerRoute {
                method: "put",
                path: "/packs/ref-sync",
                summary: "Set one ref's policy and pin.",
                row: None,
            },
            axum::routing::put(set_ref_sync),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/sync",
                summary: "Refetch an installed hub pack at its ref's policy and install it.",
                row: None,
            },
            post(sync_pack),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/packs/organs",
                summary: "Every organ of an Active installation, with the platforms this vault holds a build for.",
                row: None,
            },
            get(pack_organs),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/organs/build",
                summary: "Hold one organ build for a staged pack source.",
                row: None,
            },
            post(put_organ_build),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/skills/import",
                summary: "Import a shipped library skill, or a hub skill at a pin.",
                row: None,
            },
            post(import_skill),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/skills/restore",
                summary: "Re-import a deleted or retired library skill as a fresh Candidate; an unchanged one is left alone.",
                row: None,
            },
            post(restore_skill),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/skills/restore-defaults",
                summary: "Restore every missing or retired embedded default as a fresh Candidate.",
                row: None,
            },
            post(restore_default_skills),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/skills/{entity}/sync",
                summary: "Refetch a hub skill at its ref's stored policy.",
                row: None,
            },
            post(sync_skill),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/skills/{entity}/permissions/approve",
                summary: "The owner's answer to a hub skill's permission ask; it activates the Candidate.",
                row: None,
            },
            post(approve_skill_permissions),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/packs/skills/{entity}/receipts",
                summary: "Skill receipts.",
                row: None,
            },
            get(skill_receipts),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/skills/{entity}/activation/prepare",
                summary: "The immutable held-out activation ask for a hub Candidate.",
                row: None,
            },
            post(prepare_skill_activation),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/skills/{entity}/activation/approve",
                summary: "The owner's consent to the ask they were shown.",
                row: None,
            },
            post(approve_skill_activation),
        ),
    ];
    table.extend(line_chats::owner_table());
    table
}
