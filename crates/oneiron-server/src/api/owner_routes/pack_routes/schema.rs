//! The OpenAPI schemas of the row-less `/v1/owner/packs*` writes (FIX 11611 part D):
//! `POST /v1/owner/packs`, `/packs/activate`, `/packs/agent/world`,
//! `/packs/hooks/bind`, `/packs/hooks/qualify`, `/packs/install`,
//! `/packs/organs/build`, `/packs/remove`, `/packs/setup/answer`,
//! `/packs/setup/prepare`, `/packs/setup/verify`, `/packs/skills/import`,
//! `/packs/skills/restore`, `/packs/skills/{entity}/activation/approve`,
//! `/packs/skills/{entity}/activation/prepare`, `/packs/slack/install` and
//! `/packs/sync`, plus `PUT /v1/owner/packs/ref-sync`. Their schema fns live
//! here, beside the route files' own.

use oneiron::skill_hub::pack_catalog::{PackInstallReceipt, PackOrganBuild};

use super::{
    ActivateCandidate, ActivationAskView, ActivationRequest, AgentWorld, BindHooks, ConsentRow,
    HookEnabled, HookQualification, ImportSkill, InstallFromHub, PackPut, PackSetupAnswerRequest,
    PackSetupKey, PackSetupReply, PackSetupVerifyRequest, PutOrganBuild, PutPack, QualifyHooks,
    RefSyncView, RestoreSkill, SetRefSync, SkillRow, SkillSync, SlackInstallRequest, SyncPack,
};
use crate::builtin_host::SlackInstallLink;

/// The OpenAPI schema of `POST /v1/owner/packs`'s body (FIX 11611):
/// [`PutPack`].
pub(crate) fn put_pack_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PutPack>()
}

/// The OpenAPI schema of the pack puts' answer (FIX 11611), shared by
/// `POST /v1/owner/packs`, `/packs/activate`, `/packs/agent/world`,
/// `/packs/install` and `/packs/sync`: [`PackPut`].
pub(crate) fn pack_put_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PackPut>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/activate`'s body:
/// [`ActivateCandidate`].
pub(crate) fn activate_candidate_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ActivateCandidate>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/agent/world`'s body
/// (FIX 11611): [`AgentWorld`].
pub(crate) fn agent_world_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<AgentWorld>()
}

/// The OpenAPI schema of the pack-name writes' body (FIX 11611), shared by
/// `POST /v1/owner/packs/hooks/bind` and `POST /v1/owner/packs/remove`:
/// [`BindHooks`].
pub(crate) fn bind_hooks_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<BindHooks>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/hooks/bind`'s answer
/// (FIX 11611): the bound claims, each as 32 hex.
pub(crate) fn bound_hooks_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<Vec<String>>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/hooks/qualify`'s body
/// (FIX 11611): [`QualifyHooks`].
pub(crate) fn qualify_hooks_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<QualifyHooks>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/hooks/qualify`'s answer
/// (FIX 11611): [`HookQualification`].
pub(crate) fn hook_qualification_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<HookQualification>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/install`'s body (FIX 11611):
/// [`InstallFromHub`].
pub(crate) fn install_from_hub_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<InstallFromHub>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/organs/build`'s body
/// (FIX 11611): [`PutOrganBuild`].
pub(crate) fn put_organ_build_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PutOrganBuild>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/organs/build`'s answer
/// (FIX 11611): [`PackOrganBuild`].
pub(crate) fn organ_build_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PackOrganBuild>()
}

/// The OpenAPI schema of `PUT /v1/owner/packs/ref-sync`'s body (FIX 11611):
/// [`SetRefSync`].
pub(crate) fn set_ref_sync_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<SetRefSync>()
}

/// The OpenAPI schema of `PUT /v1/owner/packs/ref-sync`'s answer (FIX 11611):
/// [`RefSyncView`].
pub(crate) fn ref_sync_view_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<RefSyncView>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/remove`'s answer (FIX 11611):
/// [`PackInstallReceipt`].
pub(crate) fn pack_install_receipt_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PackInstallReceipt>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/setup/answer`'s body
/// (FIX 11611): [`PackSetupAnswerRequest`].
pub(crate) fn setup_answer_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PackSetupAnswerRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/setup/prepare`'s body
/// (FIX 11611): [`PackSetupKey`].
pub(crate) fn setup_key_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PackSetupKey>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/setup/verify`'s body
/// (FIX 11611): [`PackSetupVerifyRequest`].
pub(crate) fn setup_verify_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PackSetupVerifyRequest>()
}

/// The OpenAPI schema of the setup writes' answer (FIX 11611), shared by
/// `POST /v1/owner/packs/setup/answer`, `/packs/setup/prepare` and
/// `/packs/setup/verify`: [`PackSetupReply`].
pub(crate) fn pack_setup_reply_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PackSetupReply>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/skills/import`'s body
/// (FIX 11611): [`ImportSkill`].
pub(crate) fn import_skill_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ImportSkill>()
}

/// The OpenAPI schema of the skill rows' answer (FIX 11611), shared by
/// `POST /v1/owner/packs/skills/import` and `/packs/skills/restore`:
/// [`SkillRow`].
pub(crate) fn skill_row_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<SkillRow>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/skills/restore`'s body
/// (FIX 11611): [`RestoreSkill`].
pub(crate) fn restore_skill_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<RestoreSkill>()
}

/// The OpenAPI schema of
/// `POST /v1/owner/packs/skills/{entity}/activation/prepare`'s body, shared
/// with `.../activation/approve` (FIX 11611): [`ActivationRequest`].
pub(crate) fn activation_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ActivationRequest>()
}

/// The OpenAPI schema of the consent rows' answer (FIX 11611), shared by
/// `POST /v1/owner/packs/skills/{entity}/activation/approve` (and the
/// bodiless `.../permissions/approve`): [`ConsentRow`].
pub(crate) fn consent_row_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ConsentRow>()
}

/// The OpenAPI schema of
/// `POST /v1/owner/packs/skills/{entity}/activation/prepare`'s answer
/// (FIX 11611): [`ActivationAskView`].
pub(crate) fn activation_ask_view_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ActivationAskView>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/slack/install`'s body
/// (FIX 11611): [`SlackInstallRequest`].
pub(crate) fn slack_install_request_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<SlackInstallRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/slack/install`'s answer
/// (FIX 11611): [`SlackInstallLink`].
pub(crate) fn slack_install_link_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<SlackInstallLink>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/sync`'s body (FIX 11611):
/// [`SyncPack`].
pub(crate) fn sync_pack_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<SyncPack>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/hooks/enabled`'s body (FIX 11611):
/// [`HookEnabled`]. Its answer is `null`.
pub(crate) fn hook_enabled_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<HookEnabled>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/hooks/enabled`'s answer (FIX 11611): `null`.
pub(crate) fn hook_enabled_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<()>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/skills/restore-defaults`'s answer
/// (FIX 11611): one [`SkillRow`] per restored skill.
pub(crate) fn skill_rows_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<Vec<SkillRow>>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/skills/{entity}/sync`'s answer
/// (FIX 11611): [`SkillSync`].
pub(crate) fn skill_sync_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<SkillSync>()
}
