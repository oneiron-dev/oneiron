//! `/v1/owner/packs/skills`: hub skills import, restore, sync, take their
//! permission and held-out activation asks, and read their receipts here
//! (OF-213).

use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::response::Json;
use oneiron::EntityId;
use oneiron::consent::ConsentReceipt;
use oneiron::skill_hub::pack_catalog::hub_pin;
use oneiron::skill_hub::{
    HubAdmissionReceipt, HubAskSurface, HubImportReceipt, HubRef, HubSyncDisposition,
};
use serde::{Deserialize, Serialize};

use super::super::{OwnerReply, blocking, owner};
use super::entity_id;
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::OwnerError;
use crate::server::SyncServer;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ImportSkill {
    /// A shipped library subtree, imported at the released commit.
    #[serde(default)]
    subtree: Option<String>,
    /// Else a configured hub, as 32 hex, with the fields below.
    #[serde(default)]
    hub: Option<String>,
    #[serde(default)]
    folder: Option<String>,
    #[serde(default)]
    pin_type: Option<String>,
    #[serde(default)]
    pin_value: Option<String>,
    #[serde(default)]
    publisher: Option<String>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub(super) struct SkillRow {
    /// The skill, as 32 hex.
    entity: String,
}

fn skill_row(entity: EntityId) -> SkillRow {
    SkillRow {
        entity: entity.to_hex(),
    }
}

/// `POST /v1/owner/packs/skills/import`: import a shipped library skill, or
/// a hub skill at a pin. A hub skill lands Candidate behind one permission
/// ask; its dependency advisories land with it.
pub(super) async fn import_skill(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ImportSkill>,
) -> OwnerReply<SkillRow> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let row = blocking(move || {
        let vault = server.vault();
        let at = vault.now_recorded_at();
        let occurred = oneiron::TimeRange { start: at, end: at };
        let entity = match request {
            ImportSkill {
                subtree: Some(subtree),
                hub: None,
                folder: None,
                pin_type: None,
                pin_value: None,
                publisher: None,
            } => vault.import_default_hub_skill(&subtree, occurred, at)?,
            ImportSkill {
                subtree: None,
                hub: Some(hub),
                folder: Some(folder),
                pin_type: Some(pin_type),
                pin_value: Some(pin_value),
                publisher: Some(publisher),
            } => vault.import_skill_from_hub_ref(
                &owner,
                entity_id(&hub, "hub")?,
                &folder,
                hub_pin(&pin_type, &pin_value)?,
                &publisher,
            )?,
            _ => {
                return Err(OwnerError::Invalid(
                    "send a subtree, or hub, folder, pin_type, pin_value and publisher".to_owned(),
                ));
            }
        };
        Ok(skill_row(entity))
    })
    .await?;
    Ok(Json(row))
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RestoreSkill {
    subtree: String,
}

/// `POST /v1/owner/packs/skills/restore`: re-import a deleted or retired
/// library skill as a fresh Candidate; an unchanged one is left alone.
pub(super) async fn restore_skill(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<RestoreSkill>,
) -> OwnerReply<SkillRow> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let row = blocking(move || {
        let at = server.vault().now_recorded_at();
        let occurred = oneiron::TimeRange { start: at, end: at };
        Ok(skill_row(server.vault().restore_default_hub_skill(
            &owner,
            &request.subtree,
            occurred,
            at,
        )?))
    })
    .await?;
    Ok(Json(row))
}

/// `POST /v1/owner/packs/skills/restore-defaults`: restore missing or retired
/// bootstrap and pinned first-hub defaults as fresh Candidates.
pub(super) async fn restore_default_skills(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<SkillRow>> {
    let owner = owner(&auth, &server)?;
    let rows = blocking(move || {
        let at = server.vault().now_recorded_at();
        let occurred = oneiron::TimeRange { start: at, end: at };
        Ok(server
            .vault()
            .restore_default_skills(&owner, occurred, at)?
            .into_iter()
            .map(skill_row)
            .collect())
    })
    .await?;
    Ok(Json(rows))
}

/// What one skill sync did.
#[derive(Serialize, schemars::JsonSchema)]
pub(super) struct SkillSync {
    /// `applied`, `proposed` or `refused_by_policy`.
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    proposal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval: Option<&'static str>,
}

/// `POST /v1/owner/packs/skills/{entity}/sync`: refetch a hub skill at its
/// ref's stored policy. Same or narrower bytes apply; widening proposes.
pub(super) async fn sync_skill(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    UrlPath(entity): UrlPath<String>,
) -> OwnerReply<SkillSync> {
    let owner = owner(&auth, &server)?;
    let sync = blocking(move || {
        let entity = entity_id(&entity, "entity")?;
        Ok(
            match server.vault().sync_skill_from_hub_ref(&owner, &entity)? {
                HubSyncDisposition::Applied => SkillSync {
                    outcome: "applied",
                    proposal: None,
                    approval: None,
                },
                HubSyncDisposition::Proposed {
                    proposal_id,
                    approval,
                } => SkillSync {
                    outcome: "proposed",
                    proposal: Some(proposal_id.to_hex()),
                    approval: Some(approval.as_str()),
                },
                HubSyncDisposition::RefusedByPolicy => SkillSync {
                    outcome: "refused_by_policy",
                    proposal: None,
                    approval: None,
                },
            },
        )
    })
    .await?;
    Ok(Json(sync))
}

/// The owner's consent as it landed.
#[derive(Serialize, schemars::JsonSchema)]
pub(super) struct ConsentRow {
    outcome: &'static str,
    /// The gate decision, as 32 hex.
    decision: String,
}

impl From<ConsentReceipt> for ConsentRow {
    fn from(receipt: ConsentReceipt) -> Self {
        Self {
            outcome: receipt.gate_outcome(),
            decision: receipt
                .decision_id()
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        }
    }
}

/// The skill's first hub source: the ref its import or sync named.
fn skill_source(vault: &oneiron::Vault, entity: &EntityId) -> Result<HubRef, OwnerError> {
    vault
        .skill_hub_sources(entity)?
        .into_iter()
        .next()
        .ok_or_else(|| OwnerError::Invalid("the skill has no hub source".to_owned()))
}

/// `POST /v1/owner/packs/skills/{entity}/permissions/approve`: the owner's
/// answer to a hub skill's permission ask; it activates the Candidate.
pub(super) async fn approve_skill_permissions(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    UrlPath(entity): UrlPath<String>,
) -> OwnerReply<ConsentRow> {
    let owner = owner(&auth, &server)?;
    let row = blocking(move || {
        let vault = server.vault();
        let entity = entity_id(&entity, "entity")?;
        let source = skill_source(vault, &entity)?;
        let at = vault.now_recorded_at();
        let occurred = oneiron::TimeRange { start: at, end: at };
        Ok(ConsentRow::from(vault.approve_marketplace_permission_ask(
            &owner, &entity, &source, occurred, at,
        )?))
    })
    .await?;
    Ok(Json(row))
}

/// A hub skill's receipts: one import receipt per hub source, and the
/// held-out activation ruling once one landed.
#[derive(Serialize)]
pub(super) struct SkillReceipts {
    imports: Vec<HubImportReceipt>,
    admission: Option<HubAdmissionReceipt>,
}

/// `GET /v1/owner/packs/skills/{entity}/receipts`
pub(super) async fn skill_receipts(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    UrlPath(entity): UrlPath<String>,
) -> OwnerReply<SkillReceipts> {
    owner(&auth, &server)?;
    let receipts = blocking(move || {
        let vault = server.vault();
        let entity = entity_id(&entity, "entity")?;
        let mut imports = Vec::new();
        for source in vault.skill_hub_sources(&entity)? {
            if let Some(receipt) = vault.hub_import_receipt(&entity, &source)? {
                imports.push(receipt);
            }
        }
        Ok(SkillReceipts {
            imports,
            admission: vault.hub_admission_receipt(&entity)?,
        })
    })
    .await?;
    Ok(Json(receipts))
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ActivationRequest {
    /// The publisher admitted for the skill's hub.
    publisher: String,
    /// An active local skill whose attributed outcomes are the baseline.
    evidence_skill: String,
    /// On approve: the digest the owner was shown.
    #[serde(default)]
    effect_digest: Option<String>,
}

/// The activation ask as the owner reads it.
#[derive(Serialize, schemars::JsonSchema)]
pub(super) struct ActivationAskView {
    candidate: String,
    content_hash: String,
    effect_digest: String,
    /// `one_tap`, `summarized_review` or `full_review`.
    surface: &'static str,
}

fn prepare_activation(
    server: &SyncServer,
    owner: &oneiron::consent::AuthenticatedOwner,
    entity: &str,
    request: &ActivationRequest,
) -> Result<oneiron::skill_hub::HubActivationAsk, OwnerError> {
    let vault = server.vault();
    let candidate = entity_id(entity, "entity")?;
    let evidence = entity_id(&request.evidence_skill, "evidence_skill")?;
    let source = skill_source(vault, &candidate)?;
    let publisher = vault.admit_skill_publisher(owner, &request.publisher, source.hub_id)?;
    Ok(vault.prepare_marketplace_activation(candidate, &source, &publisher, evidence)?)
}

/// `POST /v1/owner/packs/skills/{entity}/activation/prepare`: the immutable
/// held-out activation ask for a hub Candidate.
pub(super) async fn prepare_skill_activation(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    UrlPath(entity): UrlPath<String>,
    payload: OwnerJsonBody<ActivationRequest>,
) -> OwnerReply<ActivationAskView> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let view = blocking(move || {
        let ask = prepare_activation(&server, &owner, &entity, &request)?;
        Ok(ActivationAskView {
            candidate: ask.candidate().to_hex(),
            content_hash: ask.content_hash().to_hex(),
            effect_digest: ask.effect_digest().to_hex(),
            surface: match ask.surface() {
                HubAskSurface::OneTap => "one_tap",
                HubAskSurface::SummarizedReview => "summarized_review",
                HubAskSurface::FullReview => "full_review",
            },
        })
    })
    .await?;
    Ok(Json(view))
}

/// `POST /v1/owner/packs/skills/{entity}/activation/approve`: the owner's
/// consent to the ask they were shown. The ask is rebuilt and must carry
/// the same digest. Admission itself needs the host's held-out scorer.
pub(super) async fn approve_skill_activation(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    UrlPath(entity): UrlPath<String>,
    payload: OwnerJsonBody<ActivationRequest>,
) -> OwnerReply<ConsentRow> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let row = blocking(move || {
        let shown = request
            .effect_digest
            .clone()
            .ok_or_else(|| OwnerError::Invalid("send the effect_digest shown".to_owned()))?;
        let ask = prepare_activation(&server, &owner, &entity, &request)?;
        if ask.effect_digest().to_hex() != shown {
            return Err(OwnerError::Invalid(
                "the activation ask moved; prepare it again".to_owned(),
            ));
        }
        Ok(ConsentRow::from(
            server
                .vault()
                .approve_marketplace_activation(&ask, &owner)?,
        ))
    })
    .await?;
    Ok(Json(row))
}
