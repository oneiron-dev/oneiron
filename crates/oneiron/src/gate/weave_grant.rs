//! The owner's auto-weave Grant (OF-351, FIX 3433). ARCH-0053 weaves: "The
//! owner may grant auto-weave at any scope." It is a standing action Grant
//! of the verb [`AUTO_WEAVE_VERB`] that names its writer and one weave
//! scope, the scope's id its target: a project (`project:<id>`, the consent
//! door's own project envelope), a research campaign (`campaign:<root
//! attempt>`) or a governed skill (`skill:<id>`). Only a Grant a live owner
//! of the vault minted counts.
//!
//! The claim door records the Grant that covers an Allow landing past
//! Proposed as the decision's `grant_ref`, with the receipt reason
//! [`GATE_REASON_ALLOW_WEAVE_GRANT`]. The door sees a claim's project, so it
//! matches a project scope exactly; it cannot see the campaign a claim will
//! weave into, so a campaign or skill scope is matched to its weave where the
//! weave is recorded ([`decision_names_weave_grant_in_txn`]). The record
//! admits and refuses nothing: a landing with no such Grant records as
//! before.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimBody};
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, BoundClass, BoundEnvelope,
    GrantBound, load_active_standing_grants, standing_grant_row_in_txn,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::memory::MemoryResult;
use crate::store::{GateDecisionRecord, Store};
use crate::write_envelope::WriteActor;

/// The verb an auto-weave Grant names.
pub(crate) const AUTO_WEAVE_VERB: &str = "research.auto_weave";
/// The receipt reason of a landing past Proposed under an auto-weave Grant.
pub(crate) const GATE_REASON_ALLOW_WEAVE_GRANT: &str = "gate.allow.weave_grant";

const PROJECT_SCOPE: &str = "project";
const CAMPAIGN_SCOPE: &str = "campaign";
const SKILL_SCOPE: &str = "skill";

/// One scope an auto-weave Grant names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WeaveScope {
    /// A project: a claim's `scope_project`.
    Project(EntityId),
    /// A research campaign, by its root attempt.
    Campaign([u8; 16]),
    /// A governed skill a campaign improves.
    Skill(EntityId),
}

impl WeaveScope {
    /// The bound an auto-weave Grant for `writer` in this scope must
    /// contain.
    fn bound(self, writer: WriteActor) -> Result<GrantBound> {
        let (kind, id) = match self {
            Self::Project(id) => (PROJECT_SCOPE, id.to_hex()),
            Self::Campaign(root) => (CAMPAIGN_SCOPE, bytes_to_hex_lower(&root)),
            Self::Skill(id) => (SKILL_SCOPE, id.to_hex()),
        };
        GrantBound::action(
            ActorBound::new(writer.entity_ref().to_hex())?
                .with_actor_class(writer.actor_class().gate_actor_class())?,
            ActionClass::new(AUTO_WEAVE_VERB)?,
            ActionEnvelope::new([format!("{kind}:{id}")])?.with_target(id)?,
        )
    }

    /// The campaign and skill scopes `bound`'s envelope names.
    fn named_by(bound: &GrantBound) -> Vec<Self> {
        let BoundEnvelope::Action(envelope) = bound.envelope() else {
            return Vec::new();
        };
        envelope
            .selectors()
            .iter()
            .filter_map(|selector| {
                let (kind, id) = selector.split_once(':')?;
                let id = EntityId::from_hex(id).ok()?;
                match kind {
                    CAMPAIGN_SCOPE => Some(Self::Campaign(*id.as_bytes())),
                    SKILL_SCOPE => Some(Self::Skill(id)),
                    _ => None,
                }
            })
            .collect()
    }
}

/// Whether `bound` names the auto-weave verb.
fn names_auto_weave(bound: &GrantBound) -> bool {
    matches!(bound.class(), BoundClass::Action(class) if class.as_str() == AUTO_WEAVE_VERB)
}

/// Whether `bound` admits `writer`'s auto-weave in one of `scopes`.
fn covers_any(bound: &GrantBound, writer: WriteActor, scopes: &[WeaveScope]) -> Result<bool> {
    for scope in scopes {
        if bound.contains(&scope.bound(writer)?) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The auto-weave Grant that covers `writer`'s landing of `body`, the gate
/// having allowed it: a landing past Proposed by an agent or system writer,
/// under an active Grant a live owner minted that names the writer and
/// either the claim's project or a campaign or skill. Its ref is the Grant's
/// bound digest. `None` for any other landing.
pub(crate) fn landing_weave_grant_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    writer: Option<WriteActor>,
    body: &ClaimBody,
) -> Result<Option<String>> {
    let Some(writer) = writer.filter(|writer| {
        matches!(
            writer.actor_class(),
            EdgeActorClass::Agent | EdgeActorClass::System
        )
    }) else {
        return Ok(None);
    };
    if !matches!(
        body.approval,
        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
    ) {
        return Ok(None);
    }
    for grant in load_active_standing_grants(store, txn)? {
        let bound = grant.bound();
        // Most standing Grants name another verb; only an auto-weave one is
        // read further.
        if !names_auto_weave(bound) {
            continue;
        }
        let mut scopes = WeaveScope::named_by(bound);
        scopes.push(WeaveScope::Project(body.scope_project));
        if !covers_any(bound, writer, &scopes)? {
            continue;
        }
        let grant_ref = bound.digest().to_hex();
        let Some(row) = standing_grant_row_in_txn(store, txn, &grant_ref)? else {
            continue;
        };
        if row.is_active()
            && crate::policy_model::is_live_vault_owner_for_store_in_txn(
                store,
                store.privacy_posture,
                txn,
                &row.owner_stamp.actor,
            )?
        {
            return Ok(Some(grant_ref));
        }
    }
    Ok(None)
}

/// Whether `decision`, the gate's record of `writer`'s landing, names an
/// auto-weave Grant for one of `scopes`: the receipt reason
/// [`GATE_REASON_ALLOW_WEAVE_GRANT`] and a `grant_ref` whose Grant is still
/// active and, as the owner minted it, names `writer` and one of them.
pub(crate) fn decision_names_weave_grant_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    decision: &GateDecisionRecord,
    writer: WriteActor,
    scopes: &[WeaveScope],
) -> Result<bool> {
    if !decision
        .receipt_reasons
        .iter()
        .any(|reason| reason == GATE_REASON_ALLOW_WEAVE_GRANT)
    {
        return Ok(false);
    }
    let Some(grant_ref) = decision.grant_ref.as_deref() else {
        return Ok(false);
    };
    let Some(row) = standing_grant_row_in_txn(store, txn, grant_ref)? else {
        return Ok(false);
    };
    Ok(row.is_active() && covers_any(row.grant.bound(), writer, scopes)?)
}

/// A writer class an auto-weave Grant names: an agent or the system. The
/// gate admits only those two past Proposed
/// ([`landing_weave_grant_in_txn`]), so the door takes no human.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AutoWeaveWriterClass {
    Agent,
    System,
}

impl From<AutoWeaveWriterClass> for EdgeActorClass {
    fn from(class: AutoWeaveWriterClass) -> Self {
        match class {
            AutoWeaveWriterClass::Agent => Self::Agent,
            AutoWeaveWriterClass::System => Self::System,
        }
    }
}

/// `vault.consent.create_auto_weave_grant`'s input: the writer the Grant
/// names and the one scope it covers. Ids are 32 hex: an entity id, or for
/// `campaign` the campaign's 16-byte root attempt.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AutoWeaveGrantRequest {
    /// The writer's entity id, as 32 hex.
    pub writer: String,
    /// The writer's actor class.
    pub writer_class: AutoWeaveWriterClass,
    /// One of `project`, `campaign` or `skill`.
    pub scope: String,
    /// The scope's id, as 32 hex.
    pub scope_id: String,
}

/// Mints the owner's auto-weave Grant for `request`'s writer in its one
/// scope (FIX 3433's door): the standing `research.auto_weave` Grant the
/// claim door records past Proposed. Bad hex or an unknown scope is
/// [`Error::InvalidConfig`](crate::error::Error::InvalidConfig); the mint
/// itself is the consent door's standing-grant path, so the receipt is the
/// same [`ConsentActReceipt`](crate::consent::lifecycle::ConsentActReceipt).
pub fn mint_auto_weave_grant(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: AutoWeaveGrantRequest,
) -> MemoryResult<crate::consent::lifecycle::ConsentActReceipt> {
    let writer_id = EntityId::from_hex(&request.writer).map_err(|_| {
        crate::error::Error::InvalidConfig("auto-weave writer is not an entity id".to_owned())
    })?;
    let writer = WriteActor::new(writer_id, EdgeActorClass::from(request.writer_class));
    let scope = match request.scope.as_str() {
        PROJECT_SCOPE => {
            let id = EntityId::from_hex(&request.scope_id).map_err(|_| {
                crate::error::Error::InvalidConfig(
                    "auto-weave scope id is not an entity id".to_owned(),
                )
            })?;
            WeaveScope::Project(id)
        }
        CAMPAIGN_SCOPE => {
            let id = EntityId::from_hex(&request.scope_id).map_err(|_| {
                crate::error::Error::InvalidConfig(
                    "auto-weave scope id is not a campaign root".to_owned(),
                )
            })?;
            WeaveScope::Campaign(*id.as_bytes())
        }
        SKILL_SCOPE => {
            let id = EntityId::from_hex(&request.scope_id).map_err(|_| {
                crate::error::Error::InvalidConfig(
                    "auto-weave scope id is not an entity id".to_owned(),
                )
            })?;
            WeaveScope::Skill(id)
        }
        _ => {
            return Err(
                crate::error::Error::InvalidConfig("unknown auto-weave scope".to_owned()).into(),
            );
        }
    };
    Ok(vault
        .create_standing_grant(owner, scope.bound(writer)?)?
        .into())
}
