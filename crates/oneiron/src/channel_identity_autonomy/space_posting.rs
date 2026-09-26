//! Owner-set per-space presentation. A dial never grants transport or memory access.

use super::codec::{AUTONOMY, address, array, id, id_value, key, text};
use super::invalid_autonomy;
use crate::consent::{ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, GrantBound};
use crate::context_projection::ResolvedContextProjection;
use crate::error::Result;
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};
use crate::{EntityId, Vault};
use rmpv::Value;

const POSTING_ENVELOPE: &str = "channel_identity.space_posting_envelope";
const POSTING_HEAD: &str = "channel_identity.space_posting_head";

/// Posting identity is data. Even owner mode must pass the normal outbound gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpacePostingMode {
    NamedParticipant,
    PostAsOwner,
}

/// Group defaults compose the existing autonomy rungs, not a workflow language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupPostingPreset {
    NamedParticipant,
    OwnerDrafts,
    OwnerWithApproval,
}
impl GroupPostingPreset {
    pub const fn mode(self) -> SpacePostingMode {
        match self {
            Self::NamedParticipant => SpacePostingMode::NamedParticipant,
            _ => SpacePostingMode::PostAsOwner,
        }
    }
    pub const fn rung(self) -> super::ChannelIdentityAutonomyRung {
        match self {
            Self::OwnerDrafts => super::ChannelIdentityAutonomyRung::DraftOnly,
            Self::NamedParticipant | Self::OwnerWithApproval => {
                super::ChannelIdentityAutonomyRung::SendWithApproval
            }
        }
    }
    pub(super) fn token(self) -> &'static str {
        match self {
            Self::NamedParticipant => "named_participant",
            Self::OwnerDrafts => "owner_drafts",
            Self::OwnerWithApproval => "owner_with_approval",
        }
    }
    fn parse(token: &str) -> Result<Self> {
        match token {
            "named_participant" => Ok(Self::NamedParticipant),
            "owner_drafts" => Ok(Self::OwnerDrafts),
            "owner_with_approval" => Ok(Self::OwnerWithApproval),
            _ => Err(invalid_autonomy()),
        }
    }
}

/// Configuration receipt. Previous presets remain readable by their immutable ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpacePostingReceipt {
    pub setting_ref: EntityId,
    pub decision_id: GateDecisionId,
}

/// The supplied room projection is carried through unchanged. No vault memory
/// is fetched here, even when owner presentation is selected.
#[derive(Debug, Clone, PartialEq)]
pub struct SpacePostingPlan {
    pub identity_ref: EntityId,
    pub space_ref: String,
    pub preset: GroupPostingPreset,
    pub policy_risk: bool,
    /// None for named presentation or when its EXTRA owner-space grant exists.
    /// This does not waive any ordinary read, outbound, recipient or budget gate.
    pub needs_owner_consent: Option<GrantBound>,
    pub room_context: ResolvedContextProjection,
}

pub(super) fn head_key(identity: EntityId, space: &str) -> Result<Vec<u8>> {
    if space.trim().is_empty() || space.len() > 512 || space.chars().any(char::is_control) {
        return Err(invalid_autonomy());
    }
    let digest = blake3::hash(space.as_bytes());
    Ok(key(
        POSTING_HEAD,
        &format!("{}:{}", identity.to_hex(), digest.to_hex()),
    ))
}
fn posting_supported(channel: &str) -> bool {
    crate::outbound::outbound_verb_contract(channel, "send")
        .ok()
        .is_some_and(|contract| {
            contract
                .params
                .get("posting")
                .and_then(|p| p.get("post_as_owner_supported"))
                .and_then(serde_json::Value::as_bool)
                == Some(true)
        })
}

impl Vault {
    /// Saves a per-space dial with an authenticated owner receipt. This never
    /// creates a send grant, changes an identity, or changes a room's scope.
    pub fn set_space_posting_preset(
        &self,
        identity: EntityId,
        space: &str,
        preset: GroupPostingPreset,
        owner: &AuthenticatedOwner,
        at: u64,
    ) -> Result<SpacePostingReceipt> {
        self.autonomy_owner(owner)?;
        let head = head_key(identity, space)?;
        self.with_write_txn(|txn| {
            self.autonomy_identity_actor(txn, identity)?;
            let raw = self
                .store
                .entities
                .get(txn, identity.as_bytes())?
                .ok_or_else(invalid_autonomy)?;
            let record = crate::channel_identity::decode_channel_identity_body(
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            )?;
            if preset.mode() == SpacePostingMode::PostAsOwner
                && (!record.may_send() || !posting_supported(&record.channel))
            {
                return Err(invalid_autonomy());
            }
            let value = Value::Array(vec![
                id_value(identity),
                Value::from(space),
                Value::from(preset.token()),
            ]);
            let setting = self.put_autonomy_envelope(txn, POSTING_ENVELOPE, value, owner, at)?;
            if AUTONOMY.contains(&self.store, txn, &head)? {
                let (_, previous_at, prior) = self.autonomy_row(txn, &head)?;
                if at < previous_at {
                    return Err(invalid_autonomy());
                }
                let fields = array(&prior, 2)?;
                if id(&fields[0])? == setting {
                    let decision = GateDecisionId::from_bytes(
                        *EntityId::from_hex(text(&fields[1])?)?.as_bytes(),
                    );
                    return Ok(SpacePostingReceipt {
                        setting_ref: setting,
                        decision_id: decision,
                    });
                }
            }
            let decision_id = GateDecisionId::now();
            self.write_autonomy_row(
                txn,
                &head,
                owner.actor(),
                at,
                Value::Array(vec![id_value(setting), Value::from(decision_id.to_hex())]),
            )?;
            self.store.append_gate_decision_in_txn(
                txn,
                &GateDecisionRecord {
                    version: GATE_DECISION_LEDGER_VERSION,
                    decision_id,
                    created_at: at,
                    outcome: "approved".to_owned(),
                    reason_codes: vec!["gate.identity.space_posting_configured".to_owned()],
                    receipt_reasons: Vec::new(),
                    system_notices: Vec::new(),
                    actor_class: "human".to_owned(),
                    actor_ref: Some(owner.actor().to_hex()),
                    content_kind: "channel_identity.posting".to_owned(),
                    policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
                    claim_id: None,
                    grant_ref: None,
                    diff_handle: setting.as_bytes().to_vec(),
                    read_frontier_hash: [0; 32],
                    redacted_at: None,
                },
            )?;
            Ok(SpacePostingReceipt {
                setting_ref: setting,
                decision_id,
            })
        })
    }

    /// Reads the per-space presentation and its exact additional owner consent.
    /// Missing settings are named-participant. Read-only OAuth identities cannot
    /// turn into senders through this door, at any preset or trust level.
    pub fn space_posting_plan(
        &self,
        identity: EntityId,
        space: &str,
        room_context: ResolvedContextProjection,
    ) -> Result<SpacePostingPlan> {
        let txn = self.store.env.read_txn()?;
        let state = self.posting_state_in_txn(&txn, identity, space)?;
        Ok(SpacePostingPlan {
            identity_ref: identity,
            space_ref: space.to_owned(),
            preset: state.preset,
            policy_risk: state.preset.mode() == SpacePostingMode::PostAsOwner,
            needs_owner_consent: state.needs_owner_consent,
            room_context,
        })
    }

    pub(super) fn posting_state_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        identity: EntityId,
        space: &str,
    ) -> Result<PostingState> {
        let head = head_key(identity, space)?;
        let actor = self.autonomy_identity_actor(txn, identity)?;
        let raw = self
            .store
            .entities
            .get(txn, identity.as_bytes())?
            .ok_or_else(invalid_autonomy)?;
        let record = crate::channel_identity::decode_channel_identity_body(
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        )?;
        let (setting_ref, preset) = if AUTONOMY.contains(&self.store, txn, &head)? {
            let (_, _, pointer) = self.autonomy_row(txn, &head)?;
            let fields = array(&pointer, 2)?;
            let reference = id(&fields[0])?;
            let (_, _, value) =
                self.autonomy_row(txn, &key(POSTING_ENVELOPE, &reference.to_hex()))?;
            if address(POSTING_ENVELOPE, &value)? != reference {
                return Err(invalid_autonomy());
            }
            let fields = array(&value, 3)?;
            if id(&fields[0])? != identity || text(&fields[1])? != space {
                return Err(invalid_autonomy());
            }
            (
                Some(reference),
                GroupPostingPreset::parse(text(&fields[2])?)?,
            )
        } else {
            (None, GroupPostingPreset::NamedParticipant)
        };
        let policy_risk = preset.mode() == SpacePostingMode::PostAsOwner;
        let needs_owner_consent = if policy_risk {
            if !record.may_send() || !posting_supported(&record.channel) {
                return Err(invalid_autonomy());
            }
            let bound = GrantBound::action(
                ActorBound::new(actor.to_hex())?,
                ActionClass::new("channel_identity.post_as_owner")?,
                ActionEnvelope::new([
                    format!("identity:{}", identity.to_hex()),
                    format!("space:{space}"),
                    format!("preset:{}", preset.token()),
                ])?
                .with_target(space)?,
            )?;
            let allowed = self
                .active_standing_consent_grants_in_txn(txn)?
                .iter()
                .any(|grant| grant.bound().contains(&bound));
            (!allowed).then_some(bound)
        } else {
            None
        };
        Ok(PostingState {
            setting_ref,
            preset,
            needs_owner_consent,
        })
    }
}

pub(super) struct PostingState {
    pub(super) setting_ref: Option<EntityId>,
    pub(super) preset: GroupPostingPreset,
    pub(super) needs_owner_consent: Option<GrantBound>,
}
