//! Doors for `tests/approval_target_round_trip.rs` (FIX 22398
//! APPROVAL-TARGET): the press each approval family composes is the one the
//! Gate's spend lookup finds, for that one send alone, and a press kept for
//! its retry proves that send on that intent alone.

use crate::Vault;
use crate::consent::approval_proof::{AdmittedApproval, PinnedApproval};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::{
    ApprovalTarget, BrowserSendTarget, CampaignLegFacts, ChannelIdentityLifecycleFacts,
    ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateProvenanceHandles,
    LinearMirrorFacts, ScopedMcpCallFacts,
};
use crate::linear_sync::{LinearEffectKind, LinearEffectRequest, MirroredTaskFields};
use crate::receipt::intent_id::IntentId;

/// The intent a kept press was spent on.
const KEPT_INTENT: IntentId = [0x31; 32];
/// Another intent of the same actor.
const OTHER_INTENT: IntentId = [0x32; 32];

/// One family's round trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyRoundTrip {
    /// The family's name.
    pub family: &'static str,
    /// The family's composer named a press for the send.
    pub composed: bool,
    /// After the owner pressed that digest, the Gate's spend lookup over the
    /// send finds an available press.
    pub press_found: bool,
    /// The same lookup over a sibling send of the family (another send ref,
    /// nonce, sequence or payload) finds one: must stay false.
    pub sibling_found: bool,
    /// For a family whose press is kept for its retry: the press kept on the
    /// send's intent is the send's retry proof. `None` for a family that
    /// keeps none.
    pub kept_press_retries: Option<bool>,
    /// For such a family: the kept press proves the sibling send, or the
    /// send on another intent: must stay false.
    pub kept_press_strays: Option<bool>,
}

/// The name of `target`'s family. No wildcard arm: a family added later
/// does not compile here until this test covers it.
fn family_name(target: &ApprovalTarget) -> &'static str {
    match target {
        ApprovalTarget::Esign { .. } => "esign",
        ApprovalTarget::Calendar { .. } => "calendar",
        ApprovalTarget::Communication { .. } => "communication",
        ApprovalTarget::HttpBundle { .. } => "http_bundle",
        ApprovalTarget::LinearDispatch { .. } => "linear_dispatch",
        ApprovalTarget::LinearMirror(_) => "linear_mirror",
        ApprovalTarget::Campaign(_) => "campaign",
        ApprovalTarget::ScopedMcp(_) => "scoped_mcp",
        ApprovalTarget::ChannelIdentityLifecycle(_) => "channel_identity_lifecycle",
        ApprovalTarget::Browser(_) => "browser",
        ApprovalTarget::ConnectorSlate(_) => "connector_slate",
    }
}

fn id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("fixture entity id")
}

fn effect(channel: &str, verb: &str, target: ApprovalTarget) -> ExternalEffectGateInput {
    ExternalEffectGateInput {
        actor: GateActor {
            actor_class: "agent".to_owned(),
            actor_ref: Some(id(0x21).to_hex()),
            delegation_grant_ref: None,
        },
        provenance: GateProvenanceHandles {
            actor_entity_ref: Some(id(0x21)),
            approval_target: Some(target),
            ..GateProvenanceHandles::default()
        },
        verb: verb.to_owned(),
        channel: channel.to_owned(),
        channel_identity_ref: None,
        counterparty: None,
        brief_ref: None,
        send_ref: None,
        standing_grant_ref: None,
        scoped_mcp_call: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: true,
        has_permission: true,
        policy_risk: ExternalEffectPolicyRisk::Normal,
        send_autonomy: None,
    }
}

fn communication(send_ref: &str) -> ApprovalTarget {
    ApprovalTarget::Communication {
        sender: Some(id(0x22)),
        target: "+15550100".to_owned(),
        recipients: Vec::new(),
        thread_ref: Some("thread-1".to_owned()),
        content_ref: Some("blob:message-1".to_owned()),
        send_ref: send_ref.to_owned(),
    }
}

fn linear_mirror(operation: u8) -> ApprovalTarget {
    ApprovalTarget::LinearMirror(LinearMirrorFacts::of(&LinearEffectRequest {
        operation_id: [operation; 32],
        task_ref: id(0x23),
        scheduler_actor: id(0x24),
        issue: None,
        kind: LinearEffectKind::Create,
        fields: MirroredTaskFields {
            title: "Mirror one task".to_owned(),
            description: None,
            priority: Some(2),
            assignee_ref: None,
            status: "todo".to_owned(),
        },
    }))
}

fn campaign(call_seq: u64) -> ApprovalTarget {
    ApprovalTarget::Campaign(CampaignLegFacts {
        query_ref: id(0x25),
        campaign_ref: id(0x26),
        entity_ref: id(0x27),
        epoch: 1,
        program_ref: id(0x28),
        step_ref: id(0x29),
        consequence_id: [0x2A; 16],
        call_seq,
        payload_digest: [0x2B; 32],
    })
}

fn scoped_mcp(call_seq: u64) -> ApprovalTarget {
    ApprovalTarget::ScopedMcp(ScopedMcpCallFacts {
        server: "payments".to_owned(),
        tool: "charge".to_owned(),
        resolved_endpoint: "https://payments.invalid/mcp".to_owned(),
        attempt_id: [0x2C; 16],
        call_seq,
        payload_digest: [0x2D; 32],
    })
}

fn channel_identity_lifecycle(request: u8) -> ApprovalTarget {
    ApprovalTarget::ChannelIdentityLifecycle(ChannelIdentityLifecycleFacts {
        verb: "provision",
        identity_id: id(0x2E),
        fulfillment_mode: Some("managed"),
        specification_digest: Some([0x2F; 32]),
        quarantine_until: None,
        request_ref: id(request),
    })
}

fn browser(ordinal: u64) -> ApprovalTarget {
    ApprovalTarget::Browser(BrowserSendTarget {
        actor_class: "agent",
        run: id(0x33),
        attempt: id(0x34),
        ordinal,
        verb: "submit".to_owned(),
        project: Some(id(0x35)),
        audience: None,
        page: Some("https://forms.invalid/apply".to_owned()),
        revision: Some("read-1".to_owned()),
        target: "button#submit".to_owned(),
        operands_digest: [0x36; 32],
    })
}

/// Every family, as (channel, verb, this send's target, a sibling send's).
fn families() -> Vec<(&'static str, &'static str, ApprovalTarget, ApprovalTarget)> {
    let esign = |send_ref: &str| ApprovalTarget::Esign {
        document: "document-1".to_owned(),
        content_ref: Some("esign-command:aa".to_owned()),
        send_ref: send_ref.to_owned(),
    };
    let calendar = |sequence: u32| ApprovalTarget::Calendar {
        uid: "event-1@oneiron".to_owned(),
        sequence,
        method: "REQUEST".to_owned(),
        ics_ref: "blob:ics-1".to_owned(),
        attendee: "guest@example.invalid".to_owned(),
        sender: Some(id(0x37)),
        send_ref: "send-1".to_owned(),
    };
    let http_bundle = |send_ref: &str| ApprovalTarget::HttpBundle {
        endpoint: "https://feedback.invalid/bundles".to_owned(),
        content_ref: Some("blob:bundle-1".to_owned()),
        send_ref: send_ref.to_owned(),
    };
    let linear_dispatch = |payload: u8| ApprovalTarget::LinearDispatch {
        verb: "create_issue".to_owned(),
        target: "team-1".to_owned(),
        content_ref: None,
        send_ref: "send-1".to_owned(),
        payload_digest: [payload; 32],
        mirror: None,
    };
    vec![
        (
            "esign",
            "send_for_signature",
            esign("send-1"),
            esign("send-2"),
        ),
        ("calendar", "invite", calendar(1), calendar(2)),
        (
            "sms",
            "send",
            communication("send-1"),
            communication("send-2"),
        ),
        (
            "feedback_cloud",
            "send",
            http_bundle("send-1"),
            http_bundle("send-2"),
        ),
        (
            "linear",
            "create_issue",
            linear_dispatch(0x41),
            linear_dispatch(0x42),
        ),
        (
            "linear",
            "create_issue",
            linear_mirror(0x43),
            linear_mirror(0x44),
        ),
        ("sms", "send", campaign(0), campaign(1)),
        ("payments", "call", scoped_mcp(0), scoped_mcp(1)),
        (
            "channel_identity",
            "provision",
            channel_identity_lifecycle(0x45),
            channel_identity_lifecycle(0x46),
        ),
        ("browser", "submit", browser(0), browser(1)),
        (
            "sms",
            "send",
            // A slate pins its inner target's digest: its own send, so the
            // press is not the communication family's above.
            ApprovalTarget::ConnectorSlate(Box::new(communication("send-3"))),
            ApprovalTarget::ConnectorSlate(Box::new(communication("send-4"))),
        ),
    ]
}

/// Whether the Gate's spend lookup over `effect` finds an available press:
/// the key `effect::evaluate` looks up for a pinned send, read on `txn`.
fn spend_lookup_finds(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
) -> Result<bool> {
    let Some(key) = crate::gate::external_effect_approval_digest(effect) else {
        return Ok(false);
    };
    Ok(crate::consent::approve_once_authorization_in_txn(&vault.store, txn, &key)?.is_some())
}

/// For each approval family: composes the owner's press on one send with
/// the family's composer, presses it as the vault's owner, runs the Gate's
/// spend lookup over that send and over a sibling send of the family, and
/// checks a press kept on the send's intent against both and against
/// another intent.
///
/// # Errors
/// The vault's: the owner's authentication, or the press.
pub fn every_family_round_trip(vault: &Vault) -> Result<Vec<FamilyRoundTrip>> {
    let actor = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| Error::InvalidConfig(format!("embedded owner: {error:?}")))?;
    let owner = vault.authenticate_owner(
        actor,
        &actor.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let mut trips = Vec::new();
    for (channel, verb, target, sibling_target) in families() {
        let family = family_name(&target);
        let kept_family = target.pinned_family();
        let send = effect(channel, verb, target);
        let sibling = effect(channel, verb, sibling_target);
        let Some(composed) = ApprovalTarget::approve_once_digest(&send) else {
            trips.push(FamilyRoundTrip {
                family,
                composed: false,
                press_found: false,
                sibling_found: false,
                kept_press_retries: None,
                kept_press_strays: None,
            });
            continue;
        };
        vault.approve_once(&owner, composed)?;
        let rtxn = vault.store.env.read_txn()?;
        let press_found = spend_lookup_finds(vault, &rtxn, &send)?;
        let sibling_found = spend_lookup_finds(vault, &rtxn, &sibling)?;
        let kept = kept_family.map(|family| {
            PinnedApproval::new(family, AdmittedApproval::from_gate(KEPT_INTENT, composed))
        });
        let kept_press_retries = kept.map(|kept| {
            ApprovalTarget::kept_press_retry_proof(&send, KEPT_INTENT, kept) == Some(kept.proof)
        });
        let kept_press_strays = kept.map(|kept| {
            ApprovalTarget::kept_press_retry_proof(&sibling, KEPT_INTENT, kept).is_some()
                || ApprovalTarget::kept_press_retry_proof(&send, OTHER_INTENT, kept).is_some()
        });
        trips.push(FamilyRoundTrip {
            family,
            composed: true,
            press_found,
            sibling_found,
            kept_press_retries,
            kept_press_strays,
        });
    }
    Ok(trips)
}
