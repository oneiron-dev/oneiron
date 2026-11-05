//! Frozen retry-contract payload: the intent bytes a connector reads and the ledger hashes.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::calendar::invite::CalendarInvitePayload;
use crate::linear_sync::{
    LinearEffectKind, LinearEffectRequest, LinearIssueRef, MirroredTaskFields,
};
use crate::outbound::intent::OutboundIntent;
/// The bytes one outbound effect freezes: the intent, plus the CA-05 send
/// hygiene headers derived from that same frozen metadata.
///
/// Flattened and elided-when-empty, the way every optional field on
/// [`OutboundIntent`] is: the frozen bytes are what a connector reads and what
/// the ledger hashes into an intent id, so a send that carries no hygiene
/// headers says nothing about them rather than freezing an empty map. Ordering
/// is fixed by the struct's field order and by the [`BTreeMap`], because these
/// bytes are the retry contract.
#[derive(Serialize)]
pub(super) struct FrozenOutboundPayload<'a> {
    #[serde(flatten)]
    pub(super) intent: &'a OutboundIntent,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) hygiene_headers: BTreeMap<String, String>,
    /// Exact step identity: frozen into the intent hash so a retry cannot
    /// name a different LLM result, and absent for non-step effects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) dreamer_step: Option<serde_json::Value>,
    /// CAL-04's exact five-field iMIP body, elided for every send that is not
    /// a calendar invite. It carries `ics_blob_ref` and never the `.ics` bytes,
    /// so the frozen payload stays small and the document a retry re-sends is
    /// byte-identical by reference rather than by re-rendering.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) calendar_invite: Option<&'a CalendarInvitePayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) space_posting: Option<&'a crate::channel_identity_autonomy::FrozenSpacePosting>,
    // The intent's display actor is not its gate principal. Freeze the actual
    // authority and sender in the existing ledger payload, including an absent
    // sender. Neither the gate audit nor the TASK stores this complete binding.
    pub(super) actor_class: &'a str,
    pub(super) actor_ref: Option<&'a str>,
    pub(super) actor_entity_ref: Option<String>,
    pub(super) channel_identity_ref: Option<String>,
    pub(super) counterparty_ref: Option<&'a str>,
    /// Admission-time native-mail classification. Replays must not depend on
    /// today's sender lifecycle when reconstructing this frozen binding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) native_mail_recipient: Option<bool>,
    /// Stable logical send ref, paired with the canonical native-mail intent.
    /// The typed admission proof is separate ledger metadata, not payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) native_mail_logical_ref: Option<&'a str>,
    /// FIX 6424: the logical send ref a non-mail press pins, for a family
    /// whose admitted press is recomposed from these bytes: e-sign, a
    /// failure-signal batch, or a communication, calendar or HTTP-bundle target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) approval_send_ref: Option<&'a str>,
    /// The native stable identity of an ordinary, non-mirror Linear send.
    /// Mirror requests retain their own target and approval path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) linear_approval_send_ref: Option<&'a str>,
    /// The native mirror request, not a TASK snapshot or a hash lookup.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) linear_mirror: Option<FrozenLinearMirror>,
    pub(super) has_opted_in: bool,
    pub(super) has_permission: bool,
    // Preserve the caller's dial too: a manifest can map both values to the
    // same effective risk, but that must not make different requests replayable.
    pub(super) requested_policy_risk: &'a str,
    pub(super) policy_risk: &'a str,
    pub(super) originating_session_ref: Option<&'a str>,
    /// OF-272: the reply thread and the facet its pin chose, elided for a
    /// send that names neither.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reply_thread_ref: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) facet_ref: Option<String>,
    /// FIX 1158: the send's relationship context and counterparty class, so
    /// a retry cannot switch the envelope it releases on; elided when the
    /// host supplied none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) send_autonomy: Option<FrozenSendAutonomy<'a>>,
}

/// All original mirror facts required by the native TASK writer authorizer.
/// These bytes describe a request; they grant neither principal permission.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FrozenLinearMirror {
    pub(super) operation_id: [u8; 32],
    pub(super) task_ref: String,
    pub(super) scheduler_actor: String,
    pub(super) issue: Option<LinearIssueRef>,
    pub(super) kind: FrozenLinearEffectKind,
    pub(super) fields: MirroredTaskFields,
    pub(super) send_ref: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum FrozenLinearEffectKind {
    Create,
    Update,
}

impl FrozenLinearMirror {
    pub(super) fn into_request(self) -> Option<(LinearEffectRequest, String)> {
        let request = LinearEffectRequest {
            operation_id: self.operation_id,
            task_ref: crate::entity_id::EntityId::from_hex(&self.task_ref).ok()?,
            scheduler_actor: crate::entity_id::EntityId::from_hex(&self.scheduler_actor).ok()?,
            issue: self.issue,
            kind: match self.kind {
                FrozenLinearEffectKind::Create => LinearEffectKind::Create,
                FrozenLinearEffectKind::Update => LinearEffectKind::Update,
            },
            fields: self.fields,
        };
        Some((request, self.send_ref))
    }

    pub(super) fn of(request: &LinearEffectRequest, send_ref: &str) -> Self {
        Self {
            operation_id: request.operation_id,
            task_ref: request.task_ref.to_hex(),
            scheduler_actor: request.scheduler_actor.to_hex(),
            issue: request.issue.clone(),
            kind: match request.kind {
                LinearEffectKind::Create => FrozenLinearEffectKind::Create,
                LinearEffectKind::Update => FrozenLinearEffectKind::Update,
            },
            fields: request.fields.clone(),
            send_ref: send_ref.to_owned(),
        }
    }
}

/// The frozen form of [`crate::channel_identity_autonomy::SendAutonomyContext`].
/// An unclassified send freezes `counterparty_class: null`.
#[derive(Serialize)]
pub(super) struct FrozenSendAutonomy<'a> {
    pub(super) relationship: &'a str,
    pub(super) counterparty_class: Option<&'a str>,
}

impl<'a> FrozenSendAutonomy<'a> {
    pub(super) fn of(context: &'a crate::channel_identity_autonomy::SendAutonomyContext) -> Self {
        Self {
            relationship: context.relationship.as_str(),
            counterparty_class: context.counterparty_class.as_deref(),
        }
    }
}
