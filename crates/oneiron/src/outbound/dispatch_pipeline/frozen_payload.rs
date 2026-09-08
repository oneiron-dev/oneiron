//! Frozen retry-contract payload: the intent bytes a connector reads and the ledger hashes.
use std::collections::BTreeMap;

use serde::Serialize;

use crate::calendar::invite::CalendarInvitePayload;
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
    /// CAL-04's exact five-field iMIP body, elided for every send that is not
    /// a calendar invite. It carries `ics_blob_ref` and never the `.ics` bytes,
    /// so the frozen payload stays small and the document a retry re-sends is
    /// byte-identical by reference rather than by re-rendering.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) calendar_invite: Option<&'a CalendarInvitePayload>,
    // The intent's display actor is not its gate principal. Freeze the actual
    // authority and sender in the existing ledger payload, including an absent
    // sender. Neither the gate audit nor the TASK stores this complete binding.
    pub(super) actor_class: &'a str,
    pub(super) actor_ref: Option<&'a str>,
    pub(super) actor_entity_ref: Option<String>,
    pub(super) channel_identity_ref: Option<String>,
    pub(super) counterparty_ref: Option<&'a str>,
    pub(super) has_opted_in: bool,
    pub(super) has_permission: bool,
    // Preserve the caller's dial too: a manifest can map both values to the
    // same effective risk, but that must not make different requests replayable.
    pub(super) requested_policy_risk: &'a str,
    pub(super) policy_risk: &'a str,
    pub(super) originating_session_ref: Option<&'a str>,
}
