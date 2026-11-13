//! The owner question a narrowing protocol revision raises. A catalog key
//! whose negotiated protocol revision changed, and whose next slate only
//! narrows, carries the owner's stamp forward (ARCH-0072 #drift: "A revision
//! that only narrows carries forward"), so no tap is owed. The key still
//! halts to Pending and re-qualifies, and the owner is still asked directly,
//! never left with a silent state (ARCH-0054 #drift, owner-ratified
//! 2026-07-29). So the revision queues one informational ask on the
//! decision-ask queue, in the revision's own write. The ask names the
//! connector, both revisions, the rows that narrowed or dropped, and the one
//! act that switches the connector off. An answer on the queue applies
//! nothing.

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::decision::{AskTo, HumanDecisionRequest};
use crate::model_decision::{
    AnswerContract, DecisionClass, DecisionQuestion, DecisionRung, HumanAskReason, ProviderPin,
};

use super::super::record::ConnectorKeyRecord;
use super::super::slate::ConnectorGrantSlate;

/// The decision-ask queue a narrowing protocol revision's question rides.
pub(crate) const CONNECTOR_PROTOCOL_NARROW_ASK_QUEUE: &str =
    "connector_key.protocol_revision.narrow";
const CONNECTOR_PROTOCOL_NARROW_ASK_QUEUE_VERSION: &str = "v1";
/// The version of the question; bump it with its wording.
const CONNECTOR_PROTOCOL_NARROW_ASK_VERSION: u32 = 1;
/// The owner door that switches a catalog connector off in one act.
const CONNECTOR_SWITCH_OFF_DOOR: &str = "POST /v1/owner/connectors/enabled";
/// The most bytes of question text the ask carries; the decision queue keeps
/// at most 16 KiB.
const MAX_ASK_TEXT_BYTES: usize = 16_000;

/// The owner's question about catalog key `id`, whose protocol revision
/// moves from `record`'s to `revision` and whose next slate `next`
/// (`next_ref`) carried `prior`'s stamp. Put by the owner who stamped
/// `prior`; one question per key and next slate.
pub(super) fn protocol_narrow_ask(
    id: &EntityId,
    record: &ConnectorKeyRecord,
    revision: &str,
    (prior, next, next_ref): (&ConnectorGrantSlate, &ConnectorGrantSlate, EntityId),
) -> Result<HumanDecisionRequest> {
    let owner = prior
        .owner_actor()
        .ok_or(Error::InvariantViolation("a carried stamp names its owner"))?;
    let principal =
        EntityId::from_hex(owner).map_err(|_| Error::CorruptedIndex("connector slate owner"))?;
    let reference = ask_reference(id, next_ref)?;
    Ok(HumanDecisionRequest {
        question: DecisionQuestion {
            id: reference,
            version: CONNECTOR_PROTOCOL_NARROW_ASK_VERSION,
            text: ask_text(record, revision, prior, next),
            class: DecisionClass::Judgment,
            contract: AnswerContract::Noul,
            accept_type: false,
        },
        principal,
        evidence: vec![*id, next_ref],
        reason: HumanAskReason::OwnerSelected,
        prior: None,
        prior_provider: None,
        queue_pin: ProviderPin {
            rung: DecisionRung::Human,
            model: CONNECTOR_PROTOCOL_NARROW_ASK_QUEUE.to_owned(),
            version: CONNECTOR_PROTOCOL_NARROW_ASK_QUEUE_VERSION.to_owned(),
        },
        to: AskTo::owner(),
        correlation: Some(reference),
    })
}

/// The question's id and correlation: one per key and next slate.
fn ask_reference(id: &EntityId, next_ref: EntityId) -> Result<EntityId> {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron.connector-key.protocol-narrow-ask.v1");
    hasher.update(id.as_bytes());
    hasher.update(next_ref.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    Ok(EntityId::from_bytes(bytes)?)
}

/// The prior slate's tools the next slate narrowed (a changed declaration
/// or a tighter setting) and the ones it dropped, by name. The revision
/// widened none, so any change is a narrow.
fn changed_tools(
    prior: &ConnectorGrantSlate,
    next: &ConnectorGrantSlate,
) -> (Vec<String>, Vec<String>) {
    let mut narrowed = Vec::new();
    let mut dropped = Vec::new();
    for tool in prior.manifest() {
        let Some(next_tool) = next.tool(&tool.name) else {
            dropped.push(tool.name.clone());
            continue;
        };
        let tighter =
            prior
                .row(&tool.name)
                .zip(next.row(&tool.name))
                .is_some_and(|(before, after)| {
                    after.effective_disposition() > before.effective_disposition()
                });
        if next_tool != tool || tighter {
            narrowed.push(tool.name.clone());
        }
    }
    (narrowed, dropped)
}

/// The wording of the question: the one place it lives.
fn ask_text(
    record: &ConnectorKeyRecord,
    revision: &str,
    prior: &ConnectorGrantSlate,
    next: &ConnectorGrantSlate,
) -> String {
    let name = record
        .catalog
        .as_ref()
        .map_or(record.connector.as_str(), |entry| entry.name.as_str());
    let from = record.protocol_revision.as_deref().unwrap_or("none");
    let (narrowed, dropped) = changed_tools(prior, next);
    let listed = |tools: &[String]| {
        if tools.is_empty() {
            "none".to_owned()
        } else {
            tools.join(", ")
        }
    };
    let mut text = format!(
        "Connector {name} changed its protocol revision from {from} to {revision}. Every \
         change only narrowed what it may do, so your stamp carried forward: it re-qualifies \
         without a new tap, and no row asks you again. Narrowed: {narrowed}. Dropped: \
         {dropped}. Keep it, or switch it off in one act at {CONNECTOR_SWITCH_OFF_DOOR} with \
         enabled false. An answer here applies nothing.",
        narrowed = listed(&narrowed),
        dropped = listed(&dropped),
    );
    if text.len() > MAX_ASK_TEXT_BYTES {
        let mut end = MAX_ASK_TEXT_BYTES;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}
