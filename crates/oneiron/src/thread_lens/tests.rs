use serde_json::Value;

use super::*;
use crate::{
    outbound::{OutboundIntentDraft, OutboundIntentSource, OutboundIntentTrigger},
    receipt::{ReceiptKind, outbound_intent_receipt},
};

fn intent(channel: &str, verb: &str, target: &str) -> OutboundIntent {
    OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", verb, channel, target)
            .content_ref("content:thread-draft")
            .idempotency_key(format!("{channel}:{target}:draft")),
        OutboundIntentTrigger {
            source: OutboundIntentSource::AgentImmediate,
            trigger_ref: "thread-lens:send".to_owned(),
            job_ref: Some("job:thread-lens".to_owned()),
        },
    )
}

fn delivered_receipt(channel: &str, verb: &str) -> ReceiptRecord {
    let outbound = intent(channel, verb, "target:one");
    let mut receipt = outbound_intent_receipt(
        "outbound:intent:thread-send",
        "intent:thread-send",
        &outbound,
        1_800_000_100,
        "delivered_to_channel",
    );
    receipt.fields.insert(
        "provider_ref".to_owned(),
        format!("{channel}:thread:abc@message:def"),
    );
    receipt.fields.insert(
        "artifact_thread_message_ref".to_owned(),
        format!("{channel}:thread:abc@message:def"),
    );
    receipt.fields.insert(
        "send_verification".to_owned(),
        "content_observed".to_owned(),
    );
    receipt
}

fn pending_receipt() -> ReceiptRecord {
    ReceiptRecord {
        receipt_id: "outbound:intent:pending".to_owned(),
        receipt_kind: ReceiptKind::Outbound,
        occurred_at: 1_800_000_000,
        actor: Some("agent-alpha".to_owned()),
        on_behalf_of: Some("owner".to_owned()),
        outcome: "held".to_owned(),
        job_ref: None,
        trigger_ref: Some("thread-lens:send".to_owned()),
        policy_trace: vec!["gate.pending.external_effect_authority".to_owned()],
        fields: [
            ("gate_outcome".to_owned(), "pending".to_owned()),
            (
                "hold_reason".to_owned(),
                "gate.pending.external_effect_authority".to_owned(),
            ),
        ]
        .into_iter()
        .collect(),
    }
}

fn linkedin_lens(receipts: Vec<ReceiptRecord>) -> Result<ThreadLensInstrument> {
    let send_box = ThreadLensSendBox::new(
        "intent:thread-send",
        intent("linkedin", "send_dm", "linkedin:member:jane-doe"),
        "Happy to share more details.",
    )?
    .with_receipts(receipts);
    ThreadLensInstrument::new(
        "linkedin-thread-lens",
        "Jane Doe",
        "linkedin",
        "linkedin:thread:2-jane-doe-abc",
        vec![
            ThreadLensEntry::new(
                "linkedin",
                "Jane Doe",
                "Thanks for reaching out about the pilot.",
            )?
            .timestamp("10:01"),
            ThreadLensEntry::new("linkedin", "Yura", "Happy to share more details.")?
                .timestamp("10:04")
                .message_ref("linkedin:thread:2-jane-doe-abc@message:def"),
        ],
        send_box,
    )
}

fn render_atom_kinds(card: &GeneratedUiCard) -> Result<Vec<&'static str>> {
    Ok(card
        .render()?
        .nodes
        .iter()
        .map(|node| node.atom.kind())
        .collect())
}

fn render_json(card: &GeneratedUiCard) -> Value {
    serde_json::to_value(card.render().expect("render")).expect("json")
}

#[test]
fn linkedin_thread_lens_renders_truthful_send_states_from_receipts() -> Result<()> {
    let mut verified = delivered_receipt("linkedin", "send_dm");
    verified.fields.insert(
        "linkedin_send_verification".to_owned(),
        "content_observed".to_owned(),
    );
    let lens = linkedin_lens(vec![pending_receipt(), verified])?;
    let card = lens.card()?;
    let render = card.render()?;

    let state_labels = render
        .nodes
        .iter()
        .filter_map(|node| match &node.atom {
            LensAtom::StatusDot(atom) => atom.label.as_ref().map(LensText::as_str),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(state_labels.contains(&"pending: complete"));
    assert!(state_labels.contains(&"verified: complete"));
    assert!(state_labels.contains(&"receipted: complete"));

    let send_input = render
        .nodes
        .iter()
        .find_map(|node| match &node.atom {
            LensAtom::SelfUi(SelfUiControl::TextInput(input)) => Some(input),
            _ => None,
        })
        .expect("send input");
    assert_eq!(
        send_input.action.command.as_str(),
        THREAD_LENS_OF327_SEND_COMMAND
    );
    assert_eq!(
        send_input.action.args,
        vec![
            SelfUiValue::Text(lens_text("intent:thread-send")?),
            SelfUiValue::Text(lens_text("linkedin")?),
            SelfUiValue::Text(lens_text("send_dm")?),
            SelfUiValue::Text(lens_text("linkedin:member:jane-doe")?),
            SelfUiValue::Text(lens_text(THREAD_LENS_INBOX_DRAFTS_KIND)?),
        ]
    );

    Ok(())
}

#[test]
fn thread_lens_survives_viewer_restart_from_engine_receipts() -> Result<()> {
    let receipts = vec![pending_receipt(), delivered_receipt("linkedin", "send_dm")];
    let first = linkedin_lens(receipts.clone())?.card()?;
    let restarted_viewer = linkedin_lens(receipts)?.card()?;

    assert_eq!(render_json(&first), render_json(&restarted_viewer));
    Ok(())
}

#[test]
fn second_channel_fixture_mounts_with_same_thread_entry_component() -> Result<()> {
    let send_box = ThreadLensSendBox::new(
        "intent:slack-thread-send",
        intent("slack", "send", "slack:channel:C123"),
        "I can send the overview here too.",
    )?
    .with_receipts(vec![delivered_receipt("slack", "send")]);
    let lens = ThreadLensInstrument::new(
        "slack-thread-lens",
        "Pilot channel",
        "slack",
        "slack:thread:C123:1700000000.000100",
        vec![
            ThreadLensEntry::new("slack", "Kenji", "Can you send the overview?")?,
            ThreadLensEntry::new("slack", "Yura", "I can send the overview here too.")?,
        ],
        send_box,
    )?;
    let card = lens.card()?;
    let atom_kinds = render_atom_kinds(&card)?;

    assert_eq!(
        atom_kinds
            .iter()
            .filter(|kind| **kind == "thread_entry")
            .count(),
        2
    );
    assert!(
        !atom_kinds.iter().any(|kind| kind.contains("linkedin")),
        "the second fixture must not require a LinkedIn-specific atom"
    );
    Ok(())
}

#[test]
fn drafts_awaiting_send_are_visible_as_inbox_kind() -> Result<()> {
    let card = linkedin_lens(vec![pending_receipt()])?.card()?;
    let render = card.render()?;
    let inbox_kind = render.nodes.iter().find_map(|node| match &node.atom {
        LensAtom::MetaLine(line) if line.label.as_str() == "inbox kind" => {
            Some(line.value.as_str())
        }
        _ => None,
    });

    assert_eq!(inbox_kind, Some(THREAD_LENS_INBOX_DRAFTS_KIND));
    assert_eq!(
        ThreadLensSendProgress::from_receipts(&[pending_receipt()]).verified,
        ThreadLensStepState::Waiting
    );
    Ok(())
}
