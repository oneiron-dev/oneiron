//! Channel-agnostic conversation thread lens (ONE-1567 / LNKD-5).
//!
//! The lens is a projection over engine-owned claims and receipts. Renderers
//! receive the existing closed atom-kit primitives: `thread_entry`, `self_ui`,
//! `status_dot`, and `meta_line`.

use crate::{
    Error, Result,
    lens::{
        CollectionAtom, GeneratedUiCard, LensAtom, LensAtomId, LensRenderId, LensStatus, LensText,
        MetaLineAtom, SectionAtom, SelfUiAction, SelfUiActionId, SelfUiControl, SelfUiControlId,
        SelfUiValue, StatusDotAtom, TextInputControl, ThreadEntryAtom,
    },
    outbound::OutboundIntent,
    receipt::ReceiptRecord,
};

/// Inbox kind used for drafts that are waiting for an approve-to-send action.
pub const THREAD_LENS_INBOX_DRAFTS_KIND: &str = "drafts_awaiting_send";

/// OF-336 action command used by the send box to trigger the OF-327 path.
pub const THREAD_LENS_OF327_SEND_COMMAND: &str = "of327.dispatch";

/// One channel-normalized message row in a conversation thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadLensEntry {
    pub channel: String,
    pub author: String,
    pub body: String,
    pub timestamp: Option<String>,
    pub message_ref: Option<String>,
}

impl ThreadLensEntry {
    pub fn new(
        channel: impl Into<String>,
        author: impl Into<String>,
        body: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            channel: non_empty("thread lens entry channel", channel.into())?,
            author: non_empty("thread lens entry author", author.into())?,
            body: non_empty("thread lens entry body", body.into())?,
            timestamp: None,
            message_ref: None,
        })
    }

    #[must_use]
    pub fn timestamp(mut self, timestamp: impl Into<String>) -> Self {
        self.timestamp = Some(timestamp.into());
        self
    }

    #[must_use]
    pub fn message_ref(mut self, message_ref: impl Into<String>) -> Self {
        self.message_ref = Some(message_ref.into());
        self
    }
}

/// Send-box input: an OF-327 intent plus the engine receipts already known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadLensSendBox {
    pub intent_ref: String,
    pub intent: OutboundIntent,
    pub draft_text: String,
    pub inbox_kind: String,
    pub receipts: Vec<ReceiptRecord>,
}

impl ThreadLensSendBox {
    pub fn new(
        intent_ref: impl Into<String>,
        intent: OutboundIntent,
        draft_text: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            intent_ref: non_empty("thread lens intent ref", intent_ref.into())?,
            intent,
            draft_text: non_empty("thread lens draft text", draft_text.into())?,
            inbox_kind: THREAD_LENS_INBOX_DRAFTS_KIND.to_owned(),
            receipts: Vec::new(),
        })
    }

    #[must_use]
    pub fn with_receipts(mut self, receipts: Vec<ReceiptRecord>) -> Self {
        self.receipts = receipts;
        self
    }

    #[must_use]
    pub fn send_progress(&self) -> ThreadLensSendProgress {
        ThreadLensSendProgress::from_receipts(&self.receipts)
    }
}

/// Engine-side data needed to render one thread-lens instrument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadLensInstrument {
    pub card_id: String,
    pub title: String,
    pub channel: String,
    pub thread_ref: String,
    pub entries: Vec<ThreadLensEntry>,
    pub send_box: ThreadLensSendBox,
}

impl ThreadLensInstrument {
    pub fn new(
        card_id: impl Into<String>,
        title: impl Into<String>,
        channel: impl Into<String>,
        thread_ref: impl Into<String>,
        entries: Vec<ThreadLensEntry>,
        send_box: ThreadLensSendBox,
    ) -> Result<Self> {
        let instrument = Self {
            card_id: non_empty("thread lens card id", card_id.into())?,
            title: non_empty("thread lens title", title.into())?,
            channel: non_empty("thread lens channel", channel.into())?,
            thread_ref: non_empty("thread lens thread ref", thread_ref.into())?,
            entries,
            send_box,
        };
        instrument.validate()?;
        Ok(instrument)
    }

    pub fn card(&self) -> Result<GeneratedUiCard> {
        let mut root = crate::lens::LensNode::with_fallback_text(
            atom_id("thread-lens-root")?,
            LensAtom::Sheet(CollectionAtom {
                title: lens_text(&self.title)?,
                rows: Vec::new(),
            }),
            lens_text(format!("{} {}", self.title, self.thread_ref))?,
        );

        root.children
            .push(meta_node("thread-lens-channel", "channel", &self.channel)?);
        root.children
            .push(meta_node("thread-lens-thread", "thread", &self.thread_ref)?);

        for (index, entry) in self.entries.iter().enumerate() {
            root.children.push(entry_node(index, entry)?);
        }

        root.children.push(send_box_node(&self.send_box)?);

        GeneratedUiCard::card(render_id(&self.card_id)?, root)
    }

    fn validate(&self) -> Result<()> {
        if self
            .entries
            .iter()
            .any(|entry| entry.channel != self.channel)
        {
            return Err(Error::InvalidConfig(
                "thread lens entries must belong to the instrument channel".to_owned(),
            ));
        }
        if self.send_box.intent.channel != self.channel {
            return Err(Error::InvalidConfig(
                "thread lens send intent must belong to the instrument channel".to_owned(),
            ));
        }
        Ok(())
    }
}

/// One visible step in the send box state rail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadLensStepState {
    Waiting,
    Complete,
    Failed,
}

impl ThreadLensStepState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Complete => "complete",
            Self::Failed => "failed",
        }
    }

    const fn lens_status(self) -> LensStatus {
        match self {
            Self::Waiting => LensStatus::Running,
            Self::Complete => LensStatus::Complete,
            Self::Failed => LensStatus::Rejected,
        }
    }
}

/// Send progress derived only from engine receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadLensSendProgress {
    pub pending: ThreadLensStepState,
    pub verified: ThreadLensStepState,
    pub receipted: ThreadLensStepState,
    pub latest_receipt_id: Option<String>,
    pub thread_message_ref: Option<String>,
}

impl ThreadLensSendProgress {
    #[must_use]
    pub fn from_receipts(receipts: &[ReceiptRecord]) -> Self {
        let latest = latest_receipt(receipts);
        let latest_receipt_id = latest.map(|receipt| receipt.receipt_id.clone());
        let thread_message_ref = latest.and_then(thread_message_ref).map(str::to_owned);

        let failed = latest.is_some_and(receipt_failed);
        let waiting_on_approval = latest.is_none_or(receipt_is_pending_hold);
        let verified = latest.is_some_and(receipt_verified_send);
        let receipted = verified && thread_message_ref.is_some();

        Self {
            pending: if waiting_on_approval {
                ThreadLensStepState::Waiting
            } else {
                ThreadLensStepState::Complete
            },
            verified: if verified {
                ThreadLensStepState::Complete
            } else if failed {
                ThreadLensStepState::Failed
            } else {
                ThreadLensStepState::Waiting
            },
            receipted: if receipted {
                ThreadLensStepState::Complete
            } else if failed {
                ThreadLensStepState::Failed
            } else {
                ThreadLensStepState::Waiting
            },
            latest_receipt_id,
            thread_message_ref,
        }
    }
}

fn entry_node(index: usize, entry: &ThreadLensEntry) -> Result<crate::lens::LensNode> {
    let mut node = crate::lens::LensNode::new(
        atom_id(format!("thread-entry-{index}"))?,
        LensAtom::ThreadEntry(ThreadEntryAtom {
            author: lens_text(&entry.author)?,
            body: lens_text(&entry.body)?,
            timestamp: entry.timestamp.as_ref().map(lens_text).transpose()?,
            seal: None,
        }),
    );
    if let Some(message_ref) = entry.message_ref.as_deref() {
        node.children.push(meta_node(
            format!("thread-entry-{index}-message-ref"),
            "message",
            message_ref,
        )?);
    }
    Ok(node)
}

fn send_box_node(send_box: &ThreadLensSendBox) -> Result<crate::lens::LensNode> {
    let progress = send_box.send_progress();
    let mut node = crate::lens::LensNode::with_fallback_text(
        atom_id("thread-send-box")?,
        LensAtom::Slip(SectionAtom {
            title: lens_text("Drafts awaiting send")?,
            lines: vec![lens_text(&send_box.draft_text)?],
        }),
        lens_text(format!("Draft waiting to send: {}", send_box.draft_text))?,
    );

    node.children.push(meta_node(
        "thread-send-inbox-kind",
        "inbox kind",
        &send_box.inbox_kind,
    )?);
    node.children.push(meta_node(
        "thread-send-of327-verb",
        "OF-327 verb",
        format!("{}.{}", send_box.intent.channel, send_box.intent.verb),
    )?);
    node.children.push(send_state_node(
        "thread-send-state-pending",
        "pending",
        progress.pending,
    )?);
    node.children.push(send_state_node(
        "thread-send-state-verified",
        "verified",
        progress.verified,
    )?);
    node.children.push(send_state_node(
        "thread-send-state-receipted",
        "receipted",
        progress.receipted,
    )?);
    if let Some(receipt_id) = progress.latest_receipt_id.as_deref() {
        node.children.push(meta_node(
            "thread-send-latest-receipt",
            "latest receipt",
            receipt_id,
        )?);
    }
    if let Some(message_ref) = progress.thread_message_ref.as_deref() {
        node.children.push(meta_node(
            "thread-send-message-ref",
            "thread message",
            message_ref,
        )?);
    }
    node.children.push(send_input_node(send_box)?);
    Ok(node)
}

fn send_input_node(send_box: &ThreadLensSendBox) -> Result<crate::lens::LensNode> {
    Ok(crate::lens::LensNode::new(
        atom_id("thread-send-input")?,
        LensAtom::SelfUi(SelfUiControl::TextInput(TextInputControl {
            id: control_id("thread-send-input")?,
            label: lens_text("Send")?,
            placeholder: Some(lens_text("Message")?),
            value: Some(lens_text(&send_box.draft_text)?),
            action: SelfUiAction {
                command: action_id(THREAD_LENS_OF327_SEND_COMMAND)?,
                args: vec![
                    SelfUiValue::Text(lens_text(&send_box.intent_ref)?),
                    SelfUiValue::Text(lens_text(&send_box.intent.channel)?),
                    SelfUiValue::Text(lens_text(&send_box.intent.verb)?),
                    SelfUiValue::Text(lens_text(&send_box.intent.target)?),
                    SelfUiValue::Text(lens_text(&send_box.inbox_kind)?),
                ],
            },
        })),
    ))
}

fn send_state_node(
    id: impl Into<String>,
    label: &'static str,
    state: ThreadLensStepState,
) -> Result<crate::lens::LensNode> {
    Ok(crate::lens::LensNode::new(
        atom_id(id)?,
        LensAtom::StatusDot(StatusDotAtom {
            status: state.lens_status(),
            label: Some(lens_text(format!("{label}: {}", state.as_str()))?),
        }),
    ))
}

fn meta_node(
    id: impl Into<String>,
    label: impl Into<String>,
    value: impl Into<String>,
) -> Result<crate::lens::LensNode> {
    Ok(crate::lens::LensNode::new(
        atom_id(id)?,
        LensAtom::MetaLine(MetaLineAtom {
            label: lens_text(label)?,
            value: lens_text(value)?,
        }),
    ))
}

fn latest_receipt(receipts: &[ReceiptRecord]) -> Option<&ReceiptRecord> {
    receipts.iter().max_by(
        |left, right| match left.occurred_at.cmp(&right.occurred_at) {
            std::cmp::Ordering::Equal => left.receipt_id.cmp(&right.receipt_id),
            ordering => ordering,
        },
    )
}

fn receipt_is_pending_hold(receipt: &ReceiptRecord) -> bool {
    receipt.outcome == "held"
        && (receipt
            .fields
            .get("gate_outcome")
            .is_some_and(|outcome| outcome == "pending")
            || receipt
                .fields
                .get("hold_reason")
                .is_some_and(|reason| reason.starts_with("gate.pending."))
            || receipt
                .policy_trace
                .iter()
                .any(|reason| reason.starts_with("gate.pending.")))
}

fn receipt_failed(receipt: &ReceiptRecord) -> bool {
    matches!(receipt.outcome.as_str(), "failed" | "suppressed")
}

fn receipt_verified_send(receipt: &ReceiptRecord) -> bool {
    if receipt.outcome != "delivered_to_channel" {
        return false;
    }
    [
        "send_verification",
        "verification_state",
        "linkedin_send_verification",
    ]
    .iter()
    .filter_map(|key| receipt.fields.get(*key))
    .any(|state| state == "content_observed" || state == "verified")
}

fn thread_message_ref(receipt: &ReceiptRecord) -> Option<&str> {
    receipt
        .fields
        .get("artifact_thread_message_ref")
        .or_else(|| receipt.fields.get("provider_ref"))
        .map(String::as_str)
}

fn non_empty(context: &str, value: String) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidConfig(format!("{context} must be non-empty")));
    }
    Ok(trimmed.to_owned())
}

fn lens_text(value: impl Into<String>) -> Result<LensText> {
    LensText::new(value)
}

fn atom_id(value: impl Into<String>) -> Result<LensAtomId> {
    LensAtomId::new(value)
}

fn render_id(value: &str) -> Result<LensRenderId> {
    LensRenderId::new(value)
}

fn control_id(value: &str) -> Result<SelfUiControlId> {
    SelfUiControlId::new(value)
}

fn action_id(value: &str) -> Result<SelfUiActionId> {
    SelfUiActionId::new(value)
}

#[cfg(test)]
mod tests {
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
}
