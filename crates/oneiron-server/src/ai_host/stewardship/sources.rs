//! What each model a follow-up draft goes to may read of its sources (FIX
//! 8714). Every offer the draft's call reaches is sent the draft's evidence
//! and voice that its own destination may receive, read for that
//! destination and kept, receipt included, before any byte goes, and read
//! again right before the send; a destination that may receive no evidence
//! or no voice is passed over, and the call goes on down the ladder. The
//! draft is scheduled as the offer that answered read it: with the evidence
//! and the voice samples it was sent (FIX 9447).

use std::sync::{Mutex, PoisonError};

use oneiron::dreamer_runner::maintenance::representation::{
    DestinationContext, PrematerializedDraft, RepresentationContext, RepresentationDraft,
    RepresentationPlanner,
};
use oneiron::dreamer_runner::maintenance::stewardship::StewardshipDraftRequest;
use oneiron::settings::{ReadDestination, ReleaseHold};
use oneiron::{ContentPart, Error, LlmMessage, LlmMessageRole, LlmRequest, Vault};

use super::draft::GeneratedDraft;
use crate::models::{SourceAdmission, SourceOffer};

/// The messages a draft's call carries: the owner's own instruction as the
/// system message, and `context`'s sources as data.
pub(super) fn draft_messages(
    draft: &StewardshipDraftRequest,
    context: &RepresentationContext,
) -> Vec<LlmMessage> {
    vec![
        message(LlmMessageRole::System, draft.instruction.clone()),
        message(LlmMessageRole::User, sources_text(draft, context)),
    ]
}

fn message(role: LlmMessageRole, text: String) -> LlmMessage {
    LlmMessage {
        role,
        content: vec![ContentPart::Text { text }],
    }
}

/// `context`'s sources as the draft's call sends them.
fn sources_text(draft: &StewardshipDraftRequest, context: &RepresentationContext) -> String {
    // Each evidence source carries the marker its citation checks for; the
    // voice samples are the owner's own words.
    serde_json::json!({
        "kind": "follow_up",
        "channel": draft.request.channel,
        "target": draft.request.target,
        "evidence": context
            .evidence
            .iter()
            .map(|source| serde_json::json!({
                "cite": source.cite(String::new()).marker(),
                "text": source.text,
            }))
            .collect::<Vec<_>>(),
        "voice": context
            .voice
            .iter()
            .map(|source| source.text.as_str())
            .collect::<Vec<_>>(),
    })
    .to_string()
}

/// One draft's sources, admitted for each offer its call reaches.
pub(super) struct DraftSources<'a> {
    vault: &'a Vault,
    draft: &'a StewardshipDraftRequest,
    parts: &'a [GeneratedDraft],
    /// What the offer last admitted was sent, kept before any byte went to
    /// it: its read bound to that destination, receipt included.
    sent: Mutex<Option<DestinationContext>>,
}

impl<'a> DraftSources<'a> {
    pub(super) const fn new(
        vault: &'a Vault,
        draft: &'a StewardshipDraftRequest,
        parts: &'a [GeneratedDraft],
    ) -> Self {
        Self {
            vault,
            draft,
            parts,
            sent: Mutex::new(None),
        }
    }

    pub(super) fn messages(&self, context: &RepresentationContext) -> Vec<LlmMessage> {
        if self.parts.is_empty() {
            return draft_messages(self.draft, context);
        }
        vec![
            message(LlmMessageRole::System, self.draft.instruction.clone()),
            message(LlmMessageRole::User, serde_json::json!({
                "kind": "follow_up",
                "channel": self.draft.request.channel,
                "target": self.draft.request.target,
                "evidence_drafts": self.parts.iter().map(|part| serde_json::json!({
                    "cites": part.snapshot.context.evidence.iter()
                        .map(|source| source.cite(String::new()).marker()).collect::<Vec<_>>(),
                    "text": part.text,
                })).collect::<Vec<_>>(),
                "voice": context.voice.iter().map(|source| source.text.as_str()).collect::<Vec<_>>(),
            }).to_string()),
        ]
    }

    /// The draft as the offer that answered read it: its evidence and its
    /// voice narrowed to what that offer was sent, so its voice provenance
    /// names only the samples it received (FIX 9447). `None` when no offer
    /// was sent anything.
    pub(super) fn served(self) -> Option<(StewardshipDraftRequest, DestinationContext)> {
        let sent = self
            .sent
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)?;
        let mut served = self.draft.clone();
        served.request.evidence = sent.context.request.evidence.clone();
        served.request.voice = sent.context.request.voice.clone();
        Some((served, sent))
    }

    /// The draft's sources `destination` may receive, read now; a read
    /// nobody can judge holds the offer, as an integrity hold.
    fn admitted(&self, destination: &ReadDestination) -> Result<DestinationContext, &'static str> {
        self.vault
            .representation_context_for(&self.draft.request, destination)
            .map_err(|error| {
                // By kind only: an engine error can quote the vault.
                tracing::warn!(
                    kind = ?error.kind(),
                    "a stewardship draft's sources could not be read for a model's destination"
                );
                ReleaseHold::Placement.reason()
            })
    }
}

impl SourceAdmission for DraftSources<'_> {
    fn offer(&self, request: &LlmRequest, destination: &ReadDestination) -> SourceOffer {
        let admitted = match self.admitted(destination) {
            Ok(admitted) => admitted,
            Err(reason) => return SourceOffer::Held(reason),
        };
        if admitted.context.evidence.is_empty() || admitted.context.voice.is_empty() {
            return SourceOffer::Held(admitted.held.unwrap_or(ReleaseHold::Placement).reason());
        }
        // A derived draft cannot be narrowed by dropping some of its inputs.
        if self
            .parts
            .iter()
            .any(|part| !contains_sources(&admitted.context, &part.snapshot.context))
        {
            return SourceOffer::Held(admitted.held.unwrap_or(ReleaseHold::Placement).reason());
        }
        let mut offered = request.clone();
        let Some(data) = offered
            .messages
            .iter_mut()
            .rev()
            .find(|message| message.role == LlmMessageRole::User)
        else {
            return SourceOffer::Held(ReleaseHold::Placement.reason());
        };
        *data = self
            .messages(&admitted.context)
            .pop()
            .expect("draft data message");
        // Kept before any byte goes to the destination.
        *self.sent.lock().unwrap_or_else(PoisonError::into_inner) = Some(admitted);
        SourceOffer::Send(offered)
    }

    fn recheck(&self, destination: &ReadDestination) -> Option<&'static str> {
        let sent = self
            .sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(sent) = sent.filter(|sent| sent.destination == *destination) else {
            return Some(ReleaseHold::Placement.reason());
        };
        let now = match self.admitted(destination) {
            Ok(now) => now,
            Err(reason) => return Some(reason),
        };
        // Every source sent still reads for it, at the revision sent.
        let holds = contains_sources(&now.context, &sent.context);
        (!holds).then(|| now.held.unwrap_or(ReleaseHold::Placement).reason())
    }
}

/// Compare the actual bytes and revisions, not just claim references.
pub(super) fn contains_sources(
    context: &RepresentationContext,
    expected: &RepresentationContext,
) -> bool {
    expected
        .evidence
        .iter()
        .all(|source| context.evidence.contains(source))
        && expected
            .voice
            .iter()
            .all(|source| context.voice.contains(source))
}

/// Cites only the source revisions the answering offer actually received.
pub(super) struct SourcedDraft {
    expected: RepresentationContext,
    inner: PrematerializedDraft,
}

impl SourcedDraft {
    pub(super) fn new(text: String, expected: RepresentationContext) -> Self {
        Self {
            expected,
            inner: PrematerializedDraft { text },
        }
    }
}

impl RepresentationPlanner for SourcedDraft {
    fn plan(&mut self, context: &RepresentationContext) -> oneiron::Result<RepresentationDraft> {
        let unchanged = self
            .expected
            .evidence
            .iter()
            .all(|source| context.evidence.contains(source))
            && self
                .expected
                .voice
                .iter()
                .all(|source| context.voice.contains(source));
        if !unchanged {
            return Err(Error::InvalidClaimBody("stewardship draft sources changed"));
        }
        self.inner.plan(context)
    }
}
