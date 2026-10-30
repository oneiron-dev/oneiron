//! A delivered proactivity digest as one viewer reads it (FIX 6411). The
//! stored digest is one canonical object under its stable locator, verified
//! by its content hash (FIX 2332) before anything reads it; a view then
//! keeps the proposals this viewer reads ([`super::private_sources`]) and
//! rebuilds the text from them under the presentation the digest was
//! assembled under. A shared timer digest is no shared authorization: the
//! owner's read, the assembly's answer and each delivery are each the
//! viewer's own view. Nothing but a proposal drawn from private thread words
//! this viewer does not read is left out, and the view says nothing of what
//! was.

use std::collections::BTreeMap;

use serde::Serialize;

use super::super::agent_health::{COACH_AGENT_HEALTH_FACET, ConcernCardSummary};
use super::private_sources::digest_item_readable_by_in;
use super::{
    CLEANUP_GROUP, DIGEST, DigestApplied, DigestCleanup, DigestNoteTombstones, DigestOffer,
    DigestProposal, EVAL_LABEL_ASK_GROUP, JUDGE_ASK_GROUP, NOTE_TOMBSTONE_GROUP,
    ProactivityDigest, ProactivityPresentation, TRAINING_OFFER_GROUP, invalid, load_state,
};
use crate::{EntityId, Result, Vault};

/// A delivered digest as one viewer reads it (FIX 6411): the stored
/// digest's locator and lines, less each proposal whose words come from a
/// private thread this viewer does not read, or did not read when those
/// words were written, with its text rebuilt from what is left. A
/// projection: neither its text nor its lines are checked against the
/// stored digest's content hash, which it does not carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct ProactivityDigestView {
    /// The stored digest's locator (FIX 2332): what its notifications name.
    pub id: [u8; 32],
    /// When the digest was assembled.
    pub created_at: u64,
    /// The authenticated reader the asks are addressed to; `None` for the
    /// ownerless timer projection, which carries no asks.
    #[serde(with = "crate::serialize::entity_ref::optional")]
    #[schemars(with = "Option<String>")]
    pub recipient: Option<EntityId>,
    /// Whether an urgent wake broke through the cadence for it.
    pub urgent: bool,
    /// The proposals this viewer reads, by display group.
    pub groups: BTreeMap<String, Vec<DigestProposal>>,
    /// The recipient's judge asks.
    pub judge_asks: Vec<crate::skill_optimize::JudgeAsk>,
    /// The recipient's eval label asks.
    pub eval_label_asks: Vec<crate::skill_optimize::EvalLabelAsk>,
    /// Pending training offers not carried by an earlier digest.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub offers: Vec<DigestOffer>,
    /// The cleanup line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup: Option<DigestCleanup>,
    /// The NOTE tombstone line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note_tombstones: Option<DigestNoteTombstones>,
    /// The applied-maintenance after-notice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied: Option<DigestApplied>,
    /// The Coach's agent-health cards.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub health_cards: Vec<ConcernCardSummary>,
    /// The digest's text as this viewer reads it: the stored text when the
    /// view keeps every proposal, else rebuilt from what it keeps.
    pub rendered: String,
    /// A host-facing style hint; the host owns voice rendering.
    pub voice_style: String,
}

impl ProactivityDigestView {
    /// Whether the view carries nothing: no proposal, ask, offer or line.
    pub(super) fn is_empty(&self) -> bool {
        self.groups.is_empty()
            && self.judge_asks.is_empty()
            && self.eval_label_asks.is_empty()
            && self.offers.is_empty()
            && self.cleanup.is_none()
            && self.note_tombstones.is_none()
            && self.applied.is_none()
            && self.health_cards.is_empty()
    }
}

impl Vault {
    /// The latest scheduled or urgent digest for the host's inbox and board
    /// read plane (`GET /v1/owner/proactivity/digest`), as the
    /// authenticated owner reads it: verified as stored (FIX 2332), then
    /// screened for them (FIX 6411). `None` before any digest.
    ///
    /// # Errors
    /// A refusal when the proof is no longer a live owner of this vault; a
    /// stored digest that does not verify; storage faults.
    pub fn latest_proactivity_digest_view(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
    ) -> Result<Option<ProactivityDigestView>> {
        let txn = self.store.env.read_txn()?;
        let viewer = crate::dreamer_runner::maintenance::validate_owner_in_txn(self, &txn, owner)?;
        let Some(id) = load_state(self, &txn)?.last_digest_id else {
            return Ok(None);
        };
        Ok(read_digest_in(self, &txn, id)?
            .map(|digest| digest_view_for_in(self, &txn, &digest, viewer)))
    }

    /// One delivered digest by its locator, an inbox NOTIFICATION's
    /// `source.result`, as the authenticated owner reads it: verified as
    /// stored (FIX 2332), then screened for them (FIX 6411). `None` for a
    /// locator no digest is stored under.
    ///
    /// # Errors
    /// A refusal when the proof is no longer a live owner of this vault; a
    /// stored digest that does not verify; storage faults.
    pub fn proactivity_digest_view(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        id: [u8; 32],
    ) -> Result<Option<ProactivityDigestView>> {
        let txn = self.store.env.read_txn()?;
        let viewer = crate::dreamer_runner::maintenance::validate_owner_in_txn(self, &txn, owner)?;
        Ok(read_digest_in(self, &txn, id)?
            .map(|digest| digest_view_for_in(self, &txn, &digest, viewer)))
    }
}

/// The digest stored under `id`, verified (FIX 2332): it names that id as
/// its locator, and its content hash is the hash of what it holds. The
/// canonical object, unscreened: a person reads [`digest_view_for_in`].
pub(super) fn read_digest_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: [u8; 32],
) -> Result<Option<ProactivityDigest>> {
    DIGEST
        .get(&vault.store, txn, &id)?
        .map(|digest| {
            if digest.id != id || content_hash(&digest)? != digest.content_hash {
                return Err(invalid());
            }
            Ok(digest)
        })
        .transpose()
}

/// FIX 2332: the digest's stable locator, the hash of every field it shows
/// as assembled, before the side-row wall reads it. It is chosen once, the
/// digest is admitted and stored under it, and every notification and the
/// board pointer name it. It is never checked against what the digest shows
/// now, which the wall may have masked: [`content_hash`] is.
pub(super) fn digest_id(digest: &ProactivityDigest) -> Result<[u8; 32]> {
    hash(&shown(digest))
}

/// FIX 2332: the digest's integrity check, the hash of its locator and of
/// every field it stores as admitted; the content hash alone is left out.
pub(super) fn content_hash(digest: &ProactivityDigest) -> Result<[u8; 32]> {
    hash(&(digest.id, shown(digest)))
}

/// Every field of `digest` but its locator and its content hash.
fn shown(digest: &ProactivityDigest) -> impl Serialize + '_ {
    (
        digest.created_at,
        digest.recipient,
        digest.urgent,
        &digest.groups,
        &digest.judge_asks,
        &digest.eval_label_asks,
        &digest.offers,
        &digest.cleanup,
        &digest.note_tombstones,
        &digest.applied,
        &digest.health_cards,
        &digest.rendered,
        &digest.voice_style,
        &digest.presentation,
        &digest.witness,
    )
}

/// BLAKE3 over `value`'s JSON.
fn hash(value: &impl Serialize) -> Result<[u8; 32]> {
    let bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

/// `digest`, the canonical object, as `viewer` reads it: each proposal
/// whose words it reads, and every line and ask as stored. An authorized
/// viewer's proposal is never left out because another reader could not
/// read it.
pub(super) fn digest_view_for_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    digest: &ProactivityDigest,
    viewer: EntityId,
) -> ProactivityDigestView {
    let mut withheld = false;
    let mut groups = BTreeMap::new();
    for (group, proposals) in &digest.groups {
        let kept: Vec<DigestProposal> = proposals
            .iter()
            .filter(|proposal| {
                let readable = digest_item_readable_by_in(vault, txn, proposal, viewer);
                withheld |= !readable;
                readable
            })
            .cloned()
            .collect();
        if !kept.is_empty() {
            groups.insert(group.clone(), kept);
        }
    }
    let rendered = if withheld {
        render(digest, &groups)
    } else {
        digest.rendered.clone()
    };
    ProactivityDigestView {
        id: digest.id,
        created_at: digest.created_at,
        recipient: digest.recipient,
        urgent: digest.urgent,
        groups,
        judge_asks: digest.judge_asks.clone(),
        eval_label_asks: digest.eval_label_asks.clone(),
        offers: digest.offers.clone(),
        cleanup: digest.cleanup.clone(),
        note_tombstones: digest.note_tombstones.clone(),
        applied: digest.applied.clone(),
        health_cards: digest.health_cards.clone(),
        rendered,
        voice_style: digest.voice_style.clone(),
    }
}

/// The text of `groups` and `digest`'s lines under the presentation the
/// digest was assembled under: each display group and its items, then the
/// recipient's judge asks, the eval label asks, the training offers, the
/// cleanup line, the NOTE tombstone line, the applied after-notice and the
/// health cards. Assembly writes the stored text so, from every group; a
/// view rebuilds it from the groups it keeps.
pub(super) fn render(
    digest: &ProactivityDigest,
    groups: &BTreeMap<String, Vec<DigestProposal>>,
) -> String {
    let presentation = &digest.presentation;
    let mut rendered = String::new();
    for (group, proposals) in groups {
        rendered.push_str(&group_line(presentation, group));
        for proposal in proposals {
            let reference = proposal.claim_ref.to_hex();
            rendered.push_str(&item_line(presentation, &proposal.summary, &reference));
        }
    }
    if !digest.judge_asks.is_empty() {
        let group = alias(presentation, JUDGE_ASK_GROUP);
        rendered.push_str(&group_line(presentation, group));
        for ask in &digest.judge_asks {
            let reference = crate::entity_id::bytes_to_hex_lower(&ask.id);
            rendered.push_str(&item_line(presentation, &judge_ask_summary(ask), &reference));
        }
    }
    if !digest.eval_label_asks.is_empty() {
        let group = alias(presentation, EVAL_LABEL_ASK_GROUP);
        rendered.push_str(&group_line(presentation, group));
        for ask in &digest.eval_label_asks {
            let reference = ask.id.to_hex();
            rendered.push_str(&item_line(
                presentation,
                &eval_label_ask_summary(ask),
                &reference,
            ));
        }
    }
    if !digest.offers.is_empty() {
        let group = alias(presentation, TRAINING_OFFER_GROUP);
        rendered.push_str(&group_line(presentation, group));
        for offer in &digest.offers {
            let reference = offer.offer.to_hex();
            rendered.push_str(&item_line(presentation, &offer.summary, &reference));
        }
    }
    if let Some(line) = &digest.cleanup {
        let group = alias(presentation, CLEANUP_GROUP);
        rendered.push_str(&group_line(presentation, group));
        for summary in line.summaries() {
            rendered.push_str(&item_line(presentation, &summary, &line.view));
        }
    }
    if let Some(line) = &digest.note_tombstones {
        let group = alias(presentation, NOTE_TOMBSTONE_GROUP);
        rendered.push_str(&group_line(presentation, group));
        rendered.push_str(&item_line(presentation, &line.summary(), &line.view));
    }
    if let Some(line) = &digest.applied {
        line.render(presentation, &mut rendered);
    }
    if !digest.health_cards.is_empty() {
        let facet = COACH_AGENT_HEALTH_FACET;
        rendered.push_str(&group_line(presentation, alias(presentation, facet)));
        for card in &digest.health_cards {
            let summary = format!(
                "{facet}: {} {} {} on {}",
                card.signal, card.tone, card.outcome, card.agent
            );
            rendered.push_str(&item_line(presentation, &summary, &card.card));
        }
    }
    rendered
}

/// One judge ask as a rendered line: its campaign, its reason and its two
/// options. The line's ref is the ask's id, which its answer binds.
fn judge_ask_summary(ask: &crate::skill_optimize::JudgeAsk) -> String {
    let reason = match ask.reason {
        crate::skill_optimize::JudgeAskReason::RevisionDisagreement => "revision disagreement",
        crate::skill_optimize::JudgeAskReason::Uncertainty => "uncertainty",
        crate::skill_optimize::JudgeAskReason::RubricRecheck => "rubric recheck",
        crate::skill_optimize::JudgeAskReason::RubricRegrade => "rubric regrade",
    };
    format!(
        "{}: {reason} ({} vs {})",
        ask.campaign, ask.option_a, ask.option_b
    )
}

/// One eval label ask as a rendered line: the decision waiting on it and
/// its two options. The line's ref is the ask's id, which its answer binds.
fn eval_label_ask_summary(ask: &crate::skill_optimize::EvalLabelAsk) -> String {
    format!("{} ({} vs {})", ask.decision, ask.option_a, ask.option_b)
}

/// `presentation`'s line for the display group `group`.
fn group_line(presentation: &ProactivityPresentation, group: &str) -> String {
    presentation.group_template.replace("{group}", group)
}

/// `presentation`'s line for one item: its summary and its ref.
fn item_line(presentation: &ProactivityPresentation, summary: &str, reference: &str) -> String {
    presentation
        .item_template
        .replace("{summary}", summary)
        .replace("{ref}", reference)
}

/// The display group of the derived group `group`: its alias, or itself.
fn alias<'p>(presentation: &'p ProactivityPresentation, group: &'p str) -> &'p str {
    presentation
        .group_aliases
        .get(group)
        .map_or(group, String::as_str)
}
