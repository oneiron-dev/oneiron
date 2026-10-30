//! Which cross-child pairs a night's link continuations judge, how one call
//! asks about them, and what each verdict keeps (OF-498d).
//!
//! A pair is two proposals of one of the merge's exposure groups (today's
//! groups, never wider) that came from different children, whose exact
//! identities differ (two of one identity are the merge's own mechanical
//! same-as or conflict card) and that [`link_eligible`] admits. Every such
//! pair is judged: none is ranked, sampled, thresholded or skipped. A call
//! asks one [`NIGHTLY_LINK`] question per pair, its three fixed choices
//! `same_as`, `no_link` and `unresolved`, over the claims by their call-local
//! labels, each value whole.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::KeptDecision;
use crate::dreamer_consolidation::call_labels::{CallLabelMap, LabelKind};
use crate::dreamer_consolidation::nightly_merge::{Proposal, identity_key, subject_label};
use crate::dreamer_consolidation::value_projection::rmpv_to_json;
use crate::llm::decision::catalogue::NIGHTLY_LINK;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionQuestion, MAX_DECISION_STATE_BYTES,
};
use crate::{EntityId, Result};

/// The room one partner's labels, keys and pair entry take in its call's
/// state beside its claim's predicate and value.
const ENTRY_ROOM: usize = 160;

/// What one link question decided about its pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::dreamer_consolidation) enum NightlyLinkVerdict {
    /// The two state the same thing: a proposed SameAs status claim is
    /// written, never an applied edge.
    SameAs,
    /// The two state different things.
    NoLink,
    /// Not settled: the reader said so, abstained, or has not answered.
    Unresolved,
}

impl NightlyLinkVerdict {
    /// Every verdict, in the order a question offers them.
    const ALL: [Self; 3] = [Self::SameAs, Self::NoLink, Self::Unresolved];

    /// The verdict as its question offers it.
    const fn option(self) -> &'static str {
        match self {
            Self::SameAs => "same_as",
            Self::NoLink => "no_link",
            Self::Unresolved => "unresolved",
        }
    }

    /// The verdict `decision` gives: the option it answers. An abstention,
    /// an answer still waiting, or any other answer leaves the pair
    /// unresolved.
    pub(in crate::dreamer_consolidation) fn of(decision: &KeptDecision) -> Self {
        match decision.answer() {
            Some(DecisionAnswer::Choice(option)) => Self::ALL
                .into_iter()
                .find(|verdict| verdict.option() == option.as_str())
                .unwrap_or(Self::Unresolved),
            _ => Self::Unresolved,
        }
    }
}

/// One judged pair as its continuation's result keeps it, whatever the
/// verdict: the two proposals, the children each came from, the verdict, the
/// proposal claim a same-as wrote, the ladder's kept decision, and the grant
/// a same-as's edge was applied under (FIX 8363).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::dreamer_consolidation) struct NightlyLinkProposal {
    /// The proposal that leads the pair: the lower claim id.
    pub(in crate::dreamer_consolidation) source: EntityId,
    pub(in crate::dreamer_consolidation) target: EntityId,
    pub(in crate::dreamer_consolidation) source_children: Vec<AttemptId>,
    pub(in crate::dreamer_consolidation) target_children: Vec<AttemptId>,
    pub(in crate::dreamer_consolidation) verdict: NightlyLinkVerdict,
    /// The proposed SameAs status claim a same-as wrote; none otherwise.
    pub(in crate::dreamer_consolidation) claim: Option<EntityId>,
    pub(in crate::dreamer_consolidation) decision: KeptDecision,
    /// Why the same-as's SameAs edge stands, when it was applied; none
    /// while the link stays proposed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::dreamer_consolidation) applied: Option<AppliedSameAs>,
}

/// An applied same-as's record (FIX 8363, L02 02:15): the owner's standing
/// grant its edge was applied under, and the reason it names.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::dreamer_consolidation) struct AppliedSameAs {
    pub(in crate::dreamer_consolidation) grant_ref: String,
    pub(in crate::dreamer_consolidation) reason: String,
}

/// A proposal that leads pairs, with each partner it leads one with, in
/// order.
pub(in crate::dreamer_consolidation) struct Anchored<'a> {
    pub(in crate::dreamer_consolidation) anchor: &'a Proposal,
    pub(in crate::dreamer_consolidation) partners: Vec<&'a Proposal>,
}

/// Whether two proposals' link is one this proposal can name (lead ruling
/// 10-22): they share their subject or their predicate. Two that differ in
/// both are never asked. A later ruling changes this one line.
fn link_eligible(source: &Proposal, target: &Proposal) -> bool {
    source.body.subject == target.body.subject || source.body.predicate == target.body.predicate
}

/// Whether two proposals came from different children: not both from one
/// and the same child alone.
fn cross_child(source: &Proposal, target: &Proposal) -> bool {
    source.children.len() != 1 || source.children != target.children
}

/// Whether two proposals of one exposure group, with their exact identities,
/// are a pair a link continuation judges.
fn eligible(source: &Proposal, source_key: &[u8], target: &Proposal, target_key: &[u8]) -> bool {
    source_key != target_key && cross_child(source, target) && link_eligible(source, target)
}

/// Every eligible cross-child pair of one exposure group, in order, the
/// lower claim id first.
pub(in crate::dreamer_consolidation) fn cross_child_pairs<'a>(
    group: &[&'a Proposal],
) -> Result<Vec<(&'a Proposal, &'a Proposal)>> {
    let mut keyed: Vec<(&'a Proposal, Vec<u8>)> = Vec::with_capacity(group.len());
    for &proposal in group {
        keyed.push((proposal, identity_key(&proposal.body)?));
    }
    let mut pairs = Vec::new();
    for (at, (source, source_key)) in keyed.iter().enumerate() {
        for (target, target_key) in &keyed[at + 1..] {
            if eligible(source, source_key, target, target_key) {
                pairs.push((*source, *target));
            }
        }
    }
    Ok(pairs)
}

/// Each proposal of `groups` that leads an eligible pair, in id order: one
/// link continuation each.
pub(in crate::dreamer_consolidation) fn anchors(
    groups: &[Vec<&Proposal>],
) -> Result<Vec<EntityId>> {
    let mut anchors = Vec::new();
    for group in groups {
        for (source, _) in cross_child_pairs(group)? {
            anchors.push(source.id);
        }
    }
    anchors.sort_unstable();
    anchors.dedup();
    Ok(anchors)
}

/// The proposal `anchor` names in `groups`, with each later proposal of its
/// group it leads an eligible pair with, as [`cross_child_pairs`] pairs
/// them. None when no group holds it now.
pub(in crate::dreamer_consolidation) fn anchored<'a>(
    groups: &[Vec<&'a Proposal>],
    anchor: EntityId,
) -> Result<Option<Anchored<'a>>> {
    for group in groups {
        let Some(at) = group.iter().position(|proposal| proposal.id == anchor) else {
            continue;
        };
        let source = group[at];
        let source_key = identity_key(&source.body)?;
        let mut partners = Vec::new();
        for &target in &group[at + 1..] {
            if eligible(source, &source_key, target, &identity_key(&target.body)?) {
                partners.push(target);
            }
        }
        return Ok(Some(Anchored {
            anchor: source,
            partners,
        }));
    }
    Ok(None)
}

/// `partners` of `anchor` split into calls, in order, each partner in one:
/// a call's state stays within the ladder's state bound beside the anchor
/// whenever two or more fit, every value whole. A partner too large to share
/// a call goes alone, whole: none is cut or left out.
pub(in crate::dreamer_consolidation) fn link_calls<'a>(
    anchor: &Proposal,
    partners: &[&'a Proposal],
) -> Vec<Vec<&'a Proposal>> {
    let base = entry_bytes(anchor);
    let mut calls = Vec::new();
    let mut call: Vec<&'a Proposal> = Vec::new();
    let mut bytes = base;
    for &partner in partners {
        let size = entry_bytes(partner);
        if !call.is_empty() && bytes.saturating_add(size) > MAX_DECISION_STATE_BYTES {
            calls.push(std::mem::take(&mut call));
            bytes = base;
        }
        bytes = bytes.saturating_add(size);
        call.push(partner);
    }
    if !call.is_empty() {
        calls.push(call);
    }
    calls
}

/// About how many bytes `proposal` takes in a call's state.
fn entry_bytes(proposal: &Proposal) -> usize {
    rmpv_to_json(&proposal.body.value)
        .to_string()
        .len()
        .saturating_add(proposal.body.predicate.len())
        .saturating_add(ENTRY_ROOM)
}

/// One link call's pack: one [`NIGHTLY_LINK`] question per pair, keyed by
/// the pair's position in its call, over the three verdicts.
pub(in crate::dreamer_consolidation) struct NightlyLinkQuestion {
    questions: Vec<DecisionQuestion>,
}

impl NightlyLinkQuestion {
    /// The pack for `pairs` pairs in `wording`, the host's.
    pub(in crate::dreamer_consolidation) fn pack(wording: &str, pairs: usize) -> Result<Self> {
        let questions = (0..pairs)
            .map(|position| {
                let position = position.to_string();
                NIGHTLY_LINK.question(
                    &[b"pair".as_slice(), position.as_bytes()],
                    wording.to_owned(),
                    AnswerContract::Choice {
                        options: NightlyLinkVerdict::ALL
                            .iter()
                            .map(|verdict| verdict.option().to_owned())
                            .collect(),
                    },
                )
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { questions })
    }

    /// The pack's questions, in pair order.
    pub(in crate::dreamer_consolidation) fn questions(&self) -> &[DecisionQuestion] {
        &self.questions
    }

    /// The call's state: the anchor's and each partner's claim, then each
    /// pair by its question and its two claims. Every id goes by its label
    /// in `labels`, as the nightly merge names them (FIX 7506): each claim
    /// `C<n>` first, the anchor `C1`, then each subject. Each value is whole.
    pub(in crate::dreamer_consolidation) fn state(
        &self,
        anchor: &Proposal,
        partners: &[&Proposal],
        labels: &mut CallLabelMap,
    ) -> serde_json::Value {
        let shown: Vec<&Proposal> = std::iter::once(anchor)
            .chain(partners.iter().copied())
            .collect();
        for proposal in &shown {
            labels.assign(LabelKind::Claim, proposal.id);
        }
        let mut claims = Vec::with_capacity(shown.len());
        for proposal in &shown {
            let claim = labels.assign(LabelKind::Claim, proposal.id).to_string();
            let subject = subject_label(labels, &proposal.body.subject);
            claims.push(serde_json::json!({
                "claim": claim,
                "subject": subject,
                "predicate": proposal.body.predicate,
                "value": rmpv_to_json(&proposal.body.value),
            }));
        }
        let source = labels.assign(LabelKind::Claim, anchor.id).to_string();
        let mut pairs = Vec::with_capacity(partners.len());
        for (question, partner) in self.questions.iter().zip(partners) {
            pairs.push(serde_json::json!({
                "question": labels.assign(LabelKind::Question, question.id).to_string(),
                "claims": [source, labels.assign(LabelKind::Claim, partner.id).to_string()],
            }));
        }
        serde_json::json!({
            "claims": claims,
            "pairs": pairs,
        })
    }
}
