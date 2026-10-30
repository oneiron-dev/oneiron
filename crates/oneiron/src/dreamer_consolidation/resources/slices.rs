//! Read-only extraction children attenuated from one prepared branch.
use super::*;
use crate::dreamer_consolidation::call_labels::{CallLabelMap, LabelKind};

pub(in crate::dreamer_consolidation) struct ExtractionSlice {
    pub(in crate::dreamer_consolidation) turns: Vec<EntityId>,
    /// The child's extraction input: a header for each conversation its
    /// turns are of, its listing after the first, and its turns, each named
    /// by its label in `labels` (`V1`, `V2`... per conversation, FIX 7524).
    pub(in crate::dreamer_consolidation) transcript: String,
    pub(in crate::dreamer_consolidation) scope: Scope,
    /// The child call's labels (FIX 7506), built from exactly the inputs
    /// it renders, before they render. The request, its reply check, its
    /// candidates and its people all read this one map.
    pub(in crate::dreamer_consolidation) labels: CallLabelMap,
    /// Whether one of its own TURNs is imported or a prior head it shows is
    /// not the user's own words (FIX 9017): its framed input may not be
    /// lent as clean, so it stays on the per-slice path.
    pub(in crate::dreamer_consolidation) low_trust: bool,
    /// The rows its transcript was read from (FIX 6998): every row its
    /// labels name and each MESSAGE its TURNs' words were projected from.
    pub(in crate::dreamer_consolidation) sources: Vec<EntityId>,
}

impl BranchResources<'_> {
    /// Group by slice line (FIX 8724) and co-mentioned known entities, then
    /// chunk each group. Every TURN appears in one chunk, and every child sees
    /// only its own source versions, its own TURNs' conversations and the
    /// neighbourhood heads that accompany them. A child may span the parts of
    /// one line, never two lines. Each group's whole listing (its thing
    /// first) is paged (FIX 7580, 9347), and a chunk is one call per page:
    /// each page's call reads the chunk's turns, and every page's call holds
    /// all of the chunk's heads, so a candidate is decided against every head
    /// listed about its subject. The flag is the whole branch's low trust;
    /// each slice also carries its own.
    pub(in crate::dreamer_consolidation) fn extraction_slices(
        &self,
        turns: &[EntityId],
        turns_per_child: usize,
    ) -> Result<(Vec<ExtractionSlice>, bool)> {
        type Group = Vec<(EntityId, TurnBodyFacts)>;
        let mut groups = BTreeMap::<(u32, Vec<EntityId>), Group>::new();
        let lines: BTreeMap<EntityId, u32> = self
            .branch
            .parts
            .iter()
            .flat_map(|part| part.turns.iter().map(move |turn| (*turn, part.line)))
            .collect();
        let mut low_trust = self.priors.values().any(low_trust_prior);
        for id in turns {
            let facts = self.turn(self.scope(), id)?;
            low_trust |= facts.imported;
            let (_, body) = self.source(self.scope(), id)?;
            let mentioned = self.known.mentioned(&body, facts.text.as_deref());
            let line = lines.get(id).copied().unwrap_or_default();
            groups
                .entry((line, mentioned))
                .or_default()
                .push((*id, facts));
        }
        let mut slices = Vec::new();
        for ((_, entities), group) in groups {
            let known = self.known.slice(&entities);
            let pages = known.pages(|id| self.priors.contains_key(id));
            for chunk in group.chunks(turns_per_child) {
                let ids: BTreeSet<_> = chunk.iter().map(|(id, _)| *id).collect();
                let parents: BTreeSet<_> = ids.iter().filter_map(|id| self.turns.get(id)).collect();
                let mut scope = self.request_scope();
                // Keep its own conversations and the buckets, but remove every
                // sibling TURN, every other part's conversation, MESSAGE and
                // prior head from this child's capabilities.
                for (id, source) in &self.sources {
                    if (self.turns.contains_key(id) && !ids.contains(id))
                        || (self.is_part_parent(id) && !parents.contains(id))
                        || (self.priors.contains_key(id) && !known.shows(*id))
                    {
                        scope.readable.remove(&source.resource);
                        scope.writable.remove(&source.resource);
                    }
                }
                let kept_messages: BTreeSet<_> = ids
                    .iter()
                    .filter_map(|id| self.texts.get(id))
                    .flat_map(TurnText::versions)
                    .map(|(_, version)| version.clone())
                    .collect();
                for version in self
                    .texts
                    .values()
                    .flat_map(TurnText::versions)
                    .map(|(_, version)| version)
                {
                    if !kept_messages.contains(version) {
                        scope.readable.remove(version);
                        scope.writable.remove(version);
                    }
                }
                for page in &pages {
                    let mut labels = CallLabelMap::default();
                    let mut transcript = String::new();
                    let mut current = None;
                    for (at, (id, facts)) in chunk.iter().enumerate() {
                        // A conversation's header leads its run of turns; the
                        // page follows the first, as a one-part child's does.
                        let conversation = self.turns.get(id).copied();
                        if at == 0 || conversation != current {
                            current = conversation;
                            if let Some(conversation) = conversation {
                                let conversation =
                                    labels.assign(LabelKind::Conversation, conversation);
                                transcript.push_str(&format!("conversation {conversation}\n"));
                            }
                            if at == 0 {
                                transcript.push_str(
                                    &page.render(&mut labels, scope.relationship.as_ref()),
                                );
                            }
                        }
                        let turn = labels.assign(LabelKind::Turn, *id);
                        transcript.push_str(&format!(
                            "[{turn} {}] {}\n",
                            facts.speaker.as_deref().unwrap_or("unknown"),
                            facts.text.as_deref().unwrap_or_default(),
                        ));
                    }
                    // A slice is low-trust by what it reads: its own TURNs and
                    // the prior heads its page shows (FIX 9017).
                    let slice_low_trust = chunk.iter().any(|(_, facts)| facts.imported)
                        || self
                            .priors
                            .iter()
                            .any(|(id, prior)| page.shows(*id) && low_trust_prior(prior));
                    let mut sources: Vec<EntityId> = labels.rows().collect();
                    sources.extend(
                        chunk
                            .iter()
                            .filter_map(|(id, _)| self.texts.get(id))
                            .flat_map(TurnText::versions)
                            .map(|(message, _)| message),
                    );
                    slices.push(ExtractionSlice {
                        turns: chunk.iter().map(|(id, _)| *id).collect(),
                        transcript,
                        scope: scope.clone(),
                        labels,
                        low_trust: slice_low_trust,
                        sources,
                    });
                }
            }
        }
        Ok((slices, low_trust))
    }
}

/// Whether a prior head is not the user's own words, by its source or its
/// evidence's taint.
fn low_trust_prior(prior: &crate::dreamer_consolidation::PriorHead) -> bool {
    prior.body.source != Some(crate::claim::ClaimSource::UserStated)
        || crate::claim::claim_evidence_taint(&prior.body)
            .is_some_and(|source| source != crate::claim::ClaimSource::UserStated)
}
