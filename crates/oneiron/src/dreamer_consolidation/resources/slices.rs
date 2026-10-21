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
}

impl BranchResources<'_> {
    /// Group by co-mentioned known entities, then chunk each group. Every
    /// TURN appears once, and every child sees only its own source versions,
    /// its own TURNs' conversations and the neighbourhood heads that
    /// accompany them. A child may span the branch's conversation parts.
    pub(in crate::dreamer_consolidation) fn extraction_slices(
        &self,
        turns: &[EntityId],
        turns_per_child: usize,
    ) -> Result<(Vec<ExtractionSlice>, bool)> {
        let mut groups = BTreeMap::<Vec<EntityId>, Vec<(EntityId, TurnBodyFacts)>>::new();
        let mut low_trust = self.priors.values().any(|prior| {
            prior.body.source != Some(crate::claim::ClaimSource::UserStated)
                || crate::claim::claim_evidence_taint(&prior.body)
                    .is_some_and(|source| source != crate::claim::ClaimSource::UserStated)
        });
        for id in turns {
            let facts = self.turn(self.scope(), id)?;
            low_trust |= facts.imported;
            let (_, body) = self.source(self.scope(), id)?;
            let mentioned = self.known.mentioned(&body, facts.text.as_deref());
            groups.entry(mentioned).or_default().push((*id, facts));
        }
        let mut slices = Vec::new();
        for (entities, group) in groups {
            let known = self.known.slice(&entities);
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
                let mut labels = CallLabelMap::default();
                let mut transcript = String::new();
                let mut current = None;
                for (at, (id, facts)) in chunk.iter().enumerate() {
                    // A conversation's header leads its run of turns; the
                    // listing follows the first, as a one-part child's does.
                    let conversation = self.turns.get(id).copied();
                    if at == 0 || conversation != current {
                        current = conversation;
                        if let Some(conversation) = conversation {
                            let conversation = labels.assign(LabelKind::Conversation, conversation);
                            transcript.push_str(&format!("conversation {conversation}\n"));
                        }
                        if at == 0 {
                            transcript.push_str(
                                &known.render(&mut labels, |id| self.priors.contains_key(id)),
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
                slices.push(ExtractionSlice {
                    turns: chunk.iter().map(|(id, _)| *id).collect(),
                    transcript,
                    scope,
                    labels,
                });
            }
        }
        Ok((slices, low_trust))
    }
}
