//! Read-only extraction children attenuated from one prepared branch.
use super::*;
use crate::claim::RelationshipRead;
use crate::dreamer_consolidation::call_labels::{CallLabelMap, LabelKind};

pub(in crate::dreamer_consolidation) struct ExtractionSlice {
    pub(in crate::dreamer_consolidation) turns: Vec<EntityId>,
    /// The child's extraction input: the wake's host material (FIX 10665),
    /// a header for each conversation its turns are of, its listing after
    /// the first, and its turns, each named by its label in `labels` (`V1`,
    /// `V2`... per conversation, FIX 7524).
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
        // The material the wake's admitted `host.wake` hooks added leads
        // every slice's input (FIX 10665): context for the call, never a
        // turn, so no label names it and nothing cites it. The material does
        // not say which hook added it, so a slice that carries any is
        // low-trust, kept off a thing agent's clean loan.
        let mut material = String::new();
        for text in self
            .prepared_wake
            .map_or(&[][..], crate::dreamer_consolidation::PreparedWake::hook_material)
        {
            material.push_str("[host material] ");
            material.push_str(text);
            material.push('\n');
        }
        let mut slices = Vec::new();
        for ((_, entities), group) in groups {
            let known = self.known.slice(&entities);
            let pages = known.pages(|id| self.priors.contains_key(id));
            // What paging costs, measured where it happens (FIX 10354): each
            // chunk of the group makes one call per page. Sharing one
            // extraction across a listing's pages waits on these numbers.
            if pages.len() > 1 {
                tracing::info!(
                    target: "oneiron::dreamer",
                    code = "listing_paged",
                    pages = pages.len(),
                    chunks = group.chunks(turns_per_child).len(),
                    entities = entities.len(),
                    "a child's listing pages into more than one extraction call"
                );
            }
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
                // The relationships a candidate may hold within: the bound
                // one, or on an unbound branch each one the chunk's words
                // are scoped to (FIX 10357).
                let rels: Vec<EntityId> = match scope.relationship {
                    Some(bound) => vec![bound],
                    None => self.word_relationships(&ids)?.into_iter().collect(),
                };
                for page in &pages {
                    let mut labels = CallLabelMap::default();
                    let mut transcript = material.clone();
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
                                transcript
                                    .push_str(&page.render(&mut labels, rels.iter().copied()));
                            }
                        }
                        let turn = labels.assign(LabelKind::Turn, *id);
                        transcript.push_str(&format!(
                            "[{turn} {}] {}\n",
                            facts.speaker.as_deref().unwrap_or("unknown"),
                            facts.text.as_deref().unwrap_or_default(),
                        ));
                    }
                    // A slice is low-trust by what it reads: its own TURNs,
                    // the prior heads its page shows (FIX 9017), and any host
                    // material, which a hub publisher's or an agent's hook may
                    // fill from rows it reads (FIX 10665).
                    let slice_low_trust = !material.is_empty()
                        || chunk.iter().any(|(_, facts)| facts.imported)
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

impl BranchResources<'_> {
    /// The relationships the words of `turns` are scoped to (FIX 10357):
    /// each MESSAGE a TURN's text was projected from, at its stored scope.
    /// A MESSAGE that is private, gone, or whose scope does not read adds
    /// none; the listing only offers labels, it grants nothing.
    fn word_relationships(&self, turns: &BTreeSet<EntityId>) -> Result<BTreeSet<EntityId>> {
        let vault = self.read.vault();
        let txn = vault.store.env.read_txn()?;
        let mut rels = BTreeSet::new();
        let messages = turns
            .iter()
            .filter_map(|id| self.texts.get(id))
            .flat_map(TurnText::versions)
            .map(|(message, _)| message);
        for message in messages {
            let Some(raw) = vault.get_raw_in(&txn, &message)? else {
                continue;
            };
            if let Ok(RelationshipRead::Gated {
                space,
                private: false,
                ..
            }) = crate::claim::relationship_read(&vault.store, &txn, &message, &raw)
            {
                rels.extend(space);
            }
        }
        Ok(rels)
    }
}

/// Whether a prior head is not the user's own words, by its source or its
/// evidence's taint.
fn low_trust_prior(prior: &crate::dreamer_consolidation::PriorHead) -> bool {
    prior.body.source != Some(crate::claim::ClaimSource::UserStated)
        || crate::claim::claim_evidence_taint(&prior.body)
            .is_some_and(|source| source != crate::claim::ClaimSource::UserStated)
}
