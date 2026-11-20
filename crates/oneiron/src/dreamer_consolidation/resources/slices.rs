//! Read-only extraction children attenuated from one prepared branch.
use super::*;
use crate::dreamer_consolidation::branch::QueuedBranch;
use crate::dreamer_consolidation::call_labels::{CallLabelMap, LabelKind};
use crate::dreamer_consolidation::extraction_step::render_host_material;

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

/// How far one extraction call's input may run (FIX
/// DREAMER-EXTRACTION-INPUT-UNBOUNDED-BY-WINDOW): at most `turns` TURNs, and,
/// when the host lends the extraction model's window, at most `room` bytes of
/// transcript by the sizing estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::dreamer_consolidation) struct SliceBound {
    pub(in crate::dreamer_consolidation) turns: usize,
    pub(in crate::dreamer_consolidation) room: Option<usize>,
}

impl SliceBound {
    /// At most `turns` TURNs a call, with no room: chunks by count alone.
    pub(in crate::dreamer_consolidation) const fn by_count(turns: usize) -> Self {
        Self { turns, room: None }
    }
}

/// Maps each queued TURN to its part line, so native slices and the
/// bound step group by the same line.
///
/// A nightly thing's parts share a line where their exposure agrees,
/// and any other part is a line of its own.
pub(super) fn branch_turn_lines(branch: &QueuedBranch) -> BTreeMap<EntityId, u32> {
    branch
        .parts
        .iter()
        .flat_map(|part| part.turns.iter().map(move |turn| (*turn, part.line)))
        .collect()
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
    /// listed about its subject. The flag is whether the whole branch
    /// extracts at width one (ARCH-0026: an imported or otherwise low-trust
    /// member, by provenance: [`serial_width_prior`]); each slice also
    /// carries its own low trust for the clean-slice loan.
    ///
    /// A chunk holds at most `bound.turns` TURNs. With a room (FIX
    /// DREAMER-EXTRACTION-INPUT-UNBOUNDED-BY-WINDOW) it also ends before the
    /// turn that would pass it beside what each of its calls carries (the
    /// host material and the group's widest page), and a chunk whose built
    /// call still passes it is split until each fits. A turn that passes it
    /// alone is a chunk of its own, its words whole: labels and spans cite
    /// them. The host material keeps only the whole texts that leave each
    /// turn of the group room, and a room that holds no page is refused.
    pub(in crate::dreamer_consolidation) fn extraction_slices(
        &self,
        turns: &[EntityId],
        bound: SliceBound,
    ) -> Result<(Vec<ExtractionSlice>, bool)> {
        type Group = Vec<(EntityId, TurnBodyFacts)>;
        let mut groups = BTreeMap::<(u32, Vec<EntityId>), Group>::new();
        let lines: BTreeMap<EntityId, u32> = match &self.origin {
            ResourceOrigin::Branch(branch) => branch_turn_lines(branch),
            ResourceOrigin::Root(_) => self.turns.keys().map(|turn| (*turn, 0)).collect(),
        };
        let mut serial_width = self.priors.values().any(serial_width_prior);
        for id in turns {
            let facts = self.turn(self.scope(), id)?;
            serial_width |= facts.imported;
            let (_, body) = self.source(self.scope(), id)?;
            let line = lines.get(id).copied().unwrap_or_default();
            let key = crate::dreamer_consolidation::extraction_step::slice_group_key(
                &self.known,
                line,
                &body,
                facts.text.as_deref(),
            );
            groups.entry(key).or_default().push((*id, facts));
        }
        // The material the wake's admitted `host.wake` hooks added leads
        // every slice's input (FIX 10665): context for the call, never a
        // turn, so no label names it and nothing cites it. The material does
        // not say which hook added it, so a slice that carries any is
        // low-trust, kept off a thing agent's clean loan.
        let hook_material = self.prepared_wake.map_or(
            &[][..],
            crate::dreamer_consolidation::PreparedWake::hook_material,
        );
        let mut slices = Vec::new();
        for ((_, entities), group) in groups {
            let known = self.known.slice(&entities);
            let pages = known.pages(|id| self.priors.contains_key(id));
            let (material, turn_room) = match bound.room {
                None => (render_host_material(hook_material), None),
                Some(room) => {
                    let widest = pages
                        .iter()
                        .map(|page| page.rendered_bytes())
                        .max()
                        .unwrap_or_default();
                    let material = material_in_room(hook_material, room, widest, &group)?;
                    let fixed = material.len().saturating_add(widest);
                    (material, Some(room.saturating_sub(fixed)))
                }
            };
            let chunks = room_chunks(&group, bound.turns, turn_room, |(_, facts)| {
                turn_line_bytes(facts)
            });
            let chunk_slices = |chunk: &[(EntityId, TurnBodyFacts)]| -> Result<Vec<_>> {
                let mut built = Vec::new();
                let ids: BTreeSet<_> = chunk.iter().map(|(id, _)| *id).collect();
                let parents: BTreeSet<EntityId> = ids
                    .iter()
                    .filter_map(|id| self.turns.get(id))
                    .copied()
                    .collect();
                let base = self.request_scope();
                let is_parent = |id: &EntityId| self.is_part_parent(id);
                let shows = |id: EntityId| known.shows(id);
                let inputs = super::extraction_scope::ExtractionScopeInputs {
                    sources: &self.sources,
                    turns: &self.turns,
                    priors: &self.priors,
                    texts: &self.texts,
                    cited: &ids,
                    cited_parents: &parents,
                    is_part_parent: &is_parent,
                    shows_prior: &shows,
                    kept_listing: Some(&known),
                    whole_listing: &self.known,
                };
                let scope =
                    super::extraction_scope::attenuate_extraction_scope(&base, &inputs, || {
                        self.word_bound(&ids)
                    })?;
                // The relationships a candidate may hold within: the bound
                // one, or none listed for words that carry no label.
                let rels: Vec<EntityId> = scope.relationship.iter().flatten().copied().collect();
                for page in &pages {
                    let mut page_rels = rels.clone();
                    if scope.relationship.is_none() {
                        page_rels.extend(page.member_relationships());
                    }
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
                                    .push_str(&page.render(&mut labels, page_rels.iter().copied()));
                            }
                        }
                        let turn = labels.assign(LabelKind::Turn, *id);
                        // The PERSON an imported turn's source names as its
                        // speaker shows by its label beside the role (FIX
                        // 15412); the role, the words and their offsets
                        // stay as they are, and a turn that names no one
                        // reads as before.
                        let speaker = match self.texts.get(id).and_then(TurnText::source_speaker) {
                            Some(person) => {
                                format!(" {}", labels.assign(LabelKind::Entity, person))
                            }
                            None => String::new(),
                        };
                        transcript.push_str(&format!(
                            "[{turn} {}{speaker}] {}\n",
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
                    if scope.relationship.is_none() {
                        sources.extend(page.membership_bindings());
                    }
                    sources.extend(
                        chunk
                            .iter()
                            .filter_map(|(id, _)| self.texts.get(id))
                            .flat_map(TurnText::versions)
                            .map(|(message, _)| message),
                    );
                    built.push(ExtractionSlice {
                        turns: chunk.iter().map(|(id, _)| *id).collect(),
                        transcript,
                        scope: scope.clone(),
                        labels,
                        low_trust: slice_low_trust,
                        sources,
                    });
                }
                Ok(built)
            };
            let fitted = fit_chunks(chunks, bound.room, chunk_slices, |slice| {
                slice.transcript.len()
            })?;
            // What paging costs, measured where it happens (FIX 10354): each
            // chunk of the group makes one call per page. Sharing one
            // extraction across a listing's pages waits on these numbers.
            if pages.len() > 1 {
                tracing::info!(
                    target: "oneiron::dreamer",
                    code = "listing_paged",
                    pages = pages.len(),
                    chunks = fitted.len(),
                    entities = entities.len(),
                    "a child's listing pages into more than one extraction call"
                );
            }
            for calls in fitted {
                let widest = calls.iter().map(|slice| slice.transcript.len()).max();
                let past = widest.zip(bound.room).filter(|(bytes, room)| bytes > room);
                if let Some((bytes, room)) = past {
                    tracing::warn!(
                        target: "oneiron::dreamer",
                        code = "extraction_turn_past_room",
                        bytes,
                        room,
                        "a turn alone passes its extraction call's room; it is read whole"
                    );
                }
                slices.extend(calls);
            }
        }
        Ok((slices, serial_width))
    }
}

impl BranchResources<'_> {
    /// The relationships every labelled word of `turns` may be read within
    /// (FIX 10357; S63E-RULED): each MESSAGE a TURN's text was projected
    /// from, at its stored scope, meets the others. A private MESSAGE, or
    /// one whose label does not resolve, admits no relationship. `None` when
    /// no word carries a label, so the branch stays unbound; a MESSAGE that
    /// is gone, or whose kind does not gate, adds none.
    fn word_bound(&self, turns: &BTreeSet<EntityId>) -> Result<Option<BTreeSet<EntityId>>> {
        let vault = self.read.vault();
        let txn = vault.store.env.read_txn()?;
        super::extraction_scope::word_bound_in_txn(vault, &txn, &self.texts, turns)
    }
}

/// What a turn's line adds to a call's transcript beside its words and its
/// speaker, at most: its label and brackets, the label of the person an
/// imported turn names, and the header of a conversation it opens.
const TURN_LINE_FRAME_BYTES: usize = 48;

/// The bytes a turn's line may add to a call's transcript.
fn turn_line_bytes(facts: &TurnBodyFacts) -> usize {
    facts.text.as_deref().map_or(0, str::len)
        + facts.speaker.as_deref().unwrap_or("unknown").len()
        + TURN_LINE_FRAME_BYTES
}

/// `group` cut in order into chunks of at most `turns_per_child` items whose
/// `line_bytes` fit `room` together (FIX
/// DREAMER-EXTRACTION-INPUT-UNBOUNDED-BY-WINDOW). An item that passes the
/// room alone is a chunk of its own, never cut. With no room, chunks are by
/// count alone, as `chunks` cuts them.
fn room_chunks<T>(
    group: &[T],
    turns_per_child: usize,
    room: Option<usize>,
    line_bytes: impl Fn(&T) -> usize,
) -> Vec<&[T]> {
    let most = turns_per_child.max(1);
    let Some(room) = room else {
        return group.chunks(most).collect();
    };
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut used = 0_usize;
    for (at, item) in group.iter().enumerate() {
        let bytes = line_bytes(item);
        if at > start && (at - start == most || used.saturating_add(bytes) > room) {
            chunks.push(&group[start..at]);
            start = at;
            used = 0;
        }
        used = used.saturating_add(bytes);
    }
    if start < group.len() {
        chunks.push(&group[start..]);
    }
    chunks
}

/// `chunks` built in order by `build`, a chunk whose calls pass `room` by
/// `bytes` split in two and each half built again, until every call fits or
/// its chunk holds one item (FIX DREAMER-EXTRACTION-INPUT-UNBOUNDED-BY-WINDOW).
/// The estimate the chunks were cut by leaves out what only a built call
/// shows: the relationship lines its turns' words are bound to, and the
/// labels they widen. Returns each kept chunk's calls, in order.
fn fit_chunks<'g, T, S>(
    chunks: Vec<&'g [T]>,
    room: Option<usize>,
    mut build: impl FnMut(&'g [T]) -> Result<Vec<S>>,
    bytes: impl Fn(&S) -> usize,
) -> Result<Vec<Vec<S>>> {
    let mut pending: Vec<&'g [T]> = chunks.into_iter().rev().collect();
    let mut kept = Vec::new();
    while let Some(chunk) = pending.pop() {
        let calls = build(chunk)?;
        let past = room.is_some_and(|room| calls.iter().any(|call| bytes(call) > room)) && chunk.is_empty();
        if past && chunk.len() > 1 {
            let (first, second) = chunk.split_at(chunk.len() / 2);
            pending.push(second);
            pending.push(first);
            continue;
        }
        kept.push(calls);
    }
    Ok(kept)
}

/// The host material one group's calls carry in `room` beside its widest
/// page of `widest` bytes (FIX DREAMER-EXTRACTION-INPUT-UNBOUNDED-BY-WINDOW):
/// the wake's texts in order, each whole, while they leave the group's
/// longest turn line room beside them. A text is never cut, and the texts
/// from the first that does not fit stay out of the group's calls.
///
/// # Errors
///
/// [`crate::Error::Refused`] when the room holds no page beside the prompt:
/// no call of the group could carry its listing.
fn material_in_room(
    material: &[String],
    room: usize,
    widest: usize,
    group: &[(EntityId, TurnBodyFacts)],
) -> Result<String> {
    let _ = (room, widest, group);
    Ok(render_host_material(material))
}

/// The chunk sizes [`fit_chunks`] keeps for items of `lines` bytes cut by
/// [`room_chunks`] at most `turns` a chunk in `room`, when each built call
/// is its items' bytes and `unseen` bytes the estimate leaves out, as a
/// chunk's bound relationship lines are.
#[cfg(oneiron_test_support)]
pub(crate) fn fitted_chunk_sizes_for_test(
    lines: &[usize],
    turns: usize,
    room: usize,
    unseen: usize,
) -> Vec<usize> {
    let chunks = room_chunks(lines, turns, Some(room), |line| *line);
    let build = |chunk: &[usize]| Ok(vec![(chunk.len(), chunk.iter().sum::<usize>() + unseen)]);
    fit_chunks(chunks, Some(room), build, |(_, bytes)| *bytes)
        .unwrap_or_default()
        .into_iter()
        .flatten()
        .map(|(items, _)| items)
        .collect()
}

/// Whether a prior head is not the user's own words, by its source or its
/// evidence's taint: a slice that shows one is never lent as clean (FIX
/// 9017).
fn low_trust_prior(prior: &crate::dreamer_consolidation::PriorHead) -> bool {
    prior.body.source != Some(crate::claim::ClaimSource::UserStated)
        || crate::claim::claim_evidence_taint(&prior.body)
            .is_some_and(|source| source != crate::claim::ClaimSource::UserStated)
}

/// Whether a prior head holds its branch's extraction at width one
/// (ARCH-0026: "any imported or otherwise low-trust member"). Low trust
/// follows provenance, not the head's own stamp (the lead's DREAMER-WIDTH
/// ruling, 13 Nov 2026): a head is low-trust when its source or its
/// evidence taint is tool output or imported, or when its ancestry is
/// unknown - no source, or a head not the user's own words that carries
/// no evidence taint. So the Dreamer's own claims drawn only from the
/// owner's words run wide, and one tainted head holds its whole branch
/// serial.
fn serial_width_prior(prior: &crate::dreamer_consolidation::PriorHead) -> bool {
    use crate::claim::ClaimSource;
    let tainted =
        |source: ClaimSource| matches!(source, ClaimSource::ToolOutput | ClaimSource::Imported);
    match (
        prior.body.source,
        crate::claim::claim_evidence_taint(&prior.body),
    ) {
        (None, _) => true,
        (Some(source), _) if tainted(source) => true,
        (_, Some(taint)) => tainted(taint),
        (Some(ClaimSource::UserStated), None) => false,
        (Some(_), None) => true,
    }
}
