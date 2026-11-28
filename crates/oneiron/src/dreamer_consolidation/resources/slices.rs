//! Read-only extraction children attenuated from one prepared branch.
use super::*;
use crate::context_board::one_line_token;
use crate::dreamer_consolidation::branch::QueuedBranch;
use crate::dreamer_consolidation::call_labels::{CallLabelMap, LabelKind};
use crate::dreamer_consolidation::extraction_step::render_host_material;
use crate::dreamer_consolidation::sieve_ports::SliceCall;
use crate::dreamer_consolidation::turn_text::writers::{TurnSpeakers, speaker_labels};

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
    /// Set when its listing page, as its transcript renders it, leaves its
    /// turns no room in the lent window: the extraction model is never
    /// called over it (FIX DREAMER-EXTRACTION-INPUT-UNBOUNDED-BY-WINDOW).
    pub(in crate::dreamer_consolidation) page_past_room: Option<PagePastRoom>,
}

impl ExtractionSlice {
    /// The slice as its extraction port reads it.
    pub(in crate::dreamer_consolidation) fn call(&self) -> SliceCall<'_> {
        SliceCall {
            transcript: &self.transcript,
            labels: &self.labels,
            scope: &self.scope,
            sources: &self.sources,
            page_past_room: self.page_past_room,
        }
    }
}

/// A call's listing page as rendered under its scope, `page` bytes, that
/// fills its `room` (FIX DREAMER-EXTRACTION-INPUT-UNBOUNDED-BY-WINDOW). A
/// request to the extraction model over the call is refused before it goes
/// out; a reply the engine authors from its turns' relations calls no model
/// and still runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::dreamer_consolidation) struct PagePastRoom {
    page: usize,
    room: usize,
}

impl PagePastRoom {
    /// The room a page of `page` bytes fills, when a room is lent and the
    /// page leaves none of it to a turn.
    fn filling(page: usize, room: Option<usize>) -> Option<Self> {
        room.filter(|room| page >= *room)
            .map(|room| Self { page, room })
    }

    /// The refusal a model call over the slice meets.
    pub(in crate::dreamer_consolidation) fn refusal(self) -> crate::Error {
        crate::Error::Refused(format!(
            "the extraction model's lent window leaves {} bytes beside its prompt, and this \
             call's listing page needs {}: lend the extraction role a model with a larger window",
            self.room, self.page
        ))
    }
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
    /// call still passes it is split until each fits. The host material
    /// keeps only the whole texts that leave each turn of the group room by
    /// that estimate, and a single turn whose built call still passes drops
    /// whole texts from the last until it fits or none is left. A turn that
    /// passes it alone then is read whole, its own chunk: labels and spans
    /// cite its words. A call whose page, as its transcript renders it under
    /// the call's scope, fills the room carries [`PagePastRoom`]: the model
    /// is never called over it.
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
        let speakers: BTreeMap<EntityId, Vec<EntityId>> = {
            let vault = self.read.vault();
            let txn = vault.store.env.read_txn()?;
            let rule = TurnSpeakers::read_in(vault, &txn)?;
            let mut speakers = BTreeMap::new();
            for (id, facts) in groups.values().flatten() {
                let people = rule.people_in(
                    vault,
                    &txn,
                    facts.speaker.as_deref(),
                    facts.imported,
                    self.texts.get(id),
                )?;
                if !people.is_empty() {
                    speakers.insert(*id, people);
                }
            }
            speakers
        };
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
            let (texts, turn_room) = match bound.room {
                None => (hook_material.len(), None),
                Some(room) => {
                    let widest = pages
                        .iter()
                        .map(|page| page.rendered_bytes())
                        .max()
                        .unwrap_or_default();
                    let texts = material_in_room(hook_material, room, widest, &group);
                    let fixed = render_host_material(&hook_material[..texts])
                        .len()
                        .saturating_add(widest);
                    (texts, Some(room.saturating_sub(fixed)))
                }
            };
            let chunks = room_chunks(&group, bound.turns, turn_room, |(_, facts)| {
                turn_line_bytes(facts)
            });
            let chunk_slices = |chunk: &[(EntityId, TurnBodyFacts)],
                                texts: usize|
             -> Result<Vec<_>> {
                let material = render_host_material(&hook_material[..texts]);
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
                    let mut page_bytes = 0;
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
                                let rendered = page.render(&mut labels, page_rels.iter().copied());
                                page_bytes = rendered.len();
                                transcript.push_str(&rendered);
                            }
                        }
                        let turn = labels.assign(LabelKind::Turn, *id);
                        // Label the PERSON an imported turn's source names
                        // (FIX 15412), or the writers of a native person turn:
                        // every such turn in a shared vault, each one its owner
                        // did not write alone in a personal vault (FIX
                        // DREAMER-NATIVE-PERSON-TURN-UNATTRIBUTED).
                        // Fence the role and words to one physical line, as the
                        // context board fences its rows (FIX
                        // DREAMER-TRANSCRIPT-TURN-TEXT-UNFENCED): each control
                        // character and U+2028/U+2029 shows as a space. A quote
                        // binds against these fenced words and maps back to the
                        // stored bytes (`SourceShown::one_line_fenced`).
                        let speaker = speaker_labels(
                            &mut labels,
                            speakers.get(id).map_or(&[][..], Vec::as_slice),
                        );
                        transcript.push_str(&format!(
                            "[{turn} {}{speaker}] {}\n",
                            one_line_token(facts.speaker.as_deref().unwrap_or("unknown")),
                            one_line_token(facts.text.as_deref().unwrap_or_default()),
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
                        page_past_room: PagePastRoom::filling(page_bytes, bound.room),
                    });
                }
                Ok(built)
            };
            let fitted = fit_chunks(chunks, bound.room, texts, chunk_slices, |slice| {
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
                let widest = calls
                    .iter()
                    .filter(|slice| slice.page_past_room.is_none())
                    .map(|slice| slice.transcript.len())
                    .max();
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
/// imported turn names or of a native person turn's writer, and the header
/// of a conversation it opens.
const TURN_LINE_FRAME_BYTES: usize = 48;

/// The bytes a turn's line may add to a call's transcript.
/// Raw lengths are an upper bound because the one-line fence never lengthens text.
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

/// `chunks` built in order by `build` with the first `texts` host material
/// texts, a chunk whose calls pass `room` by `bytes` split in two and each
/// half built again, until every call fits or its chunk holds one item; a
/// single item whose calls still pass is built again with one text fewer,
/// the last first, until they fit or it carries none (FIX
/// DREAMER-EXTRACTION-INPUT-UNBOUNDED-BY-WINDOW). The estimate the chunks
/// were cut by leaves out what only a built call shows: the relationship
/// lines its turns' words are bound to, and the labels they widen. Returns
/// each kept chunk's calls, in order.
fn fit_chunks<'g, T, S>(
    chunks: Vec<&'g [T]>,
    room: Option<usize>,
    texts: usize,
    mut build: impl FnMut(&'g [T], usize) -> Result<Vec<S>>,
    bytes: impl Fn(&S) -> usize,
) -> Result<Vec<Vec<S>>> {
    let past = |calls: &[S]| room.is_some_and(|room| calls.iter().any(|call| bytes(call) > room));
    let mut pending: Vec<&'g [T]> = chunks.into_iter().rev().collect();
    let mut kept = Vec::new();
    while let Some(chunk) = pending.pop() {
        let mut carried = texts;
        let mut calls = build(chunk, carried)?;
        if past(&calls) && chunk.len() > 1 {
            let (first, second) = chunk.split_at(chunk.len() / 2);
            pending.push(second);
            pending.push(first);
            continue;
        }
        while past(&calls) && carried > 0 {
            carried -= 1;
            calls = build(chunk, carried)?;
        }
        if carried < texts {
            tracing::warn!(
                target: "oneiron::dreamer",
                code = "host_material_past_room",
                kept = carried,
                dropped = texts - carried,
                "host material past a single turn's call stays out of that call"
            );
        }
        kept.push(calls);
    }
    Ok(kept)
}

/// How many of the wake's host material texts one group's calls carry in
/// `room` beside its widest page of `widest` bytes by the estimate (FIX
/// DREAMER-EXTRACTION-INPUT-UNBOUNDED-BY-WINDOW): the texts in order, each
/// whole, while they leave the group's longest turn line room beside them.
/// A text is never cut, and the texts from the first that does not fit stay
/// out of the group's calls; [`fit_chunks`] drops more from a single turn's
/// call that its built transcript shows past the room.
fn material_in_room(
    material: &[String],
    room: usize,
    widest: usize,
    group: &[(EntityId, TurnBodyFacts)],
) -> usize {
    let longest = group
        .iter()
        .map(|(_, facts)| turn_line_bytes(facts))
        .max()
        .unwrap_or_default();
    let share = room.saturating_sub(widest).saturating_sub(longest);
    let mut used = 0_usize;
    let kept = material
        .iter()
        .take_while(|text| {
            used = used.saturating_add(render_host_material(std::slice::from_ref(*text)).len());
            used <= share
        })
        .count();
    if kept < material.len() {
        tracing::warn!(
            target: "oneiron::dreamer",
            code = "host_material_past_room",
            kept,
            dropped = material.len() - kept,
            room,
            "host material past an extraction call's room stays out of its calls"
        );
    }
    kept
}

/// The native extraction slices over `turns` of `attempt`, with `material`
/// as its wake's host material and at most `room` transcript bytes a call,
/// in call order, each as its transcript and whether its page fills its
/// room, so no model is called over it (FIX
/// DREAMER-EXTRACTION-INPUT-UNBOUNDED-BY-WINDOW): the attempt prepared and
/// its branch opened as native extraction does, and no model run.
///
/// # Errors
///
/// A missing queue record, an unprepared branch, or the branch opening.
#[cfg(oneiron_test_support)]
pub(crate) fn native_slice_calls_in_room_for_test(
    vault: &Vault,
    attempt: AttemptId,
    turns: &[EntityId],
    material: &[String],
    room: Option<usize>,
) -> crate::memory::MemoryResult<Vec<(String, bool)>> {
    Ok(
        native_slices_in_room_for_test(vault, attempt, turns, material, room)?
            .into_iter()
            .map(|slice| (slice.transcript, slice.page_past_room.is_some()))
            .collect(),
    )
}

/// The native extraction slices over `turns` of `attempt`, as
/// [`native_slice_calls_in_room_for_test`] builds them with no host material
/// and no room bound, each as its transcript and whether every row it was
/// read from still stands now, as the model run's source fence asks before
/// it sends (REVIEW-10620 round 1).
///
/// # Errors
///
/// As [`native_slice_calls_in_room_for_test`].
#[cfg(oneiron_test_support)]
pub(crate) fn native_slice_sources_standing_for_test(
    vault: &Vault,
    attempt: AttemptId,
    turns: &[EntityId],
) -> crate::memory::MemoryResult<Vec<(String, bool)>> {
    Ok(
        native_slices_in_room_for_test(vault, attempt, turns, &[], None)?
            .into_iter()
            .map(|slice| {
                let stands = !crate::code_run::source_rows_withdrawn(vault, &slice.sources);
                (slice.transcript, stands)
            })
            .collect(),
    )
}

/// The slices both test reads above take.
#[cfg(oneiron_test_support)]
fn native_slices_in_room_for_test(
    vault: &Vault,
    attempt: AttemptId,
    turns: &[EntityId],
    material: &[String],
    room: Option<usize>,
) -> crate::memory::MemoryResult<Vec<ExtractionSlice>> {
    use crate::dreamer_consolidation::wake_plan::AttemptPreparation;
    use crate::memory::MemoryError;
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let attempt_entity = EntityId::from_bytes(*attempt.as_bytes()).map_err(crate::Error::from)?;
    let (scope, _) =
        crate::snapshot_read::queued_extraction_branch_in_txn(vault, &txn, attempt_entity)?;
    drop(txn);
    let wake = PreparedWake::prepare_one(vault, scope, None, attempt).map_err(MemoryError::from)?;
    let Some(AttemptPreparation::Ready(plan)) = wake.preparation(attempt) else {
        return Err(MemoryError::bad_request(
            "the test attempt prepared no branch",
        ));
    };
    let plan = plan.clone();
    let wake = wake.with_hook_material(material.to_vec());
    let actor = vault.dreamer_authority().map_err(MemoryError::from)?;
    let resources =
        BranchResources::open_prepared(vault, actor, &plan, &wake).map_err(MemoryError::from)?;
    let config = vault.consolidation_selection().map_err(MemoryError::from)?;
    let bound = SliceBound {
        turns: config.extraction_turns_per_child,
        room,
    };
    let (slices, _) = resources
        .extraction_slices(turns, bound)
        .map_err(MemoryError::from)?;
    Ok(slices)
}

/// The calls [`fit_chunks`] keeps for items of `lines` bytes cut by
/// [`room_chunks`] at most `turns` a chunk in what `room` leaves beside the
/// host material texts of `material` bytes, when each built call is its
/// items' bytes, the texts it carries and `unseen` bytes the estimate leaves
/// out, as a chunk's bound relationship lines are: each call's item count
/// and the texts it carries.
#[cfg(oneiron_test_support)]
pub(crate) fn fitted_calls_for_test(
    lines: &[usize],
    turns: usize,
    room: usize,
    unseen: usize,
    material: &[usize],
) -> Vec<(usize, usize)> {
    let turn_room = room.saturating_sub(material.iter().sum());
    let chunks = room_chunks(lines, turns, Some(turn_room), |line| *line);
    let build = |chunk: &[usize], texts: usize| {
        let carried: usize = material[..texts].iter().sum();
        let bytes = chunk.iter().sum::<usize>() + unseen + carried;
        Ok(vec![(chunk.len(), texts, bytes)])
    };
    fit_chunks(
        chunks,
        Some(room),
        material.len(),
        build,
        |(_, _, bytes)| *bytes,
    )
    .unwrap_or_default()
    .into_iter()
    .flatten()
    .map(|(items, texts, _)| (items, texts))
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
