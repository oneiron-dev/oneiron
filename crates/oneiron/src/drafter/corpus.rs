//! The drafter's corpus (FIX 14973, FIX 12569 slice 2; DRAFTER-DATA = A,
//! DRAFTER-ACTIVATE = A + revert): the examples one night trains the vault's
//! own drafter on, read from the vault's own conversations, rooms with other
//! people included, and sealed inside the vault.
//!
//! **Source.** The vault's chat traffic (FIX 15128, `traffic.rs`): one
//! example per answered reply of any agent, a live turn's, a queued Continue's
//! or Retry's, whether or not its context board rode, each kept once its
//! reply was saved whole. Every example is the request exactly as the reply's
//! answering rung sent it and the span the reply generated (FIX 15129): its
//! reasoning, tool calls and text, in the provider-neutral parts the request
//! uses, with its finish reason, never a re-render. The target's `model` pin
//! is the wire model its rung names.
//!
//! **Exclusions.** An example stays out, counted under its reason, when its
//! rung is not the target's; its body no longer opens (its key retired); its
//! request holds a part other than text (a tool call or result, an image or
//! audio, whose sources no row names) or ends past a user's message; it
//! generated nothing; its room holds an open off-record stretch; or a record
//! it was read from (its conversation, its reply and TURN, every row of its
//! call's sources, each MESSAGE's TURN, each summary and every turn and
//! MESSAGE the summary folds) is erased, a Tier-A withhold (a live session
//! overlay's transient row among them), of no known world or author, or sits,
//! or a record it quotes sits, in a world the owner's policy excludes. No
//! per-run consent tick is asked: the ruling is the data basis.
//!
//! **Dependencies.** Each example names every record it was read from, the
//! worlds and authors of each, the records it quotes and folds, its agent and
//! its requester, as walked again at the export and as kept with it, so an
//! erase of any of them reaches the version
//! ([`super::erase_drafters_for_source_in_txn`]).
//!
//! **Split.** Source families are assigned before the split: one family per
//! request digest, so a Retry of the same request never sits on the other
//! side. A family is held out together with every family whose examples hold
//! one of its replies, so no training example carries a held-out reply's
//! bytes; families whose replies fewest other examples hold go first (each
//! conversation's latest replies), until one example in
//! [`HELD_OUT_DIVISOR`] is held out. A training example whose generated span
//! is byte-identical to a held-out one's stays out. The trainer receives the
//! training side only; the held-out side is sealed under a key of its own
//! and only the evaluator opens it.
//!
//! **Custody.** Plaintext lives in this process's memory for the night only.
//! Each side is sealed chunk by chunk under its own erasable key, minted
//! under the version (purpose `DrafterArtifact`), so an erase of the version
//! retires both. The sealed files sit under `drafter-corpora/<version>/`;
//! [`Vault::sweep_drafter_corpora`] removes every directory no prepared,
//! training or returned version names, and drops the examples past the
//! traffic's bound.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::Path;

use heed::{RoTxn, RwTxn};
use serde::Serialize;
use zeroize::Zeroizing;

use super::traffic::{
    DrafterExampleBody, DrafterExampleRecord, example_records_in, open_example_body_in,
};
use super::{
    DrafterCorpus, DrafterCorpusFile, DrafterDependencies, DrafterPolicy, DrafterSealing,
    DrafterTarget, DrafterVersionState, VERSIONS, hash_json, invalid,
};
use crate::claim::base_world_id;
use crate::conversation_dag::{message_body_quotes, turn_body_quotes};
use crate::disclosure::{DisclosureTier, disclosure_tier};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, ErrorKind, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN};
use crate::store::Store;
use crate::store::drafter_custody::{
    drafter_artifact_key_in_txn, mint_drafter_artifact_key_in_txn,
};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{ContentPart, EdgeKind, FinishReason, LlmMessage, LlmMessageRole, LlmRequest, Vault};

/// The form every example takes, as its trainer reads it: one JSON line of
/// a reply's request as its rung sent it and the span the reply generated.
pub(super) const DRAFTER_CORPUS_FORM: &str = "oneiron.drafter.chat_traffic.v1";
/// One example in this many is held out (rounded up). Not an owner ruling:
/// the engine's own choice until the evaluator (FIX 14975) states the sample
/// it needs.
pub(super) const HELD_OUT_DIVISOR: usize = 10;
/// The plaintext width of one sealed corpus chunk.
const CORPUS_CHUNK_BYTES: usize = 1 << 20;
/// A sealed corpus file's name: its random id in hex, then this.
const SEALED_SUFFIX: &str = ".sealed";
/// A sealed corpus file's name while it is written.
const STAGING_SUFFIX: &str = ".sealed.part";

/// An example record that does not decode.
const OMIT_EXAMPLE_DAMAGED: &str = "drafter.corpus.example_damaged";
/// The reply's rung is not the target's model.
const OMIT_OTHER_MODEL: &str = "drafter.corpus.other_model";
/// The request ends past the user's message: a Continue its rung prefills.
const OMIT_REQUEST_TAIL: &str = "drafter.corpus.request_tail";
/// The request holds a part other than text, whose sources no row names.
const OMIT_UNTRACKED_PART: &str = "drafter.corpus.untracked_part";
/// The reply's room holds an open off-record stretch.
const OMIT_OFF_RECORD: &str = "drafter.corpus.off_record";
/// The reply generated no text, reasoning or tool call.
const OMIT_GENERATED_EMPTY: &str = "drafter.corpus.generated_empty";
/// A record the example was read from is erased or absent, or its body's
/// key is retired.
const OMIT_SOURCE_ERASED: &str = "drafter.corpus.source_erased";
/// A record the example was read from is a Tier-A withhold.
const OMIT_SOURCE_WITHHELD: &str = "drafter.corpus.source_withheld";
/// A record the example was read from has no known author.
const OMIT_AUTHOR_UNKNOWN: &str = "drafter.corpus.author_unknown";
/// A summary whose folded turns are not known.
const OMIT_FOLD_UNKNOWN: &str = "drafter.corpus.fold_unknown";
/// The example reaches a world the owner's policy excludes.
const OMIT_EXCLUDED_WORLD: &str = "drafter.corpus.excluded_world";
/// A row the export read refused it or did not decode.
const OMIT_ROW_FAILED: &str = "drafter.corpus.row_failed";
/// A training example whose generated span is byte-identical to a held-out
/// one's.
const OMIT_HELD_OUT_DUPLICATE: &str = "drafter.corpus.held_out_duplicate";

/// Counts one reply left out under `code`.
fn omit(omitted: &mut BTreeMap<String, u64>, code: &str) {
    *omitted.entry(code.to_owned()).or_default() += 1;
}

/// Whether `error` fails the whole export: storage and I/O. Any other error
/// is about one reply's rows, which stay out.
fn fails_export(error: &Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::Storage | ErrorKind::Io | ErrorKind::MapFull
    )
}

/// The two sides of a corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CorpusSide {
    /// What the trainer receives.
    Training,
    /// What only the evaluator opens.
    HeldOut,
}

impl CorpusSide {
    /// The name each sealed chunk of the side binds.
    fn name(self) -> &'static str {
        match self {
            Self::Training => "training.jsonl",
            Self::HeldOut => "held-out.jsonl",
        }
    }

    /// The side's file in `corpus`.
    fn file(self, corpus: &DrafterCorpus) -> &DrafterCorpusFile {
        match self {
            Self::Training => &corpus.training,
            Self::HeldOut => &corpus.held_out,
        }
    }
}

/// Every record one example was read from, and whose erase it follows.
#[derive(Debug, Default)]
pub(super) struct DependencyWalk {
    sources: BTreeSet<EntityId>,
    derived: BTreeSet<EntityId>,
    pub(super) worlds: BTreeSet<EntityId>,
    authors: BTreeSet<EntityId>,
    erase_subjects: BTreeSet<EntityId>,
}

impl DependencyWalk {
    /// Every record id the walk read, source or derived.
    fn records(&self) -> impl Iterator<Item = &EntityId> {
        self.sources.iter().chain(&self.derived)
    }

    /// Adds `other`'s lists to this walk's.
    fn absorb(&mut self, other: Self) {
        self.sources.extend(other.sources);
        self.derived.extend(other.derived);
        self.worlds.extend(other.worlds);
        self.authors.extend(other.authors);
        self.erase_subjects.extend(other.erase_subjects);
    }

    /// Adds every list of `kept`, an example's own set, to this walk's.
    fn absorb_dependencies(&mut self, kept: &DrafterDependencies) {
        self.sources.extend(kept.sources.iter().copied());
        self.derived.extend(kept.derived.iter().copied());
        self.worlds.extend(kept.worlds.iter().copied());
        self.authors.extend(kept.authors.iter().copied());
        self.erase_subjects
            .extend(kept.erase_subjects.iter().copied());
    }

    /// The walk as a dependency set, every list sorted, known whole.
    pub(super) fn into_dependencies(self) -> DrafterDependencies {
        DrafterDependencies {
            sources: self.sources.into_iter().collect(),
            worlds: self.worlds.into_iter().collect(),
            authors: self.authors.into_iter().collect(),
            erase_subjects: self.erase_subjects.into_iter().collect(),
            derived: self.derived.into_iter().collect(),
            precise: true,
        }
    }
}

/// Adds every list of `from` to `into`'s, each sorted and once each; the
/// set is precise only when both are.
pub(super) fn union_dependencies(into: &mut DrafterDependencies, from: &DrafterDependencies) {
    for (to, add) in [
        (&mut into.sources, &from.sources),
        (&mut into.worlds, &from.worlds),
        (&mut into.authors, &from.authors),
        (&mut into.erase_subjects, &from.erase_subjects),
        (&mut into.derived, &from.derived),
    ] {
        to.extend(add.iter().copied());
        to.sort_unstable();
        to.dedup();
    }
    into.precise &= from.precise;
}

/// The rung one example names, as its trainer and evaluator read it.
#[derive(Serialize)]
struct ExampleRung<'a> {
    wire_model: &'a str,
}

/// One example as its trainer reads it.
#[derive(Serialize)]
struct ExampleLine<'a> {
    form: &'static str,
    /// Its source family: the hex BLAKE3 of the request's canonical bytes.
    family: &'a str,
    conversation: EntityId,
    reply: EntityId,
    generation: EntityId,
    rung: ExampleRung<'a>,
    /// The request exactly as the rung was sent it.
    request: &'a LlmRequest,
    /// The span the reply generated: its reasoning, tool calls and text, in
    /// order, in the parts the request uses.
    generated: &'a LlmMessage,
    finish_reason: &'a FinishReason,
}

/// One example: its family, its reply, every record it was read from, the
/// BLAKE3 of its generated span and its serialized line.
pub(super) struct DrafterExample {
    family: String,
    reply: EntityId,
    walk: DependencyWalk,
    generated_blake3: [u8; 32],
    line: Zeroizing<Vec<u8>>,
}

/// What one export read: the vault's clock at its snapshot, the policy
/// revision it judged under, its examples and the replies it left out by
/// reason.
pub(super) struct DrafterExport {
    pub(super) cutoff: u64,
    pub(super) policy_revision: u64,
    pub(super) examples: Vec<DrafterExample>,
    pub(super) omitted: BTreeMap<String, u64>,
}

/// One side of a split, serialized.
pub(super) struct SideBytes {
    pub(super) plain: Zeroizing<Vec<u8>>,
    pub(super) examples: u64,
    pub(super) families: u64,
}

/// A night's examples split into its two sides, the split's pin and the
/// dependency set of every example kept on either side.
pub(super) struct DrafterSplit {
    pub(super) training: SideBytes,
    pub(super) held_out: SideBytes,
    pub(super) held_out_families_blake3: [u8; 32],
    pub(super) dependencies: DrafterDependencies,
}

/// One side of a prepared corpus with its key open in this process, to be
/// sealed and written once the night's write commits.
pub(super) struct CorpusSideToSeal {
    side: CorpusSide,
    sealing: DrafterSealing,
    pub(super) file: DrafterCorpusFile,
    plain: Zeroizing<Vec<u8>>,
}

/// Whether every message of `request` is text the request's rows hold: no
/// tool message and no part but text.
fn text_only(request: &LlmRequest) -> bool {
    request.messages.iter().all(|message| {
        message.role != LlmMessageRole::Tool
            && message
                .content
                .iter()
                .all(|part| matches!(part, ContentPart::Text { .. }))
    })
}

/// Whether `generated` holds a token the model generated: text, reasoning
/// text or a tool call.
fn holds_generated_tokens(generated: &LlmMessage) -> bool {
    generated.content.iter().any(|part| match part {
        ContentPart::Text { text } | ContentPart::Reasoning { text, .. } => !text.is_empty(),
        ContentPart::ToolCall { .. } => true,
        _ => false,
    })
}

/// The records the row `id` of `entity_type`, with body `body`, quotes: each
/// quoted MESSAGE, and a door-added MESSAGE's quoted TURN.
fn quoted_records(id: EntityId, entity_type: u8, body: &[u8]) -> Vec<EntityId> {
    match entity_type {
        ENTITY_TYPE_TURN => turn_body_quotes(id, body)
            .into_iter()
            .map(|(_, anchor)| anchor.message())
            .collect(),
        ENTITY_TYPE_MESSAGE => message_body_quotes(body)
            .into_iter()
            .flat_map(|(record, anchor)| [record, anchor.message()])
            .collect(),
        _ => Vec::new(),
    }
}

/// Which list a walked record joins.
#[derive(Clone, Copy)]
enum Lineage {
    /// Its bytes are in the request.
    Source,
    /// The request's bytes derive from it: what a summary folds.
    Derived,
}

impl Vault {
    /// The corpus of the vault's own replies for `target`, judged under
    /// `policy` (FIX 14973, FIX 15128): every training example the traffic
    /// keeps at the export's snapshot, whose clock is the cutoff, each with
    /// every record it was read from. A reply that fails a check stays out,
    /// counted under its reason.
    ///
    /// # Errors
    /// Storage and I/O faults; any other fault leaves its reply out.
    pub(super) fn export_drafter_corpus(
        &self,
        target: &DrafterTarget,
        policy: &DrafterPolicy,
    ) -> Result<DrafterExport> {
        let mut omitted = BTreeMap::new();
        // The examples at the cutoff, in a snapshot closed before the
        // off-record reads, which open their own: this thread holds one read
        // at a time.
        let (records, damaged, cutoff) = {
            let txn = self.dependency_read_txn()?;
            let cutoff = self.now_recorded_at();
            let (records, damaged) = example_records_in(&self.store, &txn)?;
            (records, damaged, cutoff)
        };
        if damaged > 0 {
            *omitted.entry(OMIT_EXAMPLE_DAMAGED.to_owned()).or_default() += damaged;
        }
        let mut off_record: BTreeMap<EntityId, bool> = BTreeMap::new();
        let mut candidates = Vec::with_capacity(records.len());
        for (id, record) in records {
            if record.target_model != target.model {
                omit(&mut omitted, OMIT_OTHER_MODEL);
                continue;
            }
            let room = record.conversation;
            if *off_record
                .entry(room)
                .or_insert_with(|| self.room_has_unrecorded_stretch(room))
            {
                omit(&mut omitted, OMIT_OFF_RECORD);
                continue;
            }
            candidates.push((id, record));
        }
        let mut examples = Vec::with_capacity(candidates.len());
        let txn = self.dependency_read_txn()?;
        for (id, record) in candidates {
            match self.drafter_example_in(&txn, policy, id, record) {
                Ok(Ok(example)) => examples.push(example),
                Ok(Err(code)) => omit(&mut omitted, code),
                Err(error) if fails_export(&error) => return Err(error),
                Err(_) => omit(&mut omitted, OMIT_ROW_FAILED),
            }
        }
        drop(txn);
        Ok(DrafterExport {
            cutoff,
            policy_revision: policy.revision,
            examples,
            omitted,
        })
    }

    /// Example `id`, kept as `record`, as one corpus example: its body
    /// opened, every record it was read from walked again in `txn` and its
    /// kept set added; or why it stays out.
    fn drafter_example_in(
        &self,
        txn: &RoTxn<'_>,
        policy: &DrafterPolicy,
        id: EntityId,
        record: DrafterExampleRecord,
    ) -> Result<std::result::Result<DrafterExample, &'static str>> {
        let Some(body) = open_example_body_in(&self.store, txn, &id, &record)? else {
            return Ok(Err(OMIT_SOURCE_ERASED));
        };
        let DrafterExampleBody {
            request,
            generated,
            finish_reason,
        } = body;
        if !text_only(&request) {
            return Ok(Err(OMIT_UNTRACKED_PART));
        }
        if request
            .messages
            .last()
            .is_none_or(|last| last.role != LlmMessageRole::User)
        {
            return Ok(Err(OMIT_REQUEST_TAIL));
        }
        if !holds_generated_tokens(&generated) {
            return Ok(Err(OMIT_GENERATED_EMPTY));
        }
        let records = record.dependencies.sources.iter().copied();
        let mut walk = match self.walk_example_in(
            txn,
            record.agent,
            record.requester,
            record.conversation,
            records,
        )? {
            Ok(walk) => walk,
            Err(code) => return Ok(Err(code)),
        };
        walk.absorb_dependencies(&record.dependencies);
        if walk
            .worlds
            .iter()
            .any(|world| policy.excluded_worlds.contains(world))
        {
            return Ok(Err(OMIT_EXCLUDED_WORLD));
        }
        let line = ExampleLine {
            form: DRAFTER_CORPUS_FORM,
            family: &record.family,
            conversation: record.conversation,
            reply: record.reply,
            generation: record.generation,
            rung: ExampleRung {
                wire_model: &record.wire_model,
            },
            request: &request,
            generated: &generated,
            finish_reason: &finish_reason,
        };
        let mut bytes = Zeroizing::new(
            serde_json::to_vec(&line).map_err(|_| invalid("a drafter example did not encode"))?,
        );
        bytes.push(b'\n');
        Ok(Ok(DrafterExample {
            generated_blake3: hash_json(&generated)?,
            family: record.family,
            reply: record.reply,
            walk,
            line: bytes,
        }))
    }

    /// Walks one example's `records` in `txn` into a fresh walk (FIX 15128):
    /// each as a source with the records it quotes, each MESSAGE's live TURN
    /// beside it, and each summary's folded turns and messages as derived;
    /// `agent` and `requester` as its authors, `requester` as an erase
    /// subject. The conversation's and the agent definition's own authors are
    /// not asked for: their rows name theirs. The traffic walks it in the
    /// write that keeps an example, the export again at each night. Why the
    /// example stays out, or the walk.
    ///
    /// # Errors
    /// Storage faults.
    pub(super) fn walk_example_in(
        &self,
        txn: &RoTxn<'_>,
        agent: EntityId,
        requester: EntityId,
        conversation: EntityId,
        records: impl IntoIterator<Item = EntityId>,
    ) -> Result<std::result::Result<DependencyWalk, &'static str>> {
        let mut walk = DependencyWalk::default();
        walk.authors.extend([agent, requester]);
        walk.erase_subjects.insert(requester);
        let mut queue: Vec<EntityId> = records.into_iter().collect();
        queue.reverse();
        let mut seen = BTreeSet::new();
        while let Some(id) = queue.pop() {
            if !seen.insert(id) {
                continue;
            }
            let author_required = id != agent && id != conversation;
            if let Some(code) =
                self.walk_record_in(txn, id, Lineage::Source, author_required, &mut walk)?
            {
                return Ok(Err(code));
            }
            let LiveEntityRow::Live { entity_type, .. } =
                live_entity_row_in_txn(&self.store, txn, &id)?
            else {
                continue;
            };
            match entity_type {
                ENTITY_TYPE_MESSAGE => queue.extend(self.turns_of_in(txn, id)?),
                ENTITY_TYPE_SUMMARY => {
                    let Some(spans) = self.summary_folded_spans_in_txn(txn, &id)? else {
                        return Ok(Err(OMIT_FOLD_UNKNOWN));
                    };
                    for span in spans {
                        for folded in std::iter::once(span.turn).chain(span.messages) {
                            if let Some(code) =
                                self.walk_record_in(txn, folded, Lineage::Derived, true, &mut walk)?
                            {
                                return Ok(Err(code));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(Ok(walk))
    }

    /// The live TURNs MESSAGE `message` is part of, in `txn`.
    pub(super) fn turns_of_in(&self, txn: &RoTxn<'_>, message: EntityId) -> Result<Vec<EntityId>> {
        let mut turns = Vec::new();
        for edge in self.store.port_edges(
            txn,
            &message,
            EdgeDirection::Out,
            Some(EdgeKind::PartOf),
            None,
        )? {
            let target = edge?.target;
            if matches!(
                live_entity_row_in_txn(&self.store, txn, &target)?,
                LiveEntityRow::Live {
                    entity_type: ENTITY_TYPE_TURN,
                    ..
                }
            ) {
                turns.push(target);
            }
        }
        Ok(turns)
    }

    /// Walks record `id` into `walk` in `txn`: live, no Tier-A withhold, its
    /// world and, when `author_required`, its author known, then the
    /// records it quotes. Why the example stays out, or `None`.
    fn walk_record_in(
        &self,
        txn: &RoTxn<'_>,
        id: EntityId,
        lineage: Lineage,
        author_required: bool,
        walk: &mut DependencyWalk,
    ) -> Result<Option<&'static str>> {
        let LiveEntityRow::Live { entity_type, body } =
            live_entity_row_in_txn(&self.store, txn, &id)?
        else {
            return Ok(Some(OMIT_SOURCE_ERASED));
        };
        if disclosure_tier(&self.store, txn, &id, entity_type, None)? == DisclosureTier::TierA {
            return Ok(Some(OMIT_SOURCE_WITHHELD));
        }
        let Some(world) = self.record_world_in_txn(txn, &id)? else {
            return Ok(Some(OMIT_SOURCE_ERASED));
        };
        walk.worlds.insert(world.unwrap_or_else(base_world_id));
        match self.record_author_in_txn(txn, &id)? {
            Some(author) => {
                walk.authors.insert(author);
            }
            None if author_required => return Ok(Some(OMIT_AUTHOR_UNKNOWN)),
            None => {}
        }
        match lineage {
            Lineage::Source => walk.sources.insert(id),
            Lineage::Derived => walk.derived.insert(id),
        };
        for quoted in quoted_records(id, entity_type, &body) {
            self.walk_quote_in(txn, quoted, walk)?;
        }
        Ok(None)
    }

    /// Walks the record `id` a walked row quotes into `walk` as derived, with
    /// its world and author, in `txn`. A quoted record no longer live holds
    /// no bytes of the request and is passed over.
    fn walk_quote_in(
        &self,
        txn: &RoTxn<'_>,
        id: EntityId,
        walk: &mut DependencyWalk,
    ) -> Result<()> {
        if walk.sources.contains(&id) || walk.derived.contains(&id) {
            return Ok(());
        }
        if !matches!(
            live_entity_row_in_txn(&self.store, txn, &id)?,
            LiveEntityRow::Live { .. }
        ) {
            return Ok(());
        }
        if let Some(world) = self.record_world_in_txn(txn, &id)? {
            walk.worlds.insert(world.unwrap_or_else(base_world_id));
        }
        if let Some(author) = self.record_author_in_txn(txn, &id)? {
            walk.authors.insert(author);
        }
        walk.derived.insert(id);
        Ok(())
    }
}

/// Keeps the examples whose every record still stands live in `txn`, the
/// night's write: one an erase reached since the export read it stays out
/// under its reason. Each record is read once.
///
/// # Errors
/// Storage faults.
pub(super) fn live_examples_in(
    store: &Store,
    txn: &RoTxn<'_>,
    examples: Vec<DrafterExample>,
    omitted: &mut BTreeMap<String, u64>,
) -> Result<Vec<DrafterExample>> {
    let mut checked = BTreeSet::new();
    let mut gone = BTreeSet::new();
    for example in &examples {
        for id in example.walk.records() {
            if checked.insert(*id)
                && !matches!(
                    live_entity_row_in_txn(store, txn, id)?,
                    LiveEntityRow::Live { .. }
                )
            {
                gone.insert(*id);
            }
        }
    }
    Ok(examples
        .into_iter()
        .filter(|example| {
            let live = !example.walk.records().any(|id| gone.contains(id));
            if !live {
                omit(omitted, OMIT_SOURCE_ERASED);
            }
            live
        })
        .collect())
}

/// The families held out of `examples`: a family goes with every family
/// whose examples hold one of its replies, those whose replies the fewest
/// other families hold first, ties broken by the BLAKE3 of the family, until
/// one example in [`HELD_OUT_DIVISOR`] (rounded up) is held out. A reply a
/// Continue extended is the reply of each family that generated a part of
/// it.
fn held_out_families(examples: &[DrafterExample]) -> BTreeSet<String> {
    let mut members: BTreeMap<&str, usize> = BTreeMap::new();
    let mut reply_families: BTreeMap<EntityId, BTreeSet<&str>> = BTreeMap::new();
    for example in examples {
        *members.entry(example.family.as_str()).or_default() += 1;
        reply_families
            .entry(example.reply)
            .or_default()
            .insert(example.family.as_str());
    }
    // Each family, and the other families whose examples hold its replies.
    let mut dependents: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for example in examples {
        for id in example.walk.records() {
            let Some(families) = reply_families.get(id) else {
                continue;
            };
            for family in families.iter().copied() {
                if family != example.family.as_str() {
                    dependents
                        .entry(family)
                        .or_default()
                        .insert(example.family.as_str());
                }
            }
        }
    }
    let mut order: Vec<(usize, [u8; 32], &str)> = members
        .keys()
        .map(|family| {
            (
                dependents.get(family).map_or(0, BTreeSet::len),
                *blake3::hash(family.as_bytes()).as_bytes(),
                *family,
            )
        })
        .collect();
    order.sort_unstable();
    let wanted = examples.len().div_ceil(HELD_OUT_DIVISOR);
    let mut held: BTreeSet<&str> = BTreeSet::new();
    let mut count = 0;
    for (_, _, family) in order {
        if count >= wanted {
            break;
        }
        let mut queue = vec![family];
        while let Some(next) = queue.pop() {
            if !held.insert(next) {
                continue;
            }
            count += members.get(next).copied().unwrap_or(0);
            if let Some(more) = dependents.get(next) {
                queue.extend(more.iter().copied());
            }
        }
    }
    held.into_iter().map(str::to_owned).collect()
}

/// One side as it is built.
struct SideBuilder {
    plain: Zeroizing<Vec<u8>>,
    examples: u64,
    families: BTreeSet<String>,
}

impl SideBuilder {
    fn new() -> Self {
        Self {
            plain: Zeroizing::new(Vec::new()),
            examples: 0,
            families: BTreeSet::new(),
        }
    }

    fn push(&mut self, example: &DrafterExample) {
        self.plain.extend_from_slice(&example.line);
        self.examples += 1;
        self.families.insert(example.family.clone());
    }

    fn finish(self) -> SideBytes {
        SideBytes {
            plain: self.plain,
            examples: self.examples,
            families: self.families.len() as u64,
        }
    }
}

/// Splits `examples` into the held-out families and the rest, a training
/// example whose generated span a held-out one's repeats left out under its
/// reason;
/// `None` when either side is empty.
///
/// # Errors
/// The split's pin does not encode.
pub(super) fn split_examples(
    examples: Vec<DrafterExample>,
    omitted: &mut BTreeMap<String, u64>,
) -> Result<Option<DrafterSplit>> {
    let held = held_out_families(&examples);
    let held_spans: BTreeSet<[u8; 32]> = examples
        .iter()
        .filter(|example| held.contains(&example.family))
        .map(|example| example.generated_blake3)
        .collect();
    let mut training = SideBuilder::new();
    let mut held_out = SideBuilder::new();
    let mut walk = DependencyWalk::default();
    for example in examples {
        let side = if held.contains(&example.family) {
            &mut held_out
        } else if held_spans.contains(&example.generated_blake3) {
            omit(omitted, OMIT_HELD_OUT_DUPLICATE);
            continue;
        } else {
            &mut training
        };
        side.push(&example);
        walk.absorb(example.walk);
    }
    if training.examples == 0 || held_out.examples == 0 {
        return Ok(None);
    }
    let families: Vec<&String> = held.iter().collect();
    Ok(Some(DrafterSplit {
        held_out_families_blake3: hash_json(&families)?,
        training: training.finish(),
        held_out: held_out.finish(),
        dependencies: walk.into_dependencies(),
    }))
}

/// How many sealed chunks a side of `len` plaintext bytes is written in.
fn chunk_count(len: usize) -> u64 {
    len.div_ceil(CORPUS_CHUNK_BYTES) as u64
}

/// Mints, in `txn`, the night's write, the key of one side of version
/// `version`'s corpus under a fresh random id, and pins the side's file.
///
/// # Errors
/// An archived vault, the random source, and custody faults.
pub(super) fn mint_side_in(
    store: &Store,
    txn: &mut RwTxn<'_>,
    version: EntityId,
    side: CorpusSide,
    bytes: SideBytes,
) -> Result<CorpusSideToSeal> {
    let mut id = [0u8; 16];
    crate::key_material::os_fill(&mut id)?;
    let key = mint_drafter_artifact_key_in_txn(store, txn, &version, &id)?;
    let file = DrafterCorpusFile {
        id,
        key_ref: key.key_ref,
        examples: bytes.examples,
        families: bytes.families,
        bytes: bytes.plain.len() as u64,
        blake3: *blake3::hash(&bytes.plain).as_bytes(),
        chunks: chunk_count(bytes.plain.len()),
    };
    Ok(CorpusSideToSeal {
        side,
        sealing: DrafterSealing::for_corpus(version, id, key),
        file,
        plain: bytes.plain,
    })
}

/// `side` sealed: each chunk's sealed length (4 bytes, big-endian), then the
/// sealed chunk.
fn seal_side(side: &CorpusSideToSeal) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for (index, chunk) in (0u64..).zip(side.plain.chunks(CORPUS_CHUNK_BYTES)) {
        let last = index + 1 == side.file.chunks;
        let sealed = side
            .sealing
            .seal_chunk(side.side.name(), index, last, chunk)?;
        let width = u32::try_from(sealed.len())
            .map_err(|_| invalid("a sealed drafter corpus chunk is too long"))?;
        out.extend_from_slice(&width.to_be_bytes());
        out.extend_from_slice(&sealed);
    }
    Ok(out)
}

/// What [`seal_side`] wrote for `file` of `side`, opened and checked whole:
/// every chunk in place, its length and its BLAKE3.
fn open_side(
    sealing: &DrafterSealing,
    side: CorpusSide,
    file: &DrafterCorpusFile,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let corrupt = || Error::CorruptedIndex("drafter corpus");
    let mut plain = Zeroizing::new(Vec::new());
    let mut rest = sealed;
    let mut index = 0u64;
    while !rest.is_empty() {
        let (width, tail) = rest.split_first_chunk::<4>().ok_or_else(corrupt)?;
        let width = usize::try_from(u32::from_be_bytes(*width)).map_err(|_| corrupt())?;
        let (frame, tail) = tail.split_at_checked(width).ok_or_else(corrupt)?;
        let opened = sealing.open_chunk(side.name(), index, index + 1 == file.chunks, frame)?;
        plain.extend_from_slice(&opened);
        rest = tail;
        index += 1;
    }
    if index != file.chunks
        || plain.len() as u64 != file.bytes
        || *blake3::hash(&plain).as_bytes() != file.blake3
    {
        return Err(corrupt());
    }
    Ok(plain)
}

/// The sealed file name of the corpus side whose random id is `id`.
fn sealed_name(id: &[u8; 16]) -> String {
    format!("{}{SEALED_SUFFIX}", bytes_to_hex_lower(id))
}

/// Writes `sealed` as `id`'s file in `dir`: beside its name, synced, renamed
/// in, and the directory synced.
fn write_sealed(dir: &Path, id: &[u8; 16], sealed: &[u8]) -> Result<()> {
    let staging = dir.join(format!("{}{STAGING_SUFFIX}", bytes_to_hex_lower(id)));
    let written = (|| -> Result<()> {
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging)?;
        out.write_all(sealed)?;
        out.sync_all()?;
        fs::rename(&staging, dir.join(sealed_name(id)))?;
        crate::store::sync_dir(dir)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&staging);
    }
    written
}

impl Vault {
    /// Seals and writes `sides` of version `version`'s corpus under
    /// `drafter-corpora/<version>/`, once the night's write committed. The
    /// plaintext goes with `sides` when this returns.
    ///
    /// # Errors
    /// Sealing and I/O faults; the sweep removes what a failed write left.
    pub(super) fn write_drafter_corpus(
        &self,
        version: &EntityId,
        sides: Vec<CorpusSideToSeal>,
    ) -> Result<()> {
        let root = self.store.drafter_corpus_dir();
        let dir = root.join(version.to_hex());
        fs::create_dir_all(&dir)?;
        crate::store::sync_dir(&root)?;
        for side in &sides {
            let sealed = seal_side(side)?;
            write_sealed(&dir, &side.file.id, &sealed)?;
        }
        Ok(())
    }

    /// The training side of drafter version `version`'s corpus, opened in
    /// this process for the host that hands it to the trainer (FIX 14974),
    /// checked whole; never the held-out side. `None` when the version keeps
    /// no corpus, its key is retired or retiring, or its file is missing.
    ///
    /// # Errors
    /// A damaged file or key, and custody, storage and I/O faults.
    pub fn drafter_training_corpus(
        &self,
        version: &EntityId,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.open_drafter_corpus(version, CorpusSide::Training)
    }

    /// The held-out side of drafter version `version`'s corpus, opened in
    /// this process for the evaluator only (FIX 14975), checked whole; never
    /// sent to a trainer. `None` as for [`Self::drafter_training_corpus`].
    ///
    /// # Errors
    /// A damaged file or key, and custody, storage and I/O faults.
    pub fn drafter_held_out_corpus(
        &self,
        version: &EntityId,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.open_drafter_corpus(version, CorpusSide::HeldOut)
    }

    fn open_drafter_corpus(
        &self,
        version: &EntityId,
        side: CorpusSide,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let (file, key) = {
            let txn = self.store.env.read_txn()?;
            let Some(row) = VERSIONS.get(&self.store, &txn, version)? else {
                return Ok(None);
            };
            let Some(corpus) = row.corpus else {
                return Ok(None);
            };
            let file = side.file(&corpus).clone();
            let Some(key) = drafter_artifact_key_in_txn(&self.store, &txn, version, &file.key_ref)?
            else {
                return Ok(None);
            };
            (file, key)
        };
        let path = self
            .store
            .drafter_corpus_dir()
            .join(version.to_hex())
            .join(sealed_name(&file.id));
        let sealed = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let sealing = DrafterSealing::for_corpus(*version, file.id, key);
        open_side(&sealing, side, &file, &sealed).map(Some)
    }

    /// Drops the training examples past the traffic's bound (FIX 15128,
    /// `DRAFTER_EXAMPLES_KEPT`), their keys' retirement staged, then removes
    /// every sealed corpus directory no prepared, training or returned
    /// version names, and every file in a kept one its corpus does not name:
    /// a superseded, rejected or erased version's, a damaged row's, a
    /// write's leftover. An erase retires the keys in its own transaction;
    /// this removes the sealed bytes after. A night runs it before its
    /// export and after its write; housekeeping runs it at open and daily
    /// (FIX 15259). Returns how many examples, directories and files it
    /// removed.
    ///
    /// # Errors
    /// Storage, custody and I/O faults.
    pub fn sweep_drafter_corpora(&self) -> Result<u64> {
        let mut removed = self.sweep_drafter_examples()?;
        let root = self.store.drafter_corpus_dir();
        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(removed),
            Err(error) => return Err(error.into()),
        };
        let txn = self.store.env.read_txn()?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let corpus = entry
                .file_name()
                .to_str()
                .and_then(|name| EntityId::from_hex(name).ok())
                .and_then(|id| VERSIONS.get(&self.store, &txn, &id).ok().flatten())
                // FIX 14974: a version keeps its corpus while it trains (its
                // host stages the training side) and once it returned (its
                // evaluator opens the held-out side).
                .filter(|row| {
                    matches!(
                        row.state,
                        DrafterVersionState::Prepared
                            | DrafterVersionState::Training
                            | DrafterVersionState::Returned
                    )
                })
                .and_then(|row| row.corpus);
            let Some(corpus) = corpus.filter(|_| path.is_dir()) else {
                if path.is_dir() {
                    fs::remove_dir_all(&path)?;
                } else {
                    fs::remove_file(&path)?;
                }
                removed += 1;
                continue;
            };
            let kept = [
                sealed_name(&corpus.training.id),
                sealed_name(&corpus.held_out.id),
            ];
            for file in fs::read_dir(&path)? {
                let file = file?;
                let named = file
                    .file_name()
                    .to_str()
                    .is_some_and(|name| kept.iter().any(|keep| keep.as_str() == name));
                if !named {
                    fs::remove_file(file.path())?;
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }
}
