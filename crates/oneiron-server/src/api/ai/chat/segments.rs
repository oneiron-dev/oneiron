//! A live chat turn's typed segments (DESIGN-V2 R2): the manifest of the
//! call's messages in the order the turn assembled them (instructions,
//! resident craft where the session layout puts it, the log, the board's
//! state part, the newest user message, then the board's query part and the
//! turn's opener, I1 = C), set on the call once it is admitted and only
//! when it describes the admitted messages exactly; and, once the reply is
//! committed, the hand-off of the turn to the model session coordinator
//! with what it was admitted under.
//!
//! A turn whose log was not read from the retained ledger, or whose rows
//! are not all known, names no conversation: its manifest keys no session.
//! Nothing here changes what the call sends.
//!
//! A snapshot of a self-chat turn's successor is kept, and restored for a
//! later call, only under the read's scope and a dependency set known
//! whole: the rows the path was read from, each craft note and fold summary
//! with the turns a summary folds, and the world and author of each, read
//! once the reply commits. A set any of them does not read for is not
//! precise, and the turn's state stays cold (V2-R3). The turn's own
//! authority is recorded for its call before the call goes out, so a
//! restore rechecks under it.
use std::sync::Arc;

use oneiron::attempt_queue::ManifestEntry;
use oneiron::claim::{CallerLocality, ScopedReadActorKey, base_world_id};
use oneiron::compaction::ChatLogLine;
use oneiron::inference_snapshot::SnapshotDependencies;
use oneiron::llm::{
    ConversationAnchor, ScopeDigest, Segment, SegmentClass, SegmentClock, SegmentKind,
    SegmentLocator, SegmentManifest, SessionInvalidation, TrustFence, VaultRef,
};
use oneiron::memory::StreamFinality;
use oneiron::prompt::PromptLayout;
use oneiron::{EdgeActorClass, EntityId, LlmMessage, LlmMessageRole, Vault};

use super::compaction::SelfChat;

mod actions;
use super::{Answering, TurnCredential, text_message};
use crate::api::context_board::BoardSectionSource;
use crate::api::credential_memory;
use crate::models::{
    AuthorityVerdict, CheckpointAuthority, NextTurnSource, ReplyCommit, RestoreClaim,
    SnapshotScope, reply_committed, reply_committed_preparing, turn_admitted,
};
pub(crate) use actions::ActionSession;

/// Where the turn's messages lay as it assembled them, before its craft and
/// its board went in.
#[derive(Clone, Copy)]
pub(super) struct Layout {
    /// The same effective layout the producer placed its craft under.
    pub(super) prompt: PromptLayout,
    /// The leading System messages: the agent's instructions.
    pub(super) system_end: usize,
    /// Where the log ended: the newest user message's place.
    pub(super) log_end: usize,
}

/// Who read the turn's canonical path, and where.
#[derive(Clone)]
pub(super) struct Reader {
    pub(super) vault: Arc<Vault>,
    pub(super) credential: TurnCredential,
    pub(super) actor: EntityId,
    pub(super) class: EdgeActorClass,
    pub(super) locality: CallerLocality,
}

impl Reader {
    /// The read key the turn's log is read under now, as the turn reads it.
    fn read_key(&self) -> Option<ScopedReadActorKey> {
        match &self.credential {
            TurnCredential::Request { auth, .. } => {
                let memory = match auth.principal_ref() {
                    Some(_) => credential_memory(&self.vault, Some(auth), self.actor, self.class)
                        .at(self.locality),
                    None => self.vault.memory(self.actor, self.class),
                };
                memory.read_key().ok()
            }
            TurnCredential::Action { action, .. } => {
                crate::ai_host::action_reader(&self.vault, action)?
                    .read_key()
                    .ok()
            }
        }
    }

    /// The reply's current full lane-admitted MESSAGE text while `expected`
    /// is its latest terminal receipt; `None` when missing, hidden, active,
    /// changed or differently projected. No raw-store fallback.
    fn committed_text(&self, expected: &oneiron::memory::MessageStreamReceipt) -> Option<String> {
        match &self.credential {
            TurnCredential::Request { auth, .. } => {
                let memory = match auth.principal_ref() {
                    Some(_) => credential_memory(&self.vault, Some(auth), self.actor, self.class)
                        .at(self.locality),
                    None => self.vault.memory(self.actor, self.class),
                };
                memory.message_stream_committed_text(expected).ok()?.value
            }
            TurnCredential::Action { action, .. } => {
                crate::ai_host::action_reader(&self.vault, action)?
                    .message_stream_committed_text(expected)
                    .ok()?
                    .value
            }
        }
    }
}

/// The board as the turn placed it (I1 = C turn order).
pub(super) struct BoardView {
    /// The text and sections of its state part, right before the newest
    /// user message, or its omission's note, with no section.
    pub(super) state: (String, Vec<BoardSectionSource>),
    /// The message right after the newest user message, when the turn has
    /// one.
    pub(super) tail: Option<TurnTail>,
}

/// The User message that closes a turn whose board rides: the board's query
/// part, then the turn's opener.
pub(super) struct TurnTail {
    pub(super) text: String,
    /// The query part's sections; none when the tail is the opener alone.
    pub(super) sections: Vec<BoardSectionSource>,
    /// Whether the turn's now-time opener closes it.
    pub(super) opener: bool,
}

/// What the turn assembled, for its manifest.
pub(super) struct Assembled<'a> {
    pub(super) layout: Layout,
    pub(super) self_chat: Option<&'a SelfChat>,
    /// The messages before the board went in.
    pub(super) messages: &'a [LlmMessage],
    /// The board, when it rides, or its omission's note.
    pub(super) board: Option<&'a BoardView>,
    /// The answering agent, and the craft notes it was shown, when it was.
    pub(super) agent: EntityId,
    pub(super) craft: Option<&'a [ManifestEntry]>,
}

/// The admitted turn's manifest, and what its successor's publication is
/// rechecked against.
pub(super) struct TurnSegments {
    pub(super) manifest: Arc<SegmentManifest>,
    authority: Option<(ScopedReadActorKey, Vec<EntityId>)>,
    /// What the canonical path was read and derived from, for a self-chat.
    path: Option<PathDependencies>,
    /// The vault's authority generation the turn was admitted at; `None`
    /// when it did not read.
    revocation: Option<u64>,
    /// The authority a snapshot restored for the turn's call is rechecked
    /// under, held at least for the turn's life: [`commit_on_answer`] keeps
    /// it until the call's outcome ends, so a turn that wrote no rows still
    /// restores warm. The [`turn_admitted`] record lapses once it goes.
    _turn: Option<Arc<dyn CheckpointAuthority>>,
}

/// The manifest of `assembled` once admitted as `admitted`; `None` when the
/// layout does not match what was assembled or admission reshaped it.
pub(super) fn admitted(
    reader: &Reader,
    assembled: Assembled<'_>,
    admitted: &[LlmMessage],
) -> Option<TurnSegments> {
    admitted_with_sources(reader, assembled, admitted, &[], None)
}

fn admitted_with_sources(
    reader: &Reader,
    assembled: Assembled<'_>,
    admitted: &[LlmMessage],
    borrowed: &[EntityId],
    continuation: Option<EntityId>,
) -> Option<TurnSegments> {
    let Layout {
        prompt,
        system_end,
        log_end,
    } = assembled.layout;
    let mut messages = assembled.messages.to_vec();
    if system_end > log_end {
        return None;
    }
    // The craft, when its message went in (FIX 6676): right after the
    // instructions in today's layout, inside the prefix; as the turn's
    // data-only context right before the newest user message in the stable
    // one, outside it.
    let early = prompt == PromptLayout::EarlySystem;
    let craft = match messages.len().checked_sub(log_end + 1) {
        Some(0) => false,
        Some(1) if assembled.craft.is_some() => true,
        _ => return None,
    };
    let log_start = system_end + usize::from(craft && early);
    let mut segments = Vec::with_capacity(messages.len() + 1);
    for index in 0..system_end {
        segments.push(Segment::whole(
            SegmentKind::System,
            SegmentClock::Epoch,
            index,
        ));
    }
    if craft && early {
        segments.push(Segment::whole(
            SegmentKind::HostSection,
            SegmentClock::Live,
            system_end,
        ));
    }
    let log = assembled.self_chat.map(SelfChat::log);
    match log {
        Some(log) if log.lines.len() == log_end - system_end => {
            for (offset, (line, id)) in log.lines.iter().zip(&log.message_ids).enumerate() {
                segments.push(log_segment(line, *id, log_start + offset));
            }
        }
        Some(_) => return None,
        None => segments.extend(
            (log_start..log_start + log_end - system_end)
                .map(|index| Segment::whole(SegmentKind::LogMessage, SegmentClock::Log, index)),
        ),
    }
    let mut newest = log_end + usize::from(craft);
    if craft && !early {
        let mut context = Segment::whole(SegmentKind::HostSection, SegmentClock::Live, log_end);
        context.class = SegmentClass::Ephemeral;
        context.fence = TrustFence::Guest;
        segments.push(context);
    }
    if let Some(BoardView {
        state: (block, sections),
        ..
    }) = assembled.board
    {
        let at = messages
            .iter()
            .rposition(|message| message.role == LlmMessageRole::User)?;
        if at != newest {
            return None;
        }
        messages.insert(at, text_message(LlmMessageRole::User, block.clone()));
        segments.extend(board_segments(sections, at));
        newest += 1;
    }
    segments.push(Segment::whole(
        SegmentKind::NewestUser,
        SegmentClock::Live,
        newest,
    ));
    // The tail right after the newest user message (I1 = C): the board's
    // query part, one segment per section, and the opener, a host line of
    // the live turn. All of it ephemeral.
    if let Some(tail) = assembled.board.and_then(|board| board.tail.as_ref()) {
        let at = newest + 1;
        if at != messages.len() {
            return None;
        }
        messages.push(text_message(LlmMessageRole::User, tail.text.clone()));
        if !tail.sections.is_empty() {
            segments.extend(board_segments(&tail.sections, at));
        }
        if tail.opener {
            let mut opener = Segment::whole(SegmentKind::HostSection, SegmentClock::Live, at);
            opener.class = SegmentClass::Ephemeral;
            segments.push(opener);
        }
    }
    // The authority generation first: a revoke between the two reads
    // leaves the key read after it.
    let (revocation, read_key) = crate::server::blocking(|| {
        let revocation = reader.vault.authority_generation().ok();
        (revocation, reader.read_key())
    });
    let sources = canonical_sources(&assembled).map(|mut sources| {
        sources.extend_from_slice(borrowed);
        sources
    });
    let anchor = match (log, &read_key, &sources) {
        (Some(log), Some(key), Some(_)) => Some(ConversationAnchor {
            vault: VaultRef(reader.vault.vault_key_vault_id()),
            read_scope: scope_digest(key),
            conversation: log.conversation,
            head: log.branch,
            fold_epoch: log
                .lines
                .iter()
                .filter_map(|line| match line {
                    ChatLogLine::Summary { epoch, .. } => Some(*epoch),
                    ChatLogLine::Message { .. } => None,
                })
                .max()
                .unwrap_or(0),
        }),
        _ => None,
    };
    let manifest = SegmentManifest::new(segments, anchor, &messages);
    let manifest = match continuation {
        Some(message) => manifest.continued(message, admitted)?,
        None => manifest,
    };
    if !manifest.describes(admitted) {
        return None;
    }
    let manifest = Arc::new(manifest);
    let path = PathDependencies::of(reader, &assembled);
    let turn = match (manifest.anchor(), &read_key, &sources) {
        (Some(anchor), Some(key), Some(rows)) => {
            let turn: Arc<dyn CheckpointAuthority> = Arc::new(ChatAuthority {
                reader: reader.clone(),
                credential: reader.credential.clone(),
                read_key: key.clone(),
                sources: rows.clone(),
                at: Some((anchor.head, anchor.fold_epoch)),
                path: path.clone(),
                revocation,
            });
            turn_admitted(&manifest, &turn);
            Some(turn)
        }
        _ => None,
    };
    Some(TurnSegments {
        manifest,
        authority: read_key.zip(sources),
        path,
        revocation,
        _turn: turn,
    })
}

/// What a self-chat turn's canonical path was read and derived from, as its
/// admission names it: who wrote its retained rows (the reader and the
/// answering agent), the craft notes it showed, the fold summaries standing
/// in its log, and the rows its board recalled. The worlds, authors and
/// folded turns of the notes and summaries are read once the reply commits
/// ([`Self::read`]).
#[derive(Clone)]
struct PathDependencies {
    authors: Vec<EntityId>,
    notes: Vec<EntityId>,
    summaries: Vec<EntityId>,
    /// The memory rows and skills the board showed: the reply derives from
    /// them, and their bytes ride only in the ephemeral tail.
    recalled: Vec<EntityId>,
}

impl PathDependencies {
    /// What `assembled`'s path was read from as `reader` read it; `None` for
    /// a turn that read no self-chat, or a craft note named by no id.
    fn of(reader: &Reader, assembled: &Assembled<'_>) -> Option<Self> {
        let log = assembled.self_chat?.log();
        let notes = assembled
            .craft
            .unwrap_or_default()
            .iter()
            .map(|entry| EntityId::from_hex(&entry.reference).ok())
            .collect::<Option<Vec<_>>>()?;
        let recalled = assembled
            .board
            .into_iter()
            .flat_map(|board| {
                board
                    .state
                    .1
                    .iter()
                    .chain(board.tail.iter().flat_map(|tail| &tail.sections))
            })
            .flat_map(|section| &section.dependencies)
            .filter_map(|locator| match locator {
                SegmentLocator::Memory { id, .. } | SegmentLocator::Skill { id, .. } => Some(*id),
                _ => None,
            })
            .collect();
        Some(Self {
            authors: vec![reader.actor, assembled.agent],
            notes,
            summaries: log.summaries.clone(),
            recalled,
        })
    }

    /// The dependency set of a snapshot whose path holds `sources`, read in
    /// `vault` now: base reality and the reader and agent, then the world
    /// and author of each note, each summary and each turn and MESSAGE a
    /// summary folds; the summaries, what they fold and every recalled row
    /// as derived. Not precise when any of those does not read: an unread
    /// world or author is never guessed. Every list sorted, once each.
    fn read(&self, vault: &Vault, sources: Vec<EntityId>) -> SnapshotDependencies {
        let mut set = SnapshotDependencies {
            sources,
            worlds: vec![base_world_id()],
            authors: self.authors.clone(),
            erase_subjects: Vec::new(),
            derived: self.recalled.clone(),
            precise: false,
        };
        set.precise = self.read_quoted(vault, &mut set).is_some();
        for list in [
            &mut set.sources,
            &mut set.worlds,
            &mut set.authors,
            &mut set.derived,
        ] {
            list.sort_unstable();
            list.dedup();
        }
        set
    }

    /// Adds to `set` the worlds and authors of the notes and summaries and
    /// of what each summary folds, and the summaries and what they fold as
    /// derived; `None` at the first of them that does not read. The whole
    /// walk reads on one snapshot: two transactions per row and one per
    /// summary do not scale to long folded logs (FIX 11338).
    fn read_quoted(&self, vault: &Vault, set: &mut SnapshotDependencies) -> Option<()> {
        let txn = vault.dependency_read_txn().ok()?;
        let mut folded = Vec::new();
        for summary in &self.summaries {
            folded.push(*summary);
            for span in vault.summary_folded_spans_in_txn(&txn, summary).ok()?? {
                folded.push(span.turn);
                folded.extend(span.messages);
            }
        }
        for id in self.notes.iter().chain(&folded) {
            let world = vault.record_world_in_txn(&txn, id).ok()??;
            set.worlds.push(world.unwrap_or_else(base_world_id));
            set.authors
                .push(vault.record_author_in_txn(&txn, id).ok()??);
        }
        set.derived.extend(folded);
        Some(())
    }
}

/// The rows the canonical path was read from: the agent, its craft notes
/// and every row of its log; `None` when any is unknown.
fn canonical_sources(assembled: &Assembled<'_>) -> Option<Vec<EntityId>> {
    let mut rows = vec![assembled.agent];
    for entry in assembled.craft.unwrap_or_default() {
        rows.push(EntityId::from_hex(&entry.reference).ok()?);
    }
    rows.extend(assembled.self_chat?.sources()?);
    Some(rows)
}

/// One line of the log as a segment at `index`: a summary by its id and
/// fold epoch, a retained message by its MESSAGE.
fn log_segment(line: &ChatLogLine, id: Option<EntityId>, index: usize) -> Segment {
    match line {
        ChatLogLine::Summary { summary, epoch, .. } => {
            Segment::whole(SegmentKind::LogSummary, SegmentClock::Log, index).at(
                SegmentLocator::Summary {
                    id: *summary,
                    epoch: *epoch,
                },
            )
        }
        ChatLogLine::Message { .. } => {
            let segment = Segment::whole(SegmentKind::LogMessage, SegmentClock::Log, index);
            match id {
                Some(id) => segment.at(SegmentLocator::Message { id }),
                None => segment,
            }
        }
    }
}

/// The board message at `index` as one segment per rendered section, each
/// behind its own fence, with the rows it shows; one unnamed section when
/// the render named none. Always ephemeral.
fn board_segments(sections: &[BoardSectionSource], index: usize) -> Vec<Segment> {
    let segment = |name: &str| {
        Segment::whole(
            SegmentKind::BoardSection(name.to_owned()),
            SegmentClock::Live,
            index,
        )
        .at(SegmentLocator::BoardSection {
            name: name.to_owned(),
        })
    };
    if sections.is_empty() {
        return vec![segment("")];
    }
    sections
        .iter()
        .map(|section| {
            let mut board = segment(&section.name);
            board.fence = section.fence;
            board.dependencies.clone_from(&section.dependencies);
            board
        })
        .collect()
}

/// The read a session is keyed by: the typed fingerprint of its whole
/// read key with every ceiling it carries. A digest of this process's own
/// view of the key, never stored: a different key only costs a cold turn.
fn scope_digest(key: &ScopedReadActorKey) -> ScopeDigest {
    ScopeDigest(key.key_fingerprint())
}

/// What the turn's canonical path was admitted under, rechecked before a
/// successor is published: the credential stays live, the read key the
/// reader resolves now is the one the path was read under (its scope and
/// its disclosure ceilings), and every row the path was read from, the
/// reply among them, still reads under it.
struct ChatAuthority {
    reader: Reader,
    credential: TurnCredential,
    read_key: ScopedReadActorKey,
    sources: Vec<EntityId>,
    /// The HEAD and fold epoch the turn read its path at; `None` on the
    /// authority a commit holds, which restores nothing.
    at: Option<(Option<EntityId>, u64)>,
    /// What the path was read and derived from, for a self-chat.
    path: Option<PathDependencies>,
    /// The vault's authority generation the turn was admitted at.
    revocation: Option<u64>,
}

impl ChatAuthority {
    /// Whether the read key the reader resolves now is the one the path was
    /// read under, and every row of `rows` still reads under it.
    fn reads(&self, rows: &[EntityId]) -> AuthorityVerdict {
        match self.reader.read_key() {
            Some(key) if key == self.read_key => {
                let read = self.reader.vault.scoped_read(key);
                let withdrawn = rows
                    .iter()
                    .any(|row| !matches!(read.is_entity_readable(row), Ok(true)));
                if withdrawn {
                    AuthorityVerdict::Rejects(SessionInvalidation::SourceWithdrawn)
                } else {
                    AuthorityVerdict::Holds
                }
            }
            _ => AuthorityVerdict::Rejects(SessionInvalidation::DisclosureOrScope),
        }
    }
}

impl CheckpointAuthority for ChatAuthority {
    fn recheck(&self, commit: &ReplyCommit) -> AuthorityVerdict {
        if !self.credential.live() {
            return AuthorityVerdict::Rejects(SessionInvalidation::DisclosureOrScope);
        }
        let mut rows = self.sources.clone();
        rows.push(commit.message);
        self.reads(&rows)
    }

    /// The read's scope as the session is keyed by it, the authority
    /// generation the turn was admitted at, and what the path was read and
    /// derived from, the reply among its sources ([`PathDependencies::read`]).
    fn snapshot_scope(&self, commit: &ReplyCommit) -> Option<SnapshotScope> {
        let path = self.path.as_ref()?;
        let mut sources = self.sources.clone();
        sources.push(commit.message);
        Some(SnapshotScope {
            read_scope: scope_digest(&self.read_key),
            revocation: self.revocation,
            dependencies: path.read(&self.reader.vault, sources),
        })
    }

    /// In order: the credential, the vault's authority generation now
    /// against the one the snapshot was admitted at, the HEAD and fold epoch
    /// the turn read at, the read key and its scope, then every source the
    /// snapshot depends on, in every case: the generation does not move on
    /// a scope or world setting held outside the authority log. A snapshot
    /// admitted with no generation read rests on that last check alone. A
    /// rejection only sends the turn cold.
    fn recheck_restore(&self, claim: &RestoreClaim<'_>) -> AuthorityVerdict {
        let Some((head, fold_epoch)) = self.at else {
            return AuthorityVerdict::Rejects(SessionInvalidation::DisclosureOrScope);
        };
        if !self.credential.live() {
            return AuthorityVerdict::Rejects(SessionInvalidation::DisclosureOrScope);
        }
        if let Some(kept) = claim.revocation
            && self.reader.vault.authority_generation().ok() != Some(kept)
        {
            return AuthorityVerdict::Rejects(SessionInvalidation::DisclosureOrScope);
        }
        if claim.head != head {
            return AuthorityVerdict::Rejects(SessionInvalidation::PathChanged);
        }
        if claim.fold_epoch != fold_epoch {
            return AuthorityVerdict::Rejects(SessionInvalidation::FoldBeforeFrontier);
        }
        let scoped = claim.dependencies.precise && scope_digest(&self.read_key) == claim.read_scope;
        if !scoped {
            return AuthorityVerdict::Rejects(SessionInvalidation::DisclosureOrScope);
        }
        self.reads(&claim.dependencies.sources)
    }
}

/// Hands `answering`'s outcome on as it ends; then, when the reply was
/// saved whole as its own MESSAGE in `turn`, hands the turn to the session
/// coordinator with what it was admitted under, the user's `written`
/// MESSAGE rows among its sources. A turn with no segments hands nothing.
/// The turn's authority is held until the outcome ends even when the turn
/// wrote no rows, so a restore for its call rechecks under it instead of
/// running cold; only the commit handoff still needs `written` (FIX 11287).
/// With `next`, what the conversation's next turn is known to start with,
/// the session prepares that once the successor is published (I1 = C).
pub(super) fn commit_on_answer(
    segments: Option<TurnSegments>,
    reader: &Reader,
    credential: &TurnCredential,
    written: Option<&[EntityId]>,
    turn: EntityId,
    next: Option<Arc<dyn NextTurnSource>>,
    answering: Answering,
) -> Answering {
    let Some(segments) = segments else {
        return answering;
    };
    let commit_authority = written.and_then(|written| {
        let (read_key, mut sources) = segments.authority.clone()?;
        sources.extend_from_slice(written);
        Some(ChatAuthority {
            reader: reader.clone(),
            credential: credential.clone(),
            read_key,
            sources,
            at: None,
            path: segments.path.clone(),
            revocation: segments.revocation,
        })
    });
    let Answering {
        handle,
        subscription,
        outcome,
    } = answering;
    // The vault the reply lands in, for the FIX 10367 HEAD read below, and
    // the reader the committed text is reread under once the outcome ends.
    let vault = reader.vault.clone();
    let reader = reader.clone();
    // The turn authority the task retains: the task only reads `manifest`,
    // so edition-2024 disjoint capture would otherwise drop `_turn` when
    // this returns and the restore would run cold (FIX 11287).
    let retain_turn = segments._turn.clone();
    let message = handle.message_id();
    let (finished, forwarded) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        // Held until the outcome ends, whatever the turn wrote.
        let _retain = retain_turn;
        let Ok(ended) = outcome.await else {
            return;
        };
        let whole = ended.result.is_ok()
            && ended.saved.as_ref().is_some_and(|saved| {
                saved.message_id == message && saved.finality == StreamFinality::Final
            });
        let saved = ended.saved.clone().filter(|_| whole);
        // The outcome goes on as it ended; nothing waits for the session.
        let _ = finished.send(ended);
        if let (Some(saved), Some(authority)) = (saved, commit_authority) {
            // The committed successor carries the current full lane-admitted
            // MESSAGE text, not the raw accepted stream text; a reread that
            // does not resolve stays cold (FIX 13020).
            let text = crate::server::blocking(|| reader.committed_text(&saved));
            let Some(text) = text else {
                return;
            };
            // The HEAD the reply lands at, read once it has landed (FIX
            // 10367): HEAD does not always move to this reply's TURN, and
            // naming the TURN anyway drops the session at the next fork.
            // No HEAD stands or reads: the TURN names it, as before.
            let head = segments
                .manifest
                .anchor()
                .map(|anchor| anchor.conversation)
                .and_then(|conversation| {
                    crate::server::blocking(|| vault.local_head(&conversation).ok().flatten())
                })
                .unwrap_or(turn);
            let commit = ReplyCommit {
                head,
                message,
                text,
            };
            match next {
                Some(next) => {
                    reply_committed_preparing(&segments.manifest, commit, Arc::new(authority), next)
                }
                None => reply_committed(&segments.manifest, commit, Arc::new(authority)),
            }
        }
    });
    Answering {
        handle,
        subscription,
        outcome: forwarded,
    }
}
