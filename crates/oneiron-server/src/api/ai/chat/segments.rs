//! A live chat turn's typed segments (DESIGN-V2 R2): the manifest of the
//! call's messages in the order the turn assembled them (instructions,
//! resident craft where the session layout puts it, the log, the board,
//! the newest user message), set on the call once it is admitted and only
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
use oneiron::prompt::{PromptLayout, session_prompt_layout};
use oneiron::{EdgeActorClass, EntityId, LlmMessage, LlmMessageRole, Vault};

use super::compaction::SelfChat;
use super::{Answering, TurnCredential, text_message};
use crate::api::context_board::BoardSectionSource;
use crate::api::credential_memory;
use crate::auth::CoreAuth;
use crate::models::{
    AuthorityVerdict, CheckpointAuthority, ReplyCommit, RestoreClaim, SnapshotScope,
    reply_committed, turn_admitted,
};

/// Where the turn's messages lay as it assembled them, before its craft and
/// its board went in.
#[derive(Clone, Copy)]
pub(super) struct Layout {
    /// The leading System messages: the agent's instructions.
    pub(super) system_end: usize,
    /// Where the log ended: the newest user message's place.
    pub(super) log_end: usize,
}

/// Who read the turn's canonical path, and where.
#[derive(Clone)]
pub(super) struct Reader {
    pub(super) vault: Arc<Vault>,
    pub(super) auth: CoreAuth,
    pub(super) actor: EntityId,
    pub(super) class: EdgeActorClass,
    pub(super) locality: CallerLocality,
}

impl Reader {
    /// The read key the turn's log is read under now, as the turn reads it.
    fn read_key(&self) -> Option<ScopedReadActorKey> {
        let memory = match self.auth.principal_ref() {
            Some(_) => credential_memory(&self.vault, Some(&self.auth), self.actor, self.class)
                .at(self.locality),
            None => self.vault.memory(self.actor, self.class),
        };
        memory.read_key().ok()
    }
}

/// What the turn assembled, for its manifest.
pub(super) struct Assembled<'a> {
    pub(super) layout: Layout,
    pub(super) self_chat: Option<&'a SelfChat>,
    /// The messages before the board went in.
    pub(super) messages: &'a [LlmMessage],
    /// The board's text and sections, when it rides.
    pub(super) board: Option<&'a (String, Vec<BoardSectionSource>)>,
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
    /// under, held for the turn's life: the record [`turn_admitted`] keeps
    /// lapses once it goes.
    _turn: Option<Arc<dyn CheckpointAuthority>>,
}

/// The manifest of `assembled` once admitted as `admitted`; `None` when the
/// layout does not match what was assembled or admission reshaped it.
pub(super) fn admitted(
    reader: &Reader,
    assembled: Assembled<'_>,
    admitted: &[LlmMessage],
) -> Option<TurnSegments> {
    let Layout {
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
    let early = session_prompt_layout() == PromptLayout::EarlySystem;
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
    if let Some((block, sections)) = assembled.board {
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
    // The authority generation first: a revoke between the two reads
    // leaves the key read after it.
    let (revocation, read_key) = crate::server::blocking(|| {
        let revocation = reader.vault.authority_generation().ok();
        (revocation, reader.read_key())
    });
    let sources = canonical_sources(&assembled);
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
    if !manifest.describes(admitted) {
        return None;
    }
    let manifest = Arc::new(manifest);
    let path = PathDependencies::of(reader, &assembled);
    let turn = match (manifest.anchor(), &read_key, &sources) {
        (Some(anchor), Some(key), Some(rows)) => {
            let turn: Arc<dyn CheckpointAuthority> = Arc::new(ChatAuthority {
                reader: reader.clone(),
                credential: TurnCredential::Request {
                    auth: reader.auth.clone(),
                    vault: Arc::clone(&reader.vault),
                },
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
            .flat_map(|(_, sections)| sections)
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
    /// derived; `None` at the first of them that does not read.
    fn read_quoted(&self, vault: &Vault, set: &mut SnapshotDependencies) -> Option<()> {
        let mut folded = Vec::new();
        for summary in &self.summaries {
            folded.push(*summary);
            for span in vault.summary_folded_spans(summary).ok()?? {
                folded.push(span.turn);
                folded.extend(span.messages);
            }
        }
        for id in self.notes.iter().chain(&folded) {
            let world = vault.record_world(id).ok()??;
            set.worlds.push(world.unwrap_or_else(base_world_id));
            set.authors.push(vault.record_author(id).ok()??);
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
/// MESSAGE rows among its sources. A turn with no segments, or whose rows
/// are not all known, hands nothing.
pub(super) fn commit_on_answer(
    segments: Option<TurnSegments>,
    reader: &Reader,
    credential: &TurnCredential,
    written: Option<&[EntityId]>,
    turn: EntityId,
    answering: Answering,
) -> Answering {
    let Some((segments, (read_key, mut sources), written)) = segments.and_then(|segments| {
        let authority = segments.authority.clone()?;
        Some((segments, authority, written?))
    }) else {
        return answering;
    };
    sources.extend_from_slice(written);
    let authority = ChatAuthority {
        reader: reader.clone(),
        credential: credential.clone(),
        read_key,
        sources,
        at: None,
        path: segments.path.clone(),
        revocation: segments.revocation,
    };
    let Answering {
        handle,
        subscription,
        outcome,
    } = answering;
    let message = handle.message_id();
    let (finished, forwarded) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let Ok(ended) = outcome.await else {
            return;
        };
        let whole = ended.result.is_ok()
            && ended.saved.as_ref().is_some_and(|saved| {
                saved.message_id == message && saved.finality == StreamFinality::Final
            });
        let commit = whole.then(|| ReplyCommit {
            head: turn,
            message,
            text: ended.text.clone(),
        });
        // The outcome goes on as it ended; nothing waits for the session.
        let _ = finished.send(ended);
        if let Some(commit) = commit {
            reply_committed(&segments.manifest, commit, Arc::new(authority));
        }
    });
    Answering {
        handle,
        subscription,
        outcome: forwarded,
    }
}
