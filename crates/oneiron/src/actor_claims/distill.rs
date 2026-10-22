//! CHAT lane: session-end distill jobs, turn readers, and the distill run.

use crate::ports::EntityStoreRead;
use rmpv::Value;

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::limit_ask::EngineLimit;
use crate::llm::CallPurpose;
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::side_table::{self, Raw, SideTable};
use crate::write_envelope::WriteActor;

use super::evidence::ActorClaimEvidence;
use super::invalid;
use super::rows::{ACTOR_DISTILL_CALL_PURPOSE_NAME, ActorClaimRow, ActorNote};
use super::write::{ground_actor_claim, require_session_entity, write_born_actor_claim_in_txn};

/// The durable SessionEnd → distill JOB, keyed by session id, value `ended_at`.
///
/// Written in the SAME transaction that closes the sitting, so a crash
/// between "session ended" and "distill queued" is not representable;
/// consumed by [`run_session_end_actor_distill`].
const DISTILL_PENDING: SideTable<EntityId, u64, Raw> =
    SideTable::new(&side_table::ACTOR_CLAIMS_DISTILL_PENDING_JOB);
/// The door a distilled note's birth names as its process (FIX 329).
const DISTILL_BIRTH_DOOR: &str = "actor_claims.distill";
/// `temporal_learned` key layout: `learned_at` (8 BE) + entity id.
// ---------------------------------------------------------------------------
// CHAT lane — SessionEnd distillation
// ---------------------------------------------------------------------------
/// One thing said in a sitting: who spoke, and their words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDistillUtterance {
    pub speaker: Option<String>,
    pub text: Option<String>,
}
/// One turn of the sitting, as the distiller sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDistillTurn {
    pub turn: EntityId,
    /// What was said, in write order. A turn is a LIST because production
    /// writes two shapes: the core turn door puts one utterance in the TURN
    /// body (`spkr`/`txt`), while the witness door stamps the speaker on the
    /// TURN and writes the words as its MESSAGE children — so a witnessed turn
    /// holding a question and its answer yields two utterances, and flattening
    /// them into one speaker would attribute half the turn to the wrong actor.
    pub said: Vec<SessionDistillUtterance>,
    /// The MESSAGE rows `said` was read from, in its order (FIX 7101); empty
    /// when the TURN body held the words.
    pub messages: Vec<EntityId>,
}
/// What a session-end distillation gets to reason over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDistillBrief {
    /// The ended sitting.
    pub session: EntityId,
    /// When it ended — the `at` every minted row is stamped with.
    pub ended_at: u64,
    /// Its turns, in `(learned_at, id)` scan order.
    pub turns: Vec<SessionDistillTurn>,
    /// The rows the brief was read from (FIX 7101): the sitting, each TURN
    /// and each MESSAGE its words came from. A host that resolves speakers
    /// adds the rows it reads for them; `None` is unknown.
    pub source_rows: Option<Vec<EntityId>>,
}
/// Distills an ended sitting into actor notes, or returns none.
///
/// The host-supplied LLM tier implements this against the engine's existing LLM
/// surface under [`actor_distill_call_purpose`]; this module constructs no
/// client (the `dreamer_consolidation` extract/merge posture). Returning an
/// empty vec is a first-class answer: a sitting that taught nothing teaches
/// nothing, and a distiller that invents a lesson to have one is the failure
/// mode this seam exists to keep out of the engine.
pub trait SessionActorDistiller {
    /// The notes `brief` supports.
    fn distill(&self, brief: &SessionDistillBrief) -> Result<Vec<ActorNote>>;
}
/// The [`CallPurpose`] a distiller's LLM tier must stamp.
#[must_use]
pub fn actor_distill_call_purpose() -> CallPurpose {
    CallPurpose::Other {
        name: ACTOR_DISTILL_CALL_PURPOSE_NAME.to_owned(),
    }
}
/// Registers the SessionEnd → distill job inside the caller's close
/// transaction (`Vault::end_session_with_wake`'s commit).
///
/// Same transaction as the close on purpose: the job row is what makes "this
/// sitting is over and unlearned-from" a durable fact rather than a live
/// process's intention.
pub(crate) fn register_session_end_distill_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    session: &EntityId,
    ended_at: u64,
) -> Result<()> {
    DISTILL_PENDING.put(&vault.store, wtxn, session, &ended_at)?;
    Ok(())
}
/// Sittings that have ended and not yet been distilled, in id order.
pub fn pending_session_actor_distills(vault: &Vault) -> Result<Vec<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(DISTILL_PENDING
        .scan(&vault.store, &rtxn)?
        .into_iter()
        .map(|(session, _)| session)
        .collect())
}
/// Runs the CHAT-lane inlet for one ended sitting: brief → distiller → the same
/// [`write_actor_claim`](crate::actor_claims::write_actor_claim) door the TASK lane uses. Returns the claim ids landed.
///
/// **Plain chatting mints no TASK (08b r13).** This path writes CLAIM entities
/// and clears its own job row; it has no task-minting door in reach, and that
/// is the boundary rather than a promise. The moment a sitting spawns real
/// work, THAT moment mints a TASK through the surface that spawns it — lanes
/// compose, they never blur.
///
/// The job row is required: distillation runs at session END, and without the
/// row there is no evidence the sitting is over.
///
/// **The job is CONSUMED AFTER the work, in the transaction that lands it.**
/// A distiller is a host-supplied LLM tier — the one step here that fails for
/// reasons that pass — so deleting the job first would trade a transient
/// timeout for the permanent loss of that sitting's distillation. Notes and the
/// job's deletion commit together or neither does, which also means a pass that
/// dies halfway leaves no partial helping of notes behind. A re-run over an
/// already-distilled sitting is still a typed no-such-job.
pub fn run_session_end_actor_distill(
    vault: &Vault,
    session: &EntityId,
    distiller: &dyn SessionActorDistiller,
) -> Result<Vec<EntityId>> {
    distill_session(vault, session, distiller, None)
}
/// [`run_session_end_actor_distill`] by a named `writer` (FIX 329): each note
/// the pass mints is born of `writer` from the turns it cites, stamped in the
/// transaction that lands it. A note a standing head already holds is not
/// minted, so it is not born again.
pub(super) fn distill_session(
    vault: &Vault,
    session: &EntityId,
    distiller: &dyn SessionActorDistiller,
    writer: Option<WriteActor>,
) -> Result<Vec<EntityId>> {
    let ended_at = distill_job(vault, session)?;
    let sitting = sitting_window(vault, session, ended_at)?;
    let turns = sitting_turns(vault, session, sitting)?;
    let brief = SessionDistillBrief {
        session: *session,
        ended_at,
        source_rows: Some(brief_rows(session, &turns)),
        turns,
    };
    if brief.turns.is_empty() {
        // Nothing to learn from, and nothing that can arrive later: the sitting
        // is closed and its turns are what they are. The job is spent.
        return vault
            .with_write_txn_grouped(|wtxn| {
                consume_distill_job_in_txn(vault, wtxn, session, ended_at)
            })
            .map(|()| Vec::new());
    }

    let turn_ids: Vec<EntityId> = brief.turns.iter().map(|turn| turn.turn).collect();
    let birth = writer.and_then(|writer| distill_birth(writer, &turn_ids, ended_at));
    let evidence = ActorClaimEvidence::chat(*session, turn_ids, ended_at)?;
    // Grounded before the transaction opens, and SKIPPED rather than fatal —
    // the TASK lane's posture: a distiller naming an entity that cannot hold a
    // lesson must not deny the notes that named real ones, nor poison the job
    // into failing every retry the same way.
    let rows: Vec<ActorClaimRow> = distiller
        .distill(&brief)?
        .into_iter()
        .map(|note| note.kind.row(note.actor, note.text))
        .filter(|row| ground_actor_claim(vault, row, &evidence).is_ok())
        .collect();

    vault.with_write_txn_grouped(|wtxn| {
        let mut written = Vec::with_capacity(rows.len());
        for row in &rows {
            written.push(write_born_actor_claim_in_txn(
                vault,
                wtxn,
                row,
                &evidence,
                birth.as_ref(),
            )?);
        }
        // LAST, deliberately: the job authorized this pass, so it is spent only
        // once the pass has landed.
        consume_distill_job_in_txn(vault, wtxn, session, ended_at)?;
        Ok(written)
    })
}
/// The birth `writer` stamps on a note it distilled at `at` (FIX 329): a
/// conclusion made from the turns the note cites.
fn distill_birth(writer: WriteActor, turns: &[EntityId], at: u64) -> Option<RowBirth> {
    RowBirth::written(
        writer,
        MadeByClass::of_writer(writer.actor_class()),
        DISTILL_BIRTH_DOOR,
        turns,
        &[],
        at,
    )
}
/// Reads the pending job for `session`, returning its `ended_at`.
fn distill_job(vault: &Vault, session: &EntityId) -> Result<u64> {
    let rtxn = vault.store.env.read_txn()?;
    DISTILL_PENDING
        .get(&vault.store, &rtxn, session)?
        .ok_or_else(|| invalid("no session-end distill job for this session"))
}
/// Spends the job inside the transaction that lands the pass.
///
/// Identity-bound like the session close it descends from (ONE-1685): the row
/// is re-read here and must still be the job this pass planned against, so two
/// runners racing one sitting cannot both commit their notes.
fn consume_distill_job_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    session: &EntityId,
    expected_ended_at: u64,
) -> Result<()> {
    let Some(ended_at) = DISTILL_PENDING.get(&vault.store, &*wtxn, session)? else {
        return Err(invalid("the session-end distill job is no longer pending"));
    };
    if ended_at != expected_ended_at {
        return Err(invalid("the session-end distill job was re-registered"));
    }
    DISTILL_PENDING.delete(&vault.store, wtxn, session)?;
    Ok(())
}
/// The window a sitting covers: `[started_at, ended_at]` in unix seconds.
#[derive(Debug, Clone, Copy)]
pub(super) struct SittingWindow {
    pub(super) started_at: u64,
    pub(super) ended_at: u64,
}
/// Resolves the ended sitting's window, refusing a subject that is not one.
fn sitting_window(vault: &Vault, session: &EntityId, ended_at: u64) -> Result<SittingWindow> {
    require_session_entity(vault, session)?;
    let Some(record) = vault.session_lifecycle_record(session)? else {
        return Err(invalid("session-end distill needs the sitting's clock"));
    };
    Ok(SittingWindow {
        started_at: record.started_at,
        ended_at: ended_at.max(record.started_at),
    })
}
/// The sitting's own turns (FIX 2015): the turns its membership rows name
/// (`session_lifecycle`'s SESSION_TURNS, which the witness door writes as it
/// records each turn), whoever spoke them. Many sittings may be open at once,
/// so a time window would also name a neighbour's turns; only a sitting
/// recorded before the membership rows, which has none, keeps the window
/// ([`session_turns`]) and so never reads nothing.
fn sitting_turns(
    vault: &Vault,
    session: &EntityId,
    window: SittingWindow,
) -> Result<Vec<SessionDistillTurn>> {
    match vault.session_member_turns(session)? {
        Some(turn_ids) => distill_turns(vault, turn_ids),
        None => session_turns(vault, window),
    }
}

/// The turns learned during a sitting's window. A sitting recorded before
/// the membership rows has only its time: the witness door bumps the open
/// sitting's activity clock and the core turn door writes a TURN plus a
/// `ChildOf` edge into its CONVERSATION, so the window names the turns
/// learned during it, which is also the index `dreamer_consolidation` walks.
pub(super) fn session_turns(
    vault: &Vault,
    window: SittingWindow,
) -> Result<Vec<SessionDistillTurn>> {
    let mut turn_ids = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        let query = crate::ports::TimelineQuery {
            start: std::ops::Bound::Included(window.started_at),
            end: std::ops::Bound::Included(window.ended_at),
            ..Default::default()
        };
        for entry in vault.store.port_entity_timeline(&rtxn, query)? {
            let id = entry?.id;
            if vault.get_entity_type_in_txn(&rtxn, &id)? == Some(ENTITY_TYPE_TURN) {
                turn_ids.push(id);
            }
        }
    }
    distill_turns(vault, turn_ids)
}

/// What each of `turn_ids` said. Both production body shapes are read,
/// because production writes both: the core door's `spkr`/`txt` TURN body,
/// and, when the turn body has no text (the witness door's speaker-only stamp
/// included), the turn's MESSAGE children, where the witnessed words live.
///
/// Every turn is kept (Engine 10-21, Rule 5, FIX 6849): the brief and the
/// citation list are the same set, and the chat lane cites however many turns
/// the sitting had. The whole count is measured, which asks whether
/// everything is okay past the bound and drops nothing.
fn distill_turns(vault: &Vault, turn_ids: Vec<EntityId>) -> Result<Vec<SessionDistillTurn>> {
    let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, turn_ids.len() as u64);
    let mut turns = Vec::with_capacity(turn_ids.len());
    for turn in turn_ids {
        let (messages, said) = match turn_utterance(vault, &turn)? {
            Some(utterance) => (Vec::new(), vec![utterance]),
            None => turn_message_utterances(vault, &turn)?,
        };
        turns.push(SessionDistillTurn {
            turn,
            said,
            messages,
        });
    }
    Ok(turns)
}

/// The rows a brief over `turns` of `session` was read from: the sitting,
/// then each turn and the MESSAGE rows its words came from.
fn brief_rows(session: &EntityId, turns: &[SessionDistillTurn]) -> Vec<EntityId> {
    std::iter::once(*session)
        .chain(
            turns
                .iter()
                .flat_map(|turn| std::iter::once(turn.turn).chain(turn.messages.iter().copied())),
        )
        .collect()
}
/// The utterance a TURN body carries itself when it has text, or `None` when
/// it has only the witness door's speaker stamp and its words are children.
fn turn_utterance(vault: &Vault, turn: &EntityId) -> Result<Option<SessionDistillUtterance>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .port_entity_record(&rtxn, turn)?
        .map(|row| row.encode())
    else {
        return Ok(None);
    };
    let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..) else {
        return Ok(None);
    };
    let utterance = decode_utterance(body, "spkr", "txt");
    Ok(utterance.text.is_some().then_some(utterance))
}
/// The witnessed words of a turn: its MESSAGE children, in `(order, id)`,
/// each beside the MESSAGE it was read from.
fn turn_message_utterances(
    vault: &Vault,
    turn: &EntityId,
) -> Result<(Vec<EntityId>, Vec<SessionDistillUtterance>)> {
    // `edges_in` reports the FAR end in `target`, so these are the messages
    // that named this turn as their part-of container.
    let messages: Vec<EntityId> = vault
        .edges_in(turn)?
        .into_iter()
        .filter(|edge| edge.kind == EdgeKind::PartOf)
        .map(|edge| edge.target)
        .collect();

    let rtxn = vault.store.env.read_txn()?;
    let mut said: Vec<(u64, EntityId, SessionDistillUtterance)> = Vec::new();
    for message in messages {
        let Some(raw) = vault.store.port_entity_record(&rtxn, &message)? else {
            continue;
        };

        if raw.entity_type != ENTITY_TYPE_MESSAGE {
            continue;
        }
        let body = &raw.body;
        said.push((
            message_order(body),
            message,
            decode_utterance(body, "author", "content"),
        ));
    }
    said.sort_by_key(|(order, id, _)| (*order, *id));
    Ok(said
        .into_iter()
        .map(|(_, message, utterance)| (message, utterance))
        .unzip())
}
/// Reads one utterance from a MessagePack body, tolerating any other shape: an
/// undecodable turn is still a turn that happened.
///
/// Both documented spellings of each key are accepted (`spkr`/`speaker`,
/// `txt`/`text`), the same tolerance `dreamer_consolidation` reads turns with.
fn decode_utterance(raw: &[u8], speaker_key: &str, text_key: &str) -> SessionDistillUtterance {
    let mut utterance = SessionDistillUtterance {
        speaker: None,
        text: None,
    };
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut std::io::Cursor::new(raw)) else {
        return utterance;
    };
    for (key, value) in entries {
        let Some(key) = key.as_str() else { continue };
        if (key == speaker_key || key == "speaker") && utterance.speaker.is_none() {
            utterance.speaker = value.as_str().map(str::to_owned);
        } else if (key == text_key || key == "text") && utterance.text.is_none() {
            utterance.text = value.as_str().map(str::to_owned);
        }
    }
    utterance
}
/// A witnessed message's position inside its turn; absent reads as first.
fn message_order(raw: &[u8]) -> u64 {
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut std::io::Cursor::new(raw)) else {
        return 0;
    };
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("order"))
        .and_then(|(_, value)| value.as_u64())
        .unwrap_or(0)
}
