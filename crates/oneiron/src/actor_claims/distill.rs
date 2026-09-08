//! CHAT lane: session-end distill jobs, turn readers, and the distill run.

use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::llm::CallPurpose;
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};

use super::evidence::ActorClaimEvidence;
use super::invalid;
use super::rows::{
    ACTOR_CLAIM_MAX_CITED_EVIDENCE, ACTOR_DISTILL_CALL_PURPOSE_NAME, ActorClaimRow, ActorNote,
};
use super::write::{ground_actor_claim, require_session_entity, write_actor_claim_in_txn};

/// `actor_claims:distill_pending:v1:` + session id (16 B) → ended_at (8 BE).
///
/// The durable SessionEnd → distill JOB. Written in the SAME transaction that
/// closes the sitting, so a crash between "session ended" and "distill queued"
/// is not representable; consumed by [`run_session_end_actor_distill`].
const DISTILL_PENDING_PREFIX: &[u8] = b"actor_claims:distill_pending:v1:";
/// `temporal_learned` key layout: `learned_at` (8 BE) + entity id.
const TEMPORAL_LEARNED_KEY_LEN: usize = 8 + ENTITY_ID_LEN;
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
    vault
        .store
        .vault_meta
        .put(wtxn, &distill_job_key(session), &ended_at.to_be_bytes())?;
    Ok(())
}
/// Sittings that have ended and not yet been distilled, in id order.
pub fn pending_session_actor_distills(vault: &Vault) -> Result<Vec<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for row in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, DISTILL_PENDING_PREFIX)?
    {
        let (key, _) = row?;
        let Some(raw) = key.get(DISTILL_PENDING_PREFIX.len()..) else {
            continue;
        };
        let bytes: [u8; ENTITY_ID_LEN] = raw
            .try_into()
            .map_err(|_| Error::CorruptedIndex("actor distill job key"))?;
        out.push(
            EntityId::from_bytes(bytes)
                .map_err(|_| Error::CorruptedIndex("actor distill job key"))?,
        );
    }
    Ok(out)
}
/// Runs the CHAT-lane inlet for one ended sitting: brief → distiller → the same
/// [`write_actor_claim`] door the TASK lane uses. Returns the claim ids landed.
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
    let ended_at = distill_job(vault, session)?;
    let sitting = sitting_window(vault, session, ended_at)?;
    let brief = SessionDistillBrief {
        session: *session,
        ended_at,
        turns: session_turns(vault, sitting)?,
    };
    if brief.turns.is_empty() {
        // Nothing to learn from, and nothing that can arrive later: the sitting
        // is closed and its turns are what they are. The job is spent.
        return vault
            .with_write_txn(|wtxn| consume_distill_job_in_txn(vault, wtxn, session, ended_at))
            .map(|()| Vec::new());
    }

    let turn_ids: Vec<EntityId> = brief.turns.iter().map(|turn| turn.turn).collect();
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

    vault.with_write_txn(|wtxn| {
        let mut written = Vec::with_capacity(rows.len());
        for row in &rows {
            written.push(write_actor_claim_in_txn(vault, wtxn, row, &evidence)?);
        }
        // LAST, deliberately: the job authorized this pass, so it is spent only
        // once the pass has landed.
        consume_distill_job_in_txn(vault, wtxn, session, ended_at)?;
        Ok(written)
    })
}
/// Reads the pending job for `session`, returning its `ended_at`.
fn distill_job(vault: &Vault, session: &EntityId) -> Result<u64> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, &distill_job_key(session))?
    else {
        return Err(invalid("no session-end distill job for this session"));
    };
    decode_distill_job(&raw)
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
    let key = distill_job_key(session);
    let Some(raw) = vault.store.vault_meta.get(&*wtxn, &key)? else {
        return Err(invalid("the session-end distill job is no longer pending"));
    };
    if decode_distill_job(&raw)? != expected_ended_at {
        return Err(invalid("the session-end distill job was re-registered"));
    }
    vault.store.vault_meta.delete(wtxn, &key)?;
    Ok(())
}
fn decode_distill_job(raw: &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex("actor distill job row"))?;
    Ok(u64::from_be_bytes(bytes))
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
/// The sitting's turns — derived from what production actually writes.
///
/// **There is no SESSION→TURN edge in this engine**, so there is none to read.
/// The witness door (`Memory::witness`) writes CONVERSATION/TURN/MESSAGE
/// and bumps the open sitting's activity clock; the core turn door writes a
/// TURN plus a `ChildOf` edge into its CONVERSATION. What binds a turn to a
/// SITTING is TIME, and at most one sitting is open per vault
/// (`session_lifecycle`), so the sitting's window names exactly the turns
/// learned during it — which is also the index `dreamer_consolidation` walks to
/// find turns to dream about.
///
/// Both production body shapes are read, because production writes both: the
/// core door's `spkr`/`txt` TURN body, and — when the turn body has no text,
/// including the witness door's speaker-only stamp — the turn's MESSAGE
/// children, where the witnessed words actually live.
///
/// Bounded by [`ACTOR_CLAIM_MAX_CITED_EVIDENCE`], keeping the LAST turns: the
/// brief and the citation list are the same set of turns, so a long sitting
/// cannot produce a brief the evidence bound would then refuse to cite.
pub(super) fn session_turns(
    vault: &Vault,
    window: SittingWindow,
) -> Result<Vec<SessionDistillTurn>> {
    let mut turn_ids = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        let mut lower = [0_u8; TEMPORAL_LEARNED_KEY_LEN];
        lower[..8].copy_from_slice(&window.started_at.to_be_bytes());
        let mut upper = [u8::MAX; TEMPORAL_LEARNED_KEY_LEN];
        upper[..8].copy_from_slice(&window.ended_at.to_be_bytes());
        for entry in vault.store.temporal_learned.range(
            &rtxn,
            &(
                std::ops::Bound::Included(&lower[..]),
                std::ops::Bound::Included(&upper[..]),
            ),
        )? {
            let (key, _) = entry?;
            let Some(raw) = key.get(8..TEMPORAL_LEARNED_KEY_LEN) else {
                continue;
            };
            let Ok(bytes) = <[u8; ENTITY_ID_LEN]>::try_from(raw) else {
                continue;
            };
            let Ok(id) = EntityId::from_bytes(bytes) else {
                continue;
            };
            if vault.get_entity_type_in_txn(&rtxn, &id)? == Some(ENTITY_TYPE_TURN) {
                turn_ids.push(id);
            }
        }
    }
    if turn_ids.len() > ACTOR_CLAIM_MAX_CITED_EVIDENCE {
        turn_ids.drain(..turn_ids.len() - ACTOR_CLAIM_MAX_CITED_EVIDENCE);
    }

    let mut turns = Vec::with_capacity(turn_ids.len());
    for turn in turn_ids {
        let said = match turn_utterance(vault, &turn)? {
            Some(utterance) => vec![utterance],
            None => turn_message_utterances(vault, &turn)?,
        };
        turns.push(SessionDistillTurn { turn, said });
    }
    Ok(turns)
}
/// The utterance a TURN body carries itself when it has text, or `None` when
/// it has only the witness door's speaker stamp and its words are children.
fn turn_utterance(vault: &Vault, turn: &EntityId) -> Result<Option<SessionDistillUtterance>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.entities.get(&rtxn, turn.as_bytes())? else {
        return Ok(None);
    };
    let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..) else {
        return Ok(None);
    };
    let utterance = decode_utterance(body, "spkr", "txt");
    Ok(utterance.text.is_some().then_some(utterance))
}
/// The witnessed words of a turn: its MESSAGE children, in `(order, id)`.
fn turn_message_utterances(vault: &Vault, turn: &EntityId) -> Result<Vec<SessionDistillUtterance>> {
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
        let Some(raw) = vault.store.entities.get(&rtxn, message.as_bytes())? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        if header.entity_type != ENTITY_TYPE_MESSAGE {
            continue;
        }
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        said.push((
            message_order(body),
            message,
            decode_utterance(body, "author", "content"),
        ));
    }
    said.sort_by_key(|(order, id, _)| (*order, *id));
    Ok(said
        .into_iter()
        .map(|(_, _, utterance)| utterance)
        .collect())
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
fn distill_job_key(session: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(DISTILL_PENDING_PREFIX.len() + ENTITY_ID_LEN);
    key.extend_from_slice(DISTILL_PENDING_PREFIX);
    key.extend_from_slice(session.as_bytes());
    key
}
