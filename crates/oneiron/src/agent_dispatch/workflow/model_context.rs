//! A workflow step's selected memory and chat as model context (FIX 6290).
//!
//! A resolved projection names its rows, `<domain>:cl_<hex>` claims and
//! `tn_<hex>` turns, never their words. This reads the words of exactly the
//! rows the step's context kept, after its member's lane (FIX 5416) and its
//! binders' cut (FIX 6412, 6715) narrowed it, and of no other: the bound
//! those cuts left behind is never a source.
//!
//! Each row is read on the run's own lanes, rebuilt from the authority its
//! wrappers store: the member whose bound run it is reads on their grant
//! lane, as `member_context` judges it; every owner or agent who bound a run
//! the step's chain crosses reads on its own lane (the vault owner's key
//! for the owner, verified in the snapshot, any other actor's under its
//! access grants); a run no one bound reads on its step's own agent's lane.
//! A row renders only when every lane reads it, policy and body in one
//! snapshot, at the grant clock persisted just before it. Claim values and
//! turn texts become plain text; no MessagePack reaches a prompt.
//!
//! Nothing here refuses and nothing is cut: a row that no longer reads, one
//! of another kind, one whose body does not decode and a turn with no text
//! of its own are each counted left out, and a read that fails leaves every
//! selected row counted so. No row is truncated or capped.

use std::collections::HashSet;

use crate::Vault;
use crate::agent_dispatch::AgentDispatcher;
use crate::agent_dispatch::codec::record_dispatch_input;
use crate::agent_dispatch::workflow_record::is_wrapper;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::claim::{ScopedRead, ScopedReadActorKey, decode_claim_body};
use crate::context_projection::ResolvedContextProjection;
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN};
use crate::scan_check::{EngineScan, ScanCount};
use crate::write_envelope::WriteActor;

/// The keys a turn body names its speaker under, first non-empty one wins:
/// the vocabulary the chat projection admits a turn by.
const TURN_SPEAKER_KEYS: &[&str] = &["speaker", "role", "author", "spkr"];

/// The keys a turn body names its text under, first non-empty one wins.
const TURN_TEXT_KEYS: &[&str] = &["text", "txt"];

/// One step's selected memory and chat rows as text, each in its
/// projection's order (newest first), and how many of each were left out.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RenderedWorkflowStepContext {
    memory: Vec<String>,
    chat: Vec<String>,
    omitted_memory: usize,
    omitted_chat: usize,
    rows: Vec<EntityId>,
}

impl std::fmt::Debug for RenderedWorkflowStepContext {
    /// Counts only: the rows hold the vault's words.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RenderedWorkflowStepContext")
            .field("memory", &self.memory.len())
            .field("chat", &self.chat.len())
            .field("omitted_memory", &self.omitted_memory)
            .field("omitted_chat", &self.omitted_chat)
            .field("rows", &self.rows.len())
            .finish()
    }
}

impl RenderedWorkflowStepContext {
    /// Every selected row of `context` counted left out.
    fn unread(context: &ResolvedContextProjection) -> Self {
        Self {
            omitted_memory: context.memory_sections.len(),
            omitted_chat: context.chat_sections.len(),
            ..Self::default()
        }
    }

    /// The step's memory rows as one context message, newest learned first;
    /// `None` when none read.
    #[must_use]
    pub fn memory_text(&self) -> Option<String> {
        section_text(
            "Memory selected for this step's context, newest first:",
            &self.memory,
        )
    }

    /// The step's chat turns as one context message, newest first; `None`
    /// when none read.
    #[must_use]
    pub fn chat_text(&self) -> Option<String> {
        section_text(
            "Chat selected for this step's context, newest first:",
            &self.chat,
        )
    }

    /// How many selected rows were left out here, by count only, never
    /// which; `None` when none were.
    #[must_use]
    pub fn omission_notice(&self) -> Option<String> {
        if self.omitted_memory == 0 && self.omitted_chat == 0 {
            return None;
        }
        Some(format!(
            "{} memory rows and {} chat rows selected for this step's context are left out: \
             they could not be read for this run now, or they hold no text of their own.",
            self.omitted_memory, self.omitted_chat
        ))
    }

    /// The ids of the rows `memory_text` and `chat_text` were read from, in
    /// the order they render; empty when none read (FIX 6934).
    #[must_use]
    pub fn source_rows(&self) -> &[EntityId] {
        &self.rows
    }
}

/// `heading`, then one line per row; `None` without rows.
fn section_text(heading: &str, lines: &[String]) -> Option<String> {
    if lines.is_empty() {
        return None;
    }
    Some(format!("{heading}\n{}", lines.join("\n")))
}

/// Whose lanes read a step's selected rows: the member whose bound run it
/// is, and each owner or agent who bound a run its chain crosses.
struct StepReaders {
    member: Option<EntityId>,
    binders: Vec<WriteActor>,
}

impl AgentDispatcher<'_> {
    /// The rows `context` selected for the leased step `attempt`, read as
    /// text on the run's own lanes (module docs). Never refuses: what does
    /// not read is counted left out.
    #[must_use]
    pub fn render_workflow_step_context(
        &self,
        attempt: &AttemptRecord,
        context: &ResolvedContextProjection,
    ) -> RenderedWorkflowStepContext {
        if context.memory_sections.is_empty() && context.chat_sections.is_empty() {
            return RenderedWorkflowStepContext::default();
        }
        self.rendered_step_context(attempt, context)
            .unwrap_or_else(|error| {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a workflow step's selected context did not read; its rows are counted left out"
                );
                RenderedWorkflowStepContext::unread(context)
            })
    }

    fn rendered_step_context(
        &self,
        attempt: &AttemptRecord,
        context: &ResolvedContextProjection,
    ) -> Result<RenderedWorkflowStepContext> {
        let readers = self.step_readers(attempt.id)?;
        let lanes = self
            .reader_keys(attempt, &readers)?
            .into_iter()
            .map(|key| self.vault.scoped_read(key))
            .collect::<Vec<_>>();
        hydrate(self.vault, &lanes, context)
    }

    /// The member and binders of the chain above `attempt`, found as the
    /// context fold finds them: the first wrapper's member, every wrapper's
    /// binder, crossing each wrapper to its real parent. Every ancestor is
    /// read, however many (rule 5): past its threshold row the walk asks
    /// whether everything is okay, counted on every way out. No read
    /// transaction is held here; like each ancestor read, the threshold read
    /// opens its own.
    fn step_readers(&self, attempt: AttemptId) -> Result<StepReaders> {
        let mut walk = ScanCount::start_at(
            EngineScan::DispatchAncestorRows,
            attempt.as_bytes(),
            self.vault
                .scan_threshold(EngineScan::DispatchAncestorRows)?,
        );
        let mut seen = HashSet::new();
        let readers = self.step_readers_walk(attempt, &mut seen);
        walk.rows(seen.len());
        walk.finish(self.vault);
        readers
    }

    /// The walk [`Self::step_readers`] counts, each attempt it reads in
    /// `seen`.
    fn step_readers_walk(
        &self,
        attempt: AttemptId,
        seen: &mut HashSet<AttemptId>,
    ) -> Result<StepReaders> {
        let queue = AttemptQueue::new(self.vault);
        let mut readers = StepReaders {
            member: None,
            binders: Vec::new(),
        };
        let mut cursor = Some(attempt);
        while let Some(id) = cursor {
            if !seen.insert(id) {
                return Err(Error::InvariantViolation("context ancestor cycle"));
            }
            let record = queue
                .get(id)?
                .ok_or(Error::InvariantViolation("context ancestor is missing"))?;
            if is_wrapper(&record) {
                if readers.member.is_none() {
                    readers.member = self.workflow_member(&record)?;
                }
                readers.binders.extend(self.workflow_binder(&record)?);
                cursor = self.workflow_authority_parent(Some(id))?;
                continue;
            }
            if record_dispatch_input(&record).is_none() {
                return Err(Error::InvariantViolation(
                    "context ancestor is not dispatch lineage",
                ));
            }
            cursor = decode_dreamer_attempt_payload(&record.payload)?.parent_attempt;
        }
        Ok(readers)
    }

    /// One read key per reader: the member's grant lane, as
    /// `member_context` builds it, then each binder's own key. A run with
    /// neither reads on its step's own agent's key.
    fn reader_keys(
        &self,
        attempt: &AttemptRecord,
        readers: &StepReaders,
    ) -> Result<Vec<ScopedReadActorKey>> {
        let mut keys = Vec::with_capacity(readers.binders.len() + 1);
        if let Some(member) = readers.member {
            keys.push(
                ScopedReadActorKey::with_actor_class(
                    member.to_hex(),
                    EdgeActorClass::Human.gate_actor_class(),
                )
                .ok_or(Error::InvariantViolation(
                    "a member's id builds no read key",
                ))?
                .require_access_grants(Some(member)),
            );
        }
        let mut actors = readers.binders.clone();
        if readers.member.is_none() && actors.is_empty() {
            let input = record_dispatch_input(attempt).ok_or(Error::InvariantViolation(
                "a workflow step carries no dispatch input",
            ))?;
            actors.push(crate::agent_dispatch::agent_dispatch_actor(&input)?);
        }
        let txn = self.vault.store.env.read_txn()?;
        for actor in actors {
            keys.push(own_key_in(self.vault, &txn, actor)?);
        }
        Ok(keys)
    }
}

/// `actor`'s own read key as `txn` judges it: the vault owner's key for the
/// owner, any other actor's under its access grants. A check that fails
/// reads as not the owner, the narrower key.
fn own_key_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
) -> Result<ScopedReadActorKey> {
    let (id, class) = (actor.entity_ref(), actor.actor_class());
    if crate::memory::actor_is_vault_owner_in_txn(vault, txn, id, class).unwrap_or(false) {
        return Ok(ScopedReadActorKey::vault_owner(id));
    }
    ScopedReadActorKey::with_actor_class(id.to_hex(), class.gate_actor_class())
        .map(|key| key.require_access_grants(Some(id)))
        .ok_or(Error::InvariantViolation(
            "a binder's id builds no read key",
        ))
}

/// The selected rows of `context` that every lane reads, each in one
/// snapshot taken after every lane persisted its grant clock, rendered as
/// text; the rest counted left out. No lane reads nothing.
fn hydrate(
    vault: &Vault,
    lanes: &[ScopedRead<'_>],
    context: &ResolvedContextProjection,
) -> Result<RenderedWorkflowStepContext> {
    let memory_rows: Vec<Option<EntityId>> = context
        .memory_sections
        .iter()
        .map(String::as_str)
        .map(memory_row)
        .collect();
    let chat_rows: Vec<Option<EntityId>> = context
        .chat_sections
        .iter()
        .map(String::as_str)
        .map(chat_row)
        .collect();
    let ids: Vec<EntityId> = memory_rows
        .iter()
        .chain(&chat_rows)
        .flatten()
        .copied()
        .collect();
    for lane in lanes {
        lane.persist_grant_clock()?;
    }
    let txn = vault.store.env.read_txn()?;
    let mut bodies: Vec<Option<(u8, u64, Vec<u8>)>> = Vec::new();
    for (index, lane) in lanes.iter().enumerate() {
        let read = lane.get_entities_parts_in_txn(&txn, &ids)?;
        if index == 0 {
            bodies = read;
        } else {
            for (kept, other) in bodies.iter_mut().zip(read) {
                if other.is_none() {
                    *kept = None;
                }
            }
        }
    }
    drop(txn);
    let mut bodies = bodies.into_iter();
    let mut rendered = RenderedWorkflowStepContext::default();
    for row in &memory_rows {
        let body = row.and_then(|_| bodies.next().flatten());
        match body.and_then(|(entity_type, _, body)| claim_line(entity_type, &body)) {
            Some(line) => {
                rendered.memory.push(line);
                if let Some(id) = row {
                    rendered.rows.push(*id);
                }
            }
            None => rendered.omitted_memory += 1,
        }
    }
    for row in &chat_rows {
        let body = row.and_then(|_| bodies.next().flatten());
        match body.and_then(|(entity_type, _, body)| turn_line(entity_type, &body)) {
            Some(line) => {
                rendered.chat.push(line);
                if let Some(id) = row {
                    rendered.rows.push(*id);
                }
            }
            None => rendered.omitted_chat += 1,
        }
    }
    Ok(rendered)
}

/// The claim a memory section names: `<domain>:cl_<hex>`.
fn memory_row(section: &str) -> Option<EntityId> {
    let (_, hex) = section.rsplit_once(":cl_")?;
    EntityId::from_hex(hex).ok()
}

/// The turn a chat section names: `tn_<hex>`.
fn chat_row(section: &str) -> Option<EntityId> {
    EntityId::from_hex(section.strip_prefix("tn_")?).ok()
}

/// A claim's line: its predicate and its value, a string as it is, any
/// other value as text. `None` for another kind or a body that does not
/// decode.
fn claim_line(entity_type: u8, body: &[u8]) -> Option<String> {
    if entity_type != ENTITY_TYPE_CLAIM {
        return None;
    }
    let claim = decode_claim_body(body, true).ok()?;
    let value = claim
        .value
        .as_str()
        .map_or_else(|| claim.value.to_string(), str::to_owned);
    Some(format!("- {}: {value}", claim.predicate))
}

/// A turn's line: its speaker and its own text. `None` for another kind, a
/// body that is not a map, or one with no text of its own (a witnessed
/// conversation's container keeps its words in its messages).
fn turn_line(entity_type: u8, body: &[u8]) -> Option<String> {
    if entity_type != ENTITY_TYPE_TURN {
        return None;
    }
    let mut cursor = body;
    let rmpv::Value::Map(entries) = rmpv::decode::read_value(&mut cursor).ok()? else {
        return None;
    };
    let field = |keys: &[&str]| {
        keys.iter().find_map(|key| {
            entries
                .iter()
                .find(|(candidate, _)| candidate.as_str() == Some(*key))
                .and_then(|(_, value)| value.as_str())
                .filter(|value| !value.trim().is_empty())
        })
    };
    let text = field(TURN_TEXT_KEYS)?;
    Some(match field(TURN_SPEAKER_KEYS) {
        Some(speaker) => format!("- {speaker}: {text}"),
        None => format!("- {text}"),
    })
}
