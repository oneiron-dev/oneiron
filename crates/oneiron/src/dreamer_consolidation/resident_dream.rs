//! A resident's own dreaming (OF-490, ARCH-0026 frame): each resident dreams
//! under its own stamp, on its own model or on the vault weaver's model and
//! window, and the weaver never reads its diary. Since its last dreaming it
//! reads its sealed scratchpads, its receipts and its INBOX rows, oldest
//! first, as many as the window holds, and writes one diary entry in its own
//! voice. What it did not read stays for its next dreaming.
//!
//! The host lends the model and the instruction; the engine ships no
//! dreaming prompt. The Nightly recipe queues one child per resident whose
//! definition is on and whose dreaming is not off.

use super::step_charge::StepChargeTally;
use crate::agent_def::DreamingMode;
use crate::dreamer_runner::{
    DREAMER_RESIDENT_DREAM_ATTEMPT_KIND, DreamerAdmittedAttempt, DreamerParkCause,
};
use crate::dreamer_wake::{
    DREAMER_HARD_CUT_PARK_REASON, DreamerAttemptExecution, WakeAttemptContext,
};
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::llm::manifest::ModelRole;
use crate::llm::{
    BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart, DurableStepContext,
    DurableStepError, HostInferenceContext, LlmBackend, LlmMessage, LlmMessageRole, LlmRequest,
    ModelId, ModelTierRef, ResponseFormat, StepOutcome, TierPrecedence, call_as_step,
};
use crate::receipt::ReceiptQuery;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::{EntityId, Vault, WriteActor};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The window a resident dreams in when the host names none, in tokens.
pub const RESIDENT_DREAM_WINDOW_DEFAULT_TOKENS: u64 = 32_000;
/// The share of the window its inputs may fill; the rest is the entry's.
const INPUT_SHARE_DIVISOR: u64 = 2;
/// The longest fork chain a resident's dreaming follows back to it.
const MAX_FORK_DEPTH: usize = 16;

/// Each resident's committed progress: what its dreaming already read.
const PROGRESS: SideTable<EntityId, ResidentDreamProgress, Named> =
    SideTable::new(&side_table::DREAMER_RESIDENT_PROGRESS);
/// The sealed scratchpads a resident's dreaming already read. Key: resident,
/// pad.
const PADS: SideTable<(EntityId, EntityId), [u8; 1], Raw> =
    SideTable::new(&side_table::DREAMER_RESIDENT_PADS);
/// The diary entry one dreaming attempt landed, so a replay writes none.
const LANDED: SideTable<crate::attempt_queue::AttemptId, EntityId, Named> =
    SideTable::new(&side_table::DREAMER_RESIDENT_LANDED);

/// What a resident's dreaming has read so far. Each source keeps the time
/// and id of the last row it read, so a cut that stops inside one second
/// resumes after that row, not after the second.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidentDreamProgress {
    /// The newest receipt time it read, in Unix seconds.
    pub receipts_after: u64,
    /// That receipt's `kind:id`.
    pub receipt_after_id: String,
    /// The newest INBOX row time it read.
    pub inbox_after: u64,
    /// That row's item id.
    pub inbox_after_id: String,
    pub dreamed_at: u64,
    pub entries: u64,
}

/// What the host lends one resident's dreaming.
pub struct ResidentDreamModel<'a> {
    pub backend: &'a dyn LlmBackend,
    pub guard: &'a BudgetGuard,
    pub model: ModelId,
    pub inference: HostInferenceContext<'a>,
    /// The vault role whose route it shares when it inherits the weaver's
    /// model; `None` when it dreams on its own.
    pub role: Option<ModelRole>,
    /// The host's dreaming instruction.
    pub instruction: &'a str,
    /// The tokens one call's input may fill on this model, when known.
    pub window_tokens: Option<u64>,
}

/// The payload input naming the resident a dreaming child dreams for.
pub(crate) fn resident_dream_input(resident: EntityId) -> rmpv::Value {
    rmpv::Value::Map(vec![(
        rmpv::Value::from("resident"),
        rmpv::Value::Binary(resident.as_bytes().to_vec()),
    )])
}

/// The resident a dreaming child's payload names.
pub fn resident_of_dream_input(input: &rmpv::Value) -> Result<EntityId> {
    let rmpv::Value::Map(entries) = input else {
        return Err(invalid("resident dream input is not a map"));
    };
    let mut found = None;
    for (key, value) in entries {
        match (key.as_str(), value) {
            (Some("resident"), rmpv::Value::Binary(bytes)) if found.is_none() => {
                found = Some(
                    EntityId::from_bytes(
                        bytes
                            .as_slice()
                            .try_into()
                            .map_err(|_| invalid("resident is not an id16"))?,
                    )
                    .map_err(|_| invalid("resident is not an entity id"))?,
                );
            }
            _ => return Err(invalid("resident dream input has an unknown field")),
        }
    }
    found.ok_or_else(|| invalid("resident dream input names no resident"))
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("resident dream: {reason}"))
}

impl Vault {
    /// The residents that dream tonight: every enabled agent definition
    /// whose dreaming is not off, by row id.
    pub(crate) fn dreaming_residents(&self) -> Result<Vec<EntityId>> {
        let mut residents = Vec::new();
        let mut after = None;
        loop {
            let page = self.entities_by_type_page(
                crate::registry::ENTITY_TYPE_AGENT_DEF,
                after.as_ref(),
                256,
            )?;
            let Some(last) = page.last().copied() else {
                break;
            };
            for id in page {
                // A row that does not decode dreams no one's dreaming.
                if let Ok(Some(definition)) = self.get_agent_definition(&id)
                    && definition.enabled
                    && definition.dreaming_mode() != DreamingMode::Off
                {
                    residents.push(id);
                }
            }
            after = Some(last);
        }
        Ok(residents)
    }

    /// What `resident`'s dreaming has read so far.
    pub fn resident_dream_progress(&self, resident: EntityId) -> Result<ResidentDreamProgress> {
        let txn = self.store.env.read_txn()?;
        resident_dream_progress_in_txn(self, &txn, resident)
    }
}

/// [`Vault::resident_dream_progress`] in the caller's snapshot: the weave
/// report reads it into the resident's own digest (OF-499).
pub(crate) fn resident_dream_progress_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    resident: EntityId,
) -> Result<ResidentDreamProgress> {
    Ok(PROGRESS
        .get(&vault.store, txn, &resident)?
        .unwrap_or_default())
}

/// The inputs one dreaming reads, and the progress reading them makes.
#[derive(Debug, Default)]
struct DreamCut {
    sections: Vec<(&'static str, Vec<String>)>,
    pads: Vec<EntityId>,
    receipts_after: Option<(u64, String)>,
    inbox_after: Option<(u64, String)>,
}

/// Moves a `(time, id)` read cursor forward, never back.
fn advance(at: &mut u64, id: &mut String, read: Option<&(u64, String)>) {
    if let Some((read_at, read_id)) = read
        && (*read_at, read_id.as_str()) > (*at, id.as_str())
    {
        *at = *read_at;
        id.clone_from(read_id);
    }
}

impl DreamCut {
    fn is_empty(&self) -> bool {
        self.sections.iter().all(|(_, lines)| lines.is_empty())
    }

    fn text(&self) -> String {
        let mut text = String::new();
        for (title, lines) in &self.sections {
            if lines.is_empty() {
                continue;
            }
            text.push_str("## ");
            text.push_str(title);
            text.push('\n');
            for line in lines {
                text.push_str(line);
                text.push('\n');
            }
            text.push('\n');
        }
        text
    }
}

/// Room left in the window, counted as each input is added.
struct Room(u64);

impl Room {
    fn take(&mut self, text: &str) -> bool {
        let tokens = crate::count_context_pack_tokens(text) as u64;
        if tokens > self.0 {
            return false;
        }
        self.0 -= tokens;
        true
    }
}

/// The agent definitions forked from `resident` whose sealed pads its
/// dreaming reads: each whose fork chain reaches it before any other bound
/// resident. A fork that is a bound resident itself dreams over its own.
fn resident_forks(vault: &Vault, resident: EntityId) -> Result<Vec<EntityId>> {
    let mut forks = Vec::new();
    let mut after = None;
    loop {
        let page = vault.entities_by_type_page(
            crate::registry::ENTITY_TYPE_AGENT_DEF,
            after.as_ref(),
            256,
        )?;
        let Some(last) = page.last().copied() else {
            break;
        };
        for id in page {
            if id != resident && forked_from_resident(vault, id, resident) {
                forks.push(id);
            }
        }
        after = Some(last);
    }
    Ok(forks)
}

/// Whether `fork`'s chain of fork parents reaches `resident` first. A bound
/// resident on the way, or one whose binding does not read, ends the chain;
/// so do a row that does not decode, a cycle and a chain past
/// [`MAX_FORK_DEPTH`].
fn forked_from_resident(vault: &Vault, fork: EntityId, resident: EntityId) -> bool {
    let unbound = |id: EntityId| matches!(vault.settled_resident_agent(id), Ok(None));
    if !unbound(fork) {
        return false;
    }
    let mut seen = BTreeSet::from([fork]);
    let mut at = fork;
    for _ in 0..MAX_FORK_DEPTH {
        let Ok(Some(definition)) = vault.get_agent_definition(&at) else {
            return false;
        };
        let Some(parent) = definition.forked_from else {
            return false;
        };
        if parent == resident {
            return true;
        }
        if !seen.insert(parent) || !unbound(parent) {
            return false;
        }
        at = parent;
    }
    false
}

/// Reads what `resident` has not dreamed over yet, oldest first within each
/// source, until the window's input share is full. Every receipt and INBOX
/// row past the cursor is a candidate, so a busy stretch is read over later
/// dreamings rather than cut to its newest page.
fn cut_for(
    vault: &Vault,
    resident: EntityId,
    progress: &ResidentDreamProgress,
    window_tokens: u64,
) -> Result<DreamCut> {
    let mut room = Room(window_tokens / INPUT_SHARE_DIVISOR);
    let mut cut = DreamCut::default();

    // Its own sealed pads, then each of its forks': "A fork's sealed
    // scratchpad feeds its resident's diary at the next dreaming."
    let authors: Vec<EntityId> = std::iter::once(resident)
        .chain(resident_forks(vault, resident)?)
        .collect();
    let pads = {
        let txn = vault.store.env.read_txn()?;
        let mut pads = Vec::new();
        for &author in &authors {
            for pad in vault.sealed_scratchpads_in_txn(&txn, author)? {
                if !PADS.contains(&vault.store, &txn, &(resident, pad))? {
                    pads.push((pad, author));
                }
            }
        }
        pads
    };
    let mut pad_lines = Vec::new();
    for (pad, author) in pads {
        let Some(note) = vault.read_note(&pad)? else {
            continue;
        };
        if note.author_ref != author {
            continue;
        }
        let line = if author == resident {
            format!("### {}\n{}", pad.to_hex(), note.markdown.trim())
        } else {
            format!(
                "### {} (fork {})\n{}",
                pad.to_hex(),
                author.to_hex(),
                note.markdown.trim()
            )
        };
        if !room.take(&line) {
            break;
        }
        pad_lines.push(line);
        cut.pads.push(pad);
    }
    cut.sections.push(("Sealed scratchpads", pad_lines));

    let after = (progress.receipts_after, progress.receipt_after_id.as_str());
    let mut receipts: Vec<_> = vault
        .receipts(
            ReceiptQuery::new(crate::receipt::MAX_RECEIPT_QUERY_SCAN)
                .with_actor(resident.to_hex())
                .with_time_bounds(
                    (progress.receipts_after > 0).then_some(progress.receipts_after),
                    None,
                ),
        )?
        .into_iter()
        .map(|receipt| {
            let id = format!("{}:{}", receipt.receipt_kind.as_str(), receipt.receipt_id);
            ((receipt.occurred_at, id), receipt)
        })
        .filter(|((at, id), _)| (*at, id.as_str()) > after)
        .collect();
    receipts.sort_by(|a, b| a.0.cmp(&b.0));
    let mut receipt_lines = Vec::new();
    for (key, receipt) in receipts {
        let mut line = format!(
            "- {} {} {}",
            receipt.occurred_at,
            receipt.receipt_kind.as_str(),
            receipt.outcome
        );
        if let Some(job) = &receipt.job_ref {
            line.push_str(&format!(" job {job}"));
        }
        if !room.take(&line) {
            break;
        }
        receipt_lines.push(line);
        cut.receipts_after = Some(key);
    }
    cut.sections.push(("Receipts", receipt_lines));

    // A standing membership with nothing on its thread yet has no time and
    // nothing to read.
    let after = (progress.inbox_after, progress.inbox_after_id.as_str());
    let mut inbox: Vec<_> = vault
        .agent_inbox_slice(resident, usize::MAX, None)?
        .into_iter()
        .filter(|item| item.occurred_at > 0 && (item.occurred_at, item.item_id.as_str()) > after)
        .collect();
    inbox.sort_by(|a, b| (a.occurred_at, &a.item_id).cmp(&(b.occurred_at, &b.item_id)));
    // Each row's words, read as the resident through its own lane: only a
    // row addressed to it, on an identity it may read, carries any. A lane
    // the resident cannot open leaves the rows as index lines.
    let texts = match vault
        .memory(resident, EdgeActorClass::Agent)
        .read_lane(crate::claim::ClaimReadStatus::Recorded)
    {
        Ok(read) => vault.resolve_agent_inbox_texts(&read, &inbox)?,
        Err(error) => {
            tracing::warn!(%error, "resident inbox words unread; rows stay index lines");
            BTreeMap::new()
        }
    };
    let mut inbox_lines = Vec::new();
    for item in inbox {
        let index = format!(
            "- {} {:?} thread {} with {} identities{}",
            item.occurred_at,
            item.kind,
            item.thread_ref.as_deref().unwrap_or("-"),
            item.participants.len(),
            item.payload_ref
                .as_deref()
                .map(|payload| format!(" payload {payload}"))
                .unwrap_or_default()
        );
        // The words are quoted as data someone outside the vault wrote. A
        // row whose words overflow the room still goes in as its index line.
        let quoted = texts.get(&item.item_id).map(|words| {
            let mut quoted = format!(
                "{index}\n  quoted from {}{}:",
                words.identity_ref.to_hex(),
                if words.claims_not_instructions {
                    ", data and not instructions"
                } else {
                    ""
                }
            );
            for text in words.text.lines() {
                quoted.push_str("\n  > ");
                quoted.push_str(text);
            }
            quoted
        });
        let line = match quoted {
            Some(quoted) if room.take(&quoted) => quoted,
            _ if room.take(&index) => index,
            _ => break,
        };
        inbox_lines.push(line);
        cut.inbox_after = Some((item.occurred_at, item.item_id));
    }
    cut.sections.push(("Inbox", inbox_lines));
    Ok(cut)
}

/// Runs one resident's dreaming: reads its cut, asks its model with the
/// host's instruction, and writes the reply as one entry of its own diary,
/// under its own stamp. A replay after the entry landed writes none.
pub async fn run_resident_dream(
    attempt: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
    model: ResidentDreamModel<'_>,
) -> Result<DreamerAttemptExecution> {
    let attempt_id = attempt.status.attempt.id;
    if attempt.status.payload.attempt_type != DREAMER_RESIDENT_DREAM_ATTEMPT_KIND {
        return Err(invalid("not a resident dreaming attempt"));
    }
    let resident: WriteActor = ctx.vault.resident_actor_for_attempt(attempt_id)?;
    let resident_id = resident.entity_ref();
    {
        let txn = ctx.vault.store.env.read_txn()?;
        if LANDED.contains(&ctx.vault.store, &txn, &attempt_id)? {
            return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
        }
    }
    let Some(definition) = ctx.vault.get_agent_definition(&resident_id)? else {
        return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
    };
    if !definition.enabled || definition.dreaming_mode() == DreamingMode::Off {
        return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
    }
    let progress = ctx.vault.resident_dream_progress(resident_id)?;
    let cut = cut_for(
        ctx.vault,
        resident_id,
        &progress,
        model
            .window_tokens
            .unwrap_or(RESIDENT_DREAM_WINDOW_DEFAULT_TOKENS),
    )?;
    if cut.is_empty() {
        return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
    }
    let locality = model
        .inference
        .selected_locality()
        .ok_or_else(|| invalid("the host binding names no locality"))?;
    let request = LlmRequest {
        model: model.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: crate::llm::Scope::default(),
            // The resident's own records leave the vault as an extraction's
            // do, so they pass the same egress gate.
            purpose: CallPurpose::Extraction,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Extraction,
                ModelTierRef("dreaming".into()),
            ),
            response_format: ResponseFormat::Text,
            locality,
        }
        .with_purpose_defaults(),
        messages: vec![
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![ContentPart::Text {
                    text: model.instruction.to_owned(),
                }],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text { text: cut.text() }],
            },
        ],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    };
    let authorized = match model.role {
        Some(role) => ctx
            .vault
            .authorize_model_role(role, request, &model.inference)?,
        None => ctx
            .vault
            .authorize_raw_inference(request, &model.inference)?,
    };
    let mut request = authorized.into_request();
    super::roles::bind_reasoning(ctx.vault, model.backend, &mut request)?;
    let step_hash = request
        .canonical_hash()
        .map_err(|_| invalid("the dreaming request did not hash"))?;
    let step_ctx = DurableStepContext {
        vault: ctx.vault,
        attempt_id,
        run_id: attempt.status.attempt.run_id.clone(),
        envelope_actor: resident,
        subject: resident_id,
        deadline: Some(ctx.deadline),
        now_ms: ctx.now_ms,
    };
    let mut charges = StepChargeTally::default();
    let response = match call_as_step(&step_ctx, model.backend, model.guard, request).await {
        Ok(StepOutcome::Finished { response, .. }) => {
            charges.record_terminal(ctx.vault, attempt_id, step_hash, &response.usage)?;
            response
        }
        Ok(StepOutcome::Trapped { .. }) => {
            return Ok(DreamerAttemptExecution::Park {
                reason: "durable step trapped for resume".to_owned(),
                cause: DreamerParkCause::Signal,
            });
        }
        Err(DurableStepError::SpentFinalizeRefused { usage }) => {
            charges.record_usage(&usage);
            return Ok(charges.checkpoint());
        }
        Err(DurableStepError::DeadlineHardCut) => {
            return Ok(DreamerAttemptExecution::Park {
                reason: DREAMER_HARD_CUT_PARK_REASON.to_owned(),
                cause: DreamerParkCause::Checkpoint,
            });
        }
        Err(DurableStepError::FinalizeRefused) => {
            return Ok(DreamerAttemptExecution::Park {
                reason: "wake pass finalize window".to_owned(),
                cause: DreamerParkCause::Checkpoint,
            });
        }
        Err(DurableStepError::Engine(error)) => return Err(error),
        Err(other) => {
            return Ok(DreamerAttemptExecution::Park {
                reason: other.to_string(),
                cause: DreamerParkCause::of_step(&other),
            });
        }
    };
    if ctx.deadline.expired() {
        return Ok(charges.checkpoint());
    }
    let entry: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let entry = entry.trim();
    if entry.is_empty() {
        return Ok(charges.park("the model wrote an empty diary entry"));
    }
    let now = ctx.now_ms / 1_000;
    // The entry, its landing marker and the progress it read commit in one
    // write: a crash between them neither drops the progress nor lands the
    // entry twice.
    ctx.vault.with_write_txn_grouped(|txn| {
        if LANDED.contains(&ctx.vault.store, txn, &attempt_id)? {
            return Ok(());
        }
        let at = crate::ports::recorded_at_in_txn(&ctx.vault.store, txn)?;
        let entry_id = crate::memory::append_agent_diary_in_txn(
            ctx.vault,
            txn,
            resident,
            entry.to_owned(),
            at,
        )
        .map_err(|error| invalid(&format!("diary entry: {error}")))?;
        LANDED.put(&ctx.vault.store, txn, &attempt_id, &entry_id)?;
        for pad in &cut.pads {
            PADS.put(&ctx.vault.store, txn, &(resident_id, *pad), &[1])?;
        }
        let mut progress = PROGRESS
            .get(&ctx.vault.store, txn, &resident_id)?
            .unwrap_or_default();
        advance(
            &mut progress.receipts_after,
            &mut progress.receipt_after_id,
            cut.receipts_after.as_ref(),
        );
        advance(
            &mut progress.inbox_after,
            &mut progress.inbox_after_id,
            cut.inbox_after.as_ref(),
        );
        progress.dreamed_at = now;
        progress.entries += 1;
        PROGRESS.put(&ctx.vault.store, txn, &resident_id, &progress)
    })?;
    // Its own digest renders from its dreaming, read as it, once this
    // dreaming's progress is committed (OF-499). A refused render leaves the
    // row to the deadline timer and fails no dreaming.
    if let Err(error) =
        ctx.vault
            .render_scheduled_weave_digest(resident_id, EdgeActorClass::Agent, now)
    {
        tracing::warn!(?error, "resident weave digest refused after dreaming");
    }
    Ok(DreamerAttemptExecution::Completed {
        completed_units: charges.units,
    })
}
