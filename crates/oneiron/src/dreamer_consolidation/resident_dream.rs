//! A resident's own dreaming (OF-490, ARCH-0026 frame): each resident dreams
//! under its own stamp, on its own model or on the vault weaver's model and
//! window, and the weaver never reads its diary. Since its last dreaming it
//! reads its sealed scratchpads, its receipts, its INBOX rows and the health
//! cards about it (`resident_health`), oldest first, as many as the window
//! holds, and writes one diary entry in its own voice. It may also propose
//! craft notes about itself, actor.lesson and actor.failure_mode candidates,
//! which land Proposed beside the entry.
//! What it did not read stays for its next dreaming.
//!
//! The host lends the model and the instruction; the engine ships no
//! dreaming prompt, only the reply's shape ([`CRAFT_ASK`]). The Nightly
//! recipe queues one child per resident whose definition is on and whose
//! dreaming is not off, unless the owner set it a free-time policy: then its
//! dreaming is its cycle's own-time item instead (FIX 4453).

use super::request_sources::{CallBackend, SourcedBackend};
use super::step_charge::StepChargeTally;
use crate::actor_claims::ResidentCraftCandidate;
use crate::agent_def::DreamingMode;
use crate::agent_inbox_lens::{AgentInboxDiaryReview, ResolvedInboxText};
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
    BudgetGuard, DurableStepContext, DurableStepError, HostInferenceContext, LlmBackend, ModelId,
    StepOutcome, call_as_step_checked,
};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::{EntityId, Vault, WriteActor};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

mod cut;
mod landing;
mod reply;
mod request;
use cut::{cut_health, cut_inbox, cut_pads, cut_receipts};
use landing::{DreamWrite, commit_dream};
use request::dream_request;

/// The window a resident dreams in when the host names none, in tokens.
pub const RESIDENT_DREAM_WINDOW_DEFAULT_TOKENS: u64 = 32_000;
/// The share of the window its inputs may fill; the rest is the entry's.
const INPUT_SHARE_DIVISOR: u64 = 2;
/// A fork chain of more hops than this, followed back to a resident, is
/// logged once per walk (FIX 7057). It is walked whole all the same: this
/// bounds nothing.
const LONG_FORK_LINEAGE: usize = 16;
/// The fence that opens a dreaming reply's craft notes, after its entry.
const CRAFT_FENCE: &str = "```oneiron-craft";
/// The reply's shape, after the cut: the entry, then optionally the
/// resident's craft notes about itself (OF-490). The host's instruction
/// stays the voice; this only says where the notes go.
const CRAFT_ASK: &str = "Write your diary entry. After it you may propose craft notes about \
     yourself: end the reply with one block fenced ```oneiron-craft holding \
     {\"lessons\":[\"<what you will do differently>\"],\
     \"failure_modes\":[\"<a lapse of yours that keeps recurring>\"]}, either list empty \
     when you have none. Nothing follows the closing fence; everything before the block is \
     the diary entry.";

/// Each resident's committed progress: what its dreaming already read.
const PROGRESS: SideTable<EntityId, ResidentDreamProgress, Named> =
    SideTable::new(&side_table::DREAMER_RESIDENT_PROGRESS);
/// The sealed scratchpads a resident's dreaming already read. Key: resident,
/// pad.
const PADS: SideTable<(EntityId, EntityId), [u8; 1], Raw> =
    SideTable::new(&side_table::DREAMER_RESIDENT_PADS);
/// The diary entry one dreaming attempt landed (its first part), so a
/// replay writes none.
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
    /// The INBOX row past the cursor its last dreaming read only in part.
    #[serde(default)]
    pub inbox_partial: Option<ResidentDreamPartial>,
    /// The sealed pad its last dreaming read only in part.
    #[serde(default)]
    pub pad_partial: Option<ResidentDreamPartial>,
    /// The time the newest health card about it that it read was last
    /// touched (FIX 1145).
    #[serde(default)]
    pub health_after: u64,
    /// That card's `health:` handle.
    #[serde(default)]
    pub health_after_id: String,
    /// The time the newest health card about one of its forks that it read
    /// was last touched (FIX 5913): a cursor of its own, so a fork's card
    /// never moves it past a card about it unread.
    #[serde(default)]
    pub fork_health_after: u64,
    /// That card's `health:` handle.
    #[serde(default)]
    pub fork_health_after_id: String,
    pub dreamed_at: u64,
    pub entries: u64,
}

/// An input one dreaming read only in part, because it did not fit any
/// window whole: the next dreaming reads on from `read` bytes into it, so it
/// is read whole across dreamings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidentDreamPartial {
    /// The row's time (an INBOX row's), or 0 for a pad.
    pub at: u64,
    /// The INBOX row's item id, or the pad's hex id.
    pub id: String,
    /// The bytes of its words (a pad's body) read so far.
    pub read: u64,
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
    /// `backend` bound per call to the rows its input was read from, when
    /// the host lends that (FIX 6998).
    pub sourced: Option<&'a dyn SourcedBackend>,
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
            // A free-time cycle's item names its cycle too (FIX 4453); the
            // binding its cycle stamped is what it runs under.
            (Some("cycle"), rmpv::Value::Binary(_)) => {}
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
    inbox_partial: Option<ResidentDreamPartial>,
    pad_partial: Option<ResidentDreamPartial>,
    health_after: Option<(u64, String)>,
    fork_health_after: Option<(u64, String)>,
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

    /// The rows this cut's text was read from (FIX 6998): its pads, the
    /// one it reads in part too, while it reads pads alone. A receipt, an
    /// INBOX row or a health card line names no complete row set, so a cut
    /// that holds one has no known set.
    fn source_rows(&self) -> Option<Vec<EntityId>> {
        if self
            .sections
            .iter()
            .any(|(title, lines)| *title != PADS_SECTION && !lines.is_empty())
        {
            return None;
        }
        let mut rows = self.pads.clone();
        if let Some(partial) = &self.pad_partial {
            rows.push(EntityId::from_hex(&partial.id).ok()?);
        }
        Some(rows)
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

    /// The longest non-empty prefix of `body`, cut at a character, that
    /// fits what is left once `render` frames it and `mark` follows, with the
    /// bytes of `body` it holds; `None` when no such prefix fits.
    fn fit_part(
        &self,
        body: &str,
        render: impl Fn(&str) -> String,
        mark: &str,
    ) -> Option<(String, usize)> {
        let mut end = body.len();
        loop {
            let end_at = body.floor_char_boundary(end);
            if end_at == 0 {
                return None;
            }
            let cut = format!("{}{mark}", render(&body[..end_at]));
            if crate::count_context_pack_tokens(&cut) as u64 <= self.0 {
                return Some((cut, end_at));
            }
            end = end_at * 9 / 10;
        }
    }
}

/// The words a dreaming quotes for one INBOX row, who they are quoted from,
/// and whether they read as data: the row's own resolved `words`, else a
/// pending diary read's stated reason, its reader's words, quoted whole as
/// data (OF-490, Rule 5); `None` for a row of pointers only.
fn diary_review_words<'a>(
    words: Option<&'a ResolvedInboxText>,
    review: Option<&'a AgentInboxDiaryReview>,
) -> Option<(EntityId, &'a str, bool)> {
    match (words, review) {
        (Some(words), _) => Some((
            words.identity_ref,
            words.text.as_str(),
            words.claims_not_instructions,
        )),
        (None, Some(review)) if !review.reason.is_empty() => {
            Some((review.reader, review.reason.as_str(), true))
        }
        (None, _) => None,
    }
}

/// What a row's quoted words, cut to fit, end with.
const WORDS_CUT_MARK: &str = "\n  > (the words run on past this dreaming's window)";
/// What a pad's body, cut to fit, ends with.
const PAD_CUT_MARK: &str = "\n(the pad runs on past this dreaming's window)";
/// The title of a cut's sealed pads.
const PADS_SECTION: &str = "Sealed scratchpads";

/// Where an input an earlier dreaming read in part reads on from: `read`
/// bytes in, at a character, when `partial` is that input; else its start.
fn read_on_from(partial: Option<&ResidentDreamPartial>, at: u64, id: &str, body: &str) -> usize {
    partial
        .filter(|partial| partial.at == at && partial.id == id)
        .map_or(0, |partial| {
            body.floor_char_boundary(usize::try_from(partial.read).unwrap_or(usize::MAX))
        })
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
/// so do a row that does not decode, the chain's root and a cycle. A visited
/// set stops a cycle, never a count (FIX 7057): a chain of any length is
/// followed to its end.
fn forked_from_resident(vault: &Vault, fork: EntityId, resident: EntityId) -> bool {
    let unbound = |id: EntityId| matches!(vault.settled_resident_agent(id), Ok(None));
    if !unbound(fork) {
        return false;
    }
    let mut seen = BTreeSet::from([fork]);
    let mut at = fork;
    loop {
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
        if seen.len() == LONG_FORK_LINEAGE + 1 {
            tracing::warn!(
                kind = "fork_lineage_long",
                past = LONG_FORK_LINEAGE,
                "a resident's fork walk follows an unusually long fork lineage"
            );
        }
        at = parent;
    }
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

    let authors = cut_pads(vault, resident, progress, &mut room, &mut cut)?;
    cut_receipts(vault, resident, progress, &mut room, &mut cut)?;
    cut_inbox(vault, resident, progress, &mut room, &mut cut)?;
    cut_health(vault, resident, progress, &mut room, &mut cut, &authors);
    Ok(cut)
}

/// A dreaming reply's diary entry and the craft notes it proposes: a reply
/// that ends with one ```oneiron-craft block whose lessons and failure
/// modes parse proposes them, and its entry is what precedes the block. Any
/// other reply is all entry and proposes nothing: a note is never made up.
fn split_craft_notes(reply: &str) -> (&str, Vec<ResidentCraftCandidate>) {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CraftBlock {
        #[serde(default)]
        lessons: Vec<String>,
        #[serde(default)]
        failure_modes: Vec<String>,
    }
    let parsed = reply
        .strip_suffix("```")
        .and_then(|rest| rest.rsplit_once(CRAFT_FENCE))
        .and_then(|(entry, block)| {
            let block = serde_json::from_str::<CraftBlock>(block.trim()).ok()?;
            Some((entry.trim_end(), block))
        });
    let Some((entry, block)) = parsed else {
        return (reply, Vec::new());
    };
    let craft = block
        .lessons
        .into_iter()
        .map(ResidentCraftCandidate::Lesson)
        .chain(
            block
                .failure_modes
                .into_iter()
                .map(ResidentCraftCandidate::FailureMode),
        )
        .collect();
    (entry, craft)
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
            return Ok(DreamerAttemptExecution::Completed {
                completed_units: 0,
                step_hashes: Vec::new(),
            });
        }
    }
    // A free-time cycle's own-time item (FIX 4453) dreams only while its
    // cycle is open and its agent did not choose rest; its receipt lands with
    // its entry. One that lands no entry gets no success receipt.
    let free_time =
        match crate::dreamer_runner::free_time_item_to_run(ctx.vault, attempt_id, resident_id)? {
            crate::dreamer_runner::FreeTimeItemRun::Done => {
                return Ok(DreamerAttemptExecution::Completed {
                    completed_units: 0,
                    step_hashes: Vec::new(),
                });
            }
            crate::dreamer_runner::FreeTimeItemRun::Unbound => None,
            crate::dreamer_runner::FreeTimeItemRun::Run(binding) => Some(binding),
        };
    let Some(definition) = ctx.vault.get_agent_definition(&resident_id)? else {
        return Ok(DreamerAttemptExecution::Completed {
            completed_units: 0,
            step_hashes: Vec::new(),
        });
    };
    if !definition.enabled || definition.dreaming_mode() == DreamingMode::Off {
        return Ok(DreamerAttemptExecution::Completed {
            completed_units: 0,
            step_hashes: Vec::new(),
        });
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
        return Ok(DreamerAttemptExecution::Completed {
            completed_units: 0,
            step_hashes: Vec::new(),
        });
    }
    let (request, step_hash, craft) = dream_request(ctx, attempt_id, resident_id, &model, &cut)?;
    // The call sends under the rows its cut and craft were read from.
    let rows = cut.source_rows().map(|mut rows| {
        rows.extend(craft);
        rows
    });
    let backend = CallBackend::new(model.backend, model.sourced, rows);
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
    let response = match call_as_step_checked(
        &step_ctx,
        backend.get(),
        model.guard,
        request,
        &reply::check_diary_reply,
    )
    .await
    {
        Ok(StepOutcome::Finished { response, .. }) => {
            charges.record_terminal_metered(ctx, attempt_id, step_hash, &response.usage)?;
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
        // An empty entry the check refused was paid and never memoized: it
        // is asked again after its retry delay (FIX 7431).
        Err(DurableStepError::SpentSchemaValidation { usage, errors, .. }) => {
            charges.record_usage(&usage);
            return Ok(charges.park_for(&errors.join("; "), DreamerParkCause::Retry));
        }
        Err(DurableStepError::Engine(error)) => return Err(error),
        // A failed call's paid usage has no terminal step: the park carries
        // it with the tally (FIX 11554). A tally park, not a handover, as at
        // the commit below: free-time runs meter their line.
        Err(other) => {
            if let DurableStepError::SpentLlm { usage, .. } = &other {
                charges.record_usage(usage);
            }
            return Ok(charges.park_for(&other.to_string(), DreamerParkCause::of_step(&other)));
        }
    };
    if ctx.deadline.expired() {
        return Ok(charges.checkpoint());
    }
    let (entry, craft) = match reply::diary_entry(&response) {
        Ok(read) => read,
        // Only a memo stored before the check can hold no entry: it goes,
        // and the Retry asks again (FIX 7431, OF-193a).
        Err(reason) => return charges.park_refused_reply(ctx.vault, attempt_id, step_hash, reason),
    };
    let now = ctx.now_ms / 1_000;
    // The entry, every part of it, its craft notes, its landing marker and
    // the progress it read commit in one write: a crash between them neither
    // drops the progress nor lands the entry twice.
    // A tally park, not a handover: this same function dreams free-time
    // items whose run line the driver meters (FIX 4453), so handing the
    // tally over would charge metered spend twice.
    if let Err(error) = commit_dream(
        ctx,
        attempt_id,
        resident,
        resident_id,
        DreamWrite {
            entry: &entry,
            craft: &craft,
            free_time: &free_time,
        },
        &cut,
        now,
    ) {
        return Ok(charges.park_on_error(&error));
    }
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
        step_hashes: charges.step_hashes.clone(),
    })
}
