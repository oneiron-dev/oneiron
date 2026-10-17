//! The compaction host in the executor (agent-runtime-v1 §d7).
//!
//! In first-party code mode Oneiron compacts the run's own window. Each step
//! boundary feeds the assembled request's size to the run's
//! [`CompactionDriver`]; a crossing snapshots the steps up to the watermark
//! and hands them to the backend OFF the step loop, so the run keeps working.
//! A finished pass must clear the six-check gate before its summary replaces
//! those steps, and the swap lands as an epoch SUMMARY bound to the run's
//! replay. A run whose window fills with no accepted swap parks with the
//! typed reason instead of truncating.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, TryRecvError, channel};
use std::time::Instant;

use crate::code_run::{CodeRunBridgeCall, CodeRunHistoryTurn};
use crate::compaction::{
    CompactHooks, CompactionBackend, CompactionCheck, CompactionDirective, CompactionDriver,
    CompactionGateFailure, CompactionGatePolicy, CompactionOff, CompactionRefusal,
    CompactionRequest, CompactionSuppression, CompactionWatermark, CompactionWindowMessage,
    EpochPlacement, FoldLedger, GatedCompaction, escape_compacted_text, gate_compaction,
};
use crate::entity_id::EntityId;
use crate::tokenizer::count_context_pack_tokens;
use crate::{ContentPart, LlmRequest, WriteActor};

/// Runs one background pass where the host chooses: a thread, a blocking
/// pool. The executor never spawns one itself.
pub trait CompactionSpawn: Send + Sync {
    fn spawn(&self, pass: Box<dyn FnOnce() + Send + 'static>);
}

/// One run's compaction state, kept by the HOST across `run` calls: the
/// single flight, the margin law and the last outcome outlive one call.
pub struct RunCompaction {
    seat: Seat,
    report: CompactionReport,
}

enum Seat {
    Off,
    Live(Box<LiveSeat>),
}

struct LiveSeat {
    driver: CompactionDriver,
    policy: CompactionGatePolicy,
    byline: WriteActor,
    placement: EpochPlacement,
    hot_steps: u64,
    spawn: Arc<dyn CompactionSpawn>,
    flight: Option<Receiver<FlightOutcome>>,
    /// The in-flight epoch pass's `host.compact` chain, for its post-hooks
    /// once the keyframe lands.
    hooks: CompactHooks,
    /// Set for the rest of one `run` call when its pass ended without a swap.
    held: Option<CompactionSuppression>,
    last_feed: Option<(Instant, u64)>,
    /// The run writes through a room it is bound to on a recording route:
    /// an off-record room's overlay, or a room on record at entry, under its
    /// saver. Its epochs land along that same route.
    session_bound: bool,
}

enum PassOutcome {
    /// Boxed: it carries the whole sealed request.
    Accepted(Box<GatedCompaction>),
    Rejected(CompactionGateFailure),
    Refused(CompactionRefusal),
}

/// What one breakpoint sends to the backend in one flight: the next epoch's
/// window, when one is due, and every fold mark it applies (ARCH-0067 §2.2).
#[derive(Default)]
pub(super) struct Flight {
    pub(super) epoch: Option<CompactionRequest>,
    pub(super) folds: Vec<FoldJob>,
    /// The epoch pass's `host.compact` chain past its pre-hooks.
    pub(super) hooks: CompactHooks,
}

/// One mark of a batch, sealed: its request, and what its stub lists beside
/// the summary.
pub(super) struct FoldJob {
    pub(super) run_id: EntityId,
    pub(super) fold: u64,
    pub(super) from: u64,
    pub(super) through: u64,
    pub(super) request: CompactionRequest,
    /// The ids the span's turns name.
    pub(super) ids: Vec<String>,
    /// A handle to each step's output and every stored result the span names.
    pub(super) handles: Vec<String>,
}

/// What a flight answered.
struct FlightOutcome {
    epoch: Option<PassOutcome>,
    folds: Vec<(FoldJob, PassOutcome)>,
}

/// A landed flight: the epoch pass, if it ran one, and each fold of its
/// batch, accepted or with why not.
pub(super) struct FinishedFlight {
    pub(super) epoch: Option<Result<GatedCompaction, CompactionSuppression>>,
    pub(super) folds: Vec<(FoldJob, Result<GatedCompaction, String>)>,
    /// The epoch pass's `host.compact` chain, for its post-hooks.
    pub(super) hooks: CompactHooks,
}

/// What a caller can know about a run's compaction after a call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompactionReport {
    /// Tokens of the last assembled request.
    pub used_tokens: u64,
    /// The soft threshold that starts a pass.
    pub compact_at: u64,
    /// The window budget: the end of the headroom band.
    pub window_tokens: u64,
    pub in_flight: bool,
    /// The epoch the last swap landed, and the steps it covers.
    pub last_swap: Option<(u64, u64, u64)>,
    /// Why compaction did not run, typed.
    pub suppressed: Option<CompactionSuppression>,
}

/// Why a run parked at its window budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowFullReason {
    /// A pass is running; the same run continues once it lands.
    InFlight,
    /// No pass can run now, for this typed reason.
    Suppressed(CompactionSuppression),
    /// Every step outside the hot window is already compacted.
    NothingToCompact,
}

impl RunCompaction {
    /// A run whose compaction is off, saying why. It never calls a model and
    /// never parks.
    #[must_use]
    pub fn off(why: CompactionOff) -> Self {
        Self {
            seat: Seat::Off,
            report: CompactionReport {
                suppressed: Some(CompactionSuppression::Sticky { why }),
                ..CompactionReport::default()
            },
        }
    }

    /// A live seat: `driver` from the run's profile, the gate `policy`, the
    /// byline its epoch summaries carry, the newest `hot_steps` steps that
    /// never compact, and where passes run.
    #[must_use]
    pub fn live(
        driver: CompactionDriver,
        policy: CompactionGatePolicy,
        byline: WriteActor,
        hot_steps: u64,
        spawn: Arc<dyn CompactionSpawn>,
    ) -> Self {
        let report = CompactionReport {
            compact_at: driver.compact_at(),
            window_tokens: driver.window_token_budget(),
            ..CompactionReport::default()
        };
        Self {
            seat: Seat::Live(Box::new(LiveSeat {
                driver,
                policy,
                byline,
                placement: EpochPlacement::default(),
                hot_steps,
                spawn,
                flight: None,
                hooks: CompactHooks::default(),
                held: None,
                last_feed: None,
                session_bound: false,
            })),
            report,
        }
    }

    #[must_use]
    pub const fn report(&self) -> &CompactionReport {
        &self.report
    }

    /// Whether a backend can fold this run's log.
    pub(super) const fn is_live(&self) -> bool {
        matches!(self.seat, Seat::Live(_))
    }

    /// The agent profile's output decay (Docs Q13, agent-runtime-v1 #d7),
    /// when the seat is live and its profile names one.
    pub(super) fn output_decay(&self) -> Option<crate::compaction::output::OutputDecayPolicy> {
        match &self.seat {
            Seat::Live(seat) => seat.driver.memory_profile().output_decay,
            Seat::Off => None,
        }
    }

    /// The run credential's world and facet: its epoch summaries are born
    /// there, as its other records are. `None` (a vault-wide run) is base
    /// reality and the vault's default facet.
    pub fn place(&mut self, world: Option<EntityId>, facet: Option<EntityId>) {
        if let Seat::Live(seat) = &mut self.seat {
            seat.placement = EpochPlacement { world, facet };
        }
    }

    /// Binds the seat to the room a session-bound run writes along `target`,
    /// the route it captured at entry. An off-record room's run compacts into
    /// the room's overlay (agent-runtime-v1 §d7); a room already on record at
    /// entry compacts into base under its saver, as its other writes land
    /// (Docs Q17). An anonymous room keeps nothing to land a summary in, so it
    /// stays raw.
    pub(super) fn bind_room(&mut self, target: crate::session_overlay::RouteTarget) {
        use crate::session_overlay::RouteTarget;
        match target {
            RouteTarget::Overlay | RouteTarget::Base => {
                if let Seat::Live(seat) = &mut self.seat {
                    seat.session_bound = true;
                }
            }
            RouteTarget::Discard => {
                *self = Self::off(CompactionOff::OffRecordRun);
            }
        }
    }

    /// A new `run` call is a new turn: a turn-scoped hold ends. A run off
    /// canonical storage compacts only when [`Self::bind_room`] bound it to
    /// its room's recording route.
    pub(super) fn begin_turn(&mut self, on_record: bool) {
        if !on_record && !matches!(&self.seat, Seat::Live(seat) if seat.session_bound) {
            *self = Self::off(CompactionOff::OffRecordRun);
            return;
        }
        if let Seat::Live(seat) = &mut self.seat
            && matches!(seat.held, Some(CompactionSuppression::TurnScoped { .. }))
        {
            seat.held = None;
            self.report.suppressed = None;
        }
    }

    /// Takes a finished flight, if one is ready, without waiting.
    pub(super) fn take_finished(&mut self) -> Option<FinishedFlight> {
        let Seat::Live(seat) = &mut self.seat else {
            return None;
        };
        let outcome = match seat.flight.as_ref()?.try_recv() {
            Ok(outcome) => outcome,
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => FlightOutcome {
                epoch: Some(PassOutcome::Refused(CompactionRefusal {
                    suppression: CompactionSuppression::TurnScoped { check: None },
                    detail: "the compaction pass ended without an answer".to_owned(),
                })),
                folds: Vec::new(),
            },
        };
        seat.flight = None;
        let hooks = std::mem::take(&mut seat.hooks);
        self.report.in_flight = false;
        let epoch = outcome.epoch.map(|outcome| match outcome {
            PassOutcome::Accepted(gated) => Ok(*gated),
            PassOutcome::Rejected(failure) => {
                tracing::warn!(%failure, "a compaction pass failed the pre-swap gate on every try");
                Err(CompactionSuppression::TurnScoped {
                    check: Some(failure.check),
                })
            }
            PassOutcome::Refused(refusal) => {
                // The detail can quote a provider's error body: never logged.
                tracing::warn!(
                    reason = refusal.suppression.as_str(),
                    "the compaction backend refused a pass"
                );
                Err(refusal.suppression)
            }
        });
        // A failed fold keeps its mark, saying why; the detail of a refusal
        // can quote a provider's error body, so only its reason is kept.
        let folds = outcome
            .folds
            .into_iter()
            .map(|(job, outcome)| {
                let answer = match outcome {
                    PassOutcome::Accepted(gated) => Ok(*gated),
                    PassOutcome::Rejected(failure) => Err(format!(
                        "its summary failed the {} check",
                        failure.check.as_str()
                    )),
                    PassOutcome::Refused(refusal) => Err(format!(
                        "the compaction backend refused it ({})",
                        refusal.suppression.as_str()
                    )),
                };
                (job, answer)
            })
            .collect();
        Some(FinishedFlight {
            epoch,
            folds,
            hooks,
        })
    }

    /// The pass did not swap: the run keeps its raw window, and this reason
    /// holds for the rest of the turn (a sticky one for the run's life).
    pub(super) fn hold(&mut self, suppression: CompactionSuppression) {
        if let Seat::Live(seat) = &mut self.seat {
            seat.driver.abandon();
            seat.held = Some(suppression);
        }
        self.report.suppressed = Some(suppression);
    }

    pub(super) fn swapped(&mut self, epoch: u64, first: u64, last: u64) {
        self.report.last_swap = Some((epoch, first, last));
        self.report.suppressed = None;
    }

    /// The live driver, byline and placement, for the swap.
    pub(super) fn swap_seat(
        &mut self,
    ) -> Option<(&mut CompactionDriver, WriteActor, EpochPlacement)> {
        match &mut self.seat {
            Seat::Live(seat) => Some((&mut seat.driver, seat.byline, seat.placement)),
            Seat::Off => None,
        }
    }

    /// Feeds one assembled request's size. At a breakpoint (a crossing, or
    /// the agent's `self.compact` ask), `build` seals the flight: the next
    /// epoch's snapshot (steps `start..=watermark`) when one is due, and
    /// every fold mark that applies (`marks`), all in one background flight.
    /// Returns why the run must park, when its window is full.
    pub(super) fn feed(
        &mut self,
        used_tokens: u64,
        completed_steps: u64,
        asked: bool,
        marks: bool,
        build: impl FnOnce(&mut CompactionDriver, Option<u64>) -> super::EngineExecutorResult<Flight>,
    ) -> Option<WindowFullReason> {
        self.report.used_tokens = used_tokens;
        let Seat::Live(seat) = &mut self.seat else {
            return None;
        };
        let now = Instant::now();
        if let Some((at, tokens)) = seat.last_feed {
            let seconds = now.duration_since(at).as_secs_f64();
            if seconds > 0.0 && used_tokens >= tokens {
                seat.driver
                    .observe_velocity((used_tokens - tokens) as f64 / seconds);
            }
        }
        seat.last_feed = Some((now, used_tokens));
        self.report.compact_at = seat.driver.compact_at();
        let crossing = used_tokens >= seat.driver.compact_at();
        if seat.flight.is_none() && seat.held.is_none() && (asked || crossing) {
            // The agent's breakpoint keeps the crossing's watermark law: the
            // hot steps stay raw, and the watermark must advance.
            let epoch = completed_steps
                .checked_sub(seat.hot_steps.saturating_add(1))
                .filter(|watermark| {
                    let position = CompactionWatermark {
                        learned_at: 0,
                        turn_id: None,
                        turn: Some(*watermark),
                    };
                    let directive = if asked {
                        seat.driver.begin_positioned(position)
                    } else {
                        seat.driver.observe_positioned(used_tokens, position)
                    };
                    matches!(directive, CompactionDirective::Begin { .. })
                });
            if epoch.is_some() || asked || marks {
                match build(&mut seat.driver, epoch) {
                    Ok(Flight {
                        epoch: request,
                        folds,
                        hooks,
                    }) => {
                        if epoch.is_some() && request.is_none() {
                            seat.driver.abandon();
                        }
                        if request.is_some() || !folds.is_empty() {
                            let backend = Arc::clone(seat.driver.backend());
                            let policy = seat.policy;
                            let (sender, receiver) = channel();
                            seat.spawn.spawn(Box::new(move || {
                                let epoch = request
                                    .as_ref()
                                    .map(|request| run_pass(&*backend, request, &policy));
                                let folds = folds
                                    .into_iter()
                                    .map(|job| {
                                        let outcome = run_pass(&*backend, &job.request, &policy);
                                        (job, outcome)
                                    })
                                    .collect();
                                let _ = sender.send(FlightOutcome { epoch, folds });
                            }));
                            seat.flight = Some(receiver);
                            seat.hooks = hooks;
                            self.report.in_flight = true;
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            variant = error.variant(),
                            kind = ?error.engine_kind(),
                            "a compaction window could not be sealed"
                        );
                        seat.driver.abandon();
                        let held = CompactionSuppression::TurnScoped { check: None };
                        seat.held = Some(held);
                        self.report.suppressed = Some(held);
                    }
                }
            }
        }
        if used_tokens < seat.driver.window_token_budget() {
            return None;
        }
        Some(if seat.flight.is_some() {
            WindowFullReason::InFlight
        } else if let Some(held) = seat.held {
            WindowFullReason::Suppressed(held)
        } else {
            WindowFullReason::NothingToCompact
        })
    }
}

/// Up to `policy.tries` tries; each retry names the check the last failed.
fn run_pass(
    backend: &dyn CompactionBackend,
    request: &CompactionRequest,
    policy: &CompactionGatePolicy,
) -> PassOutcome {
    let mut retry: Option<CompactionCheck> = None;
    let mut last = None;
    for _ in 0..policy.tries.max(1) {
        let product = match backend.compact(request, retry) {
            Ok(product) => product,
            Err(refusal) => return PassOutcome::Refused(refusal),
        };
        match gate_compaction(request, &product, policy) {
            Ok(gated) => return PassOutcome::Accepted(Box::new(gated)),
            Err(failure) => {
                retry = Some(failure.check);
                last = Some(failure);
            }
        }
    }
    match last {
        Some(failure) => PassOutcome::Rejected(failure),
        None => PassOutcome::Refused(CompactionRefusal {
            suppression: CompactionSuppression::TurnScoped { check: None },
            detail: "the compaction pass made no try".to_owned(),
        }),
    }
}

/// Every token the model is sent, by the context-pack tokenizer.
pub(super) fn request_tokens(request: &LlmRequest) -> u64 {
    request
        .messages
        .iter()
        .flat_map(|message| &message.content)
        .map(|part| match part {
            ContentPart::Text { text } => count_context_pack_tokens(text) as u64,
            _ => 0,
        })
        .sum()
}

/// One step as the backend reads it: its program and its whole console.
pub(super) fn window_message(
    message_id: EntityId,
    turn_id: EntityId,
    seq: u64,
    code: String,
    console: String,
) -> CompactionWindowMessage {
    let turn = CodeRunHistoryTurn { code, console };
    let content = format!("{}\n{}", turn.assistant_exec(), turn.user_console(seq));
    CompactionWindowMessage {
        message_id,
        turn_id,
        tokens: count_context_pack_tokens(&content) as u64,
        content,
        turn: seq,
    }
}

/// Every record whose words can reach a sealed window: each entity `calls`
/// returned (the run's calls since its newest epoch, which stands for the
/// rest), and `host`, the records the host itself put into the run's words
/// (its speech, the epoch its requests rendered). A superset of what any
/// step could have printed, because the guest keeps state across steps and
/// no step boundary is stored with its calls. An id that never existed is no
/// source. A deleted record stays a source, its shell or, once purged, its
/// tombstone, so a summary written after the deletion is born withdrawn and
/// the run's later seals still advance: a purged newest epoch, which stands
/// for every call before it, withdraws each epoch after it rather than
/// parking the run.
pub(super) fn served_sources(
    dbs: &impl crate::store::ManifestDbs,
    rtxn: &heed::RoTxn<'_>,
    calls: &[CodeRunBridgeCall],
    host: impl IntoIterator<Item = EntityId>,
) -> crate::Result<Vec<EntityId>> {
    let mut found: std::collections::BTreeSet<EntityId> = host.into_iter().collect();
    for call in calls {
        collect_ids(&call.outcome, &mut found);
    }
    let mut sources = Vec::new();
    for id in found {
        if crate::ports::EntityStoreRead::port_entity_record(dbs, rtxn, &id)?.is_some()
            || crate::ports::TombstoneStoreRead::port_deletion_state(dbs, rtxn, &id)?.deleted
        {
            sources.push(id);
        }
    }
    Ok(sources)
}

fn collect_ids(value: &rmpv::Value, found: &mut std::collections::BTreeSet<EntityId>) {
    match value {
        rmpv::Value::Binary(bytes) => {
            if let Ok(bytes) = <[u8; 16]>::try_from(bytes.as_slice())
                && let Ok(id) = EntityId::from_bytes(bytes)
            {
                found.insert(id);
            }
        }
        rmpv::Value::String(text) => {
            if let Some(text) = text.as_str() {
                hex_ids(text, found);
            }
        }
        rmpv::Value::Array(items) => items.iter().for_each(|item| collect_ids(item, found)),
        rmpv::Value::Map(entries) => entries.iter().for_each(|(key, item)| {
            collect_ids(key, found);
            collect_ids(item, found);
        }),
        _ => {}
    }
}

/// Every maximal run of exactly 32 lowercase hex digits in `text`.
fn hex_ids(text: &str, found: &mut std::collections::BTreeSet<EntityId>) {
    let bytes = text.as_bytes();
    let hex = |byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte);
    let mut start = 0;
    while start < bytes.len() {
        if !hex(bytes[start]) {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < bytes.len() && hex(bytes[end]) {
            end += 1;
        }
        if end - start == 32
            && let Ok(id) = EntityId::from_hex(&text[start..end])
        {
            found.insert(id);
        }
        start = end;
    }
}

/// The window identity of one step: stable per (run, step), never stored.
pub(super) fn step_message_id(run_id: EntityId, seq: u64) -> EntityId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron:executor-compaction-step:v1");
    hasher.update(run_id.as_bytes());
    hasher.update(&seq.to_be_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    loop {
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return id;
        }
        bytes[0] ^= 0x42;
    }
}

/// The engine-authored first words of a failed step's console.
pub(super) const FAILED_STEP_PREFIXES: [&str; 3] = [
    "Runtime error after host bridge calls: ",
    "Host bridge call failed: ",
    "Runtime output recording failed after host bridge calls: ",
];

/// A failed step's first console line, whole and verbatim from `content`:
/// failures are never compacted away (agent-runtime-v1 §d7). A pin is never
/// shortened; a window whose pins do not fit the summary is cut instead.
pub(super) fn failure_pin(content: &str) -> Option<String> {
    content
        .lines()
        .find(|line| {
            FAILED_STEP_PREFIXES
                .iter()
                .any(|prefix| line.starts_with(prefix))
        })
        .map(str::to_owned)
}

/// The failure line of each step in `window`, in order: a line several
/// steps fail with is one pin, kept once.
pub(super) fn window_pins(window: &[crate::compaction::CompactionWindowMessage]) -> Vec<String> {
    let mut pins = Vec::new();
    for pin in window
        .iter()
        .filter_map(|message| failure_pin(&message.content))
    {
        if !pins.contains(&pin) {
            pins.push(pin);
        }
    }
    pins
}

/// Docs Q13 (agent-runtime-v1 #d7 verbatim pins): adds the agent profile's
/// literal pins that occur in `window`, after its failure pins, each once.
/// A profile pin is kept only while `fits` still holds with it, so it never
/// displaces a failure pin or cuts the window; the failure pins stay the
/// mandatory ones.
pub(super) fn add_profile_pins(
    pins: &mut Vec<String>,
    window: &[crate::compaction::CompactionWindowMessage],
    literals: &[String],
    fits: impl Fn(&[String]) -> bool,
) {
    for literal in literals {
        if pins.contains(literal)
            || !window
                .iter()
                .any(|message| message.content.contains(literal.as_str()))
        {
            continue;
        }
        pins.push(literal.clone());
        if !fits(pins) {
            pins.pop();
        }
    }
}

/// The bridge positions `calls` spoke at: each call that emitted a bubble.
/// A position no call spoke at names none of the run's records, whatever
/// sits at its id. The trailing fallback speaks only once the run completes,
/// after its last window. A blocked report's receipt is in its call's outcome.
pub(super) fn speech_orders(calls: &[CodeRunBridgeCall]) -> impl Iterator<Item = u32> + '_ {
    calls
        .iter()
        .filter_map(CodeRunBridgeCall::emitted_speech_order)
}

/// One epoch's steps as the model reads them after a swap: the accepted
/// summary (none once it is withdrawn) and a handle to every original
/// output, so nothing a reader may still need leaves reach.
pub(super) fn compacted_frame(
    epoch: u64,
    first: u64,
    last: u64,
    text: Option<&str>,
    handles: &[String],
) -> String {
    // The verb catalog's revision is restated after compaction (EIRI-ARCH-0002).
    let catalog = crate::task_verb::sdk::code_mode_catalog_fragment().revision;
    let mut frame =
        format!("<compacted epoch=\"{epoch}\" steps=\"{first}-{last}\" catalog=\"{catalog}\">\n");
    if let Some(text) = text {
        frame.push_str(&escape_compacted_text(text));
        frame.push('\n');
    }
    for handle in handles {
        frame.push_str(handle);
        frame.push('\n');
    }
    frame.push_str("</compacted>");
    frame
}

/// What a request renders in place of a run's raw steps: its swapped
/// epochs with their summaries' prose, and its fold ledger.
pub(super) struct RunFrames {
    pub(super) epochs: Vec<(crate::code_run::CodeRunCompactionCoverage, Option<String>)>,
    pub(super) folds: FoldLedger,
}

impl RunFrames {
    /// Whether nothing is compacted, folded, marked or unfolded.
    pub(super) fn is_empty(&self) -> bool {
        self.epochs.is_empty() && self.folds.is_empty()
    }

    /// Whether the place just before step `seq` lies inside one compacted or
    /// folded span: an unfold appended there went with the span.
    pub(super) fn hides(&self, run_id: EntityId, seq: u64) -> bool {
        seq > 0
            && (self
                .epochs
                .iter()
                .any(|(row, _)| row.covers(run_id, seq) && row.covers(run_id, seq - 1))
                || self.folds.covering(seq).is_some_and(|fold| fold.from < seq))
    }
}

/// The model-facing message for step `seq` when a swapped epoch or a fold
/// covers it: `Some(Some(frame))` at the span's first step, `Some(None)` for
/// its other steps, `None` when the step stands raw. An epoch comes first; a
/// fold whose head an epoch covers shows its stub at its first step past it.
pub(super) fn epoch_frame(
    frames: &RunFrames,
    run_id: EntityId,
    seq: usize,
    views: &[crate::compaction::output::OutputContextView],
) -> super::EngineExecutorResult<Option<Option<crate::LlmMessage>>> {
    let epochs = &frames.epochs;
    let Some((row, text)) = epochs
        .iter()
        .find(|(row, _)| row.covers(run_id, seq as u64))
    else {
        let Some(fold) = frames.folds.covering(seq as u64) else {
            return Ok(None);
        };
        let head = (fold.from..=fold.through)
            .find(|step| !epochs.iter().any(|(row, _)| row.covers(run_id, *step)))
            .unwrap_or(fold.from);
        if seq as u64 != head {
            return Ok(Some(None));
        }
        return Ok(Some(Some(crate::LlmMessage {
            role: crate::LlmMessageRole::User,
            content: vec![ContentPart::Text { text: fold.stub() }],
        })));
    };
    if seq as u64 != row.first() {
        return Ok(Some(None));
    }
    let mut handles = Vec::new();
    for covered in row.first()..=row.last() {
        let Some(view) = usize::try_from(covered)
            .ok()
            .and_then(|index| views.get(index))
        else {
            continue;
        };
        handles.push(serde_json::to_string(&serde_json::json!({
            "step": covered,
            "sandbox.fs.read_file": super::store::recoverable_chunk_path(covered, view.source, 0),
            "byte_len": view.source.byte_len,
            "max_chunk_bytes": super::store::RECOVERABLE_OUTPUT_CHUNK_BYTES,
        }))?);
    }
    Ok(Some(Some(crate::LlmMessage {
        role: crate::LlmMessageRole::User,
        content: vec![ContentPart::Text {
            text: compacted_frame(
                row.epoch(),
                row.first(),
                row.last(),
                text.as_deref(),
                &handles,
            ),
        }],
    })))
}

/// Every entity id the window's text names, in order.
pub(super) fn span_ids(window: &[CompactionWindowMessage]) -> Vec<String> {
    let mut found = std::collections::BTreeSet::new();
    for message in window {
        hex_ids(&message.content, &mut found);
    }
    found.iter().map(EntityId::to_hex).collect()
}

/// Every stored result's read path `text` names.
pub(super) fn result_reads(text: &str, found: &mut std::collections::BTreeSet<String>) {
    let mut rest = text;
    while let Some(at) = rest.find(super::store::RESULT_READ_ROOT) {
        let tail = &rest[at..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || "/._-".contains(c)))
            .unwrap_or(tail.len());
        found.insert(tail[..end].to_owned());
        rest = &tail[end..];
    }
}

/// The request identity of one fold's pass: stable per (run, fold).
pub(super) fn fold_request_id(run_id: EntityId, fold: u64) -> EntityId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron:executor-fold-request:v1");
    hasher.update(run_id.as_bytes());
    hasher.update(&fold.to_be_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    loop {
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return id;
        }
        bytes[0] ^= 0x42;
    }
}
