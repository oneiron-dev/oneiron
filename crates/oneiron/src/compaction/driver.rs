//! RT-05 in-engine compaction backend, margin law, and single-flight driver.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use crate::agent_def::{CompactionOwnership, MemoryProfile};
use crate::context_pack::SerializedContextPack;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

use super::epoch::{
    mint_epoch_summary, prior_epoch_in_txn, validate_epoch_boundary, validate_window_span,
};

/// Registered class of a compaction backend.
///
/// The ladder has exactly two rungs because the owner ruling has exactly two:
/// compaction is cheap, never frontier. This is a REGISTRATION declaration,
/// not an inference from a tier string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompactionTierClass {
    /// The only admissible class — the cheap-model tier a compaction backend
    /// is allowed to be.
    Cheap,
    /// Frontier tiers are banned as compaction backends and are refused at
    /// registration, so one is never present to resolve.
    Frontier,
}

/// A host-registered context-window compactor.
///
/// Cheap by design: [`CompactionBackendRegistry::register`] refuses a
/// frontier-tier implementation before insertion, so the ban is structural
/// rather than a post-hoc audit.
pub trait CompactionBackend: Send + Sync {
    /// The registry key a profile names in `memory_profile.compaction_backend`.
    fn backend_key(&self) -> &str;
    /// The tier class this implementation declares at registration.
    fn tier_class(&self) -> CompactionTierClass;
    /// Compacts one window span into summary text.
    ///
    /// Pure with respect to the vault: the backend sees rendered message
    /// content and a token ceiling, never storage.
    fn compact(&self, request: &CompactionRequest) -> Result<CompactionProduct>;
}

/// One message-log row the host hands the backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionWindowMessage {
    pub message_id: EntityId,
    /// The covered TURN entity — the `DerivedFrom` target and the H-S3 probe
    /// subject.
    pub turn_id: EntityId,
    /// Rendered MESSAGE content: the material the backend summarizes.
    pub content: String,
    /// The turn NUMBER this row belongs to, in the session's own ordering.
    pub turn: u64,
    pub tokens: u64,
}

/// The snapshot point a compaction runs against.
///
/// This is the Dreamer's compound consolidation position (ONE-1793 v2), not a
/// bare second: `learned_at` alone cannot separate two turns sharing one
/// second, so the exact temporal-index key rides alongside it. Epoch NUMBER is
/// deliberately absent — it is minted only inside
/// [`CompactionDriver::integrate`]'s write transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactionWatermark {
    /// The Dreamer's `last_learned_at` at trigger time.
    pub learned_at: u64,
    /// The Dreamer's `last_turn_id`: `None` is the end-of-second boundary,
    /// `Some` the exact temporal-index key.
    pub turn_id: Option<EntityId>,
}

/// The compaction job the driver hands the host to run on ITS runtime.
///
/// Created only by [`CompactionDriver::request_for`]. Hosts may read, move or
/// clone it, but integration requires the original fields and job identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionRequest {
    /// Unique to this issued job, including across abandoned or replaced drivers.
    request_id: EntityId,
    /// The SESSION whose window is being compacted — the same `session_ref`
    /// vocabulary the admission door above uses.
    pub session_ref: EntityId,
    /// Ordered message-log span between the last epoch boundary and the
    /// watermark, assembled by the host: the engine never holds the log.
    pub window: Vec<CompactionWindowMessage>,
    /// Token ceiling for the produced summary text: the rounded profile
    /// summary allocation, with a minimum of one token.
    pub summary_token_budget: u64,
    /// First turn number this epoch covers, read DURABLY from the session's
    /// prior epoch summaries: prior `turn_end + 1`, or the window's first turn
    /// for the session's first epoch.
    pub turn_start: u64,
    /// The recorded snapshot point.
    pub watermark: CompactionWatermark,
}

/// What a backend produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionProduct {
    pub summary_text: String,
    /// Measured wall time of THIS compact call — the latency half of the
    /// margin law.
    pub latency: Duration,
}

/// The host-constructed backend registry.
///
/// An explicit value the host builds and passes, deliberately NOT a [`Vault`]
/// field: registration is host policy, and the vault holds no policy.
#[derive(Default)]
pub struct CompactionBackendRegistry {
    backends: BTreeMap<String, Arc<dyn CompactionBackend>>,
}

impl std::fmt::Debug for CompactionBackendRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompactionBackendRegistry")
            .field("backend_keys", &self.backends.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl CompactionBackendRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one backend under its own [`CompactionBackend::backend_key`].
    ///
    /// Refuses a frontier-tier implementation. The ban is EAGER: a frontier
    /// backend never enters the map, so [`Self::resolve`] cannot hand one out
    /// and no call site needs a second check.
    pub fn register(&mut self, backend: Arc<dyn CompactionBackend>) -> Result<()> {
        if backend.tier_class() != CompactionTierClass::Cheap {
            return Err(Error::InvariantViolation(
                "compaction backend declares a frontier tier and is refused",
            ));
        }
        let key = backend.backend_key().to_owned();
        if key.trim().is_empty() {
            return Err(Error::InvariantViolation("backend key must not be blank"));
        }
        self.backends.insert(key, backend);
        Ok(())
    }

    /// Resolves the backend a profile names.
    ///
    /// An unregistered key fails typed rather than falling back. `byoa`
    /// profiles never reach here — [`CompactionDriver::for_profile`] answers
    /// `Ok(None)` before resolution.
    pub fn resolve(&self, profile: &MemoryProfile) -> Result<Arc<dyn CompactionBackend>> {
        self.backends
            .get(profile.compaction_backend.as_str())
            .map(Arc::clone)
            .ok_or(Error::InvariantViolation(
                "compaction backend key is not registered",
            ))
    }

    /// The registered tier class of a registered backend, or `None` when the
    /// key names nothing.
    ///
    /// This is the ONLY authority on "is this backend a frontier tier": a
    /// frontier answer is unreachable through a registered key, which is the
    /// ban made observable.
    #[must_use]
    pub fn tier_class_of(&self, backend_key: &str) -> Option<CompactionTierClass> {
        self.backends
            .get(backend_key)
            .map(|backend| backend.tier_class())
    }
}

/// EMA smoothing factor for both margin estimators.
///
/// It tunes how fast the estimators converge on measured reality. It is NOT
/// the margin and it is not a size: changing it changes convergence speed,
/// never the law.
const MARGIN_EMA_ALPHA: f64 = 0.3;

/// Share of the window budget an epoch summary may occupy when the profile
/// carries no `budget_split`.
///
/// Mirrors the engine's existing default summaries allocation rather than
/// minting a second policy for the same question.
const DEFAULT_SUMMARY_BUDGET_FRACTION: f64 = 0.25;

/// A floor against `margin >= budget` degeneracy — not a margin, not a knob.
const COMPACT_AT_FLOOR_FRACTION: f64 = 0.5;

/// The overflow window a session lives in while a compaction runs.
///
/// **The law (owner comment `58474826`):** `margin >= compaction-latency x
/// token-velocity`. Both factors are MEASURED exponential moving averages.
/// The only constants here are the cold-start seeds and the smoothing factor,
/// and each is displaced or bounded by real samples — there is no constant
/// margin anywhere in this type.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MarginLaw {
    latency_ema_ms: f64,
    velocity_ema_tps: f64,
    latency_samples: u32,
    velocity_samples: u32,
}

impl Default for MarginLaw {
    fn default() -> Self {
        Self::new()
    }
}

impl MarginLaw {
    /// Cold-start latency seed, in milliseconds. Displaced outright by the
    /// FIRST measured sample — it is a starting guess, not a floor.
    pub const SEED_LATENCY_MS: f64 = 30_000.0;
    /// Cold-start velocity seed, in tokens per second. Displaced outright by
    /// the first measured sample.
    pub const SEED_VELOCITY_TPS: f64 = 50.0;

    #[must_use]
    pub const fn new() -> Self {
        Self {
            latency_ema_ms: Self::SEED_LATENCY_MS,
            velocity_ema_tps: Self::SEED_VELOCITY_TPS,
            latency_samples: 0,
            velocity_samples: 0,
        }
    }

    /// Feeds one measured compaction latency.
    pub fn observe_latency(&mut self, latency: Duration) {
        let sample = latency.as_secs_f64() * 1_000.0;
        self.latency_ema_ms = blend(self.latency_ema_ms, sample, self.latency_samples);
        self.latency_samples = self.latency_samples.saturating_add(1);
    }

    /// Feeds the measured token velocity of the live session. The caller
    /// measures; the law only consumes.
    pub fn observe_velocity(&mut self, tokens_per_second: f64) {
        if !tokens_per_second.is_finite() || tokens_per_second < 0.0 {
            return;
        }
        self.velocity_ema_tps = blend(
            self.velocity_ema_tps,
            tokens_per_second,
            self.velocity_samples,
        );
        self.velocity_samples = self.velocity_samples.saturating_add(1);
    }

    /// `margin = ceil(latency_ema x velocity_ema)` — the law, nothing else.
    #[must_use]
    pub fn margin_tokens(&self) -> u64 {
        let margin = (self.latency_ema_ms / 1_000.0 * self.velocity_ema_tps).ceil();
        if margin.is_finite() && margin > 0.0 {
            margin as u64
        } else {
            0
        }
    }

    /// The latency EMA in milliseconds, rounded half-up — the exact field a
    /// [`CompactionSignal::Starvation`] reports.
    #[must_use]
    pub fn measured_latency_ms(&self) -> u64 {
        round_half_up(self.latency_ema_ms)
    }

    /// The velocity EMA in tokens per second, rounded half-up.
    #[must_use]
    pub fn measured_velocity_tps(&self) -> u64 {
        round_half_up(self.velocity_ema_tps)
    }

    fn velocity_ema_tps(&self) -> f64 {
        self.velocity_ema_tps
    }
}

/// The FIRST sample displaces the seed outright; later samples blend.
fn blend(current: f64, sample: f64, prior_samples: u32) -> f64 {
    if prior_samples == 0 {
        sample
    } else {
        MARGIN_EMA_ALPHA.mul_add(sample, (1.0 - MARGIN_EMA_ALPHA) * current)
    }
}

fn round_half_up(value: f64) -> u64 {
    let rounded = value.round();
    if rounded.is_finite() && rounded > 0.0 {
        rounded as u64
    } else {
        0
    }
}

fn ceil_non_negative(value: f64) -> u64 {
    let ceiled = value.ceil();
    if ceiled.is_finite() && ceiled > 0.0 {
        ceiled as u64
    } else {
        0
    }
}

/// What an observation tells the session to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactionDirective {
    /// The soft threshold was crossed: begin compacting the span up to
    /// `watermark` NOW, in the background, while the session keeps working.
    /// Emitted at most once per crossing.
    Begin { watermark: CompactionWatermark },
    /// Nothing to do.
    Quiet,
}

/// A typed signal the driver surfaces INSTEAD of pausing the world.
///
/// The session continues; the consumer decides what the signal means.
/// ONE-1896's landing ladder is the sibling terminal response to this same
/// threshold law — this module emits, never acts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactionSignal {
    /// Measured velocity times remaining latency will overrun the margin
    /// before the in-flight compaction can land.
    Starvation {
        deficit_tokens: u64,
        /// The [`MarginLaw`] latency EMA, half-up rounded — not
        /// `remaining_latency`.
        measured_latency_ms: u64,
        /// The [`MarginLaw`] velocity EMA, half-up rounded.
        measured_velocity_tps: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CompactionState {
    Idle,
    /// A background compaction is in flight; the session keeps working.
    Compacting {
        watermark: CompactionWatermark,
        /// Seals the issued snapshot, not the host's live message log.
        request: Option<Box<CompactionRequest>>,
    },
}

/// The pure plan a finished compaction produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapPlan {
    pub epoch: u64,
    pub summary_id: EntityId,
    /// `accumulated`, DEFINED by the host as every message-log entry after
    /// the watermark — including messages that arrived while the backend ran.
    /// The host assembles it once; `integrate` never derives a second tail.
    pub retained_tail: Vec<CompactionWindowMessage>,
}

/// One session's compaction driver.
///
/// Owned by the session/host runtime: the engine supplies the state machine
/// and the arithmetic, the host supplies the async runtime and the message
/// log. `byoa` profiles never construct one.
pub struct CompactionDriver {
    backend: Arc<dyn CompactionBackend>,
    margin: MarginLaw,
    state: CompactionState,
    /// Resolved copy of the profile that produced this driver.
    profile: MemoryProfile,
}

impl std::fmt::Debug for CompactionDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompactionDriver")
            .field("backend_key", &self.backend.backend_key())
            .field("margin", &self.margin)
            .field("state", &self.state)
            .field("profile", &self.profile)
            .finish()
    }
}

impl CompactionDriver {
    /// Constructs a driver for an `engine`-owned profile.
    ///
    /// A `byoa` profile answers `Ok(None)`: exclusion by CONSTRUCTION, not a
    /// runtime check sprinkled at call sites. With no driver there is nothing
    /// to observe, request, or integrate, so the engine cannot compact that
    /// window even by mistake.
    pub fn for_profile(
        profile: &MemoryProfile,
        registry: &CompactionBackendRegistry,
    ) -> Result<Option<Self>> {
        match profile.compaction {
            CompactionOwnership::Byoa => Ok(None),
            CompactionOwnership::Engine => Ok(Some(Self {
                backend: registry.resolve(profile)?,
                margin: MarginLaw::new(),
                state: CompactionState::Idle,
                profile: profile.clone(),
            })),
        }
    }

    /// The backend this driver resolved.
    #[must_use]
    pub fn backend(&self) -> &Arc<dyn CompactionBackend> {
        &self.backend
    }

    /// The margin law's current state — the measured EMAs, never a constant.
    #[must_use]
    pub const fn margin(&self) -> &MarginLaw {
        &self.margin
    }

    /// True while a background compaction is in flight.
    #[must_use]
    pub const fn is_compacting(&self) -> bool {
        matches!(self.state, CompactionState::Compacting { .. })
    }

    /// The soft threshold: `max(budget - margin, ceil(budget / 2))`.
    ///
    /// The floor is what keeps a degenerate `margin >= budget` from asking a
    /// session to compact at zero used tokens.
    #[must_use]
    pub fn compact_at(&self) -> u64 {
        let budget = self.profile.window_token_budget;
        let floor = ceil_non_negative(budget as f64 * COMPACT_AT_FLOOR_FRACTION);
        budget
            .saturating_sub(self.margin.margin_tokens())
            .max(floor)
    }

    /// Production wiring for measured token velocity.
    ///
    /// The driver is the entry: the [`MarginLaw`] inside it is private, so a
    /// velocity sample cannot reach the law except through a live driver.
    pub fn observe_velocity(&mut self, tokens_per_second: f64) {
        self.margin.observe_velocity(tokens_per_second);
    }

    /// The production consumer contract (ONE-1687 §8): the host applies
    /// `memory_profile(..)` at builder construction, produces a REAL
    /// [`SerializedContextPack`] through
    /// [`crate::ContextPackBuilder::run_serialized_with_stats`], and passes it
    /// here after every serialized assembly.
    ///
    /// Deliberately serialized-only: a raw `ContextPackBuilder::run()` product
    /// documents `PackTokenStats::default()`, so it cannot truthfully drive a
    /// token threshold and is not accepted.
    pub fn observe_serialized_pack(
        &mut self,
        vault: &Vault,
        pack: &SerializedContextPack,
    ) -> Result<CompactionDirective> {
        self.observe_from_context_build(vault, pack.stats.tokens.total_tokens as u64)
    }

    /// The shared integer seam behind [`Self::observe_serialized_pack`].
    pub fn observe_from_context_build(
        &mut self,
        vault: &Vault,
        used_tokens: u64,
    ) -> Result<CompactionDirective> {
        self.directive(vault, used_tokens)
    }

    /// Explicit driver-callable evaluation (host sweep, turn boundary, test
    /// driver). Same threshold, same watermark read, same state machine.
    pub fn evaluate_now(&mut self, vault: &Vault, used_tokens: u64) -> Result<CompactionDirective> {
        self.directive(vault, used_tokens)
    }

    /// ONE threshold, ONE watermark read, ONE state transition.
    ///
    /// Every observation entry funnels here, so a second crossing while a
    /// compaction is in flight is `Quiet` — not a queue. One compaction stays
    /// in flight by construction.
    fn directive(&mut self, vault: &Vault, used_tokens: u64) -> Result<CompactionDirective> {
        match self.state {
            CompactionState::Compacting { .. } => Ok(CompactionDirective::Quiet),
            CompactionState::Idle if used_tokens >= self.compact_at() => {
                let watermark = snapshot_watermark(vault)?;
                self.state = CompactionState::Compacting {
                    watermark,
                    request: None,
                };
                Ok(CompactionDirective::Begin { watermark })
            }
            CompactionState::Idle => Ok(CompactionDirective::Quiet),
        }
    }

    /// Builds the single compaction job for the in-flight crossing.
    ///
    /// A successful call seals this request. Further calls fail without
    /// replacing it. The host may clone the returned request for its runtime,
    /// but must return it unchanged to [`Self::integrate`]. Invalid windows do
    /// not consume the crossing. Distinct turn numbers must be contiguous and
    /// nondecreasing; multiple messages in the same turn are valid.
    ///
    /// Legal only in `Compacting`: outside it the recorded watermark has no
    /// referent, so the call is a typed refusal rather than a guess. The HOST
    /// supplies `window` from its own message log — the engine never holds the
    /// log — and then runs `backend.compact(&request)` on its own runtime.
    ///
    /// The span START is read DURABLY from the session's prior epoch
    /// summaries (prior `turn_end + 1`, or the window's first turn for the
    /// first epoch). Epoch NUMBER is deliberately absent from this request:
    /// it is minted only inside [`Self::integrate`]'s write transaction.
    pub fn request_for(
        &mut self,
        vault: &Vault,
        session_ref: &EntityId,
        window: Vec<CompactionWindowMessage>,
    ) -> Result<CompactionRequest> {
        let CompactionState::Compacting { watermark, request } = &self.state else {
            return Err(Error::InvariantViolation(
                "request_for is legal only while compacting",
            ));
        };
        if request.is_some() {
            return Err(Error::InvariantViolation(
                "compaction flight already has a request",
            ));
        }
        let watermark = *watermark;
        let (turn_start, _) = validate_window_span(&window)?;

        let rtxn = vault.store.env.read_txn()?;
        let prior = prior_epoch_in_txn(&vault.store, &rtxn, session_ref)?;
        validate_epoch_boundary(prior, turn_start)?;
        drop(rtxn);

        let request = CompactionRequest {
            request_id: EntityId::now(),
            session_ref: *session_ref,
            summary_token_budget: self.summary_token_budget(),
            window,
            turn_start,
            watermark,
        };
        self.state = CompactionState::Compacting {
            watermark,
            request: Some(Box::new(request.clone())),
        };
        Ok(request)
    }

    /// `budget_split.summaries * window_token_budget`, or the module's named
    /// [`DEFAULT_SUMMARY_BUDGET_FRACTION`] of it when the profile carries no
    /// split. The ceiling is at least one token, even for a zero summary share,
    /// because a successful compaction must carry nonblank prose.
    ///
    /// Half-up rounding, not `ceil`: a stored `f32` fraction of `0.4` widens
    /// to `0.4000000059…` in `f64`, and ceiling that would answer 401 tokens
    /// for a 40% share of 1000 — an arithmetic artifact, not a budget.
    fn summary_token_budget(&self) -> u64 {
        let fraction = self
            .profile
            .budget_split
            .map_or(DEFAULT_SUMMARY_BUDGET_FRACTION, |split| {
                f64::from(split.summaries)
            });
        round_half_up(self.profile.window_token_budget as f64 * fraction).max(1)
    }

    /// Whether the in-flight compaction is losing the race against the live
    /// session, and by how much.
    ///
    /// `None` in `Idle`, because with no compaction in flight
    /// `remaining_latency` has no referent. In `Compacting` a signal is
    /// raised iff either arm holds:
    ///
    /// * DEGENERACY — `margin_tokens() >= window_token_budget` with a
    ///   non-zero measured velocity: the law itself is asking for more room
    ///   than the window has.
    /// * OVERRUN — `velocity_ema x remaining_latency > headroom_tokens`: the
    ///   session will out-write the remaining compaction time.
    ///
    /// Emitting is the whole response. The session-facing API keeps accepting
    /// messages either way.
    #[must_use]
    pub fn starvation_check(
        &self,
        remaining_latency: Duration,
        headroom_tokens: u64,
    ) -> Option<CompactionSignal> {
        if !self.is_compacting() {
            return None;
        }
        let velocity = self.margin.velocity_ema_tps();
        let budget = self.profile.window_token_budget;
        let margin = self.margin.margin_tokens();
        let degenerate = margin >= budget && velocity > 0.0;
        let projected = velocity * remaining_latency.as_secs_f64();
        let overrun = projected > headroom_tokens as f64;
        if !degenerate && !overrun {
            return None;
        }
        let deficit_tokens = if overrun {
            ceil_non_negative(projected - headroom_tokens as f64)
        } else {
            margin.saturating_sub(budget)
        };
        Some(CompactionSignal::Starvation {
            deficit_tokens,
            measured_latency_ms: self.margin.measured_latency_ms(),
            measured_velocity_tps: self.margin.measured_velocity_tps(),
        })
    }

    /// Backend-failure exit.
    ///
    /// Legal only in `Compacting`; returns to `Idle` WITHOUT minting, so the
    /// next threshold crossing emits `Begin` again. The host calls it on a
    /// typed backend error.
    pub fn abandon(&mut self) {
        self.state = CompactionState::Idle;
    }

    /// Integrates a finished compaction: mints the epoch summary and returns
    /// the swap plan.
    ///
    /// THIS is the moment the epoch increments — integration, when the
    /// compaction result is used, not when the work began (owner unification
    /// line). `request` is authoritative for the covered TURN ids and the turn
    /// range; backend-returned range metadata is never accepted.
    ///
    /// One vault write transaction carries the H-S3 probe, the epoch
    /// derivation, the SUMMARY put, its pending-embedding marker and the
    /// capped `DerivedFrom` edge set. The session's message-log splice
    /// (prefix out, summary in, `accumulated` replayed on top) is the caller's
    /// in-memory step: the engine never holds the session's log.
    pub fn integrate(
        &mut self,
        vault: &Vault,
        session_ref: &EntityId,
        byline: WriteActor,
        request: &CompactionRequest,
        product: CompactionProduct,
        accumulated: &[CompactionWindowMessage],
    ) -> Result<SwapPlan> {
        let CompactionState::Compacting {
            request: active, ..
        } = &self.state
        else {
            return Err(Error::InvariantViolation(
                "integrate is legal only while compacting",
            ));
        };
        // Compare both the unique job identity and the sealed input. A stale,
        // duplicate, foreign-driver, or edited request cannot mint or clear
        // the current flight, nor feed its latency into the margin law.
        if active.as_deref() != Some(request) {
            return Err(Error::InvariantViolation(
                "compaction result does not match the active request",
            ));
        }
        let (epoch, summary_id) =
            mint_epoch_summary(vault, session_ref, byline, request, &product)?;
        self.margin.observe_latency(product.latency);
        self.state = CompactionState::Idle;
        Ok(SwapPlan {
            epoch,
            summary_id,
            retained_tail: accumulated.to_vec(),
        })
    }
}

/// Reads the trigger-time durable watermark through the Dreamer's existing
/// public surface (S-11, ONE-1793 v2).
///
/// The compound position is read whole: `last_learned_at` alone cannot
/// separate two turns sharing one second. `DreamerConsolidationScope::Micro`
/// names the Dreamer lane's OWN finest consolidation cursor — it is that
/// lane's enum variant, not a summary-tier name. Epoch summaries mint at the
/// unbounded integer `level` 0 and this module coins no tier vocabulary of
/// its own.
fn snapshot_watermark(vault: &Vault) -> Result<CompactionWatermark> {
    let watermark = crate::dreamer_consolidation::read_watermark(
        vault,
        crate::dreamer_runner::DreamerConsolidationScope::Micro,
    )?;
    Ok(CompactionWatermark {
        learned_at: watermark.last_learned_at,
        turn_id: watermark.last_turn_id,
    })
}
