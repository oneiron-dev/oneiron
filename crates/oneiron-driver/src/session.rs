//! RT-03 (ONE-1685): the driver owns the SESSION lifecycle; apps send hints.
//!
//! The engine's `session_lifecycle` module is mechanism (the canonical
//! SESSION entity plus durable clock fields); THIS module is the policy the
//! ticket pins on the driver:
//!
//! * mint on the app-open hint (a zero-turn session is valid — presence is
//!   signal),
//! * bump `last_activity` on an activity hint (turn-witness bumps ride the
//!   engine's witness transaction),
//! * set `endedAt` on the explicit-end hint OR the idle floor — first to
//!   fire — and then fire SessionEnd → Meso consolidation,
//! * HARDENING (H-S4): the idle floor is a backstop, NOT a cap — forged
//!   activity hints reset `last_activity` forever — so a hard wall-clock
//!   lifetime ceiling INDEPENDENT of hints also closes the session, and
//!   hints only enter through the typed [`HintPusher`](crate::HintPusher)
//!   producer role (an authenticated hint producer is structurally unable
//!   to forge a wake; an unauthenticated producer has no way to push at
//!   all — fail-closed).
//!
//! The SessionEnd → Meso wake is DURABLE and ATOMIC: ending a session runs
//! the production meso planning round (`read_watermark` →
//! `scan_dirty_turns` → `plan_partitions` — the exact payload and dedupe
//! shape the `ConsolidationExecutor` decodes) and hands the plans to ONE
//! engine transaction ([`Vault::end_session_with_wake`]) that re-checks the
//! session's identity and the close predicate, stamps `ended_at`, enqueues
//! the attempts and advances the watermark together. A attempt row therefore exists
//! ⟺ the end committed: the wake is never lost, never doubled, and a stale
//! closer can never end (or enqueue for) a replacement session. A sitting
//! with NO dirty turns closes with no attempt — nothing to dream about. The
//! supervisor's existing attempt-queue deadline lane surfaces the enqueued
//! attempts; no new tick authority is minted for them.

use std::collections::VecDeque;
use std::sync::Arc;

use oneiron::{
    DreamerConsolidationScope, EndedSession, EntityId, Result, SessionClosePredicate,
    SessionEndWake, SessionMintOutcome, Vault, plan_partitions, read_watermark, scan_dirty_turns,
};

use crate::tick::{NowMillis, Tick, TickSource, sleep_until_due};

/// The ticket-pinned default idle floor: 20 minutes without activity ends
/// the session. A floor, not a cap (H-S4).
pub const DEFAULT_SESSION_IDLE_FLOOR_SECS: u64 = 20 * 60;

/// Session-lifecycle facts an app may hint. Deliberately carries no session
/// id, no scope, and no trigger: the driver owns which session (at most one
/// is open per vault) and what pass, if any, results — a hint producer can
/// never shape a pass (H-S4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionHint {
    /// The app opened: mint a session (or re-signal presence on the open
    /// one). A zero-turn session is valid.
    AppOpen,
    /// User activity (typing, focus): bump `last_activity`. Never mints —
    /// presence is signaled by app-open only (fail-closed).
    Activity,
    /// The app explicitly ended the sitting: close now.
    ExplicitEnd,
}

/// Driver session policy knobs, in unix SECONDS (the engine's clock
/// convention).
///
/// There is no ceiling default on purpose: the hard lifetime ceiling is a
/// security backstop (H-S4) whose right value is host-specific, so hosts
/// must state it — a hidden default could silently be wider than the host's
/// threat model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLifecycleConfig {
    /// Idle floor: the session ends after this many seconds without
    /// activity. Defaults to [`DEFAULT_SESSION_IDLE_FLOOR_SECS`] via
    /// [`Self::with_idle_floor_default`].
    pub idle_floor_secs: u64,
    /// Hard wall-clock lifetime ceiling, measured from `started_at` and
    /// INDEPENDENT of activity hints. Must exceed the idle floor.
    pub lifetime_ceiling_secs: u64,
}

impl SessionLifecycleConfig {
    #[must_use]
    pub fn new(idle_floor_secs: u64, lifetime_ceiling_secs: u64) -> Self {
        Self {
            idle_floor_secs,
            lifetime_ceiling_secs,
        }
    }

    /// The ticket-default 20-minute idle floor with a host-chosen ceiling.
    #[must_use]
    pub fn with_idle_floor_default(lifetime_ceiling_secs: u64) -> Self {
        Self::new(DEFAULT_SESSION_IDLE_FLOOR_SECS, lifetime_ceiling_secs)
    }

    /// Rejects configs that disable either close path: a zero idle floor
    /// would end every session instantly, and a ceiling at or below the
    /// floor means the "backstop vs cap" split the hardening requires
    /// cannot exist.
    pub fn validate(&self) -> Result<()> {
        if self.idle_floor_secs == 0 {
            return Err(oneiron::Error::InvalidConfig(
                "session idle_floor_secs must be > 0".into(),
            ));
        }
        if self.lifetime_ceiling_secs <= self.idle_floor_secs {
            return Err(oneiron::Error::InvalidConfig(format!(
                "session lifetime_ceiling_secs ({}) must exceed idle_floor_secs ({}): \
                 the ceiling is the hard cap the idle floor is not",
                self.lifetime_ceiling_secs, self.idle_floor_secs
            )));
        }
        Ok(())
    }
}

/// What one applied hint did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionHintEffect {
    /// App-open minted a fresh session.
    Minted(EntityId),
    /// Activity (or app-open on an already-open session) bumped the clock.
    Bumped(EntityId),
    /// Explicit-end closed the open session (its durable meso round was
    /// enqueued atomically with the close).
    Ended(EndedSession),
    /// Nothing to do (e.g. activity or explicit-end with no open session).
    NoOp,
}

/// Driver-owned session policy over one vault: applies hints, computes the
/// idle-floor / ceiling expiry, and closes due sessions with a durable
/// SessionEnd → Meso wake.
pub struct SessionLifecycleDriver<'v> {
    vault: &'v Vault,
    config: SessionLifecycleConfig,
    now_ms: NowMillis,
}

impl<'v> SessionLifecycleDriver<'v> {
    /// Fails fast on a config that would disable a close path — same
    /// stance as [`WakeSupervisorConfig::validate`](crate::WakeSupervisorConfig::validate).
    pub fn new(
        vault: &'v Vault,
        config: SessionLifecycleConfig,
        now_ms: NowMillis,
    ) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            vault,
            config,
            now_ms,
        })
    }

    fn now_secs(&self) -> u64 {
        (self.now_ms)() / 1_000
    }

    pub(crate) fn clock(&self) -> NowMillis {
        Arc::clone(&self.now_ms)
    }

    /// Applies one session hint under driver policy.
    pub fn apply_hint(&self, hint: SessionHint) -> Result<SessionHintEffect> {
        let now = self.now_secs();
        match hint {
            SessionHint::AppOpen => match self.vault.mint_session(now)? {
                SessionMintOutcome::Minted(id) => Ok(SessionHintEffect::Minted(id)),
                // Presence re-signal on the open sitting counts as activity.
                SessionMintOutcome::AlreadyOpen(_) => Ok(self
                    .vault
                    .bump_session_activity(now)?
                    .map_or(SessionHintEffect::NoOp, SessionHintEffect::Bumped)),
            },
            SessionHint::Activity => Ok(self
                .vault
                .bump_session_activity(now)?
                .map_or(SessionHintEffect::NoOp, SessionHintEffect::Bumped)),
            SessionHint::ExplicitEnd => {
                let Some(open) = self.vault.open_session()? else {
                    return Ok(SessionHintEffect::NoOp);
                };
                Ok(self
                    .end_session(&open.session, SessionClosePredicate::Explicit)?
                    .map_or(SessionHintEffect::NoOp, SessionHintEffect::Ended))
            }
        }
    }

    /// When the open session is due to close (unix MILLISECONDS): the
    /// earlier of `last_activity + idle_floor` and `started_at + ceiling`.
    /// `None` when no session is open.
    pub fn next_expiry_ms(&self) -> Result<Option<u64>> {
        let Some(open) = self.vault.open_session()? else {
            return Ok(None);
        };
        Ok(Some(
            self.expiry_secs(open.started_at, open.last_activity)
                .saturating_mul(1_000),
        ))
    }

    fn expiry_secs(&self, started_at: u64, last_activity: u64) -> u64 {
        let idle_due = last_activity.saturating_add(self.config.idle_floor_secs);
        let ceiling_due = started_at.saturating_add(self.config.lifetime_ceiling_secs);
        idle_due.min(ceiling_due)
    }

    /// Closes the open session if its idle floor or lifetime ceiling has
    /// passed. The ceiling closes REGARDLESS of how fresh `last_activity`
    /// is (H-S4: forged hints must not hold a session open forever).
    ///
    /// The snapshot check here is only a fast path: the engine transaction
    /// re-validates identity AND the expiry predicate against the re-read
    /// record, so a bump that races this close makes it a no-op instead of
    /// ending a still-active sitting.
    pub fn close_due_session(&self) -> Result<Option<EndedSession>> {
        let Some(open) = self.vault.open_session()? else {
            return Ok(None);
        };
        if self.now_secs() < self.expiry_secs(open.started_at, open.last_activity) {
            return Ok(None);
        }
        self.end_session(
            &open.session,
            SessionClosePredicate::Expiry {
                idle_floor_secs: self.config.idle_floor_secs,
                lifetime_ceiling_secs: self.config.lifetime_ceiling_secs,
            },
        )
    }

    /// Ends session `expected` with the DURABLE SessionEnd → Meso wake in
    /// ONE engine transaction (ONE-1685 close protocol): identity re-check,
    /// in-txn predicate re-validation, `ended_at` stamp, attempt enqueue and
    /// watermark advance commit together — a attempt row exists ⟺ the end
    /// committed.
    ///
    /// The wake IS the production meso planning round: dirty turns since
    /// the Meso watermark become partition attempts with the executor-decodable
    /// payload and the production dedupe key. No dirty turns → no attempt — a
    /// zero-turn sitting has nothing to dream about.
    fn end_session(
        &self,
        expected: &EntityId,
        predicate: SessionClosePredicate,
    ) -> Result<Option<EndedSession>> {
        let scope = DreamerConsolidationScope::Meso;
        let watermark = read_watermark(self.vault, scope)?;
        let dirty = scan_dirty_turns(self.vault, scope, &watermark, usize::MAX)?;
        let advance_watermark_to = dirty.iter().map(|turn| turn.learned_at).max();
        let plans = plan_partitions(self.vault, scope, &dirty, &watermark)?;
        let wake = SessionEndWake {
            plans,
            planned_watermark: watermark.last_learned_at,
            advance_watermark_to,
        };
        self.vault
            .end_session_with_wake(expected, predicate, self.now_secs(), &wake)
    }
}

/// [`TickSource`] decorator that runs the session lifecycle on the driver's
/// tick loop — the driver stays a pure event consumer (ARCH-0026):
///
/// * BUFFERED session hints are drained and applied BEFORE the close
///   decision reads durable state (an activity hint that arrived ahead of
///   the idle deadline bumps the clock the close is about to trust), in
///   ARRIVAL order — an end-then-open burst ends one sitting and mints the
///   next; each applied hint then surfaces to the supervisor as an ordinary
///   least-privileged hint tick — never escalated by the producer;
/// * the idle-floor / ceiling expiry is a sleep armed from DURABLE session
///   state, re-read every cycle (the [`TimerTick`](crate::TimerTick)
///   pattern — no heartbeat, no poll);
/// * a close (hint or expiry) enqueues the durable meso attempts atomically
///   with the end and simply loops: the INNER source's attempt-queue deadline
///   lane surfaces them as due [`Tick::Deadline`]s, so this decorator mints
///   no wake authority of its own.
pub struct SessionTicks<'v, T> {
    inner: T,
    lifecycle: SessionLifecycleDriver<'v>,
    /// Applied-but-not-yet-surfaced session hints: each still earns its one
    /// least-privileged follow-up pass (H-S4), one tick per call.
    pending_hints: VecDeque<crate::tick::HintSignal>,
}

impl<'v, T: TickSource> SessionTicks<'v, T> {
    #[must_use]
    pub fn new(inner: T, lifecycle: SessionLifecycleDriver<'v>) -> Self {
        Self {
            inner,
            lifecycle,
            pending_hints: VecDeque::new(),
        }
    }

    /// Drains every BUFFERED session hint from the inner source and applies
    /// it, in arrival order, BEFORE any close decision reads durable state
    /// (ONE-1685). A hint whose apply CLOSED the sitting is consumed — the
    /// wakeup it earns is the meso deadline the close enqueued; every other
    /// applied hint is queued to surface as a least-privileged hint tick.
    fn drain_buffered_hints(&mut self) {
        while let Some(hint) = self.inner.take_buffered_session_hint() {
            match self.lifecycle.apply_hint(hint) {
                Ok(SessionHintEffect::Ended(_)) => {}
                Ok(_) => self.pending_hints.push_back(crate::tick::HintSignal {
                    session: Some(hint),
                }),
                Err(error) => {
                    tracing::error!(?error, "session hint apply failed");
                    self.pending_hints.push_back(crate::tick::HintSignal {
                        session: Some(hint),
                    });
                }
            }
        }
    }
}

impl<T: TickSource> TickSource for SessionTicks<'_, T> {
    async fn next_tick(&mut self) -> Option<Tick> {
        loop {
            // Buffered lifecycle facts first: the close predicate below must
            // see the activity clock they bump, not a stale snapshot.
            self.drain_buffered_hints();

            // Close anything already due (also catches a session left
            // open across a restart). A lifecycle read/write error leaves
            // the session lane QUIET for this cycle — no expiry is armed, so
            // a past-due expiry over a broken store cannot spin the loop
            // (the TimerTick fail-stop stance); the close retries on the
            // next real wakeup.
            let expiry = match self.lifecycle.close_due_session() {
                Ok(_) => match self.lifecycle.next_expiry_ms() {
                    Ok(expiry) => expiry,
                    Err(error) => {
                        tracing::error!(
                            ?error,
                            "session expiry read failed; lane quiet this cycle"
                        );
                        None
                    }
                },
                Err(error) => {
                    tracing::error!(?error, "session close failed; lane quiet this cycle");
                    None
                }
            };

            // Surface one applied hint per call: its lifecycle effect is
            // already durable, and the supervisor still owes it one
            // least-privileged micro pass (H-S4). A due deadline is never
            // lost to this — deadlines are re-read every cycle and surface
            // on the next call.
            if let Some(signal) = self.pending_hints.pop_front() {
                return Some(Tick::Hint(signal));
            }

            let tick = match expiry {
                Some(due_at_ms) => {
                    let clock = self.lifecycle.clock();
                    tokio::select! {
                        biased;
                        tick = self.inner.next_tick() => Some(tick),
                        () = sleep_until_due(&clock, due_at_ms) => None,
                    }
                }
                None => Some(self.inner.next_tick().await),
            };

            match tick {
                // Expiry fired: loop — the close at the top runs, enqueues
                // the durable meso attempt, and the inner deadline lane
                // surfaces it as a due Tick::Deadline on the next read.
                None => continue,
                Some(Some(Tick::Hint(signal))) => {
                    if let Some(hint) = signal.session {
                        match self.lifecycle.apply_hint(hint) {
                            // A close means a meso deadline is now queued;
                            // loop so the deadline lane surfaces it instead
                            // of spending this wakeup on a micro pass.
                            Ok(SessionHintEffect::Ended(_)) => continue,
                            Ok(_) => {}
                            Err(error) => {
                                tracing::error!(?error, "session hint apply failed");
                            }
                        }
                    }
                    // Hints keep their shipped meaning: one least-privileged
                    // follow-up pass (H-S4) — the supervisor maps the shape.
                    return Some(Tick::Hint(signal));
                }
                Some(Some(tick)) => return Some(tick),
                Some(None) => {
                    // Inner source exhausted. If a session is still open the
                    // driver owns closing it: wait its expiry out, close, and
                    // loop — the enqueued meso deadline gives the inner
                    // timer lane one final unit of timed work. With nothing
                    // open (or a broken store), exhaustion is final —
                    // fail-stop, never a spin.
                    match self.lifecycle.next_expiry_ms() {
                        Ok(Some(due_at_ms)) => {
                            let clock = self.lifecycle.clock();
                            sleep_until_due(&clock, due_at_ms).await;
                            if let Err(error) = self.lifecycle.close_due_session() {
                                tracing::error!(
                                    ?error,
                                    "final session close failed at exhaustion; stopping"
                                );
                                return None;
                            }
                            continue;
                        }
                        Ok(None) => return None,
                        Err(error) => {
                            tracing::error!(
                                ?error,
                                "session expiry read failed at exhaustion; stopping"
                            );
                            return None;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
