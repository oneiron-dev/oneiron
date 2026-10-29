//! The supervisor's one arbitration point (FIX 8601). Shutdown beats
//! everything; then the three work lanes — fresh source ticks (session hints
//! among them), owed retries that are due, and wave quanta — take turns in
//! a fixed rotation: each decision starts at the lane after the one served
//! last and passes over only a lane with nothing ready, so no lane pins
//! another. Notifications and timer wakes come after every lane and never
//! take a turn.
use std::time::Duration;

use super::shutdown::ShutdownListener;
use crate::tick::{Tick, TickSource};

/// One arbitration decision; each wave pass, owed retry, notification and
/// ordinary tick returns here rather than running another pre-select loop.
#[derive(Debug)]
pub(super) enum SupervisorWake {
    Shutdown,
    Wave,
    Retry,
    Notify,
    Due,
    Tick(Option<Tick>),
}

/// The work lanes that take turns.
#[derive(Debug, Clone, Copy)]
pub(super) enum Lane {
    Source,
    Retry,
    Wave,
}

impl Lane {
    const fn next(self) -> Self {
        match self {
            Self::Source => Self::Retry,
            Self::Retry => Self::Wave,
            Self::Wave => Self::Source,
        }
    }
}

/// The round-robin cursor: the lane served last hands the first look to the
/// lane after it.
#[derive(Debug, Clone, Copy)]
pub(super) struct LaneRotation {
    first: Lane,
}

impl LaneRotation {
    pub(super) const fn new() -> Self {
        Self {
            first: Lane::Source,
        }
    }

    pub(super) fn served(&mut self, lane: Lane) {
        self.first = lane.next();
    }
}

pub(super) struct SupervisorEventInputs<'a, T> {
    pub(super) shutdown: &'a mut ShutdownListener,
    pub(super) ticks: &'a mut T,
    pub(super) wave_events: &'a mut tokio::sync::broadcast::Receiver<()>,
    pub(super) wave_enabled: bool,
    /// The source may be read: it has not run dry, and it is not resting
    /// behind an owed retry of the tick it keeps redelivering.
    pub(super) source_open: bool,
    pub(super) retry_ready: bool,
    pub(super) wave_ready: bool,
    pub(super) delay: Option<Duration>,
    pub(super) rotation: LaneRotation,
}

pub(super) async fn next_supervisor_event<T: TickSource>(
    input: SupervisorEventInputs<'_, T>,
) -> SupervisorWake {
    let SupervisorEventInputs {
        shutdown,
        ticks,
        wave_events,
        wave_enabled,
        source_open,
        retry_ready,
        wave_ready,
        delay,
        rotation,
    } = input;
    match rotation.first {
        Lane::Source => tokio::select! {
            biased;
            () = shutdown.triggered() => SupervisorWake::Shutdown,
            tick = ticks.next_tick(), if source_open => SupervisorWake::Tick(tick),
            () = std::future::ready(()), if retry_ready => SupervisorWake::Retry,
            () = std::future::ready(()), if wave_ready => SupervisorWake::Wave,
            _ = wave_events.recv(), if wave_enabled => SupervisorWake::Notify,
            () = sleep_for(delay), if delay.is_some() => SupervisorWake::Due,
        },
        Lane::Retry => tokio::select! {
            biased;
            () = shutdown.triggered() => SupervisorWake::Shutdown,
            () = std::future::ready(()), if retry_ready => SupervisorWake::Retry,
            () = std::future::ready(()), if wave_ready => SupervisorWake::Wave,
            tick = ticks.next_tick(), if source_open => SupervisorWake::Tick(tick),
            _ = wave_events.recv(), if wave_enabled => SupervisorWake::Notify,
            () = sleep_for(delay), if delay.is_some() => SupervisorWake::Due,
        },
        Lane::Wave => tokio::select! {
            biased;
            () = shutdown.triggered() => SupervisorWake::Shutdown,
            () = std::future::ready(()), if wave_ready => SupervisorWake::Wave,
            tick = ticks.next_tick(), if source_open => SupervisorWake::Tick(tick),
            () = std::future::ready(()), if retry_ready => SupervisorWake::Retry,
            _ = wave_events.recv(), if wave_enabled => SupervisorWake::Notify,
            () = sleep_for(delay), if delay.is_some() => SupervisorWake::Due,
        },
    }
}

/// Sleeps `delay`, or pends without one.
async fn sleep_for(delay: Option<Duration>) {
    match delay {
        Some(delay) => tokio::time::sleep(delay).await,
        None => std::future::pending::<()>().await,
    }
}
