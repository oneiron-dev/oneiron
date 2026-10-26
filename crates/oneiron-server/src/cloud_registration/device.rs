//! The device grant's pending flows (LC cloud #97 §2, §3; L14 lead call
//! 08:3x): each bound to the owner whose request started it, held in this
//! process's memory alone, its device code wiped when the flow ends. A
//! restart ends every flow; the owner starts again.
//!
//! Pacing is the wire's: the interval the start answered (5 s), plus 5 s for
//! good with each `slow_down`, inside the code's own deadline (600 s),
//! counted from before the start request was sent. A poll asked early sends
//! nothing. The first poll waits one interval (CALLS G7_FIRST_POLL).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::{Duration, Instant};

use oneiron::EntityId;
use zeroize::Zeroizing;

use super::discovery::Endpoints;
use super::wire::SLOW_DOWN_SECS;

/// One owner's pending device flow.
pub(crate) struct Flow {
    /// The owner whose request started it: every poll's fresh proof must be
    /// this owner's.
    pub(crate) actor: EntityId,
    /// Whether its link may replace a current link to another subject.
    pub(crate) replace: bool,
    pub(crate) endpoints: Endpoints,
    pub(crate) device_code: Zeroizing<String>,
    deadline: Instant,
    interval: Duration,
    next_poll: Instant,
}

impl Flow {
    /// A flow started at `started` (before its start request), as the start
    /// answered it.
    pub(crate) fn new(
        actor: EntityId,
        replace: bool,
        endpoints: Endpoints,
        device_code: Zeroizing<String>,
        started: Instant,
        expires_in: u64,
        interval: u64,
    ) -> Self {
        let interval = Duration::from_secs(interval);
        Self {
            actor,
            replace,
            endpoints,
            device_code,
            deadline: started + Duration::from_secs(expires_in),
            interval,
            next_poll: started + interval,
        }
    }

    /// How long until a poll is due; zero when it is.
    pub(crate) fn wait(&self, now: Instant) -> Duration {
        self.next_poll.saturating_duration_since(now)
    }

    /// What is left of the code's lifetime; zero once it expired.
    pub(crate) fn left(&self, now: Instant) -> Duration {
        self.deadline.saturating_duration_since(now)
    }

    /// The poll sent at `now` was timely: the next is one interval on.
    pub(crate) fn polled(&mut self, now: Instant) {
        self.next_poll = now + self.interval;
    }

    /// The issuer answered `slow_down` to the poll sent at `now`: the
    /// interval grows by 5 s for good, and the next poll waits it.
    pub(crate) fn slow_down(&mut self, now: Instant) {
        self.interval += Duration::from_secs(SLOW_DOWN_SECS);
        self.next_poll = now + self.interval;
    }
}

/// Every pending flow of this process, by its opaque local handle.
#[derive(Default)]
pub(crate) struct Flows(BTreeMap<String, Flow>);

impl Flows {
    /// Holds `flow` under a fresh random handle, which names it to its
    /// owner and nothing else.
    pub(crate) fn hold(&mut self, flow: Flow) -> String {
        let mut handle = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut handle);
        let mut hex = String::with_capacity(2 * handle.len());
        for byte in handle {
            let _ = write!(hex, "{byte:02x}");
        }
        let handle = hex;
        self.0.insert(handle.clone(), flow);
        handle
    }

    /// Takes the flow `handle` names out, when `actor` started it: a poll
    /// holds it alone while its one request runs.
    pub(crate) fn take(&mut self, handle: &str, actor: &EntityId) -> Option<Flow> {
        if self.0.get(handle).is_some_and(|flow| flow.actor == *actor) {
            return self.0.remove(handle);
        }
        None
    }

    /// Puts a flow still pending back under its handle.
    pub(crate) fn put_back(&mut self, handle: String, flow: Flow) {
        self.0.insert(handle, flow);
    }

    /// Ends every flow `actor` started: a logout or an erase cancels them.
    pub(crate) fn cancel(&mut self, actor: &EntityId) {
        self.0.retain(|_, flow| flow.actor != *actor);
    }

    /// Ends every flow whose code expired by `now`.
    pub(crate) fn expire(&mut self, now: Instant) {
        self.0.retain(|_, flow| !flow.left(now).is_zero());
    }
}
