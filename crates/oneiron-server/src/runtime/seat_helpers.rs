//! The credential-helper destinations of a seat run (FIX 10624 step 2;
//! ARCH-0069 T1, the credential-helper shim).
//!
//! A vendor tool inside an official CLI seat (git, and tools that speak its
//! credential-helper protocol) asks for a credential at the moment it uses
//! one. The seat host registers here, by the run's attempt and claim, the
//! helper destinations the operator binds (`[runtime.helper_destinations]`):
//! each one names the custody record that serves it, the effector the
//! owner's binding names for its consumer, and the exact git context and
//! username it answers. The helper the CLI runs presents the run's
//! seat-child slip at `POST /v1/seat/credential-helper`; the grant it gets
//! is a T1 grant on a `helper:<name>` host destination, minted through the
//! same vault grant door as `self.secrets.materialize`, and its value goes
//! back once to that helper, never into the CLI's environment.
//!
//! The registration keeps the grants and taints it handed out, so the run's
//! teardown revokes each grant and its exhaust carries each taint. Once the
//! run is retired or replaced, the registration is closed: it names no
//! destination and records no grant, under one lock, so a request still in
//! flight cannot deliver past it.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use oneiron::error::SecretError;
use oneiron::secret_lease::{SecretCleanup, SecretGrantHolder, SecretHostDelivery, SecretTaintRef};
use oneiron::{AttemptId, EntityId, Error, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The prefix of a helper destination's name, `helper:<name>`.
pub const HELPER_DESTINATION_PREFIX: &str = "helper:";

/// One helper destination the operator binds, by its name in
/// `[runtime.helper_destinations]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperDestination {
    /// The custody name of the record that serves it. A run reaches it only
    /// when the run's pinned secret manifest declares this name.
    pub secret: String,
    /// The effector the owner's binding names for its consumer, such as
    /// `cli:git`. The binding must admit T1 for it.
    pub effector: String,
    /// The git credential `protocol` it answers, such as `https`.
    pub protocol: String,
    /// The git credential `host` it answers, exactly, such as `github.com`.
    pub host: String,
    /// The git credential `path` it answers, exactly, when git sends one
    /// (`credential.useHttpPath`); `None` answers any path on the host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The username the helper answers beside the value.
    pub username: String,
}

impl HelperDestination {
    /// Whether a helper asking for `protocol`, `host` and `path` asks for
    /// this destination's own context.
    #[must_use]
    pub fn answers(&self, protocol: &str, host: &str, path: Option<&str>) -> bool {
        self.protocol == protocol
            && self.host == host
            && self.path.as_deref().is_none_or(|own| path == Some(own))
    }
}

/// Every seat run's helper registration on this host, by the run's attempt.
#[derive(Default)]
pub struct SeatHelperRuns {
    runs: Mutex<HashMap<AttemptId, SeatHelperRun>>,
}

impl fmt::Debug for SeatHelperRuns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeatHelperRuns")
            .field("runs", &lock(&self.runs).len())
            .finish()
    }
}

impl SeatHelperRuns {
    /// Registers `destinations`, keyed by their names in the operator's
    /// table, for the run of `attempt` under the claim of `lease_owner` at
    /// `attempt_count`, and answers its handle. A second registration of the
    /// attempt replaces the first, which closes.
    pub fn register(
        &self,
        attempt: AttemptId,
        lease_owner: &str,
        attempt_count: u32,
        destinations: BTreeMap<String, HelperDestination>,
    ) -> SeatHelperRun {
        let registered = SeatHelperRun {
            state: Arc::new(Mutex::new(HelperRunState {
                lease_owner: lease_owner.to_owned(),
                attempt_count,
                destinations,
                grants: Vec::new(),
                taints: Vec::new(),
                closed: false,
            })),
        };
        let earlier = lock(&self.runs).insert(attempt, registered.clone());
        if let Some(earlier) = earlier {
            earlier.close();
        }
        registered
    }

    /// The registration of `attempt`'s run under the claim of `lease_owner`
    /// at `attempt_count`, if its host made one and it is open.
    #[must_use]
    pub fn of(
        &self,
        attempt: AttemptId,
        lease_owner: &str,
        attempt_count: u32,
    ) -> Option<SeatHelperRun> {
        let run = lock(&self.runs).get(&attempt).cloned()?;
        let state = lock(&run.state);
        (!state.closed && state.lease_owner == lease_owner && state.attempt_count == attempt_count)
            .then(|| run.clone())
    }

    /// Forgets `attempt`'s run while `own` is still its registration, so a
    /// host retiring a predecessor never closes its successor's, and closes
    /// `own`: what it hands back is the grants to revoke and the taints the
    /// run's exhaust carries.
    pub fn retire_own(&self, attempt: AttemptId, own: &SeatHelperRun) -> HelperRunEnd {
        let mut runs = lock(&self.runs);
        if runs
            .get(&attempt)
            .is_some_and(|held| Arc::ptr_eq(&held.state, &own.state))
        {
            runs.remove(&attempt);
        }
        drop(runs);
        own.close()
    }
}

/// One seat run's helper registration. Clones share it.
#[derive(Clone)]
pub struct SeatHelperRun {
    state: Arc<Mutex<HelperRunState>>,
}

struct HelperRunState {
    lease_owner: String,
    attempt_count: u32,
    destinations: BTreeMap<String, HelperDestination>,
    grants: Vec<EntityId>,
    taints: Vec<SecretTaintRef>,
    closed: bool,
}

impl fmt::Debug for SeatHelperRun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = lock(&self.state);
        f.debug_struct("SeatHelperRun")
            .field(
                "destinations",
                &state.destinations.keys().collect::<Vec<_>>(),
            )
            .field("grants", &state.grants.len())
            .field("closed", &state.closed)
            .finish()
    }
}

/// What a closed registration hands its run's teardown: the grants to
/// revoke and the taints the run's exhaust carries.
#[derive(Debug, Default)]
pub struct HelperRunEnd {
    pub grants: Vec<EntityId>,
    pub taints: Vec<SecretTaintRef>,
}

impl SeatHelperRun {
    /// The destination the operator named `name`, while the registration is
    /// open.
    #[must_use]
    pub fn destination(&self, name: &str) -> Option<HelperDestination> {
        let state = lock(&self.state);
        if state.closed {
            return None;
        }
        state.destinations.get(name).cloned()
    }

    /// Records a grant the run's helper took and the taint its value
    /// carries, before the value leaves the host. `false` once the
    /// registration is closed: the caller then revokes the grant itself and
    /// hands nothing out.
    #[must_use]
    pub fn record(&self, grant: EntityId, taint: SecretTaintRef) -> bool {
        let mut state = lock(&self.state);
        if state.closed {
            return false;
        }
        state.grants.push(grant);
        if !state.taints.contains(&taint) {
            state.taints.push(taint);
        }
        true
    }

    /// Closes the registration and hands back what it recorded. A second
    /// close hands back nothing.
    pub fn close(&self) -> HelperRunEnd {
        let mut state = lock(&self.state);
        state.closed = true;
        HelperRunEnd {
            grants: std::mem::take(&mut state.grants),
            taints: std::mem::take(&mut state.taints),
        }
    }
}

/// The [`SecretHostDelivery`] of one helper request: the T1 grant minted for
/// it delivers into this request's own buffer, once, for the one helper
/// destination it names under the run's attempt, and the door hands those
/// bytes back to the asking helper alone. Every other destination, and a
/// grant held for another run, is refused.
pub struct HelperReplyDelivery {
    run: AttemptId,
    destination: String,
    effector: String,
    value: Option<(EntityId, Zeroizing<Vec<u8>>)>,
}

impl fmt::Debug for HelperReplyDelivery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HelperReplyDelivery")
            .field("destination", &self.destination)
            .field("filled", &self.value.is_some())
            .finish()
    }
}

impl HelperReplyDelivery {
    /// The delivery for `destination` (a `helper:<name>`) under `run`, for
    /// `effector`.
    #[must_use]
    pub fn new(run: AttemptId, destination: String, effector: String) -> Self {
        Self {
            run,
            destination,
            effector,
            value: None,
        }
    }

    /// The bytes delivered, taken once.
    pub fn take(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        self.value.take().map(|(_, value)| value)
    }

    fn admits(&self, holder: &SecretGrantHolder, destination: &str) -> bool {
        holder.run() == Some(self.run) && destination == self.destination
    }
}

impl SecretHostDelivery for HelperReplyDelivery {
    fn destination_effector(
        &self,
        holder: &SecretGrantHolder,
        destination: &str,
    ) -> Option<String> {
        self.admits(holder, destination)
            .then(|| self.effector.clone())
    }

    fn deliver(
        &mut self,
        holder: &SecretGrantHolder,
        grant: &EntityId,
        destination: &str,
        value: &[u8],
    ) -> Result<()> {
        if !self.admits(holder, destination) {
            return Err(refused(
                destination,
                "the request asked for another destination",
            ));
        }
        // The git credential protocol is line-based text: a value with a
        // newline or a NUL byte cannot be answered whole.
        if value.iter().any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
            || std::str::from_utf8(value).is_err()
        {
            return Err(refused(
                destination,
                "a credential helper answers one line of text",
            ));
        }
        self.value = Some((*grant, Zeroizing::new(value.to_vec())));
        Ok(())
    }

    fn withdraw(
        &mut self,
        _holder: &SecretGrantHolder,
        grant: &EntityId,
        _destination: &str,
    ) -> Result<SecretCleanup> {
        // Bytes handed to the helper are beyond this host's reach; only a
        // copy still in this buffer clears.
        let taken = self.value.take_if(|(id, _)| id == grant);
        Ok(match taken {
            Some(_) => SecretCleanup::Removed,
            None => SecretCleanup::Absent,
        })
    }
}

fn refused(destination: &str, reason: &'static str) -> Error {
    Error::Secret(SecretError::SecretHostDeliveryRefused {
        destination: destination.to_owned(),
        reason,
    })
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
