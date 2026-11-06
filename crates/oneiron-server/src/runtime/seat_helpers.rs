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
//!
//! The same registration holds the run's model door slots (FIX 15702,
//! [`super::seat_models`]): the digest of each slot's reference and the
//! run's admitted seat-child credential, which the door's every key release
//! rechecks. Closing it forgets both, so a copied reference stops with it.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use oneiron::authority::SeatChildCredential;
use oneiron::error::SecretError;
use oneiron::secret_lease::{SecretCleanup, SecretGrantHolder, SecretHostDelivery, SecretTaintRef};
use oneiron::{AttemptId, EntityId, Error, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::seat_models::SeatModelSlot;
use crate::models::SeatModelMeter;

/// The prefix of a helper destination's name, `helper:<name>`.
pub const HELPER_DESTINATION_PREFIX: &str = "helper:";

/// The variable a seat CLI's credential helper reads the run's seat-child
/// slip from. Its own name, not `ONEIRON_SECRET`: a CLI's own Oneiron bridge
/// keeps the credential it was given.
pub const SEAT_SLIP_ENV: &str = "ONEIRON_SEAT_SLIP";
/// The variable it reads the slip's 64-hex binding seed from.
pub const SEAT_BINDING_KEY_ENV: &str = "ONEIRON_SEAT_BINDING_KEY";
/// The variable it reads the loopback origin it calls back on from.
pub const SEAT_URL_ENV: &str = "ONEIRON_SEAT_URL";

/// The subcommand of this binary git runs as the seat's credential helper.
pub const CREDENTIAL_HELPER_SUBCOMMAND: &str = "credential-helper";

/// Whether `name` may name a helper destination: it rides a git config
/// value and a request, so ASCII letters, digits, `.`, `_` and `-` alone.
#[must_use]
pub fn is_helper_destination_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

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
    /// The URL git matches this destination's `credential.<url>.*` keys on.
    #[must_use]
    pub fn credential_url(&self) -> String {
        match &self.path {
            Some(path) => format!("{}://{}/{}", self.protocol, self.host, path),
            None => format!("{}://{}", self.protocol, self.host),
        }
    }

    /// Whether its context can ride a git config key: a plain protocol and
    /// host, and a path, with no space, quote, control or config syntax.
    #[must_use]
    pub fn is_plain_context(&self) -> bool {
        let plain = |text: &str, extra: &[u8]| {
            !text.is_empty()
                && text.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b'.' | b'-')
                        || extra.contains(&byte)
                })
        };
        plain(&self.protocol, b"")
            && plain(&self.host, b":[]")
            && self.path.as_deref().is_none_or(|path| plain(path, b"/_~"))
    }

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
    /// Registers `destinations` and the model door's `slots`, each keyed by
    /// its name in the operator's table, for the run of `attempt` under the
    /// claim of `lease_owner` at `attempt_count`, and answers its handle.
    /// `credential` is the run's seat-child credential the host admitted for
    /// the model door, and `meter` the claim's run every model door call is
    /// admitted on (FIX 15702 slice 3); with no slot there are none. A
    /// second registration of the attempt replaces the first, which closes.
    #[expect(
        clippy::too_many_arguments,
        reason = "one claim's registration: its id, what it may reach and its credential"
    )]
    pub(crate) fn register(
        &self,
        attempt: AttemptId,
        lease_owner: &str,
        attempt_count: u32,
        destinations: BTreeMap<String, HelperDestination>,
        slots: BTreeMap<String, SeatModelSlot>,
        credential: Option<SeatChildCredential>,
        meter: Option<Arc<SeatModelMeter>>,
    ) -> SeatHelperRun {
        let registered = SeatHelperRun {
            state: Arc::new(Mutex::new(HelperRunState {
                lease_owner: lease_owner.to_owned(),
                attempt_count,
                destinations,
                slots,
                credential,
                meter,
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

    /// The open registration whose model door slot `slot` `reference` is
    /// the reference to, beside that slot, the run's credential and its
    /// claim's meter. `None` for every other reference, a closed run and a
    /// run with no credential or meter.
    #[must_use]
    pub fn model_door(&self, slot: &str, reference: &str) -> Option<SeatModelDoor> {
        let runs: Vec<SeatHelperRun> = lock(&self.runs).values().cloned().collect();
        runs.into_iter().find_map(|run| {
            let state = lock(&run.state);
            if state.closed {
                return None;
            }
            let bound = state.slots.get(slot)?;
            if !bound.presented(reference) {
                return None;
            }
            let door = SeatModelDoor {
                slot: bound.clone(),
                credential: state.credential.clone()?,
                meter: state.meter.clone()?,
                run: run.clone(),
            };
            drop(state);
            Some(door)
        })
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
    slots: BTreeMap<String, SeatModelSlot>,
    credential: Option<SeatChildCredential>,
    /// The claim's run its model door calls are admitted on.
    meter: Option<Arc<SeatModelMeter>>,
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
            .field("slots", &state.slots.keys().collect::<Vec<_>>())
            .field("grants", &state.grants.len())
            .field("closed", &state.closed)
            .finish()
    }
}

/// What the model door resolves a reference to: the run's registration, the
/// slot it names, the run's seat-child credential and its claim's meter.
#[derive(Clone)]
pub struct SeatModelDoor {
    pub run: SeatHelperRun,
    pub slot: SeatModelSlot,
    pub credential: SeatChildCredential,
    pub(crate) meter: Arc<SeatModelMeter>,
}

impl fmt::Debug for SeatModelDoor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeatModelDoor")
            .field("slot", &self.slot)
            .finish_non_exhaustive()
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

    /// Takes back `grant`, one [`Self::record`] recorded whose value never
    /// left the host. `true` when it was still recorded: the caller then
    /// tears it down itself. `false` when the registration's close already
    /// took it: the run's teardown revokes it with the rest. The grant's
    /// taint stays recorded, so the run's exhaust still names the secret.
    #[must_use]
    pub fn withdraw(&self, grant: &EntityId) -> bool {
        let mut state = lock(&self.state);
        let Some(at) = state.grants.iter().position(|held| held == grant) else {
            return false;
        };
        state.grants.remove(at);
        true
    }

    /// Records the taint of a provider key the model door released for the
    /// run (FIX 15702), before the key goes to the broker. `false` once the
    /// registration is closed: the door then sends nothing.
    #[must_use]
    pub fn record_taint(&self, taint: SecretTaintRef) -> bool {
        let mut state = lock(&self.state);
        if state.closed {
            return false;
        }
        if !state.taints.contains(&taint) {
            state.taints.push(taint);
        }
        true
    }

    /// Closes the registration and hands back what it recorded. A second
    /// close hands back nothing. Its model door slots and credential are
    /// forgotten, so no reference to them is answered again.
    pub fn close(&self) -> HelperRunEnd {
        let mut state = lock(&self.state);
        state.closed = true;
        state.slots.clear();
        state.credential = None;
        state.meter = None;
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

/// The environment a seat CLI's credential helper needs (FIX 10624 step 2):
/// the run's seat-child slip, its binding seed and the loopback origin, and
/// the git configuration that makes git call the helper, and only it, for
/// each bound context. Set on the CLI's process as it is built; a running
/// process's environment never changes.
#[derive(Clone)]
pub struct SeatHelperEnv {
    slip: Zeroizing<String>,
    binding_seed: Zeroizing<String>,
    origin: String,
    git_config: Vec<(String, String)>,
}

impl fmt::Debug for SeatHelperEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeatHelperEnv")
            .field("origin", &self.origin)
            .field("git_config", &self.git_config)
            .finish_non_exhaustive()
    }
}

impl SeatHelperEnv {
    /// The environment for a run whose slip is `slip`, held by `binding_seed`
    /// (64 hex), calling back on `origin`, with `program` (this binary) as
    /// the helper for each of `destinations`, by their names.
    #[must_use]
    pub fn new(
        slip: Zeroizing<String>,
        binding_seed: Zeroizing<String>,
        origin: String,
        program: &std::path::Path,
        destinations: &BTreeMap<String, HelperDestination>,
    ) -> Self {
        let program = shell_quoted(&program.to_string_lossy());
        let mut git_config = Vec::new();
        for (name, destination) in destinations {
            let url = destination.credential_url();
            // An empty helper first clears every helper configured before for
            // this context, so no other helper is asked or handed the value
            // to store; then this binary alone answers it. The leading `!`
            // makes git run the value as a shell command: without it, git
            // runs `git credential-<value>`, since the quoted path starts
            // with neither `/` nor `!`. The name is shell-safe
            // (`is_helper_destination_name`).
            git_config.push((format!("credential.{url}.helper"), String::new()));
            git_config.push((
                format!("credential.{url}.helper"),
                format!("!{program} {CREDENTIAL_HELPER_SUBCOMMAND} --destination {name}"),
            ));
            if destination.path.is_some() {
                git_config.push((format!("credential.{url}.useHttpPath"), "true".to_owned()));
            }
        }
        Self {
            slip,
            binding_seed,
            origin,
            git_config,
        }
    }

    /// Sets the helper's variables and appends its git configuration after
    /// any the host process already passes on through `GIT_CONFIG_COUNT`.
    pub fn apply(&self, command: &mut std::process::Command) {
        command
            .env(SEAT_SLIP_ENV, self.slip.as_str())
            .env(SEAT_BINDING_KEY_ENV, self.binding_seed.as_str())
            .env(SEAT_URL_ENV, &self.origin);
        let inherited = std::env::var("GIT_CONFIG_COUNT")
            .ok()
            .and_then(|count| count.parse::<usize>().ok())
            .filter(|count| *count <= 1024)
            .unwrap_or(0);
        for (offset, (key, value)) in self.git_config.iter().enumerate() {
            let index = inherited + offset;
            command
                .env(format!("GIT_CONFIG_KEY_{index}"), key)
                .env(format!("GIT_CONFIG_VALUE_{index}"), value);
        }
        command.env(
            "GIT_CONFIG_COUNT",
            (inherited + self.git_config.len()).to_string(),
        );
    }
}

/// `text` as one single-quoted POSIX shell word: git runs a helper given by
/// an absolute path through the shell.
fn shell_quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}
