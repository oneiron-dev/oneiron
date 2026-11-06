//! T1 host delivery (DOOR-124, FIX 4490): the secret destinations a run host
//! registers for one run, and the [`SecretHostDelivery`] the
//! `self.secrets.*` doors hand the engine.
//!
//! A host that starts processes for a run (the official CLI seat executor,
//! the BYOA CLI sandbox host's [`ByoaCliExecutor`]) registers the run's
//! destinations here, by the run's attempt, before it starts them: each one
//! a name, the environment variable it fills and the effector the owner's
//! binding names for its consumer. A CLI's credential slot is the variable
//! it reads its credential from. A T1 grant's bytes land in the destination,
//! held zeroized on drop, and the host sets every filled variable in each
//! process it starts for the run from then on
//! ([`RunSecretDestinations::apply_env`]). Nothing else reads them: no
//! answer, log or receipt.
//!
//! Withdrawing clears the destination. A process already started keeps the
//! copy it was given, as ARCH-0069 S6 says of every T1 copy. A run whose
//! host registered nothing answers as [`NoSecretHostDelivery`] does: every
//! T1 grant refuses, by name.
//!
//! [`ByoaCliExecutor`]: oneiron::dispatch_byoa::ByoaCliExecutor

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::process::Command;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use oneiron::error::SecretError;
use oneiron::secret_lease::{
    NoSecretHostDelivery, SecretCleanup, SecretGrantHolder, SecretHostDelivery,
};
use oneiron::{AttemptId, EntityId, Error, Result};
use zeroize::Zeroizing;

/// The prefix of an environment destination's name, `env:<VARIABLE>`
/// (CALLS: DOOR-124 destination naming).
pub const SECRET_DESTINATION_ENV_PREFIX: &str = "env:";

/// One destination a run host offers the run it starts processes for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretDestination {
    /// The name a `host_destination` purpose names.
    pub name: String,
    /// The environment variable the destination fills, such as `GH_TOKEN`.
    pub variable: String,
    /// The effector the owner's binding names for the destination's
    /// consumer, such as `cli:gh`. The binding must admit T1 for it.
    pub effector: String,
}

impl SecretDestination {
    /// The destination `env:<variable>`, for `effector`.
    #[must_use]
    pub fn env(variable: impl Into<String>, effector: impl Into<String>) -> Self {
        let variable = variable.into();
        Self {
            name: format!("{SECRET_DESTINATION_ENV_PREFIX}{variable}"),
            variable,
            effector: effector.into(),
        }
    }
}

/// Every run's destinations on this host, by the run's attempt.
#[derive(Default)]
pub struct SecretDestinations {
    runs: Mutex<HashMap<AttemptId, RunSecretDestinations>>,
}

impl fmt::Debug for SecretDestinations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretDestinations")
            .field("runs", &lock(&self.runs).len())
            .finish()
    }
}

impl SecretDestinations {
    /// Registers `destinations` for `run` and answers the run's handle, which
    /// its host starts processes with. A second registration of the run
    /// replaces the first, and what the first's destinations held is
    /// dropped.
    ///
    /// # Errors
    /// [`SecretError::SecretHostDeliveryRefused`] naming a destination whose
    /// variable is no environment variable name, that names no effector, or
    /// whose name or variable the run registers twice.
    pub fn register(
        &self,
        run: AttemptId,
        destinations: impl IntoIterator<Item = SecretDestination>,
    ) -> Result<RunSecretDestinations> {
        let mut slots = BTreeMap::new();
        let mut variables = BTreeSet::new();
        for destination in destinations {
            let SecretDestination {
                name,
                variable,
                effector,
            } = destination;
            if !is_env_name(&variable) {
                return Err(refused(
                    &name,
                    "its variable is not an environment variable name",
                ));
            }
            if effector.is_empty() {
                return Err(refused(&name, "it names no effector"));
            }
            if slots.contains_key(&name) || !variables.insert(variable.clone()) {
                return Err(refused(
                    &name,
                    "the run registers this destination or its variable twice",
                ));
            }
            slots.insert(
                name,
                Slot {
                    variable,
                    effector,
                    value: None,
                },
            );
        }
        let registered = RunSecretDestinations {
            slots: Arc::new(Mutex::new(HeldSlots {
                slots,
                closed: false,
            })),
        };
        let earlier = lock(&self.runs).insert(run, registered.clone());
        if let Some(earlier) = earlier {
            earlier.close();
        }
        Ok(registered)
    }

    /// Drops what each destination of `run` holds and forgets the run: its
    /// host starts no more processes for it.
    pub fn retire(&self, run: AttemptId) {
        let retired = lock(&self.runs).remove(&run);
        if let Some(retired) = retired {
            retired.close();
        }
    }

    /// [`Self::retire`] for the registration `own` made (FIX 4552): its
    /// bytes go, and the run is forgotten only while `own` is still its
    /// registration, so a host retiring a predecessor never clears its
    /// successor's.
    pub fn retire_own(&self, run: AttemptId, own: &RunSecretDestinations) {
        let mut runs = lock(&self.runs);
        let current = runs
            .get(&run)
            .is_some_and(|held| Arc::ptr_eq(&held.slots, &own.slots));
        if current {
            runs.remove(&run);
        }
        drop(runs);
        own.close();
    }

    /// The delivery the `self.secrets.*` doors hand the engine: the
    /// destinations of the run each grant's holder acts in.
    #[must_use]
    pub fn delivery(&self) -> ServedSecretDelivery<'_> {
        ServedSecretDelivery { destinations: self }
    }

    /// The destinations of the run `holder` acts in, if its host registered
    /// any.
    fn of(&self, holder: &SecretGrantHolder) -> Option<RunSecretDestinations> {
        let run = holder.run()?;
        lock(&self.runs).get(&run).cloned()
    }
}

/// One run's destinations and what each holds. Clones share them.
#[derive(Clone, Default)]
pub struct RunSecretDestinations {
    slots: Arc<Mutex<HeldSlots>>,
}

/// A registration's destinations, and whether it is closed: once its run is
/// retired or replaced, every clone of it refuses a delivery, under the same
/// lock as the slots, so a mint still in flight cannot refill them.
#[derive(Default)]
struct HeldSlots {
    slots: BTreeMap<String, Slot>,
    closed: bool,
}

/// One destination and the bytes delivered into it.
struct Slot {
    variable: String,
    effector: String,
    // FIX 7954: the delivering grant's id beside its copy.
    value: Option<(EntityId, Zeroizing<Vec<u8>>)>,
}

impl fmt::Debug for RunSecretDestinations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let held_slots = lock(&self.slots);
        f.debug_map()
            .entries(held_slots.slots.iter().map(|(name, slot)| {
                let held = if slot.value.is_some() {
                    "filled"
                } else {
                    "empty"
                };
                (name, held)
            }))
            .finish()
    }
}

impl RunSecretDestinations {
    /// Sets each filled destination's variable in `command`'s environment.
    /// A host calls it as it builds each process for the run, before the
    /// variables it removes, so a variable it removes stays removed.
    pub fn apply_env(&self, command: &mut Command) {
        for slot in lock(&self.slots).slots.values() {
            // Delivery admits only text with no NUL byte.
            // FIX 7954: the slot's first half is the delivering grant's id.
            if let Some(text) = slot
                .value
                .as_ref()
                .and_then(|(_, value)| std::str::from_utf8(value).ok())
            {
                command.env(&slot.variable, text);
            }
        }
    }

    fn effector(&self, destination: &str) -> Option<String> {
        let held = lock(&self.slots);
        if held.closed {
            return None;
        }
        held.slots
            .get(destination)
            .map(|slot| slot.effector.clone())
    }

    /// Whether `destination` is one of these destinations.
    #[must_use]
    pub fn names(&self, destination: &str) -> bool {
        lock(&self.slots).slots.contains_key(destination)
    }

    /// The delivery for the grants run `run`'s host mints for it itself
    /// (FIX 10624): their bytes land in these destinations only, never in
    /// another registration the run's attempt names by then.
    #[must_use]
    pub fn own_delivery(&self, run: AttemptId) -> OwnSecretDelivery<'_> {
        OwnSecretDelivery { run, own: self }
    }

    fn fill(&self, grant: &EntityId, destination: &str, value: &[u8]) -> Result<()> {
        if value.contains(&0) || std::str::from_utf8(value).is_err() {
            return Err(refused(
                destination,
                "an environment variable holds text with no NUL byte",
            ));
        }
        let mut held = lock(&self.slots);
        if held.closed {
            return Err(refused(
                destination,
                "the run's registration is retired; it takes no more deliveries",
            ));
        }
        let slot = held.slots.get_mut(destination).ok_or_else(|| {
            refused(
                destination,
                "the caller's run host registered no such destination",
            )
        })?;
        // FIX 7954: the slot records which grant delivered this copy.
        slot.value = Some((*grant, Zeroizing::new(value.to_vec())));
        Ok(())
    }

    fn withdraw(&self, grant: &EntityId, destination: &str) -> SecretCleanup {
        // FIX 7954: only this grant's copy clears; a newer one stays, absent
        // for this grant.
        let taken = lock(&self.slots)
            .slots
            .get_mut(destination)
            .and_then(|slot| slot.value.take_if(|(id, _)| id == grant));
        match taken {
            Some(_) => SecretCleanup::Removed,
            None => SecretCleanup::Absent,
        }
    }

    /// Drops what each destination holds and refuses every later delivery
    /// into this registration, through any of its clones.
    fn close(&self) {
        let mut held = lock(&self.slots);
        held.closed = true;
        for slot in held.slots.values_mut() {
            slot.value = None;
        }
    }
}

/// The [`SecretHostDelivery`] of one run's own registration
/// ([`RunSecretDestinations::own_delivery`], FIX 10624): a grant held for
/// that run fills these destinations and withdraws from them; one held for
/// another run is refused, by name.
#[derive(Debug, Clone, Copy)]
pub struct OwnSecretDelivery<'a> {
    run: AttemptId,
    own: &'a RunSecretDestinations,
}

impl SecretHostDelivery for OwnSecretDelivery<'_> {
    fn destination_effector(
        &self,
        holder: &SecretGrantHolder,
        destination: &str,
    ) -> Option<String> {
        if holder.run() != Some(self.run) {
            return None;
        }
        self.own.effector(destination)
    }

    fn deliver(
        &mut self,
        holder: &SecretGrantHolder,
        grant: &EntityId,
        destination: &str,
        value: &[u8],
    ) -> Result<()> {
        if holder.run() != Some(self.run) {
            return Err(refused(destination, "the grant is held for another run"));
        }
        self.own.fill(grant, destination, value)
    }

    fn withdraw(
        &mut self,
        holder: &SecretGrantHolder,
        grant: &EntityId,
        destination: &str,
    ) -> Result<SecretCleanup> {
        if holder.run() != Some(self.run) {
            return Ok(SecretCleanup::Absent);
        }
        Ok(self.own.withdraw(grant, destination))
    }
}

/// The [`SecretHostDelivery`] of a host's registered runs.
#[derive(Debug, Clone, Copy)]
pub struct ServedSecretDelivery<'a> {
    destinations: &'a SecretDestinations,
}

impl SecretHostDelivery for ServedSecretDelivery<'_> {
    fn destination_effector(
        &self,
        holder: &SecretGrantHolder,
        destination: &str,
    ) -> Option<String> {
        self.destinations.of(holder)?.effector(destination)
    }

    fn deliver(
        &mut self,
        holder: &SecretGrantHolder,
        grant: &EntityId, // FIX 7954: the delivering grant, recorded beside its copy.
        destination: &str,
        value: &[u8],
    ) -> Result<()> {
        match self.destinations.of(holder) {
            Some(run) => run.fill(grant, destination, value),
            None => NoSecretHostDelivery.deliver(holder, grant, destination, value),
        }
    }

    fn withdraw(
        &mut self,
        holder: &SecretGrantHolder,
        grant: &EntityId, // FIX 7954: only this grant's copy clears.
        destination: &str,
    ) -> Result<SecretCleanup> {
        match self.destinations.of(holder) {
            Some(run) => Ok(run.withdraw(grant, destination)),
            None => NoSecretHostDelivery.withdraw(holder, grant, destination),
        }
    }
}

/// Whether `name` is a portable environment variable name.
pub(super) fn is_env_name(name: &str) -> bool {
    name.bytes()
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// The refusal of a destination, by name. It never carries value bytes.
fn refused(destination: &str, reason: &'static str) -> Error {
    Error::Secret(SecretError::SecretHostDeliveryRefused {
        destination: destination.to_owned(),
        reason,
    })
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
