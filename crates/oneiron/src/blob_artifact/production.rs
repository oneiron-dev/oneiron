//! Host-bound production facts for an output. These are historical records,
//! not a live lease check or authority to submit the output.

use rmpv::Value;

use crate::attempt_queue::AttemptId;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::task_verb::HostBinding;
use crate::write_envelope::WriteActor;

use super::store_keys::{entity_value, u64_value};

/// The production witness retained for an output. Unknown means the writer
/// held no host binding. Erased is the neutral, no-actor form used by erasure
/// and checkpoint projection; it does not assert an erase operation executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputProductionStamp {
    Unknown,
    Erased,
    Host(HostProductionStamp),
}

/// A fact captured from the actual writer and its sealed host binding.
/// A genuine absence of an executor run is recorded as `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostProductionStamp {
    actor: EntityId,
    actor_class: EdgeActorClass,
    attempt: AttemptId,
    executor_run: Option<EntityId>,
    lease_generation: u32,
}

impl HostProductionStamp {
    #[must_use]
    pub const fn actor(&self) -> EntityId {
        self.actor
    }

    #[must_use]
    pub const fn actor_class(&self) -> EdgeActorClass {
        self.actor_class
    }

    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    #[must_use]
    pub const fn executor_run(&self) -> Option<EntityId> {
        self.executor_run
    }

    #[must_use]
    pub const fn lease_generation(&self) -> u32 {
        self.lease_generation
    }
}

impl OutputProductionStamp {
    /// Capture only the context the writer actually holds. Lease expiry does
    /// not erase a sealed historical witness; this adds no live-lease gate.
    pub(crate) fn capture(actor: &WriteActor, host: Option<&HostBinding>) -> Self {
        match host {
            Some(host) => Self::Host(HostProductionStamp {
                actor: actor.entity_ref(),
                actor_class: actor.actor_class(),
                attempt: host.parent(),
                executor_run: host.executor_run(),
                lease_generation: host.attempt_count(),
            }),
            None => Self::Unknown,
        }
    }

    pub(crate) fn to_value(&self) -> Value {
        let entries = match self {
            Self::Unknown => vec![(Value::from("kind"), Value::from("unknown"))],
            Self::Erased => vec![(Value::from("kind"), Value::from("erased"))],
            Self::Host(host) => vec![
                (Value::from("kind"), Value::from("host")),
                (
                    Value::from("actor"),
                    Value::Binary(host.actor.as_bytes().to_vec()),
                ),
                (
                    Value::from("actor_class"),
                    Value::from(host.actor_class as u8),
                ),
                (
                    Value::from("attempt"),
                    Value::Binary(host.attempt.as_bytes().to_vec()),
                ),
                (
                    Value::from("executor_run"),
                    host.executor_run
                        .map_or(Value::Nil, |run| Value::Binary(run.as_bytes().to_vec())),
                ),
                (
                    Value::from("lease_generation"),
                    Value::from(host.lease_generation),
                ),
            ],
        };
        Value::Map(entries)
    }

    /// Decode only the closed current format. The containing record must
    /// supply this value even when its production witness is unknown.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        const KEYS: [&str; 6] = [
            "kind",
            "actor",
            "actor_class",
            "attempt",
            "executor_run",
            "lease_generation",
        ];
        let Value::Map(entries) = value else {
            return Err(invalid_production());
        };
        let mut fields = [None; KEYS.len()];
        for (key, value) in entries {
            let index = key
                .as_str()
                .and_then(|key| KEYS.iter().position(|known| *known == key))
                .ok_or_else(invalid_production)?;
            if fields[index].replace(value).is_some() {
                return Err(invalid_production());
            }
        }
        match fields[0].and_then(Value::as_str) {
            Some("unknown") if entries.len() == 1 => Ok(Self::Unknown),
            Some("erased") if entries.len() == 1 => Ok(Self::Erased),
            Some("host") if entries.len() == KEYS.len() => {
                let field = |index: usize| fields[index].ok_or_else(invalid_production);
                let actor = entity_value(field(1)?, "invalid production actor")?;
                let actor_class =
                    u8::try_from(u64_value(field(2)?, "invalid production actor class")?)
                        .ok()
                        .and_then(EdgeActorClass::try_from_u8)
                        .ok_or_else(invalid_production)?;
                let Value::Binary(attempt) = field(3)? else {
                    return Err(invalid_production());
                };
                let attempt = AttemptId::from_bytes(attempt).map_err(|_| invalid_production())?;
                let executor_run = match field(4)? {
                    Value::Nil => None,
                    value => Some(entity_value(value, "invalid production executor run")?),
                };
                let lease_generation =
                    u32::try_from(u64_value(field(5)?, "invalid production generation")?)
                        .map_err(|_| invalid_production())?;
                Ok(Self::Host(HostProductionStamp {
                    actor,
                    actor_class,
                    attempt,
                    executor_run,
                    lease_generation,
                }))
            }
            _ => Err(invalid_production()),
        }
    }

    pub(super) fn references_actor(&self, actor: &EntityId) -> bool {
        matches!(self, Self::Host(host) if host.actor == *actor || host.executor_run == Some(*actor))
    }

    pub(crate) fn erase_actor(&mut self, actor: &EntityId) -> bool {
        if self.references_actor(actor) {
            *self = Self::Erased;
            true
        } else {
            false
        }
    }

    pub(crate) fn project_erased_in_txn(
        &mut self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<()> {
        if let Self::Host(host) = self {
            if vault.carrier_actor_erased_in_txn(txn, &host.actor)?
                || match host.executor_run {
                    Some(run) => vault.carrier_actor_erased_in_txn(txn, &run)?,
                    None => false,
                }
            {
                *self = Self::Erased;
            }
        }
        Ok(())
    }
}

fn invalid_production() -> Error {
    Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
        "invalid output production stamp",
    ))
}
