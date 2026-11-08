//! Original dispatcher facts carried with a private saved step response.

use super::codec::{
    expect_key, expect_map, expect_string, expect_u64, invalid_step, pinned_key_index,
};
use super::types::DurableStepContext;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::write_envelope::WriteActor;
use rmpv::Value;

const SOURCE_KEYS: [&str; 7] = [
    "actor",
    "class",
    "frontier",
    "run_attempt",
    "run_id",
    "subject",
    "at",
];

/// Source facts, not a grant, a receiver context or proof of payment.
#[derive(Clone, Debug)]
pub(super) struct StepSource {
    pub(super) actor: WriteActor,
    pub(super) run_id: Option<String>,
    pub(super) subject: EntityId,
    pub(super) at: u64,
}

impl StepSource {
    pub(super) fn of(ctx: &DurableStepContext<'_>) -> Self {
        Self {
            actor: ctx.envelope_actor,
            run_id: ctx.run_id.clone(),
            subject: ctx.subject,
            at: ctx.now_ms,
        }
    }

    pub(super) fn to_value(&self) -> Value {
        Value::Map(vec![
            (
                Value::from("actor"),
                Value::Binary(self.actor.entity_ref().as_bytes().to_vec()),
            ),
            (
                Value::from("class"),
                Value::from(self.actor.actor_class() as u8),
            ),
            (
                Value::from("frontier"),
                self.actor
                    .authority_frontier()
                    .map_or(Value::Nil, |bytes| Value::Binary(bytes.to_vec())),
            ),
            (
                Value::from("run_attempt"),
                self.actor
                    .run_attempt()
                    .map_or(Value::Nil, |bytes| Value::Binary(bytes.to_vec())),
            ),
            (
                Value::from("run_id"),
                self.run_id.as_deref().map_or(Value::Nil, Value::from),
            ),
            (
                Value::from("subject"),
                Value::Binary(self.subject.as_bytes().to_vec()),
            ),
            (Value::from("at"), Value::from(self.at)),
        ])
    }

    pub(super) fn from_value(value: &Value) -> Result<Self> {
        let entries = expect_map(value, "dreamer step source must be a map")?;
        let mut fields = [None; SOURCE_KEYS.len()];
        for (key, value) in entries {
            let key = expect_key(key, "dreamer step source keys must be strings")?;
            let index = pinned_key_index(key, &SOURCE_KEYS)
                .ok_or(invalid_step("dreamer step source key is not pinned"))?;
            if fields[index].replace(value).is_some() {
                return Err(invalid_step("duplicate dreamer step source key"));
            }
        }
        let fields =
            fields.map(|value| value.ok_or(invalid_step("missing dreamer step source key")));
        let [actor, class, frontier, run_attempt, run_id, subject, at] = fields;
        let actor = EntityId::from_bytes(fixed_bytes(actor?)?)?;
        let class = u8::try_from(expect_u64(
            class?,
            "dreamer step source class must be an integer",
        )?)
        .ok()
        .and_then(EdgeActorClass::try_from_u8)
        .ok_or(invalid_step("unknown dreamer step source class"))?;
        let mut actor = WriteActor::new(actor, class);
        let frontier = frontier?;
        if !frontier.is_nil() {
            actor = actor.with_authority_frontier(fixed_bytes(frontier)?);
        }
        let run_attempt = run_attempt?;
        if !run_attempt.is_nil() {
            actor = actor.with_run_attempt(fixed_bytes(run_attempt)?);
        }
        let run_id = run_id?;
        let run_id = if run_id.is_nil() {
            None
        } else {
            Some(expect_string(
                run_id,
                "dreamer step source run_id must be a string or nil",
            )?)
        };
        Ok(Self {
            actor,
            run_id,
            subject: EntityId::from_bytes(fixed_bytes(subject?)?)?,
            at: expect_u64(at?, "dreamer step source at must be an integer")?,
        })
    }
}

fn fixed_bytes<const N: usize>(value: &Value) -> Result<[u8; N]> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_step(
            "dreamer step source id or frontier must be binary",
        ));
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_step("dreamer step source id or frontier has the wrong length"))
}
