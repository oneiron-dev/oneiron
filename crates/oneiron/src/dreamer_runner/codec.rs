//! MessagePack row codecs, LMDB key builders, and validators for the
//! private Dreamer runner rows.

use rmpv::Value;

use crate::code_run::WaitKey;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::Result;
use crate::side_table::{CodecError, RawValue};

use crate::workspace_roster::spend_scope::SpendScopeId;

use super::constants::{
    DREAMER_HOME_NODE_DESIGNATION_KEYS, DREAMER_HOME_NODE_DESIGNATION_SCHEMA_VERSION,
    DREAMER_PARKED_KEYS, DREAMER_PARKED_SCHEMA_VERSION, DREAMER_PARKED_WAIT_KEYS,
    DREAMER_RUN_TREE_KEYS, DREAMER_RUN_TREE_SCHEMA_VERSION, KEY_ATTEMPT_ID, KEY_CARRIED_SPEND,
    KEY_CAUSE, KEY_CLASS, KEY_CREATED_AT, KEY_ELECTED_AT, KEY_NODE_ID, KEY_PARENT_ATTEMPT,
    KEY_PARK_OWNER, KEY_PARKED_AT, KEY_REASON, KEY_SCHEMA_VERSION, KEY_WAIT, KEY_WAIT_ASKED_UNITS,
    KEY_WAIT_GENERATION, KEY_WAIT_ID, KEY_WAIT_LEASE_GENERATION, KEY_WAIT_RESET_AT_S, KEY_WAIT_RUN,
    KEY_WAIT_SCOPE, KEY_WAIT_SEAT, KEY_WAIT_SEAT_GENERATION,
};
use super::types::{
    DreamerHomeNodeClass, DreamerHomeNodeDesignation, DreamerParkCause, DreamerParkWait,
    DreamerParkWaitClass, DreamerParkedAttemptRecord, DreamerParkedWait, DreamerRunTreeRecord,
};

mod budget;

pub(super) use self::budget::{validate_budget_record, validate_budget_reservation};
pub(super) use crate::store::dreamer_attempt_payload::{
    decode_attempt_id, decode_optional_attempt_id, decode_value, encode_attempt_id,
    encode_optional_attempt_id, encode_value, expect_key, expect_map, expect_string, expect_u64,
    invalid_dreamer_runner, pinned_key_index, validate_attempt_type,
};
pub use crate::store::dreamer_attempt_payload::{
    decode_dreamer_attempt_payload, encode_dreamer_attempt_payload,
};

pub(super) fn encode_home_node_designation(record: &DreamerHomeNodeDesignation) -> Result<Vec<u8>> {
    validate_home_node_designation(record)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_HOME_NODE_DESIGNATION_SCHEMA_VERSION),
        ),
        (Value::from(KEY_NODE_ID), Value::from(record.node_id)),
        (Value::from(KEY_CLASS), Value::from(record.class.as_str())),
        (Value::from(KEY_ELECTED_AT), Value::from(record.elected_at)),
    ]);
    encode_value(&value, "dreamer home-node MessagePack encode failed")
}

pub(super) fn decode_home_node_designation(bytes: &[u8]) -> Result<DreamerHomeNodeDesignation> {
    let value = decode_value(bytes)?;
    let entries = expect_map(&value, "dreamer home-node row must be a MessagePack map")?;
    let mut schema_version = None;
    let mut node_id = None;
    let mut class = None;
    let mut elected_at = None;
    let mut seen = [false; DREAMER_HOME_NODE_DESIGNATION_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer home-node keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_HOME_NODE_DESIGNATION_KEYS).ok_or(
            invalid_dreamer_runner("dreamer home-node key is not pinned"),
        )?;
        if seen[index] {
            return Err(invalid_dreamer_runner("duplicate dreamer home-node key"));
        }
        seen[index] = true;

        match DREAMER_HOME_NODE_DESIGNATION_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer home-node schema_version must be an integer",
                )?);
            }
            KEY_NODE_ID => {
                node_id = Some(expect_u64(
                    value,
                    "dreamer home-node node_id must be an integer",
                )?);
            }
            KEY_CLASS => {
                let parsed = expect_string(value, "dreamer home-node class must be a string")?;
                class = Some(
                    DreamerHomeNodeClass::parse(&parsed)
                        .ok_or(invalid_dreamer_runner("invalid dreamer home-node class"))?,
                );
            }
            KEY_ELECTED_AT => {
                elected_at = Some(expect_u64(
                    value,
                    "dreamer home-node elected_at must be an integer",
                )?);
            }
            _ => unreachable!("index resolved from DREAMER_HOME_NODE_DESIGNATION_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer home-node schema_version",
    ))?;
    if schema_version != DREAMER_HOME_NODE_DESIGNATION_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer home-node schema_version",
        ));
    }
    let record = DreamerHomeNodeDesignation {
        node_id: node_id.ok_or(invalid_dreamer_runner("missing dreamer home-node node_id"))?,
        class: class.ok_or(invalid_dreamer_runner("missing dreamer home-node class"))?,
        elected_at: elected_at.ok_or(invalid_dreamer_runner(
            "missing dreamer home-node elected_at",
        ))?,
    };
    validate_home_node_designation(&record)?;
    Ok(record)
}

impl RawValue for DreamerHomeNodeDesignation {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_home_node_designation(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_home_node_designation(bytes)?)
    }
}

pub(super) fn encode_run_tree_record(record: &DreamerRunTreeRecord) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_RUN_TREE_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_ATTEMPT_ID),
            encode_attempt_id(record.attempt_id),
        ),
        (
            Value::from(KEY_PARENT_ATTEMPT),
            encode_optional_attempt_id(record.parent_attempt),
        ),
        (Value::from(KEY_CREATED_AT), Value::from(record.created_at)),
    ]);
    encode_value(&value, "dreamer run-tree MessagePack encode failed")
}

pub(super) fn decode_run_tree_record(bytes: &[u8]) -> Result<DreamerRunTreeRecord> {
    let value = decode_value(bytes)?;
    let entries = expect_map(&value, "dreamer run-tree row must be a MessagePack map")?;
    let mut schema_version = None;
    let mut attempt_id = None;
    let mut parent_attempt = None;
    let mut created_at = None;
    let mut seen = [false; DREAMER_RUN_TREE_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer run-tree keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_RUN_TREE_KEYS)
            .ok_or(invalid_dreamer_runner("dreamer run-tree key is not pinned"))?;
        if seen[index] {
            return Err(invalid_dreamer_runner("duplicate dreamer run-tree key"));
        }
        seen[index] = true;

        match DREAMER_RUN_TREE_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer run-tree schema_version must be an integer",
                )?);
            }
            KEY_ATTEMPT_ID => attempt_id = Some(decode_attempt_id(value)?),
            KEY_PARENT_ATTEMPT => parent_attempt = Some(decode_optional_attempt_id(value)?),
            KEY_CREATED_AT => {
                created_at = Some(expect_u64(
                    value,
                    "dreamer run-tree created_at must be an integer",
                )?);
            }
            _ => unreachable!("index resolved from DREAMER_RUN_TREE_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer run-tree schema_version",
    ))?;
    if schema_version != DREAMER_RUN_TREE_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer run-tree schema_version",
        ));
    }

    Ok(DreamerRunTreeRecord {
        attempt_id: attempt_id.ok_or(invalid_dreamer_runner("missing dreamer run-tree job_id"))?,
        parent_attempt: parent_attempt.ok_or(invalid_dreamer_runner(
            "missing dreamer run-tree parent_job",
        ))?,
        created_at: created_at.ok_or(invalid_dreamer_runner(
            "missing dreamer run-tree created_at",
        ))?,
    })
}

impl RawValue for DreamerRunTreeRecord {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_run_tree_record(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_run_tree_record(bytes)?)
    }
}

fn encode_parked_wait(wait: Option<&DreamerParkedWait>) -> Value {
    wait.map_or(Value::Nil, |wait| {
        let class = Value::from(wait.wait.class().as_str());
        let lease_generation = (
            Value::from(KEY_WAIT_LEASE_GENERATION),
            Value::from(wait.lease_generation),
        );
        // Key order is `DREAMER_PARKED_WAIT_KEYS`, filtered to the class's set.
        let entries = match &wait.wait {
            DreamerParkWait::Budget { scope, asked_units } => vec![
                (Value::from(KEY_CLASS), class),
                (Value::from(KEY_WAIT_SCOPE), Value::from(scope.as_str())),
                (Value::from(KEY_WAIT_ASKED_UNITS), Value::from(*asked_units)),
                lease_generation,
            ],
            DreamerParkWait::PassBudget { asked_units, scope } => {
                let mut entries = vec![(Value::from(KEY_CLASS), class)];
                // The scope key only when the wait names one, as the seat's reset time.
                if let Some(scope) = scope {
                    entries.push((Value::from(KEY_WAIT_SCOPE), Value::from(scope.as_str())));
                }
                entries.push((Value::from(KEY_WAIT_ASKED_UNITS), Value::from(*asked_units)));
                entries.push(lease_generation);
                entries
            }
            DreamerParkWait::Consent { key }
            | DreamerParkWait::Peer { key }
            | DreamerParkWait::Human { key } => vec![
                (Value::from(KEY_CLASS), class),
                lease_generation,
                (
                    Value::from(KEY_WAIT_RUN),
                    Value::Binary(key.run.as_bytes().to_vec()),
                ),
                (
                    Value::from(KEY_WAIT_ID),
                    Value::Binary(key.wait_id.as_bytes().to_vec()),
                ),
                (
                    Value::from(KEY_WAIT_GENERATION),
                    Value::from(key.generation),
                ),
            ],
            DreamerParkWait::Seat {
                seat,
                generation,
                reset_at_s,
            } => {
                let mut entries = vec![
                    (Value::from(KEY_CLASS), class),
                    lease_generation,
                    (
                        Value::from(KEY_WAIT_SEAT),
                        Value::Binary(seat.as_bytes().to_vec()),
                    ),
                    (
                        Value::from(KEY_WAIT_SEAT_GENERATION),
                        Value::from(*generation),
                    ),
                ];
                if let Some(reset_at_s) = reset_at_s {
                    entries.push((Value::from(KEY_WAIT_RESET_AT_S), Value::from(*reset_at_s)));
                }
                entries
            }
        };
        Value::Map(entries)
    })
}

fn decode_wait_entity_id(value: &Value, reason: &'static str) -> Result<EntityId> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_dreamer_runner(reason));
    };
    let raw: [u8; ENTITY_ID_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_dreamer_runner(reason))?;
    EntityId::from_bytes(raw).map_err(|_| invalid_dreamer_runner(reason))
}

pub(super) fn encode_parked_record(record: &DreamerParkedAttemptRecord) -> Result<Vec<u8>> {
    validate_park_reason(&record.reason)?;
    validate_park_owner(&record.park_owner)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_PARKED_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_ATTEMPT_ID),
            encode_attempt_id(record.attempt_id),
        ),
        (Value::from(KEY_REASON), Value::from(record.reason.as_str())),
        (Value::from(KEY_CAUSE), Value::from(record.cause.as_str())),
        (
            Value::from(KEY_PARK_OWNER),
            Value::from(record.park_owner.as_str()),
        ),
        (
            Value::from(KEY_CARRIED_SPEND),
            record.carried_spend.map_or(Value::Nil, Value::from),
        ),
        (Value::from(KEY_PARKED_AT), Value::from(record.parked_at)),
        (
            Value::from(KEY_WAIT),
            encode_parked_wait(record.wait.as_ref()),
        ),
    ]);
    encode_value(&value, "dreamer parked row MessagePack encode failed")
}

fn decode_parked_wait(value: &Value) -> Result<DreamerParkedWait> {
    let entries = expect_map(value, "dreamer parked wait must be a MessagePack map")?;
    let mut class = None;
    let mut scope = None;
    let mut asked_units = None;
    let mut lease_generation = None;
    let mut wait_run = None;
    let mut wait_id = None;
    let mut wait_generation = None;
    let mut seat = None;
    let mut seat_generation = None;
    let mut reset_at_s = None;
    let mut seen = [false; DREAMER_PARKED_WAIT_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer parked wait keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_PARKED_WAIT_KEYS).ok_or(
            invalid_dreamer_runner("dreamer parked wait key is not pinned"),
        )?;
        if seen[index] {
            return Err(invalid_dreamer_runner("duplicate dreamer parked wait key"));
        }
        seen[index] = true;

        match DREAMER_PARKED_WAIT_KEYS[index] {
            KEY_CLASS => {
                let parsed = expect_string(value, "dreamer parked wait class must be a string")?;
                class = Some(
                    DreamerParkWaitClass::parse(&parsed)
                        .ok_or(invalid_dreamer_runner("invalid dreamer parked wait class"))?,
                );
            }
            KEY_WAIT_SCOPE => {
                scope = Some(expect_string(
                    value,
                    "dreamer parked wait scope must be a string",
                )?);
            }
            KEY_WAIT_ASKED_UNITS => {
                asked_units = Some(expect_u64(
                    value,
                    "dreamer parked wait asked_units must be an integer",
                )?);
            }
            KEY_WAIT_LEASE_GENERATION => {
                let generation = expect_u64(
                    value,
                    "dreamer parked wait lease_generation must be an integer",
                )?;
                lease_generation = Some(u32::try_from(generation).map_err(|_| {
                    invalid_dreamer_runner("dreamer parked wait lease_generation overflows u32")
                })?);
            }
            KEY_WAIT_RUN => {
                wait_run = Some(decode_wait_entity_id(
                    value,
                    "dreamer parked wait wait_run must be 16-byte binary",
                )?);
            }
            KEY_WAIT_ID => {
                wait_id = Some(decode_wait_entity_id(
                    value,
                    "dreamer parked wait wait_id must be 16-byte binary",
                )?);
            }
            KEY_WAIT_GENERATION => {
                wait_generation = Some(expect_u64(
                    value,
                    "dreamer parked wait wait_generation must be an integer",
                )?);
            }
            KEY_WAIT_SEAT => {
                seat = Some(decode_wait_entity_id(
                    value,
                    "dreamer parked wait seat must be 16-byte binary",
                )?);
            }
            KEY_WAIT_SEAT_GENERATION => {
                seat_generation = Some(expect_u64(
                    value,
                    "dreamer parked wait seat_generation must be an integer",
                )?);
            }
            KEY_WAIT_RESET_AT_S => {
                reset_at_s = Some(expect_u64(
                    value,
                    "dreamer parked wait reset_at_s must be an integer",
                )?);
            }
            _ => unreachable!("index resolved from DREAMER_PARKED_WAIT_KEYS"),
        }
    }

    let class = class.ok_or(invalid_dreamer_runner("missing dreamer parked wait class"))?;
    let lease_generation = lease_generation.ok_or(invalid_dreamer_runner(
        "missing dreamer parked wait lease_generation",
    ))?;
    let wait = match class {
        DreamerParkWaitClass::Budget => {
            if wait_run.is_some()
                || wait_id.is_some()
                || wait_generation.is_some()
                || seat.is_some()
                || seat_generation.is_some()
                || reset_at_s.is_some()
            {
                return Err(invalid_dreamer_runner(
                    "dreamer parked wait key does not belong to its class",
                ));
            }
            DreamerParkWait::Budget {
                scope: SpendScopeId(
                    scope.ok_or(invalid_dreamer_runner("missing dreamer parked wait scope"))?,
                ),
                asked_units: asked_units.ok_or(invalid_dreamer_runner(
                    "missing dreamer parked wait asked_units",
                ))?,
            }
        }
        DreamerParkWaitClass::PassBudget => {
            if wait_run.is_some()
                || wait_id.is_some()
                || wait_generation.is_some()
                || seat.is_some()
                || seat_generation.is_some()
                || reset_at_s.is_some()
            {
                return Err(invalid_dreamer_runner(
                    "dreamer parked wait key does not belong to its class",
                ));
            }
            DreamerParkWait::PassBudget {
                asked_units: asked_units.ok_or(invalid_dreamer_runner(
                    "missing dreamer parked wait asked_units",
                ))?,
                scope: scope.map(SpendScopeId),
            }
        }
        DreamerParkWaitClass::Seat => {
            if scope.is_some()
                || asked_units.is_some()
                || wait_run.is_some()
                || wait_id.is_some()
                || wait_generation.is_some()
            {
                return Err(invalid_dreamer_runner(
                    "dreamer parked wait key does not belong to its class",
                ));
            }
            DreamerParkWait::Seat {
                seat: seat.ok_or(invalid_dreamer_runner("missing dreamer parked wait seat"))?,
                generation: seat_generation.ok_or(invalid_dreamer_runner(
                    "missing dreamer parked wait seat_generation",
                ))?,
                reset_at_s,
            }
        }
        answer => {
            if scope.is_some()
                || asked_units.is_some()
                || seat.is_some()
                || seat_generation.is_some()
                || reset_at_s.is_some()
            {
                return Err(invalid_dreamer_runner(
                    "dreamer parked wait key does not belong to its class",
                ));
            }
            let key = WaitKey {
                run: wait_run.ok_or(invalid_dreamer_runner(
                    "missing dreamer parked wait wait_run",
                ))?,
                wait_id: wait_id.ok_or(invalid_dreamer_runner(
                    "missing dreamer parked wait wait_id",
                ))?,
                generation: wait_generation.ok_or(invalid_dreamer_runner(
                    "missing dreamer parked wait wait_generation",
                ))?,
            };
            match answer {
                DreamerParkWaitClass::Consent => DreamerParkWait::Consent { key },
                DreamerParkWaitClass::Peer => DreamerParkWait::Peer { key },
                DreamerParkWaitClass::Human => DreamerParkWait::Human { key },
                DreamerParkWaitClass::Budget
                | DreamerParkWaitClass::PassBudget
                | DreamerParkWaitClass::Seat => {
                    unreachable!("budget, pass budget and seat waits decode above")
                }
            }
        }
    };
    Ok(DreamerParkedWait {
        wait,
        lease_generation,
    })
}

pub(super) fn decode_parked_record(bytes: &[u8]) -> Result<DreamerParkedAttemptRecord> {
    let value = decode_value(bytes)?;
    let entries = expect_map(&value, "dreamer parked row must be a MessagePack map")?;
    let mut schema_version = None;
    let mut attempt_id = None;
    let mut reason = None;
    let mut cause = None;
    let mut park_owner = None;
    let mut carried_spend: Option<Option<u64>> = None;
    let mut parked_at = None;
    let mut wait: Option<Option<DreamerParkedWait>> = None;
    let mut seen = [false; DREAMER_PARKED_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer parked row keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_PARKED_KEYS).ok_or(invalid_dreamer_runner(
            "dreamer parked row key is not pinned",
        ))?;
        if seen[index] {
            return Err(invalid_dreamer_runner("duplicate dreamer parked row key"));
        }
        seen[index] = true;

        match DREAMER_PARKED_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer parked row schema_version must be an integer",
                )?);
            }
            KEY_ATTEMPT_ID => attempt_id = Some(decode_attempt_id(value)?),
            KEY_REASON => {
                let parsed = expect_string(value, "dreamer parked reason must be a string")?;
                validate_park_reason(&parsed)?;
                reason = Some(parsed);
            }
            KEY_CAUSE => {
                let parsed = expect_string(value, "dreamer parked cause must be a string")?;
                cause = Some(
                    DreamerParkCause::parse(&parsed)
                        .ok_or(invalid_dreamer_runner("invalid dreamer parked cause"))?,
                );
            }
            KEY_PARK_OWNER => {
                let parsed = expect_string(value, "dreamer parked park_owner must be a string")?;
                validate_park_owner(&parsed)?;
                park_owner = Some(parsed);
            }
            KEY_CARRIED_SPEND => {
                if matches!(value, Value::Nil) {
                    carried_spend = Some(None);
                } else {
                    carried_spend = Some(Some(expect_u64(
                        value,
                        "dreamer parked carried_spend must be an integer",
                    )?));
                }
            }
            KEY_PARKED_AT => {
                parked_at = Some(expect_u64(value, "dreamer parked_at must be an integer")?);
            }
            KEY_WAIT => {
                if matches!(value, Value::Nil) {
                    wait = Some(None);
                } else {
                    wait = Some(Some(decode_parked_wait(value)?));
                }
            }
            _ => unreachable!("index resolved from DREAMER_PARKED_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer parked row schema_version",
    ))?;
    if schema_version != DREAMER_PARKED_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer parked row schema_version",
        ));
    }

    Ok(DreamerParkedAttemptRecord {
        attempt_id: attempt_id.ok_or(invalid_dreamer_runner("missing dreamer parked job_id"))?,
        reason: reason.ok_or(invalid_dreamer_runner("missing dreamer parked reason"))?,
        cause: cause.ok_or(invalid_dreamer_runner("missing dreamer parked cause"))?,
        park_owner: park_owner
            .ok_or(invalid_dreamer_runner("missing dreamer parked park_owner"))?,
        carried_spend: carried_spend.ok_or(invalid_dreamer_runner(
            "missing dreamer parked carried_spend",
        ))?,
        parked_at: parked_at.ok_or(invalid_dreamer_runner("missing dreamer parked_at"))?,
        wait: wait.ok_or(invalid_dreamer_runner("missing dreamer parked wait"))?,
    })
}

impl RawValue for DreamerParkedAttemptRecord {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_parked_record(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_parked_record(bytes)?)
    }
}

pub(super) fn validate_budget_id(budget_id: &str) -> Result<()> {
    if budget_id.is_empty() {
        return Err(invalid_dreamer_runner(
            "dreamer budget_id must not be empty",
        ));
    }
    Ok(())
}

pub(super) fn validate_park_reason(reason: &str) -> Result<()> {
    if reason.is_empty() {
        return Err(invalid_dreamer_runner(
            "dreamer parked reason must not be empty",
        ));
    }
    Ok(())
}

pub(super) fn validate_park_owner(park_owner: &str) -> Result<()> {
    if park_owner.is_empty() {
        return Err(invalid_dreamer_runner(
            "dreamer parked park_owner must not be empty",
        ));
    }
    Ok(())
}

pub(super) fn validate_home_node_designation(record: &DreamerHomeNodeDesignation) -> Result<()> {
    if record.node_id == 0 {
        return Err(invalid_dreamer_runner(
            "dreamer home node_id must be nonzero",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::attempt_queue::AttemptId;
    use crate::workspace_roster::spend_scope::SpendScopeId;

    use super::*;

    fn parked_record(wait: Option<DreamerParkedWait>) -> DreamerParkedAttemptRecord {
        DreamerParkedAttemptRecord {
            attempt_id: AttemptId::from_bytes(&[9; 16]).expect("test attempt id reads"),
            reason: "budget trap".to_owned(),
            cause: DreamerParkCause::Signal,
            park_owner: "dreamer.trap:00ff".to_owned(),
            carried_spend: None,
            parked_at: 7,
            wait,
        }
    }

    fn budget_wait() -> DreamerParkedWait {
        DreamerParkedWait {
            wait: DreamerParkWait::Budget {
                scope: SpendScopeId::launch("test-launch").expect("test scope reads"),
                asked_units: 11,
            },
            lease_generation: 3,
        }
    }

    fn answer_key() -> WaitKey {
        WaitKey {
            run: EntityId::from_bytes([7; 16]).expect("test run id reads"),
            wait_id: EntityId::from_bytes([8; 16]).expect("test wait id reads"),
            generation: 2,
        }
    }

    fn answer_wait(class: DreamerParkWaitClass) -> DreamerParkedWait {
        let key = answer_key();
        let wait = match class {
            DreamerParkWaitClass::Consent => DreamerParkWait::Consent { key },
            DreamerParkWaitClass::Peer => DreamerParkWait::Peer { key },
            DreamerParkWaitClass::Human => DreamerParkWait::Human { key },
            DreamerParkWaitClass::Budget
            | DreamerParkWaitClass::PassBudget
            | DreamerParkWaitClass::Seat => {
                unreachable!("answer waits only")
            }
        };
        DreamerParkedWait {
            wait,
            lease_generation: 5,
        }
    }

    fn answer_wait_value(class: &str, omit: Option<&str>, extra: Option<(&str, Value)>) -> Value {
        let key = answer_key();
        let mut entries = vec![
            (Value::from(KEY_CLASS), Value::from(class)),
            (Value::from(KEY_WAIT_LEASE_GENERATION), Value::from(5_u32)),
            (
                Value::from(KEY_WAIT_RUN),
                Value::Binary(key.run.as_bytes().to_vec()),
            ),
            (
                Value::from(KEY_WAIT_ID),
                Value::Binary(key.wait_id.as_bytes().to_vec()),
            ),
            (
                Value::from(KEY_WAIT_GENERATION),
                Value::from(key.generation),
            ),
        ];
        if let Some(omit) = omit {
            entries.retain(|(key, _)| key.as_str() != Some(omit));
        }
        if let Some((key, value)) = extra {
            entries.push((Value::from(key), value));
        }
        Value::Map(entries)
    }

    fn wait_value(class: &str, extra: Option<(&str, Value)>) -> Value {
        let mut entries = vec![
            (Value::from(KEY_CLASS), Value::from(class)),
            (Value::from(KEY_WAIT_SCOPE), Value::from("test-launch")),
            (Value::from(KEY_WAIT_ASKED_UNITS), Value::from(11_u64)),
            (Value::from(KEY_WAIT_LEASE_GENERATION), Value::from(3_u32)),
        ];
        if let Some((key, value)) = extra {
            entries.push((Value::from(key), value));
        }
        Value::Map(entries)
    }

    fn seat_wait(reset_at_s: Option<u64>) -> DreamerParkedWait {
        DreamerParkedWait {
            wait: DreamerParkWait::Seat {
                seat: EntityId::from_bytes([0x71; 16]).expect("test seat id reads"),
                generation: 2,
                reset_at_s,
            },
            lease_generation: 4,
        }
    }

    fn seat_wait_value(omit: Option<&str>) -> Value {
        let seat = EntityId::from_bytes([0x71; 16]).expect("test seat id reads");
        let mut entries = vec![
            (Value::from(KEY_CLASS), Value::from("seat")),
            (Value::from(KEY_WAIT_LEASE_GENERATION), Value::from(4_u32)),
            (
                Value::from(KEY_WAIT_SEAT),
                Value::Binary(seat.as_bytes().to_vec()),
            ),
            (Value::from(KEY_WAIT_SEAT_GENERATION), Value::from(2_u64)),
            (Value::from(KEY_WAIT_RESET_AT_S), Value::from(90_u64)),
        ];
        if let Some(omit) = omit {
            entries.retain(|(key, _)| key.as_str() != Some(omit));
        }
        Value::Map(entries)
    }

    fn row_bytes(schema_version: u64, wait: Option<Value>) -> Vec<u8> {
        let record = parked_record(None);
        let mut entries = vec![
            (Value::from(KEY_SCHEMA_VERSION), Value::from(schema_version)),
            (
                Value::from(KEY_ATTEMPT_ID),
                encode_attempt_id(record.attempt_id),
            ),
            (Value::from(KEY_REASON), Value::from(record.reason.as_str())),
            (Value::from(KEY_CAUSE), Value::from(record.cause.as_str())),
            (
                Value::from(KEY_PARK_OWNER),
                Value::from(record.park_owner.as_str()),
            ),
            (Value::from(KEY_CARRIED_SPEND), Value::Nil),
            (Value::from(KEY_PARKED_AT), Value::from(record.parked_at)),
        ];
        if let Some(wait) = wait {
            entries.push((Value::from(KEY_WAIT), wait));
        }
        let value = Value::Map(entries);
        encode_value(&value, "test parked row encodes").expect("test parked row encodes")
    }

    #[test]
    fn parked_rows_round_trip_with_and_without_a_wait() {
        let pass_budget = DreamerParkedWait {
            wait: DreamerParkWait::PassBudget {
                asked_units: 500,
                scope: None,
            },
            lease_generation: 3,
        };
        let scoped_pass_budget = DreamerParkedWait {
            wait: DreamerParkWait::PassBudget {
                asked_units: 500,
                scope: Some(SpendScopeId::launch("free_time:cycle").expect("test scope reads")),
            },
            lease_generation: 3,
        };
        for wait in [
            None,
            Some(budget_wait()),
            Some(pass_budget),
            Some(scoped_pass_budget),
        ] {
            let record = parked_record(wait);
            let bytes = encode_parked_record(&record).expect("parked row encodes");
            let decoded = decode_parked_record(&bytes).expect("parked row decodes");
            assert_eq!(decoded, record, "a parked row round-trips its wait");
        }
    }

    #[test]
    fn a_v3_parked_row_fails_closed() {
        let bytes = row_bytes(3, None);
        assert!(
            decode_parked_record(&bytes).is_err(),
            "a v3 parked row has no wait key and fails decode"
        );
    }

    #[test]
    fn a_v4_parked_row_without_wait_fails() {
        let bytes = row_bytes(DREAMER_PARKED_SCHEMA_VERSION, None);
        assert!(
            decode_parked_record(&bytes).is_err(),
            "a v4 parked row without wait fails decode"
        );
    }

    #[test]
    fn a_parked_wait_with_an_unknown_class_fails() {
        let bytes = row_bytes(
            DREAMER_PARKED_SCHEMA_VERSION,
            Some(wait_value("funding", None)),
        );
        assert!(
            decode_parked_record(&bytes).is_err(),
            "a parked wait with an unknown class fails decode"
        );
    }

    #[test]
    fn a_parked_wait_with_an_unknown_key_fails() {
        let bytes = row_bytes(
            DREAMER_PARKED_SCHEMA_VERSION,
            Some(wait_value("budget", Some(("granted_by", Value::Nil)))),
        );
        assert!(
            decode_parked_record(&bytes).is_err(),
            "a parked wait with an unknown key fails decode"
        );
    }

    #[test]
    fn answer_parks_round_trip_their_wait_key() {
        for class in [
            DreamerParkWaitClass::Consent,
            DreamerParkWaitClass::Peer,
            DreamerParkWaitClass::Human,
        ] {
            let record = parked_record(Some(answer_wait(class)));
            let bytes = encode_parked_record(&record).expect("parked row encodes");
            let decoded = decode_parked_record(&bytes).expect("parked row decodes");
            assert_eq!(decoded, record, "an answer park round-trips its wait key");
        }
    }

    #[test]
    fn a_consent_wait_with_a_budget_key_fails() {
        let bytes = row_bytes(
            DREAMER_PARKED_SCHEMA_VERSION,
            Some(answer_wait_value(
                "consent",
                None,
                Some((KEY_WAIT_SCOPE, Value::from("test-launch"))),
            )),
        );
        assert!(
            decode_parked_record(&bytes).is_err(),
            "a consent wait carrying scope fails decode"
        );
    }

    #[test]
    fn a_peer_wait_without_wait_id_fails() {
        let bytes = row_bytes(
            DREAMER_PARKED_SCHEMA_VERSION,
            Some(answer_wait_value("peer", Some(KEY_WAIT_ID), None)),
        );
        assert!(
            decode_parked_record(&bytes).is_err(),
            "a peer wait without wait_id fails decode"
        );
    }

    #[test]
    fn seat_parks_round_trip_with_and_without_a_reset() {
        for reset_at_s in [Some(90), None] {
            let record = parked_record(Some(seat_wait(reset_at_s)));
            let bytes = encode_parked_record(&record).expect("parked row encodes");
            let decoded = decode_parked_record(&bytes).expect("parked row decodes");
            assert_eq!(decoded, record, "a seat park round-trips its seat wait");
        }
    }

    #[test]
    fn a_seat_wait_without_seat_generation_fails() {
        let bytes = row_bytes(
            DREAMER_PARKED_SCHEMA_VERSION,
            Some(seat_wait_value(Some(KEY_WAIT_SEAT_GENERATION))),
        );
        assert!(
            decode_parked_record(&bytes).is_err(),
            "a seat wait without seat_generation fails decode"
        );
    }
}
