//! `wait_policy` and `act_policy` row parsers.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::gate::class_policy::{
    ActPolicyRow, ActPolicyTable, ActPosture, ClassPolicyPrecedence, WaitPolicyRow, WaitPolicyTable,
};
use crate::gate::constants::{
    ACT_POLICY_CLASS_KEY, ACT_POLICY_POSTURE_KEY, ACT_POLICY_SUBJECT_CLASS_KEY,
    CLASS_POLICY_HOLDER_REF_KEY, CLASS_POLICY_PRECEDENCE_KEY, WAIT_POLICY_CLASS_KEY,
    WAIT_POLICY_MAX_SECS_KEY, WAIT_POLICY_MIN_SECS_KEY,
};

use super::decode_map_util::{
    MapValue, optional_string, required_nonempty_string, required_value, single_map_value,
};

/// Longest class string a row may carry. A class is a NAME the engine looks up,
/// never content, so the bound only keeps a manifest from carrying a blob where
/// a name belongs.
const CLASS_NAME_MAX_LEN: usize = 128;

pub(super) fn parse_wait_policy(value: &Value) -> Option<WaitPolicyTable> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut parsed: Vec<WaitPolicyRow> = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        for (key, _) in entries {
            match key.as_str()? {
                WAIT_POLICY_CLASS_KEY
                | WAIT_POLICY_MIN_SECS_KEY
                | WAIT_POLICY_MAX_SECS_KEY
                | CLASS_POLICY_HOLDER_REF_KEY
                | CLASS_POLICY_PRECEDENCE_KEY => {}
                _ => return None,
            }
        }
        let wait_class = bounded_class(entries, WAIT_POLICY_CLASS_KEY)?;
        let min_secs = required_value(entries, WAIT_POLICY_MIN_SECS_KEY)?.as_u64()?;
        let max_secs = match single_map_value(entries, WAIT_POLICY_MAX_SECS_KEY) {
            MapValue::Missing => None,
            MapValue::Duplicate => return None,
            MapValue::Present(value) => Some(value.as_u64()?),
        };
        // A row whose own floor is above its own ceiling admits no window at
        // all. That is a misauthored row, not a policy state, so it drops the
        // whole manifest rather than resolving to either bound.
        if max_secs.is_some_and(|max| min_secs > max) {
            return None;
        }
        let (holder_ref, precedence) = parse_shared_keys(entries)?;
        if duplicate_wait_key(&parsed, &wait_class, holder_ref) {
            return None;
        }
        parsed.push(WaitPolicyRow {
            wait_class,
            holder_ref,
            min_secs,
            max_secs,
            precedence,
        });
    }
    Some(WaitPolicyTable::from_rows(parsed))
}

pub(super) fn parse_act_policy(value: &Value) -> Option<ActPolicyTable> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut parsed: Vec<ActPolicyRow> = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        for (key, _) in entries {
            match key.as_str()? {
                ACT_POLICY_CLASS_KEY
                | ACT_POLICY_SUBJECT_CLASS_KEY
                | ACT_POLICY_POSTURE_KEY
                | CLASS_POLICY_HOLDER_REF_KEY
                | CLASS_POLICY_PRECEDENCE_KEY => {}
                _ => return None,
            }
        }
        let act_class = bounded_class(entries, ACT_POLICY_CLASS_KEY)?;
        let subject_class = bounded_class(entries, ACT_POLICY_SUBJECT_CLASS_KEY)?;
        // An unreadable posture drops the whole manifest, which fails the gate
        // closed. It must never fall through to the permissive arm.
        let posture =
            ActPosture::parse(required_value(entries, ACT_POLICY_POSTURE_KEY)?.as_str()?)?;
        let (holder_ref, precedence) = parse_shared_keys(entries)?;
        if duplicate_act_key(&parsed, &act_class, &subject_class, holder_ref) {
            return None;
        }
        parsed.push(ActPolicyRow {
            act_class,
            subject_class,
            holder_ref,
            posture,
            precedence,
        });
    }
    Some(ActPolicyTable::from_rows(parsed))
}

/// `holder_ref` and `holder_precedence`, shared by both tables.
///
/// A holder ref must decode to a real entity id, for the same reason an
/// actor-bound source-trust row does: a row aimed at an unreadable ref would
/// otherwise silently become a second vault row.
fn parse_shared_keys(
    entries: &[(Value, Value)],
) -> Option<(Option<EntityId>, ClassPolicyPrecedence)> {
    let holder_ref = match optional_string(entries, CLASS_POLICY_HOLDER_REF_KEY)? {
        None => None,
        Some(value) => Some(EntityId::from_hex(&value).ok()?),
    };
    let precedence = match optional_string(entries, CLASS_POLICY_PRECEDENCE_KEY)? {
        None => ClassPolicyPrecedence::default(),
        Some(value) => ClassPolicyPrecedence::parse(&value)?,
    };
    // Precedence is what the VAULT lets holders do. A holder row naming it
    // would be naming its own widener.
    if holder_ref.is_some() && precedence != ClassPolicyPrecedence::default() {
        return None;
    }
    Some((holder_ref, precedence))
}

fn bounded_class(entries: &[(Value, Value)], key: &str) -> Option<String> {
    let value = required_nonempty_string(entries, key)?;
    if value.len() > CLASS_NAME_MAX_LEN {
        return None;
    }
    Some(value)
}

/// Two rows on the same `(class, holder)` key are a rule that can never fire,
/// however strict it is: resolution folds both, so the looser one is dead text
/// and the stricter one silently rewrites what the author of the first wrote.
/// Refused per manifest, exactly as `parse_owner_policy_rows` refuses its own
/// duplicate key.
fn duplicate_wait_key(
    parsed: &[WaitPolicyRow],
    wait_class: &str,
    holder_ref: Option<EntityId>,
) -> bool {
    parsed
        .iter()
        .any(|seen| seen.wait_class == wait_class && seen.holder_ref == holder_ref)
}

fn duplicate_act_key(
    parsed: &[ActPolicyRow],
    act_class: &str,
    subject_class: &str,
    holder_ref: Option<EntityId>,
) -> bool {
    parsed.iter().any(|seen| {
        seen.act_class == act_class
            && seen.subject_class == subject_class
            && seen.holder_ref == holder_ref
    })
}
