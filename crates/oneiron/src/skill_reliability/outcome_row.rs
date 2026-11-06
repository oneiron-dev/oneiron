//! Disjoint original and rule wrappers around the shared outcome payload.

use std::ops::Deref;

use rmpv::Value;

use super::codec::{decode_value, encode_value, invalid, map_entry};
use super::ledger::OutcomeRow;
use super::outcome_position::OutcomePlacement;
use super::rule_outcome::RuleOutcomeRow;
use crate::side_table::{CodecError, RawValue};

pub(super) struct OriginalOutcomeRow {
    pub(super) outcome: OutcomeRow,
    pub(super) placement: OutcomePlacement,
}

impl RawValue for OriginalOutcomeRow {
    fn to_raw(&self) -> Result<Vec<u8>, CodecError> {
        let Value::Map(mut row) = decode_value(&self.outcome.to_raw()?)? else {
            return Err(invalid("skill reliability outcome is not a map").into());
        };
        self.placement.append(&mut row)?;
        Ok(encode_value(&Value::Map(row))?)
    }

    fn from_raw(bytes: &[u8]) -> Result<Self, CodecError> {
        Ok(Self {
            outcome: OutcomeRow::from_raw(bytes)?,
            placement: OutcomePlacement::decode(&decode_value(bytes)?)?,
        })
    }
}

/// The unknown-executor table also holds typed rule outcomes. Neither arm
/// requires the other producer's metadata or duplicates its map keys.
pub(super) enum LedgerOutcomeRow {
    Original(OriginalOutcomeRow),
    Rule {
        outcome: OutcomeRow,
        native: Option<RuleOutcomeRow>,
        bytes: Vec<u8>,
    },
}

impl Deref for LedgerOutcomeRow {
    type Target = OutcomeRow;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Original(row) => &row.outcome,
            Self::Rule { outcome, .. } => outcome,
        }
    }
}

impl RawValue for LedgerOutcomeRow {
    fn to_raw(&self) -> Result<Vec<u8>, CodecError> {
        match self {
            Self::Original(row) => row.to_raw(),
            Self::Rule { bytes, .. } => Ok(bytes.clone()),
        }
    }

    fn from_raw(bytes: &[u8]) -> Result<Self, CodecError> {
        if map_entry(&decode_value(bytes)?, "rule_source").is_some() {
            // The original ledger decoded only the shared payload. Damage
            // to rule-only metadata must not turn that successful read into
            // a fatal rule decoder call; only native capture becomes unknown.
            Ok(Self::Rule {
                outcome: OutcomeRow::from_raw(bytes)?,
                native: RuleOutcomeRow::from_raw(bytes).ok(),
                bytes: bytes.to_vec(),
            })
        } else {
            OriginalOutcomeRow::from_raw(bytes).map(Self::Original)
        }
    }
}
