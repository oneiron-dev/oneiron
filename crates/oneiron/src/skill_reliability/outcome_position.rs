//! Original producer placement for the physical outcome, amendment and marker rows.

use std::collections::BTreeSet;

use oneiron_authority::federation::Scope;
use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::side_table::CodecError;
use crate::store::GateReadAnchors;
use crate::{EntityId, Vault};

use super::codec::{invalid, map_entry};

/// Original caller-requested placement for a derived physical outcome.
///
/// This is output placement data, not a read grant or a supporting row's identity.
/// It is consumed only at physical birth; a later request cannot restamp a row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeReadPosition {
    pub scope: Scope,
    pub kind_band: u8,
    pub relationship: Option<BTreeSet<EntityId>>,
    pub private: bool,
    pub body_worlds: Vec<EntityId>,
    pub body_facets: Vec<EntityId>,
    pub anchors: GateReadAnchors,
}

/// Metadata is part of its physical row, not a second keyed registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct OutcomePlacement {
    pub(super) row_id: Option<EntityId>,
    pub(super) read_position: Option<OutcomeReadPosition>,
}

impl OutcomePlacement {
    pub(super) fn unknown() -> Self {
        Self {
            row_id: None,
            read_position: None,
        }
    }

    pub(super) fn birth(vault: &Vault, position: Option<&OutcomeReadPosition>) -> Self {
        let row_id = vault.store.clock.entity_id().ok();
        Self {
            row_id,
            read_position: row_id.and(position.cloned()),
        }
    }

    pub(super) fn retained(&self, same: bool) -> Self {
        Self {
            row_id: self.row_id,
            read_position: same.then(|| self.read_position.clone()).flatten(),
        }
    }

    pub(super) fn append(&self, row: &mut Vec<(Value, Value)>) -> Result<(), CodecError> {
        let identity = rmpv::ext::to_value(self.row_id)
            .map_err(|_| invalid("outcome identity encode failed"))?;
        let position = rmpv::ext::to_value(&self.read_position)
            .map_err(|_| invalid("outcome position encode failed"))?;
        row.push((
            Value::from("native_outcome"),
            Value::Map(vec![
                (Value::from("row_id"), identity),
                (Value::from("read_position"), position),
            ]),
        ));
        Ok(())
    }

    pub(super) fn decode(value: &Value) -> Result<Self, CodecError> {
        let metadata = map_entry(value, "native_outcome")
            .ok_or(invalid("outcome is missing its native metadata"))?;
        let row_id = rmpv::ext::from_value(
            map_entry(metadata, "row_id")
                .ok_or(invalid("outcome is missing its identity"))?
                .clone(),
        )
        .map_err(|_| invalid("outcome identity decode failed"))?;
        let read_position = rmpv::ext::from_value(
            map_entry(metadata, "read_position")
                .ok_or(invalid("outcome is missing its position"))?
                .clone(),
        )
        .map_err(|_| invalid("outcome position decode failed"))?;
        Ok(Self {
            row_id,
            read_position,
        })
    }
}
