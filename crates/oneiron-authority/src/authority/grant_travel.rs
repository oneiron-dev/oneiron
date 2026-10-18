//! The owner's choice of the born-with text one federation grant's windows
//! carry to another vault (OF-491, FIX 2998), and its wire codec.
//!
//! The choice never lives in the FederationGrant body. The owner makes it
//! from any surface where he is authenticated; the install that served him,
//! a live machine of the vault in any role, signs it with its install key,
//! and the authority fold meets concurrent choices: the fields every live
//! choice names travel. A choice is a main-log entry, not a world's side
//! branch, so it reaches every machine the owner admits.

use std::collections::BTreeSet;

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::share_travel::{BornWithField, TravelChoice};

use super::*;

pub const OP_KIND_GRANT_TRAVEL: &str = "grant_travel";
const GRANT_TRAVEL_KEYS: [&str; 5] = [OP_KEY_KIND, "grant", "owner", "machine", "choice"];

/// One owner choice for one federation grant, signed by the install key of
/// `machine`, a live machine of the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantTravelSet {
    /// The FEDERATION_GRANT row.
    pub grant: EntityId,
    /// The owner the door authenticated.
    pub owner: EntityId,
    pub machine: EntityId,
    /// The fields the grant's windows carry. `None` clears the choice: the
    /// grant then sends no born-with text. A choice of no field is written
    /// as `None`, so one clear has one encoding.
    pub choice: Option<TravelChoice>,
}

impl GrantTravelSet {
    pub fn validate(&self) -> Result<()> {
        if self
            .choice
            .as_ref()
            .is_some_and(|choice| choice.born_with.is_empty())
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

pub(super) fn grant_travel_value(set: &GrantTravelSet) -> Value {
    let choice = match &set.choice {
        None => Value::Nil,
        Some(choice) => Value::Array(
            choice
                .born_with
                .iter()
                .map(|field| Value::from(field.as_str()))
                .collect(),
        ),
    };
    Value::Map(vec![
        (Value::from(OP_KEY_KIND), Value::from(OP_KIND_GRANT_TRAVEL)),
        (Value::from("grant"), Value::from(set.grant.to_hex())),
        (Value::from("owner"), Value::from(set.owner.to_hex())),
        (Value::from("machine"), Value::from(set.machine.to_hex())),
        (Value::from("choice"), choice),
    ])
}

/// Each field name once, from the four born-with names; the envelope's
/// canonical re-encode then pins their order.
pub(super) fn decode_grant_travel(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &GRANT_TRAVEL_KEYS)?;
    let choice = match required(entries, "choice")? {
        Value::Nil => None,
        Value::Array(names) => {
            let mut born_with = BTreeSet::new();
            for name in names {
                let field = name
                    .as_str()
                    .and_then(BornWithField::from_name)
                    .ok_or_else(invalid_authority)?;
                if !born_with.insert(field) {
                    return Err(invalid_authority());
                }
            }
            Some(TravelChoice { born_with })
        }
        _ => return Err(invalid_authority()),
    };
    Ok(AuthorityOp::GrantTravelSet(GrantTravelSet {
        grant: decode_canonical_id(required(entries, "grant")?)?,
        owner: decode_canonical_id(required(entries, "owner")?)?,
        machine: decode_canonical_id(required(entries, "machine")?)?,
        choice,
    }))
}
