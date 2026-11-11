//! The house mind's read of a person's turn for its project question
//! (OF-501, ARCH-0067).
//!
//! The house mind asks its one project question over the words of a
//! person's on-record turn (`agent_dispatch/project_proposal.rs`
//! `source_text`), read under its own agent key and the relationship gate.
//! A non-owner key that no scoped grant names reads nothing, and FIX 22357
//! (#6857) moved that read under the gate with no grant for the house: every
//! question settled unread before the ladder was asked. So the shipped
//! manifest a fresh vault seeds carries one actor-bound `scoped_grants` row
//! for the seeded house, `sys.team_lead`, in the shape of the Dreamer's read
//! row: `core:read` of the MESSAGE band only, with no receipt. The
//! relationship gate still decides every MESSAGE that names a relationship
//! or a private scope, on the house's own live grants, so the row opens only
//! the vault's own, unscoped MESSAGEs.
//!
//! A house that a workspace finish or a host start binds in the seeded
//! house's place has no row of its own yet: that row comes with the house
//! bind's fix (HOUSE-BIND-ANCHOR), as an engine default.
//!
//! The unchanged shipped row supplies only an uncredentialed read floor;
//! reads carrying an explicit Scope leave it out. An owner edit makes it an
//! ordinary policy row that also caps those reads.
use std::collections::BTreeSet;
use std::sync::OnceLock;

use rmpv::Value;

use super::constants::{
    ACTOR_CLASS_KEY, ACTOR_REF_KEY, GRANT_EFFECTOR_KEY, GRANT_RECEIPT_REQUIRED_KEY,
    GRANT_SCOPE_KEY, POLICY_SCOPED_GRANTS_KEY, SCOPED_READ_EFFECTOR_CORE_READ,
};
use super::grants::PolicyScopedGrant;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_MESSAGE;

fn invalid(reason: &'static str) -> Error {
    Error::InvariantViolation(reason)
}

/// The house mind's read row: bound to `actor_ref` in the agent class, the
/// read preset narrowed to the MESSAGE band, and no receipt.
fn house_read_row(actor_ref: &str) -> Result<Value> {
    let mut scope = crate::federation::scope_codec::read_preset();
    scope.bands = crate::federation::ScopeAxis::Some(BTreeSet::from([ENTITY_TYPE_MESSAGE]));
    Ok(Value::Map(vec![
        (Value::from(ACTOR_REF_KEY), Value::from(actor_ref)),
        (
            Value::from(ACTOR_CLASS_KEY),
            Value::from(EdgeActorClass::Agent.gate_actor_class()),
        ),
        (
            Value::from(GRANT_EFFECTOR_KEY),
            Value::from(SCOPED_READ_EFFECTOR_CORE_READ),
        ),
        (
            Value::from(GRANT_SCOPE_KEY),
            crate::federation::scope_codec::encode_scope_value(&scope)?,
        ),
        (
            Value::from(GRANT_RECEIPT_REQUIRED_KEY),
            Value::Boolean(false),
        ),
    ]))
}

/// Whether this is the unchanged shipped row, compared after Scope decoding.
pub(crate) fn is_shipped_house_read_row(grant: &PolicyScopedGrant) -> bool {
    static SHIPPED_HOUSE_READ_ROW: OnceLock<Option<PolicyScopedGrant>> = OnceLock::new();
    SHIPPED_HOUSE_READ_ROW
        .get_or_init(|| {
            let house = crate::workspace_roster::seeded_house_agent().ok()??;
            let row = house_read_row(&house.to_hex()).ok()?;
            super::decode::decode_scoped_grant_table(&Value::Array(vec![row]))?.pop()
        })
        .as_ref()
        .is_some_and(|expected| grant == expected)
}

/// `manifest` with the house read row for `actor_ref` joined to its one
/// scoped-grant table.
fn with_house_read_row(mut manifest: &[u8], actor_ref: &str) -> Result<Vec<u8>> {
    let Value::Map(mut entries) =
        rmpv::decode::read_value(&mut manifest).map_err(|_| invalid("decode shipped policy"))?
    else {
        return Err(invalid("shipped policy is not a map"));
    };
    let row = house_read_row(actor_ref)?;
    match entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some(POLICY_SCOPED_GRANTS_KEY))
    {
        Some((_, Value::Array(rows))) => rows.push(row),
        Some(_) => return Err(invalid("shipped scoped grants are not a list")),
        None => entries.push((
            Value::from(POLICY_SCOPED_GRANTS_KEY),
            Value::Array(vec![row]),
        )),
    }
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &Value::Map(entries))
        .map_err(|_| invalid("encode shipped policy"))?;
    Ok(data)
}

/// The shipped manifest with the seeded house's read row: what a fresh vault
/// seeds.
pub(super) fn with_shipped_house_read(manifest: Vec<u8>) -> Result<Vec<u8>> {
    match crate::workspace_roster::seeded_house_agent()? {
        Some(house) => with_house_read_row(&manifest, &house.to_hex()),
        None => Ok(manifest),
    }
}
