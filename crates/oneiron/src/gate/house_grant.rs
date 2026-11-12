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
//! A workspace finish or a host start makes another seeded AGENT_DEF the
//! root's house (`workspace_roster/project/house.rs`). In that same write
//! the engine re-seeds an untouched seeded default with the body
//! [`seeded_policy_manifest_in_txn`] gives: the shipped manifest with the
//! same row for that house. It takes the seeded install every shipped
//! upgrade takes, so the row is an engine default, marked seeded and never
//! written as the owner's policy, and a later upgrade keeps it while that
//! house leads. A default the owner has authored is left as it is: there
//! the owner's own grant opens the bound house's read.
//!
//! An unchanged engine-default row, the shipped one or a bound house's,
//! supplies only an uncredentialed read floor; reads carrying an explicit
//! Scope leave it out, so the house's own Grant or verified slip reads what
//! it confers. An owner edit makes it an ordinary policy row that also caps
//! those reads.
use std::collections::BTreeSet;
use std::sync::OnceLock;

use rmpv::Value;

use super::constants::{
    ACTOR_CLASS_KEY, ACTOR_REF_KEY, GRANT_EFFECTOR_KEY, GRANT_RECEIPT_REQUIRED_KEY,
    GRANT_SCOPE_KEY, POLICY_SCOPED_GRANTS_KEY, SCOPED_READ_EFFECTOR_CORE_READ,
};
use super::grants::PolicyScopedGrant;
use crate::Vault;
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

/// Whether this is an unchanged engine-default house read row, compared
/// after Scope decoding: the shipped row of the seeded house, or the row
/// [`seeded_policy_manifest_in_txn`] adds for the house that leads the root
/// in its place. Only a seeded AGENT_DEF can be a workspace's house
/// (`workspace_roster::steps`), so the rows of the seeded system agents are
/// every row the engine writes. The candidates are built from the embedded
/// system-agent manifest's ids and the row's fixed shape, never from a stored
/// AGENT_DEF or policy row, so a re-seed or an edit cannot leave a stale
/// match. The compare is on decoded values: an owner-edited row that differs
/// from every candidate still caps, and one that decodes equal to a
/// candidate is that engine default.
pub(crate) fn is_shipped_house_read_row(grant: &PolicyScopedGrant) -> bool {
    static HOUSE_READ_ROWS: OnceLock<Vec<PolicyScopedGrant>> = OnceLock::new();
    HOUSE_READ_ROWS
        .get_or_init(|| {
            crate::agent_def::seeded_system_agent_ids()
                .unwrap_or_default()
                .iter()
                .filter_map(|house| {
                    let row = house_read_row(&house.to_hex()).ok()?;
                    super::decode::decode_scoped_grant_table(&Value::Array(vec![row]))?.pop()
                })
                .collect()
        })
        .contains(grant)
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

/// The body this vault's seeded default carries in `txn`: the shipped
/// manifest, and the house read row of the house mind that leads the root
/// when that house is not the seeded one, whose row ships.
pub(super) fn seeded_policy_manifest_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<u8>> {
    let shipped = super::default_policy_manifest()?;
    let Some(house) = crate::workspace_roster::project_house_agent_in_txn(vault, txn)? else {
        return Ok(shipped);
    };
    if Some(house) == crate::workspace_roster::seeded_house_agent()? {
        return Ok(shipped);
    }
    with_house_read_row(&shipped, &house.to_hex())
}
