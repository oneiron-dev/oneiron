//! Doors to the free-time policy rows a home move carries (FABLE-6918-2): the
//! table's own export and adoption, as a move runs them, here with no move;
//! and one agent's stored policy row, so a test can stand a home that has not
//! seen a later act.

use crate::dreamer_runner::FreeTimePolicyRows;
use crate::{EntityId, Result, Vault};

/// The policy rows a move carries: the facts and each actor's content,
/// encoded as the carrier encodes them.
pub struct CarriedPolicyRows {
    facts: Vec<u8>,
    actors: Vec<Vec<u8>>,
}

/// One agent's stored policy row, encoded.
pub struct StoredPolicyRow(Vec<u8>);

/// Every policy row of `vault`, as a move exports them.
///
/// # Errors
/// A store read that fails or a row that does not encode.
pub fn export_policy_rows(vault: &Vault) -> Result<CarriedPolicyRows> {
    let (facts, actors) = FreeTimePolicyRows::export_for_doors(vault)?;
    Ok(CarriedPolicyRows { facts, actors })
}

/// Lands `rows` in `vault` as a move's adoption does, every actor's content
/// opened: `true` when they applied, `false` for a Conflict.
///
/// # Errors
/// Rows that do not decode, and store errors.
pub fn adopt_policy_rows(vault: &Vault, rows: &CarriedPolicyRows) -> Result<bool> {
    FreeTimePolicyRows::adopt_for_doors(vault, &rows.facts, &rows.actors)
}

/// `agent`'s stored policy row in `vault`; `None` when there is none.
///
/// # Errors
/// A store read that fails.
pub fn stored_policy_row(vault: &Vault, agent: EntityId) -> Result<Option<StoredPolicyRow>> {
    Ok(FreeTimePolicyRows::row_for_doors(vault, agent)?.map(StoredPolicyRow))
}

/// Puts `row` back as `agent`'s stored policy row in `vault`.
///
/// # Errors
/// A row that does not decode, and store errors.
pub fn put_stored_policy_row(vault: &Vault, agent: EntityId, row: &StoredPolicyRow) -> Result<()> {
    FreeTimePolicyRows::put_row_for_doors(vault, agent, &row.0)
}
