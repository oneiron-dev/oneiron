//! Doors for `tests/secret_same_value_exchange.rs` (FIX [SECRETS-SAME-VALUE-FACT]): the machine's
//! half of `residence.secret_same_value.exchange` without a socket (the home's half,
//! `sync::residence::secret_same_value_residence_exchange`, is public), what a statement says in
//! the clear, and the two ways a relay could alter one.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::secret_custody::SameValueStatement;

/// The statements this machine sends its home on a steady pass, its own first brought up to the
/// pairs it proves now. `None` while it serves no machine of the fold.
///
/// # Errors
/// As [`Vault::same_value_statements_written_here`].
pub fn statements_to_send(vault: &Vault) -> Result<Option<Vec<SameValueStatement>>> {
    vault.same_value_statements_written_here()
}

/// Takes the home's answer as the steady pass does; returns how many statements changed here.
///
/// # Errors
/// As [`Vault::take_same_value_statements`].
pub fn take_answer(vault: &Vault, statements: Vec<SameValueStatement>) -> Result<usize> {
    vault.take_same_value_statements(statements)
}

/// The statement's writer, in the clear.
#[must_use]
pub fn writer(statement: &SameValueStatement) -> EntityId {
    statement.writer
}

/// The machines the statement's pairs are sealed to, in the clear.
#[must_use]
pub fn recipients(statement: &SameValueStatement) -> Vec<EntityId> {
    statement
        .envelopes
        .iter()
        .map(|envelope| envelope.recipient)
        .collect()
}

/// Whether the pairs this install opened from `writer`'s statement it holds name `a` and `b`
/// together, in either order. `false` when it holds none from `writer` or opened none.
///
/// # Errors
/// The store's.
pub fn opened_pair(vault: &Vault, writer: EntityId, a: EntityId, b: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    let held = crate::secret_custody::same_value_statement_held_in_txn(vault, &txn, writer)?;
    Ok(held.and_then(|held| held.opened).is_some_and(|pairs| {
        pairs
            .iter()
            .any(|pair| (pair.a, pair.b) == (a, b) || (pair.a, pair.b) == (b, a))
    }))
}

/// Whether this install holds a statement from `writer`, opened or not.
///
/// # Errors
/// The store's.
pub fn holds_statement_from(vault: &Vault, writer: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(crate::secret_custody::same_value_statement_held_in_txn(vault, &txn, writer)?.is_some())
}

/// `statement` with one byte of its first envelope changed, its signature kept: what a relay that
/// alters the sealed pairs hands on.
#[must_use]
pub fn with_altered_envelope(statement: &SameValueStatement) -> SameValueStatement {
    let mut altered = statement.clone();
    if let Some(envelope) = altered.envelopes.first_mut()
        && let Some(mut bytes) = oneiron_hex::decode_vec(&envelope.sealed)
        && let Some(last) = bytes.last_mut()
    {
        *last ^= 0x01;
        envelope.sealed = oneiron_hex::encode(&bytes);
    }
    altered
}

/// `statement` signed again by `vault`'s own machine key, its writer and time kept and its time
/// moved one past: what a relay holding a machine key of its own hands on as someone else's.
///
/// # Errors
/// The store's and the machine key's.
pub fn signed_again_by(
    vault: &Vault,
    statement: &SameValueStatement,
) -> Result<SameValueStatement> {
    let txn = vault.store.env.read_txn()?;
    let fold = vault.authority_view_readonly_in_txn(&txn)?;
    let (_, signing) = crate::identity::machine_signer_in_txn(vault, &txn)?;
    Ok(crate::secret_custody::same_value_statement_signed_by(
        &fold, statement, &signing,
    ))
}
