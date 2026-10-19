//! The training link (TRAINING-LINK = C, TL-1): the opaque codes that stand
//! in for this vault, its sources, persons and worlds in everything the
//! publisher training outbox writes, and the one key they are made under.
//!
//! The vault holds the link; the publisher keeps only codes. K is a 32-byte
//! random key per vault, held in key custody (kind `TrainingLink`, in the
//! custody head's host-readable compartment, so a restore by the recovery
//! kit or by the vault data key keeps the vault's past codes). It is minted
//! on the vault's first training use and never leaves the vault: no outbox
//! file, log, error, control-plane call or intake call carries it, and no
//! log names a scope or a code.
//!
//! Every digest here is keyed BLAKE3, under a key derived from K for its one
//! purpose (`blake3::derive_key`, held zeroized):
//!
//! - [`training_month`]: the UTC calendar month, `YYYY-MM`, of an offer's
//!   first preparation. A retry keeps it.
//! - [`scope_tag`]: S, keyed BLAKE3 under
//!   derive_key(`oneiron.training.scope.v2`, K) of the month: it rotates
//!   monthly.
//! - [`code`]: keyed BLAKE3 under derive_key(`oneiron.training.code.v2`, K)
//!   of the kind ([`SOURCE`], [`PERSON`] or [`WORLD`]), the id and the month.
//!
//! Every input part is framed as its length, a big-endian `u32`, then its
//! bytes. Once K is minted (`link_minted` in the training state, set in the
//! writer that mints it), a missing or unreadable K is an error and never a
//! new key: a fresh K would orphan every past code from withdrawal and
//! erase.

use std::collections::BTreeSet;

use chrono::Datelike as _;
use zeroize::Zeroizing;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::custody::{self, OutboxState};

/// The context the scope key is derived from K under.
const SCOPE_CONTEXT: &str = "oneiron.training.scope.v2";
/// The context the code key is derived from K under.
const CODE_CONTEXT: &str = "oneiron.training.code.v2";
/// The kind of a source's code.
pub(super) const SOURCE: &str = "source";
/// The kind of a person's code.
pub(super) const PERSON: &str = "person";
/// The kind of a world's code.
pub(super) const WORLD: &str = "world";
/// The month a time past the four-digit calendar reads as, so months still
/// sort as text.
const LAST_MONTH: &str = "9999-12";

/// Keyed BLAKE3 of `parts`, under the key derived from `key` for `context`,
/// each part framed as its length, a big-endian `u32`, then its bytes. The
/// derived key is zeroized when it drops.
pub(super) fn keyed_digest(key: &[u8; 32], context: &str, parts: &[&[u8]]) -> [u8; 32] {
    let derived = Zeroizing::new(blake3::derive_key(context, key));
    let mut digest = blake3::Hasher::new_keyed(&derived);
    for part in parts {
        // A part is a kind, an id or a month: far below 4 GiB.
        let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
        digest.update(&len.to_be_bytes());
        digest.update(part);
    }
    *digest.finalize().as_bytes()
}

/// The UTC calendar month `unix_secs` falls in, as `YYYY-MM`.
pub(super) fn training_month(unix_secs: u64) -> String {
    i64::try_from(unix_secs)
        .ok()
        .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0))
        .filter(|at| at.year() <= 9999)
        .map_or_else(
            || LAST_MONTH.to_owned(),
            |at| {
                let (year, month) = (at.year(), at.month());
                format!("{year:04}-{month:02}")
            },
        )
}

/// S, the scope of `month` under `key`.
pub(super) fn scope_tag(key: &[u8; 32], month: &str) -> [u8; 32] {
    keyed_digest(key, SCOPE_CONTEXT, &[month.as_bytes()])
}

/// The code of `id`, of `kind`, for `month` under `key`.
pub(super) fn code(key: &[u8; 32], kind: &str, id: &EntityId, month: &str) -> [u8; 32] {
    keyed_digest(
        key,
        CODE_CONTEXT,
        &[kind.as_bytes(), id.as_bytes().as_slice(), month.as_bytes()],
    )
}

/// [`code`] as the wire spells it: 64 lower-case hex.
pub(super) fn code_hex(key: &[u8; 32], kind: &str, id: &EntityId, month: &str) -> String {
    oneiron_vault_contract::hex(&code(key, kind, id, month))
}

/// The codes of `ids`, sorted, so a list's order says nothing of the ids
/// behind it.
pub(super) fn code_set(
    key: &[u8; 32],
    kind: &str,
    ids: &BTreeSet<EntityId>,
    month: &str,
) -> Vec<String> {
    let mut codes: Vec<String> = ids
        .iter()
        .map(|id| code_hex(key, kind, id, month))
        .collect();
    codes.sort_unstable();
    codes
}

/// K, for a writer: minted on the vault's first training use, with
/// `link_minted` set on `state`, which the caller writes in this same
/// writer. Once it is set, K is read, never minted again.
///
/// # Errors
/// K minted once and now missing or unreadable ("training link key
/// missing"), and custody faults while minting it.
pub(super) fn training_link_key_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    state: &mut OutboxState,
) -> Result<Zeroizing<[u8; 32]>> {
    if state.link_minted {
        return vault
            .store
            .read_training_link_key()
            .map_err(|_| link_missing());
    }
    let key = vault.store.mint_training_link_key_in_txn(txn)?;
    state.link_minted = true;
    Ok(key)
}

/// K, for a reader: never minted here.
///
/// # Errors
/// K never minted, or missing or unreadable now ("training link key
/// missing").
pub(super) fn training_link_key(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Zeroizing<[u8; 32]>> {
    if !custody::state(vault, txn)?.link_minted {
        return Err(link_missing());
    }
    vault
        .store
        .read_training_link_key()
        .map_err(|_| link_missing())
}

/// A K that should be there and is not. It names no key byte.
fn link_missing() -> Error {
    Error::CorruptedIndex("training link key missing")
}

/// K's readiness rule, its own and beside the claim key's, never inside it:
/// K retires only once the intake's `removed` receipt for the purge is in
/// (TL-5). Never at the purge's creation or spooling, at switch-off, on a
/// source or person erase, at reap, or on a timer.
fn link_retirement_ready(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    custody::purge_removed(vault, txn)
}

impl Vault {
    /// Finishes K's staged retirement, including one an interrupted process
    /// left behind, once its rule holds.
    ///
    /// # Errors
    /// Storage and custody faults; the intent stays for the next pass.
    pub(super) fn finish_training_link_retirement(&self) -> Result<()> {
        self.store
            .finish_training_link_retirements(|txn| link_retirement_ready(self, txn))
    }

    /// The post-commit door after a write that may have staged K's
    /// retirement, and each upkeep pass's retry. The intent is durable, so
    /// a failure here is retried by the next pass and never fails the write
    /// that committed.
    pub(super) fn finish_training_link_retirement_after_commit(&self) {
        if let Err(error) = self.finish_training_link_retirement() {
            tracing::warn!(
                %error,
                "training link key retirement deferred to the next publisher training upkeep pass"
            );
        }
    }
}
