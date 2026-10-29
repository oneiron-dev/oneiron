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
//! - [`piece_code`]: C, a submission's code for the anonymous training
//!   window (TL-6), the same digest of kind [`PIECE`], the submission id's
//!   16 raw bytes and its month. It is made once, at the submission's first
//!   preparation under K at its generation, and kept in its custody row:
//!   never made again, and never logged.
//!
//! Every input part is framed as its length, a big-endian `u32`, then its
//! bytes. Once K is minted (`link_minted` in the training state, set in the
//! writer that mints it), an unreadable K is an error and a retired one too
//! (the erase purge finished); neither is ever replaced. A K whose slot is
//! missing, as after a restore that brought no custody head, is minted
//! afresh under the next generation at the vault's next training writer
//! (FIX 5892): the months of older generations keep their scopes, so an
//! erase still purges them whole, but their codes cannot be made again, so
//! their hosted withdrawals are counted unavailable. An anonymous piece
//! keeps its C in its custody row, so a restore that brought that row back
//! still withdraws it one by one.

use std::collections::BTreeSet;

use chrono::Datelike as _;
use zeroize::Zeroizing;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::TrainingLinkSlot;

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
/// The kind of a submission's piece code, C (TL-6).
pub(super) const PIECE: &str = "piece";
/// The month a time past the four-digit calendar reads as, so months still
/// sort as text.
const LAST_MONTH: &str = "9999-12";

/// Keyed BLAKE3 of `parts`, under the key derived from `key` for `context`,
/// each part framed as its length, a big-endian `u32`, then its bytes. The
/// derived key is zeroized when it drops.
pub(super) fn keyed_digest(key: &[u8; 32], context: &str, parts: &[&[u8]]) -> [u8; 32] {
    // FIX 6669: derive straight into the guard.
    let derived = crate::world_keys::derive_guarded(context, &[&key[..]]);
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

/// C, the piece code of `submission`, first prepared in `month`, under
/// `key`: the anonymous window's only handle on the piece (TL-6). The kind
/// [`PIECE`] in the framing keeps it apart from every source, person and
/// world code.
pub(super) fn piece_code(key: &[u8; 32], submission: &[u8; 16], month: &str) -> [u8; 32] {
    keyed_digest(
        key,
        CODE_CONTEXT,
        &[PIECE.as_bytes(), submission, month.as_bytes()],
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

/// What a restore that brought no training link key reports (FIX 5892;
/// CALLS TL6_RESTORE_NOTICE): the key is made afresh at the vault's next
/// training write, and what that costs. A donation whose custody row the
/// restore brought back keeps its stored C, so an anonymous one is still
/// withdrawn one by one; an older hosted one's codes cannot be made again.
/// It names no key, scope, code or id.
pub(crate) const TRAINING_LINK_RESTORE_NOTICE: &str = "This restore brought no training link key. \
                                                       A fresh one will be made. Training \
                                                       donations whose records this restore \
                                                       brought back can still be withdrawn one \
                                                       by one from this vault. Older donations \
                                                       shared through Oneiron Cloud hosting may \
                                                       no longer be withdrawn one by one; an \
                                                       erase still purges every donation this \
                                                       vault recorded.";

/// K, for a writer: minted on the vault's first training use, with
/// `link_minted` set on `state`, which the caller writes in this same
/// writer. Once it is set, K at the current generation is read. When a
/// restore that brought no custody head left that slot missing, a fresh K
/// is minted under the next generation, which `state` takes with the time
/// (FIX 5892): a retry of an uncommitted writer finds the slot it published
/// and never advances twice. A retired K (the erase purge finished) or an
/// unreadable one is never replaced.
///
/// # Errors
/// A retired K ("training link key retired"), an unreadable one ("training
/// link key missing"), and custody faults while minting.
pub(super) fn training_link_key_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    state: &mut OutboxState,
) -> Result<Zeroizing<[u8; 32]>> {
    if !state.link_minted {
        let key = vault
            .store
            .mint_training_link_key_in_txn(txn, state.link_generation)?;
        state.link_minted = true;
        return Ok(key);
    }
    let slot = vault
        .store
        .training_link_slot(state.link_generation)
        .map_err(|_| link_missing())?;
    match slot {
        TrainingLinkSlot::Live => vault
            .store
            .read_training_link_key(state.link_generation)
            .map_err(|_| link_missing()),
        TrainingLinkSlot::Retired => Err(link_retired()),
        TrainingLinkSlot::Missing => {
            let generation = state
                .link_generation
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("training link key generation"))?;
            let key = vault.store.mint_training_link_key_in_txn(txn, generation)?;
            state.link_generation = generation;
            state.link_reminted_at = Some(crate::unix_seconds_now());
            Ok(key)
        }
    }
}

/// K at `generation`, for a reader: never minted here. An orphaned
/// generation's K is gone, so it never reads.
///
/// # Errors
/// K never minted, or missing or unreadable at `generation` ("training link
/// key missing").
pub(super) fn training_link_key(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    generation: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    if !custody::state(vault, txn)?.link_minted {
        return Err(link_missing());
    }
    vault
        .store
        .read_training_link_key(generation)
        .map_err(|_| link_missing())
}

/// Whether the vault's next training writer must mint K afresh: it was
/// minted once, and its slot at the current generation is missing, as after
/// a restore that brought no custody head. A finished purge needs no key.
fn link_lost(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    let state = custody::state(vault, txn)?;
    if !state.link_minted || custody::purge_removed(vault, txn)? {
        return Ok(false);
    }
    Ok(vault.store.training_link_slot(state.link_generation)? == TrainingLinkSlot::Missing)
}

/// A K that should be there and is not. It names no key byte.
fn link_missing() -> Error {
    Error::CorruptedIndex("training link key missing")
}

/// A K the erase purge retired: never minted again.
fn link_retired() -> Error {
    Error::CorruptedIndex("training link key retired")
}

/// K's readiness rule, its own and beside the claim key's, never inside it:
/// K retires only once the purge is done by its one predicate (TL-5, TL-6):
/// every hosted scope's `removed` receipt and every anonymous piece's signed
/// `removed` in. Never at the purge's creation or spooling, at switch-off,
/// on a source or person erase, at reap, or on a timer.
fn link_retirement_ready(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    custody::purge_removed(vault, txn)
}

impl Vault {
    /// What a restore reports about the training link key (FIX 5892):
    /// [`TRAINING_LINK_RESTORE_NOTICE`] when the vault minted K once and its
    /// slot at the current generation is missing now; `None` otherwise. It
    /// reads only: the fresh K is minted at the vault's next training
    /// writer, never during a restore. A notice that cannot be read is
    /// logged and left out: it never fails the restore it rides on.
    pub(crate) fn training_link_restore_notice(&self) -> Option<String> {
        let lost = self
            .store
            .env
            .read_txn()
            .map_err(Error::from)
            .and_then(|txn| link_lost(self, &txn));
        match lost {
            Ok(lost) => lost.then(|| TRAINING_LINK_RESTORE_NOTICE.to_owned()),
            Err(error) => {
                tracing::warn!(%error, "the training link restore notice could not be read");
                None
            }
        }
    }

    /// Mints K afresh, under the next generation, when a restore that
    /// brought no custody head left its slot missing (FIX 5892): the first
    /// step of every upkeep and offer pass, a writer only when one is due.
    /// Hosted withdrawals of the orphaned generation are then counted
    /// unavailable rather than stopping the pass; an anonymous piece keeps
    /// its stored C, and its withdrawal still goes.
    ///
    /// # Errors
    /// Storage and custody faults.
    pub(super) fn renew_lost_training_link(&self) -> Result<()> {
        let lost = {
            let txn = self.store.env.read_txn()?;
            link_lost(self, &txn)?
        };
        if lost {
            self.with_write_txn_grouped(|txn| custody::link_generation_in(self, txn).map(|_| ()))?;
        }
        Ok(())
    }

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
