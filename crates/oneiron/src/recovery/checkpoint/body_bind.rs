//! The binding pass a checkpoint runs before its snapshot (KS-2A, FIX 5683
//! part A): every body its rows will carry gets its instance first.
//!
//! An inline body (an ASSET entity's row body, an inline result) takes its
//! instance the first time a checkpoint carries it, and a plain vault's file
//! written before it had one takes it the same way; so does a row-held
//! response, each time its bytes change (KS-2B1), with an obligation for
//! each owner its stamps name. The pass reads the rows in one read
//! transaction, mints each missing instance outside any writer (a Mint is a
//! synced journal frame), then binds them in one short write transaction
//! that only writes rows, each rechecked there: one bound since, or whose
//! body has gone, is left as debris. A response binding whose row holds no
//! response now is dropped there, every key kept. So no image ever holds a
//! body sealed under an instance its owner's erase cannot find: the binding
//! commits before any snapshot that carries it opens.

use std::collections::BTreeSet;

use heed::RoTxn;
use heed::types::Bytes;

use super::carried_bodies::{BodyCensus, Unbound, inline_asset};
use super::{StorageTier, response_rows, storage_tier};
use crate::store::{BODY_KEYS, BodyKeyRow, INLINE_ASSETS, Store, pin_body_custody_in_txn};
use crate::{Error, Result, Vault};

/// The databases whose rows name the bodies a checkpoint carries: the host's
/// row-held responses rest in `sync_state` (KS-2B2).
const BODY_DATABASES: [&str; 3] = ["entities", "vault_meta", "sync_state"];

impl Vault {
    /// Mints and binds an instance for every body the next checkpoint will
    /// carry that has none yet.
    ///
    /// # Errors
    ///
    /// Storage and custody errors; an archived vault, which mints nothing.
    pub(super) fn bind_carried_bodies(&self) -> Result<()> {
        let (unbound, stale) = {
            let txn = self.store.env.read_txn()?;
            unbound_in_txn(&self.store, &txn)?
        };
        if unbound.is_empty() && stale.is_empty() {
            return Ok(());
        }
        let mut minted = Vec::with_capacity(unbound.len());
        if !unbound.is_empty() {
            let mint = self.store.body_mint()?;
            for body in unbound {
                let instance = *mint.mint()?.instance();
                minted.push((body, instance));
            }
        }
        self.with_write_txn(|txn| {
            if !minted.is_empty() {
                pin_body_custody_in_txn(&self.store, txn)?;
            }
            for (body, instance) in &minted {
                bind_in_txn(self, txn, body, *instance)?;
            }
            response_rows::release_stale_in_txn(&self.store, txn, &stale)
        })
    }
}

/// Every body the rows in `txn` name that a checkpoint carries with no
/// instance bound, and every response binding whose row holds no response:
/// the census a snapshot takes, read here first.
fn unbound_in_txn(store: &Store, txn: &RoTxn<'_>) -> Result<(Vec<Unbound>, BTreeSet<Vec<u8>>)> {
    let mut census = BodyCensus::default();
    for name in BODY_DATABASES {
        let db = store
            .env
            .open_database::<Bytes, Bytes>(txn, Some(name))?
            .ok_or(Error::CorruptedIndex("canonical checkpoint image"))?;
        for row in db.iter(txn)? {
            let (key, value) = row?;
            if storage_tier(name, key) == StorageTier::Canonical {
                census.note(store, txn, name, key, value)?;
            }
        }
    }
    Ok((census.unbound(store)?, census.stale()))
}

/// Binds `instance` to `body` in `txn`, unless one was bound since or the
/// body has gone: then the instance is debris.
fn bind_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    body: &Unbound,
    instance: [u8; 16],
) -> Result<()> {
    let store = &vault.store;
    match body {
        Unbound::Asset(id) => {
            let still = match crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? {
                Some(raw) => {
                    inline_asset(&raw)
                        && crate::store::asset_body_file_of_row(store, txn, id.as_bytes(), &raw)?
                            .is_none()
                }
                None => false,
            };
            if still && !INLINE_ASSETS.contains(store, txn, id)? {
                INLINE_ASSETS.put(store, txn, id, &instance)?;
            }
        }
        Unbound::Result(digest, len) => {
            let inline = BODY_KEYS
                .get(store, txn, digest)?
                .is_some_and(|row| row.inline);
            if !inline && vault.code_run_body_inline_in_txn(txn, digest)? {
                BODY_KEYS.put(store, txn, digest, &BodyKeyRow::vault(instance, *len, true))?;
            }
        }
        Unbound::File(digest, len) => {
            let held = BODY_KEYS
                .get(store, txn, digest)?
                .is_some_and(|row| !row.inline);
            if !held {
                // A file a row names and the disk lacks is no body to bind:
                // the checkpoint refuses, as it refused before.
                if store.body_dir()?.open_reader(digest, *len, None)?.is_none() {
                    return Err(Error::CorruptedIndex("code-run result body file missing"));
                }
                BODY_KEYS.put(
                    store,
                    txn,
                    digest,
                    &BodyKeyRow::vault(instance, *len, false),
                )?;
            }
        }
        Unbound::Response(carrier) => response_rows::bind_in_txn(store, txn, carrier, instance)?,
    }
    Ok(())
}
