//! A file the write door sealed whole (L6-03-SEALED-FILE-NO-NOTICE; Engine
//! RULING 14 Nov 13:01: "a notice for a whole sealed file, plus an owner
//! answer that clears the seal"). The door read a hit there that no span
//! places and no value of the file holds alone, so no custody record holds
//! any of it and no key handle names it (ARCH-0069 #binary-secrets: the
//! notice "names the handle if the key is already in custody"). The file's
//! record keeps the seal beside its keys, and the owner's notice shows it as
//! a key placed `file` whose handle is the file's own short id, such as
//! `as12`.
//!
//! The owner answers it not a secret with that handle. The seal is cleared
//! on the file's mark ([`clear_file_seal_in_txn`]): a masked reader is
//! served the file as its marks leave it, and a put of the same bytes is not
//! sealed again. No value goes back, because the bytes never changed, and
//! nothing is revoked or carried. Only the owner answers it: the mark is the
//! bytes', which another person's record may hold too.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::actions::{append_ruling_receipt_in_txn, gate_ref, live_owner_in_txn};
use super::{
    DUE, FOUND, FOUND_KEY_REASON_NOT_A_SECRET, FoundKeyAction, FoundKeyCard, FoundKeySettled,
    FoundKeys, REASON_PREFIX,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::ports::ShortIdStoreRead;
use crate::registry::ENTITY_TYPE_ASSET;
use crate::secret_custody::masked_files::clear_file_seal_in_txn;
use crate::secret_custody::reveal::resolve_typed_handle_in_txn;
use crate::store::Store;
use crate::vault::Vault;

/// Where a sealed file's card says its key sat.
const SEALED_FILE_PLACE: &str = "file";

/// One file the write door sealed whole in a record. It holds no value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct FileSeal {
    /// The BLAKE3 hash of the file's stored bytes, which keys its mark.
    hash: [u8; 32],
    /// The scan's reason code.
    reason: String,
    pub(super) found_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) settled: Option<FoundKeySettled>,
}

/// One file a batch sealed whole, as the mask hands it over.
#[derive(Debug, Clone)]
pub(crate) struct SealedFileNote {
    /// The ASSET put that carried it.
    pub(crate) record: EntityId,
    /// The BLAKE3 hash of the file's stored bytes.
    pub(crate) hash: [u8; 32],
    /// The scan's reason code.
    pub(crate) reason: &'static str,
}

/// Records each file `seals` names in its record's found keys, in the
/// write's own transaction, and leaves each record due for its notice. The
/// same bytes sealed again in a record are not recorded again.
pub(crate) fn note_file_seals_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    seals: &[SealedFileNote],
    at: u64,
) -> Result<()> {
    for seal in seals {
        let mut found = FOUND.get(store, txn, &seal.record)?.unwrap_or_default();
        if found.seals.iter().any(|held| held.hash == seal.hash) {
            continue;
        }
        found.seals.push(FileSeal {
            hash: seal.hash,
            reason: seal.reason.to_owned(),
            found_at: at,
            settled: None,
        });
        FOUND.put(store, txn, &seal.record, &found)?;
        DUE.put(store, txn, &seal.record, &at)?;
    }
    Ok(())
}

impl FileSeal {
    fn kind(&self) -> &str {
        self.reason
            .strip_prefix(REASON_PREFIX)
            .unwrap_or(&self.reason)
    }

    /// The seal as the owner's notice shows it: no custody name or label,
    /// and not a secret while it is open.
    pub(super) fn card_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        record: &EntityId,
    ) -> Result<FoundKeyCard> {
        let actions = if self.settled.is_none() {
            vec![FoundKeyAction::NotASecret]
        } else {
            Vec::new()
        };
        Ok(FoundKeyCard {
            handle: file_handle_in_txn(store, txn, record)?,
            name: String::new(),
            label: None,
            suggested_label: None,
            kind: self.kind().to_owned(),
            place: SEALED_FILE_PLACE.to_owned(),
            found_at: self.found_at,
            settled: self.settled.clone(),
            actions,
        })
    }
}

/// The handle a sealed file's card names: the file's own short id, or its
/// id in hex when it has none.
fn file_handle_in_txn(store: &Store, txn: &RoTxn<'_>, record: &EntityId) -> Result<String> {
    Ok(store
        .port_short_id_reference(txn, record)?
        .map_or_else(|| record.to_hex(), |(short, _)| short))
}

/// Whether `handle` is written as a file's id rather than a key's: an ASSET
/// short id (`as12`, `as12:ab`) or an id in hex. Its syntax alone decides,
/// before any proof is read.
pub(super) fn names_a_file(handle: &str) -> bool {
    let handle = handle.trim();
    if EntityId::from_hex(handle).is_ok() {
        return true;
    }
    let short = handle.split_once(':').map_or(handle, |(short, _)| short);
    let Ok(prefix) = crate::registry::short_id_prefix(ENTITY_TYPE_ASSET) else {
        return false;
    };
    crate::entity_id::parse_presentation_id(short).is_ok_and(|parsed| parsed.prefix == prefix)
}

/// The record a file's `handle` names, in `txn`.
fn file_named_in_txn(store: &Store, txn: &RoTxn<'_>, handle: &str) -> Result<EntityId> {
    let handle = handle.trim();
    if let Ok(record) = EntityId::from_hex(handle) {
        return Ok(record);
    }
    resolve_typed_handle_in_txn(store, txn, handle, ENTITY_TYPE_ASSET)
        .map(|(_, record)| record)
        .map_err(|_| Error::EntityNotFound)
}

impl Vault {
    /// The owner's answer on the file `handle` names: each open seal of
    /// its record is settled not a secret, with its Gate receipt, and the
    /// file's mark drops it. Any other answer is refused, since no value
    /// left the file to go back as text.
    pub(super) fn rule_sealed_file(
        &self,
        owner: &AuthenticatedOwner,
        handle: &str,
        action: FoundKeyAction,
    ) -> Result<FoundKeySettled> {
        self.with_write_txn_grouped(|txn| {
            let actor = live_owner_in_txn(
                self,
                owner,
                txn,
                "only the vault owner rules on a sealed file",
            )?;
            if action != FoundKeyAction::NotASecret {
                return Err(Error::Gate(GateError::InvalidConsentBound(
                    "a sealed file is answered not a secret: its bytes never left it, so none \
                     goes back as text",
                )));
            }
            let record = file_named_in_txn(&self.store, txn, handle)?;
            let mut found = FOUND
                .get(&self.store, txn, &record)?
                .filter(|found| !found.seals.is_empty())
                .ok_or(Error::EntityNotFound)?;
            if found.seals.iter().all(|seal| seal.settled.is_some()) {
                return Err(Error::Gate(GateError::InvalidConsentBound(
                    "this file's seal was ruled no secret",
                )));
            }
            let settled = settle_open_seals_in_txn(self, txn, actor, &record, &mut found)?;
            FOUND.put(&self.store, txn, &record, &found)?;
            Ok(settled)
        })
    }
}

/// Settles each open seal of `found`, the found keys of `record`, as
/// `actor`'s not a secret, each with its Gate receipt, and clears it on the
/// file's mark. Returns the last settlement.
fn settle_open_seals_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    actor: EntityId,
    record: &EntityId,
    found: &mut FoundKeys,
) -> Result<FoundKeySettled> {
    let at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let handle = file_handle_in_txn(&vault.store, txn, record)?;
    let mut last = None;
    for seal in found.seals.iter_mut().filter(|seal| seal.settled.is_none()) {
        let decision = append_ruling_receipt_in_txn(
            vault,
            txn,
            actor,
            FOUND_KEY_REASON_NOT_A_SECRET,
            vec![
                format!("handle:{handle}"),
                format!("record:{}", record.to_hex()),
                format!("place:{SEALED_FILE_PLACE}"),
                format!("kind:{}", seal.kind()),
                format!("sealed_file:{}", blake3::Hash::from(seal.hash).to_hex()),
            ],
            seal.hash.to_vec(),
        )?;
        let settled = FoundKeySettled {
            action: FoundKeyAction::NotASecret,
            by: Some(actor),
            at,
            receipt: gate_ref(decision),
            grant_ref: None,
        };
        seal.settled = Some(settled.clone());
        clear_file_seal_in_txn(&vault.store, txn, &seal.hash, at)?;
        last = Some(settled);
    }
    last.ok_or(Error::InvariantViolation(
        "a sealed file's answer settled no seal",
    ))
}
