//! The admitted keys a file read asks for, in one group per custody class.

use super::{AdmittedKey, ReadGroup};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::secret_custody::{
    CustodyClass, SecretCustodyFloor, SecretCustodyStatus, masked_file_in_txn,
    read_secret_custody_admission_in_txn,
};
use crate::vault::Vault;

/// Each key `custody` names, once, with its class and handle, in the order
/// given: `None` when one has no custody record, is not active, or is not
/// admitted to a model (T1).
pub(super) fn admitted_keys_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    custody: impl IntoIterator<Item = EntityId>,
) -> Result<Option<Vec<AdmittedKey>>> {
    let floor = SecretCustodyFloor::resolve(&vault.store, txn)?;
    let mut keys: Vec<AdmittedKey> = Vec::new();
    for secret in custody {
        if keys.iter().any(|key| key.secret == secret) {
            continue;
        }
        let Some(rec) = read_secret_custody_admission_in_txn(&vault.store, txn, &secret)? else {
            return Ok(None);
        };
        if rec.status != SecretCustodyStatus::Active
            || crate::secret_lease::reveal_tier_admission(&rec, &floor).is_err()
        {
            return Ok(None);
        }
        let class = rec.class;
        let handle =
            crate::ports::ShortIdStoreRead::port_short_id_reference(&vault.store, txn, &secret)?
                .map_or(rec.name, |(short, _)| short);
        keys.push(AdmittedKey {
            class,
            secret,
            handle,
        });
    }
    Ok(Some(keys))
}

/// The keys the mark of the file `hash` names, each with its handle, in one
/// group per custody class ([`class_groups`]), each group's keys in the
/// file's order: `None` when no mark covers the file, it names no key, a
/// key is not admitted ([`admitted_keys_in_txn`]), or the write door sealed
/// the file whole (`MaskedFile.sealed`).
pub(super) fn marked_groups_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    hash: &[u8; 32],
) -> Result<Option<Vec<ReadGroup>>> {
    let Some(mark) = masked_file_in_txn(&vault.store, txn, hash)? else {
        return Ok(None);
    };
    // A file sealed whole goes to the owner only (ARCH-0069
    // #binary-secrets): it holds a hit no mark places, and a granted read is
    // served the stored bytes whole, so its marked keys open no grant
    // (REVIEW-7708 P1).
    if mark.sealed {
        return Ok(None);
    }
    // Every key the mark places: in the stored bytes, and in each member of a
    // container.
    let marked = mark
        .keys
        .iter()
        .chain(mark.members.iter().flat_map(|member| member.keys.iter()))
        .map(|key| key.custody);
    let Some(admitted) = admitted_keys_in_txn(vault, txn, marked)? else {
        return Ok(None);
    };
    if admitted.is_empty() {
        return Ok(None);
    }
    class_groups(admitted).map(Some)
}

#[cfg(oneiron_test_support)]
impl Vault {
    /// The test door's view of [`marked_groups_in_txn`]: how many key groups
    /// an agent's read of the stored file `hash` asks for; `None` when no
    /// grant reaches the file.
    pub(crate) fn marked_file_key_groups_for_test(&self, hash: &[u8; 32]) -> Result<Option<usize>> {
        let txn = self.store.env.read_txn()?;
        Ok(marked_groups_in_txn(self, &txn, hash)?.map(|groups| groups.len()))
    }
}

/// `keys` in one group per custody class: the groups in their class word's
/// order, each group's keys in the order given.
pub(super) fn class_groups(keys: Vec<AdmittedKey>) -> Result<Vec<ReadGroup>> {
    let mut classes: Vec<(CustodyClass, Vec<(EntityId, String)>)> = Vec::new();
    for key in keys {
        match classes.iter_mut().find(|(class, _)| *class == key.class) {
            Some((_, held)) => held.push((key.secret, key.handle)),
            None => classes.push((key.class, vec![(key.secret, key.handle)])),
        }
    }
    classes.sort_by_key(|(class, _)| class.as_str());
    classes
        .into_iter()
        .map(|(class, keys)| ReadGroup::of(class, keys))
        .collect()
}
