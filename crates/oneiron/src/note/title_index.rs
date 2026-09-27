//! Atomic title-reservation replacement for authoritative NOTE document sets.
//! Replica materialization is not a second title-admission authority.

#[cfg(feature = "sync")]
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use super::document::{NoteDocument, invalid, validate_title};
use crate::store::Store;
use crate::{EntityId, Result, Vault};

struct TitleKey(String);
struct FinalTitle {
    note: EntityId,
    key: Option<TitleKey>,
}

/// A complete, transaction-local replacement set. The constructors below
/// derive membership from a committed document or every canonical live head.
struct ValidatedTitleReplacement {
    members: Vec<FinalTitle>,
}

fn reverse_key(note: EntityId) -> String {
    format!("note.title/v1/id/{}", note.to_hex())
}

fn title_key(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    title: Option<&str>,
) -> Result<Option<TitleKey>> {
    title
        .map(|title| {
            validate_title(title)?;
            let (_, core) = super::verbs::note_core(vault, txn, note)?;
            let normalized = title
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();
            Ok(TitleKey(format!(
                "note.title/v1/author/{}:{}",
                core.author_ref.to_hex(),
                blake3::hash(normalized.as_bytes()).to_hex()
            )))
        })
        .transpose()
}

impl ValidatedTitleReplacement {
    fn document(vault: &Vault, txn: &heed::RoTxn<'_>, doc: &NoteDocument) -> Result<Self> {
        Ok(Self {
            members: vec![FinalTitle {
                note: doc.id,
                key: title_key(vault, txn, doc.id, doc.title()?.as_deref())?,
            }],
        })
    }

    #[cfg(feature = "sync")]
    fn recovery(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        snapshot: &crate::recovery::CanonicalSnapshot,
    ) -> Result<Self> {
        let heads: BTreeMap<_, _> = snapshot
            .document_heads
            .iter()
            .map(|head| (head.entity_id, head.head))
            .collect();
        let mut members = BTreeMap::new();
        for row in &snapshot.doc_snapshots {
            if heads.get(&row.entity_id) != Some(&row.head) {
                continue; // Unlanded proposals do not own reservations.
            }
            let note = EntityId::from_bytes(row.entity_id)?;
            let key = title_key(vault, txn, note, row.title.as_deref())?;
            if members
                .insert(row.entity_id, FinalTitle { note, key })
                .is_some()
            {
                return Err(invalid("duplicate NOTE recovery head"));
            }
        }
        if members.len() != heads.len() {
            return Err(invalid("incomplete NOTE recovery title set"));
        }
        Ok(Self {
            members: members.into_values().collect(),
        })
    }

    fn replace(self, store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
        let mut ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for member in &self.members {
            if !ids.insert(*member.note.as_bytes()) {
                return Err(invalid("duplicate NOTE in title replacement"));
            }
            if let Some(key) = &member.key
                && !keys.insert(key.0.as_str())
            {
                return Err(invalid("duplicate NOTE title in replacement set"));
            }
        }
        for member in &self.members {
            if let Some(key) = &member.key
                && let Some(owner) = store.vault_meta.get(txn, key.0.as_bytes())?
            {
                let owner: [u8; 16] = owner
                    .as_ref()
                    .try_into()
                    .map_err(|_| invalid("NOTE title reservation owner"))?;
                if !ids.contains(&owner) {
                    return Err(invalid("duplicate NOTE title"));
                }
            }
        }
        // Validate every old pair before changing either direction.
        for member in &self.members {
            validate_old_pair(store, txn, member.note)?;
        }
        for member in &self.members {
            remove_old_pair(store, txn, member.note)?;
        }
        for member in self.members {
            if let Some(key) = member.key {
                store
                    .vault_meta
                    .put(txn, key.0.as_bytes(), member.note.as_bytes())?;
                store
                    .vault_meta
                    .put(txn, reverse_key(member.note).as_bytes(), key.0.as_bytes())?;
            }
        }
        Ok(())
    }
}

fn validate_old_pair(store: &Store, txn: &heed::RoTxn<'_>, note: EntityId) -> Result<()> {
    if let Some(key) = store.vault_meta.get(txn, reverse_key(note).as_bytes())?
        && store.vault_meta.get(txn, &key)?.as_deref() != Some(note.as_bytes())
    {
        return Err(invalid("NOTE title reservation mismatch"));
    }
    Ok(())
}

fn remove_old_pair(store: &Store, txn: &mut heed::RwTxn<'_>, note: EntityId) -> Result<()> {
    let reverse = reverse_key(note);
    if let Some(key) = store
        .vault_meta
        .get(txn, reverse.as_bytes())?
        .map(|key| key.to_vec())
    {
        store.vault_meta.delete(txn, &key)?;
        store.vault_meta.delete(txn, reverse.as_bytes())?;
    }
    Ok(())
}

/// Only the checked authoritative NOTE writer may claim a singleton title.
pub(super) fn replace_authoritative_document_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    doc: &NoteDocument,
) -> Result<()> {
    if vault
        .store
        .sync_state
        .get(txn, &format!("ds:e:{}", doc.id.to_hex()))?
        .is_some()
    {
        return Err(invalid(
            "replica NOTE cannot reserve an authoritative title",
        ));
    }
    ValidatedTitleReplacement::document(vault, txn, doc)?.replace(&vault.store, txn)
}

/// A canonical recovery replaces ALL live heads as a single authoritatively
/// admitted set. This runs even when each document was value-equal and not rewritten.
#[cfg(feature = "sync")]
pub(crate) fn replace_recovered_set_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    snapshot: &crate::recovery::CanonicalSnapshot,
) -> Result<()> {
    let set = ValidatedTitleReplacement::recovery(vault, txn, snapshot)?;
    for row in &set.members {
        if vault
            .store
            .sync_state
            .get(txn, &format!("ds:e:{}", row.note.to_hex()))?
            .is_some()
        {
            return Err(invalid("replica NOTE cannot recover as authority"));
        }
    }
    set.replace(&vault.store, txn)
}

/// An authenticated authority can update a replica in any document order.
#[cfg(feature = "sync")]
pub(super) fn remove_replica_projection_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
) -> Result<()> {
    if vault
        .store
        .sync_state
        .get(txn, &format!("ds:e:{}", note.to_hex()))?
        .is_none()
    {
        return Err(invalid("NOTE replica subscription missing"));
    }
    validate_old_pair(&vault.store, txn, note)?;
    remove_old_pair(&vault.store, txn, note)
}

/// Erasure cannot leave a title index that blocks a future, unrelated NOTE.
pub(super) fn remove_erased_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
) -> Result<()> {
    validate_old_pair(store, txn, note)?;
    remove_old_pair(store, txn, note)
}
