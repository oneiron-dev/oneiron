//! What a restore, a fork or an activation knows of erased credentials
//! (KS-6 part 2, CALLS `KS-6 erase fence form`), looked up one handle at a
//! time.
//!
//! The evidence is the live source's own: its fences and its credential
//! keys' erase intents, read from the source vault (a fork's or an
//! activation's source, the live rows a restore over a live vault carried,
//! or the vault whose custody a restore keeps), and a retired first
//! generation of a credential's value key in the custody the restore takes,
//! which only an erase retires. An image never supplies any: its own fence
//! and credential intent rows are dropped before its rows land
//! ([`CredentialFences::image_owned`]).
//!
//! A row of the source that does not read names no one id: it is warned
//! and skipped. A handle whose own custody evidence does not read, or whose
//! source's fences did not read at all, is withheld, PendingCustody, warned
//! (ruling 4); every other handle keeps today's path.

use std::collections::BTreeSet;
use std::path::Path;

use heed::types::Bytes;
use heed::{RoTxn, RwTxn};

use super::erase::{CREDENTIAL_PARENT_KINDS, Discovery, FENCES, FenceLookup, parent_of};
use crate::entity_id::EntityId;
use crate::error::{Error, Result, StoreError, VaultRootProblem};
use crate::side_table::SideKey;
use crate::store::Store;
use crate::store::key_custody::{
    CustodyBinding, CustodyKind, CustodySubject, LocalCustody, RetireCause, retirement_prefix,
    retirements_in_rows,
};

/// The `vault_meta` prefixes a source's erase evidence is read from: its
/// fences, and its key retirement intents.
fn evidence_prefixes() -> [&'static [u8]; 2] {
    [FENCES.decl().prefix, retirement_prefix()]
}

/// What a restore, a fork or an activation knows of erased credentials.
#[derive(Clone, Debug, Default)]
pub(crate) struct CredentialFences {
    /// The ids the source fenced, or whose keys it staged an erase of, and
    /// those a lookup found retired in the custody taken.
    fenced: BTreeSet<EntityId>,
    /// The custody whose retired credential value keys prove an erase.
    custody: Option<CustodyBinding>,
    /// The source's fences did not read: a handle nothing else names
    /// fenced reads faulted.
    unread: bool,
}

impl CredentialFences {
    /// A source whose fences did not read.
    fn unread() -> Self {
        Self {
            unread: true,
            ..Self::default()
        }
    }

    /// The erase evidence among raw `vault_meta` rows of a live source, or
    /// the live rows a restore over a live vault carried: each fence, and
    /// the credential of each credential key's erase intent. A row that
    /// does not read is warned and skipped.
    pub(crate) fn in_rows(rows: &[(Vec<u8>, Vec<u8>)]) -> Self {
        let mut fences = Self::default();
        for row in rows {
            if let Some(rest) = row.0.strip_prefix(FENCES.decl().prefix) {
                match <EntityId as SideKey>::decode_key(rest) {
                    Some(id) => {
                        fences.fenced.insert(id);
                    }
                    None => tracing::warn!("a credential erase fence row did not read; skipped"),
                }
                continue;
            }
            if !row.0.starts_with(retirement_prefix()) {
                continue;
            }
            match retirements_in_rows(std::slice::from_ref(row)) {
                Ok(intents) => fences.fenced.extend(
                    intents
                        .iter()
                        .filter(|intent| intent.cause == RetireCause::Erase)
                        .filter_map(|intent| parent_of(&intent.subject)),
                ),
                Err(_) => tracing::warn!("a key retirement intent row did not read; skipped"),
            }
        }
        fences
    }

    /// The erase evidence of the existing vault at `root`, read through the
    /// read-only door, a sealed one with `page_seal`. No vault there is no
    /// evidence; one that does not read is warned, and reads unread.
    pub(crate) fn at_vault(
        root: &Path,
        page_seal: Option<&crate::world_keys::VaultPageSeal>,
    ) -> Self {
        let read = crate::world_keys::read_sealed(root, page_seal, || {
            crate::store::read_existing_vault_meta(root, &evidence_prefixes())
        });
        match read {
            Ok(read) => Self::in_rows(&read.rows),
            Err(Error::Store(StoreError::VaultRootPreflight {
                problem: VaultRootProblem::NotAnExistingVaultRoot { .. },
                ..
            })) => Self::default(),
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a source vault's credential erase fences did not read; each credential it \
                     would re-admit and nothing fences is withheld, pending"
                );
                Self::unread()
            }
        }
    }

    /// Adds every fence of `other`.
    pub(crate) fn merge(&mut self, other: &Self) {
        self.fenced.extend(other.fenced.iter().copied());
        self.unread |= other.unread;
        if self.custody.is_none() {
            self.custody.clone_from(&other.custody);
        }
    }

    /// Takes `binding`'s retired credential value keys as evidence too,
    /// each looked up by its own handle.
    pub(crate) fn with_custody(&mut self, binding: &CustodyBinding) {
        self.custody = Some(binding.clone());
    }

    /// What these fences say of `id`: fenced when the source named it or
    /// the custody taken retired its value key's first generation; faulted
    /// when its own custody evidence, or the source's fences, did not read.
    pub(crate) fn lookup(&mut self, id: &EntityId) -> FenceLookup {
        if self.fenced.contains(id) {
            return FenceLookup::Fenced;
        }
        if let Some(binding) = &self.custody {
            let retired = binding
                .subject(CustodyKind::CredentialValue, id.as_bytes())
                .and_then(|subject| LocalCustody::at(binding).retired(&subject.at(0)));
            match retired {
                Ok(true) => {
                    self.fenced.insert(*id);
                    return FenceLookup::Fenced;
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(
                        credential = %id.to_hex(),
                        kind = ?error.kind(),
                        "a credential's custody retirement did not read; it is withheld, pending"
                    );
                    return FenceLookup::Faulted;
                }
            }
        }
        if self.unread {
            FenceLookup::Faulted
        } else {
            FenceLookup::Clear
        }
    }

    /// Whether a `vault_meta` row is erase evidence an image would supply:
    /// a fence, or a credential key's retirement intent. A restore that
    /// does not carry its live source's rows drops each before they land.
    pub(crate) fn image_owned(key: &[u8]) -> bool {
        key.starts_with(FENCES.decl().prefix)
            || key
                .strip_prefix(retirement_prefix())
                .and_then(<CustodySubject as SideKey>::decode_key)
                .is_some_and(|subject| CREDENTIAL_PARENT_KINDS.contains(&subject.kind()))
    }

    /// The fence rows a restored or activated vault takes, each with its
    /// discovery owed, so its own finisher finds every key the id names in
    /// the custody it holds now.
    pub(crate) fn rows(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let owed = FENCES.encode_value(&Discovery::Owed)?;
        Ok(self
            .fenced
            .iter()
            .map(|id| (FENCES.key_bytes(id), owed.clone()))
            .collect())
    }

    /// Puts every fence in `wtxn`, its discovery owed: an activation's.
    pub(crate) fn put_in_txn(&self, store: &Store, wtxn: &mut RwTxn<'_>) -> Result<()> {
        for id in &self.fenced {
            FENCES.put(store, wtxn, id, &Discovery::Owed)?;
        }
        Ok(())
    }
}

impl Store {
    /// This open vault's erase evidence, read in `txn` apart from any
    /// other read, so it never fails the read it rides: rows that do not
    /// read are warned and skipped; a scan that faults reads unread.
    pub(crate) fn credential_fences_in_txn(&self, txn: &RoTxn<'_>) -> CredentialFences {
        let rows = (|| -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
            let vault_meta = self
                .env
                .open_database::<Bytes, Bytes>(txn, Some("vault_meta"))?
                .ok_or(Error::CorruptedIndex("vault holds no side-table database"))?;
            let mut rows = Vec::new();
            for prefix in evidence_prefixes() {
                for row in vault_meta.prefix_iter(txn, prefix)? {
                    let (key, value) = row?;
                    rows.push((key.to_vec(), value.to_vec()));
                }
            }
            Ok(rows)
        })();
        match rows {
            Ok(rows) => CredentialFences::in_rows(&rows),
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a vault's credential erase fences did not read; each credential it would \
                     re-admit and nothing fences is withheld, pending"
                );
                CredentialFences::unread()
            }
        }
    }
}
