//! The found-key notice (OF-560; owner ruling G04 binary = C2): a write
//! whose mask lifts a key out of a record, or marks a file, raises one
//! non-blocking needs-you notice per record for the owner. The notice is an
//! inbox Ask (`NOTIFICATION`) naming the record; this module keeps what it
//! points at: each key the mask lifted there, with its kind (the scan rule
//! that found it), its `sc` handle and where it sat. Nothing here holds a
//! value.
//!
//! The owner answers each key with one of four doors, each owner-only and
//! each with its receipt ([`actions`]):
//!
//! - **rotate**: the existing rotate door for the key's custody record
//!   (`Vault::rotate_secret_as_owner`), which settles the key in its own
//!   transaction;
//! - **delete**: the record or file that holds the key, through the owner's
//!   delete door;
//! - **grant**: a standing reveal grant for the key's class to one agent
//!   (the 2a bound: that connection × that class × a project);
//! - **not a secret**: the owner overrules the scan. A masked span in a
//!   record's body gets its value back, a file's mark drops the key, and the
//!   custody record is revoked. The value stays a kept value of that record
//!   ([`KeptValues`]): the write door no longer reads it as a hit there.
//!
//! A batch that masks many keys in one record raises one notice for it. The
//! mask writes inside the batch's own transaction, where no vault is at
//! hand, so it leaves the record due ([`note_found_keys_in_txn`]); the
//! write's commit boundary raises the notice ([`raise_found_key_notices_in_txn`]).

mod actions;

use std::collections::HashMap;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::doors::read_secret_custody_in_txn;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::vault::Vault;

pub use self::actions::FOUND_KEY_REASON_NOT_A_SECRET;
pub(crate) use self::actions::settle_found_key_in_txn;

/// Producer name of a found-key notice.
pub const NOTIFICATION_PRODUCER_FOUND_KEY: &str = "secret.found_key";

/// The most due records one write's commit boundary raises notices for; the
/// rest wait for the next write.
const NOTICES_PER_WRITE: usize = 64;

/// The scan's reason codes share this prefix; a key's kind is what follows.
const REASON_PREFIX: &str = "gate.secret_scan.";

/// Each record's found keys. Key: the record's id.
const FOUND: SideTable<EntityId, FoundKeys, Named> = SideTable::new(&side_table::SECRET_FOUND_KEY);

/// The records whose notice is still due, with when their keys were found.
const DUE: SideTable<EntityId, u64, Named> = SideTable::new(&side_table::SECRET_FOUND_KEY_DUE);

/// What the owner did about one found key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FoundKeyAction {
    /// The custody record took a new value.
    Rotate,
    /// The record or file that held the key was deleted.
    Delete,
    /// An agent was granted reveals of the key's class.
    Grant,
    /// The owner ruled it no secret: the value went back, and its custody
    /// record was revoked.
    NotASecret,
}

impl FoundKeyAction {
    /// The pinned action word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rotate => "rotate",
            Self::Delete => "delete",
            Self::Grant => "grant",
            Self::NotASecret => "not_a_secret",
        }
    }
}

/// The owner's last act on one found key, and its receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoundKeySettled {
    pub action: FoundKeyAction,
    /// The owner who acted; `None` for a rotation, whose receipt names it.
    pub by: Option<EntityId>,
    pub at: u64,
    /// The act's receipt: `rotation:<hex>`, `redaction:<hex>` or
    /// `gate:<hex>`.
    pub receipt: String,
    /// The standing grant a `grant` wrote; revoke it in the consent
    /// registry.
    pub grant_ref: Option<String>,
}

/// One record's notice as the owner reads it: the record, and each key the
/// mask lifted out of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundKeyNotice {
    /// The record, or the file's ASSET.
    pub record: EntityId,
    pub keys: Vec<FoundKeyCard>,
}

/// One found key, value-free, with the actions the owner may still take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundKeyCard {
    /// The handle the record holds, such as `sc12`.
    pub handle: String,
    /// The custody record's name; the rotate door takes it.
    pub name: String,
    /// The scan rule's word for the key, such as `openai_key`.
    pub kind: String,
    /// Where it sat: `body`, `claim`, `text:<field>`, `file`, or a row
    /// outside the entity tables (`side:<table>`, `attempt`, `intake`).
    pub place: String,
    pub found_at: u64,
    pub settled: Option<FoundKeySettled>,
    /// What the owner may still do about it.
    pub actions: Vec<FoundKeyAction>,
}

/// The keys found in one record. It holds no value.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct FoundKeys {
    keys: Vec<FoundKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FoundKey {
    custody: EntityId,
    handle: String,
    /// The scan's reason code.
    reason: String,
    place: String,
    found_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    settled: Option<FoundKeySettled>,
}

impl FoundKey {
    fn kind(&self) -> &str {
        self.reason
            .strip_prefix(REASON_PREFIX)
            .unwrap_or(&self.reason)
    }

    fn ruled_no_secret(&self) -> bool {
        self.settled
            .as_ref()
            .is_some_and(|settled| settled.action == FoundKeyAction::NotASecret)
    }
}

/// One key a mask lifted, as the mask hands it over.
#[derive(Debug, Clone)]
pub(crate) struct FoundNote {
    pub(crate) record: EntityId,
    pub(crate) custody: EntityId,
    pub(crate) handle: String,
    pub(crate) reason: &'static str,
    pub(crate) place: String,
}

/// Records the keys a mask lifted, in the write's own transaction, and
/// leaves each record they came from due for its notice.
pub(crate) fn note_found_keys_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    notes: &[FoundNote],
    at: u64,
) -> Result<()> {
    let mut by_record: HashMap<EntityId, Vec<&FoundNote>> = HashMap::new();
    for note in notes {
        by_record.entry(note.record).or_default().push(note);
    }
    for (record, notes) in by_record {
        let mut found = FOUND.get(store, txn, &record)?.unwrap_or_default();
        for note in notes {
            if found.keys.iter().any(|key| key.custody == note.custody) {
                continue;
            }
            found.keys.push(FoundKey {
                custody: note.custody,
                handle: note.handle.clone(),
                reason: note.reason.to_owned(),
                place: note.place.clone(),
                found_at: at,
                settled: None,
            });
        }
        FOUND.put(store, txn, &record, &found)?;
        DUE.put(store, txn, &record, &at)?;
    }
    Ok(())
}

/// Raises the needs-you notice of each record left due, one inbox Ask per
/// owner, at a write's commit boundary. A write under an actor's in-flight
/// binding raises none: the next write does.
pub(crate) fn raise_found_key_notices_in_txn(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    if DUE.iter_from(&vault.store, txn, &[])?.next().is_none()
        || crate::federation::actor_for_txn(vault, txn)?.is_some()
    {
        return Ok(());
    }
    let due = DUE
        .iter_from(&vault.store, txn, &[])?
        .take(NOTICES_PER_WRITE)
        .collect::<Result<Vec<_>>>()?;
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    for (record, found_at) in due {
        DUE.delete(&vault.store, txn, &record)?;
        // The count of keys found there names this notice: a later write
        // that finds more raises a new one.
        let keys = FOUND
            .get(&vault.store, txn, &record)?
            .map_or(0, |found| found.keys.len());
        if keys == 0 {
            continue;
        }
        let record_hex = record.to_hex();
        for owner in &owners {
            vault.record_notification_in_txn(
                txn,
                &NotificationEvent {
                    kind: NotificationKind::Ask,
                    source: NotificationSource {
                        producer: NOTIFICATION_PRODUCER_FOUND_KEY.to_owned(),
                        event: format!("{record_hex}:{keys}:{}", owner.to_hex()),
                        result: Some(record_hex.clone()),
                        ..NotificationSource::default()
                    },
                    subject_refs: vec![record],
                    recipient: Some(*owner),
                    created_at: found_at,
                    origin_conversation: None,
                },
            )?;
        }
    }
    Ok(())
}

/// What the owner did about each key a mask found in `record`, in the order
/// they were found; `None` for one not answered yet. The historical lift
/// sweep closes a proposal on a record whose keys are all answered (OF-067).
pub(crate) fn found_key_actions_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    record: &EntityId,
) -> Result<Vec<Option<FoundKeyAction>>> {
    Ok(FOUND
        .get(store, txn, record)?
        .map_or_else(Vec::new, |found| {
            found
                .keys
                .iter()
                .map(|key| key.settled.as_ref().map(|settled| settled.action))
                .collect()
        }))
}

/// The values the owner ruled no secret, by record: the write door reads
/// none of them as a hit in its record, and the mask leaves each as
/// written. Each value is read from its revoked custody record and wiped
/// when dropped; no digest of it is kept anywhere.
#[derive(Clone, Default)]
pub(crate) struct KeptValues(HashMap<EntityId, Vec<Zeroizing<Vec<u8>>>>);

impl std::fmt::Debug for KeptValues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeptValues")
            .field("records", &self.0.len())
            .finish()
    }
}

impl KeptValues {
    /// The kept values of each of `records`, read in `txn`.
    pub(crate) fn for_records_in_txn(
        store: &Store,
        txn: &RoTxn<'_>,
        records: impl IntoIterator<Item = EntityId>,
    ) -> Result<Self> {
        let mut kept = HashMap::new();
        for record in records {
            if kept.contains_key(&record) {
                continue;
            }
            let Some(found) = FOUND.get(store, txn, &record)? else {
                continue;
            };
            let mut values = Vec::new();
            for key in found.keys.iter().filter(|key| key.ruled_no_secret()) {
                if let Some(mut rec) = read_secret_custody_in_txn(store, txn, &key.custody)? {
                    values.push(Zeroizing::new(std::mem::take(&mut rec.value_bytes)));
                }
            }
            if !values.is_empty() {
                kept.insert(record, values);
            }
        }
        Ok(Self(kept))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether the owner ruled `value` no secret in `record`.
    pub(crate) fn holds(&self, record: &EntityId, value: &[u8]) -> bool {
        self.0
            .get(record)
            .is_some_and(|values| values.iter().any(|kept| kept.as_slice() == value))
    }

    /// `bytes` of `record` with each kept value in them overwritten by the
    /// mask's filler, for the door's scan; `None` when none sits there.
    pub(crate) fn screened(&self, record: &EntityId, bytes: &[u8]) -> Option<Vec<u8>> {
        let values = self.0.get(record)?;
        let mut copy = None::<Vec<u8>>;
        for value in values.iter().filter(|value| !value.is_empty()) {
            let mut at = 0;
            loop {
                let haystack = copy.as_deref().unwrap_or(bytes);
                let Some(found) = haystack.get(at..).and_then(|rest| {
                    rest.windows(value.len())
                        .position(|window| window == value.as_slice())
                }) else {
                    break;
                };
                let start = at + found;
                let end = start + value.len();
                copy.get_or_insert_with(|| bytes.to_vec())[start..end].fill(b'*');
                at = end;
            }
        }
        copy
    }
}

impl Vault {
    /// The found-key notices for the owner, newest first: each record the
    /// mask lifted keys out of, with each key's handle, kind, place, what
    /// the owner did about it and what they may still do. `open_only` keeps
    /// the records with a key the owner has not acted on. No value is read.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof is not the owner's.
    pub fn found_keys(
        &self,
        owner: &AuthenticatedOwner,
        open_only: bool,
        limit: usize,
    ) -> Result<Vec<FoundKeyNotice>> {
        owner.revalidate(self)?;
        let txn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for row in FOUND.iter_from(&self.store, &txn, &[])? {
            let (record, found) = row?;
            if open_only && found.keys.iter().all(|key| key.settled.is_some()) {
                continue;
            }
            let latest = found.keys.iter().map(|key| key.found_at).max();
            rows.push((latest, record, found));
        }
        rows.sort_by(|left, right| right.0.cmp(&left.0));
        rows.into_iter()
            .take(limit)
            .map(|(_, record, found)| {
                let keys = found
                    .keys
                    .iter()
                    .map(|key| actions::card_in_txn(self, &txn, &record, key))
                    .collect::<Result<Vec<_>>>()?;
                Ok(FoundKeyNotice { record, keys })
            })
            .collect()
    }
}
