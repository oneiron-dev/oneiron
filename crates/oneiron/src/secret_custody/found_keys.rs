//! The found-key notice (OF-560; owner ruling G04 binary = C2): a write
//! whose mask lifts a key out of a record, or marks a file, raises one
//! non-blocking needs-you notice per record for the owner. The notice is an
//! inbox Ask (`NOTIFICATION`) naming the record; this module keeps what it
//! points at: each key the mask lifted there, with its kind (the scan rule
//! that found it), its `sc` handle and where it sat. Nothing here holds a
//! value.
//!
//! The owner answers each key with one of five doors, each owner-only and
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
//!   record's body or text field gets its value back, a file's mark drops
//!   the key, and the custody record is revoked. The value stays a kept value of that record
//!   ([`KeptValues`]): the write door no longer reads it as a hit there.
//! - **kept as text**: the owner accepts the risk and keeps the marked span as
//!   text by choice, with the same restore, revoke and kept-value screen but a
//!   distinct action and receipt reason.
//!
//! A batch that masks many keys in one record raises one notice for it. The
//! mask writes inside the batch's own transaction, where no vault is at
//! hand, so it leaves the record due ([`note_found_keys_in_txn`]); the
//! write's commit boundary raises the notice ([`raise_found_key_notices_in_txn`]).

mod actions;
mod page;
mod purpose;
pub(crate) use purpose::purpose_questions_in_txn;

pub(crate) use self::actions::{HANDLE_TEXT_OPEN, unmask_value};

use std::collections::HashMap;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::reveal::names_no_actor;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::store::found_key_notice_queue::DUE;
use crate::vault::Vault;

pub(crate) use crate::store::found_key_notice_queue::found_key_notices_due_in_txn;

pub use self::actions::{FOUND_KEY_REASON_KEPT_AS_TEXT, FOUND_KEY_REASON_NOT_A_SECRET};
pub(crate) use self::actions::{
    kept_as_text_in_txn, ruled_no_secret_in_txn, settle_found_key_in_txn,
};
pub use self::page::{FoundKeyCursor, FoundKeyNoticePage};

/// Producer name of a found-key notice.
pub const NOTIFICATION_PRODUCER_FOUND_KEY: &str = "secret.found_key";

/// The most due records one write's commit boundary raises notices for; the
/// rest wait for the next write, or the housekeeping drain
/// ([`raise_found_key_notices_page`]).
const NOTICES_PER_WRITE: usize = 64;

/// The scan's reason codes share this prefix; a key's kind is what follows.
const REASON_PREFIX: &str = "gate.secret_scan.";

/// Each record's found keys. Key: the record's id.
const FOUND: SideTable<EntityId, FoundKeys, Named> = SideTable::new(&side_table::SECRET_FOUND_KEY);

pub use crate::secret_record::FoundKeyAction;

pub use crate::secret_record::FoundKeySettled;

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
    /// The owner's display-label override, when one is set.
    pub label: Option<String>,
    /// The value-free suggestion derived from the scan kind.
    pub suggested_label: Option<String>,
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

    fn kept_as_text(&self) -> bool {
        self.settled
            .as_ref()
            .is_some_and(|settled| settled.action == FoundKeyAction::KeptAsText)
    }

    fn kept_by_owner(&self) -> bool {
        self.ruled_no_secret() || self.kept_as_text()
    }
}

pub(crate) use crate::secret_record::FoundNote;

/// Erasing `actor` from the found keys it settled (FIX 3520): each
/// settlement keeps its action, its time, its receipt and its grant, and
/// names no owner. One-way, in the erase's own transaction. An id whose
/// entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a found-key row that cannot be read.
pub(crate) fn erase_found_key_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut erased = Vec::new();
    for (record, mut found) in FOUND.scan(&vault.store, wtxn)? {
        let mut named = false;
        for key in &mut found.keys {
            if let Some(settled) = &mut key.settled
                && settled.by == Some(*actor)
            {
                settled.by = None;
                named = true;
            }
        }
        if named {
            erased.push((record, found));
        }
    }
    for (record, found) in &erased {
        FOUND.put(&vault.store, wtxn, record, found)?;
    }
    Ok(())
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

/// Raises the notices of the next [`NOTICES_PER_WRITE`] records left due, in
/// a write of their own: the housekeeping drain for a vault that goes quiet
/// with more due than one write raises (FIX 2648). That write carries nothing
/// else, so its commit boundary raises them
/// ([`raise_found_key_notices_in_txn`]). Returns how many records the page
/// took and whether any is still due; with none due it takes no write.
pub(crate) fn raise_found_key_notices_page(vault: &Vault) -> Result<(usize, bool)> {
    if !found_key_notices_due_in_txn(vault, &vault.store.env.read_txn()?)? {
        return Ok((0, false));
    }
    let page = vault.with_write_txn_grouped(|wtxn| {
        Ok(DUE
            .iter_from(&vault.store, wtxn, &[])?
            .take(NOTICES_PER_WRITE)
            .collect::<Result<Vec<_>>>()?
            .len())
    })?;
    let more = found_key_notices_due_in_txn(vault, &vault.store.env.read_txn()?)?;
    Ok((page, more))
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

/// The custody record of each key a mask lifted out of `record`, in the
/// order they were found: what an erase of a row outside the entity tables
/// revokes (FIX 6710).
pub(super) fn found_key_custody_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    record: &EntityId,
) -> Result<Vec<EntityId>> {
    Ok(FOUND
        .get(store, txn, record)?
        .map_or_else(Vec::new, |found| {
            found.keys.iter().map(|key| key.custody).collect()
        }))
}

/// Moves a deleted side row's found-key state to its replacement's origin (FIX
/// 12779, REVIEW-4444 follow-up): every `FOUND` key under `old` joins `new`,
/// merged by custody without losing either side's settlement or the earliest
/// `found_at`, and `old`'s `DUE` marker moves to `new` without losing a
/// destination marker. Leaves no `FOUND`/`DUE` under `old`. Each moved
/// custody's mask origin is rebound `old` -> `new` only when it still names
/// `old`, so a known value the row references keeps its owner. Skips cleanly
/// when `old` holds nothing. Runs in the caller's write transaction, with the
/// row move it follows: the handles the new row keeps still resolve.
pub(crate) fn move_side_row_custody_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    old: &EntityId,
    new: &EntityId,
) -> Result<()> {
    if old == new {
        return Ok(());
    }
    if let Some(old_found) = FOUND.get(store, wtxn, old)? {
        for key in &old_found.keys {
            crate::batch::secret_scan::rebind_mask_origin_in_txn(
                store,
                wtxn,
                &key.custody,
                old,
                new,
            )?;
        }
        let mut merged = FOUND.get(store, wtxn, new)?.unwrap_or_default();
        for key in old_found.keys {
            match merged
                .keys
                .iter_mut()
                .find(|held| held.custody == key.custody)
            {
                Some(held) => {
                    if held.settled.is_none() {
                        held.settled = key.settled;
                    }
                    held.found_at = held.found_at.min(key.found_at);
                }
                None => merged.keys.push(key),
            }
        }
        if !merged.keys.is_empty() {
            FOUND.put(store, wtxn, new, &merged)?;
        }
        FOUND.delete(store, wtxn, old)?;
    }
    if let Some(old_due) = DUE.get(store, wtxn, old)? {
        if DUE.get(store, wtxn, new)?.is_none() {
            DUE.put(store, wtxn, new, &old_due)?;
        }
        DUE.delete(store, wtxn, old)?;
    }
    Ok(())
}

/// The values the owner ruled no secret or kept as text by choice, by record:
/// the write door reads none of them as a hit in that record, and the mask
/// leaves each as written. Each value is read from its revoked custody record
/// and wiped when dropped; no digest of it is kept anywhere.
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
            for key in found.keys.iter().filter(|key| key.kept_by_owner()) {
                if let Some(mut rec) = super::read_secret_custody_in_txn(store, txn, &key.custody)?
                {
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

    /// Whether the owner ruled `value` no secret or kept it as text in `record`,
    /// as it is or as one of its spellings decodes (base64, percent or JSON
    /// escapes): the choice covers the value however it is written (FIX 2725).
    pub(crate) fn holds(&self, record: &EntityId, value: &[u8]) -> bool {
        let Some(values) = self.0.get(record) else {
            return false;
        };
        let ruled = |bytes: &[u8]| values.iter().any(|kept| kept.as_slice() == bytes);
        ruled(value)
            || super::known_values::decodings(value)
                .iter()
                .any(|decoded| ruled(decoded.as_slice()))
    }

    /// `bytes` of `record` with each kept value's raw or encoded spelling
    /// overwritten by the mask's filler, for the door's scan; `None` when none
    /// sits there.
    pub(crate) fn screened(&self, record: &EntityId, bytes: &[u8]) -> Option<Vec<u8>> {
        let values = self.0.get(record)?;
        let mut copy = None::<Vec<u8>>;
        for value in values.iter().filter(|value| !value.is_empty()) {
            for span in super::known_values::occurrences(bytes, value) {
                copy.get_or_insert_with(|| bytes.to_vec())[span].fill(b'*');
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
