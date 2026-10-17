//! Rule A at row birth: one immutable `made_by` envelope per born row, written
//! beside the row in the transaction that births it (ARCH-0035 Rule A; owner
//! 2026-09-17: "one born-from shape for every generated artifact: summary,
//! lens, code, generated UI, explainer").
//!
//! A row whose text is born as a document carries the same value in its first
//! commit's receipt (`text_commit`, `proposal_text`); this record is the birth
//! of a row that has no document yet. Later commits carry their own receipts,
//! so a row's full provenance is still the fold of its commits.
//!
//! The trigger index reads the born-from ref backwards: a task, ask, run or
//! skill lists the rows it produced (ARCH-0078: "Read that ref backwards and a
//! task has its artifacts").

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess, MadeByTrigger,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::ManifestDbs;
use crate::vault::live_entity_row_in_txn;
use crate::write_envelope::WriteActor;

/// Most inputs one birth may name; the text-commit fold keeps the same bound.
pub const MAX_BIRTH_INPUTS: usize = 1024;

/// Most hex characters a birth's input hash may carry.
const MAX_CONTENT_HASH_HEX: usize = 128;

/// Hex characters of a withheld ref's keyed hash in its handle, after `wh_`
/// (64 bits; an open call in engine-calls-review/CALLS.md, "OF-491 Q26
/// handles").
const WITHHELD_HANDLE_HEX: usize = 16;

/// The birth envelope of one row: Rule A's `made_by` plus the derivation
/// memo-key's input hash (ARCH-0035, `content_hash`: the hash of the exact
/// input records and claims read).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RowBirth {
    pub made_by: MadeBy,
    /// Lowercase hex of the hash of the exact inputs as read; empty for a
    /// stated birth that read nothing.
    pub content_hash: String,
    /// Refs a copy of this birth withholds from its destination
    /// ([`RowBirth::masked`]); empty in the vault's own birth row.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub withheld: Vec<WithheldRef>,
}

/// A ref a birth names that its copy's destination may not see (Q26 = B): a
/// handle in its place, never the ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithheldRef {
    /// `wh_` and 16 hex of the ref keyed by the copy's [`WithheldKey`]: one
    /// ref reads as one handle within a copy, and the handle never reverses.
    pub handle: String,
    pub role: WithheldRole,
}

/// What a withheld ref was in the birth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithheldRole {
    Input,
    Prompt,
    Trigger,
}

/// One copy's masking key. An export takes a fresh one, so its handles link
/// to no other copy; a replicated birth, which its destination keeps
/// immutable, takes its destination's stable key, so a resync writes the same
/// handles.
pub struct WithheldKey([u8; 32]);

impl WithheldKey {
    #[must_use]
    pub fn fresh() -> Self {
        let mut key = [0; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut key);
        Self(key)
    }

    /// The key one export masks its births under: fresh, so no two exports
    /// link their handles (the open call "OF-491 Q26 handles" in
    /// engine-calls-review/CALLS.md).
    #[must_use]
    pub fn for_export() -> Self {
        Self::fresh()
    }

    /// The stable key for every copy bound for `destination`: the vault's
    /// local withheld secret, made on first use and never shipped, keys a
    /// hash of the destination bytes. One destination reads one ref as one
    /// handle on every sync; two destinations cannot join their handles.
    ///
    /// # Errors
    ///
    /// Storage errors as they occur.
    pub fn for_destination(vault: &crate::Vault, destination: &[u8]) -> Result<Self> {
        // Only the first call writes: once the secret exists, a read serves.
        let secret = {
            let txn = vault.store.env.read_txn()?;
            WITHHELD_SECRET.get(&vault.store, &txn, &())?
        };
        if let Some(secret) = secret {
            return Ok(Self::keyed(&secret, destination));
        }
        vault.with_write_txn_grouped(|txn| {
            Self::for_destination_in_txn(&vault.store, txn, destination)
        })
    }

    /// [`WithheldKey::for_destination`] inside the caller's transaction.
    pub(crate) fn for_destination_in_txn(
        store: &impl ManifestDbs,
        txn: &mut RwTxn<'_>,
        destination: &[u8],
    ) -> Result<Self> {
        let secret = if let Some(secret) = WITHHELD_SECRET.get(store, txn, &())? {
            secret
        } else {
            let secret = Self::fresh().0;
            WITHHELD_SECRET.put(store, txn, &(), &secret)?;
            secret
        };
        Ok(Self::keyed(&secret, destination))
    }

    fn keyed(secret: &[u8; 32], destination: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new_keyed(secret);
        hasher.update(b"oneiron.provenance.withheld.destination.v1\0");
        hasher.update(destination);
        Self(*hasher.finalize().as_bytes())
    }

    fn handle(&self, row: &EntityId) -> String {
        format!(
            "wh_{}",
            &blake3::keyed_hash(&self.0, row.as_bytes()).to_hex()[..WITHHELD_HANDLE_HEX]
        )
    }
}

impl RowBirth {
    /// A stated birth: a person or an import wrote the row from nothing the
    /// engine read, so there is no prompt, trigger or input hash.
    #[must_use]
    pub const fn stated(made_by: MadeBy) -> Self {
        Self {
            made_by,
            content_hash: String::new(),
            withheld: Vec::new(),
        }
    }

    /// This birth as a copy carries it to a destination that sees only the
    /// rows `ships` admits (Q26 = B). Each input, and the trigger, whose row
    /// it refuses moves to `withheld` as a handle. Who made the row, by which
    /// process and when, and the input hash ship whole.
    #[must_use]
    pub fn masked(&self, ships: impl Fn(&EntityId) -> bool, key: &WithheldKey) -> Self {
        let mut birth = self.clone();
        let mut withheld = std::mem::take(&mut birth.withheld);
        birth.made_by.inputs.retain(|input| {
            if ships(&input.row) {
                return true;
            }
            withheld.push(WithheldRef {
                handle: key.handle(&input.row),
                role: match input.role {
                    MadeByInputRole::Input => WithheldRole::Input,
                    MadeByInputRole::Prompt => WithheldRole::Prompt,
                },
            });
            false
        });
        if let Some(row) = birth.made_by.trigger.as_ref().map(MadeByTrigger::row)
            && !ships(&row)
        {
            withheld.push(WithheldRef {
                handle: key.handle(&row),
                role: WithheldRole::Trigger,
            });
            birth.made_by.trigger = None;
        }
        birth.withheld = withheld;
        birth
    }

    /// The birth of a row `actor` wrote through `door` at `at`, made from
    /// `inputs`, whose bytes as the door read them are `read`. It names no
    /// prompt or trigger: a door that has them builds its own envelope.
    /// `None` for a concluded birth that names no input: a concluded birth
    /// names what it was made from, and the door has nothing to name.
    pub(crate) fn written(
        actor: WriteActor,
        class: MadeByClass,
        door: &str,
        inputs: &[EntityId],
        read: &[&[u8]],
        at: u64,
    ) -> Option<Self> {
        if class == MadeByClass::Concluded && inputs.is_empty() {
            return None;
        }
        let mut named: Vec<MadeByInput> = Vec::with_capacity(inputs.len());
        for row in inputs {
            if !named.iter().any(|input| input.row == *row) {
                named.push(MadeByInput {
                    row: *row,
                    role: MadeByInputRole::Input,
                });
            }
        }
        Some(Self {
            made_by: MadeBy {
                inputs: named,
                process: MadeByProcess {
                    actor: actor.entity_ref(),
                    class,
                    identity: door.to_owned(),
                    version: "1".into(),
                    // A write door takes no render parameters.
                    params_hash: format!("{:x}", Sha256::digest([])),
                },
                at,
                trigger: None,
            },
            content_hash: if read.is_empty() {
                String::new()
            } else {
                Self::content_hash_of(read)
            },
            withheld: Vec::new(),
        })
    }

    /// The input hash over `parts`, each length-prefixed so two splits of the
    /// same bytes never collide.
    #[must_use]
    pub fn content_hash_of(parts: &[&[u8]]) -> String {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron made_by content_hash v1");
        for part in parts {
            hasher.update(&(part.len() as u64).to_le_bytes());
            hasher.update(part);
        }
        hasher.finalize().to_hex().to_string()
    }

    /// The shape rules a birth must meet before any row is read: a valid
    /// process, bounded inputs, a hex input hash, and a prompt input on every
    /// triggered birth (the same rule `RowProvenance::fold` applies to a
    /// birth commit). A concluded birth names what it was made from.
    fn check_shape(&self) -> Result<()> {
        let made_by = &self.made_by;
        let withheld = |role: WithheldRole| self.withheld.iter().any(|w| w.role == role);
        let has_prompt = made_by
            .inputs
            .iter()
            .any(|input| input.role == MadeByInputRole::Prompt)
            || withheld(WithheldRole::Prompt);
        let names_trigger = made_by.trigger.is_some() || withheld(WithheldRole::Trigger);
        let names_input = !made_by.inputs.is_empty()
            || withheld(WithheldRole::Input)
            || withheld(WithheldRole::Prompt);
        let handles_ok = self.withheld.len() <= MAX_BIRTH_INPUTS + 1
            && self.withheld.iter().all(|w| {
                w.handle.strip_prefix("wh_").is_some_and(|hex| {
                    hex.len() == WITHHELD_HANDLE_HEX
                        && hex
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
            });
        let hash_ok = self.content_hash.len() <= MAX_CONTENT_HASH_HEX
            && self
                .content_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !made_by.process.is_valid()
            || made_by.inputs.len() > MAX_BIRTH_INPUTS
            || !hash_ok
            || !handles_ok
            || (names_trigger && !has_prompt)
            || (made_by.process.class == MadeByClass::Concluded && !names_input)
        {
            return Err(Error::InvalidConfig(
                "a row birth needs a valid process, bounded inputs, a hex input hash and a prompt \
                 input when it names a trigger"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// One row's birth envelope. Key: id16 (the born row).
const ROW_BIRTH: SideTable<EntityId, RowBirth, Named> =
    SideTable::new(&side_table::PROVENANCE_ROW_BIRTH);

/// The born-from index. Key: id16 (the trigger's ref) + id16 (the born row).
const BIRTH_BY_TRIGGER: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::PROVENANCE_BIRTH_BY_TRIGGER);

/// The vault's local secret behind [`WithheldKey::for_destination`]. Key:
/// `()`; value: 32 raw bytes. Local only: no copy or sync ships it.
const WITHHELD_SECRET: SideTable<(), [u8; 32], Raw> =
    SideTable::new(&side_table::PROVENANCE_WITHHELD_SECRET);

/// A run's durable replay record, the identity a `Run` trigger names.
const CODE_RUN_REPLAY_KEYS: SideTable<EntityId, (), Raw> =
    SideTable::new(&side_table::CODE_RUN_REPLAY);

/// Whether `trigger` names a live row of its kind (a run: a stored replay
/// record) in this transaction.
pub(crate) fn trigger_is_live_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    trigger: &MadeByTrigger,
) -> Result<bool> {
    let expected = match trigger {
        MadeByTrigger::Task(_) => crate::registry::ENTITY_TYPE_TASK,
        MadeByTrigger::Ask(_) => crate::registry::ENTITY_TYPE_TURN,
        MadeByTrigger::Skill(_) => crate::registry::ENTITY_TYPE_SKILL,
        MadeByTrigger::Run(run) => return CODE_RUN_REPLAY_KEYS.contains(store, txn, run),
    };
    Ok(live_entity_row_in_txn(store, txn, &trigger.row())?.live_type() == Some(expected))
}

/// Whether `run` has a durable replay record, for a receipt that names it.
pub(crate) fn run_exists(vault: &crate::Vault, run: &EntityId) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    CODE_RUN_REPLAY_KEYS.contains(&vault.store, &rtxn, run)
}

/// Stamps `row`'s birth inside the transaction that births it. The row must
/// be live; every prompt input must be a live row a reader can open, and a
/// trigger must name a live task, ask, run or skill. Birth is immutable: the
/// same envelope again is a no-op, a different one is refused.
///
/// # Errors
///
/// [`Error::InvalidConfig`] for a malformed envelope, an absent row, an
/// unreadable prompt or a dead trigger; [`Error::InvariantViolation`] when the
/// row already has a different birth; storage errors as they occur.
pub(crate) fn stamp_row_birth_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
    birth: &RowBirth,
) -> Result<()> {
    birth.check_shape()?;
    // A local producer names its own refs; only a copy withholds any.
    if !birth.withheld.is_empty() {
        return Err(Error::InvalidConfig(
            "a locally stamped row birth withholds no ref".into(),
        ));
    }
    if !live_entity_row_in_txn(store, txn, row)?.is_live() {
        return Err(Error::InvalidConfig(
            "a row birth names a row this transaction does not hold".into(),
        ));
    }
    for input in &birth.made_by.inputs {
        if input.role == MadeByInputRole::Prompt
            && !live_entity_row_in_txn(store, txn, &input.row)?.is_live()
        {
            return Err(Error::InvalidConfig(
                "a row birth's prompt input is not a live row".into(),
            ));
        }
    }
    if let Some(trigger) = &birth.made_by.trigger
        && !trigger_is_live_in_txn(store, txn, trigger)?
    {
        return Err(Error::InvalidConfig(
            "a row birth's trigger is not a live task, ask, run or skill".into(),
        ));
    }
    match ROW_BIRTH.get(store, txn, row)? {
        Some(stored) if stored == *birth => return Ok(()),
        Some(_) => {
            return Err(Error::InvariantViolation(
                "a row's birth envelope is immutable",
            ));
        }
        None => {}
    }
    ROW_BIRTH.put(store, txn, row, birth)?;
    if let Some(trigger) = &birth.made_by.trigger {
        BIRTH_BY_TRIGGER.put(store, txn, &(trigger.row(), *row), &())?;
    }
    Ok(())
}

/// Stamps `row`'s birth unless it already has one. A document birth names
/// the row's birth actor and time; a row its writing door stamped keeps
/// that birth, so the door's richer envelope is never refused here.
///
/// # Errors
///
/// As [`stamp_row_birth_in_txn`].
pub(crate) fn stamp_birth_if_absent_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
    birth: &RowBirth,
) -> Result<()> {
    if ROW_BIRTH.contains(store, txn, row)? {
        return Ok(());
    }
    stamp_row_birth_in_txn(store, txn, row, birth)
}

/// Stamps a birth that arrived on sync beside its row. The shape rules, the
/// live-row rule and immutability hold as in [`stamp_row_birth_in_txn`], but
/// a prompt input or trigger may be absent here: it can sit in another
/// window, outside the receiver's grant, or not have arrived yet. The trigger
/// index is written from the envelope alone, so the born-from read still
/// lists the row once the trigger lands.
///
/// # Errors
///
/// [`Error::InvalidConfig`] for a malformed envelope or an absent row;
/// [`Error::InvariantViolation`] when the row already has a different birth;
/// storage errors as they occur.
pub(crate) fn stamp_replicated_row_birth_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
    birth: &RowBirth,
) -> Result<()> {
    birth.check_shape()?;
    if !live_entity_row_in_txn(store, txn, row)?.is_live() {
        return Err(Error::InvalidConfig(
            "a replicated row birth names a row this transaction does not hold".into(),
        ));
    }
    match ROW_BIRTH.get(store, txn, row)? {
        Some(stored) if stored == *birth => return Ok(()),
        Some(_) => {
            return Err(Error::InvariantViolation(
                "a row's birth envelope is immutable",
            ));
        }
        None => {}
    }
    ROW_BIRTH.put(store, txn, row, birth)?;
    if let Some(trigger) = &birth.made_by.trigger {
        BIRTH_BY_TRIGGER.put(store, txn, &(trigger.row(), *row), &())?;
    }
    Ok(())
}

/// `row`'s birth envelope, or `None` when the row has no stamped birth.
/// Unknown provenance is never read as stated.
pub(crate) fn row_birth_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    row: &EntityId,
) -> Result<Option<RowBirth>> {
    ROW_BIRTH.get(store, txn, row)
}

/// The rows whose birth names `trigger` (a task, ask, run or skill ref), in
/// id order.
pub(crate) fn rows_born_from_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    trigger: &EntityId,
) -> Result<Vec<EntityId>> {
    Ok(BIRTH_BY_TRIGGER
        .scan_keys(store, txn, trigger.as_bytes())?
        .into_iter()
        .map(|(_, row)| row)
        .collect())
}

/// Drops `row`'s birth and its born-from index row. The erase paths call it
/// beside the row's other carriers, so a recreated id is born afresh.
pub(crate) fn erase_row_birth_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
) -> Result<()> {
    if let Some(birth) = ROW_BIRTH.get(store, txn, row)? {
        if let Some(trigger) = &birth.made_by.trigger {
            BIRTH_BY_TRIGGER.delete(store, txn, &(trigger.row(), *row))?;
        }
        ROW_BIRTH.delete(store, txn, row)?;
    }
    Ok(())
}

impl crate::Vault {
    /// `row`'s birth envelope (Rule A), or `None` when none was stamped.
    ///
    /// # Errors
    ///
    /// Storage errors, or a stored envelope that does not decode.
    pub fn row_birth(&self, row: &EntityId) -> Result<Option<RowBirth>> {
        let rtxn = self.store.env.read_txn()?;
        row_birth_in_txn(&self.store, &rtxn, row)
    }

    /// The rows born from `trigger`: a task's, ask's, run's or skill's
    /// artifacts, read through their `made_by` trigger.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn rows_born_from(&self, trigger: &EntityId) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        rows_born_from_in_txn(&self.store, &rtxn, trigger)
    }
}
