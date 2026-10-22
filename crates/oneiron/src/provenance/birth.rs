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

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess, MadeByTrigger,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{DeletionMarker, EntityStoreRead, TombstoneStoreRead};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::{ManifestDbs, Store};
use crate::vault::live_entity_row_in_txn;
use crate::write_envelope::WriteActor;
pub(crate) mod checkpoint;
pub(crate) mod room;

/// Most hex characters a birth's input hash may carry.
const MAX_CONTENT_HASH_HEX: usize = 128;

/// Hex characters of a withheld ref's keyed hash in its handle, after `wh_`
/// (64 bits; an open call in engine-calls-review/CALLS.md, "OF-491 Q26
/// handles").
const WITHHELD_HANDLE_HEX: usize = 16;

/// The birth envelope of one row: Rule A's `made_by` plus the derivation
/// memo-key's input hash (ARCH-0035, `content_hash`: the hash of the exact
/// input records and claims read).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// The evidence refs a room write's caller supplied, as supplied (FIX
    /// 4281): bookkeeping only a room's own stamper keeps
    /// ([`room::stamp_room_birth_in_txn`]), never authenticated evidence. A
    /// base stamp treats it as absent, and no copy carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room_evidence: Option<RoomEvidence>,
}

/// The evidence refs a room write's caller named, each with what the room
/// read it as (FIX 4281, Engine 10-22). A ref the room did not read as a
/// TURN is kept as supplied: the room accepts it, and it is no evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomEvidence {
    /// Every supplied ref, in the order given.
    pub refs: Vec<RoomEvidenceRef>,
}

/// One supplied evidence ref of a room write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomEvidenceRef {
    /// The ref as the caller spelled it.
    pub supplied: String,
    /// The 32 hex digits of the TURN the caller read it as in the room, one
    /// of the birth's inputs; `None` for a ref the room read as no TURN.
    pub turn: Option<String>,
}

/// A ref a birth names that its copy's destination may not see (Q26 = B): a
/// handle in its place, never the ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WithheldRef {
    /// `wh_` and 16 hex of the ref keyed by the copy's [`WithheldKey`]: one
    /// ref reads as one handle within a copy, and the handle never reverses.
    pub handle: String,
    pub role: WithheldRole,
}

/// What a withheld ref was in the birth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
            room_evidence: None,
        }
    }

    /// This birth as a copy carries it to a destination that sees only the
    /// rows `ships` admits (Q26 = B). Each input, and the trigger, whose row
    /// it refuses moves to `withheld` as a handle. Who made the row, by which
    /// process and when, and the input hash ship whole. A room's evidence
    /// refs never ship: they are the room's bookkeeping, as supplied.
    #[must_use]
    pub fn masked(&self, ships: impl Fn(&EntityId) -> bool, key: &WithheldKey) -> Self {
        let mut birth = self.clone();
        birth.room_evidence = None;
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

    /// This birth with each input and prompt ref, and the ref its trigger
    /// names, renamed by `rename`: a copy that lands a ref's row under
    /// another id names it by that id (FIX 3890). The trigger keeps its kind.
    /// Who made the row, by which process and when, the input hash and the
    /// refs it already withholds stay as they are. A room's evidence refs,
    /// spelled as supplied, are not renamed: the copy drops them.
    #[must_use]
    pub fn renamed_refs(&self, rename: impl Fn(EntityId) -> EntityId) -> Self {
        let mut birth = self.clone();
        birth.room_evidence = None;
        for input in &mut birth.made_by.inputs {
            input.row = rename(input.row);
        }
        if let Some(
            MadeByTrigger::Task(row)
            | MadeByTrigger::Ask(row)
            | MadeByTrigger::Run(row)
            | MadeByTrigger::Skill(row),
        ) = birth.made_by.trigger.as_mut()
        {
            *row = rename(*row);
        }
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
        let mut seen = std::collections::BTreeSet::new();
        let named: Vec<MadeByInput> = inputs
            .iter()
            .filter(|row| seen.insert(**row))
            .map(|row| MadeByInput {
                row: *row,
                role: MadeByInputRole::Input,
            })
            .collect();
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
            room_evidence: None,
        })
    }

    /// Whether this is a document birth: the stand-in a document's first
    /// commit stamps when no door stamped the row (`entity_doc`'s doors).
    pub(crate) fn is_document_birth(&self) -> bool {
        self.made_by.process.identity.starts_with("entity_doc.")
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
    /// process, a hex input hash, well-formed withheld handles, and a prompt
    /// input on every triggered birth (the same rule `RowProvenance::fold`
    /// applies to a birth commit). A concluded birth names what it was made
    /// from, but for a room's: it keeps the evidence its caller supplied,
    /// none of which the room may have read as a TURN (FIX 4281). No count
    /// of inputs or handles is refused.
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
        let handles_ok = self.withheld.iter().all(|w| {
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
            || !hash_ok
            || !handles_ok
            || (names_trigger && !has_prompt)
            || (made_by.process.class == MadeByClass::Concluded
                && !names_input
                && self.room_evidence.is_none())
        {
            return Err(Error::InvalidConfig(
                "a row birth needs a valid process, a hex input hash, well-formed withheld handles \
                 and a prompt input when it names a trigger"
                    .into(),
            ));
        }
        Ok(())
    }

    /// This birth as a base stamp takes it: a room's evidence stripped, so a
    /// marker a guest supplied counts for nothing outside a room (FIX 4281).
    fn base_form(&self) -> std::borrow::Cow<'_, Self> {
        if self.room_evidence.is_none() {
            return std::borrow::Cow::Borrowed(self);
        }
        let mut birth = self.clone();
        birth.room_evidence = None;
        std::borrow::Cow::Owned(birth)
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
/// row already has a different birth; storage errors as they occur. A
/// room's evidence on `birth` is treated as absent ([`RowBirth::base_form`]).
pub(crate) fn stamp_row_birth_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
    birth: &RowBirth,
) -> Result<()> {
    let birth = birth.base_form();
    let birth = &*birth;
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
/// lists the row once the trigger lands. A document birth stamped before the
/// carried one landed was a stand-in: the carried birth replaces it (Engine
/// 10-18, FIX 1180: the origin's carried birth wins). A birth whose process
/// actor this vault hard-erased never lands (FIX 6279): this vault's own
/// `dt:` marker for the actor, read in this transaction, decides, as
/// `deletion::ACTOR_ERASE_CARRIER_SOURCE` says; never an absent row or a
/// peer's word.
///
/// # Errors
///
/// [`Error::InvalidConfig`] for a malformed envelope, an absent row or an
/// actor erased here; [`Error::InvariantViolation`] when the row already has
/// a different birth that is not a document birth; storage errors as they
/// occur. A room's evidence on `birth` is treated as absent
/// ([`RowBirth::base_form`]).
pub(crate) fn stamp_replicated_row_birth_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
    birth: &RowBirth,
) -> Result<()> {
    let birth = birth.base_form();
    let birth = &*birth;
    birth.check_shape()?;
    if !live_entity_row_in_txn(store, txn, row)?.is_live() {
        return Err(Error::InvalidConfig(
            "a replicated row birth names a row this transaction does not hold".into(),
        ));
    }
    let maker = &birth.made_by.process.actor;
    if store.port_deletion_marked(txn, DeletionMarker::HardDelete, maker)? {
        return Err(Error::InvalidConfig(
            "a replicated row birth names an actor this vault erased".into(),
        ));
    }
    match ROW_BIRTH.get(store, txn, row)? {
        Some(stored) if stored == *birth => return Ok(()),
        Some(stored) if stored.is_document_birth() => {
            if let Some(trigger) = &stored.made_by.trigger {
                BIRTH_BY_TRIGGER.delete(store, txn, &(trigger.row(), *row))?;
            }
        }
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

/// Erasing `actor` (FIX 6074): every birth that names it as its process
/// actor goes, with its born-from index row, in the erase's own transaction,
/// and so does every window carrier of one this vault keeps (FIX 6279). A
/// birth has no erased form (its process names one actor), so the born rows
/// and their content stay and their births read unknown, as a KS-7 restore
/// leaves out a birth whose actor does not open. A born row a legal hold
/// keeps keeps its birth and its carrier (FIX 6280, ARCH-0038: every
/// destructive path checks) until the hold lifts:
/// [`release_held_births_in_txn`] drops them then.
///
/// # Errors
///
/// Storage errors, or a stored birth that does not decode.
pub(crate) fn erase_birth_actor_in_txn(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let actors = BTreeSet::from([*actor]);
    drop_actor_births_in_txn(vault, wtxn, &actors)?;
    #[cfg(feature = "sync")]
    crate::sync::row_birth::actor_erase::erase_birth_carriers_in_txn(vault, wtxn, &actors)?;
    Ok(())
}

/// The births a legal hold kept from the scrubs of the hard-erased ids
/// `erased`, once nothing holds their rows (FIX 6280): each goes, with its
/// born-from index row, and when one did, every window carrier of a birth
/// one of them made whose row no hold keeps. A row still held keeps both.
///
/// # Errors
///
/// Storage errors, or a stored birth that does not decode.
pub(crate) fn release_held_births_in_txn(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    erased: &BTreeSet<EntityId>,
) -> Result<()> {
    if drop_actor_births_in_txn(vault, wtxn, erased)? {
        #[cfg(feature = "sync")]
        crate::sync::row_birth::actor_erase::erase_birth_carriers_in_txn(vault, wtxn, erased)?;
    }
    Ok(())
}

/// Drops each birth whose process actor is in `actors`, but for a born row a
/// legal hold keeps. Whether any went.
fn drop_actor_births_in_txn(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    actors: &BTreeSet<EntityId>,
) -> Result<bool> {
    let mut dropped = false;
    for (row, birth) in ROW_BIRTH.scan(&vault.store, wtxn)? {
        if actors.contains(&birth.made_by.process.actor)
            && !birth_held_in_txn(&vault.store, wtxn, &row)?
        {
            erase_row_birth_in_txn(&vault.store, wtxn, &row)?;
            dropped = true;
        }
    }
    Ok(dropped)
}

/// Whether a legal hold keeps `row`'s birth: a hold on the row itself or,
/// for a key pad, on its world or a claim its key seals. These are the holds
/// the row's own erase refuses on (`erase_row_provenance_in_txn`), read here
/// as a bool, so an actor's scrub leaves the birth rather than refusing the
/// whole erase (OF-470).
///
/// # Errors
///
/// Storage errors, or a pad body that does not decode.
pub(crate) fn birth_held_in_txn(store: &Store, txn: &RoTxn<'_>, row: &EntityId) -> Result<bool> {
    if crate::store::legal_hold::held_in_txn(store, txn, row.as_bytes())? {
        return Ok(true);
    }
    match store.port_entity_raw(txn, row)? {
        Some(raw) => crate::world_keys::held_pad_world_in_txn(store, txn, &raw),
        None => Ok(false),
    }
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
