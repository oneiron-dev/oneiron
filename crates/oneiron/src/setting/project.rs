//! The act is the write (stage 7a-2; DESIGN 1.6 "What travels", "The fold and the projection").
//!
//! In a vault with an authority root, an owner's change of a row that travels
//! ([`travels`]: a `sync: vault` key that is not learned) appends its signed act in the change's
//! own write, naming its row and carrying its value ([`append_act_in_txn`]): inside the act where
//! the key's value type is closed and its JSON fits, else beside it (stage 7c-1,
//! [`super::beside`]). The act is no longer best effort: a machine that cannot carry it
//! refuses the change, with the append's typed reason, and nothing is written.
//!
//! The projection writes such a row from the acts the fold counts ([`project_target_in_txn`]):
//! - the heads agree: their value, or no row for a clear;
//! - on a key whose order has a meet, the heads that differ meet (a clear of the vault value row
//!   gives the accepted default, a clear of any other row no bound);
//! - on any other key, heads that differ conflict, and the last act every head descends from
//!   stays in force (no row when none does), [`SettingStanding::Conflict`];
//! - a value this build cannot decode or check reads the key's strictest value:
//!   [`SettingStanding::Quarantined`].
//!
//! Each head is read by what it counts for here (stage 7b-2; DESIGN 1.6, "What an act counts
//! for"; [`ChoiceCount`]). One that counts in full gives its value. One whose decider is proved
//! and whose entry is in doubt here (its carrier raced its removal, it landed restriction only,
//! this install's holds keep its carrier back, or two copies of it disagree) is a safe move: on a
//! key whose order has a meet it gives the stricter of its value and what the acts it replaced
//! give, each read the same way ([`Walk`]); on any other key it gives what it replaced, as the
//! register reads it. An act with no proof where one is needed waits in no frontier: a proposal,
//! which changes nothing.
//!
//! It writes the row and one change row only when the row the acts give differs from the one
//! stored, or the stored one is not the owner's, and runs the key's hook. It records the
//! revision it projected ([`super::tables::SETTING_PROJECTION`]), so a pass over the same
//! revision writes nothing, and a row a person, an agent or the engine changed on this install
//! alone stays as they left it until an act names the row again (RULING SETTING-7A-2-DECIDERS =
//! A). It runs in the door's own write, after every commit that stored an authority row
//! ([`Vault::project_settings_after_authority_ingest`]), after every commit that stored a value
//! beside an act, and at open. A key this build does not know, a signed record that keeps only a
//! digest (an older door's, or a change of a key that does not travel), and a head the log here
//! does not hold leave the row as it is. A head whose value is beside its act and has not
//! reached this install leaves it too: the row reads as it did before that act, `Pending`, until
//! the value arrives (stage 7c-1; DESIGN 1.6, "Fold states"). A value beside an act that does not
//! match its digest, or was erased, reads the key's strictest value, `Quarantined`.
//!
//! The read on proofs (stage 7b-3; DESIGN 1.6, "The read of one slot", "Fold states" and
//! "Receipts"):
//! - a key judged by its own comparator ([`super::Order::Custom`]) reads its heads by it: a safe
//!   move gives its value where the comparator says it is no wider than what it replaced, else
//!   what it replaced; of several heads the one no wider than every other stands, and where none
//!   is, the key's strictest value, [`SettingStanding::Conflict`];
//! - an act two copies of which disagree ([`ChoiceCount::Disputed`]) quarantines the row;
//! - a pin whose acts do not all count in full is read as a value row at its scope: it narrows
//!   and releases nothing ([`pin_reads_as_value_in_txn`]);
//! - the empty slot of a vault value row gives the accepted default, the item's row as the
//!   item-less one;
//! - the row reads [`SettingStanding::Held`] where this install's own counting holds a head
//!   back, and [`SettingStanding::Pending`] while an act on it waits for the owner's proof
//!   ([`super::proposal`]);
//! - each change row the projection writes, and the door's own change row it receipts, names the
//!   other heads the value was met with and how the acts stood ([`ChangeStanding`]).
//!
//! The door's own act that would wait for the owner's proof is refused, and nothing of the
//! change is stored, as the choice doors refuse theirs (ruling CARRIER-CHOICE-DOOR-WAIT-OR-REFUSE
//! = B): such an act changes nothing on any machine, the acting one included.
//!
//! A carried row travels as a move's copy (stage 7a-4; [`crate::setting::carry`]): a copy head
//! reads as the meet of the acts it names, each read on this install by this install's own
//! counting (a named act it refused, cannot read or holds no row of reads the key's strictest
//! value). The owner's clear of a carried row is its release, and travels as his act. A carried
//! row is the engine's (`Setter::Engine`), credited to the deciding act, and keeps the bound this
//! install's own carry wrote (`StoredRow::local`): its value is the meet of the heads and of that
//! bound, so a copy never loosens what this install carried, and the release clears both.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use oneiron_authority::authority::{
    ActSurface, AuthorityEntryHash, OwnerActKind, PolicySetting, SettingCopyName,
    setting_slot_target, setting_value_digest,
};
use oneiron_contracts::fingerprint::{Fingerprinter, purposes};
use oneiron_setting_contract::{ChangeStanding, Order, RowKey, SettingStanding};

use super::beside::{
    BesideRead, beside_row_settled_in_txn, beside_value_in_txn, slot_value_in_txn,
};
use super::change::{record_change_in_txn, record_receipt_in_txn, record_signed_entry_in_txn};
use super::pack::layer_default_in_txn;
use super::read::{StoredRow, table_of};
use super::{
    EncodedValue, Setter, SettingChange, SettingMode, SettingScope, SettingSpec, SettingSync,
    spec_named,
};
use crate::Vault;
use crate::authority::{
    ChoiceCount, ChoiceCounts, SettingSlotAct, SettingSlotFold, SettingSlotHead, SettingSlotRow,
};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::side_table::{self, Named, SideTable, SideTableDbs};

/// One projected row per act target.
const PROJECTIONS: SideTable<Vec<u8>, Projection, Named> =
    SideTable::new(&side_table::SETTING_PROJECTION);

/// A value no MessagePack decoder reads (the format's one unused byte): the row a quarantined
/// slot keeps, so every read of it takes the key's strictest value as for any row that does not
/// decode.
const UNREADABLE_VALUE: u8 = 0xc1;

/// What the projection last wrote for one act target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Projection {
    /// The row's stored key ([`RowKey::encode`]); empty where the target's acts name no row this
    /// build writes (a digest-only act, an older setting's act, a free-time policy).
    slot: Vec<u8>,
    /// What the row was projected from ([`basis_of`]): the target's act revision, and how its
    /// acts counted here when one did not count in full, and its acts that wait for the owner's
    /// proof.
    basis: [u8; 32],
    /// How the acts stood.
    standing: SettingStanding,
    /// A pin whose acts do not all count in full here (stage 7b-3): every read takes it as a
    /// value row at its scope, so it narrows and releases nothing. Absent on every other
    /// projection, whose bytes it leaves as they were.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pin_read_as_value: bool,
    /// The row beside an act the projection waits for (stage 7c-1): the row reads as it did
    /// before that act, `Pending`, and a pass reads the target again once that row is here or
    /// was erased. Absent on every other projection, whose bytes it leaves as they were.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    awaiting: Option<EntityId>,
}

/// What projecting one target did ([`project_target_in_txn`]).
pub(super) struct TargetProjected {
    /// The key whose row the pass wrote or removed.
    pub(super) changed: Option<&'static SettingSpec>,
    /// How the acts the row came from stood, and the other live heads its value was met with:
    /// the receipt a door's own change row takes where the pass wrote no change of its own
    /// (stage 7b-3). `None` where the pass left the row as it is.
    pub(super) receipt: Option<(ChangeStanding, Vec<AuthorityEntryHash>)>,
}

impl TargetProjected {
    /// A pass that read nothing new.
    const UNMOVED: Self = Self {
        changed: None,
        receipt: None,
    };
}

/// What a projection pass did ([`Vault::project_settings`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SettingsProjected {
    /// Act targets whose revision moved since their last projection.
    pub moved: usize,
    /// Rows the pass wrote or removed.
    pub rows_changed: usize,
}

/// Whether an owner's change of a row of `spec` travels as its signed act (stage 7a-2): a
/// `sync: vault` key that is not learned, whose seed weight does not travel yet. Its value rides
/// inside the act where the key's value type is closed and its JSON fits, else beside it (stage
/// 7c-1, [`slot_value_in_txn`]). A carried row travels too (stage 7a-4): a move's copy brings it
/// to every machine, and the owner's clear of it is his act.
pub(super) fn travels(spec: &SettingSpec) -> bool {
    spec.sync == SettingSync::Vault && spec.kind.travels_inline() && !spec.is_learned()
}

/// The most copies one read follows through the copies they name (stage 7a-4): a name deeper
/// than this reads as one this install cannot read, the key's strictest value.
const COPY_DEPTH_MAX: usize = 64;

/// Whether the vault has an authority root, a conflicted one included: a vault without one is
/// one machine, and its door writes the row alone, as before stage 7 (the cut
/// `project_depth/fold.rs` makes).
pub(super) fn rooted_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    let view = vault.authority_view_readonly_in_txn(txn)?;
    Ok(view.vault_id.is_some() || view.vault_root_is_conflicted())
}

/// Appends the owner `owner`'s applied change `recorded` of a row of `spec` that travels as its
/// signed act, in the change's write `txn`, from `surface`, with its value inside the act or
/// beside it ([`slot_value_in_txn`]); names the entry on the change row; and projects the row
/// from the fold in the same write.
///
/// # Errors
///
/// The append's typed refusal (no live machine profile to carry the act, a fold that does not
/// count it, more heads than one entry names), or a storage error: the change fails with it.
pub(super) fn append_act_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    spec: &'static SettingSpec,
    (owner, surface): (EntityId, ActSurface),
    recorded: &SettingChange,
) -> Result<()> {
    let json = recorded
        .value
        .as_ref()
        .map(|value| json_bytes(spec, value))
        .transpose()?;
    let slot = RowKey {
        name: recorded.key.clone(),
        item: recorded.item.clone(),
        mode: recorded.mode,
        scope: recorded.scope.clone(),
    };
    let target = setting_slot_target(&slot)?;
    let prior = setting_value_digest(&match &recorded.prior {
        Some(prior) => json_bytes(spec, prior)?,
        None => b"null".to_vec(),
    });
    let value = slot_value_in_txn(vault, txn, spec, &slot, json)?;
    let signed = vault.append_setting_slot_act_in_txn(
        txn,
        SettingSlotAct {
            owner,
            surface,
            rows: vec![SettingSlotRow { slot, prior, value }],
        },
    )?;
    // An act that waits for the owner's proof changes nothing, here as on every other machine:
    // the door refuses it with the reason, and nothing of the change is stored (module doc).
    if vault.setting_act_waits_in_txn(txn, signed)? {
        return Err(Error::Record(RecordError::OwnerKeyRequired));
    }
    record_signed_entry_in_txn(&vault.store, txn, recorded, signed)?;
    let now = recorded.at;
    let projected = project_target_in_txn(vault, txn, target, now)?;
    if projected.changed.is_none()
        && let Some((standing, with)) = projected.receipt
    {
        record_receipt_in_txn(&vault.store, txn, recorded.sequence, standing, with)?;
    }
    Ok(())
}

/// The value's JSON bytes: what an act carries inline, and what its digest is over (the digest
/// stage 7a-1's acts keep).
pub(super) fn json_bytes(spec: &SettingSpec, value: &EncodedValue) -> Result<Vec<u8>> {
    let json = spec.kind.to_json(value).unwrap_or(serde_json::Value::Null);
    serde_json::to_vec(&json).map_err(|_| Error::InvariantViolation("setting act encoding"))
}

/// The basis a row's projection records (stage 7b-2): the target's act `revision` while every
/// act a reader of it meets counts in full here, its heads do not conflict and none waits for
/// the owner's proof, as stage 7a-2 recorded it; otherwise a fingerprint of the revision, of each
/// act's count, where the heads conflict of the act the register holds in force (`in_force`, the
/// last act every head descends from, judged the same way: an act no count names), and of each
/// act that waits (stage 7b-3). So a pass reads the row again when a head's count moves and its
/// revision does not (a removal it raced arrives, a hold ends), when the conflict's act loses its
/// standing, and when a proposal arrives or its ask ends.
fn basis_of(
    revision: [u8; 32],
    counts: &ChoiceCounts,
    (conflict, in_force): (bool, Option<AuthorityEntryHash>),
    asking: &BTreeSet<AuthorityEntryHash>,
) -> [u8; 32] {
    if !conflict
        && asking.is_empty()
        && counts
            .values()
            .all(|counted| counted.count == ChoiceCount::Full)
    {
        return revision;
    }
    let mut basis = Fingerprinter::new(purposes::setting::PROJECTION_BASIS);
    basis.part(&revision).u64(counts.len() as u64);
    for (act, counted) in counts {
        let count = match counted.count {
            ChoiceCount::Full => 0,
            ChoiceCount::Safe { held: false } => 1,
            ChoiceCount::Safe { held: true } => 2,
            ChoiceCount::Disputed => 3,
        };
        basis.part(act).u64(count);
    }
    if conflict {
        basis.u64(1).part(&in_force.unwrap_or([0; 32]));
    }
    if !asking.is_empty() {
        basis.u64(asking.len() as u64);
        for act in asking {
            basis.part(act);
        }
    }
    basis.finish().into_bytes()
}

/// How the acts a reader of one row meets stand by their counts and proposals alone (stage
/// 7b-3): a proposal that still asks, else a head held back by this install's own counting, else
/// a safe move the log alone shows, else every act in full. A conflict or a quarantine the
/// combine finds outranks it.
fn counted_standing(fold: &SettingSlotFold) -> ChangeStanding {
    if !fold.asking.is_empty() {
        return ChangeStanding::Pending;
    }
    let counts = || fold.counts.values().map(|counted| counted.count);
    if counts().any(|count| count == ChoiceCount::Safe { held: true }) {
        ChangeStanding::Held
    } else if counts().any(|count| count != ChoiceCount::Full) {
        ChangeStanding::Narrowed
    } else {
        ChangeStanding::Full
    }
}

fn target_key(target: EntityId) -> Vec<u8> {
    target.as_bytes().to_vec()
}

/// One head as the projection reads it.
struct Head {
    act: AuthorityEntryHash,
    /// Who decided, and where his say-so reached the carrier: a setting act's owner and surface;
    /// `None` for a move's copy, which no one decided (stage 7a-4).
    decider: Option<(EntityId, ActSurface)>,
    slot: RowKey,
    body: HeadBody,
}

/// What a head says of its row.
enum HeadBody {
    /// A setting act's value as its JSON bytes; `None` for a clear.
    Inline(Option<Vec<u8>>),
    /// A setting act that keeps only BLAKE3 over its value's JSON bytes: a value beside the act
    /// on a key that travels (stage 7c-1), else a signed record no row is written from.
    Beside([u8; 32]),
    /// A move's copy: the acts it copies (stage 7a-4).
    Copy(Vec<SettingCopyName>),
}

impl Head {
    fn credit(&self) -> Credit {
        Credit {
            act: self.act,
            owner: self.decider.map(|(owner, _)| owner),
            surface: self.decider.map(|(_, surface)| surface),
        }
    }

    /// Whether the head says more than a clear: a value, or a copy's names.
    fn carries_value(&self) -> bool {
        !matches!(self.body, HeadBody::Inline(None))
    }

    /// Whether the act keeps only its value's digest ([`HeadBody::Beside`]).
    fn keeps_only_digest(&self) -> bool {
        matches!(self.body, HeadBody::Beside(_))
    }
}

/// The act a projected row is credited to: its change row's `signed`, `by` and `surface`.
#[derive(Clone, Copy)]
struct Credit {
    act: AuthorityEntryHash,
    /// The owner who decided; `None` for a move's copy.
    owner: Option<EntityId>,
    surface: Option<ActSurface>,
}

/// Why a target leaves its row as it is.
enum Inert {
    /// Its acts name no row this build writes, now or under a later build: recorded, so a later
    /// pass reads them again only once the revision moves.
    ForGood,
    /// Its acts name a row this build cannot write yet (a key it does not know, one that does
    /// not travel here, a head the log here does not hold): not recorded, so the open pass of a
    /// later build reads them again.
    ForNow,
    /// An act on the way keeps its value beside it, and that value has not reached this install
    /// (stage 7c-1; DESIGN 1.6, "Fold states": Pending): the row reads as it did before that
    /// act. Recorded as `Pending` with the row it waits for, so a pass reads the target again
    /// once that row is here.
    Awaiting(EntityId),
}

/// The head `head` reads as, or why it leaves the row as it is.
fn head_of(head: &SettingSlotHead) -> std::result::Result<Head, Inert> {
    if let Some(copy) = &head.copy {
        return Ok(Head {
            act: head.act,
            decider: None,
            slot: copy.slot.clone(),
            body: HeadBody::Copy(copy.names.clone()),
        });
    }
    let Some(set) = &head.set else {
        return Err(Inert::ForNow);
    };
    // The eight older settings' doors sign acts that keep only digests, and an act of another
    // kind names no row: no build writes a row from either.
    if set.act.act != OwnerActKind::PolicySetting || PolicySetting::parse(&set.setting).is_some() {
        return Err(Inert::ForGood);
    }
    let body = match (set.value, &set.inline) {
        (Some(_), None) => return Err(Inert::ForGood),
        (_, inline) => HeadBody::Inline(inline.clone()),
    };
    let slot = match &set.slot {
        Some(slot) => slot.clone(),
        None => RowKey {
            name: set.setting.clone(),
            item: None,
            mode: SettingMode::Value,
            scope: SettingScope::Vault,
        },
    };
    Ok(Head {
        act: head.act,
        decider: Some((set.act.owner, set.act.surface)),
        slot,
        body,
    })
}

/// A head's value under `spec`, read in `txn`: `None` for a clear, and for a copy whose acts
/// leave no bound. [`Short::Unreadable`] for a value this build cannot decode or whose check
/// refuses it, a value beside the act that does not match its digest or was erased, and a copy
/// whose acts read so on a key that names no strictest value; [`Inert::Awaiting`] for a value
/// beside the act that has not reached this install.
fn value_of(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    head: &Head,
) -> Result<std::result::Result<Option<EncodedValue>, Short>> {
    match &head.body {
        HeadBody::Inline(None) => Ok(Ok(None)),
        HeadBody::Inline(Some(bytes)) => {
            Ok(inline_value(spec, bytes).map_err(|()| Short::Unreadable))
        }
        HeadBody::Beside(digest) => beside_of(vault, txn, spec, &head.slot, *digest),
        HeadBody::Copy(names) => copy_value_in_txn(vault, txn, spec, names, 0),
    }
}

/// The value beside an act on the row `slot` whose JSON bytes have BLAKE3 `digest`, under
/// `spec` (stage 7c-1; [`value_of`]).
fn beside_of(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    slot: &RowKey,
    digest: [u8; 32],
) -> Result<std::result::Result<Option<EncodedValue>, Short>> {
    Ok(match beside_value_in_txn(vault, txn, slot, digest)? {
        BesideRead::Here(bytes) => inline_value(spec, &bytes).map_err(|()| Short::Unreadable),
        BesideRead::Absent(row) => Err(Short::Inert(Inert::Awaiting(row))),
        BesideRead::Unreadable => Err(Short::Unreadable),
    })
}

/// A value's JSON bytes under `spec`; `Err` when this build cannot decode them or the key's
/// check refuses them.
fn inline_value(spec: &SettingSpec, bytes: &[u8]) -> std::result::Result<Option<EncodedValue>, ()> {
    let json: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| ())?;
    spec.kind.from_json(json).map(Some).map_err(|_| ())
}

/// A copy's value (stage 7a-4): the meet of what each act it names gives its row, a name this
/// install refused, cannot read or holds no row of reading the key's strictest value. `None`
/// when no name leaves a bound; [`Short::Unreadable`] where the key names no strictest value for
/// such a name, or two values do not meet; [`Inert::Awaiting`] where a named act's value beside
/// it has not reached this install (stage 7c-1). `depth` counts the copies followed so far.
fn copy_value_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    names: &[SettingCopyName],
    depth: usize,
) -> Result<std::result::Result<Option<EncodedValue>, Short>> {
    let mut met: Option<EncodedValue> = None;
    for name in names {
        let value = match name_value_in_txn(vault, txn, spec, name, depth)? {
            Ok(Some(value)) => value,
            Ok(None) => continue,
            Err(Short::Unreadable) => match spec.kind.strictest_value()? {
                Some(strictest) => strictest,
                None => return Ok(Err(Short::Unreadable)),
            },
            Err(inert @ Short::Inert(_)) => return Ok(Err(inert)),
        };
        met = Some(match met {
            None => value,
            Some(so_far) => match spec.kind.meet(&so_far, &value) {
                Some(meet) => meet,
                None => return Ok(Err(Short::Unreadable)),
            },
        });
    }
    Ok(Ok(met))
}

/// What the entry `name` names gives the row it names, under `spec`: a setting act's value
/// (`None` for a clear), or an earlier copy's ([`copy_value_in_txn`]).
/// [`Short::Unreadable`] where this install refused the entry, does not hold it, holds no row of
/// it on that slot, or cannot decode its value (a value beside the act that does not match its
/// digest or was erased included), and past [`COPY_DEPTH_MAX`] copies; [`Inert::Awaiting`]
/// where its value beside it has not reached this install (stage 7c-1).
fn name_value_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    name: &SettingCopyName,
    depth: usize,
) -> Result<std::result::Result<Option<EncodedValue>, Short>> {
    if depth >= COPY_DEPTH_MAX || vault.policy_setting_act_refused_in_txn(txn, name.act)? {
        return Ok(Err(Short::Unreadable));
    }
    let head = vault.setting_slot_head_in_txn(txn, setting_slot_target(&name.slot)?, name.act)?;
    if let Some(set) = &head.set {
        let named = set.slot.as_ref().is_some_and(|slot| *slot == name.slot);
        if !named || set.act.act != OwnerActKind::PolicySetting {
            return Ok(Err(Short::Unreadable));
        }
        return match (set.value, &set.inline) {
            (None, _) => Ok(Ok(None)),
            (Some(_), Some(bytes)) => Ok(inline_value(spec, bytes).map_err(|()| Short::Unreadable)),
            (Some(digest), None) => beside_of(vault, txn, spec, &name.slot, digest),
        };
    }
    if let Some(copy) = &head.copy
        && copy.slot == name.slot
    {
        return copy_value_in_txn(vault, txn, spec, &copy.names, depth + 1);
    }
    Ok(Err(Short::Unreadable))
}

/// The row the acts give, and how they stand.
struct Projected {
    /// The row's value; `None` for no row.
    value: Option<EncodedValue>,
    /// The row stays as it is: a quarantined value of a key that names no strictest value, so
    /// no row could read as one (its read would fail).
    keep: bool,
    standing: ChangeStanding,
    /// The act the row is credited to.
    deciding: Credit,
    /// The other live heads the value was met with: the change row's `with` (stage 7b-3).
    with: Vec<AuthorityEntryHash>,
}

/// How a walk reads the acts of a row whose key orders its values.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Rule {
    /// The order has a meet: a safe move gives the meet of its value and what it replaced, and
    /// heads meet.
    Meet,
    /// The key's own comparator ([`Order::Custom`], stage 7b-3): a safe move gives its value
    /// where it is no wider than what it replaced, else what it replaced; of several heads the
    /// one no wider than every other stands, else the key's strictest value.
    Comparator,
}

/// Combines the live heads of one row (module doc), each read by what it counts for here
/// (stage 7b-2; the comparator, a disputed act, the standing and `with` stage 7b-3).
fn combine(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    (spec, target): (&'static SettingSpec, EntityId),
    heads: &[Head],
    fold: &SettingSlotFold,
) -> Result<std::result::Result<Projected, Inert>> {
    let Some(newest) = heads.first() else {
        return Ok(Err(Inert::ForNow));
    };
    let strictest = spec.kind.strictest_value()?;
    let others = |deciding: &Credit| -> Vec<AuthorityEntryHash> {
        heads
            .iter()
            .map(|head| head.act)
            .filter(|act| *act != deciding.act)
            .collect()
    };
    let quarantined = || Projected {
        value: Some(EncodedValue(vec![UNREADABLE_VALUE])),
        keep: strictest.is_none(),
        standing: ChangeStanding::Quarantined,
        deciding: newest.credit(),
        with: others(&newest.credit()),
    };
    // Two copies of one act the row's reading meets disagree: what it says cannot be read.
    if fold
        .counts
        .values()
        .any(|counted| counted.count == ChoiceCount::Disputed)
    {
        return Ok(Ok(quarantined()));
    }
    let counted = counted_standing(fold);
    let rule = match spec.kind.order() {
        order if order.has_meet() => Some(Rule::Meet),
        Order::Custom => Some(Rule::Comparator),
        _ => None,
    };
    if let Some(rule) = rule {
        let empty = if is_vault_value_row(&newest.slot) {
            Some(layer_default_in_txn(&vault.store, txn, spec)?.value)
        } else {
            None
        };
        let mut walk = Walk {
            vault,
            txn,
            spec,
            target,
            slot: &newest.slot,
            counts: &fold.counts,
            rule,
            strictest: strictest.clone(),
            empty,
            given: BTreeMap::new(),
            conflict: Cell::new(false),
        };
        let mut given = Vec::with_capacity(heads.len());
        let mut inert = None;
        for head in heads {
            match walk.gives(head.act)? {
                Ok(gives) => given.push(gives),
                Err(Short::Unreadable) => return Ok(Ok(quarantined())),
                Err(Short::Inert(why)) => inert = inert.or(Some(why)),
            }
        }
        // A value that does not decode quarantines the row whichever head it is under; only then
        // does an act this build cannot read yet leave the row as it is.
        if let Some(why) = inert {
            return Ok(Err(why));
        }
        let Ok(joined) = walk.join(given) else {
            return Ok(Ok(quarantined()));
        };
        let standing = if walk.conflict.get() {
            ChangeStanding::Conflict
        } else {
            counted
        };
        let deciding = newest.credit();
        return Ok(Ok(Projected {
            value: joined,
            keep: false,
            standing,
            with: others(&deciding),
            deciding,
        }));
    }
    let mut inert = None;
    for head in heads {
        match value_of(vault, txn, spec, head)? {
            Ok(_) => {}
            Err(Short::Unreadable) => return Ok(Ok(quarantined())),
            Err(Short::Inert(why)) => inert = inert.or(Some(why)),
        }
    }
    if let Some(why) = inert {
        return Ok(Err(why));
    }
    // No order or a neutral key: nothing is safer than anything else, so an act that does not
    // count in full gives what it replaced, and heads that differ conflict: the last value every
    // head descends from stays (owner_choice.rs `in_force`), or no row.
    let standing = if fold.conflict {
        ChangeStanding::Conflict
    } else {
        counted
    };
    let Some(agreed) = &fold.in_force else {
        let deciding = newest.credit();
        return Ok(Ok(Projected {
            value: None,
            keep: false,
            standing,
            with: others(&deciding),
            deciding,
        }));
    };
    let agreed = match head_of(agreed) {
        Ok(head) if head.slot == newest.slot => head,
        Ok(_) => return Ok(Err(Inert::ForGood)),
        Err(why) => return Ok(Err(why)),
    };
    Ok(match value_of(vault, txn, spec, &agreed)? {
        Ok(value) => Ok({
            let deciding = agreed.credit();
            Projected {
                value,
                keep: false,
                standing,
                with: others(&deciding),
                deciding,
            }
        }),
        Err(Short::Unreadable) => Ok(quarantined()),
        Err(Short::Inert(why)) => Err(why),
    })
}

/// Why a walk of a row's acts gives no value.
enum Short {
    /// A value on the way does not decode or fails its check, or two values do not meet: the
    /// row is quarantined.
    Unreadable,
    /// An act on the way names no row this build writes, or the log here does not hold it.
    Inert(Inert),
}

/// The walk of one row's acts on a key that orders its values (stage 7b-2; DESIGN 1.6, "The
/// read of one slot"; the comparator stage 7b-3): what each act gives the row, by what it counts
/// for here ([`ChoiceCount`]). An act that counts in full gives its own value; a safe move gives
/// the stricter of its own value and what the acts it replaced give, each read the same way, so
/// it can narrow and never widens ([`Rule`]). `None` is no row: a clear's, or the empty slot's,
/// which an act that replaced nothing replaced.
struct Walk<'v, 't> {
    vault: &'v Vault,
    txn: &'v heed::RoTxn<'t>,
    spec: &'static SettingSpec,
    target: EntityId,
    slot: &'v RowKey,
    counts: &'v ChoiceCounts,
    rule: Rule,
    /// The key's strictest value: what heads no comparator orders give.
    strictest: Option<EncodedValue>,
    /// What no row gives where it meets a value: the accepted default on a vault value row, the
    /// item's as the item-less one (a first row there that counts as a safe move lands only as
    /// far as it narrows the default), no bound on any other row (a first row there lands whole:
    /// adding a row only narrows).
    empty: Option<EncodedValue>,
    /// What each act read so far gives.
    given: BTreeMap<AuthorityEntryHash, Option<EncodedValue>>,
    /// Whether the comparator found heads none of which is no wider than every other.
    conflict: Cell<bool>,
}

impl Walk<'_, '_> {
    /// What `act` gives the row. The acts a safe move replaced are read first, without
    /// recursion; an act the counts do not name (no frontier here keeps it) gives no row.
    fn gives(
        &mut self,
        act: AuthorityEntryHash,
    ) -> Result<std::result::Result<Option<EncodedValue>, Short>> {
        let counts = self.counts;
        let mut stack = vec![(act, false)];
        while let Some((next, expanded)) = stack.pop() {
            if self.given.contains_key(&next) {
                continue;
            }
            let Some(counted) = counts.get(&next) else {
                self.given.insert(next, None);
                continue;
            };
            let safe = counted.count != ChoiceCount::Full;
            if safe && !expanded {
                stack.push((next, true));
                stack.extend(
                    counted
                        .replaced
                        .iter()
                        .filter(|replaced| !self.given.contains_key(*replaced))
                        .map(|replaced| (*replaced, false)),
                );
                continue;
            }
            let own = match self.own_value(next)? {
                Ok(own) => own,
                Err(short) => return Ok(Err(short)),
            };
            let gives = if safe {
                let from = counted
                    .replaced
                    .iter()
                    .map(|replaced| self.given.get(replaced).cloned().flatten());
                let Ok(from) = self.join(from.collect::<Vec<_>>()) else {
                    return Ok(Err(Short::Unreadable));
                };
                let Ok(gives) = self.safe_move(own, from) else {
                    return Ok(Err(Short::Unreadable));
                };
                gives
            } else {
                own
            };
            self.given.insert(next, gives);
        }
        Ok(Ok(self.given.get(&act).cloned().flatten()))
    }

    /// `act`'s own value on the row, read back from the log here: `None` for a clear.
    fn own_value(
        &self,
        act: AuthorityEntryHash,
    ) -> Result<std::result::Result<Option<EncodedValue>, Short>> {
        let head = match head_of(&self.vault.setting_slot_head_in_txn(
            self.txn,
            self.target,
            act,
        )?) {
            Ok(head) if head.slot == *self.slot => head,
            Ok(_) => return Ok(Err(Short::Inert(Inert::ForGood))),
            Err(why) => return Ok(Err(Short::Inert(why))),
        };
        value_of(self.vault, self.txn, self.spec, &head)
    }

    /// What the heads or replaced acts `given` give the row together, by the walk's rule: their
    /// meet ([`Self::meet_all`]), or the one no wider than every other
    /// ([`Self::no_wider_of_all`]). No row when there is none.
    fn join(
        &self,
        given: Vec<Option<EncodedValue>>,
    ) -> std::result::Result<Option<EncodedValue>, ()> {
        match self.rule {
            Rule::Meet => self.meet_all(given),
            Rule::Comparator => self.no_wider_of_all(&given),
        }
    }

    /// What a safe move of value `own` over `from`, what it replaced, gives, by the walk's rule:
    /// their meet; or `own` where the comparator says it is no wider than `from`, else `from`.
    fn safe_move(
        &self,
        own: Option<EncodedValue>,
        from: Option<EncodedValue>,
    ) -> std::result::Result<Option<EncodedValue>, ()> {
        match self.rule {
            Rule::Meet => self.meet(own, from),
            Rule::Comparator => Ok(if self.no_wider(own.as_ref(), from.as_ref())? {
                own
            } else {
                from
            }),
        }
    }

    /// Whether `left` is no wider than `right` under the key's comparator. No row reads as what
    /// no row gives here ([`Self::empty`]). Where that is no row too: two of them are equal; a
    /// value is no wider than no row on a value row (adding a bound only narrows) and not on a
    /// pin (no pin leaves the value rows to decide, so a pin may widen them); no row is no
    /// narrower than a value. `Err` where the comparator cannot judge the two values.
    fn no_wider(
        &self,
        left: Option<&EncodedValue>,
        right: Option<&EncodedValue>,
    ) -> std::result::Result<bool, ()> {
        let left = left.or(self.empty.as_ref());
        let right = right.or(self.empty.as_ref());
        match (left, right) {
            (None, None) => Ok(true),
            (Some(_), None) => Ok(self.slot.mode != SettingMode::Pin),
            (None, Some(_)) => Ok(false),
            (Some(left), Some(right)) => self.spec.kind.no_wider(left, right).ok_or(()),
        }
    }

    /// The first of `given` that is no wider than every other ([`Self::no_wider`]); where none
    /// is, the key's strictest value, and the row is in conflict. No row when `given` is empty.
    /// `Err` where the comparator cannot judge two of them, or the key names no strictest value
    /// for heads it cannot order.
    fn no_wider_of_all(
        &self,
        given: &[Option<EncodedValue>],
    ) -> std::result::Result<Option<EncodedValue>, ()> {
        for (index, candidate) in given.iter().enumerate() {
            let mut stands = true;
            for (other_index, other) in given.iter().enumerate() {
                if index != other_index && !self.no_wider(candidate.as_ref(), other.as_ref())? {
                    stands = false;
                    break;
                }
            }
            if stands {
                return Ok(candidate.clone());
            }
        }
        if given.is_empty() {
            return Ok(None);
        }
        self.conflict.set(true);
        self.strictest.clone().map(Some).ok_or(())
    }

    /// The meet of what each of `given` gives the row ([`Self::meet`], folded from the first):
    /// no row when there is none (an act that replaced nothing replaced the empty slot), or when
    /// each gives no row. `Err` where two values do not meet.
    fn meet_all(
        &self,
        given: Vec<Option<EncodedValue>>,
    ) -> std::result::Result<Option<EncodedValue>, ()> {
        let mut given = given.into_iter();
        let Some(mut met) = given.next() else {
            return Ok(None);
        };
        for one in given {
            met = self.meet(met, one)?;
        }
        Ok(met)
    }

    /// The stricter of two things the row is given: their meet; no row on both sides is no row,
    /// and no row against a value is what no row gives there ([`Self::empty`]). `Err` where two
    /// values do not meet.
    fn meet(
        &self,
        left: Option<EncodedValue>,
        right: Option<EncodedValue>,
    ) -> std::result::Result<Option<EncodedValue>, ()> {
        let (value, other) = match (left, right) {
            (None, None) => return Ok(None),
            (Some(value), None) | (None, Some(value)) => (value, self.empty.clone()),
            (Some(left), Some(right)) => (left, Some(right)),
        };
        match other {
            None => Ok(Some(value)),
            Some(other) => self.spec.kind.meet(&value, &other).map(Some).ok_or(()),
        }
    }
}

/// Whether `slot` is a vault value row, the item's or the item-less one: its empty slot gives the
/// accepted default (DESIGN 1.6, "What the empty slot gives"; the item's row stage 7b-3), since a
/// read with no item-less vault row starts from the item's row alone.
fn is_vault_value_row(slot: &RowKey) -> bool {
    slot.mode == SettingMode::Value && slot.scope == SettingScope::Vault
}

/// Projects the row the acts on `target` name, in `txn`, at `now`, when the target's basis
/// ([`basis_of`]) moved since its last projection. Returns the key whose row changed, and the
/// receipt of the acts the row came from.
pub(super) fn project_target_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    target: EntityId,
    now: u64,
) -> Result<TargetProjected> {
    let Some(fold) = vault.setting_slot_fold_in_txn(txn, target)? else {
        return Ok(TargetProjected::UNMOVED);
    };
    let in_force = fold.in_force.as_ref().map(|head| head.act);
    let basis = basis_of(
        fold.revision,
        &fold.counts,
        (fold.conflict, in_force),
        &fold.asking,
    );
    if let Some(projection) = PROJECTIONS.get(&vault.store, txn, &target_key(target))?
        && !moved_since(vault, txn, &projection, basis)?
    {
        return Ok(TargetProjected::UNMOVED);
    }
    let inert = |why: Inert| (target, basis, why);
    let heads = match fold
        .live
        .iter()
        .map(head_of)
        .collect::<std::result::Result<Vec<Head>, Inert>>()
    {
        Ok(heads) => heads,
        Err(why) => return leave_in_txn(vault, txn, inert(why)),
    };
    let Some(slot) = heads.first().map(|head| head.slot.clone()) else {
        // Only proposals name the row: they change nothing, and it reads `Pending` while they
        // ask (stage 7b-3).
        if !fold.asking.is_empty() {
            PROJECTIONS.put(
                &vault.store,
                txn,
                &target_key(target),
                &Projection {
                    slot: Vec::new(),
                    basis,
                    standing: SettingStanding::Pending,
                    pin_read_as_value: false,
                    awaiting: None,
                },
            )?;
        }
        return Ok(TargetProjected::UNMOVED);
    };
    if heads.iter().any(|head| head.slot != slot) {
        return leave_in_txn(vault, txn, inert(Inert::ForGood));
    }
    let Ok(spec) = spec_named(&slot.name) else {
        return leave_in_txn(vault, txn, inert(Inert::ForNow));
    };
    if !travels(spec)
        || !spec.admits_scope(slot.scope.kind())
        || spec.check_item(slot.item.as_deref()).is_err()
    {
        // Acts that carry no value were only ever digests here: a key that does not travel
        // keeps only a signed record of the owner's change (stage 7a-1), and no build writes a
        // row from it. One that carries a value, or a copy, waits for a build where its key
        // travels.
        let carried = heads
            .iter()
            .any(|head| head.carries_value() && !head.keeps_only_digest());
        let why = if carried {
            Inert::ForNow
        } else {
            Inert::ForGood
        };
        return leave_in_txn(vault, txn, inert(why));
    }
    let projected = match combine(vault, txn, (spec, target), &heads, &fold)? {
        Ok(projected) => projected,
        Err(why) => return leave_in_txn(vault, txn, inert(why)),
    };
    let kept = match slot.mode {
        SettingMode::Carried => carried_row_in_txn(vault, txn, spec, &slot, &heads)?,
        SettingMode::Value | SettingMode::Pin => None,
    };
    let bound = kept
        .as_ref()
        .map(|row| row.local.clone().unwrap_or_else(|| row.value.clone()))
        .filter(|bound| spec.kind.decodes(bound));
    let projected = met_with_local(spec, projected, bound.as_ref());
    let local = kept.and_then(|row| row.local);
    let changed = write_row_in_txn(vault, txn, spec, &slot, &projected, local.as_ref(), now)?;
    // A pin keeps its release only while every act it comes from counts in full here: one that
    // counts as a safe move keeps its value and is read as a value row (DESIGN 1.6, "The read
    // of one slot", step 3). A pin on a key with no meet never takes a safe move's own value.
    let pin_read_as_value = slot.mode == SettingMode::Pin
        && spec.kind.order().has_meet()
        && fold
            .counts
            .values()
            .any(|counted| counted.count != ChoiceCount::Full);
    PROJECTIONS.put(
        &vault.store,
        txn,
        &target_key(target),
        &Projection {
            slot: slot.encode(),
            basis,
            standing: projected.standing.read_as(),
            pin_read_as_value,
            awaiting: None,
        },
    )?;
    Ok(TargetProjected {
        changed: changed.then_some(spec),
        receipt: Some((projected.standing, projected.with)),
    })
}

/// The carried row `slot` as stored here, which bounds its projection (stage 7a-4): by the bound
/// this install's own carry wrote (`StoredRow::local`), or, for a row with none (one a copy
/// wrote, or an older build's carry), by its value, so a carried row only tightens until it is
/// released. `None` once the owner released it (every head a clear of it), and where no row
/// decodes.
fn carried_row_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    slot: &RowKey,
    heads: &[Head],
) -> Result<Option<StoredRow>> {
    if heads.iter().all(|head| !head.carries_value()) {
        return Ok(None);
    }
    Ok(table_of(spec)
        .get_bytes(&vault.store, txn, &slot.encode())?
        .and_then(|bytes| rmp_serde::from_slice::<StoredRow>(&bytes).ok()))
}

/// `projected` met with the bound a carried row keeps here ([`carried_row_in_txn`], stage 7a-4):
/// a copy never loosens what this install carried. A quarantined row stays quarantined.
fn met_with_local(
    spec: &SettingSpec,
    mut projected: Projected,
    local: Option<&EncodedValue>,
) -> Projected {
    let Some(local) = local else {
        return projected;
    };
    if projected.keep || projected.standing == ChangeStanding::Quarantined {
        return projected;
    }
    projected.value = Some(match projected.value.take() {
        Some(value) => spec
            .kind
            .meet(&value, local)
            .unwrap_or_else(|| local.clone()),
        None => local.clone(),
    });
    projected
}

/// Leaves the row of `target` as it is (`Inert`), recording its `basis` when no build writes a
/// row from those acts, and, while a value beside an act has not arrived, that the row reads
/// `Pending` and what the last projection left (its row and how a pin reads) until it does.
/// Returns no changed key.
fn leave_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (target, basis, why): (EntityId, [u8; 32], Inert),
) -> Result<TargetProjected> {
    let projection = match why {
        Inert::ForNow => return Ok(TargetProjected::UNMOVED),
        Inert::ForGood => Projection {
            slot: Vec::new(),
            basis,
            standing: SettingStanding::Settled,
            pin_read_as_value: false,
            awaiting: None,
        },
        Inert::Awaiting(row) => {
            let last = PROJECTIONS.get(&vault.store, txn, &target_key(target))?;
            Projection {
                slot: last
                    .as_ref()
                    .map(|last| last.slot.clone())
                    .unwrap_or_default(),
                basis,
                standing: SettingStanding::Pending,
                pin_read_as_value: last.is_some_and(|last| last.pin_read_as_value),
                awaiting: Some(row),
            }
        }
    };
    PROJECTIONS.put(&vault.store, txn, &target_key(target), &projection)?;
    Ok(TargetProjected::UNMOVED)
}

/// Whether `target`'s acts moved since `projection` was recorded: its basis is not `basis`, or
/// the value beside an act it waited for is here now, or was erased (stage 7c-1).
fn moved_since(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    projection: &Projection,
    basis: [u8; 32],
) -> Result<bool> {
    if projection.basis != basis {
        return Ok(true);
    }
    match projection.awaiting {
        Some(row) => beside_row_settled_in_txn(vault, txn, row),
        None => Ok(false),
    }
}

/// Writes `projected` as the row `slot` of `spec` when it differs from the stored row, or the
/// stored row is not the deciding act's: the row, one change row credited to the deciding act,
/// and the key's hook. Whether it wrote. A carried row, and a row a copy decided, is the
/// engine's, with its `local` bound (stage 7a-4); every other row is the deciding owner's.
fn write_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    spec: &'static SettingSpec,
    slot: &RowKey,
    projected: &Projected,
    local: Option<&EncodedValue>,
    now: u64,
) -> Result<bool> {
    let deciding = projected.deciding;
    if projected.keep {
        return Ok(false);
    }
    let (setter, by, surface) = match deciding.owner {
        Some(owner) if slot.mode != SettingMode::Carried => {
            (Setter::Owner, Some(owner), deciding.surface)
        }
        _ => (Setter::Engine { ask: None }, None, None),
    };
    let table = table_of(spec);
    let key = slot.encode();
    let stored = table
        .get_bytes(&vault.store, txn, &key)?
        .map(|bytes| rmp_serde::from_slice::<StoredRow>(&bytes).ok());
    let same = match (&stored, &projected.value) {
        (None, None) => true,
        (Some(Some(row)), Some(value)) => {
            row.value == *value
                && row.setter == setter
                && row.by == by
                && row.local.as_ref() == local
        }
        _ => false,
    };
    if same {
        return Ok(false);
    }
    let prior = stored.flatten().map(|row| row.value);
    let recorded = record_change_in_txn(
        &vault.store,
        txn,
        SettingChange {
            id: vault.store.clock.entity_id()?,
            sequence: 0,
            key: spec.name.to_owned(),
            item: slot.item.clone(),
            scope: slot.scope.clone(),
            mode: slot.mode,
            by,
            setter,
            prior,
            value: projected.value.clone(),
            at: now,
            why: None,
            weight_runs: None,
            direction: None,
            surface,
            signed: Some(deciding.act),
            with: projected.with.clone(),
            standing: Some(projected.standing),
        },
    )?;
    match &projected.value {
        Some(value) => table.put(
            &vault.store,
            txn,
            &key,
            &StoredRow {
                value: value.clone(),
                by,
                setter,
                set_at: now,
                change: recorded.sequence,
                weight_runs: None,
                local: local.cloned(),
            },
        )?,
        None => {
            table.delete(&vault.store, txn, &key)?;
        }
    }
    if let Some(on_change) = spec.on_change {
        on_change(vault, txn, &recorded)?;
    }
    Ok(true)
}

/// Forgets every row the projection wrote, and its record (stage 7a-3 tests): this install then
/// holds the log and none of those rows, as a machine that took the log from another holds it
/// until its next pass. The rows forgotten.
///
/// # Errors
///
/// Storage errors.
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) fn forget_projected_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
) -> Result<usize> {
    let mut forgotten = 0;
    for (target, projection) in PROJECTIONS.scan(&vault.store, txn)? {
        if let Some(slot) = RowKey::decode(&projection.slot)
            && let Ok(spec) = spec_named(&slot.name)
            && table_of(spec).delete(&vault.store, txn, &projection.slot)?
        {
            forgotten += 1;
        }
        PROJECTIONS.delete(&vault.store, txn, &target)?;
    }
    Ok(forgotten)
}

/// Whether the pin row `slot` reads as a value row at its scope (stage 7b-3): its projection
/// found an act it comes from that does not count in full here, so it narrows and releases
/// nothing. A pin no projection wrote reads as a pin.
///
/// # Errors
///
/// Storage errors.
pub(super) fn pin_reads_as_value_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    slot: &RowKey,
) -> Result<bool> {
    if slot.mode != SettingMode::Pin {
        return Ok(false);
    }
    Ok(PROJECTIONS
        .get(dbs, txn, &target_key(setting_slot_target(slot)?))?
        .is_some_and(|projection| projection.pin_read_as_value))
}

/// How the acts behind the rows of `spec` a read walks stand: the least settled of the pin, value
/// and carried rows on `chain`, for `item` and the item-less rows (stage 7a-2; carried rows stage
/// 7a-4). A key that stays on its install is always settled; a key no act names reads no
/// projection and is settled too.
///
/// # Errors
///
/// Storage errors.
pub(super) fn standing_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    chain: &[SettingScope],
    item: Option<&str>,
) -> Result<SettingStanding> {
    if spec.sync != SettingSync::Vault {
        return Ok(SettingStanding::Settled);
    }
    let items: Vec<Option<&str>> = match item {
        Some(_) => vec![item, None],
        None => vec![None],
    };
    let mut standing = SettingStanding::Settled;
    for scope in chain {
        for row_item in &items {
            for mode in [SettingMode::Pin, SettingMode::Value, SettingMode::Carried] {
                let slot = RowKey {
                    name: spec.name.to_owned(),
                    item: row_item.map(str::to_owned),
                    mode,
                    scope: scope.clone(),
                };
                if let Some(projection) =
                    PROJECTIONS.get(dbs, txn, &target_key(setting_slot_target(&slot)?))?
                {
                    standing = standing.max(projection.standing);
                }
            }
        }
    }
    Ok(standing)
}

impl Vault {
    /// Projects every setting row whose signed acts moved since it was last projected, in one
    /// write, and runs the `after_commit` of each key whose row changed (stage 7a-2). A vault
    /// with no authority root, or with no setting act, writes nothing.
    ///
    /// First, in its own write, the owner's rows no act backs are published as batch acts, once
    /// per vault (stage 7a-3, [`Self::publish_settings`]); a fault there is logged, and the
    /// projection goes on.
    ///
    /// # Errors
    ///
    /// Storage errors; a key's hook's error.
    pub fn project_settings(&self) -> Result<SettingsProjected> {
        match self.publish_settings() {
            Ok(Some(published)) if published.acts > 0 => tracing::info!(
                acts = published.acts,
                rows = published.rows,
                "the owner's setting rows no act backed were published as batch acts"
            ),
            Ok(_) => {}
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "the owner's setting rows no act backs were not published; the next authority commit or open tries again"
            ),
        }
        let moved: Vec<EntityId> = {
            let txn = self.store.env.read_txn()?;
            if !rooted_in_txn(self, &txn)? {
                return Ok(SettingsProjected::default());
            }
            let mut moved = Vec::new();
            for target in self.policy_setting_revisions_in_txn(&txn)? {
                let fallback = (target.conflict, target.in_force);
                let basis = basis_of(target.revision, &target.counts, fallback, &target.asking);
                let moved_here =
                    match PROJECTIONS.get(&self.store, &txn, &target_key(target.target))? {
                        Some(projection) => moved_since(self, &txn, &projection, basis)?,
                        None => true,
                    };
                if moved_here {
                    moved.push(target.target);
                }
            }
            moved
        };
        if moved.is_empty() {
            return Ok(SettingsProjected::default());
        }
        let changed = self.with_write_txn_grouped(|txn| {
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let mut changed = Vec::new();
            for target in &moved {
                if let Some(spec) = project_target_in_txn(self, txn, *target, now)?.changed {
                    changed.push(spec);
                }
            }
            Ok(changed)
        })?;
        for spec in &changed {
            if let Some(after_commit) = spec.after_commit {
                after_commit(self);
            }
        }
        Ok(SettingsProjected {
            moved: moved.len(),
            rows_changed: changed.len(),
        })
    }

    /// [`Self::project_settings`] once a commit stored an authority row (`noted`), whichever
    /// door stored it: a peer's acts, an import, a machine's standing or a Grant changed. A no-op
    /// otherwise; a failure is logged, and the next such commit or the next open tries again.
    pub(crate) fn project_settings_after_authority_ingest(&self, noted: bool) {
        if !noted {
            return;
        }
        if let Err(error) = self.project_settings() {
            tracing::warn!(
                kind = ?error.kind(),
                "the setting rows were not projected from their signed acts; the next authority commit or open tries again"
            );
        }
    }
}
