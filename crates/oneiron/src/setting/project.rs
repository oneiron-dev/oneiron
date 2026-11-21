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
//! does not hold leave the row as it is; a pass reads the acts on a key this build does not
//! know again only once their revision moves or a build knows the key. A head whose value is
//! beside its act and has not reached this install leaves it too: the row reads as it did before
//! that act, `Pending`, until the value arrives (stage 7c-1; DESIGN 1.6, "Fold states"). A value
//! beside an act that does not match its digest, or was erased, reads the key's strictest value,
//! `Quarantined`, whenever that happens, while a later act waits for its own value too: a pass
//! reads a row again once a value beside an act it read, or one the row's value came from, holds
//! otherwise. On a key that names no strictest value such a row reads no value of it: the key's
//! default, `Quarantined`. A pass projects each row in a savepoint of its own: a row a key's hook
//! refuses on this install stays as it was, and the next pass reads it again; the pass raises the
//! owner's notice of it, which names the acts and offers the fix (`refusal`).
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

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

mod head_values;
use head_values::{birth_value_in_txn, combine, copy_meet_in_txn, head_of, quarantined_of};
mod projection_rows;
pub(crate) use projection_rows::project_deferred_settings;
pub(super) use projection_rows::{
    append_act_in_txn, beside_source_in_txn, json_bytes, pin_reads_as_value_in_txn, rooted_in_txn,
    standing_in_txn, travels,
};
use projection_rows::{
    basis_of, empty_of_in_txn, leave_in_txn, met_with_local, own_carry_bound_in_txn,
    project_pack_target_in_txn, record_projection_in_txn, target_key, write_row_in_txn,
};
mod refusal;
pub(super) use refusal::slot_refused_here_in_txn;
pub(crate) use refusal::{SETTING_REFUSAL_NOTIFICATION_PRODUCER, setting_refusal_taps_in_txn};
use refusal::{raise_refusal_notice_in_txn, record_refusal_in_txn};

use serde::{Deserialize, Serialize};

use oneiron_authority::authority::{
    ActSurface, AuthorityEntryHash, OwnerActKind, PolicySetting, SettingCopyName, birth_yes_table,
    setting_pack_accept_target, setting_pack_target, setting_slot_target, setting_value_digest,
};
use oneiron_contracts::fingerprint::{Fingerprinter, purposes};
use oneiron_setting_contract::{ChangeStanding, Order, RowKey, SettingStanding};

use super::beside::{
    BesideHeld, BesideRead, beside_row_id, beside_row_read_in_txn, put_beside_value_in_txn,
    slot_value, watch_rows_in_txn,
};
use super::born::is_born_value_slot;
use super::change::{
    change_in_txn, hex_id_mentions, record_change_in_txn, record_receipt_in_txn,
    record_signed_entry_in_txn,
};
use super::pack::{birth_pack_row_in_txn, fold_layer, layer_default_in_txn, project_pack_in_txn};
use super::read::{StoredRow, table_of};
use super::{
    EncodedValue, Setter, SettingChange, SettingMode, SettingScope, SettingSpec, SettingSync,
    WriteTurn, spec_named,
};
use crate::Vault;
use crate::authority::{
    ChoiceCount, ChoiceCounts, NameCounts, OwnerProofGround, SettingSlotAct, SettingSlotFold,
    SettingSlotHead, SettingSlotRow,
};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::side_table::{self, Named, SideTable, SideTableDbs};

/// One projected row per act target.
const PROJECTIONS: SideTable<Vec<u8>, Projection, Named> =
    SideTable::new(&side_table::SETTING_PROJECTION);

/// Per act target, the basis ([`basis_of`]) of the acts this install's pass last found its key's
/// hook refusing (`refusal`); a projection of the target removes it.
const REFUSALS: SideTable<Vec<u8>, [u8; 32], Named> = SideTable::new(&side_table::SETTING_REFUSAL);

/// A value no MessagePack decoder reads (the format's one unused byte): the row a quarantined
/// slot keeps, so every read of it takes the key's strictest value as for any row that does not
/// decode. A pack's layer row whose yes names a table that cannot be read keeps it too (stage
/// 7c-3c).
pub(super) const UNREADABLE_VALUE: u8 = 0xc1;

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
    /// The rows beside acts the projection read (stage 7c-1), each with what it held: while one
    /// has not arrived the row reads as it did before that act, `Pending`, and a pass reads the
    /// target again once one holds otherwise ([`moved_since`]). Absent on every other
    /// projection, whose bytes it leaves as they were.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    beside: Vec<BesideSeen>,
    /// The key the acts are on, where this build does not know it (stage 7c-1): a pass reads the
    /// target again once a build knows it ([`moved_since`]). Absent on every other projection,
    /// whose bytes it leaves as they were.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unknown_key: Option<String>,
}

/// A row beside an act that a projection read, and what it held then (stage 7c-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BesideSeen {
    /// The row ([`beside_row_id`]).
    row: EntityId,
    /// BLAKE3 over the JSON bytes of the act's value.
    digest: [u8; 32],
    held: BesideHeld,
    /// Whether the row's value as stored here came from it: while a later act waits for its own
    /// value, a pass reads it again, and the row reads the key's strictest value once it is
    /// erased here or no longer matches its act ([`BesideReads::carry_kept_in_txn`]).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    kept: bool,
}

/// The rows beside acts one projection reads, by row ([`Projection::beside`]).
#[derive(Default)]
struct BesideReads(RefCell<BTreeMap<EntityId, BesideSeen>>);

/// What projecting one target did ([`project_target_in_txn`]).
pub(super) struct TargetProjected {
    /// The keys whose row the pass wrote or removed: one at most, but for a pack's target, where
    /// an owner's yes moves the layer rows of every key it accepts (stage 7c-3c).
    pub(super) changed: Vec<&'static SettingSpec>,
    /// How the acts the row came from stood, and the other live heads its value was met with:
    /// the receipt a door's own change row takes where the pass wrote no change of its own
    /// (stage 7b-3). `None` where the pass left the row as it is.
    pub(super) receipt: Option<(ChangeStanding, Vec<AuthorityEntryHash>)>,
}

impl TargetProjected {
    /// A pass that read nothing new.
    const UNMOVED: Self = Self {
        changed: Vec::new(),
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

/// The most copies one read follows through the copies they name (stage 7a-4): a name deeper
/// than this reads as one this install cannot read, the key's strictest value.
const COPY_DEPTH_MAX: usize = 64;

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
    /// A project's birth: the source key's heads it copies (stage 7c-3b, [`birth_value_in_txn`]).
    Birth(Vec<SettingCopyName>),
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
    /// Its acts name a row this build cannot write yet (a key that does not travel here, a head
    /// the log here does not hold): not recorded, so the open pass of a later build reads them
    /// again.
    ForNow,
    /// Its acts are on the key named, which this build does not know (stage 7c-1): recorded as
    /// `Pending` with the key's name ([`Projection::unknown_key`]), so a pass reads them again
    /// only once the revision moves or a build knows the key. A value that comes beside one of
    /// them changes nothing such a build reads. The record keeps the row a build that knew the
    /// key last projected, and how a pin at it reads, for when a build knows it again.
    UnknownKey(String),
    /// An act on the way keeps its value beside it, and that value has not reached this install
    /// (stage 7c-1; DESIGN 1.6, "Fold states": Pending): the row reads as it did before that
    /// act. Recorded as `Pending` with the rows it read ([`Projection::beside`]), so a pass reads
    /// the target again once that value is here.
    Awaiting,
}

/// `value`, decoded from the JSON bytes `json` beside an act, with each entity this vault erased
/// taken out where the key says how ([`super::Kind::erase_mentions`]), as an erase takes it out
/// of the rows stored when it ran: a value that reaches this install after the erase, or is read
/// again, names it no more than they do (stage 7c-1). A value names an entity by its hex id.
fn without_erased_mentions_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    json: &[u8],
    mut value: EncodedValue,
) -> Result<EncodedValue> {
    let named: BTreeSet<EntityId> = hex_id_mentions(json).collect();
    for id in named {
        if crate::deletion::row_deletion_marked(&vault.store, txn, &id, None)?
            && let Some(erased) = spec.kind.erase_mentions_in(&value, id)
        {
            value = erased;
        }
    }
    Ok(value)
}

/// A copy's value (stage 7a-4): the meet of what each act it names gives its row, a name this
/// install refused, cannot read or holds no row of reading the key's strictest value. `None`
/// when no name leaves a bound; [`Short::Unreadable`] where the key names no strictest value for
/// such a name, or two values do not meet; [`Inert::Awaiting`] where a named act's value beside
/// it has not reached this install (stage 7c-1). Each name reads by what its act counts for on
/// its own row (`name_counts`, [`name_value_in_txn`]). `depth` counts the copies followed so far.
fn copy_value_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    (reads, name_counts): (&BesideReads, &NameCounts),
    spec: &SettingSpec,
    names: &[SettingCopyName],
    depth: usize,
) -> Result<std::result::Result<Option<EncodedValue>, Short>> {
    Ok(copy_meet_in_txn(vault, txn, (reads, name_counts), spec, names, depth)?.map(|(met, _)| met))
}

/// What the entry `name` names gives the row it names, under `spec`, by what it counts for on
/// that row here (row SETTING-COPY-NAME-IGNORES-COUNT), as a walk of that row reads it
/// ([`Walk::gives`]): where it counts in full, its own value (`None` for a clear, an earlier
/// copy's for a copy, [`copy_value_in_txn`]); where it counts as a safe move, no more than what
/// it replaced gives. [`Short::Unreadable`] where this install refused the entry, holds no count
/// of it on that row (it does not hold it, or holds it only as a proposal), holds no row of it on
/// that slot, or cannot decode a value on the way (a value beside an act that does not match its
/// digest or was erased included), where an act on the way is disputed, and past
/// [`COPY_DEPTH_MAX`] copies; [`Inert::Awaiting`] where a value beside an act on the way has not
/// reached this install (stage 7c-1).
fn name_value_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    (reads, name_counts): (&BesideReads, &NameCounts),
    spec: &SettingSpec,
    name: &SettingCopyName,
    depth: usize,
) -> Result<std::result::Result<Option<EncodedValue>, Short>> {
    if depth >= COPY_DEPTH_MAX || vault.policy_setting_act_refused_in_txn(txn, name.act)? {
        return Ok(Err(Short::Unreadable));
    }
    let target = setting_slot_target(&name.slot)?;
    let Some((counts, named)) = name_counts
        .get(&target)
        .and_then(|counts| Some((counts, counts.get(&name.act)?)))
    else {
        return Ok(Err(Short::Unreadable));
    };
    // A key with no order has no safe move to read: only an act that counts in full gives its
    // value, and the rule is never used for it (a move copies only keys whose order has a meet).
    let rule = match rule_of(spec) {
        Some(rule) => rule,
        None if named.count == ChoiceCount::Full => Rule::Meet,
        None => return Ok(Err(Short::Unreadable)),
    };
    let empty = empty_of_in_txn(vault, txn, spec, &name.slot)?;
    let mut walk = Walk {
        vault,
        txn,
        reads,
        name_counts,
        spec,
        target,
        slot: &name.slot,
        counts,
        rule,
        strictest: spec.kind.strictest_value()?,
        empty,
        given: BTreeMap::new(),
        conflict: Cell::new(false),
        depth: depth + 1,
    };
    walk.gives(name.act)
}

/// The row the acts give, and how they stand.
struct Projected {
    /// The row's value; `None` for no row.
    value: Option<EncodedValue>,
    /// The row stays as it is: a quarantined value of a key that names no strictest value, so
    /// no row could read as one (its read would fail).
    keep: bool,
    /// A row beside an act the projection read was erased here or does not hold its act's value
    /// (stage 7c-1): the change row names no prior value, so no erased value is written again.
    erased: bool,
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

/// The rule a walk of a row of `spec`'s key reads by; `None` where its order has neither a meet
/// nor its own comparator.
fn rule_of(spec: &SettingSpec) -> Option<Rule> {
    match spec.kind.order() {
        order if order.has_meet() => Some(Rule::Meet),
        Order::Custom => Some(Rule::Comparator),
        _ => None,
    }
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
/// which an act that replaced nothing replaced. A copy's names are read by walks of their own
/// rows ([`name_value_in_txn`]).
struct Walk<'v, 't> {
    vault: &'v Vault,
    txn: &'v heed::RoTxn<'t>,
    /// The rows beside acts the walk read.
    reads: &'v BesideReads,
    /// What each act the copies the walk meets name counts for on its own row.
    name_counts: &'v NameCounts,
    spec: &'v SettingSpec,
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
    /// The copies followed to reach this row ([`COPY_DEPTH_MAX`]): zero on the row a pass
    /// projects, one more on each row a copy names.
    depth: usize,
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
        (&fold.counts, &fold.name_counts),
        (fold.conflict, in_force),
        &fold.asking,
    );
    let last = PROJECTIONS.get(&vault.store, txn, &target_key(target))?;
    if let Some(projection) = &last
        && !moved_since(vault, txn, projection, basis)?
    {
        return Ok(TargetProjected::UNMOVED);
    }
    if fold.live.iter().any(|head| head.pack.is_some()) {
        return project_pack_target_in_txn(vault, txn, (target, basis), &fold, now);
    }
    let inert = |why: Inert| (target, basis, why);
    let reads = BesideReads::default();
    let heads = match fold
        .live
        .iter()
        .map(head_of)
        .collect::<std::result::Result<Vec<Head>, Inert>>()
    {
        Ok(heads) => heads,
        Err(why) => return leave_in_txn(vault, txn, inert(why), reads),
    };
    let Some(slot) = heads.first().map(|head| head.slot.clone()) else {
        // Only proposals name the row: they change nothing, and it reads `Pending` while they
        // ask (stage 7b-3).
        if !fold.asking.is_empty() {
            record_projection_in_txn(
                vault,
                txn,
                target,
                &Projection {
                    slot: Vec::new(),
                    basis,
                    standing: SettingStanding::Pending,
                    pin_read_as_value: false,
                    beside: Vec::new(),
                    unknown_key: None,
                },
            )?;
        }
        return Ok(TargetProjected::UNMOVED);
    };
    if heads.iter().any(|head| head.slot != slot) {
        return leave_in_txn(vault, txn, inert(Inert::ForGood), reads);
    }
    let Ok(spec) = spec_named(&slot.name) else {
        let why = Inert::UnknownKey(slot.name.clone());
        return leave_in_txn(vault, txn, inert(why), reads);
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
        return leave_in_txn(vault, txn, inert(why), reads);
    }
    let mut projected = match combine(vault, txn, &reads, (spec, target), &heads, &fold)? {
        Ok(projected) => projected,
        // A later act waits for its own value (stage 7c-1): the row keeps the value it holds
        // while every row beside an act that value came from holds it, and reads the key's
        // strictest value, `Quarantined`, once one is erased here or no longer matches its act.
        Err(Inert::Awaiting) => {
            let kept = last.as_ref().map_or(&[][..], |last| last.beside.as_slice());
            match heads.first() {
                Some(newest) if reads.carry_kept_in_txn(vault, txn, kept)? => {
                    let has_strictest = spec.kind.strictest_value()?.is_some();
                    quarantined_of(has_strictest, (newest, &heads), &reads)
                }
                _ => return leave_in_txn(vault, txn, inert(Inert::Awaiting), reads),
            }
        }
        Err(why) => return leave_in_txn(vault, txn, inert(why), reads),
    };
    // A quarantine that keeps the row keeps the value it holds (stage 7c-1): it reads again each
    // row beside an act that value came from, keeps watching it, and holds no row once one is
    // erased here or no longer matches its act, so no read takes that value.
    if projected.keep {
        let kept = last.as_ref().map_or(&[][..], |last| last.beside.as_slice());
        if reads.carry_kept_in_txn(vault, txn, kept)?
            && let Some(newest) = heads.first()
        {
            projected = quarantined_of(false, (newest, &heads), &reads);
        }
    }
    let local = match slot.mode {
        SettingMode::Carried => own_carry_bound_in_txn(vault, txn, spec, &slot, &heads)?,
        SettingMode::Value | SettingMode::Pin => None,
    };
    let bound = local.as_ref().filter(|bound| spec.kind.decodes(bound));
    let projected = met_with_local(spec, projected, bound);
    let birth = birth_of_in_txn(vault, txn, (&reads, &fold.name_counts), spec, &heads)?;
    let changed = write_row_in_txn(
        vault,
        txn,
        (spec, &slot),
        &projected,
        (local.as_ref(), birth),
        now,
    )?;
    // A pin keeps its release only while every act it comes from counts in full here: one that
    // counts as a safe move keeps its value and is read as a value row (DESIGN 1.6, "The read
    // of one slot", step 3). A pin on a key with no meet never takes a safe move's own value.
    let pin_read_as_value = slot.mode == SettingMode::Pin
        && spec.kind.order().has_meet()
        && fold
            .counts
            .values()
            .any(|counted| counted.count != ChoiceCount::Full);
    record_projection_in_txn(
        vault,
        txn,
        target,
        &Projection {
            slot: slot.encode(),
            basis,
            standing: projected.standing.read_as(),
            pin_read_as_value,
            beside: reads.into_seen(!projected.keep),
            unknown_key: None,
        },
    )?;
    Ok(TargetProjected {
        changed: if changed { vec![spec] } else { Vec::new() },
        receipt: Some((projected.standing, projected.with)),
    })
}

/// Whether the row's one head is a project's birth that reads here (stage 7c-3b), and if so
/// whether it reads as a copy of a pack's default ([`birth_value_in_txn`]): `Some(seeded)` for
/// such a birth; `None` for a birth this install cannot read (its quarantined row is a change
/// like any other), any other head, or several.
fn birth_of_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    (reads, name_counts): (&BesideReads, &NameCounts),
    spec: &SettingSpec,
    heads: &[Head],
) -> Result<Option<bool>> {
    let [head] = heads else {
        return Ok(None);
    };
    let HeadBody::Birth(names) = &head.body else {
        return Ok(None);
    };
    let read = birth_value_in_txn(vault, txn, (reads, name_counts), spec, names, 0)?;
    Ok(read.ok().map(|(_, seeded)| seeded))
}

/// Whether `target`'s acts moved since `projection` was recorded: its basis is not `basis`, this
/// build knows the key it did not know then, or a row beside an act it read holds otherwise now
/// (stage 7c-1): the value arrived, was erased here, or no longer matches its act.
fn moved_since(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    projection: &Projection,
    basis: [u8; 32],
) -> Result<bool> {
    if projection.basis != basis
        || projection
            .unknown_key
            .as_deref()
            .is_some_and(|key| spec_named(key).is_ok())
    {
        return Ok(true);
    }
    for seen in &projection.beside {
        if beside_row_read_in_txn(vault, txn, seen.row, seen.digest)?.held() != seen.held {
            return Ok(true);
        }
    }
    Ok(false)
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

/// Forgets every record of a projection and leaves the rows it wrote (row
/// SETTING-PROJECTED-ROW-REFUSING-HOOKS tests): each row then holds its value while its acts read
/// as moved, as a row does once a peer's act arrived and before the pass read it. The records
/// forgotten.
///
/// # Errors
///
/// Storage errors.
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) fn forget_projection_records_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
) -> Result<usize> {
    let mut forgotten = 0;
    for (target, _) in PROJECTIONS.scan(&vault.store, txn)? {
        if PROJECTIONS.delete(&vault.store, txn, &target)? {
            forgotten += 1;
        }
    }
    Ok(forgotten)
}

/// A row beside an act that a target's last projection read, as an erase of it takes its value
/// out of the setting history (stage 7c-1, `change::scrub_beside_value_in_txn`).
pub(super) struct BesideSource {
    /// The row the target's acts name.
    pub(super) slot: RowKey,
    /// BLAKE3 over the JSON bytes of the value the act keeps beside it.
    pub(super) digest: [u8; 32],
    /// That row's value as stored here, where the value came from the row beside the act.
    pub(super) stored: Option<EncodedValue>,
}
