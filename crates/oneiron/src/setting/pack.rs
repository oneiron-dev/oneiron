//! The default layer (DESIGN 1.5 "The four layers", layer 0, and "Packs: a default that
//! changes"). A pack's defaults are value rows at [`SettingScope::Pack`], and only the pack door
//! writes them ([`Setter::Pack`]). The door keeps one head row per pack: the digest of the
//! defaults it last weighed, the keys the vault accepted from the pack, and the defaults that
//! wait on a holder's yes. The `engine` pack is this build's own catalogue; it runs at every open
//! and skips at once when the build's defaults are the ones its head weighed.
//!
//! A pack is an actor that holds no widening power. A tighter default lands, and so does any
//! default of a key that guards nothing; a looser one, or one the key's order cannot compare,
//! waits in the head's proposal while the accepted row stays, so every read is unchanged. A key
//! new in this build takes the engine pack's default with no compare: no earlier build read it.
//!
//! The head travels (stage 7c-3a; DESIGN 1.6 "Packs across machines"). On a rooted vault the
//! door appends one engine act per update in its own write: the pack's version, the digest of
//! its defaults, and the keys it held at their earlier accepted value. A reader proves a table by
//! its digest, never by the machine that sent it, and a version only by its own build: so on
//! another machine a head changes nothing, and that machine's door weighs its own build's
//! defaults (a birth's copy names the head, stage 7c-3b; an owner's yes that names its digest
//! proves its table, stage 7c-3c). The head row keeps the newest version the door acted under,
//! and the door acts only for a build whose version is not older, so an older build never
//! proposes its older defaults back.
//!
//! The owner's yes travels (stage 7c-3c; DESIGN 1.5 "A holder's yes replaces the rows", 1.6
//! "Packs across machines"). On a rooted vault it is one act with the owner's act, naming the
//! table's digest and the keys he accepts, on a target of its own per pack and table, so no pack
//! door's later head replaces it; it is appended in the yes's own write, and the act is the
//! write, so a yes this install cannot carry, or one that would wait for his proof, is refused.
//! The table's bytes travel beside each act that carries them, the door's head and the owner's yes,
//! in a row per act ([`super::beside::pack_table_row_id`]), and a reader takes a copy that is the
//! table beside the act it reads or beside a live act that names the table
//! ([`table_acts_in_txn`]). Each machine reads a yes that counts in full there
//! ([`project_pack_in_txn`]): where its head names the yes's table, the keys its waiting proposal
//! holds land as the owner's; where the yes names a newer table of the `engine` pack, the yes
//! proves that table, and the door weighs it from the bytes beside it first, as a build that ships
//! it would, so an older build reads the newer defaults at once. A yes to an older table changes
//! nothing: that machine's own proposal waits for a holder. A door that weighs a table lands the
//! yeses to it that came first. A row a yes landed stands while a yes that counts in full here
//! names its key; once none does (a later entry held it back), the row it replaced stands again
//! ([`revert_landings_in_txn`]). A yes whose table is not here, or erased here, leaves each key
//! it accepts at its strictest value until a weigh of a table that names the key, which starts
//! from the row the yes found ([`lift_quarantines_in_txn`]).

use std::collections::{BTreeMap, BTreeSet};

mod accept_checks;
use accept_checks::{CheckedAccept, checked_accept_in_txn, head_defaults_digest};
mod door;
pub(super) use door::project_pack_in_txn;
mod installed;
pub(crate) use installed::{
    close_pack_proposal_in_txn, pack_defaults_from_json, propose_installed_pack_defaults_in_txn,
};
mod layer;
pub(super) use layer::{
    LayerDefault, birth_pack_row_in_txn, fold_layer, layer_default_in_txn, pack_head_act_in_txn,
    packs_holding_in_txn, proposed_defaults_in_txn, yes_landing_tables_in_txn,
};
use layer::{
    LayerRow, append_head_with_table_in_txn, layer_rows_in_txn, newest_yes_pack, quarantine_in_txn,
    shipped_table,
};

use serde::{Deserialize, Serialize};

use oneiron_authority::authority::{
    ActSurface, AuthorityEntryHash, SettingPackHead, setting_pack_accept_target,
};
use oneiron_contracts::fingerprint::{ContentHash, Fingerprint, Fingerprinter, purposes};
use oneiron_setting_contract::{ChangeDirection, Order, RowKey};

use super::beside::{BesideRead, pack_table_read_in_txn, put_pack_table_in_txn};
use super::change::{record_change_in_txn, record_signed_entry_in_txn};
use super::project::{UNREADABLE_VALUE, rooted_in_txn};
use super::read::{StoredRow, table_of};
use super::{
    EncodedValue, ScopeKind, Setter, SettingChange, SettingMode, SettingScope, SettingSpec,
    catalogue, spec_named,
};
use crate::Vault;
use crate::authority::{ChoiceCount, OwnerProofGround, SettingSlotFold};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::side_table::{self, Named, SideTable, SideTableDbs};
use crate::world_keys::{OwnerActImportance, owner_presence_reasons};

/// The pack whose layer is this build's catalogue: every key.
pub const ENGINE_PACK: &str = "engine";

/// The version of the `engine` pack this build ships: the build's own (stage 7c-3a).
pub const ENGINE_PACK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The head rows, keyed by the pack's name.
const HEADS: SideTable<Vec<u8>, PackHead, Named> = SideTable::new(&side_table::SETTING_PACK_HEAD);

/// One pack's head row: what the vault accepted from it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PackHead {
    /// The digest of the defaults the door last weighed for this pack (hex).
    digest: String,
    /// The keys whose default the vault accepted from this pack, in name order.
    accepted: Vec<String>,
    /// The defaults of the last update the door could not land, waiting on a holder's yes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proposal: Option<PackProposal>,
    /// The version of the pack the door last acted under (stage 7c-3a): the newest it met, since
    /// the door never acts for an older one. Empty in a head written before versions, which
    /// reads as the oldest.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    version: String,
    /// The layer rows an owner's yes wrote here, oldest first (stage 7c-3c review): what a pass
    /// puts back once no yes that counts in full here names their key ([`revert_landings_in_txn`]).
    /// Empty in a head written before them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    landed: Vec<YesLanding>,
}

/// One layer row an owner's yes wrote here (stage 7c-3c review; the read-on-proofs rule: an act
/// that counts only as a safe move gives no more than what it replaced).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct YesLanding {
    /// The key whose row the yes wrote.
    key: String,
    /// The digest (hex) of the table the yes names: its yeses' target holds it.
    table: String,
    /// The row it replaced; `None` where the pack held no row. A row that did not decode is kept
    /// as one that reads unreadable.
    prior: Option<StoredRow>,
    /// The digest of the row it wrote ([`row_digest`]).
    wrote: String,
    /// The waiting default it took, and the digest (hex) of the table the head named then: it
    /// waits again where the head still names that table.
    proposed: Option<(String, ProposedDefault)>,
}

/// The loose defaults of one update, proposed together to the holders.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PackProposal {
    /// Its digest (hex): what an accept names.
    digest: String,
    defaults: Vec<ProposedDefault>,
}

/// One default that waits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProposedDefault {
    key: String,
    value: EncodedValue,
    /// The digest (hex) of the stored row it replaces; `None` where the pack holds no row.
    replaced: Option<String>,
    direction: ChangeDirection,
}

/// What one run of the pack door did, key by key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackApplied {
    /// Keys whose first default landed: new in this build.
    pub landed: Vec<String>,
    /// Keys whose default moved, tighter or on a key that guards nothing, or by the owner's yes
    /// to the weighed defaults that another machine carried first (stage 7c-3c).
    pub moved: Vec<String>,
    /// Keys whose new default waits on a holder's yes, in the head's proposal.
    pub proposed: Vec<String>,
    /// Keys the head names whose row is gone or does not decode: they read strictest until a
    /// holder sets them, and the door does not repair them.
    pub lost: Vec<String>,
}

/// A waiting default as `vault.settings.list` shows it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProposedDefaultView {
    /// The pack that proposes it.
    pub pack: String,
    /// The proposed default, as JSON.
    pub value: serde_json::Value,
    /// Which way it moves the default the vault accepted.
    pub direction: ChangeDirection,
    /// The proposal's digest: what `vault.settings.accept_defaults` names.
    pub proposal: String,
}

/// A pack's table of defaults as its bytes travel beside its head acts (stage 7c-3c): the
/// pack's name, then each key's name and default's bytes, in name order. A reader takes it as
/// the table a head names only where the defaults digest over it is the head's
/// ([`table_of_bytes`]).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackTable {
    pack: String,
    defaults: Vec<(String, EncodedValue)>,
}

/// The stored key of `name`'s row in `pack`'s layer.
fn pack_row_key(name: &str, pack: &str) -> Vec<u8> {
    RowKey {
        name: name.to_owned(),
        item: None,
        mode: SettingMode::Value,
        scope: SettingScope::Pack(pack.to_owned()),
    }
    .encode()
}

/// The head row of `pack`, if the door ever ran for it.
fn head_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    pack: &str,
) -> Result<Option<PackHead>> {
    HEADS.get(dbs, txn, &pack.as_bytes().to_vec())
}

/// The digest of `pack`'s defaults: a fingerprint under
/// [`purposes::setting::PACK_DEFAULTS`] of the pack's name, the count of its defaults, then each
/// key's name and default's bytes, in name order ([`table_digest`]).
fn defaults_digest(pack: &str, defaults: &[(&'static SettingSpec, EncodedValue)]) -> Fingerprint {
    let mut sorted: Vec<(&str, &EncodedValue)> = defaults
        .iter()
        .map(|(spec, value)| (spec.name, value))
        .collect();
    sorted.sort_by_key(|(name, _)| *name);
    table_digest(pack, &sorted)
}

/// The digest of `pack`'s table whose entries `sorted` are in name order ([`defaults_digest`]).
fn table_digest(pack: &str, sorted: &[(&str, &EncodedValue)]) -> Fingerprint {
    let mut digest = Fingerprinter::new(purposes::setting::PACK_DEFAULTS);
    digest.part(pack.as_bytes()).u64(sorted.len() as u64);
    for (name, value) in sorted {
        digest.part(name.as_bytes()).part(&value.0);
    }
    digest.finish()
}

/// `pack`'s table `defaults` as the bytes that travel beside its head acts (stage 7c-3c).
///
/// # Errors
///
/// `InvariantViolation` when the table does not encode (never in practice).
fn table_bytes(pack: &str, defaults: &[(&'static SettingSpec, EncodedValue)]) -> Result<Vec<u8>> {
    let mut entries: Vec<(String, EncodedValue)> = defaults
        .iter()
        .map(|(spec, value)| (spec.name.to_owned(), value.clone()))
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    rmp_serde::to_vec_named(&PackTable {
        pack: pack.to_owned(),
        defaults: entries,
    })
    .map_err(|_| Error::InvariantViolation("a pack table encodes"))
}

/// The defaults `bytes` hold where they are `pack`'s table whose digest is `digest`: they
/// decode, name the pack, list each key once in name order, and their defaults digest is
/// `digest` (stage 7c-3c). `None` otherwise.
fn table_of_bytes(
    pack: &str,
    digest: &[u8; 32],
    bytes: &[u8],
) -> Option<Vec<(String, EncodedValue)>> {
    let table: PackTable = rmp_serde::from_slice(bytes).ok()?;
    let sorted: Vec<(&str, &EncodedValue)> = table
        .defaults
        .iter()
        .map(|(name, value)| (name.as_str(), value))
        .collect();
    (table.pack == pack
        && sorted.windows(2).all(|pair| pair[0].0 < pair[1].0)
        && table_digest(pack, &sorted).into_bytes() == *digest)
        .then_some(table.defaults)
}

/// The acts here whose rows may hold `pack`'s table `digest`, `act` first where given (stage
/// 7c-3c review): `act`, the live yeses to that table, and the live heads of the pack that name
/// it. A reader takes any copy beside them that is the table ([`pack_table_read_in_txn`]).
///
/// # Errors
///
/// A target that does not encode; an entry that does not decode; storage errors.
fn table_acts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    (pack, digest): (&str, &[u8; 32]),
    act: Option<AuthorityEntryHash>,
) -> Result<Vec<AuthorityEntryHash>> {
    let mut acts: Vec<AuthorityEntryHash> = act.into_iter().collect();
    let yeses = vault.setting_slot_live_in_txn(txn, setting_pack_accept_target(pack, digest)?)?;
    let heads = vault
        .setting_pack_heads_in_txn(txn, pack)?
        .into_iter()
        .filter(|(_, head)| head.digest == *digest)
        .map(|(hash, _)| hash);
    for hash in yeses.into_iter().chain(heads) {
        if !acts.contains(&hash) {
            acts.push(hash);
        }
    }
    Ok(acts)
}

/// The digest of a stored layer row's bytes: what a proposal names as the row it replaces. The
/// row's content hash; the proposal binds the key beside it.
fn row_digest(bytes: &[u8]) -> String {
    ContentHash::of(bytes).to_hex()
}

/// The digest of a proposal: a fingerprint under [`purposes::setting::PACK_PROPOSAL`] of the
/// pack, the defaults digest it was made under, the count of waiting defaults, then each with
/// the row it replaces.
fn proposal_digest(pack: &str, digest: &str, defaults: &[ProposedDefault]) -> String {
    let mut fingerprint = Fingerprinter::new(purposes::setting::PACK_PROPOSAL);
    fingerprint
        .part(pack.as_bytes())
        .part(digest.as_bytes())
        .u64(defaults.len() as u64);
    for proposed in defaults {
        fingerprint
            .part(proposed.key.as_bytes())
            .part(&proposed.value.0);
        match &proposed.replaced {
            None => fingerprint.flag(false),
            Some(replaced) => fingerprint.flag(true).part(replaced.as_bytes()),
        };
    }
    fingerprint.finish().to_hex()
}

/// Which way a pack's new default moves the layer: by the key's order, on what the layer reads
/// before and after (RULING SETTING-6-0-AGENT-HOLDER-ONE-ROW = A: one rule for every actor
/// without the widening power; a key that guards nothing never asks).
fn layer_direction(
    spec: &SettingSpec,
    after: &EncodedValue,
    before: &EncodedValue,
) -> ChangeDirection {
    match spec.kind.order() {
        Order::Neutral => ChangeDirection::Neutral,
        Order::None => ChangeDirection::Unordered,
        _ => ChangeDirection::of(after, before, |a, b| {
            spec.kind.no_wider(a, b).unwrap_or(false)
        }),
    }
}

/// This build's defaults: every catalogue key's.
///
/// # Errors
///
/// A key whose default does not encode.
pub(crate) fn engine_pack_defaults() -> Result<Vec<(&'static SettingSpec, EncodedValue)>> {
    catalogue()
        .into_iter()
        .map(|spec| Ok((spec, spec.kind.default_value()?)))
        .collect()
}

/// Puts back, before a weigh of `defaults` in `pack`'s layer, the row each quarantine on one of
/// their keys replaced ([`quarantine_in_txn`]), and drops its landing from `head` (FIX
/// SETTING-PACK-TABLE-ERASED-ROW-BLOCKS-SAME-TABLE review): a table this install weighs is one
/// it reads, so the key is weighed from the row the unreadable yes found, never lost to the
/// unreadable row. A key's latest landing is lifted while its row is still the unreadable one
/// that landing wrote, so stacked quarantines lift down to the first readable row; a key the pack
/// held no row of before leaves `head`'s accepted keys. A quarantine wrote no change row, so the
/// lift writes none: the weigh's own change row runs from that row.
///
/// # Errors
///
/// Storage errors.
fn lift_quarantines_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    pack: &str,
    head: &mut PackHead,
    defaults: &[(&'static SettingSpec, EncodedValue)],
) -> Result<()> {
    for (spec, _) in defaults {
        let at = pack_row_key(spec.name, pack);
        while let Some(current) = table_of(spec).get_bytes(&vault.store, txn, &at)? {
            let unreadable = rmp_serde::from_slice::<StoredRow>(&current)
                .is_ok_and(|row| row.value.0 == [UNREADABLE_VALUE]);
            let wrote = row_digest(&current);
            let Some(index) = head
                .landed
                .iter()
                .rposition(|landing| landing.key == spec.name)
                .filter(|index| unreadable && head.landed[*index].wrote == wrote)
            else {
                break;
            };
            match head.landed.remove(index).prior {
                Some(row) => table_of(spec).put(&vault.store, txn, &at, &row)?,
                None => {
                    table_of(spec).delete(&vault.store, txn, &at)?;
                    head.accepted.retain(|name| name != spec.name);
                }
            }
        }
    }
    Ok(())
}

/// The digest of `spec`'s row in `pack`'s layer as stored now ([`row_digest`]); `None` with no
/// row.
fn layer_row_digest_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    pack: &str,
) -> Result<Option<String>> {
    Ok(table_of(spec)
        .get_bytes(&vault.store, txn, &pack_row_key(spec.name, pack))?
        .as_deref()
        .map(row_digest))
}

/// The keys the live yeses to `pack`'s table `digest` that count in full here accept (stage
/// 7c-3c review); `None` where such a yes is not stored here (an adopted image covers it), so its
/// keys cannot be read.
///
/// # Errors
///
/// A target that does not encode; storage errors.
fn counted_accepts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pack: &str,
    digest: &[u8; 32],
) -> Result<Option<BTreeSet<String>>> {
    let target = setting_pack_accept_target(pack, digest)?;
    let Some(fold) = vault.setting_slot_fold_in_txn(txn, target)? else {
        return Ok(Some(BTreeSet::new()));
    };
    let unread = fold.live.iter().any(|head| {
        head.pack.is_none()
            && fold
                .counts
                .get(&head.act)
                .is_some_and(|counted| counted.count == ChoiceCount::Full)
    });
    if unread {
        return Ok(None);
    }
    Ok(Some(
        fold.live
            .iter()
            .filter_map(|head| counted_yes(&fold, head))
            .filter_map(|yes| yes.accept.as_ref())
            .flat_map(|accept| accept.accepted.iter().cloned())
            .collect(),
    ))
}

/// The owner's yes `head` is, where it counts in full in `fold` (stage 7c-3c).
fn counted_yes<'f>(
    fold: &SettingSlotFold,
    head: &'f crate::authority::SettingSlotHead,
) -> Option<&'f SettingPackHead> {
    let full = fold
        .counts
        .get(&head.act)
        .is_some_and(|counted| counted.count == ChoiceCount::Full);
    head.pack
        .as_ref()
        .filter(|pack| full && pack.accept.is_some())
}

/// Puts back each layer row an owner's yes wrote here that no live yes counted in full here
/// names any more (stage 7c-3c review; DESIGN's read-on-proofs rule: an act that counts only as a
/// safe move gives no more than what it replaced). Per key, latest landing first: while the row
/// is still the one it wrote and no yes to its table that counts in full names the key, the row
/// it replaced stands again (none: the row goes), with a change row and the key's `on_change`,
/// and its default waits again in the head's proposal where the head still names the table it
/// was proposed under; a landing a later yes still keeps stays, with those under it. A landing
/// whose row another write replaced since is dropped, with those under it: that write decides
/// the row. A later yes that counts in full lands the key again. Answers the keys whose row
/// moved.
///
/// # Errors
///
/// A key's `on_change` refusal; storage errors.
fn revert_landings_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    now: u64,
) -> Result<Vec<&'static SettingSpec>> {
    let mut heads = Vec::new();
    for row in HEADS.iter_raw_from(&vault.store, txn, &[])? {
        let (pack, bytes) = row?;
        let (Ok(pack), Ok(head)) = (
            String::from_utf8(pack),
            rmp_serde::from_slice::<PackHead>(&bytes),
        ) else {
            continue;
        };
        if !head.landed.is_empty() {
            heads.push((pack, head));
        }
    }
    let mut moved = Vec::new();
    for (pack, mut head) in heads {
        let mut by_key: BTreeMap<String, Vec<YesLanding>> = BTreeMap::new();
        for landing in std::mem::take(&mut head.landed) {
            by_key.entry(landing.key.clone()).or_default().push(landing);
        }
        let mut counted: BTreeMap<String, Option<BTreeSet<String>>> = BTreeMap::new();
        let mut kept = Vec::new();
        let mut changed = false;
        for (key, mut landings) in by_key {
            let Ok(spec) = spec_named(&key) else {
                changed = true;
                continue;
            };
            while let Some(landing) = landings.pop() {
                let current =
                    table_of(spec).get_bytes(&vault.store, txn, &pack_row_key(spec.name, &pack))?;
                if current.as_deref().map(row_digest).as_deref() != Some(landing.wrote.as_str()) {
                    landings.clear();
                    changed = true;
                    break;
                }
                if yes_names_in_txn(vault, txn, (&pack, &landing.table), &key, &mut counted)? {
                    landings.push(landing);
                    break;
                }
                revert_landing_in_txn(vault, txn, (spec, &pack), (&mut head, landing), now)?;
                moved.push(spec);
                changed = true;
            }
            kept.extend(landings);
        }
        if changed {
            head.landed = kept;
            HEADS.put(&vault.store, txn, &pack.as_bytes().to_vec(), &head)?;
        }
    }
    Ok(moved)
}

/// Whether a live yes to `pack`'s table `table` (hex) that counts in full here accepts `key`,
/// or may: one not stored here keeps every row ([`counted_accepts_in_txn`]). Each table's yeses
/// are read once per pass (`counted`).
///
/// # Errors
///
/// A target that does not encode; storage errors.
fn yes_names_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    (pack, table): (&str, &str),
    key: &str,
    counted: &mut BTreeMap<String, Option<BTreeSet<String>>>,
) -> Result<bool> {
    if !counted.contains_key(table) {
        let keys = match oneiron_hex::decode::<32>(table) {
            Some(digest) => counted_accepts_in_txn(vault, txn, pack, &digest)?,
            None => Some(BTreeSet::new()),
        };
        counted.insert(table.to_owned(), keys);
    }
    Ok(counted
        .get(table)
        .is_none_or(|keys| keys.as_ref().is_none_or(|keys| keys.contains(key))))
}

/// Puts back the row `landing` replaced in `pack`'s layer ([`revert_landings_in_txn`]): the row
/// it replaced (none: the row goes), a change row by no one from the yes's value back, the key's
/// `on_change`, and its default waiting again in `head`'s proposal where `head` still names the
/// table it was proposed under. A key the pack held no row of before leaves `head`'s accepted
/// keys.
///
/// # Errors
///
/// A key's `on_change` refusal; storage errors.
fn revert_landing_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (spec, pack): (&'static SettingSpec, &str),
    (head, landing): (&mut PackHead, YesLanding),
    now: u64,
) -> Result<()> {
    let at = pack_row_key(spec.name, pack);
    let readable = |row: &StoredRow| spec.kind.decodes(&row.value).then(|| row.value.clone());
    let was = table_of(spec)
        .get_bytes(&vault.store, txn, &at)?
        .and_then(|bytes| rmp_serde::from_slice::<StoredRow>(&bytes).ok())
        .and_then(|row| readable(&row));
    let back = landing.prior.as_ref().and_then(readable);
    let direction = match (&back, &was) {
        (Some(after), Some(before)) => Some(layer_direction(spec, after, before)),
        _ => None,
    };
    let recorded = record_change_in_txn(
        &vault.store,
        txn,
        SettingChange {
            id: vault.store.clock.entity_id()?,
            sequence: 0,
            key: spec.name.to_owned(),
            item: None,
            scope: SettingScope::Pack(pack.to_owned()),
            mode: SettingMode::Value,
            by: None,
            setter: Setter::Pack,
            prior: was,
            value: back,
            at: now,
            why: Some(format!(
                "the owner's yes to defaults {} of pack `{pack}` no longer counts in full here: \
                 the row it replaced stands again",
                &landing.table[..landing.table.len().min(16)]
            )),
            weight_runs: None,
            direction,
            surface: None,
            signed: None,
            with: Vec::new(),
            standing: None,
        },
    )?;
    match &landing.prior {
        Some(row) => table_of(spec).put(&vault.store, txn, &at, row)?,
        None => {
            table_of(spec).delete(&vault.store, txn, &at)?;
            head.accepted.retain(|name| name != spec.name);
        }
    }
    if let Some(on_change) = spec.on_change {
        on_change(vault, txn, &recorded)?;
    }
    if let Some((of, proposed)) = landing.proposed
        && of == head.digest
    {
        let mut defaults = head
            .proposal
            .take()
            .map(|proposal| proposal.defaults)
            .unwrap_or_default();
        if defaults.iter().all(|waiting| waiting.key != proposed.key) {
            defaults.push(proposed);
            defaults.sort_by(|a, b| a.key.cmp(&b.key));
        }
        head.proposal = Some(PackProposal {
            digest: proposal_digest(pack, &head.digest, &defaults),
            defaults,
        });
    }
    Ok(())
}

/// The revision of `name`'s row in `pack`'s layer: the sequence of the change that wrote it, 0
/// for a first default; `None` with no readable row. A test door's read.
///
/// # Errors
///
/// An unknown key; storage errors.
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) fn layer_row_revision(vault: &Vault, name: &str, pack: &str) -> Result<Option<u64>> {
    let spec = spec_named(name)?;
    let txn = vault.store.env.read_txn()?;
    Ok(table_of(spec)
        .get_bytes(&vault.store, &txn, &pack_row_key(spec.name, pack))?
        .and_then(|bytes| rmp_serde::from_slice::<StoredRow>(&bytes).ok())
        .map(|row| row.change))
}

/// Deletes `name`'s row in `pack`'s layer, as a damaged store would lose it. A test door's
/// write.
///
/// # Errors
///
/// An unknown key; storage errors.
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) fn delete_layer_row(vault: &Vault, name: &str, pack: &str) -> Result<()> {
    let spec = spec_named(name)?;
    let mut txn = vault.store.env.write_txn()?;
    table_of(spec).delete(&vault.store, &mut txn, &pack_row_key(spec.name, pack))?;
    txn.commit()?;
    Ok(())
}

/// The version and the defaults digest (hex) `pack`'s head row keeps; `None` when the door never
/// ran for it. A test door's read (stage 7c-3a).
///
/// # Errors
///
/// Storage errors.
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) fn head_version_and_digest(
    vault: &Vault,
    pack: &str,
) -> Result<Option<(String, String)>> {
    let txn = vault.store.env.read_txn()?;
    Ok(head_in_txn(&vault.store, &txn, pack)?.map(|head| (head.version, head.digest)))
}

/// Writes `digest` as the defaults digest `pack`'s head row keeps, as a damaged store would hold
/// it. A test door's write.
///
/// # Errors
///
/// `InvalidConfig` for a pack with no head; storage errors.
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) fn put_head_digest(vault: &Vault, pack: &str, digest: &str) -> Result<()> {
    let mut txn = vault.store.env.write_txn()?;
    let Some(mut head) = head_in_txn(&vault.store, &txn, pack)? else {
        return Err(Error::InvalidConfig(format!(
            "no pack named `{pack}` has defaults in this vault"
        )));
    };
    head.digest = digest.to_owned();
    HEADS.put(&vault.store, &mut txn, &pack.as_bytes().to_vec(), &head)?;
    txn.commit()?;
    Ok(())
}

/// `pack`'s table `defaults` as the bytes that travel beside its head acts, and its digest
/// (stage 7c-3c tests).
///
/// # Errors
///
/// As [`table_bytes`].
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) fn table_digest_and_bytes(
    pack: &str,
    defaults: &[(&'static SettingSpec, EncodedValue)],
) -> Result<([u8; 32], Vec<u8>)> {
    Ok((
        defaults_digest(pack, defaults).into_bytes(),
        table_bytes(pack, defaults)?,
    ))
}
