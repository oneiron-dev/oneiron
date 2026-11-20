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
//! The table's bytes travel beside every head act ([`super::beside::pack_table_row_id`]). Each
//! machine reads a yes that counts in full there ([`project_pack_in_txn`]): where its head names
//! the yes's table, the keys its waiting proposal holds land as the owner's; where the yes names
//! a newer table of the `engine` pack, the yes proves that table, and the door weighs it from the
//! bytes beside it first, as a build that ships it would, so an older build reads the newer
//! defaults at once. A yes to an older table changes nothing: that machine's own proposal waits
//! for a holder. A door that weighs a table lands the yeses to it that came first. A row a yes
//! landed stands while a yes that counts in full here names its key; once none does (a later
//! entry held it back), the row it replaced stands again ([`revert_landings_in_txn`]).

use std::collections::{BTreeMap, BTreeSet};

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
use crate::authority::{ChoiceCount, SettingSlotFold};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::side_table::{self, Named, SideTable, SideTableDbs};

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

/// What reading a pack's heads did here ([`project_pack_in_txn`]).
pub(super) struct PackRead {
    /// The keys whose layer row moved: their `after_commit` runs once the write commits.
    pub(super) moved: Vec<&'static SettingSpec>,
    /// A yes names a newer table whose bytes have not reached this install: a later pass reads
    /// the heads again.
    pub(super) awaiting: bool,
}

/// The default a read starts from where no vault row or pin decides (DESIGN 1.5 "The read",
/// step 1).
pub(super) struct LayerDefault {
    /// The value the vault accepted, the build's default for a key no head names, or the key's
    /// strictest value when the accepted row is lost.
    pub(super) value: EncodedValue,
    /// The pack whose accepted row is gone or does not decode: the read is unreadable there.
    pub(super) lost: Option<SettingScope>,
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

/// The prefix every layer row of `name` starts with: its item-less value rows at a pack.
fn pack_rows_prefix(name: &str) -> Vec<u8> {
    let mut prefix = RowKey::item_prefix(name, None);
    prefix.push(SettingMode::Value.tag());
    prefix.push(ScopeKind::Pack.tag());
    prefix
}

/// Every layer row of `spec`, by pack: its value, or `None` when it does not decode.
fn layer_rows_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
) -> Result<Vec<(String, Option<EncodedValue>)>> {
    let mut rows = Vec::new();
    for row in table_of(spec).iter_raw_from(dbs, txn, &pack_rows_prefix(spec.name))? {
        let (key, bytes) = row?;
        let Some(RowKey {
            item: None,
            mode: SettingMode::Value,
            scope: SettingScope::Pack(pack),
            ..
        }) = RowKey::decode(&key)
        else {
            continue;
        };
        let value = rmp_serde::from_slice::<StoredRow>(&bytes)
            .ok()
            .map(|row| row.value)
            .filter(|value| spec.kind.decodes(value));
        rows.push((pack, value));
    }
    Ok(rows)
}

/// The value the layer's readable rows read: on a key whose rows meet, their meet; on any other
/// key, the engine pack's row, else the first.
pub(super) fn fold_layer(
    spec: &SettingSpec,
    rows: &[(String, EncodedValue)],
) -> Option<EncodedValue> {
    if spec.reads_met() {
        rows.iter()
            .map(|(_, value)| value.clone())
            .reduce(|met, value| spec.kind.meet(&met, &value).unwrap_or(met))
    } else {
        rows.iter()
            .find(|(pack, _)| pack == ENGINE_PACK)
            .or_else(|| rows.first())
            .map(|(_, value)| value.clone())
    }
}

/// The head row of `pack`, if the door ever ran for it.
fn head_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    pack: &str,
) -> Result<Option<PackHead>> {
    HEADS.get(dbs, txn, &pack.as_bytes().to_vec())
}

/// The packs whose layer holds a row of `spec` here, readable or not: the packs a birth of a key
/// `born` from `spec` names (stage 7c-3b).
///
/// # Errors
///
/// Storage errors.
pub(super) fn packs_holding_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
) -> Result<Vec<String>> {
    Ok(layer_rows_in_txn(dbs, txn, spec)?
        .into_iter()
        .map(|(pack, _)| pack)
        .collect())
}

/// The live head act of `pack` that names the table this install's own head names (stage
/// 7c-3b): what a birth names for a default the pack gives. Where none is live (the door last
/// acted before the vault had a root, or another machine's head with other defaults replaced
/// it), this install's head is appended in `txn` first, when the vault has a root and this
/// install can carry. `None` where the door never ran for the pack here, its head predates
/// versions, or the append fails (logged).
///
/// # Errors
///
/// Storage errors.
pub(super) fn pack_head_act_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    pack: &str,
) -> Result<Option<AuthorityEntryHash>> {
    let Some(head) = head_in_txn(&vault.store, txn, pack)? else {
        return Ok(None);
    };
    let Some(digest) = oneiron_hex::decode::<32>(&head.digest) else {
        return Ok(None);
    };
    if let Some((hash, _)) = vault
        .setting_pack_heads_in_txn(txn, pack)?
        .into_iter()
        .find(|(_, live)| live.digest == digest)
    {
        return Ok(Some(hash));
    }
    if head.version.is_empty()
        || !rooted_in_txn(vault, txn)?
        || !vault.can_carry_owner_act_in_txn(txn)?
    {
        return Ok(None);
    }
    let table = shipped_table(pack, &digest)?;
    let mut held: Vec<String> = head
        .proposal
        .iter()
        .flat_map(|proposal| {
            proposal
                .defaults
                .iter()
                .map(|proposed| proposed.key.clone())
        })
        .collect();
    held.sort_unstable();
    held.dedup();
    match append_head_with_table_in_txn(vault, txn, (pack, &head.version, digest, held), table) {
        Ok(hash) => Ok(Some(hash)),
        Err(error) => {
            tracing::warn!(
                pack,
                kind = ?error.kind(),
                "a birth found no head act of the pack and appended none: its born rows stand on this install"
            );
            Ok(None)
        }
    }
}

/// `spec`'s row in `pack`'s layer as a birth that names a head of the table `digest` reads it,
/// where this install's head of `pack` names that table (stage 7c-3b): this install's own row of
/// the key, the record of what it accepted from that table, a held key's earlier value included,
/// before each owner's yes the birth did not see (stage 7c-3d; DESIGN 1.6: a later change of the
/// default does not move a birth). The key's landings are walked newest first while the row is
/// the one a landing wrote, as a pass puts them back ([`revert_landings_in_txn`]): a landing whose
/// table (hex) `named` holds, the birth naming a yes to it, stops the walk; any other gives back
/// the row it replaced. `None` where the door never ran for the pack here or its head names
/// another table: the table is not proved here. `Some(None)` where the row reached is gone (a
/// landing replaced no row) or does not decode.
///
/// # Errors
///
/// `named`'s errors; storage errors.
pub(super) fn birth_pack_row_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    (pack, digest): (&str, &[u8; 32]),
    spec: &SettingSpec,
    mut named: impl FnMut(&str) -> Result<bool>,
) -> Result<Option<Option<EncodedValue>>> {
    let Some(head) = head_in_txn(dbs, txn, pack)?
        .filter(|head| oneiron_hex::decode::<32>(&head.digest).is_some_and(|ours| ours == *digest))
    else {
        return Ok(None);
    };
    let table = table_of(spec);
    let mut row = table.get_bytes(dbs, txn, &pack_row_key(spec.name, pack))?;
    for landing in head
        .landed
        .iter()
        .rev()
        .filter(|landing| landing.key == spec.name)
    {
        if row.as_deref().map(row_digest).as_deref() != Some(landing.wrote.as_str())
            || named(&landing.table)?
        {
            break;
        }
        row = landing
            .prior
            .as_ref()
            .map(|prior| table.encode_value(prior))
            .transpose()?;
    }
    Ok(Some(
        row.and_then(|bytes| rmp_serde::from_slice::<StoredRow>(&bytes).ok())
            .map(|row| row.value)
            .filter(|value| spec.kind.decodes(value)),
    ))
}

/// The table (its digest) of the owner's yes whose landing wrote `spec`'s row in `pack`'s layer
/// as it stands (stage 7c-3d): the key's newest landing, while the row is the one it wrote. What a
/// birth names a yes to, beside the pack's head. `None` where no yes wrote the row here.
///
/// # Errors
///
/// Storage errors.
pub(super) fn yes_landing_table_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    pack: &str,
    spec: &SettingSpec,
) -> Result<Option<[u8; 32]>> {
    let Some(head) = head_in_txn(dbs, txn, pack)? else {
        return Ok(None);
    };
    let Some(landing) = head
        .landed
        .iter()
        .rev()
        .find(|landing| landing.key == spec.name)
    else {
        return Ok(None);
    };
    let row = table_of(spec).get_bytes(dbs, txn, &pack_row_key(spec.name, pack))?;
    if row.as_deref().map(row_digest).as_deref() != Some(landing.wrote.as_str()) {
        return Ok(None);
    }
    Ok(oneiron_hex::decode::<32>(&landing.table))
}

/// The read's default for `spec`: what the vault accepted from its packs. A key a head names
/// whose row is gone or does not decode reads strictest. A key no head names reads the build's
/// default: it is new in this build, and that is the value the door lands for it.
///
/// # Errors
///
/// `CorruptedIndex` for a lost row of a key that names no strictest value; storage errors.
pub(super) fn layer_default_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
) -> Result<LayerDefault> {
    let rows = layer_rows_in_txn(dbs, txn, spec)?;
    if let Some((pack, _)) = rows.iter().find(|(_, value)| value.is_none()) {
        return lost(spec, pack);
    }
    let readable: Vec<(String, EncodedValue)> = rows
        .into_iter()
        .filter_map(|(pack, value)| value.map(|value| (pack, value)))
        .collect();
    if let Some(value) = fold_layer(spec, &readable) {
        return Ok(LayerDefault { value, lost: None });
    }
    for row in HEADS.iter_raw_from(dbs, txn, &[])? {
        let (pack, bytes) = row?;
        let names = rmp_serde::from_slice::<PackHead>(&bytes)
            .map(|head| {
                head.accepted
                    .binary_search_by(|key| key.as_str().cmp(spec.name))
                    .is_ok()
            })
            // A head that does not decode may name any key: read it as naming this one.
            .unwrap_or(true);
        if names {
            return lost(spec, &String::from_utf8_lossy(&pack));
        }
    }
    Ok(LayerDefault {
        value: spec.kind.default_value()?,
        lost: None,
    })
}

fn lost(spec: &SettingSpec, pack: &str) -> Result<LayerDefault> {
    Ok(LayerDefault {
        value: spec.kind.strictest_value()?.ok_or(Error::CorruptedIndex(
            "a setting's accepted default is lost and its key names no strictest value",
        ))?,
        lost: Some(SettingScope::Pack(pack.to_owned())),
    })
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

/// The bytes of `pack`'s table whose digest is `digest` where this build ships it: the `engine`
/// pack's own defaults (stage 7c-3c). `None` for any other table.
///
/// # Errors
///
/// A key whose default does not encode.
fn shipped_table(pack: &str, digest: &[u8; 32]) -> Result<Option<Vec<u8>>> {
    if pack != ENGINE_PACK {
        return Ok(None);
    }
    let defaults = engine_pack_defaults()?;
    if defaults_digest(pack, &defaults).into_bytes() != *digest {
        return Ok(None);
    }
    table_bytes(pack, &defaults).map(Some)
}

/// Appends `pack`'s head as one act in `txn`, with its table's bytes `table` beside it where
/// given (stage 7c-3c), in one savepoint: both, or neither. The entry's hash.
///
/// # Errors
///
/// The append's typed refusal; the put's refusal; storage errors.
fn append_head_with_table_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (pack, version, digest, held): (&str, &str, [u8; 32], Vec<String>),
    table: Option<Vec<u8>>,
) -> Result<AuthorityEntryHash> {
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    if let Some(table) = &table {
        put_pack_table_in_txn(vault, &mut savepoint, (pack, &digest), table)?;
    }
    let hash =
        vault.append_setting_pack_head_in_txn(&mut savepoint, pack, version, digest, held)?;
    savepoint.commit()?;
    Ok(hash)
}

/// Whether the pack door acts on `head` for a build that ships `version` of the pack, whose
/// defaults digest is `digest` (hex): not when the head weighed these defaults, and not when the
/// head holds a newer version than the build's (DESIGN 1.6, "Packs across machines": an older
/// build never proposes its older defaults back). An equal version with other defaults acts:
/// every build of one release names one version, so the rule tells releases apart, not builds.
fn door_acts(head: &PackHead, version: &str, digest: &str) -> bool {
    head.digest != digest && crate::gate::version_gt(&head.version, version) != Some(true)
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

/// The pack door: weighs `pack`'s `defaults`, as its build ships `version` of the pack, against
/// what the vault accepted from it, in the caller's write. `layer` lists the keys the pack's
/// install named; `None` is every key (the `engine` pack). A default outside the layer is a
/// proposal, tighter or not. Answers `None` when the door does not act ([`door_acts`]): the head
/// weighed these defaults, or holds a newer version. On a rooted vault whose install can carry,
/// the door appends the new head as one act in the same write (stage 7c-3a), with the table's
/// bytes beside it (stage 7c-3c); an append it cannot make is logged, and the rows stand.
///
/// # Errors
///
/// `InvalidConfig` for an empty pack name; a key's `on_change` refusal; storage errors.
pub(crate) fn apply_pack_defaults_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    pack: &str,
    (version, defaults): (&str, &[(&'static SettingSpec, EncodedValue)]),
    layer: Option<&[&str]>,
) -> Result<Option<PackApplied>> {
    if pack.is_empty() {
        return Err(Error::InvalidConfig("a pack has a name".into()));
    }
    let digest = defaults_digest(pack, defaults).into_bytes();
    weigh_in_txn(vault, txn, (pack, version, digest), defaults, (layer, true))
}

/// [`apply_pack_defaults_in_txn`] over `defaults` of the table whose digest is `digest`: this
/// build's own, or (stage 7c-3c) the keys this build knows of a table an owner's yes proved,
/// whose digest is the whole table's. With `append`, the door appends its head where it can; a
/// table a yes proved appends none, since the yes is its head.
fn weigh_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (pack, version, digest_bytes): (&str, &str, [u8; 32]),
    defaults: &[(&'static SettingSpec, EncodedValue)],
    (layer, append): (Option<&[&str]>, bool),
) -> Result<Option<PackApplied>> {
    let digest = oneiron_hex::encode(&digest_bytes);
    let head = head_in_txn(&vault.store, txn, pack)?.unwrap_or_default();
    if !door_acts(&head, version, &digest) {
        return Ok(None);
    }
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let mut accepted: BTreeSet<String> = head.accepted.iter().cloned().collect();
    let mut applied = PackApplied::default();
    let mut proposals = Vec::new();
    for (spec, value) in defaults {
        let spec: &'static SettingSpec = *spec;
        let name = spec.name.to_owned();
        let table = table_of(spec);
        let key = pack_row_key(spec.name, pack);
        let prior_bytes = table.get_bytes(&vault.store, txn, &key)?;
        let prior = match prior_bytes.as_deref() {
            None if accepted.contains(&name) => {
                applied.lost.push(name);
                continue;
            }
            None => None,
            Some(bytes) => match rmp_serde::from_slice::<StoredRow>(bytes)
                .ok()
                .filter(|row| spec.kind.decodes(&row.value))
            {
                Some(row) => Some(row),
                None => {
                    applied.lost.push(name);
                    continue;
                }
            },
        };
        let in_layer = layer.is_none_or(|keys| keys.contains(&spec.name));
        match &prior {
            Some(row) if row.value == *value => {
                accepted.insert(name);
                continue;
            }
            None if pack == ENGINE_PACK && in_layer => {
                // A key new in this build: nothing can be compared, so its first default lands.
                // It is no move, so it writes no change row.
                let row = StoredRow {
                    value: value.clone(),
                    by: None,
                    setter: Setter::Pack,
                    set_at: now,
                    change: 0,
                    weight_runs: None,
                    local: None,
                    seeded: false,
                };
                table.put(&vault.store, txn, &key, &row)?;
                accepted.insert(name.clone());
                applied.landed.push(name);
                continue;
            }
            _ => {}
        }
        // A move on the layer: judged against what its readers read before and after it.
        let others: Vec<(String, EncodedValue)> = layer_rows_in_txn(&vault.store, txn, spec)?
            .into_iter()
            .filter(|(at, _)| at != pack)
            .filter_map(|(at, value)| value.map(|value| (at, value)))
            .collect();
        let mut before_rows = others.clone();
        if let Some(row) = &prior {
            before_rows.push((pack.to_owned(), row.value.clone()));
        }
        let mut after_rows = others;
        after_rows.push((pack.to_owned(), value.clone()));
        let before = match fold_layer(spec, &before_rows) {
            Some(before) => before,
            None => spec.kind.default_value()?,
        };
        let after = fold_layer(spec, &after_rows).unwrap_or_else(|| value.clone());
        let direction = layer_direction(spec, &after, &before);
        if !in_layer
            || !matches!(
                direction,
                ChangeDirection::Tighter | ChangeDirection::Neutral
            )
        {
            proposals.push(ProposedDefault {
                key: name.clone(),
                value: value.clone(),
                replaced: prior_bytes.as_deref().map(row_digest),
                direction,
            });
            applied.proposed.push(name);
            continue;
        }
        write_layer_row_in_txn(
            vault,
            txn,
            spec,
            pack,
            LayerWrite {
                value,
                prior: prior.map(|row| row.value),
                by: None,
                direction,
                why: format!("pack `{pack}` defaults {}", &digest[..16]),
                at: now,
                signed: None,
            },
        )?;
        accepted.insert(name.clone());
        applied.moved.push(name);
    }
    let proposal = (!proposals.is_empty()).then(|| PackProposal {
        digest: proposal_digest(pack, &digest, &proposals),
        defaults: proposals,
    });
    HEADS.put(
        &vault.store,
        txn,
        &pack.as_bytes().to_vec(),
        &PackHead {
            digest,
            accepted: accepted.into_iter().collect(),
            proposal,
            version: version.to_owned(),
            landed: head.landed,
        },
    )?;
    // The owner's yeses to this table that count here land now (stage 7c-3c): a yes another
    // machine carried before this one weighed the table, which no head below holds back.
    for spec in take_live_accepts_in_txn(vault, txn, (pack, digest_bytes), now)? {
        applied.proposed.retain(|key| key != spec.name);
        applied.moved.push(spec.name.to_owned());
    }
    let held: Vec<String> = head_in_txn(&vault.store, txn, pack)?
        .and_then(|head| head.proposal)
        .map(|proposal| {
            proposal
                .defaults
                .into_iter()
                .map(|proposed| proposed.key)
                .collect::<BTreeSet<String>>()
                .into_iter()
                .collect()
        })
        .unwrap_or_default();
    if append
        && rooted_in_txn(vault, txn)?
        && vault.can_carry_owner_act_in_txn(txn)?
        && let Err(error) = table_bytes(pack, defaults).and_then(|table| {
            append_head_with_table_in_txn(
                vault,
                txn,
                (pack, version, digest_bytes, held),
                Some(table),
            )
        })
    {
        tracing::warn!(
            pack,
            kind = ?error.kind(),
            "the pack door's head was not appended: its rows stand on this install, and other machines weigh their own builds' defaults"
        );
    }
    Ok(Some(applied))
}

/// One write of a layer row by the door.
struct LayerWrite<'a> {
    value: &'a EncodedValue,
    prior: Option<EncodedValue>,
    by: Option<crate::entity_id::EntityId>,
    direction: ChangeDirection,
    why: String,
    at: u64,
    /// The owner's yes that made the write, a peer's (stage 7c-3c review): the change row names
    /// it. A local yes names its act once it is appended ([`record_signed_entry_in_txn`]).
    signed: Option<AuthorityEntryHash>,
}

/// Writes `spec`'s row in `pack`'s layer, with its change row and the key's `on_change`, and
/// answers the change row.
fn write_layer_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    spec: &'static SettingSpec,
    pack: &str,
    write: LayerWrite<'_>,
) -> Result<SettingChange> {
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
            by: write.by,
            setter: Setter::Pack,
            prior: write.prior,
            value: Some(write.value.clone()),
            at: write.at,
            why: Some(write.why),
            weight_runs: None,
            direction: Some(write.direction),
            surface: None,
            signed: write.signed,
            with: Vec::new(),
            standing: None,
        },
    )?;
    let row = StoredRow {
        value: write.value.clone(),
        by: write.by,
        setter: Setter::Pack,
        set_at: write.at,
        change: recorded.sequence,
        weight_runs: None,
        local: None,
        seeded: false,
    };
    table_of(spec).put(&vault.store, txn, &pack_row_key(spec.name, pack), &row)?;
    if let Some(on_change) = spec.on_change {
        on_change(vault, txn, &recorded)?;
    }
    Ok(recorded)
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

/// The waiting defaults of every pack, by key: what `vault.settings.list` shows.
///
/// # Errors
///
/// Storage errors.
pub(super) fn proposed_defaults_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(String, ProposedDefaultView)>> {
    let mut views = Vec::new();
    for row in HEADS.iter_raw_from(dbs, txn, &[])? {
        let (pack, bytes) = row?;
        let Ok(head) = rmp_serde::from_slice::<PackHead>(&bytes) else {
            continue;
        };
        let Some(proposal) = head.proposal else {
            continue;
        };
        let pack = String::from_utf8_lossy(&pack).into_owned();
        for proposed in proposal.defaults {
            let value = spec_named(&proposed.key)
                .ok()
                .and_then(|spec| spec.kind.to_json(&proposed.value))
                .unwrap_or(serde_json::Value::Null);
            views.push((
                proposed.key,
                ProposedDefaultView {
                    pack: pack.clone(),
                    value,
                    direction: proposed.direction,
                    proposal: proposal.digest.clone(),
                },
            ));
        }
    }
    Ok(views)
}

impl Vault {
    /// The `engine` pack's run at open: weighs this build's defaults against what the vault
    /// accepted, in its own write, and skips at once when the head already weighed them. Runs
    /// each moved key's `after_commit` once the write committed.
    ///
    /// # Errors
    ///
    /// As [`apply_pack_defaults_in_txn`].
    pub(crate) fn apply_engine_pack(&self) -> Result<Option<PackApplied>> {
        let defaults = engine_pack_defaults()?;
        {
            let txn = self.store.env.read_txn()?;
            let digest = defaults_digest(ENGINE_PACK, &defaults).to_hex();
            if head_in_txn(&self.store, &txn, ENGINE_PACK)?
                .is_some_and(|head| !door_acts(&head, ENGINE_PACK_VERSION, &digest))
            {
                return Ok(None);
            }
        }
        self.apply_pack_defaults(ENGINE_PACK, (ENGINE_PACK_VERSION, &defaults), None)
    }

    /// [`apply_pack_defaults_in_txn`] in its own write, then each moved key's `after_commit`.
    ///
    /// # Errors
    ///
    /// As [`apply_pack_defaults_in_txn`].
    pub(crate) fn apply_pack_defaults(
        &self,
        pack: &str,
        shipped: (&str, &[(&'static SettingSpec, EncodedValue)]),
        layer: Option<&[&str]>,
    ) -> Result<Option<PackApplied>> {
        self.with_write_txn_grouped_after_commit(
            |txn| apply_pack_defaults_in_txn(self, txn, pack, shipped, layer),
            |applied| {
                if let Some(applied) = &applied {
                    run_layer_after_commit(self, &applied.moved);
                }
                Ok(applied)
            },
        )
    }

    /// The owner says yes to `pack`'s waiting proposal `proposal`: each of its defaults replaces
    /// the row it was proposed over, with a change row by the owner, and the proposal closes.
    /// All or none: when any row moved since the proposal, nothing lands, and the next run of the
    /// pack door proposes again. On a rooted vault the yes travels as one head act with his act
    /// (stage 7c-3c), appended in the same write, or the yes is refused. Answers the keys whose
    /// default landed.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for a pack with no head, a proposal that is not the pack's waiting one, a
    /// row that moved since, or a key this build does not know; an owner proof that no longer
    /// holds; on a rooted vault, the append's typed refusal, and `OwnerKeyRequired` for a yes
    /// that would wait for the owner's proof; a key's `on_change` refusal; storage errors.
    pub fn accept_pack_defaults(
        &self,
        owner: &AuthenticatedOwner,
        pack: &str,
        proposal: &str,
    ) -> Result<Vec<String>> {
        self.with_write_txn_grouped_after_commit(
            |txn| accept_pack_defaults_in_txn(self, txn, owner, pack, proposal),
            |keys| {
                run_layer_after_commit(self, &keys);
                Ok(keys)
            },
        )
    }
}

fn accept_pack_defaults_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    pack: &str,
    proposal: &str,
) -> Result<Vec<String>> {
    let by = owner.revalidate_in_txn(vault, txn)?;
    let Some(mut head) = head_in_txn(&vault.store, txn, pack)? else {
        return Err(Error::InvalidConfig(format!(
            "no pack named `{pack}` has defaults in this vault"
        )));
    };
    let Some(waiting) = head
        .proposal
        .take()
        .filter(|waiting| waiting.digest == proposal)
    else {
        return Err(Error::InvalidConfig(format!(
            "pack `{pack}` has no waiting proposal `{proposal}`: read the list again"
        )));
    };
    let mut checked = Vec::with_capacity(waiting.defaults.len());
    for proposed in &waiting.defaults {
        let spec = spec_named(&proposed.key)?;
        let current =
            table_of(spec).get_bytes(&vault.store, txn, &pack_row_key(spec.name, pack))?;
        if current.as_deref().map(row_digest) != proposed.replaced
            || !spec.kind.decodes(&proposed.value)
        {
            return Err(Error::InvalidConfig(format!(
                "the default of `{}` moved since proposal `{proposal}`: the pack door proposes \
                 again at its next run",
                proposed.key
            )));
        }
        let prior = current
            .as_deref()
            .and_then(|bytes| rmp_serde::from_slice::<StoredRow>(bytes).ok());
        checked.push((spec, prior));
    }
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let mut accepted: BTreeSet<String> = head.accepted.iter().cloned().collect();
    let mut keys = Vec::with_capacity(checked.len());
    let mut changes = Vec::with_capacity(checked.len());
    let mut landings = Vec::with_capacity(checked.len());
    for (proposed, (spec, prior)) in waiting.defaults.iter().zip(checked) {
        changes.push(write_layer_row_in_txn(
            vault,
            txn,
            spec,
            pack,
            LayerWrite {
                value: &proposed.value,
                prior: prior.as_ref().map(|row| row.value.clone()),
                by: Some(by),
                direction: proposed.direction,
                why: format!(
                    "the owner accepted proposal {} of pack `{pack}`",
                    &proposal[..proposal.len().min(16)]
                ),
                at: now,
                signed: None,
            },
        )?);
        landings.push(YesLanding {
            key: proposed.key.clone(),
            table: head.digest.clone(),
            prior,
            wrote: layer_row_digest_in_txn(vault, txn, spec, pack)?.unwrap_or_default(),
            proposed: Some((head.digest.clone(), proposed.clone())),
        });
        accepted.insert(proposed.key.clone());
        keys.push(proposed.key.clone());
    }
    head.accepted = accepted.into_iter().collect();
    HEADS.put(&vault.store, txn, &pack.as_bytes().to_vec(), &head)?;
    // The yes that travels is the act its change rows name, and what keeps its rows here: a pass
    // puts them back once no yes that counts in full names their keys (stage 7c-3c review).
    if rooted_in_txn(vault, txn)?
        && let Some(signed) = append_yes_in_txn(vault, txn, (pack, &head), (by, keys.clone()))?
    {
        for change in &changes {
            record_signed_entry_in_txn(&vault.store, txn, change, signed)?;
        }
        head.landed.extend(landings);
        HEADS.put(&vault.store, txn, &pack.as_bytes().to_vec(), &head)?;
    }
    Ok(keys)
}

/// Appends the owner `owner`'s yes to the keys `accepted` of the table `head` (`pack`'s, after
/// the yes) names, in the yes's write `txn` (stage 7c-3c): one head act with his act, naming the
/// head's version and digest and the keys still held, with the table beside it where this build
/// ships it and no row of it is here. The act is the write: an append this install cannot make,
/// or a yes that would wait for his proof, refuses the yes, as an owner's change of a row that
/// travels is refused (ruling CARRIER-CHOICE-DOOR-WAIT-OR-REFUSE = B). A head from before
/// versions names no version an act carries: that yes stays on this install, as such a head's
/// birth does (logged). The yes accepts `accepted` and every key a live yes to the same table
/// that counts in full here accepts (stage 7c-3c review): it replaces those yeses, so the keys
/// the owner accepted there stay accepted; a yes that counts only as a safe move is not carried,
/// so a new yes never makes it count in full. Answers the appended act; `None` where the yes
/// stays on this install.
///
/// # Errors
///
/// The append's typed refusal; `OwnerKeyRequired`; `CorruptedIndex` for a head whose digest is
/// not 64 hex digits; storage errors.
fn append_yes_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (pack, head): (&str, &PackHead),
    (owner, mut accepted): (EntityId, Vec<String>),
) -> Result<Option<AuthorityEntryHash>> {
    let Some(digest) = oneiron_hex::decode::<32>(&head.digest) else {
        return Err(Error::CorruptedIndex(
            "a pack head's digest is not 64 hex digits",
        ));
    };
    if head.version.is_empty() {
        tracing::warn!(
            pack,
            "the owner's yes names a pack head from before versions: it stays on this install"
        );
        return Ok(None);
    }
    if let Some(table) = shipped_table(pack, &digest)? {
        put_pack_table_in_txn(vault, txn, (pack, &digest), &table)?;
    }
    accepted.extend(counted_accepts_in_txn(vault, txn, pack, &digest)?.unwrap_or_default());
    let held: BTreeSet<String> = head
        .proposal
        .iter()
        .flat_map(|proposal| {
            proposal
                .defaults
                .iter()
                .map(|proposed| proposed.key.clone())
        })
        .collect();
    accepted.retain(|key| !held.contains(key));
    accepted.sort_unstable();
    accepted.dedup();
    let signed = vault.append_setting_pack_accept_in_txn(
        txn,
        (pack, &head.version, digest, held.into_iter().collect()),
        (owner, ActSurface::ThisInstall),
        accepted,
    )?;
    if vault.setting_act_waits_in_txn(txn, signed)? {
        return Err(Error::Record(RecordError::OwnerKeyRequired));
    }
    Ok(Some(signed))
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

/// Reads `fold`, the acts on a pack's target or on the target of the owner's yeses to one of its
/// tables, in `txn` (stage 7c-3c; DESIGN 1.6 "Packs across machines"). A pack door's head changes
/// nothing here: this install's own door weighs its own build's defaults (stage 7c-3a). Each
/// owner's yes that counts in full here lands ([`land_yes_in_txn`]); one that does not changes
/// nothing, as a proposal or a safe move that would loosen changes nothing. First, each row a yes
/// landed that no yes counted in full names any more is put back ([`revert_landings_in_txn`]).
///
/// # Errors
///
/// A key's `on_change` refusal; storage errors.
pub(super) fn project_pack_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    fold: &SettingSlotFold,
    now: u64,
) -> Result<PackRead> {
    let mut read = PackRead {
        moved: revert_landings_in_txn(vault, txn, now)?,
        awaiting: false,
    };
    for head in &fold.live {
        let Some(yes) = counted_yes(fold, head) else {
            continue;
        };
        match land_yes_in_txn(vault, txn, (head.act, yes), now)? {
            Some(moved) => read.moved.extend(moved),
            None => read.awaiting = true,
        }
    }
    Ok(read)
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

/// Lands, in the pack door's write, each of the owner's yeses to `pack`'s table `digest` that
/// counts in full here (stage 7c-3c): the door just weighed that table, and a yes another
/// machine carried before lands its keys from the door's proposal ([`take_accepted_in_txn`]).
/// Answers the keys whose layer row moved.
///
/// # Errors
///
/// A key's `on_change` refusal; storage errors.
fn take_live_accepts_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (pack, digest): (&str, [u8; 32]),
    now: u64,
) -> Result<Vec<&'static SettingSpec>> {
    let target = setting_pack_accept_target(pack, &digest)?;
    let Some(fold) = vault.setting_slot_fold_in_txn(txn, target)? else {
        return Ok(Vec::new());
    };
    let mut moved = Vec::new();
    for head in &fold.live {
        if let Some(yes) = counted_yes(&fold, head) {
            moved.extend(take_accepted_in_txn(vault, txn, (head.act, yes), now)?);
        }
    }
    Ok(moved)
}

/// Lands the owner's yes `yes`, the entry `act`, here (stage 7c-3c), and answers the keys whose
/// layer row moved; `None` while it waits for its table's bytes.
/// - Where this install's head names the yes's table, each key of the yes that this install's
///   waiting proposal holds lands ([`take_accepted_in_txn`]).
/// - Where the yes names a table of the `engine` pack of a version newer than this install's
///   head's, the yes proves that table, and its bytes come from beside it: absent, the yes waits
///   and every row reads as before it; not that table, or erased here, each key the yes accepts
///   reads its strictest value ([`quarantine_in_txn`]); that table, where this build knows each
///   of its keys and reads each of its defaults, the door weighs it as a build that ships it
///   would, records the yes's version and digest, appends no head (no build of this install
///   shipped it), and lands every yes to it that counts here, this one with them.
/// - Otherwise (an older table, an equal version with another table, a newer table with a key
///   this build does not know or a default it cannot read, a pack whose door never ran here)
///   nothing changes here: this install's own proposal waits for a holder, and the door of a
///   build that ships the yes's table lands it ([`take_live_accepts_in_txn`]).
fn land_yes_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (act, yes): (AuthorityEntryHash, &SettingPackHead),
    now: u64,
) -> Result<Option<Vec<&'static SettingSpec>>> {
    let Some(accept) = &yes.accept else {
        return Ok(Some(Vec::new()));
    };
    let pack = yes.pack.as_str();
    let Some(head) = head_in_txn(&vault.store, txn, pack)? else {
        return Ok(Some(Vec::new()));
    };
    let mut moved = Vec::new();
    if head.digest != oneiron_hex::encode(&yes.digest) {
        let newer = head.version.is_empty()
            || crate::gate::version_gt(&yes.version, &head.version) == Some(true);
        if pack != ENGINE_PACK || !newer {
            return Ok(Some(moved));
        }
        let read = pack_table_read_in_txn(vault, txn, (pack, &yes.digest), |bytes| {
            table_of_bytes(pack, &yes.digest, bytes).is_some()
        })?;
        let table = match read {
            BesideRead::Absent => return Ok(None),
            BesideRead::Unreadable => {
                let table = oneiron_hex::encode(&yes.digest);
                return quarantine_in_txn(vault, txn, (pack, &table), &accept.accepted, now)
                    .map(Some);
            }
            BesideRead::Here(bytes) => table_of_bytes(pack, &yes.digest, &bytes).ok_or(
                Error::InvariantViolation("a pack table that matched reads again"),
            )?,
        };
        let Some(defaults) = table
            .into_iter()
            .map(|(name, value)| {
                let spec = spec_named(&name).ok()?;
                spec.kind.decodes(&value).then_some((spec, value))
            })
            .collect::<Option<Vec<(&'static SettingSpec, EncodedValue)>>>()
        else {
            return Ok(Some(moved));
        };
        if let Some(applied) = weigh_in_txn(
            vault,
            txn,
            (pack, &yes.version, yes.digest),
            &defaults,
            (None, false),
        )? {
            moved.extend(applied.moved.iter().filter_map(|key| spec_named(key).ok()));
        }
    }
    moved.extend(take_accepted_in_txn(vault, txn, (act, yes), now)?);
    Ok(Some(moved))
}

/// Lands each key the owner's yes `yes` (the entry `act`) accepts that this install's waiting
/// proposal of its pack holds, where this install's head names the yes's table (stage 7c-3c):
/// the proposal's default replaces the row it was proposed over, with a change row by the owner
/// naming the yes, and leaves the proposal, which closes when nothing waits in it. A key whose
/// row moved since the proposal stays in it, as the accept door refuses such a row. Answers the
/// keys whose row moved.
///
/// # Errors
///
/// A key's `on_change` refusal; storage errors.
fn take_accepted_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (act, yes): (AuthorityEntryHash, &SettingPackHead),
    now: u64,
) -> Result<Vec<&'static SettingSpec>> {
    let pack = yes.pack.as_str();
    let Some(accept) = &yes.accept else {
        return Ok(Vec::new());
    };
    let (owner, accepted) = (accept.act.owner, accept.accepted.as_slice());
    let Some(mut head) = head_in_txn(&vault.store, txn, pack)? else {
        return Ok(Vec::new());
    };
    if head.digest != oneiron_hex::encode(&yes.digest) {
        return Ok(Vec::new());
    }
    let Some(proposal) = head.proposal.take() else {
        return Ok(Vec::new());
    };
    let mut landed: BTreeSet<String> = head.accepted.iter().cloned().collect();
    let mut kept = Vec::new();
    let mut moved = Vec::new();
    for proposed in proposal.defaults {
        let spec = match spec_named(&proposed.key) {
            Ok(spec) if accepted.binary_search(&proposed.key).is_ok() => spec,
            _ => {
                kept.push(proposed);
                continue;
            }
        };
        let current =
            table_of(spec).get_bytes(&vault.store, txn, &pack_row_key(spec.name, pack))?;
        if current.as_deref().map(row_digest) != proposed.replaced
            || !spec.kind.decodes(&proposed.value)
        {
            kept.push(proposed);
            continue;
        }
        let prior = current
            .as_deref()
            .and_then(|bytes| rmp_serde::from_slice::<StoredRow>(bytes).ok());
        write_layer_row_in_txn(
            vault,
            txn,
            spec,
            pack,
            LayerWrite {
                value: &proposed.value,
                prior: prior.as_ref().map(|row| row.value.clone()),
                by: Some(owner),
                direction: proposed.direction,
                why: format!(
                    "the owner accepted defaults {} of pack `{pack}` (act {})",
                    &head.digest[..head.digest.len().min(16)],
                    &oneiron_hex::encode(&act)[..16]
                ),
                at: now,
                signed: Some(act),
            },
        )?;
        head.landed.push(YesLanding {
            key: proposed.key.clone(),
            table: head.digest.clone(),
            prior,
            wrote: layer_row_digest_in_txn(vault, txn, spec, pack)?.unwrap_or_default(),
            proposed: Some((head.digest.clone(), proposed.clone())),
        });
        landed.insert(proposed.key.clone());
        moved.push(spec);
    }
    if moved.is_empty() {
        return Ok(moved);
    }
    head.proposal = (!kept.is_empty()).then(|| PackProposal {
        digest: proposal_digest(pack, &head.digest, &kept),
        defaults: kept,
    });
    head.accepted = landed.into_iter().collect();
    HEADS.put(&vault.store, txn, &pack.as_bytes().to_vec(), &head)?;
    Ok(moved)
}

/// Writes each of `keys` this build knows as a row of `pack`'s layer that does not decode, and
/// takes it out of the pack's waiting proposal (stage 7c-3c): the owner accepted its default of a
/// table whose bytes here are not that table, or were erased here, so it reads the key's
/// strictest value, unreadable, as a lost row does (DESIGN 1.6, "Fold states"). No change row and
/// no hook: no value was read. Each row it writes is a landing of the yes to `table` (hex), put
/// back once no yes that counts in full names its key (stage 7c-3c review). Answers the keys whose
/// row moved.
///
/// # Errors
///
/// Storage errors.
fn quarantine_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (pack, table): (&str, &str),
    keys: &[String],
    now: u64,
) -> Result<Vec<&'static SettingSpec>> {
    let mut head = head_in_txn(&vault.store, txn, pack)?.unwrap_or_default();
    let mut accepted: BTreeSet<String> = head.accepted.iter().cloned().collect();
    let mut moved = Vec::new();
    for key in keys {
        let Ok(spec) = spec_named(key) else {
            continue;
        };
        let at = pack_row_key(spec.name, pack);
        let prior = table_of(spec)
            .get_bytes(&vault.store, txn, &at)?
            .map(|bytes| {
                rmp_serde::from_slice::<StoredRow>(&bytes).unwrap_or_else(|_| unreadable_row(now))
            });
        table_of(spec).put(&vault.store, txn, &at, &unreadable_row(now))?;
        let proposed = head.proposal.as_ref().and_then(|proposal| {
            proposal
                .defaults
                .iter()
                .find(|proposed| proposed.key == spec.name)
                .map(|proposed| (head.digest.clone(), proposed.clone()))
        });
        head.landed.push(YesLanding {
            key: spec.name.to_owned(),
            table: table.to_owned(),
            prior,
            wrote: layer_row_digest_in_txn(vault, txn, spec, pack)?.unwrap_or_default(),
            proposed,
        });
        accepted.insert(spec.name.to_owned());
        moved.push(spec);
    }
    if let Some(proposal) = head.proposal.take() {
        let kept: Vec<ProposedDefault> = proposal
            .defaults
            .into_iter()
            .filter(|proposed| keys.binary_search(&proposed.key).is_err())
            .collect();
        head.proposal = (!kept.is_empty()).then(|| PackProposal {
            digest: proposal_digest(pack, &head.digest, &kept),
            defaults: kept,
        });
    }
    head.accepted = accepted.into_iter().collect();
    HEADS.put(&vault.store, txn, &pack.as_bytes().to_vec(), &head)?;
    Ok(moved)
}

/// A layer row that reads its key's strictest value, unreadable ([`quarantine_in_txn`]).
fn unreadable_row(now: u64) -> StoredRow {
    StoredRow {
        value: EncodedValue(vec![UNREADABLE_VALUE]),
        by: None,
        setter: Setter::Pack,
        set_at: now,
        change: 0,
        weight_runs: None,
        local: None,
        seeded: false,
    }
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

/// Runs the `after_commit` of each key in `keys` once.
fn run_layer_after_commit(vault: &Vault, keys: &[String]) {
    for key in keys {
        if let Some(after_commit) = spec_named(key).ok().and_then(|spec| spec.after_commit) {
            after_commit(vault);
        }
    }
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
