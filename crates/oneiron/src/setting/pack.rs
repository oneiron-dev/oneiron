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

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use oneiron_setting_contract::{ChangeDirection, Order, RowKey};

use super::change::record_change_in_txn;
use super::read::{StoredRow, table_of};
use super::{
    EncodedValue, ScopeKind, Setter, SettingChange, SettingMode, SettingScope, SettingSpec,
    catalogue, spec_named,
};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable, SideTableDbs};

/// The pack whose layer is this build's catalogue: every key.
pub const ENGINE_PACK: &str = "engine";

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
    /// Keys whose default moved, tighter or on a key that guards nothing.
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
fn fold_layer(spec: &SettingSpec, rows: &[(String, EncodedValue)]) -> Option<EncodedValue> {
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

/// The digest of `pack`'s defaults: the pack's name, then each key's name and default's bytes,
/// in name order, each length-prefixed.
fn defaults_digest(pack: &str, defaults: &[(&'static SettingSpec, EncodedValue)]) -> String {
    let mut sorted: Vec<&(&'static SettingSpec, EncodedValue)> = defaults.iter().collect();
    sorted.sort_by_key(|(spec, _)| spec.name);
    let mut hasher = blake3::Hasher::new_derive_key("oneiron setting pack defaults v1");
    hasher
        .update(&(pack.len() as u64).to_be_bytes())
        .update(pack.as_bytes());
    for (spec, value) in sorted {
        hasher
            .update(&(spec.name.len() as u64).to_be_bytes())
            .update(spec.name.as_bytes())
            .update(&(value.0.len() as u64).to_be_bytes())
            .update(&value.0);
    }
    hasher.finalize().to_hex().to_string()
}

/// The digest of a stored layer row's bytes: what a proposal names as the row it replaces.
fn row_digest(bytes: &[u8]) -> String {
    blake3::Hasher::new_derive_key("oneiron setting pack row v1")
        .update(bytes)
        .finalize()
        .to_hex()
        .to_string()
}

/// The digest of a proposal: the pack, the defaults digest it was made under, and each waiting
/// default with the row it replaces.
fn proposal_digest(pack: &str, digest: &str, defaults: &[ProposedDefault]) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron setting pack proposal v1");
    hasher
        .update(&(pack.len() as u64).to_be_bytes())
        .update(pack.as_bytes())
        .update(digest.as_bytes());
    for proposed in defaults {
        hasher
            .update(&(proposed.key.len() as u64).to_be_bytes())
            .update(proposed.key.as_bytes())
            .update(&(proposed.value.0.len() as u64).to_be_bytes())
            .update(&proposed.value.0);
        match &proposed.replaced {
            None => hasher.update(&[0]),
            Some(replaced) => hasher.update(&[1]).update(replaced.as_bytes()),
        };
    }
    hasher.finalize().to_hex().to_string()
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

/// The pack door: weighs `pack`'s `defaults` against what the vault accepted from it, in the
/// caller's write. `layer` lists the keys the pack's install named; `None` is every key (the
/// `engine` pack). A default outside the layer is a proposal, tighter or not. Answers `None` when
/// the head's digest is the defaults' own: the door then writes nothing.
///
/// # Errors
///
/// `InvalidConfig` for an empty pack name; a key's `on_change` refusal; storage errors.
pub(crate) fn apply_pack_defaults_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    pack: &str,
    defaults: &[(&'static SettingSpec, EncodedValue)],
    layer: Option<&[&str]>,
) -> Result<Option<PackApplied>> {
    if pack.is_empty() {
        return Err(Error::InvalidConfig("a pack has a name".into()));
    }
    let digest = defaults_digest(pack, defaults);
    let head = head_in_txn(&vault.store, txn, pack)?.unwrap_or_default();
    if head.digest == digest {
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
        },
    )?;
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
}

/// Writes `spec`'s row in `pack`'s layer, with its change row and the key's `on_change`.
fn write_layer_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    spec: &'static SettingSpec,
    pack: &str,
    write: LayerWrite<'_>,
) -> Result<()> {
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
            signed: None,
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
    };
    table_of(spec).put(&vault.store, txn, &pack_row_key(spec.name, pack), &row)?;
    if let Some(on_change) = spec.on_change {
        on_change(vault, txn, &recorded)?;
    }
    Ok(())
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
            let digest = defaults_digest(ENGINE_PACK, &defaults);
            if head_in_txn(&self.store, &txn, ENGINE_PACK)?
                .is_some_and(|head| head.digest == digest)
            {
                return Ok(None);
            }
        }
        self.apply_pack_defaults(ENGINE_PACK, &defaults, None)
    }

    /// [`apply_pack_defaults_in_txn`] in its own write, then each moved key's `after_commit`.
    ///
    /// # Errors
    ///
    /// As [`apply_pack_defaults_in_txn`].
    pub(crate) fn apply_pack_defaults(
        &self,
        pack: &str,
        defaults: &[(&'static SettingSpec, EncodedValue)],
        layer: Option<&[&str]>,
    ) -> Result<Option<PackApplied>> {
        self.with_write_txn_grouped_after_commit(
            |txn| apply_pack_defaults_in_txn(self, txn, pack, defaults, layer),
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
    /// pack door proposes again. Answers the keys whose default landed.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for a pack with no head, a proposal that is not the pack's waiting one, a
    /// row that moved since, or a key this build does not know; an owner proof that no longer
    /// holds; a key's `on_change` refusal; storage errors.
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
            .and_then(|bytes| rmp_serde::from_slice::<StoredRow>(bytes).ok())
            .map(|row| row.value);
        checked.push((spec, prior));
    }
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let mut accepted: BTreeSet<String> = head.accepted.iter().cloned().collect();
    let mut keys = Vec::with_capacity(checked.len());
    for (proposed, (spec, prior)) in waiting.defaults.iter().zip(checked) {
        write_layer_row_in_txn(
            vault,
            txn,
            spec,
            pack,
            LayerWrite {
                value: &proposed.value,
                prior,
                by: Some(by),
                direction: proposed.direction,
                why: format!(
                    "the owner accepted proposal {} of pack `{pack}`",
                    &proposal[..proposal.len().min(16)]
                ),
                at: now,
            },
        )?;
        accepted.insert(proposed.key.clone());
        keys.push(proposed.key.clone());
    }
    head.accepted = accepted.into_iter().collect();
    HEADS.put(&vault.store, txn, &pack.as_bytes().to_vec(), &head)?;
    Ok(keys)
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
