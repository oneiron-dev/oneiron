//! Reading a key: one walk for every key, and who may read what.

use serde::{Deserialize, Serialize};

use oneiron_setting_contract::{
    Decided, FitCell, FoundFit, FoundRow, Met, Order, Quorum, RowKey, decide, decide_met,
};

use super::learned::{LoadedFit, SettingFitView, fit_view, fits_in_txn};
use super::pack::{
    LayerDefault, ProposedDefaultView, layer_default_in_txn, proposed_defaults_in_txn,
};
use super::{
    EncodedValue, Kind, LearnedRange, ReadBy, Resolved, Restore, ScopeKind, SetBy, Setter, Setting,
    SettingMode, SettingScope, SettingSource, SettingSpec, SettingValue,
};
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::SubstrateRead;
use crate::side_table::{self, Named, SideTable, SideTableDbs};
use crate::store::Store;

/// The rows of keys kept live through a restore.
pub(super) const ROWS: SideTable<Vec<u8>, StoredRow, Named> = SideTable::new(&side_table::SETTING);
/// The rows of keys whose choice travels with the records.
pub(super) const CONTENT_ROWS: SideTable<Vec<u8>, StoredRow, Named> =
    SideTable::new(&side_table::SETTING_CONTENT);

/// The table a key's rows live in.
pub(super) const fn table_of(spec: &SettingSpec) -> SideTable<Vec<u8>, StoredRow, Named> {
    match spec.restore {
        Restore::Live => ROWS,
        Restore::Content => CONTENT_ROWS,
    }
}

/// One stored row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredRow {
    pub(super) value: EncodedValue,
    /// Who set it; `None` once an erase took that actor out.
    pub(super) by: Option<EntityId>,
    /// In which capacity.
    pub(super) setter: Setter,
    pub(super) set_at: u64,
    /// The sequence of the change that wrote it: the row's revision. It only grows, through a
    /// clear and a new write too, so a caller's `expected_revision` never matches a later row.
    pub(super) change: u64,
    /// A learned key's seed: its weight in runs (ARCH-0003 `#learning-settings`). Absent on every
    /// other row, whose bytes it leaves as they were.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) weight_runs: Option<f64>,
}

impl StoredRow {
    /// Whether the row is the owner's: set by the owner, or by the engine, which writes the
    /// owner's answer or its own path's choice. A holder or a subject asks before it replaces
    /// either, and a holder's value stays inside either.
    pub(super) const fn by_owner(&self) -> bool {
        matches!(self.setter, Setter::Owner | Setter::Engine { .. })
    }
}

/// One row the walk found: where it sits, and its stored row when that decodes.
#[derive(Clone)]
pub(super) struct Loaded {
    pub(super) scope: SettingScope,
    pub(super) found: FoundRow<EncodedValue>,
    pub(super) revision: u64,
}

/// The chain a read of `spec` walks from the places `known`: every project line the reader
/// names on a key whose rows meet ([`SettingScope::chain_of_lines`]), else one scope per kind
/// ([`SettingScope::chain`]): the walk of a key that reads one row is unchanged.
pub(super) fn chain_of(spec: &SettingSpec, known: &[SettingScope]) -> Result<Vec<SettingScope>> {
    if spec.reads_met() {
        SettingScope::chain_of_lines(known, spec.scopes)
    } else {
        SettingScope::chain(known, spec.scopes)
    }
}

/// The modes of the rows a read of `spec` loads at each scope: the pin and the value row, and on
/// a key whose rows meet the row a move carried. A key that reads one row has no carried row.
pub(super) fn modes_of(spec: &SettingSpec) -> &'static [SettingMode] {
    if spec.reads_met() {
        &[SettingMode::Pin, SettingMode::Value, SettingMode::Carried]
    } else {
        &[SettingMode::Pin, SettingMode::Value]
    }
}

/// The source a deciding row at `scope` names.
fn source_of(mode: SettingMode, scope: &SettingScope) -> SettingSource {
    match mode {
        SettingMode::Pin => SettingSource::Pin(scope.clone()),
        SettingMode::Value => SettingSource::Row(scope.clone()),
        SettingMode::Carried => SettingSource::Carried(scope.clone()),
    }
}

/// The rows of `spec` on `chain` for `item`: at each scope its pin and its value row (and its
/// carried row, [`modes_of`]), the item's and the item-less ones. A row that does not decode is
/// kept, valueless and counted as the owner's, so it decides as unreadable wherever it would have
/// decided.
pub(super) fn load_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    chain: &[SettingScope],
    item: Option<&str>,
) -> Result<Vec<Loaded>> {
    let table = table_of(spec);
    let items: Vec<Option<&str>> = match item {
        Some(_) => vec![item, None],
        None => vec![None],
    };
    let mut loaded = Vec::new();
    for (at, scope) in chain.iter().enumerate() {
        for row_item in &items {
            for &mode in modes_of(spec) {
                let key = RowKey {
                    name: spec.name.to_owned(),
                    item: row_item.map(str::to_owned),
                    mode,
                    scope: scope.clone(),
                };
                let Some(bytes) = table.get_bytes(dbs, txn, &key.encode())? else {
                    continue;
                };
                let row = rmp_serde::from_slice::<StoredRow>(&bytes).ok();
                let value = row
                    .as_ref()
                    .map(|row| row.value.clone())
                    .filter(|value| spec.kind.decodes(value));
                loaded.push(Loaded {
                    scope: scope.clone(),
                    found: FoundRow {
                        at,
                        item: row_item.is_some(),
                        mode,
                        by_owner: row.as_ref().is_none_or(StoredRow::by_owner),
                        value,
                    },
                    revision: row.map_or(0, |row| row.change),
                });
            }
        }
    }
    Ok(loaded)
}

/// What decided a read, before the default or the strictest value fills it in.
pub(super) enum Walked<V> {
    Row {
        value: V,
        source: SettingSource,
        revision: u64,
    },
    Default,
    Unreadable(SettingScope),
}

/// The rows `loaded`, with values decoded by `decode`.
fn decoded<V>(loaded: &[Loaded], decode: impl Fn(&EncodedValue) -> Option<V>) -> Vec<FoundRow<V>> {
    loaded
        .iter()
        .map(|row| FoundRow {
            at: row.found.at,
            item: row.found.item,
            mode: row.found.mode,
            by_owner: row.found.by_owner,
            value: row.found.value.as_ref().and_then(&decode),
        })
        .collect()
}

/// The read of a key whose order has a meet ([`decide_met`]), over loaded rows on `chain`, with
/// values decoded by `decode`. The source is the narrowest row that holds the result; the
/// default when no row took part or the result is the default; else [`SettingSource::Met`].
pub(super) fn walk_met<V: Clone + PartialEq>(
    loaded: &[Loaded],
    chain: &[SettingScope],
    decode: impl Fn(&EncodedValue) -> Option<V>,
    meet: &dyn Fn(&V, &V) -> V,
    default: &V,
) -> Walked<V> {
    let found = decoded(loaded, decode);
    match decide_met(&found, chain.len().saturating_sub(1), meet, default) {
        Met::Unreadable(at) => Walked::Unreadable(chain[at].clone()),
        Met::Value { value, by, rows } => match by {
            Some(by) => {
                let index = found
                    .iter()
                    .position(|row| std::ptr::eq(row, by))
                    .unwrap_or_default();
                let loaded = &loaded[index];
                Walked::Row {
                    value,
                    source: source_of(by.mode, &loaded.scope),
                    revision: loaded.revision,
                }
            }
            None if rows == 0 || value == *default => Walked::Default,
            None => Walked::Row {
                value,
                source: SettingSource::Met,
                revision: 0,
            },
        },
    }
}

/// The walk of a key that reads one row, over loaded rows and a learned key's fits, with values
/// decoded by `decode`; `default` is the default layer's value, and with `no_wider` (a learned
/// key's comparator) a holder's cap where the owner set no row.
pub(super) fn walk<V: Clone>(
    loaded: &[Loaded],
    fits: &[LoadedFit],
    chain: &[SettingScope],
    decode: impl Fn(&EncodedValue) -> Option<V>,
    no_wider: Option<&dyn Fn(&V, &V) -> bool>,
    default: &V,
) -> Walked<V> {
    let found = decoded(loaded, &decode);
    // A fit that does not decode as the key's type is passed over: it is no row of the key.
    let (found_fits, fit_cells): (Vec<FoundFit<V>>, Vec<&FitCell>) = fits
        .iter()
        .filter_map(|fit| {
            let value = decode(&fit.found.value)?;
            Some((
                FoundFit {
                    at: fit.found.at,
                    value,
                },
                &fit.cell,
            ))
        })
        .unzip();
    let index_of = |decided: &FoundRow<V>| {
        found
            .iter()
            .position(|row| std::ptr::eq(row, decided))
            .unwrap_or_default()
    };
    match decide(&found, &found_fits, no_wider, Some(default)) {
        Decided::Default => Walked::Default,
        Decided::Fit(fit) => {
            let index = found_fits
                .iter()
                .position(|found| std::ptr::eq(found, fit))
                .unwrap_or_default();
            Walked::Row {
                value: fit.value.clone(),
                source: SettingSource::Fit(fit_cells[index].clone()),
                revision: 0,
            }
        }
        Decided::Unreadable(at) => Walked::Unreadable(chain[at].clone()),
        Decided::Pin(row) | Decided::Row(row) => {
            let loaded = &loaded[index_of(row)];
            let source = source_of(row.mode, &loaded.scope);
            match &row.value {
                Some(value) => Walked::Row {
                    value: value.clone(),
                    source,
                    revision: loaded.revision,
                },
                None => Walked::Unreadable(loaded.scope.clone()),
            }
        }
    }
}

impl<T: SettingValue> Setting<T> {
    /// The value in force for this key in `txn`, where the reader knows the places `known`
    /// (narrowest first or in any order; never the vault, which is always last), for `item` of
    /// a family key. With no deciding row it reads the default the vault accepted (the default
    /// layer); an unreadable deciding row, or a lost accepted default, reads the key's strictest
    /// value.
    ///
    /// # Errors
    ///
    /// A place or item the key does not admit; an unreadable deciding row on a key that names no
    /// strictest value (`CorruptedIndex`); storage errors.
    pub fn read_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        known: &[SettingScope],
        item: Option<&str>,
    ) -> Result<Resolved<T>> {
        self.read_in_dbs_txn(&vault.store, txn, known, item)
    }

    /// [`Self::read_in_txn`] below the vault: the same walk over the setting tables of `dbs`
    /// (a store, or any other holder of its side databases), for a reader that holds no
    /// [`Vault`].
    ///
    /// # Errors
    ///
    /// As [`Self::read_in_txn`].
    pub(crate) fn read_in_dbs_txn(
        &self,
        dbs: &impl SideTableDbs,
        txn: &heed::RoTxn<'_>,
        known: &[SettingScope],
        item: Option<&str>,
    ) -> Result<Resolved<T>> {
        self.spec.check_item(item)?;
        let chain = chain_of(self.spec, known)?;
        let loaded = load_in_txn(dbs, txn, self.spec, &chain, item)?;
        let layer = layer_default_in_txn(dbs, txn, self.spec)?;
        let default = Kind::<T>::decode(&layer.value).unwrap_or_else(|| self.kind.default_typed());
        let walked = match self.kind.meet_typed().filter(|_| self.spec.reads_met()) {
            Some(meet) => walk_met(&loaded, &chain, Kind::<T>::decode, &meet, &default),
            None => {
                let fits = fits_in_txn(dbs, txn, self.spec, &chain)?;
                let cap = self
                    .kind
                    .no_wider_typed()
                    .filter(|_| self.spec.is_learned());
                let cap_ref = cap.as_ref().map(|f| f as &dyn Fn(&T, &T) -> bool);
                walk(&loaded, &fits, &chain, Kind::<T>::decode, cap_ref, &default)
            }
        };
        Ok(match walked {
            Walked::Row {
                value,
                source,
                revision,
            } => Resolved {
                value,
                source,
                revision,
            },
            Walked::Default => Resolved {
                value: default,
                source: layer
                    .lost
                    .map_or(SettingSource::Default, SettingSource::Unreadable),
                revision: 0,
            },
            Walked::Unreadable(scope) => Resolved {
                value: self.kind.strictest_typed().ok_or(Error::CorruptedIndex(
                    "a setting row does not decode and its key names no strictest value",
                ))?,
                source: SettingSource::Unreadable(scope),
                revision: 0,
            },
        })
    }
}

/// What one call asked of a key, met with the value in force (DESIGN 1.5 "The read", step 3).
/// Nothing is stored.
#[derive(Debug, Clone, PartialEq)]
pub struct Requested<T> {
    /// The value the call runs under: the meet of the value in force and the ask.
    pub value: T,
    /// Whether the ask was wider than the value in force, and was clamped to it.
    pub clamped: bool,
    /// The value in force the ask was met with, and the row that decided it.
    pub in_force: Resolved<T>,
}

impl<T: SettingValue> Setting<T> {
    /// `ask`, one call's request, met with `in_force`, the value [`Self::read_in_txn`] read: an
    /// over-ask is clamped, and says so; an ask no wider than the value in force runs as asked.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for a key whose order has no meet: a request never reaches it.
    pub fn narrowed(&self, in_force: Resolved<T>, ask: &T) -> Result<Requested<T>> {
        let meet = self.kind.meet_typed().ok_or_else(|| {
            Error::InvalidConfig(format!(
                "`{}` has no order with a meet: a request cannot narrow it",
                self.spec.name
            ))
        })?;
        let value = meet(&in_force.value, ask);
        Ok(Requested {
            clamped: value != *ask,
            value,
            in_force,
        })
    }
}

/// A key's value in force, as the verbs show it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettingView {
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    /// The value in force, as JSON.
    pub value: serde_json::Value,
    /// Which row decided it.
    pub source: SettingSource,
    /// The deciding row's revision; 0 when no row decided.
    pub revision: u64,
    /// A learned key's narrowest fit on the read's chain, also when a row or a pin decides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fit: Option<SettingFitView>,
}

/// One stored row, as the verbs show it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettingRowView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    pub mode: SettingMode,
    pub scope: SettingScope,
    /// The stored value as JSON; null when it does not decode.
    pub value: serde_json::Value,
    pub revision: u64,
    /// Who set it, 32 hex, while the record names them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    pub setter: Setter,
    pub set_at: u64,
    /// A learned key's seed: its weight in runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight_runs: Option<f64>,
}

/// The value in force for `spec` in `txn`, as JSON.
pub(super) fn view_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    known: &[SettingScope],
    item: Option<&str>,
) -> Result<SettingView> {
    spec.check_item(item)?;
    let chain = chain_of(spec, known)?;
    let (value, source, revision) = in_force_in_txn(store, txn, spec, &chain, item)?;
    Ok(SettingView {
        key: spec.name.to_owned(),
        item: item.map(str::to_owned),
        value: spec.kind.to_json(&value).unwrap_or(serde_json::Value::Null),
        source,
        revision,
        fit: fit_view(spec, &fits_in_txn(store, txn, spec, &chain)?),
    })
}

/// The value in force for `spec` over `chain`, encoded, with the row that decided it.
pub(super) fn in_force_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    chain: &[SettingScope],
    item: Option<&str>,
) -> Result<(EncodedValue, SettingSource, u64)> {
    let loaded = load_in_txn(dbs, txn, spec, chain, item)?;
    let fits = fits_in_txn(dbs, txn, spec, chain)?;
    let layer = layer_default_in_txn(dbs, txn, spec)?;
    in_force_of(spec, &loaded, &fits, chain, &layer)
}

/// The value in force for `spec` over `chain`, from rows already loaded and the default layer's
/// answer `layer`: [`in_force_in_txn`]'s walk, for a caller that weighs the rows as a change
/// would leave them.
pub(super) fn in_force_of(
    spec: &SettingSpec,
    loaded: &[Loaded],
    fits: &[LoadedFit],
    chain: &[SettingScope],
    layer: &LayerDefault,
) -> Result<(EncodedValue, SettingSource, u64)> {
    let default = layer.value.clone();
    let meet =
        |a: &EncodedValue, b: &EncodedValue| spec.kind.meet(a, b).unwrap_or_else(|| a.clone());
    let cap = |a: &EncodedValue, b: &EncodedValue| spec.kind.no_wider(a, b).unwrap_or(false);
    let cap_ref = (spec.is_learned() && spec.kind.order() != Order::None)
        .then_some(&cap as &dyn Fn(&EncodedValue, &EncodedValue) -> bool);
    let walked = if spec.reads_met() {
        walk_met(loaded, chain, |value| Some(value.clone()), &meet, &default)
    } else {
        walk(
            loaded,
            fits,
            chain,
            |value| Some(value.clone()),
            cap_ref,
            &default,
        )
    };
    Ok(match walked {
        Walked::Row {
            value,
            source,
            revision,
        } => (value, source, revision),
        Walked::Default => (
            default,
            layer
                .lost
                .clone()
                .map_or(SettingSource::Default, SettingSource::Unreadable),
            0,
        ),
        Walked::Unreadable(scope) => (
            spec.kind.strictest_value()?.ok_or(Error::CorruptedIndex(
                "a setting row does not decode and its key names no strictest value",
            ))?,
            SettingSource::Unreadable(scope),
            0,
        ),
    })
}

/// Every stored row of `spec`, in key order.
pub(super) fn rows_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
) -> Result<Vec<SettingRowView>> {
    let mut rows = Vec::new();
    for row in table_of(spec).iter_raw_from(store, txn, &RowKey::name_prefix(spec.name))? {
        let (key, bytes) = row?;
        let Some(key) = RowKey::decode(&key) else {
            continue;
        };
        // A pack's row is the default layer: the entry's `accepted_default`, not a stored choice.
        if key.scope.kind() == ScopeKind::Pack {
            continue;
        }
        let stored = rmp_serde::from_slice::<StoredRow>(&bytes).ok();
        rows.push(SettingRowView {
            item: key.item,
            mode: key.mode,
            scope: key.scope,
            value: stored
                .as_ref()
                .and_then(|row| spec.kind.to_json(&row.value))
                .unwrap_or(serde_json::Value::Null),
            revision: stored.as_ref().map_or(0, |row| row.change),
            by: stored.as_ref().and_then(|row| row.by).map(|by| by.to_hex()),
            setter: stored.as_ref().map_or(Setter::Owner, |row| row.setter),
            set_at: stored.as_ref().map_or(0, |row| row.set_at),
            weight_runs: stored.as_ref().and_then(|row| row.weight_runs),
        });
    }
    Ok(rows)
}

/// Who reads: the owner (already proved), or an actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettingReader {
    Owner,
    Actor(EntityId),
}

/// Whether `reader` may read `spec`'s rows at `scope` (all its rows when `None`), in `txn`: the
/// owner always; a member of the vault for a key read by members; a live holder of the key's
/// `engine.controls` class; for a dials key, a live whole-vault Steward grant naming any
/// `engine.controls` class; an agent whose live owner Grant lists the key's read line
/// ([`super::get_line`]), vault-wide; the agent or person a row's scope names, for that row.
pub(crate) fn reader_reads_key_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reader: SettingReader,
    spec: &SettingSpec,
    scope: Option<&SettingScope>,
) -> Result<bool> {
    let actor = match reader {
        SettingReader::Owner => return Ok(true),
        SettingReader::Actor(actor) => actor,
    };
    if spec.read_by == ReadBy::Members {
        return Ok(true);
    }
    if let SetBy::Class(class) = spec.set_by
        && vault.engine_controls_grant_in(txn, actor, class)?.is_some()
    {
        return Ok(true);
    }
    if spec.read_by == ReadBy::Dials
        && vault.substrate_read_granted_in_txn(txn, actor, SubstrateRead::Dials)?
    {
        return Ok(true);
    }
    if scope.is_some_and(|scope| names_subject(scope, actor)) {
        return Ok(true);
    }
    Ok(key_line_grant_in_txn(vault, txn, actor, &super::get_line(spec.name))?.is_some())
}

/// The live owner Grant through which `agent` holds the per-key line `line`
/// ([`super::set_line`], [`super::get_line`]), vault-wide: the rule of the vault-wide review
/// policy doors (FIX 8268), which takes any verb. The shipped principal rule for an agent, then
/// the first live Grant in id order that alone stands for the agent and lists `line` exactly,
/// stands under this vault's own rule and carries no repo bounds. Grants are never unioned, and
/// a Grant over every verb lists no line.
///
/// # Errors
///
/// A store, fold or clock failure; never a refusal.
pub(super) fn key_line_grant_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    line: &str,
) -> Result<Option<EntityId>> {
    Ok(vault
        .admit_queue_review_policy_in_txn(txn, agent, EdgeActorClass::Agent, line)?
        .ok())
}

/// Whether `scope` is `actor`'s own: an agent's or a person's row about them.
pub(super) fn names_subject(scope: &SettingScope, actor: EntityId) -> bool {
    matches!(scope.kind(), ScopeKind::Agent | ScopeKind::Person) && scope.entity() == Some(actor)
}

/// One catalogue key as `vault.settings.list` shows it: the row, its schema and default, the
/// value in force, and the stored rows the reader may read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettingCatalogueEntry {
    pub key: String,
    /// What the key chooses.
    pub doc: String,
    /// The value's JSON Schema.
    pub schema: serde_json::Value,
    /// The build's default, as JSON: what the `engine` pack proposes for the key.
    pub default: serde_json::Value,
    /// The default the vault accepted (the default layer, DESIGN 1.5), as JSON: what a read with
    /// no deciding row starts from. `null` when the accepted row is lost: the key then reads
    /// strictest.
    pub accepted_default: serde_json::Value,
    /// A pack's default for the key that waits on the owner's yes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_default: Option<ProposedDefaultView>,
    /// Who sets it without asking: `owner`, `subject`, or the `engine.controls` grant verb of
    /// its class.
    pub set_by: String,
    /// The key's order: which side of a change is safe.
    pub order: Order,
    /// How many holders must say yes to a loose move.
    pub quorum: Quorum,
    /// The check-in act class of a change.
    pub act_class: String,
    pub read_by: ReadBy,
    pub restore: super::Restore,
    pub sync: super::SettingSync,
    /// The kinds of scope its rows may sit at.
    pub scopes: Vec<ScopeKind>,
    /// For a family key, what its items name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    /// For a learned key, the range its rows and its fits stay in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub learned: Option<LearnedRange>,
    /// The value in force at the vault (or at the places the request named), when the reader
    /// reads the whole key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<SettingView>,
    pub rows: Vec<SettingRowView>,
}

/// What `vault.settings.list` narrows to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SettingListFilter {
    /// Keys whose name starts with it.
    pub(crate) prefix: Option<String>,
    /// Keys a holder of this `engine.controls` class sets.
    pub(crate) class: Option<crate::federation::EngineControlClass>,
    /// The places the value in force is read at.
    pub(crate) at: Vec<SettingScope>,
}

impl Vault {
    /// The value in force for `key` (and `item`) at the places `at`, when `reader` may read it.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for an unknown key, a place or item it does not admit, or a reader who may
    /// not read it; storage errors.
    pub(crate) fn setting_view_for(
        &self,
        reader: SettingReader,
        key: &str,
        item: Option<&str>,
        at: &[SettingScope],
    ) -> Result<SettingView> {
        let spec = super::spec_named(key)?;
        let txn = self.store.env.read_txn()?;
        let own = match reader {
            SettingReader::Owner => None,
            SettingReader::Actor(actor) => at.iter().find(|scope| names_subject(scope, actor)),
        };
        if !reader_reads_key_in_txn(self, &txn, reader, spec, own)? {
            return Err(Error::InvalidConfig(format!(
                "reading `{key}` needs the owner, a holder of its class, its Grant line, or its \
                 subject"
            )));
        }
        view_in_txn(&self.store, &txn, spec, at, item)
    }

    /// Every catalogue key `filter` takes that `reader` may read, wholly or for its own rows.
    ///
    /// # Errors
    ///
    /// A place no key admits only skips that key's value; storage errors.
    pub(crate) fn setting_catalogue_for(
        &self,
        reader: SettingReader,
        filter: &SettingListFilter,
    ) -> Result<Vec<SettingCatalogueEntry>> {
        let txn = self.store.env.read_txn()?;
        let mut proposed = proposed_defaults_in_txn(&self.store, &txn)?;
        let mut entries = Vec::new();
        for spec in super::catalogue() {
            if filter
                .prefix
                .as_deref()
                .is_some_and(|prefix| !spec.name.starts_with(prefix))
                || filter
                    .class
                    .is_some_and(|class| spec.set_by != SetBy::Class(class))
            {
                continue;
            }
            let whole = reader_reads_key_in_txn(self, &txn, reader, spec, None)?;
            let mut rows = rows_in_txn(&self.store, &txn, spec)?;
            if let SettingReader::Actor(actor) = reader
                && !whole
            {
                rows.retain(|row| names_subject(&row.scope, actor));
                if rows.is_empty() {
                    continue;
                }
            }
            let value = if whole {
                let at: Vec<SettingScope> = filter
                    .at
                    .iter()
                    .filter(|scope| spec.admits_scope(scope.kind()))
                    .cloned()
                    .collect();
                Some(view_in_txn(&self.store, &txn, spec, &at, None)?)
            } else {
                None
            };
            // A lost accepted default (or one whose key names no strictest value) shows null.
            let accepted_default = layer_default_in_txn(&self.store, &txn, spec)
                .ok()
                .filter(|layer| layer.lost.is_none())
                .and_then(|layer| spec.kind.to_json(&layer.value))
                .unwrap_or(serde_json::Value::Null);
            let proposed_default = proposed
                .iter()
                .position(|(key, _)| key == spec.name)
                .map(|at| proposed.swap_remove(at).1);
            entries.push(SettingCatalogueEntry {
                key: spec.name.to_owned(),
                doc: spec.doc.trim().to_owned(),
                schema: spec.kind.schema(),
                default: spec
                    .kind
                    .default_value()
                    .ok()
                    .and_then(|value| spec.kind.to_json(&value))
                    .unwrap_or(serde_json::Value::Null),
                accepted_default,
                proposed_default,
                set_by: match spec.set_by {
                    SetBy::Owner => "owner".to_owned(),
                    SetBy::Subject => "subject".to_owned(),
                    SetBy::Class(class) => class.grant_verb().to_owned(),
                },
                order: spec.kind.order(),
                quorum: spec.quorum,
                act_class: spec.act.as_str().to_owned(),
                read_by: spec.read_by,
                restore: spec.restore,
                sync: spec.sync,
                scopes: ScopeKind::NARROWEST_FIRST
                    .into_iter()
                    .filter(|kind| spec.admits_scope(*kind))
                    .collect(),
                item: spec.item.map(|domain| domain.name.to_owned()),
                learned: spec.kind.learned_range(),
                value,
                rows,
            });
        }
        Ok(entries)
    }
}

/// Writes `bytes` as the stored row of `name`'s `mode` row at `scope`, as a damaged store would
/// hold it. A test door's write.
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) fn put_stored_bytes(
    vault: &Vault,
    name: &str,
    mode: SettingMode,
    scope: SettingScope,
    bytes: &[u8],
) -> Result<()> {
    let spec = super::spec_named(name)?;
    let key = RowKey {
        name: spec.name.to_owned(),
        item: None,
        mode,
        scope,
    };
    let mut txn = vault.store.env.write_txn()?;
    table_of(spec).put_undecodable(&vault.store, &mut txn, &key.encode(), bytes)?;
    txn.commit()?;
    Ok(())
}
