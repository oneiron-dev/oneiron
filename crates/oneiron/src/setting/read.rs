//! Reading a key: one walk for every key, and who may read what.

use serde::{Deserialize, Serialize};

use oneiron_setting_contract::{Decided, FoundRow, RowKey, decide};

use super::{
    EncodedValue, Kind, ReadBy, Resolved, Restore, ScopeKind, SetBy, Setter, Setting, SettingMode,
    SettingScope, SettingSource, SettingSpec, SettingValue,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
}

impl StoredRow {
    pub(super) const fn by_owner(&self) -> bool {
        matches!(self.setter, Setter::Owner)
    }
}

/// One row the walk found: where it sits, and its stored row when that decodes.
pub(super) struct Loaded {
    pub(super) scope: SettingScope,
    pub(super) found: FoundRow<EncodedValue>,
    pub(super) revision: u64,
}

/// The rows of `spec` on `chain` for `item`: at each scope its pin and its value row, the item's
/// and the item-less ones. A row that does not decode is kept, valueless and counted as the
/// owner's, so it decides as unreadable wherever it would have decided.
pub(super) fn load_in_txn(
    store: &Store,
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
            for mode in [SettingMode::Pin, SettingMode::Value] {
                let key = RowKey {
                    name: spec.name.to_owned(),
                    item: row_item.map(str::to_owned),
                    mode,
                    scope: scope.clone(),
                };
                let Some(bytes) = table.get_bytes(store, txn, &key.encode())? else {
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

/// The walk over loaded rows, with values decoded by `decode`.
pub(super) fn walk<V: Clone>(
    loaded: &[Loaded],
    chain: &[SettingScope],
    decode: impl Fn(&EncodedValue) -> Option<V>,
    tighter: Option<&dyn Fn(&V, &V) -> bool>,
) -> Walked<V> {
    let found: Vec<FoundRow<V>> = loaded
        .iter()
        .map(|row| FoundRow {
            at: row.found.at,
            item: row.found.item,
            mode: row.found.mode,
            by_owner: row.found.by_owner,
            value: row.found.value.as_ref().and_then(&decode),
        })
        .collect();
    let index_of = |decided: &FoundRow<V>| {
        found
            .iter()
            .position(|row| std::ptr::eq(row, decided))
            .unwrap_or_default()
    };
    match decide(&found, tighter) {
        Decided::Default => Walked::Default,
        Decided::Unreadable(at) => Walked::Unreadable(chain[at].clone()),
        Decided::Pin(row) | Decided::Row(row) => {
            let loaded = &loaded[index_of(row)];
            let source = match row.mode {
                SettingMode::Pin => SettingSource::Pin(loaded.scope.clone()),
                SettingMode::Value => SettingSource::Row(loaded.scope.clone()),
            };
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
    /// a family key. A missing row reads the catalogue default; an unreadable deciding row reads
    /// the key's strictest value.
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
        self.spec.check_item(item)?;
        let chain = SettingScope::chain(known, self.spec.scopes)?;
        let loaded = load_in_txn(&vault.store, txn, self.spec, &chain, item)?;
        let tighter = self.kind.tighter_typed();
        let tighter_ref = tighter.as_ref().map(|f| f as &dyn Fn(&T, &T) -> bool);
        Ok(
            match walk(&loaded, &chain, Kind::<T>::decode, tighter_ref) {
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
                    value: self.kind.default_typed(),
                    source: SettingSource::Default,
                    revision: 0,
                },
                Walked::Unreadable(scope) => Resolved {
                    value: self.kind.strictest_typed().ok_or(Error::CorruptedIndex(
                        "a setting row does not decode and its key names no strictest value",
                    ))?,
                    source: SettingSource::Unreadable(scope),
                    revision: 0,
                },
            },
        )
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
    let chain = SettingScope::chain(known, spec.scopes)?;
    let (value, source, revision) = in_force_in_txn(store, txn, spec, &chain, item)?;
    Ok(SettingView {
        key: spec.name.to_owned(),
        item: item.map(str::to_owned),
        value: spec.kind.to_json(&value).unwrap_or(serde_json::Value::Null),
        source,
        revision,
    })
}

/// The value in force for `spec` over `chain`, encoded, with the row that decided it.
pub(super) fn in_force_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    chain: &[SettingScope],
    item: Option<&str>,
) -> Result<(EncodedValue, SettingSource, u64)> {
    let loaded = load_in_txn(store, txn, spec, chain, item)?;
    let tighter = |a: &EncodedValue, b: &EncodedValue| spec.kind.is_tighter(a, b).unwrap_or(false);
    let tighter_ref = spec
        .kind
        .has_direction()
        .then_some(&tighter as &dyn Fn(&EncodedValue, &EncodedValue) -> bool);
    Ok(
        match walk(&loaded, chain, |value| Some(value.clone()), tighter_ref) {
            Walked::Row {
                value,
                source,
                revision,
            } => (value, source, revision),
            Walked::Default => (spec.kind.default_value()?, SettingSource::Default, 0),
            Walked::Unreadable(scope) => (
                spec.kind.strictest_value()?.ok_or(Error::CorruptedIndex(
                    "a setting row does not decode and its key names no strictest value",
                ))?,
                SettingSource::Unreadable(scope),
                0,
            ),
        },
    )
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
/// `engine.controls` class; the agent or person a row's scope names, for that row.
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
    Ok(scope.is_some_and(|scope| names_subject(scope, actor)))
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
    /// The catalogue default, as JSON.
    pub default: serde_json::Value,
    /// Who sets it without asking: `owner`, `subject`, or the `engine.controls` grant verb of
    /// its class.
    pub set_by: String,
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
                "reading `{key}` needs the owner, a holder of its class, or its subject"
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
                set_by: match spec.set_by {
                    SetBy::Owner => "owner".to_owned(),
                    SetBy::Subject => "subject".to_owned(),
                    SetBy::Class(class) => class.grant_verb().to_owned(),
                },
                act_class: spec.act.as_str().to_owned(),
                read_by: spec.read_by,
                restore: spec.restore,
                sync: spec.sync,
                scopes: ScopeKind::NARROWEST_FIRST
                    .into_iter()
                    .filter(|kind| spec.admits_scope(*kind))
                    .collect(),
                item: spec.item.map(|domain| domain.name.to_owned()),
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
