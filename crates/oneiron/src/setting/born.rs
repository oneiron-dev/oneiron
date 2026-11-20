//! Keys whose things are born with a row (stage 7c-2; DESIGN 1.6, `born` under "The
//! project-depth carriers become two keys"). A `born` key says that each new thing of its
//! narrowest scope kind starts with a row copied from another key. That has two effects. The door
//! that creates the thing writes the row ([`write_born_rows_in_txn`]). And a thing with no row reads
//! the strictest value, never the wider one ([`missing_born_row`]): for such a key an absent row
//! means "not arrived", not "no bound".
//!
//! The row is a copy of the source key's value in force at the vault when the thing is created. A
//! copy of a pack's default is seeded (`StoredRow::seeded`), so a read it decides says
//! [`SettingSource::Seeded`]; a copy of a row someone set is explicit. The row is this install's: no
//! act names it yet, so another machine reads a born thing it did not create as strictest, pending,
//! until the birth's copy travels (stage 7c-3, with the pack head). Every creation door of a
//! project writes it, so a born key's narrowest kind is a project.

use oneiron_setting_contract::RowKey;

use super::read::{Loaded, StoredRow, chain_of, in_force_in_txn, table_of};
use super::{
    ScopeKind, Setter, SettingMode, SettingScope, SettingSource, SettingSpec, catalogue, spec_named,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The kind of thing a `born` key's rows are born at: its narrowest admitted scope kind. `None` for
/// a key with no `born`.
pub(super) fn born_kind(spec: &SettingSpec) -> Option<ScopeKind> {
    spec.born?;
    ScopeKind::NARROWEST_FIRST
        .into_iter()
        .find(|kind| spec.scopes.contains(kind))
}

/// Whether `slot` is a born thing's own value row: its empty slot gives the strictest value (DESIGN
/// 1.6, "What the empty slot gives").
pub(super) fn is_born_value_slot(spec: &SettingSpec, slot: &RowKey) -> bool {
    slot.mode == SettingMode::Value && born_kind(spec) == Some(slot.scope.kind())
}

/// The thing on `chain` whose row of the `born` key `spec` has not arrived: the chain's first scope
/// of the key's born kind (the reader's own thing; a project's own line comes before its parents)
/// when `loaded` holds neither a value row nor a pin there. A carried row does not stand in for it.
/// `None` for a key with no `born`, a chain with no such thing, or a thing that has its row.
pub(super) fn missing_born_row(
    spec: &SettingSpec,
    chain: &[SettingScope],
    loaded: &[Loaded],
) -> Option<SettingScope> {
    let kind = born_kind(spec)?;
    let at = chain.iter().position(|scope| scope.kind() == kind)?;
    let held = loaded.iter().any(|row| {
        row.found.at == at && matches!(row.found.mode, SettingMode::Value | SettingMode::Pin)
    });
    (!held).then(|| chain[at].clone())
}

/// Writes the birth row of every `born` key on the new `project`, in the write that creates it
/// (module doc): the source key's value in force at the vault, as the engine's row, seeded when the
/// source reads its default. A row already there stays (a thing is born once). A source that does
/// not read (an unreadable row, a value the born key does not decode) writes nothing, so the
/// project reads the strictest value, pending. The row is the thing's start, no move: like a pack's
/// first default it writes no change row. Returns how many rows it wrote.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn write_born_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    project: EntityId,
) -> Result<usize> {
    let mut written = 0;
    for spec in catalogue() {
        let Some(born) = spec.born else {
            continue;
        };
        if born_kind(spec) != Some(ScopeKind::Project) {
            continue;
        }
        let Ok(source) = spec_named(born.from) else {
            tracing::warn!(
                key = spec.name,
                from = born.from,
                "a born key's source is no catalogue key: the project reads strictest"
            );
            continue;
        };
        let table = table_of(spec);
        let key = RowKey {
            name: spec.name.to_owned(),
            item: None,
            mode: SettingMode::Value,
            scope: SettingScope::Project(project),
        }
        .encode();
        if table.get_bytes(&vault.store, txn, &key)?.is_some() {
            continue;
        }
        let chain = chain_of(source, &[])?;
        let (value, read, _) = in_force_in_txn(&vault.store, txn, source, &chain, None)?;
        if matches!(read, SettingSource::Unreadable(_)) || !spec.kind.decodes(&value) {
            continue;
        }
        let row = StoredRow {
            value,
            by: None,
            setter: Setter::Engine { ask: None },
            set_at: crate::ports::recorded_at_in_txn(&vault.store, txn)?,
            change: 0,
            weight_runs: None,
            local: None,
            seeded: matches!(read, SettingSource::Default | SettingSource::Seeded(_)),
        };
        table.put(&vault.store, txn, &key, &row)?;
        written += 1;
    }
    Ok(written)
}
