//! Keys whose things are born with a row (stage 7c-2; DESIGN 1.6, `born` under "The
//! project-depth carriers become two keys"). A `born` key says that each new thing of its
//! narrowest scope kind starts with a row copied from another key. That has two effects. The door
//! that creates the thing writes the row ([`write_born_rows_in_txn`]). And a thing with no row reads
//! the strictest value, never the wider one ([`missing_born_row`]): for such a key an absent row
//! means "not arrived", not "no bound".
//!
//! The row is a copy of the source key's value in force at the vault when the thing is created. A
//! copy of a pack's default is seeded (`StoredRow::seeded`), so a read it decides says
//! [`SettingSource::Seeded`]; a copy of a row someone set is explicit. Every creation door of a
//! project writes it, so a born key's narrowest kind is a project.
//!
//! The birth travels as one engine copy (stage 7c-3b; DESIGN 1.6, "A copy carries no value"): on
//! a vault with a root whose install can carry, the door also appends one `SettingCopy` whose rows
//! are the project's born rows, each naming the source key's heads (the live acts of its vault
//! value row, and the head act of each pack whose layer holds it). Every machine's fold checks
//! that the copy is the first act on its row and names the source's heads; every machine reads it
//! as the named acts read there ([`super::project`]). Without a root, or where nothing names a
//! default (no pack head act could be had), the row stays this install's, and another machine
//! reads the project strictest, pending.

use oneiron_authority::authority::{SettingCopyName, setting_slot_target};
use oneiron_setting_contract::RowKey;

use super::pack::{pack_head_act_in_txn, packs_holding_in_txn};
use super::project::{project_target_in_txn, rooted_in_txn};
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
/// not read (an unreadable row, a lost default, a value the born key does not decode) writes
/// nothing, so the project reads the strictest value, pending: the catalogue holds every born
/// key's source to a strictest value (`tests/setting_born_pending.rs`), so its read comes back
/// unreadable and never fails the creation. The row is the thing's start, no move: like a pack's
/// first default it writes no change row. On a vault with a root, the rows travel as one birth
/// copy appended in the same write ([`append_birth_in_txn`]). Every door that creates a project
/// on this install calls it: the project write door, a subproject, an owner's project, a card's
/// mint, a thread's conversion and the vault's root. Returns how many rows it wrote.
///
/// # Errors
///
/// Storage errors, and a corrupted index when a source key names no strictest value.
pub(crate) fn write_born_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    project: EntityId,
) -> Result<usize> {
    let mut written = Vec::new();
    let mut set_at = None;
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
        let at = match set_at {
            Some(at) => at,
            None => *set_at.insert(crate::ports::recorded_at_in_txn(&vault.store, txn)?),
        };
        let row = StoredRow {
            value,
            by: None,
            setter: Setter::Engine { ask: None },
            set_at: at,
            change: 0,
            weight_runs: None,
            local: None,
            seeded: matches!(read, SettingSource::Default | SettingSource::Seeded(_)),
        };
        table.put(&vault.store, txn, &key, &row)?;
        written.push((spec, source));
    }
    if let Some(at) = set_at {
        append_birth_in_txn(vault, txn, project, &written, at)?;
    }
    Ok(written.len())
}

/// Appends the birth of `project`'s rows `born` (each a born key with its source) as one engine
/// copy, and projects each row from the fold, in the creation's write `txn`, at `now` (stage
/// 7c-3b; module doc). A row names the live acts of its source's vault value row and the head act
/// of each pack whose layer holds the source ([`pack_head_act_in_txn`], which appends this
/// install's head where none of its table is live). A row with no pack head to name stays this
/// install's alone. Best effort, as a move's copy: without a root or a carrier nothing is
/// appended, and whatever stops the append is logged and rolled back alone, so a creation never
/// fails for its copy.
///
/// # Errors
///
/// Storage errors.
fn append_birth_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    project: EntityId,
    born: &[(&'static SettingSpec, &'static SettingSpec)],
    now: u64,
) -> Result<()> {
    if !rooted_in_txn(vault, txn)? || !vault.can_carry_owner_act_in_txn(txn)? {
        return Ok(());
    }
    let mut rows = Vec::with_capacity(born.len());
    for (spec, source) in born {
        let mut packs = Vec::new();
        for pack in packs_holding_in_txn(&vault.store, txn, source)? {
            if let Some(act) = pack_head_act_in_txn(vault, txn, &pack)? {
                packs.push(SettingCopyName {
                    slot: source_row(source, SettingScope::Pack(pack)),
                    act,
                });
            }
        }
        if packs.is_empty() {
            tracing::warn!(
                key = spec.name,
                "a born row names no pack head: it stands on this install alone"
            );
            continue;
        }
        let vault_row = source_row(source, SettingScope::Vault);
        let mut names: Vec<SettingCopyName> = vault
            .setting_slot_live_in_txn(txn, setting_slot_target(&vault_row)?)?
            .into_iter()
            .map(|act| SettingCopyName {
                slot: vault_row.clone(),
                act,
            })
            .collect();
        names.extend(packs);
        let slot = RowKey {
            name: spec.name.to_owned(),
            item: None,
            mode: SettingMode::Value,
            scope: SettingScope::Project(project),
        };
        rows.push((slot, names));
    }
    if rows.is_empty() {
        return Ok(());
    }
    let targets = rows
        .iter()
        .map(|(slot, _)| setting_slot_target(slot))
        .collect::<std::result::Result<Vec<EntityId>, _>>()?;
    if let Err(error) = vault.append_setting_copy_in_txn(txn, rows) {
        tracing::warn!(
            %error,
            "a project's born rows stand on this install alone: no copy of its birth was appended"
        );
        return Ok(());
    }
    for target in targets {
        project_target_in_txn(vault, txn, target, now)?;
    }
    Ok(())
}

/// The item-less value row of `source` at `scope`: a row a birth names.
fn source_row(source: &SettingSpec, scope: SettingScope) -> RowKey {
    RowKey {
        name: source.name.to_owned(),
        item: None,
        mode: SettingMode::Value,
        scope,
    }
}
