//! The owner's rows no act backs travel as one batch act per owner (stage 7a-3; DESIGN 1.6
//! "What travels", a vault with no authority root).
//!
//! A vault with no authority root is one machine, and its owner's changes write their rows alone
//! (stage 7a-2). The setting rows are local to each install, so a row the owner set before the
//! vault was rooted would never reach a later machine. Once the vault is rooted and this install
//! can carry the owner's act, the publish pass signs those rows as one batch act per owner
//! ([`Vault::publish_settings`]): every row of a key that travels ([`super::project::travels`])
//! that the owner set, on a slot no act names yet. Each row's change row then names the act, as
//! the door's own do, and a machine that takes the log writes the rows from it.
//!
//! The pass leaves every other row on this install: a person's, an agent's or the engine's change
//! (RULING SETTING-7A-2-DECIDERS = A), a pack's default, a key that stays on its install, a
//! learned key, a carried row, a value longer than an act carries, a value this build cannot
//! decode, and a slot an act already names, whose acts decide it. Each row names `seen` zero (no
//! act names its slot) and the prior value `null`, as the door does for a slot with no row.
//!
//! It runs once per vault. It records that it ran ([`super::tables::SETTING_PUBLISHED`]) in the
//! write where it published, or found nothing to publish, and only when the vault is rooted and
//! this install can carry. Until then it does nothing, and the next pass tries again. From then
//! on the door appends an act for every owner's change of a row that travels, or refuses the
//! change. It runs first in every projection pass ([`Vault::project_settings`]): at open, and
//! after every commit that stored an authority row.

use std::collections::BTreeMap;

use oneiron_authority::authority::{
    ActSurface, POLICY_SETTING_INLINE_MAX, setting_slot_target, setting_value_digest,
};
use oneiron_setting_contract::{RowKey, ScopeKind, SettingMode};

use super::change::{change_in_txn, record_signed_entry_in_txn};
use super::project::{json_bytes, rooted_in_txn, travels};
use super::read::{StoredRow, table_of};
use super::{Setter, SettingChange, SettingSpec, SettingSync, catalogue};
use crate::Vault;
use crate::authority::{SettingSlotAct, SettingSlotRow};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::side_table::{self, Named, SideTable};

/// When the publish pass ran, in recorded seconds; absent until it ran.
const PUBLISHED: SideTable<(), u64, Named> = SideTable::new(&side_table::SETTING_PUBLISHED);

/// What a publish pass did ([`Vault::publish_settings`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SettingsPublished {
    /// Batch acts appended: one per owner whose rows it published.
    pub acts: usize,
    /// The rows those acts name.
    pub rows: usize,
}

/// One row the pass publishes.
struct Unbacked {
    row: SettingSlotRow,
    /// The change that wrote the row, while it stands: it then names the act.
    change: Option<SettingChange>,
}

impl Vault {
    /// Publishes, in its own write, the owner's rows that travel and that no act backs, as one
    /// batch act per owner (module doc). `None` when the pass ran before, or cannot run yet: no
    /// authority root, or no live profile of this install to carry the acts.
    ///
    /// # Errors
    ///
    /// Storage errors, and an append that failed for another reason than a typed refusal: the
    /// write is rolled back, and the next pass tries again.
    pub fn publish_settings(&self) -> Result<Option<SettingsPublished>> {
        {
            let txn = self.store.env.read_txn()?;
            if !publish_due_in_txn(self, &txn)? {
                return Ok(None);
            }
        }
        self.with_write_txn_grouped(|txn| publish_settings_in_txn(self, txn))
    }
}

/// Whether the pass is owed and can run in `txn`: it never ran, the vault is rooted, and this
/// install can carry an owner's act.
fn publish_due_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(PUBLISHED.get(&vault.store, txn, &())?.is_none()
        && rooted_in_txn(vault, txn)?
        && vault.can_carry_owner_act_in_txn(txn)?)
}

fn publish_settings_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
) -> Result<Option<SettingsPublished>> {
    if !publish_due_in_txn(vault, txn)? {
        return Ok(None);
    }
    let mut by_owner: BTreeMap<EntityId, Vec<Unbacked>> = BTreeMap::new();
    for spec in catalogue() {
        if spec.sync != SettingSync::Vault {
            continue;
        }
        for (owner, unbacked) in unbacked_rows_in_txn(vault, txn, spec)? {
            by_owner.entry(owner).or_default().push(unbacked);
        }
    }
    let mut published = SettingsPublished::default();
    for (owner, rows) in by_owner {
        let count = rows.len();
        if publish_owner_rows_in_txn(vault, txn, owner, rows)? {
            published.acts += 1;
            published.rows += count;
        }
    }
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    PUBLISHED.put(&vault.store, txn, &(), &now)?;
    Ok(Some(published))
}

/// The rows of `spec` the pass publishes (module doc), each with the owner who set it.
fn unbacked_rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &'static SettingSpec,
) -> Result<Vec<(EntityId, Unbacked)>> {
    let mut rows = Vec::new();
    for row in table_of(spec).iter_raw_from(&vault.store, txn, &RowKey::name_prefix(spec.name))? {
        let (key, bytes) = row?;
        let Some(slot) = RowKey::decode(&key) else {
            continue;
        };
        // A carried row is the engine's: a move's copy carries it (stage 7a-4).
        if slot.name != spec.name
            || !travels(spec)
            || slot.mode == SettingMode::Carried
            || slot.scope.kind() == ScopeKind::Pack
            || !spec.admits_scope(slot.scope.kind())
            || spec.check_item(slot.item.as_deref()).is_err()
        {
            continue;
        }
        let Ok(stored) = rmp_serde::from_slice::<StoredRow>(&bytes) else {
            continue;
        };
        let (Setter::Owner, Some(owner)) = (stored.setter, stored.by) else {
            continue;
        };
        if !spec.kind.decodes(&stored.value) {
            continue;
        }
        let inline = json_bytes(spec, &stored.value)?;
        if inline.len() > POLICY_SETTING_INLINE_MAX
            || vault.policy_setting_revision_in_txn(txn, setting_slot_target(&slot)?)? != [0; 32]
        {
            continue;
        }
        let change = change_in_txn(&vault.store, txn, stored.change)?;
        rows.push((
            owner,
            Unbacked {
                row: SettingSlotRow {
                    slot,
                    prior: setting_value_digest(b"null"),
                    inline: Some(inline),
                },
                change,
            },
        ));
    }
    Ok(rows)
}

/// Signs `rows`, the owner `owner`'s, as one act in a savepoint of `txn`, and names it on each
/// row's change. Whether it published: a typed refusal of the append, or an act the fold holds
/// without effect (an owner the log no longer holds live), leaves the rows on this install, and
/// is logged.
fn publish_owner_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: EntityId,
    rows: Vec<Unbacked>,
) -> Result<bool> {
    let (rows, changes): (Vec<SettingSlotRow>, Vec<Option<SettingChange>>) = rows
        .into_iter()
        .map(|unbacked| (unbacked.row, unbacked.change))
        .unzip();
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    let act = SettingSlotAct {
        owner,
        surface: ActSurface::ThisInstall,
        rows,
    };
    let signed = match vault.append_setting_slot_act_in_txn(&mut savepoint, act) {
        Ok(signed) => signed,
        Err(Error::Record(RecordError::AuthorityRefused(reason))) => {
            tracing::warn!(
                reason,
                "the owner's setting rows stay on this install: their batch act was refused"
            );
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    if vault.policy_setting_act_refused_in_txn(&savepoint, signed)? {
        tracing::warn!(
            "the owner's setting rows stay on this install: the fold holds their batch act without effect"
        );
        return Ok(false);
    }
    for change in changes.iter().flatten() {
        record_signed_entry_in_txn(&vault.store, &mut savepoint, change, signed)?;
    }
    savepoint.commit()?;
    Ok(true)
}

/// Whether the publish pass ran in this vault (stage 7a-3 tests).
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) fn settings_published_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(PUBLISHED.get(&vault.store, txn, &())?.is_some())
}
