//! Where a proposed lens is read (FIX 2136): the world and facet its author
//! declares for it, or, undeclared, where the author's credential is bound
//! to author. The proposal's writer places the lens's `lens/intent` NOTE
//! there by its `InWorld` and `FacetOf` edges. The lens row's birth names
//! that NOTE as the one thing its tree was written from, so a reader
//! narrowed to some worlds or facets reads the frozen tree, and the
//! proposal once its pack is gone, exactly when its own read admits the
//! NOTE: the vault's own row admission, no second scope rule, and no live
//! pack install asked for.

use serde::{Deserialize, Serialize};

use super::proposal::{LensProposalRecord, PROPOSALS};
use crate::claim::ScopedRead;
use crate::federation::record_scope::BirthPosition;
use crate::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use crate::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_WORLD};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Error, Result, Vault};

/// `vault.lenses.propose`'s declared scope: the world and facet a lens's
/// frozen tree belongs to, each a 32-hex entity id. An axis left out is
/// where the proposer's credential is bound to author. A lens placed under
/// no facet is read by no reader narrowed to some worlds or facets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LensScope {
    /// The WORLD the lens belongs to; left out, base reality unless the
    /// proposer's credential is bound to a world.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub world: Option<String>,
    /// The FACET the lens belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facet: Option<String>,
}

impl LensScope {
    /// The declaration `position` reads as.
    pub(super) fn of(position: BirthPosition) -> Self {
        Self {
            world: position.world.map(|world| world.to_hex()),
            facet: position.facet.map(|facet| facet.to_hex()),
        }
    }
}

/// What a reader of `vault.lenses.list` is given of one proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LensAdmission {
    /// Nothing: the reader learns of no such proposal.
    Withheld,
    /// Its row, without the frozen tree.
    Listed,
    /// Its row and its frozen tree.
    Whole,
}

/// The position a proposal places its lens at: `declared` over `bound`,
/// the author's verified authoring context (the birth position its host
/// bound, never an input). An axis the context binds is declared only as
/// it is bound; an axis it leaves open is the author's to declare only
/// when its own read is not narrowed (`vault_wide`).
///
/// # Errors
///
/// An axis that is not 32 hex, or one the author does not author in.
pub(super) fn declared_position(
    declared: Option<&LensScope>,
    bound: BirthPosition,
    vault_wide: bool,
) -> MemoryResult<BirthPosition> {
    let Some(declared) = declared else {
        return Ok(bound);
    };
    Ok(BirthPosition {
        world: declared_axis("world", declared.world.as_deref(), bound.world, vault_wide)?,
        facet: declared_axis("facet", declared.facet.as_deref(), bound.facet, vault_wide)?,
    })
}

/// One axis of [`declared_position`].
fn declared_axis(
    axis: &str,
    declared: Option<&str>,
    bound: Option<EntityId>,
    vault_wide: bool,
) -> MemoryResult<Option<EntityId>> {
    let Some(declared) = declared else {
        return Ok(bound);
    };
    let declared = EntityId::from_hex(declared)
        .map_err(|_| MemoryError::bad_request(format!("scope.{axis} is a 32-hex entity id")))?;
    match bound {
        Some(bound) if bound == declared => Ok(Some(declared)),
        None if vault_wide => Ok(Some(declared)),
        _ => Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("scope.{axis} names a {axis} this credential does not author in"),
            &["Leave scope out to place the lens where this credential authors."],
        )),
    }
}

/// `position`, kept to the axes that name a live WORLD and a live FACET in
/// `txn`. A declared axis that names none refuses; an undeclared one places
/// nothing on its axis.
///
/// # Errors
///
/// A declared axis naming no live row of its kind; a storage failure.
pub(super) fn placed_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    position: BirthPosition,
    declared: Option<&LensScope>,
) -> MemoryResult<BirthPosition> {
    let mut placed = BirthPosition::default();
    if let Some(world) = position.world
        && live_of(vault, txn, &world, ENTITY_TYPE_WORLD)?
    {
        placed.world = Some(world);
    }
    if let Some(facet) = position.facet
        && live_of(vault, txn, &facet, ENTITY_TYPE_FACET)?
    {
        placed.facet = Some(facet);
    }
    let declared = declared.cloned().unwrap_or_default();
    for (axis, asked, kept) in [
        ("world", declared.world.is_some(), placed.world.is_some()),
        ("facet", declared.facet.is_some(), placed.facet.is_some()),
    ] {
        if asked && !kept {
            return Err(MemoryError::bad_request(format!(
                "scope.{axis} names no live {axis}"
            )));
        }
    }
    Ok(placed)
}

impl Vault {
    /// The scope a later proposal of the lens `lens_ref` declares, so it is
    /// read where that lens is: each axis of that lens's scope that still
    /// names a live row of its kind. `None` when none does, or no proposal
    /// has that ref.
    ///
    /// # Errors
    ///
    /// A storage failure.
    pub(super) fn carried_lens_scope(&self, lens_ref: &EntityId) -> Result<Option<LensScope>> {
        let txn = self.store.env.read_txn()?;
        let Some(record) = PROPOSALS.get(&self.store, &txn, lens_ref)? else {
            return Ok(None);
        };
        let live = |id: Option<&String>, kind: u8| -> Result<Option<String>> {
            let Some(id) = id.and_then(|id| EntityId::from_hex(id).ok()) else {
                return Ok(None);
            };
            Ok(live_of(self, &txn, &id, kind)?.then(|| id.to_hex()))
        };
        let carried = LensScope {
            world: live(record.scope.world.as_ref(), ENTITY_TYPE_WORLD)?,
            facet: live(record.scope.facet.as_ref(), ENTITY_TYPE_FACET)?,
        };
        Ok((carried != LensScope::default()).then_some(carried))
    }
}

/// Whether `id` is a live row of `kind` in `txn`.
fn live_of(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId, kind: u8) -> Result<bool> {
    Ok(matches!(
        live_entity_row_in_txn(&vault.store, txn, id)?,
        LiveEntityRow::Live { entity_type, .. } if entity_type == kind
    ))
}

/// What `read`, narrowed to some worlds or facets, is given in `txn` of the
/// proposal `record` for the slot skill `skill_id`. Its row and frozen tree
/// when its read admits the lens's intent NOTE where the proposal placed
/// it, whether or not its pack is installed now (FIX 2136). Else its row
/// alone, as before, while the read admits both records it is bound to:
/// the slot's SKILL and the live source of the pack installed under its
/// pack name.
///
/// # Errors
///
/// A corrupt proposal record or install catalog; a storage failure.
pub(super) fn proposal_admission_in(
    vault: &Vault,
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    record: &LensProposalRecord,
    skill_id: &EntityId,
) -> Result<LensAdmission> {
    let prompt_ref = EntityId::from_hex(&record.prompt_ref)
        .map_err(|_| Error::CorruptedIndex("lens proposal record"))?;
    if read.is_entity_readable_in(txn, &prompt_ref)? {
        return Ok(LensAdmission::Whole);
    }
    let Some(install) = vault.mounted_pack_in_txn(txn, &record.pack_name)? else {
        return Ok(LensAdmission::Withheld);
    };
    let source = EntityId::from_hex(&install.source_id)
        .map_err(|_| Error::CorruptedIndex("pack install catalog"))?;
    Ok(
        if read.is_entity_readable_in(txn, skill_id)? && read.is_entity_readable_in(txn, &source)? {
            LensAdmission::Listed
        } else {
            LensAdmission::Withheld
        },
    )
}
