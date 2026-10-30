//! KS7-5 restore: every compartment the artifact's payload names is
//! required through the restore's one custody plan, so a fork copies its
//! leaf with the claim keys', and each whose leaf is live opens before
//! anything is made ([`open_image_payload`]): its bundles read back to the
//! locators they were sealed with, its entity rows offered to the image's
//! own checks, and the image's rows that hold an id link to an owner that
//! did not open taken out (FIX 6376). Once the image's rows are in, each
//! opened bundle lands through its getter's or carrier's restore, and each
//! unavailable call through the ledger's own sink
//! ([`restore_opened_in_txn`]). An owner that did not open was erased since
//! the cut, and the restore carries it beside the source's erasures
//! ([`OpenedPayload::carry_erasures`]).

use std::collections::BTreeSet;

use heed::RwTxn;

#[cfg(not(feature = "sync"))]
use super::Deferred;
#[cfg(feature = "sync")]
use super::SyncCarriers;
use super::{
    BundleRole, Getter, MixedCarrierProjection, open_bundle, opened_content, structure,
    unavailable,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::recovery::checkpoint::artifact::SealedPayload;
use crate::recovery::checkpoint::image::CheckpointImage;
use crate::side_table;
use crate::store::checkpoint_payload::rows::{
    OpenedOwnerRows, OwnerRef, RowDb, RowLocator, RowPart, read_actor_parts,
};
use crate::store::checkpoint_payload::{CompartmentAccess, Subtype, compartment_access};
use crate::store::{CustodyPlan, Store};

/// A payload whose compartments opened, held until its rows land.
pub(in crate::recovery::checkpoint) struct OpenedPayload {
    /// Each content and carrier bundle that opened, as its role's restore
    /// takes it.
    bundles: Vec<(BundleRole, OpenedOwnerRows)>,
    /// The owners whose compartments the payload holds that did not open:
    /// every part they hold up drops.
    unopened: BTreeSet<OwnerRef>,
    /// The image's unavailable-call rows (FIX 6260), which land through the
    /// ledger's own sink.
    unavailable_calls: Vec<(RowLocator, Vec<u8>)>,
}

/// Opens `sealed`, the payload an artifact carries apart from its image,
/// before anything is made: each compartment it names is required through
/// `plan`, a live one opens, and a retired one's owner is unopened; the rows
/// of `image` that hold an id link to an unopened owner go. `None` for an
/// artifact that carries no payload.
///
/// # Errors
///
/// A missing compartment leaf (lost custody refuses, KS-4), a stream or
/// bundle that does not read back as sealed, and custody faults.
pub(in crate::recovery::checkpoint) fn open_image_payload(
    sealed: Option<SealedPayload<'_>>,
    plan: &mut CustodyPlan,
    image: &mut CheckpointImage,
) -> Result<Option<OpenedPayload>> {
    let Some(mut sealed) = sealed else {
        return Ok(None);
    };
    let required = sealed.section.required()?;
    let access = compartment_access(plan, &required)?;
    let owner = |index: usize| {
        required.get(index).map(|(item, _)| OwnerRef {
            subtype: item.subtype(),
            owner32: *item.owner(),
        })
    };
    let held: BTreeSet<OwnerRef> = (0..required.len()).filter_map(owner).collect();
    let opened: BTreeSet<OwnerRef> = access
        .iter()
        .enumerate()
        .filter(|(_, answer)| matches!(answer, CompartmentAccess::Open(_)))
        .filter_map(|(index, _)| owner(index))
        .collect();
    let unopened = unavailable(&held, &opened);
    let vault = sealed.vault_id();
    let mut contents = Vec::new();
    let mut actor_parts = Vec::new();
    for (index, (compartment, role, stream)) in sealed.section.bundles().into_iter().enumerate() {
        let Some(CompartmentAccess::Open(key)) = access.get(compartment) else {
            continue;
        };
        let bytes = sealed.stream(stream)?;
        let plain = open_bundle(&vault, &sealed.section, index, &bytes, key)?;
        match role {
            BundleRole::Actors => actor_parts.extend(read_actor_parts(&plain)?),
            BundleRole::Content(_) | BundleRole::Carrier(_) => contents.push((role, plain)),
        }
    }
    let mut bundles = Vec::with_capacity(contents.len());
    for (role, plain) in contents {
        bundles.push((role, opened_content(&plain, &actor_parts, unopened.clone())?));
    }
    let pruned = structure::prune(&mut image.databases, &unopened);
    if pruned > 0 {
        tracing::info!(
            unopened = unopened.len(),
            pruned,
            "checkpoint payload owners erased since the image did not open; the rows naming them \
             stay out"
        );
    }
    Ok(Some(OpenedPayload {
        bundles,
        unopened,
        unavailable_calls: take_unavailable_calls(image),
    }))
}

/// Takes the image's unavailable-call rows (FIX 6260) out of its rows, to
/// land through the ledger's own sink.
fn take_unavailable_calls(image: &mut CheckpointImage) -> Vec<(RowLocator, Vec<u8>)> {
    let prefix = side_table::OUTBOUND_INTENT_UNAVAILABLE.prefix;
    let Some(rows) = image.databases.get_mut("vault_meta") else {
        return Vec::new();
    };
    let mut taken = Vec::new();
    rows.retain(|(key, value)| {
        if !key.starts_with(prefix) {
            return true;
        }
        taken.push((RowLocator::row(RowDb::VaultMeta, key.clone()), value.clone()));
        false
    });
    taken
}

impl OpenedPayload {
    /// The entity rows the opened entity bundles land, in key order, that
    /// no unopened owner holds up: a restore checks each as it checks the
    /// image's, and stages its type index.
    pub(in crate::recovery::checkpoint) fn entity_rows(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut rows: Vec<(Vec<u8>, Vec<u8>)> = self
            .bundles
            .iter()
            .filter(|(role, _)| *role == BundleRole::Content(Getter::Entities))
            .flat_map(|(_, opened)| {
                opened.rows.iter().filter_map(|part| match part {
                    RowPart::Exact { at, value }
                        if at.db == RowDb::Entities && !held_up(opened, at) =>
                    {
                        Some((at.key.clone(), value.clone()))
                    }
                    _ => None,
                })
            })
            .collect();
        rows.sort();
        rows
    }

    /// `erased`, the ids a restore's source erased, with every entity
    /// whose compartment did not open: erased since the cut, so the
    /// restore's removal scrub and actor sweep take it as theirs.
    pub(in crate::recovery::checkpoint) fn carry_erasures(
        &self,
        erased: &BTreeSet<EntityId>,
    ) -> BTreeSet<EntityId> {
        let mut carried = erased.clone();
        carried.extend(
            self.unopened
                .iter()
                .filter(|owner| owner.subtype == Subtype::EntityTree)
                .filter_map(|owner| {
                    EntityId::from_bytes(owner.owner32[..16].try_into().ok()?).ok()
                }),
        );
        carried
    }
}

/// Whether an unopened owner holds `opened`'s part at `at` up.
fn held_up(opened: &OpenedOwnerRows, at: &RowLocator) -> bool {
    opened
        .dependencies
        .iter()
        .any(|dependency| dependency.at == *at && opened.unavailable.contains(&dependency.on))
}

/// Lands `opened` in `txn`, the restore's image write, once the image's rows
/// are in: each content bundle through its getter's restore, each carrier
/// bundle through KS7-3's port, and each unavailable call through the
/// ledger's own sink (FIX 6260). How many parts an unopened owner held up.
///
/// # Errors
///
/// A part its getter's codecs refuse, and storage faults.
pub(in crate::recovery::checkpoint) fn restore_opened_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    opened: OpenedPayload,
) -> Result<usize> {
    #[cfg(feature = "sync")]
    let carriers = SyncCarriers::new(store);
    #[cfg(not(feature = "sync"))]
    let carriers = Deferred;
    let mut dropped = 0;
    for (role, rows) in opened.bundles {
        let restored = match role {
            BundleRole::Content(getter) => getter.restore_in_txn(store, txn, rows)?,
            BundleRole::Carrier(carrier) => carriers.restore_in_txn(txn, carrier, rows)?,
            BundleRole::Actors => {
                return Err(Error::InvariantViolation(
                    "an actor bundle lands through its owners' content",
                ));
            }
        };
        dropped += restored.dropped.len();
    }
    for (at, value) in &opened.unavailable_calls {
        crate::outbound_intent_ledger::checkpoint::restore_unavailable_in_txn(
            store, txn, at, value,
        )?;
    }
    Ok(dropped)
}
