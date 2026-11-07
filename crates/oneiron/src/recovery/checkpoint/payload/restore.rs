//! KS7-5 restore: every compartment the artifact's payload names is
//! required through the restore's one custody plan, so a fork copies its
//! leaf with the claim keys', and each whose leaf is live opens before
//! anything is made ([`open_image_payload`]): its bundles read back to the
//! locators they were sealed with, its entity rows offered to the image's
//! own checks, and the image's rows that hold an id link to an owner that
//! did not open taken out (FIX 6376). Once the image's rows are in, each
//! opened bundle lands through its getter's or carrier's restore, and each
//! unavailable call through the ledger's own sink
//! ([`restore_opened_in_txn`]). Each window the payload split is joined from
//! its carrier in the image and the copies that opened, before anything is
//! made, and its rows and markers land with the bundles (FIX 10277). An
//! owner that did not open was erased since the cut, and the restore carries
//! it beside the source's erasures ([`OpenedPayload::carry_erasures`]).

use std::collections::{BTreeMap, BTreeSet};

use heed::RwTxn;

#[cfg(not(feature = "sync"))]
use super::Deferred;
#[cfg(feature = "sync")]
use super::SyncCarriers;
use super::{
    BundleRole, Getter, MixedCarrierProjection, open_bundle, opened_content, structure, unavailable,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::recovery::checkpoint::Rejected;
use crate::recovery::checkpoint::artifact::SealedPayload;
use crate::recovery::checkpoint::image::CheckpointImage;
use crate::side_table;
use crate::store::checkpoint_payload::rows::{
    OpenedOwnerRows, OwnerRef, RowDb, RowLocator, RowPart, read_actor_parts, restore_row_in_txn,
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
    /// The image's unavailable-call rows (FIX 6260) and call accounting rows
    /// (KS7-5, FIX 12117), which land through the ledger's own sinks once
    /// the bundles are in.
    call_rows: Vec<(RowLocator, Vec<u8>)>,
    /// Each split window's rows, joined from its carrier and the copies that
    /// opened, with the markers its join asks (FIX 10277).
    window_rows: Vec<(RowLocator, Vec<u8>)>,
}

/// Opens `sealed`, the payload an artifact carries apart from its image,
/// before anything is made: each compartment it names is required through
/// `plan`, a live one opens, and a retired one's owner is unopened; the rows
/// of `image` that hold an id link to an unopened owner go. `None` for an
/// artifact that carries no payload.
///
/// # Errors
///
/// A missing compartment leaf (lost custody refuses, KS-4, as
/// `custody_key_missing`), a stream or bundle that does not read back as
/// sealed, and custody faults.
pub(in crate::recovery::checkpoint) fn open_image_payload(
    sealed: Option<SealedPayload<'_>>,
    plan: &mut CustodyPlan,
    image: &mut CheckpointImage,
) -> std::result::Result<Option<OpenedPayload>, Rejected> {
    let Some(mut sealed) = sealed else {
        // A split window's rows ride only in a payload's compartments.
        if !image.window_carriers.is_empty() {
            return Err(crate::store::checkpoint_payload::rows::bad_part().into());
        }
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
            BundleRole::Content(_) | BundleRole::Carrier(_) | BundleRole::Window => {
                contents.push((role, plain));
            }
        }
    }
    let mut bundles = Vec::with_capacity(contents.len());
    let mut windows = Vec::new();
    for (role, plain) in contents {
        let opened = opened_content(&plain, &actor_parts, unopened.clone())?;
        if role == BundleRole::Window {
            windows.push(opened);
        } else {
            bundles.push((role, opened));
        }
    }
    let window_rows = join_windows(&image.window_carriers, &windows, &unopened)?;
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
        call_rows: take_call_rows(image),
        window_rows,
    }))
}

/// Each split window's rows and markers, joined from its carrier in
/// `records` and the copies `windows`, the opened window bundles, hold
/// (FIX 10277). A copy whose owner, or an owner it holds only while, is in
/// `unopened` is erased; a window whose values none opened keeps its
/// history with them erased.
#[cfg(feature = "sync")]
fn join_windows(
    records: &[super::WindowCarrierRecord],
    windows: &[OpenedOwnerRows],
    unopened: &BTreeSet<OwnerRef>,
) -> Result<Vec<(RowLocator, Vec<u8>)>> {
    if records.is_empty() {
        return Ok(Vec::new());
    }
    super::sync::restore_window_carriers(records, windows, unopened)
}

/// A build without sync joins no window: a payload that split one refuses.
#[cfg(not(feature = "sync"))]
fn join_windows(
    records: &[super::WindowCarrierRecord],
    _windows: &[OpenedOwnerRows],
    _unopened: &BTreeSet<OwnerRef>,
) -> Result<Vec<(RowLocator, Vec<u8>)>> {
    if records.is_empty() {
        Ok(Vec::new())
    } else {
        Err(crate::store::checkpoint_payload::rows::bad_part())
    }
}

/// A payload's selected owners as their compartments opened for a legal
/// read of one checkpoint (LEGAL-HOLD-USE = B as a clone): each content
/// bundle of a selected owner, with the parts of the opened actor groups
/// that name one of its parts, and the owners that did not open.
pub(in crate::recovery::checkpoint) struct SelectedPayload {
    bundles: Vec<(BundleRole, OpenedOwnerRows)>,
    opened: BTreeSet<OwnerRef>,
}

impl SelectedPayload {
    /// Each opened content bundle `getter` framed for `owner`.
    pub(in crate::recovery::checkpoint) fn contents(
        &self,
        owner: OwnerRef,
        getter: Getter,
    ) -> impl Iterator<Item = &OpenedOwnerRows> {
        self.bundles.iter().filter_map(move |(role, opened)| {
            (*role == BundleRole::Content(getter)
                && opened.subtype == owner.subtype
                && opened.owner32 == owner.owner32)
                .then_some(opened)
        })
    }

    /// Whether the payload holds `owner`'s compartment and it opened: live
    /// custody still holds its leaf, so no erase or purge retired it since
    /// the cut.
    pub(in crate::recovery::checkpoint) fn opened(&self, owner: OwnerRef) -> bool {
        self.opened.contains(&owner)
    }
}

/// [`open_image_payload`] for a legal read of the `selected` owners only:
/// every compartment the payload names is required through `plan` and
/// opens or stays shut exactly as there, and the image's rows that hold an
/// id link to an owner that did not open are taken out the same way. Only
/// the selected owners' content bundles open, beside every actor bundle (an
/// actor-keyed part names its actor in its actor's group alone). Nothing is
/// restored or written, and no other owner's content is read.
///
/// # Errors
///
/// As [`open_image_payload`].
pub(in crate::recovery::checkpoint) fn open_selected_payload(
    sealed: Option<SealedPayload<'_>>,
    plan: &mut CustodyPlan,
    image: &mut CheckpointImage,
    selected: &BTreeSet<OwnerRef>,
) -> std::result::Result<Option<SelectedPayload>, Rejected> {
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
        // A window bundle holds an owner's copies of sync window values,
        // which no legal read of messages names (FIX 10277).
        let wanted = match role {
            BundleRole::Actors => true,
            BundleRole::Content(_) | BundleRole::Carrier(_) => {
                owner(compartment).is_some_and(|owner| selected.contains(&owner))
            }
            BundleRole::Window => false,
        };
        if !wanted {
            continue;
        }
        let bytes = sealed.stream(stream)?;
        let plain = open_bundle(&vault, &sealed.section, index, &bytes, key)?;
        match role {
            BundleRole::Actors => actor_parts.extend(read_actor_parts(&plain)?),
            BundleRole::Content(_) | BundleRole::Carrier(_) | BundleRole::Window => {
                contents.push((role, plain));
            }
        }
    }
    let mut bundles = Vec::with_capacity(contents.len());
    for (role, plain) in contents {
        bundles.push((
            role,
            opened_content(&plain, &actor_parts, unopened.clone())?,
        ));
    }
    structure::prune(&mut image.databases, &unopened);
    Ok(Some(SelectedPayload { bundles, opened }))
}

/// Takes the image's unavailable-call rows (FIX 6260) and call accounting
/// rows (FIX 12117) out of its rows, to land through the ledger's own sinks.
fn take_call_rows(image: &mut CheckpointImage) -> Vec<(RowLocator, Vec<u8>)> {
    let prefixes = [
        side_table::OUTBOUND_INTENT_UNAVAILABLE.prefix,
        side_table::OUTBOUND_INTENT_ACCOUNTING.prefix,
    ];
    let Some(rows) = image.databases.get_mut("vault_meta") else {
        return Vec::new();
    };
    let mut taken = Vec::new();
    rows.retain(|(key, value)| {
        if !prefixes.iter().any(|prefix| key.starts_with(prefix)) {
            return true;
        }
        taken.push((
            RowLocator::row(RowDb::VaultMeta, key.clone()),
            value.clone(),
        ));
        false
    });
    taken
}

impl OpenedPayload {
    /// Marks opened MESSAGE results before their rewritten lengths are budgeted.
    pub(in crate::recovery::checkpoint) fn retire_message_results(
        &mut self,
        digests: &BTreeSet<[u8; 32]>,
    ) -> Result<()> {
        if digests.is_empty() {
            return Ok(());
        }
        for (role, opened) in &mut self.bundles {
            if *role != BundleRole::Content(Getter::Entities) {
                continue;
            }
            for part in &mut opened.rows {
                let RowPart::Exact { at, value } = part else {
                    continue;
                };
                if at.db != RowDb::Entities
                    || opened.dependencies.iter().any(|dependency| {
                        dependency.at == *at && opened.unavailable.contains(&dependency.on)
                    })
                {
                    continue;
                }
                crate::memory::retire_message_result_in_row(value, digests)?;
            }
        }
        Ok(())
    }

    /// The entity rows the opened entity bundles land, in key order, that
    /// no unopened owner holds up: each exact row, and each actor-keyed one
    /// (an author carrier, FIX 17143) whose actor opened. A restore checks
    /// each as it checks the image's, and stages its type index.
    ///
    /// # Errors
    ///
    /// An actor part that does not read as the row it names.
    pub(in crate::recovery::checkpoint) fn entity_rows(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut rows = Vec::new();
        let entities = self
            .bundles
            .iter()
            .filter(|(role, _)| *role == BundleRole::Content(Getter::Entities));
        for (_, opened) in entities {
            for part in &opened.rows {
                let at = part.at();
                if at.db != RowDb::Entities || held_up(opened, at) {
                    continue;
                }
                match part {
                    RowPart::Exact { value, .. } => rows.push((at.key.clone(), value.clone())),
                    RowPart::ActorKeyed { .. } => {
                        if let Some((row, value)) = opened.actor_keyed_row(at)? {
                            rows.push((row.key, value));
                        }
                    }
                    RowPart::NoActor { .. } => {}
                }
            }
        }
        rows.sort();
        Ok(rows)
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

    /// Each row the opened bundles and the unavailable calls land, its key
    /// and value lengths, for the restore's write budget: a no-one-form row
    /// with the actor parts that fill it back, an actor-keyed row at its
    /// actor parts' framed key and value. A part an unopened owner holds up
    /// lands nothing.
    pub(in crate::recovery::checkpoint) fn row_lengths(&self) -> Vec<(u64, u64)> {
        let len = |bytes: &[u8]| bytes.len() as u64;
        let mut rows = Vec::new();
        for (_, opened) in &self.bundles {
            let mut filled: BTreeMap<&RowLocator, u64> = BTreeMap::new();
            for actor in &opened.actor_parts {
                let bytes = filled.entry(&actor.content_locator).or_default();
                *bytes = bytes.saturating_add(len(&actor.bytes));
            }
            for part in &opened.rows {
                let at = part.at();
                if held_up(opened, at) {
                    continue;
                }
                let actors = filled.get(at).copied().unwrap_or(0);
                rows.push(match part {
                    RowPart::Exact { value, .. } | RowPart::NoActor { value, .. } => {
                        (len(&at.key), len(value).saturating_add(actors))
                    }
                    RowPart::ActorKeyed { .. } => (0, actors),
                });
            }
        }
        rows.extend(
            self.call_rows
                .iter()
                .chain(&self.window_rows)
                .map(|(at, value)| (len(&at.key), len(value))),
        );
        rows
    }
}

/// Whether an unopened owner holds `opened`'s part at `at` up.
fn held_up(opened: &OpenedOwnerRows, at: &RowLocator) -> bool {
    opened
        .dependencies
        .iter()
        .any(|dependency| dependency.at == *at && opened.unavailable.contains(&dependency.on))
}

/// Lands every bundle once the image's rows are in. Only blob versions
/// missing their actor part wait for the authenticated landing continuation:
/// its native claim reads need all history/custody rows and the type index.
/// Unavailable calls (FIX 6260) and the accounting of calls that did not
/// open (FIX 12117) still land through the ledger's own sinks, last.
///
/// # Errors
///
/// A part its getter's codecs refuse, and storage faults.
pub(in crate::recovery::checkpoint) fn restore_opened_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    opened: OpenedPayload,
    retired_digests: &BTreeSet<[u8; 32]>,
) -> Result<Vec<OpenedOwnerRows>> {
    #[cfg(feature = "sync")]
    let carriers = SyncCarriers::new(store);
    #[cfg(not(feature = "sync"))]
    let carriers = Deferred;
    let mut blob_artifacts = Vec::new();
    for (role, rows) in opened.bundles {
        match role {
            BundleRole::Content(Getter::ProvenanceBody) => {
                crate::provenance::body::checkpoint::restore_pruned_in_txn(
                    store,
                    txn,
                    rows,
                    retired_digests,
                )?;
            }
            BundleRole::Content(Getter::BlobArtifact) => {
                if let Some(deferred) =
                    crate::blob_artifact::checkpoint::restore_or_defer_in_txn(store, txn, rows)?
                {
                    blob_artifacts.push(deferred);
                }
            }
            BundleRole::Content(getter) => {
                getter.restore_in_txn(store, txn, rows)?;
            }
            BundleRole::Carrier(carrier) => {
                carriers.restore_in_txn(txn, carrier, rows)?;
            }
            BundleRole::Actors => {
                return Err(Error::InvariantViolation(
                    "an actor bundle lands through its owners' content",
                ));
            }
            BundleRole::Window => {
                return Err(Error::InvariantViolation(
                    "a window bundle lands through its window's carrier",
                ));
            }
        }
    }
    // Each split window's rows and markers, joined before anything was made
    // (FIX 10277).
    for (at, value) in &opened.window_rows {
        restore_row_in_txn(store, txn, at, value)?;
    }
    // After every bundle, so a call whose record came back keeps no
    // accounting row (FIX 12117).
    for (at, value) in &opened.call_rows {
        if !crate::outbound_intent_ledger::checkpoint::restore_unavailable_in_txn(
            store, txn, at, value,
        )? {
            crate::outbound_intent_ledger::checkpoint::restore_accounting_in_txn(
                store, txn, at, value,
            )?;
        }
    }
    Ok(blob_artifacts)
}
