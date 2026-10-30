//! The checkpoint payload projection (KS-7, FIX 5688 KS7-2b): which of an
//! image's rows go into their owners' compartments, framed and sealed one
//! bundle at a time, and which stay under the image's own seal.
//!
//! [`project`] reads the capture's one read view. Tier and exclusion
//! filtering come first, the snapshot's own ([`ImageFilter`]): a row the
//! image does not take is dropped before anything places it. Each owner
//! getter then reads its whole families once, and every row the image takes
//! has exactly one handler, its family's class ([`rows`]): a getter's row is
//! where that getter put it, a mixed carrier's goes to KS7-3's port
//! ([`MixedCarrierProjection`]), another client's stays with that client,
//! and any row no compartment holds stays in the image, named by family on
//! the capture receipt ([`NOT_COMPARTMENTED`]). The actor parts the getters
//! split out are grouped under each actor's own entity tree ([`actors`]),
//! and each bundle is sealed under its compartment's key ([`seal`]).
//!
//! Nothing calls this before KS7-5 wires capture and restore, and while
//! [`CHECKPOINT_PAYLOADS_ENABLED`] is false it answers
//! [`Projection::Unchanged`] before it classifies, reads, mints or refuses
//! anything. The artifact's writer is handed no payload, so the image's
//! bytes, its stream numbering and every refusal stay as they are.
#![allow(
    dead_code,
    reason = "KS7-5 wires capture and restore; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

mod actors;
mod rows;
mod seal;
#[cfg(feature = "sync")]
mod sync;

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

#[allow(unused_imports, reason = "KS7-5 restores through them")]
pub(super) use self::actors::{opened_content, unavailable};
use self::rows::{Class, DbClass, Families};
use self::seal::Bundle;
#[allow(unused_imports, reason = "KS7-5 restores through it")]
pub(super) use self::seal::open_bundle;
pub(super) use self::seal::{BundleRole, Compartment, PayloadSection, PayloadStreams};
#[cfg(feature = "sync")]
#[allow(unused_imports, reason = "KS7-5 hands it to project and restore")]
pub(super) use self::sync::SyncCarriers;
use super::{INDEX_SOURCE_PHONETIC, INDEX_SOURCE_TEXT, StorageTier, storage_tier};
use crate::error::{Error, Result};
use crate::side_table::SideDb;
use crate::store::{ManifestDbs, Store};
use crate::store::checkpoint_payload::CHECKPOINT_PAYLOADS_ENABLED;
use crate::store::checkpoint_payload::rows::{
    Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowDb, RowLocator, RowPart,
    frame_actor_parts, frame_owner,
};

/// CALLS PAYLOAD_UNCLASSIFIED (Engine 10-20 07:3x): a row of an
/// Unclassified family, and any row no handler compartments, stays under
/// today's vault-wide seal, and the capture receipt names its family with
/// these words. It never refuses the capture.
pub(super) const NOT_COMPARTMENTED: &str =
    "not compartmented: erase can't reach it in this checkpoint";

/// The family a receipt names a row by when no declaration covers its key.
const UNDECLARED: &str = "undeclared rows";

/// The owner getters, each beside its own store's codecs (KS7-2a), with
/// the tag a bundle's binding names it by; a tag is never reused.
macro_rules! getters {
    ($($(#[$doc:meta])* $name:ident = $tag:literal => $($module:ident)::+;)+) => {
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(rename_all = "snake_case")]
        pub(in crate::recovery::checkpoint) enum Getter {
            $($(#[$doc])* $name,)+
        }

        impl Getter {
            /// Every getter: a capture calls each once.
            pub(super) const ALL: &[Self] = &[$(Self::$name),+];

            pub(super) const fn tag(self) -> u8 {
                match self {
                    $(Self::$name => $tag,)+
                }
            }

            /// Every row of this getter's families in `txn`, by owner. It
            /// reads its whole families: nothing here filters them.
            pub(super) fn capture(
                self,
                dbs: &impl ManifestDbs,
                txn: &RoTxn<'_>,
            ) -> Result<Captured> {
                match self {
                    $(Self::$name => $($module)::+::capture(dbs, txn),)+
                }
            }

            /// `rows`' parts in this getter's families, framed for their
            /// compartment.
            pub(super) fn bytes_for_owner(self, rows: &OwnerRows) -> Result<Vec<u8>> {
                match self {
                    $(Self::$name => $($module)::+::bytes_for_owner(rows),)+
                }
            }

            /// Puts an opened compartment's rows of this getter back in
            /// `txn`, through the restore-only sink.
            pub(in crate::recovery::checkpoint) fn restore_in_txn(
                self,
                dbs: &impl ManifestDbs,
                txn: &mut RwTxn<'_>,
                opened: OpenedOwnerRows,
            ) -> Result<Restored> {
                match self {
                    $(Self::$name => $($module)::+::restore_in_txn(dbs, txn, opened),)+
                }
            }
        }
    };
}

getters! {
    /// Entity rows by kind, and edges.
    Entities = 1 => crate::ports::checkpoint;
    /// NOTE heads, forks, receipts, bundles, pins and titles.
    Note = 2 => crate::note::checkpoint;
    /// Entity documents: heads, forks, pins, receipts and the document rows.
    EntityDoc = 3 => crate::entity_doc::checkpoint;
    /// Typed bodies, their forks and receipts.
    TypedBody = 4 => crate::typed_body::checkpoint;
    /// Entity revisions and their staged index and phonetic inputs.
    EntityRevision = 5 => crate::vault::entity_revision::checkpoint;
    /// The text index's source text.
    TextSource = 6 => crate::bm25::checkpoint;
    /// The phonetic index's source codes.
    PhoneticSource = 7 => crate::batch::checkpoint;
    /// Body descriptors and their digest holders; KS-2 carries the bytes.
    ProvenanceBody = 8 => crate::provenance::body::checkpoint;
    /// Row births and the born-from index.
    ProvenanceBirth = 9 => crate::provenance::birth::checkpoint;
    /// Code documents.
    CodeDocument = 10 => crate::code_document::checkpoint;
    /// Code revisions, proposals and promotions.
    CodeRevision = 11 => crate::code_revision::checkpoint;
    /// Codebase snapshots and their indexes.
    Codebase = 12 => crate::codebase::checkpoint;
    /// Office bodies: heads, forks, exports and proposals.
    OfficeBody = 13 => crate::office_body::checkpoint;
    /// Blob artifact heads and versions.
    BlobArtifact = 14 => crate::blob_artifact::checkpoint;
    /// Outbound calls' frozen input.
    OutboundCall = 15 => crate::outbound_intent_ledger::checkpoint;
}

/// The mixed sync carriers KS7-3's port splits, with the tag a bundle's
/// binding names each by; a tag is never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::recovery::checkpoint) enum Carrier {
    /// A sync window's document snapshot.
    WindowSnapshot,
    /// A window's pending CRDT update.
    WindowUpdate,
    /// A thin-residence item's opened blob or document.
    ResidenceItem,
    /// An unacknowledged local text-document edit.
    PendingEdit,
    /// A pending NOTE-operation request.
    PendingNoteOperation,
    /// The sync queue's update carriers and quarantine.
    SyncQueue,
}

impl Carrier {
    pub(super) const fn tag(self) -> u8 {
        match self {
            Self::WindowSnapshot => 1,
            Self::WindowUpdate => 2,
            Self::ResidenceItem => 3,
            Self::PendingEdit => 4,
            Self::PendingNoteOperation => 5,
            Self::SyncQueue => 6,
        }
    }
}

/// KS7-3's port: splits a mixed sync carrier's row into the fragments its
/// owners hold, as a getter's capture records them, and puts an opened
/// carrier's fragments back. Before KS7-3 lands, [`Deferred`] splits none,
/// and each carrier row stays under the vault-wide seal, named.
pub(super) trait MixedCarrierProjection {
    /// Records the fragments of `carrier`'s row `key` in `out`; `false`,
    /// with `out` as it was, for a row this port does not split.
    fn project(
        &self,
        txn: &RoTxn<'_>,
        carrier: Carrier,
        key: &[u8],
        value: &[u8],
        out: &mut Captured,
    ) -> Result<bool>;

    /// Puts `opened`'s fragments of `carrier` back in `txn`, through the
    /// restore-only sink.
    fn restore_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        carrier: Carrier,
        opened: OpenedOwnerRows,
    ) -> Result<Restored>;

    /// Records in `out`, by carrier, the document groups of `rows` (FIX
    /// 10932): the image's rows of the carriers that hold entity-document
    /// frames, each update grouped with its document's history read from
    /// `txn` as `filter` takes it. Answers the indexes of the rows it
    /// placed; [`Self::project`] places the rest one at a time. None by
    /// default.
    fn project_documents(
        &self,
        _txn: &RoTxn<'_>,
        _filter: &ImageFilter,
        _rows: &[DocumentCarrierRow],
        _out: &mut BTreeMap<Carrier, Captured>,
    ) -> Result<BTreeSet<usize>> {
        Ok(BTreeSet::new())
    }
}

/// One image row of a carrier that holds entity-document frames (a pending
/// edit's, a cached item's), kept until every row is read so that a
/// document's rows group whole (FIX 10932).
pub(super) struct DocumentCarrierRow {
    pub(super) carrier: Carrier,
    /// The family the receipt names it by when it stays unclassified.
    pub(super) family: &'static str,
    pub(super) key: Vec<u8>,
    pub(super) value: Vec<u8>,
}

/// The port before KS7-3: it splits no carrier, so none is compartmented.
pub(super) struct Deferred;

impl MixedCarrierProjection for Deferred {
    fn project(
        &self,
        _: &RoTxn<'_>,
        _: Carrier,
        _: &[u8],
        _: &[u8],
        _: &mut Captured,
    ) -> Result<bool> {
        Ok(false)
    }

    fn restore_in_txn(
        &self,
        _: &mut RwTxn<'_>,
        _: Carrier,
        _: OpenedOwnerRows,
    ) -> Result<Restored> {
        Err(Error::InvariantViolation(
            "no mixed sync carrier is compartmented before KS7-3",
        ))
    }
}

fn db_name(db: RowDb) -> &'static str {
    match db {
        RowDb::Entities => "entities",
        RowDb::EdgesOut => "edges_out",
        RowDb::EdgesIn => "edges_in",
        RowDb::VaultMeta => "vault_meta",
        RowDb::SyncState => "sync_state",
        RowDb::SyncQueue => "sync_queue",
    }
}

fn row_db(database: &str) -> Option<RowDb> {
    match database {
        "entities" => Some(RowDb::Entities),
        "edges_out" => Some(RowDb::EdgesOut),
        "edges_in" => Some(RowDb::EdgesIn),
        "vault_meta" => Some(RowDb::VaultMeta),
        "sync_state" => Some(RowDb::SyncState),
        "sync_queue" => Some(RowDb::SyncQueue),
        _ => None,
    }
}

/// What the image takes, the one rule the snapshot and the projection read
/// it by (FIX 6377): canonical rows only, and no row of an excluded entity
/// (a diagnostic): its own, its short ids, its edges and its index sources.
pub(super) struct ImageFilter {
    excluded: BTreeSet<Vec<u8>>,
}

impl ImageFilter {
    /// The filter of the image `txn` reads: every diagnostic entity left
    /// out, as runtime-only.
    pub(super) fn of_snapshot(store: &Store, txn: &RoTxn<'_>) -> Result<Self> {
        let mut excluded = BTreeSet::new();
        for row in crate::ports::EntityStoreRead::port_entity_raw_records(store, txn)? {
            let (key, value) = row?;
            if crate::batch::EntityMetadataHeader::parse(&value)
                .is_some_and(|h| h.entity_type == crate::registry::ENTITY_TYPE_DIAGNOSTIC)
            {
                excluded.insert(key.as_bytes().to_vec());
            }
        }
        Ok(Self { excluded })
    }

    /// Whether the image takes the row `key` of `database`, as it rests.
    pub(super) fn takes(&self, database: &str, key: &[u8], value: &[u8]) -> bool {
        if storage_tier(database, key) != StorageTier::Canonical {
            return false;
        }
        let excluded = |id: &[u8]| self.excluded.contains(id);
        !match database {
            "entities" | "short_ids_reverse" => excluded(key),
            "short_ids" => excluded(value),
            "edges_out" | "edges_in" => {
                key.len() == 33 && (excluded(&key[..16]) || excluded(&key[17..]))
            }
            "vault_meta" => [
                INDEX_SOURCE_TEXT.decl().prefix,
                INDEX_SOURCE_PHONETIC.decl().prefix,
            ]
            .iter()
            .any(|prefix| key.strip_prefix(*prefix).is_some_and(excluded)),
            _ => false,
        }
    }

    /// `captured` with only the rows the image takes: an owner's part the
    /// image leaves out goes, with its actor parts and its dependencies.
    fn keep(&self, captured: Captured) -> Captured {
        let mut kept = Captured::default();
        for rows in captured.owners() {
            let parts: Vec<&RowPart> = rows
                .rows
                .iter()
                .filter(|part| {
                    actors::image_row(rows, part)
                        .is_some_and(|(db, key, value)| self.takes(db_name(db), key, value))
                })
                .collect();
            if parts.is_empty() {
                continue;
            }
            let held: BTreeSet<&RowLocator> = parts.iter().copied().map(RowPart::at).collect();
            let owner = kept.owner(rows.owner());
            owner.occurrence_hint = rows.occurrence_hint;
            owner.rows = parts.into_iter().cloned().collect();
            owner.actor_parts = rows
                .actor_parts
                .iter()
                .filter(|part| held.contains(&part.content_locator))
                .cloned()
                .collect();
            owner.dependencies = rows
                .dependencies
                .iter()
                .filter(|dependency| held.contains(&dependency.at))
                .cloned()
                .collect();
            owner.image_keys = rows
                .image_keys
                .iter()
                .filter(|(at, _)| held.contains(at))
                .map(|(at, key)| (at.clone(), key.clone()))
                .collect();
        }
        let takes = |at: &RowLocator, value: &[u8]| self.takes(db_name(at.db), &at.key, value);
        kept.structure = captured
            .structure
            .into_iter()
            .filter(|row| takes(&row.at, &row.value))
            .collect();
        kept.dispatched = captured
            .dispatched
            .into_iter()
            .filter(|row| takes(&row.at, &row.value))
            .collect();
        kept.unclassified = captured
            .unclassified
            .into_iter()
            .filter(|row| takes(&row.at, &[]))
            .collect();
        kept
    }
}

/// How a handler placed one image row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Claim {
    /// In its owners' compartments: the image leaves it out.
    Sealed,
    /// In the image as it is: structure, or another client's.
    Kept,
    /// In the image, not compartmented.
    Unclassified,
}

/// The image rows each handler placed, by row.
#[derive(Default)]
struct Claims(BTreeMap<(RowDb, Vec<u8>), (BundleRole, Claim)>);

impl Claims {
    /// Notes every row `captured` placed, by `by`.
    fn note(&mut self, by: BundleRole, captured: &Captured) -> Result<()> {
        for rows in captured.owners() {
            for part in &rows.rows {
                if let Some((db, key, _)) = actors::image_row(rows, part) {
                    self.put(db, key, by, Claim::Sealed)?;
                }
            }
        }
        for at in captured.structure.iter().map(|row| &row.at) {
            self.put(at.db, &at.key, by, Claim::Kept)?;
        }
        for at in captured.dispatched.iter().map(|row| &row.at) {
            self.put(at.db, &at.key, by, Claim::Kept)?;
        }
        for at in captured.unclassified.iter().map(|row| &row.at) {
            self.put(at.db, &at.key, by, Claim::Unclassified)?;
        }
        Ok(())
    }

    /// Exactly one handler places a row, in one way.
    fn put(&mut self, db: RowDb, key: &[u8], by: BundleRole, claim: Claim) -> Result<()> {
        match self.0.insert((db, key.to_vec()), (by, claim)) {
            Some(before) if before != (by, claim) => Err(Error::InvariantViolation(
                "an image row has two checkpoint payload handlers",
            )),
            _ => Ok(()),
        }
    }

    fn of(&self, database: &str, key: &[u8]) -> Option<(BundleRole, Claim)> {
        let db = row_db(database)?;
        self.0.get(&(db, key.to_vec())).copied()
    }
}

/// What a capture does with the image's ordinary payload.
pub(super) enum Projection {
    /// CHECKPOINT_PAYLOADS_ENABLED is off: the image is taken as today.
    Unchanged,
    /// Where every row the image takes goes.
    Projected(Projected),
}

/// Where a projection placed the image's rows.
#[derive(Default)]
pub(super) struct Projected {
    /// Each handler's rows the image takes, by owner, kept apart so that
    /// each frames and restores only its own.
    captures: Vec<(BundleRole, Captured)>,
    /// The rows the image keeps that no compartment holds, counted by
    /// family: the capture receipt names each ([`NOT_COMPARTMENTED`]).
    pub(super) not_compartmented: BTreeMap<&'static str, u64>,
    /// Every image row a compartment holds, which the image leaves out.
    pub(super) sealed: BTreeSet<(RowDb, Vec<u8>)>,
}

impl Projected {
    fn count(&mut self, family: &'static str) {
        *self.not_compartmented.entry(family).or_default() += 1;
    }

    /// Every owner a compartment is needed for: each owner whose rows a
    /// handler placed in one, and each actor whose parts the getters split
    /// out.
    pub(super) fn owners(&self) -> BTreeSet<OwnerRef> {
        let mut owners: BTreeSet<OwnerRef> = self
            .captures
            .iter()
            .flat_map(|(_, captured)| captured.owners().map(OwnerRows::owner))
            .collect();
        owners.extend(
            actors::group(&self.captures)
                .into_keys()
                .map(|actor| OwnerRef::entity(&actor)),
        );
        owners
    }

    /// Seals every bundle for `vault`, each under its owner's compartment
    /// in `compartments` (one for each of [`Self::owners`]): each handler's
    /// owners' content, framed by that handler, then each actor's parts.
    pub(super) fn seal(
        &self,
        vault: &[u8; 32],
        compartments: &BTreeMap<OwnerRef, Compartment>,
    ) -> Result<PayloadStreams> {
        let mut bundles = Vec::new();
        for (role, captured) in &self.captures {
            for rows in captured.owners() {
                let plain = match role {
                    BundleRole::Content(getter) => getter.bytes_for_owner(rows)?,
                    _ => frame_owner(rows, |_| true)?,
                };
                bundles.push(Bundle {
                    owner: rows.owner(),
                    role: *role,
                    plain,
                });
            }
        }
        for (actor, parts) in actors::group(&self.captures) {
            bundles.push(Bundle {
                owner: OwnerRef::entity(&actor),
                role: BundleRole::Actors,
                plain: frame_actor_parts(&parts)?,
            });
        }
        seal::seal_bundles(vault, &bundles, compartments)
    }
}

/// Every row of the manifest database `name` in `txn`, as stored, to
/// `each`.
fn for_each_row(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    name: &str,
    each: &mut dyn FnMut(&[u8], &[u8]) -> Result<()>,
) -> Result<()> {
    let db = match name {
        "entities" => dbs.entities(),
        "short_ids" => dbs.short_ids(),
        "short_ids_reverse" => dbs.short_ids_reverse(),
        "vault_meta" => dbs.vault_meta(),
        "hnsw_meta" => dbs.hnsw_meta(),
        "edges_out" => dbs.edges_out(),
        "edges_in" => dbs.edges_in(),
        "sync_queue" => dbs.sync_queue(),
        "job_records" => dbs.attempt_records(),
        "sync_state" => {
            for row in dbs.sync_state().iter(txn)? {
                let (key, value) = row?;
                each(key.as_bytes(), &value)?;
            }
            return Ok(());
        }
        _ => {
            return Err(Error::InvariantViolation(
                "a checkpoint payload database the image does not take",
            ));
        }
    };
    for row in db.iter(txn)? {
        let (key, value) = row?;
        each(&key, &value)?;
    }
    Ok(())
}

/// Places every row the image of `txn` takes (KS7-2b). `filter` is the
/// image's own, and `carriers` is KS7-3's port. While
/// CHECKPOINT_PAYLOADS_ENABLED is off this answers
/// [`Projection::Unchanged`] before anything else; on, a registry that
/// does not name every family, database and kind refuses ([`rows::check`]),
/// and nothing else does.
pub(super) fn project(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    filter: &ImageFilter,
    carriers: &dyn MixedCarrierProjection,
) -> Result<Projection> {
    if !CHECKPOINT_PAYLOADS_ENABLED {
        return Ok(Projection::Unchanged);
    }
    rows::check()?;
    let mut projected = Projected::default();
    let mut claims = Claims::default();
    // Each getter reads its whole families once; only the rows the image
    // takes are kept.
    for getter in Getter::ALL {
        let role = BundleRole::Content(*getter);
        let captured = filter.keep(getter.capture(dbs, txn)?);
        claims.note(role, &captured)?;
        projected.captures.push((role, captured));
    }
    let families = Families::new();
    let mut split: BTreeMap<Carrier, Captured> = BTreeMap::new();
    let mut documents = Vec::new();
    for &(name, class) in rows::DATABASES {
        if matches!(class, DbClass::Rows(Class::NotImaged)) {
            continue;
        }
        let mut place = |key: &[u8], value: &[u8]| -> Result<()> {
            if !filter.takes(name, key, value) {
                return Ok(());
            }
            let (family, class) = match class {
                DbClass::Rows(class) => (name, class),
                DbClass::Families(db) => match families.of(db, key) {
                    Some((decl, class)) => (decl.name, class),
                    None => {
                        projected.count(UNDECLARED);
                        return Ok(());
                    }
                },
            };
            // A mixed family's response rows go to the response client
            // (FIX 9179).
            let class = rows::class_for_row(name, key, value, class);
            match (class, claims.of(name, key)) {
                (Class::Owner(getter), Some((BundleRole::Content(by), claim))) if by == getter => {
                    if claim == Claim::Unclassified {
                        projected.count(family);
                    }
                }
                // A row its getter left out, or an unclassified family's,
                // stays in the image, named.
                (Class::Owner(_) | Class::Unclassified, None) => projected.count(family),
                (Class::Mixed(carrier @ (Carrier::PendingEdit | Carrier::ResidenceItem)), None) => {
                    documents.push(DocumentCarrierRow {
                        carrier,
                        family,
                        key: key.to_vec(),
                        value: value.to_vec(),
                    });
                }
                (Class::Mixed(carrier), None) => {
                    let out = split.entry(carrier).or_default();
                    if !carriers.project(txn, carrier, key, value, out)? {
                        projected.count(family);
                    }
                }
                (Class::Structure | Class::Other(_), None) => {}
                _ => {
                    return Err(Error::InvariantViolation(
                        "an image row is placed against its family's class",
                    ));
                }
            }
            Ok(())
        };
        for_each_row(dbs, txn, name, &mut place)?;
    }
    let grouped = carriers.project_documents(txn, filter, &documents, &mut split)?;
    for (index, row) in documents.iter().enumerate() {
        if grouped.contains(&index) {
            continue;
        }
        let out = split.entry(row.carrier).or_default();
        if !carriers.project(txn, row.carrier, &row.key, &row.value, out)? {
            projected.count(row.family);
        }
    }
    for (carrier, captured) in split {
        let role = BundleRole::Carrier(carrier);
        let captured = filter.keep(captured);
        claims.note(role, &captured)?;
        for at in captured.unclassified.iter().map(|row| &row.at) {
            let family = match at.db {
                RowDb::VaultMeta => families.of(SideDb::VaultMeta, &at.key),
                RowDb::SyncState => families.of(SideDb::SyncState, &at.key),
                // The queue's rows are named by their database.
                RowDb::SyncQueue => {
                    projected.count("sync_queue");
                    continue;
                }
                _ => None,
            };
            projected.count(family.map_or(UNDECLARED, |(decl, _)| decl.name));
        }
        projected.captures.push((role, captured));
    }
    projected.sealed = claims
        .0
        .into_iter()
        .filter(|(_, (_, claim))| *claim == Claim::Sealed)
        .map(|(row, _)| row)
        .collect();
    Ok(Projection::Projected(projected))
}
