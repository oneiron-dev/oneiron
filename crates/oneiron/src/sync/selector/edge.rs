//! Admitted-edge copy with reserved-kind rejection and the FacetOf off-table verdict.

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, RegistryError, Result};
#[cfg(feature = "sync")]
use crate::federation::facet_read;
use crate::sync::loro_support::{map_for_each_value_bytes, map_insert_bytes};
#[cfg(feature = "sync")]
use crate::sync::quarantine::{self, QuarantineContainer};
use crate::sync::types::WindowKey;
#[cfg(feature = "sync")]
use loro::{ExportMode, LoroDoc};

/// Copies the federated edges map, rejecting reserved-kind edge keys:
/// `merged_into` / `split_into` writes are the identity-topology door's
/// side-effects and never member/guest input (ARCH-0055) — copying the raw
/// bytes would hand a federated peer redirect-shell write authority over
/// the host's entities. Keys that do not parse as edge keys copy through
/// unchanged: the ordinary materialization path quarantines them with
/// evidence (the same division Observer B uses).
///
/// ONE-1645 admission boundary for the `FacetOf` type table. The replay
/// chokepoint (`window::forward_rematerialize`) already quarantines an
/// off-table stamp before it reaches LMDB, but the FEDERATION SELECTOR reads
/// the RAW Loro map, not LMDB: a forged `PERSON -> <selected FACET>` row that
/// merely SITS in the admitted / live document could scope what this vault
/// exports to a facet-limited peer — quarantined-but-present is enough. The
/// complete fix is layered: this door keeps a PROVABLY off-table row out of
/// the doc, and [`facet_scope_by_source`] mirrors the same table on the READ
/// side so whatever residue survives the H2 defer is inert anyway.
///
/// The invariant here is deliberately asymmetric, and the asymmetry is the
/// whole design (see [`admitted_facet_of_verdict`]):
///
/// * PROVABLY off-table on the facts in hand — a KNOWN off-table source, or a
///   KNOWN non-FACET target, either one sufficient ALONE — is DROPPED with a
///   typed [`RegistryError::InvalidFacetOfEdge`](crate::error::RegistryError::InvalidFacetOfEdge) quarantine record. The row is not
///   copied, so the selector can never read it.
/// * UNKNOWABLE deciding endpoint — the endpoint has not arrived yet — PASSES
///   THROUGH. The remat gate's defer-then-validate owns those: a hard verdict
///   here would burn a legitimate out-of-order delivery permanently (H2). The
///   read mirror is what makes that pass-through safe even after the missing
///   endpoint later lands off-table.
///
/// Dropping the edge while still admitting its source entity is harmless: the
/// entity arrives UNSTAMPED, which is strictly less disclosure than the peer
/// asked for.
///
/// THE DROP IS TERMINAL, and the quarantine shape follows from that. A dropped
/// row never enters the admitted doc, so no forward rematerialization can ever
/// replay it — the evidence written here is the WHOLE account of that row, and
/// it must not schedule retry work nobody can discharge. The rejections
/// therefore ride a [`quarantine::TerminalRejectionBatch`]: no `rm:w:` marker
/// (an unhealable marker would pend forever and permanently poison the erasure
/// SLA channel `rm:` exists to carry), and ONE write transaction for the whole
/// pass rather than one per rejected row (the peer chooses N, so a per-row
/// commit is an amplification primitive it controls). Evidence is bounded at
/// [`quarantine::MAX_QUARANTINE_ROWS_PER_PASS`] rows per pass; beyond that
/// rejections are accounted by count, never silently.
///
/// No stamp onto a row this vault does not store is copied: no one can tell
/// yet whether its sender may place that row, and the document replicates to
/// the owner's other devices as their own (Engine ruling on Sol R3 F1). One
/// whose row the update brings (`brought`, the admitted entities) waits for
/// that birth to apply here, since the row's presence in the update is not
/// its birth (Astra-b F1 on #1432); any other is held under its sender.
#[cfg(feature = "sync")]
pub(super) fn copy_admitted_edges(
    vault: &Vault,
    window_key: &WindowKey,
    source_entities: &loro::LoroMap,
    brought: &loro::LoroMap,
    source: &loro::LoroMap,
    target: &loro::LoroMap,
) -> Result<EarlyStamps> {
    let rtxn = vault.store.env.read_txn()?;
    let mut rejections = quarantine::TerminalRejectionBatch::new(window_key.as_str());
    let mut early = EarlyStamps::default();
    let mut result = Ok(());
    map_for_each_value_bytes(source, |key, value| {
        if result.is_err() {
            return;
        }
        // [`refuse_non_binary_edges`] refused the frame for any such value.
        let Some(value) = value else {
            result = Err(Error::InvalidKey);
            return;
        };
        if let Some((src, kind, tgt)) = super::bridge::parse_edge_key(key) {
            if kind != EdgeKind::AddressedTo
                && let Err(reserved) = crate::edge::validate_public_edge_kind(kind)
            {
                result = Err(reserved);
                return;
            }
            let verdict = if kind == EdgeKind::AddressedTo {
                admitted_addressing_verdict(vault, &rtxn, source_entities, src, tgt, value)
            } else {
                admitted_facet_of_verdict(vault, &rtxn, source_entities, brought, src, kind, tgt)
            };
            match verdict {
                Ok(AdmittedEdgeVerdict::Copy) => {}
                Ok(AdmittedEdgeVerdict::Drop) => return,
                Ok(verdict @ (AdmittedEdgeVerdict::Hold | AdmittedEdgeVerdict::WithBirth)) => {
                    // Only a value replay could write waits; any other is
                    // the peer's rejection, typed as the materializers type it.
                    match crate::edge::decode_edge_value_for_kind(EdgeKind::FacetOf, value) {
                        Ok(_) => {
                            let waits = if matches!(verdict, AdmittedEdgeVerdict::Hold) {
                                &mut early.held
                            } else {
                                &mut early.with_birth
                            };
                            waits.push(HeldStamp {
                                src,
                                tgt,
                                value: value.to_vec(),
                            });
                        }
                        Err(malformed) => {
                            rejections.push(QuarantineContainer::Edges, key, &malformed, value);
                        }
                    }
                    return;
                }
                Ok(AdmittedEdgeVerdict::DropRejected(off_table)) => {
                    // Quarantine-and-continue: the peer's forged row gets
                    // typed durable evidence, the window's other N-1 rows
                    // still admit. `payload` is the raw value.
                    rejections.push(QuarantineContainer::Edges, key, &off_table, value);
                    return;
                }
                // A LOCAL fault reading endpoint types (corrupted stored
                // header, heed read error) is never the peer's rejection:
                // fail closed on the whole admission rather than record a
                // quarantine row that misattributes our defect to them.
                Err(local) => {
                    result = Err(local);
                    return;
                }
            }
        }
        result = map_insert_bytes(target, key, value);
    });
    result?;
    // Evidence commits only once the copy pass itself succeeded: a pass that
    // fails closed admits nothing, so recording peer rejections from a frame
    // this vault refused whole would be an account of a thing that never
    // happened.
    drop(rtxn);
    rejections.commit(vault)?;
    Ok(early)
}

/// Refuses the frame for an edge value that is not bytes, whatever rows it
/// names, before anything reads the vault for it or a release fills its key:
/// judged after the stored endpoints, the outcome would tell the peer whether
/// they exist (Astra R5 F3, R7 F1 on #1432).
#[cfg(feature = "sync")]
pub(super) fn refuse_non_binary_edges(edges: &loro::LoroMap) -> Result<()> {
    let mut result = Ok(());
    map_for_each_value_bytes(edges, |_, value| {
        if value.is_none() {
            result = Err(Error::InvalidKey);
        }
    });
    result
}

/// The facet stamps an update sent onto rows this vault does not store: the
/// ones whose rows it brings wait for those births, and the rest are held.
#[cfg(feature = "sync")]
#[derive(Default)]
pub(super) struct EarlyStamps {
    pub(super) held: Vec<HeldStamp>,
    pub(super) with_birth: Vec<HeldStamp>,
}

/// Holds `stamps` under the sender's `lane` and the `grant` it sent them
/// under, out of the admitted document ([`copy_admitted_edges`]). When
/// `capped`, a stamp past the sender's caps is refused with typed evidence,
/// and the rest of the update is admitted as it would be without it.
#[cfg(feature = "sync")]
pub(super) fn hold_stamps(
    vault: &Vault,
    window_key: &WindowKey,
    (lane, grant): (&str, Option<EntityId>),
    stamps: &[HeldStamp],
    capped: bool,
) -> Result<()> {
    if stamps.is_empty() {
        return Ok(());
    }
    let now = vault.store.clock.now_recorded_at();
    vault.with_write_txn_grouped(|wtxn| {
        let mut refused = quarantine::TerminalRejectionBatch::new(window_key.as_str());
        for stamp in stamps {
            let hold = facet_read::park_stamp(
                &vault.store,
                wtxn,
                (stamp.src, stamp.tgt),
                (lane, grant),
                &stamp.value,
                (now, capped),
            )?;
            if hold == facet_read::Hold::SenderFull {
                let full =
                    Error::Sync(crate::error::SyncError::HeldFacetStampsFull { src: stamp.src });
                refused.push(
                    QuarantineContainer::Edges,
                    &stamp.key(),
                    &full,
                    &stamp.value,
                );
            }
        }
        refused.commit_in_txn(vault, wtxn, now)
    })
}

/// The rows `brought`, an admitted update's entities, carries that this
/// vault does not store and that `with_birth` or the stamps `lane` holds
/// name, each with the bytes the update brings for it.
#[cfg(feature = "sync")]
pub(super) fn pending_births(
    vault: &Vault,
    lane: &str,
    brought: &loro::LoroMap,
    with_birth: &[HeldStamp],
) -> Result<Vec<(EntityId, Vec<u8>)>> {
    // Only a row's own spelling, with bytes, can be its birth; the entity
    // door refuses any other before it lands (Astra R7 F2 on #1432).
    let mut rows = Vec::new();
    map_for_each_value_bytes(brought, |key, value| {
        if let (Some(_), Ok(id)) = (value, EntityId::from_hex(key))
            && id.to_hex() == key
        {
            rows.push(id);
        }
    });
    // One lookup per row, not a scan of every stamp (Astra R10 F1 on #1432).
    let stamped: std::collections::BTreeSet<_> = with_birth.iter().map(|stamp| stamp.src).collect();
    let rtxn = vault.store.env.read_txn()?;
    let mut births = Vec::new();
    for src in rows {
        if crate::batch::stored_entity_type(&vault.store, &rtxn, &src)?.is_some() {
            continue;
        }
        if (stamped.contains(&src)
            || !facet_read::parked_under(&vault.store, &rtxn, src, lane)?.is_empty())
            && let Some(blob) = super::loro_support::map_get_bytes(brought, &src.to_hex())
        {
            births.push((src, blob));
        }
    }
    Ok(births)
}

/// Facet stamps released once their rows' births applied: the update that
/// writes the ones the type table admits, and the held copies to discard.
#[cfg(feature = "sync")]
pub(crate) struct ReleasedStamps {
    pub(crate) update: Option<Vec<u8>>,
    lane: String,
    stamps: Vec<(EntityId, EntityId)>,
}

#[cfg(feature = "sync")]
impl ReleasedStamps {
    /// Discards the held copies of the released stamps, once the update
    /// that writes them is imported.
    pub(crate) fn discard(&self, vault: &Vault) -> Result<()> {
        vault.with_write_txn_grouped(|wtxn| {
            for stamp in &self.stamps {
                facet_read::unpark_released(&vault.store, wtxn, *stamp, &self.lane)?;
            }
            Ok(())
        })
    }
}

/// After an update's import, the stamps on each of its `births` that the
/// import birthed: a row the import's entity door wrote where none was stored
/// (`born`, [`crate::sync::ingest::watch_births`]), and that stores exactly
/// the bytes the update brought for it. Its stamps are the update's own
/// (`with_birth`) and those `lane` holds. A row the write door refused, or
/// one another writer stored first, releases nothing, so no stamp of it
/// enters the window ahead of its sender's birth (Astra-b F1, Sol R10 F2 on
/// #1432). A released stamp the type table now proves off-table, its row born
/// typed, is dropped with typed evidence instead. `None` when nothing is
/// released.
#[cfg(feature = "sync")]
pub(super) fn release_born_stamps(
    vault: &Vault,
    key: &WindowKey,
    lane: &str,
    births: &[(EntityId, Vec<u8>)],
    born: &std::collections::BTreeSet<EntityId>,
    with_birth: &[HeldStamp],
) -> Result<Option<ReleasedStamps>> {
    let mut by_row = std::collections::BTreeMap::<_, Vec<_>>::new();
    for stamp in with_birth {
        by_row.entry(stamp.src).or_default().push(stamp);
    }
    let rtxn = vault.store.env.read_txn()?;
    let mut stamps = std::collections::BTreeMap::new();
    for (src, blob) in births {
        if !born.contains(src)
            || crate::ports::EntityStoreRead::port_entity_with_raw(&vault.store, &rtxn, src, |raw| {
                Ok(raw != blob.as_slice())
            })?
            .unwrap_or(true)
        {
            continue;
        }
        for (tgt, value) in facet_read::parked_under(&vault.store, &rtxn, *src, lane)? {
            stamps.insert((*src, tgt), value);
        }
        for stamp in by_row.get(src).into_iter().flatten() {
            stamps.insert((stamp.src, stamp.tgt), stamp.value.clone());
        }
    }
    if stamps.is_empty() {
        return Ok(None);
    }
    let mut refused = quarantine::TerminalRejectionBatch::new(key.as_str());
    let mut released = Vec::new();
    for (&(src, tgt), value) in &stamps {
        let edge = super::bridge::format_edge_key(&src, EdgeKind::FacetOf, &tgt);
        let src_type = crate::batch::stored_entity_type(&vault.store, &rtxn, &src)?;
        let tgt_type = crate::batch::stored_entity_type(&vault.store, &rtxn, &tgt)?;
        if crate::batch::facet_of_endpoints_provably_off_table(src_type, tgt_type) {
            let off_table = Error::Registry(RegistryError::InvalidFacetOfEdge {
                src,
                src_type,
                tgt,
                tgt_type,
            });
            refused.push(QuarantineContainer::Edges, &edge, &off_table, value);
        } else {
            released.push((edge, value.clone()));
        }
    }
    drop(rtxn);
    refused.commit(vault)?;
    let update = if released.is_empty() {
        None
    } else {
        Some(release_update(key, &released)?)
    };
    Ok(Some(ReleasedStamps {
        update,
        lane: lane.to_owned(),
        stamps: stamps.into_keys().collect(),
    }))
}

/// The update that writes `released`, each edge key with its value, into
/// the window. Its operation ids derive from what it writes, so devices that
/// release the same stamps author the same operations, and devices that
/// release different ones never author two contents under one id.
#[cfg(feature = "sync")]
fn release_update(key: &WindowKey, released: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
    let mut material = b"oneiron.federation.release.peer.v0".to_vec();
    let parts = released
        .iter()
        .flat_map(|(stamp, value)| [stamp.as_bytes(), value.as_slice()]);
    for part in std::iter::once(key.as_str().as_bytes()).chain(parts) {
        material.extend_from_slice(&(part.len() as u64).to_le_bytes());
        material.extend_from_slice(part);
    }
    let peer = match xxhash_rust::xxh3::xxh3_64(&material) {
        0 => 1,
        u64::MAX => u64::MAX - 1,
        peer => peer,
    };
    let doc = LoroDoc::new();
    doc.set_peer_id(peer)
        .map_err(|e| Error::sync_engine(crate::error::SyncEngineContext::LoroSetPeerId, e))?;
    let edges = doc.get_map("edges");
    for (stamp, value) in released {
        map_insert_bytes(&edges, stamp, value)?;
    }
    doc.commit();
    doc.export(ExportMode::all_updates())
        .map_err(|e| Error::sync_engine(crate::error::SyncEngineContext::LoroExportAllUpdates, e))
}

/// A `FacetOf` stamp an update sent onto a row this vault does not store.
#[cfg(feature = "sync")]
pub(super) struct HeldStamp {
    src: EntityId,
    tgt: EntityId,
    value: Vec<u8>,
}

#[cfg(feature = "sync")]
impl HeldStamp {
    fn key(&self) -> String {
        super::bridge::format_edge_key(&self.src, EdgeKind::FacetOf, &self.tgt)
    }

    /// The stamps of each of `groups` as the record a staged receipt keeps of
    /// them: each stamp's source, target, its value's length (u64 BE) and its
    /// value.
    pub(super) fn record(groups: &[&[Self]]) -> Vec<u8> {
        let mut record = Vec::new();
        for stamp in groups.iter().copied().flatten() {
            record.extend_from_slice(stamp.src.as_bytes());
            record.extend_from_slice(stamp.tgt.as_bytes());
            record.extend_from_slice(&(stamp.value.len() as u64).to_be_bytes());
            record.extend_from_slice(&stamp.value);
        }
        record
    }

    /// The stamps of a staged receipt's `record`, which the receipt binds by
    /// `digest` (none for one staged before the record existed, which has no
    /// record). A record edited, cut short or lost on disk, or one with a
    /// value admission would refuse, is refused here, before any is held
    /// again (Astra-d F1 on #1432).
    pub(super) fn from_receipt_record(
        record: &[u8],
        digest: Option<[u8; 32]>,
    ) -> Result<Vec<Self>> {
        let bound = match digest {
            Some(digest) => *blake3::hash(record).as_bytes() == digest,
            None => record.is_empty(),
        };
        Self::from_record(record)
            .filter(|stamps| {
                bound
                    && stamps.iter().all(|stamp| {
                        crate::edge::decode_edge_value_for_kind(EdgeKind::FacetOf, &stamp.value)
                            .is_ok()
                    })
            })
            .ok_or(Error::CorruptedIndex("staged facet stamps"))
    }

    /// A [`Self::record`] read back, or `None` for one that does not decode.
    fn from_record(mut record: &[u8]) -> Option<Vec<Self>> {
        let mut stamps = Vec::new();
        while !record.is_empty() {
            let (src, rest) = record.split_first_chunk::<16>()?;
            let (tgt, rest) = rest.split_first_chunk::<16>()?;
            let (len, rest) = rest.split_first_chunk::<8>()?;
            let (value, rest) =
                rest.split_at_checked(usize::try_from(u64::from_be_bytes(*len)).ok()?)?;
            stamps.push(Self {
                src: EntityId::from_bytes(*src).ok()?,
                tgt: EntityId::from_bytes(*tgt).ok()?,
                value: value.to_vec(),
            });
            record = rest;
        }
        Some(stamps)
    }
}

/// What the admission boundary does with one parsed edge row.
#[cfg(feature = "sync")]
enum AdmittedEdgeVerdict {
    /// On-table, not a `FacetOf` row at all, or a row whose DECIDING endpoint
    /// type is not knowable yet — copy it and let the replay gate own it.
    Copy,
    /// A stamp onto a row the update brings and this vault does not store:
    /// it waits for that birth to apply, and enters the document after it.
    WithBirth,
    /// A stamp whose source row neither this vault holds nor the update
    /// brings: hold it out of the document under the sender's lane.
    Hold,
    /// A stamp this vault already holds: a copy adds nothing, and is no
    /// rejection either.
    Drop,
    /// PROVABLY off-table on the facts in hand (a known off-table source, or
    /// a known non-FACET target, is each sufficient alone), or a new stamp
    /// onto a row this vault already holds. Drop with this typed rejection.
    DropRejected(Error),
}

/// An admitted source body can authorize an addressing edge; neither the
/// edge key nor the recipient's membership does. An unknown source or target
/// is tentative (H2): forward replay defers until both arrive.
#[cfg(feature = "sync")]
fn admitted_addressing_verdict(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source_entities: &loro::LoroMap,
    src: EntityId,
    tgt: EntityId,
    value: &[u8],
) -> Result<AdmittedEdgeVerdict> {
    let reject = || {
        AdmittedEdgeVerdict::DropRejected(Error::Registry(RegistryError::ReservedEdgeKind(
            "conversation_dag",
        )))
    };
    let local = crate::ports::EntityStoreRead::port_entity_raw_wiped(&vault.store, txn, &src)?;
    let staged = if local.is_none() {
        super::loro_support::map_get_bytes(source_entities, &src.to_hex())
    } else {
        None
    };
    let Some(raw) = local.as_deref().map(Vec::as_slice).or(staged.as_deref()) else {
        return Ok(AdmittedEdgeVerdict::Copy);
    };
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        // Malformed staged sources are refused by the entity door, not
        // permanently classified as an edge forgery here.
        return Ok(AdmittedEdgeVerdict::Copy);
    };
    if header.entity_type != crate::registry::ENTITY_TYPE_TURN {
        return Ok(reject());
    }
    if admitted_endpoint_type(vault, txn, source_entities, &tgt)?
        .is_some_and(|kind| kind != crate::registry::ENTITY_TYPE_PERSON)
    {
        return Ok(reject());
    }
    let Ok(fields) = crate::edge::decode_edge_value_for_kind(EdgeKind::AddressedTo, value) else {
        return Ok(reject());
    };
    let Some(body) = raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..) else {
        return Ok(reject());
    };
    match crate::conversation_dag::addressed_to_echo(body, header.learned_at, &tgt, fields) {
        Ok(true) => Ok(AdmittedEdgeVerdict::Copy),
        Ok(false) => Ok(reject()),
        Err(local_error) if local.is_some() => Err(local_error),
        Err(_) => Ok(reject()),
    }
}
/// Resolves the ONE-1645 `FacetOf` table for ONE admitted row.
///
/// Endpoint types resolve from two sources, in this order:
///
/// 1. the LOCAL vault row (`batch::stored_entity_type`) — entity type is
///    immutable per id ([`RegistryError::EntityTypeImmutable`](crate::error::RegistryError::EntityTypeImmutable)), so a stored type is
///    permanent truth about that id;
/// 2. the ADMITTED UPDATE's own entities map — the endpoint arriving in the
///    SAME frame as its stamp is the common legitimate case, and reading it
///    here is what keeps a well-formed peer from being forced through the
///    defer path on every first delivery.
///
/// The verdict is ONE-SIDED-sufficient
/// ([`crate::batch::facet_of_endpoints_provably_off_table`]): the table is a
/// conjunction of two independent per-endpoint predicates, so a KNOWN off-table
/// source alone proves the row bad no matter what its target turns out to be,
/// and a KNOWN non-FACET target alone proves it bad no matter what its source
/// turns out to be. Demanding BOTH endpoints before rejecting would let a
/// forger buy a pass by simply withholding the endpoint that is not the
/// incriminating one.
///
/// Only a row whose DECIDING endpoint stays unknowable passes through: the
/// endpoint has not arrived, and the remat gate's defer-then-validate owns it.
/// This is the H2 line — an unknowable type is not evidence of a forgery, and
/// treating it as one would wedge out-of-order delivery permanently. A row
/// whose SOURCE has not arrived is held instead of copied, and the source's
/// birth from the same sender releases it, so it still heals. Any residue is
/// inert on the export path regardless, because
/// [`facet_scope_by_source`] now honors a scope only from a row whose BOTH
/// endpoints resolve onto this same table.
///
/// The table itself is [`crate::batch::facet_of_endpoint_types_on_table`] and
/// its halves, the single copy the write/replay door also runs.
#[cfg(feature = "sync")]
fn admitted_facet_of_verdict(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    source_entities: &loro::LoroMap,
    brought: &loro::LoroMap,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
) -> Result<AdmittedEdgeVerdict> {
    if kind != EdgeKind::FacetOf {
        return Ok(AdmittedEdgeVerdict::Copy);
    }
    let src_type = admitted_endpoint_type(vault, rtxn, source_entities, &src)?;
    let tgt_type = admitted_endpoint_type(vault, rtxn, source_entities, &tgt)?;
    if crate::batch::facet_of_endpoints_provably_off_table(src_type, tgt_type) {
        return Ok(AdmittedEdgeVerdict::DropRejected(Error::Registry(
            RegistryError::InvalidFacetOfEdge {
                src,
                src_type,
                tgt,
                tgt_type,
            },
        )));
    }
    // A peer places only a row whose birth it brings. A stamp onto a row
    // this vault already holds puts the row in a facet it was not born in,
    // and a narrowed reader reads a row in ANY of its facets, so an added
    // stamp only widens who reads it (Astra on #1432). A stamp this vault
    // already holds adds nothing and goes no further either: the checks a
    // frame's surviving edges meet later would tell the peer which stamps a
    // row it cannot read holds (Astra R8 F1). A stamp onto a row this vault
    // lacks waits for the row's birth, never for its presence in the update.
    if crate::batch::stored_entity_type(&vault.store, rtxn, &src)?.is_none() {
        return Ok(
            if super::loro_support::map_contains_binary(brought, &src.to_hex()) {
                AdmittedEdgeVerdict::WithBirth
            } else {
                AdmittedEdgeVerdict::Hold
            },
        );
    }
    Ok(match restamp_of_stored_row(vault, rtxn, src, tgt)? {
        Some(refusal) => AdmittedEdgeVerdict::DropRejected(refusal),
        None => AdmittedEdgeVerdict::Drop,
    })
}

/// The refusal for a stamp `src -FacetOf-> tgt` onto a row this vault stores
/// that does not already hold it; `None` for any other row.
#[cfg(feature = "sync")]
fn restamp_of_stored_row(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    src: EntityId,
    tgt: EntityId,
) -> Result<Option<Error>> {
    let stored = crate::batch::stored_entity_type(&vault.store, rtxn, &src)?.is_some()
        && crate::ports::EdgeStoreRead::port_edge_get(
            &vault.store,
            rtxn,
            &src,
            EdgeKind::FacetOf,
            &tgt,
        )?
        .is_none();
    Ok(stored.then_some(Error::Registry(RegistryError::FacetStampImmutable { src })))
}

/// Refuses already admitted bytes that carry a facet stamp. This door keeps
/// every stamp onto a row this vault lacks out of the bytes it admits, until
/// the row's birth from the same sender has applied, so one in staged bytes
/// was admitted by an older door with no birth bound to it (Astra-b F1 on
/// #1432).
#[cfg(feature = "sync")]
pub(super) fn refuse_admitted_stamps(edges: &loro::LoroMap) -> Result<()> {
    let mut result = Ok(());
    map_for_each_value_bytes(edges, |key, _| {
        if result.is_ok()
            && let Some((src, EdgeKind::FacetOf, _)) = super::bridge::parse_edge_key(key)
        {
            result = Err(Error::Registry(RegistryError::FacetStampImmutable { src }));
        }
    });
    result
}

/// One endpoint's type byte at admission time: the stored row first (permanent
/// truth — entity type is immutable per id), then the admitted update's own
/// entities map. `None` = not knowable yet.
///
/// A remote blob too short to carry a header is NOT a local defect and must
/// not fail the admission closed — it is unparsable REMOTE input, which the
/// entity pass and the replay door already reject on their own terms. It reads
/// as unknowable here, so a forged stamp cannot dodge the table by shipping a
/// truncated endpoint blob: the endpoint never materializes, so the stamp's
/// source never becomes exportable either.
#[cfg(feature = "sync")]
fn admitted_endpoint_type(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    source_entities: &loro::LoroMap,
    id: &EntityId,
) -> Result<Option<u8>> {
    if let Some(stored) = crate::batch::stored_entity_type(&vault.store, rtxn, id)? {
        return Ok(Some(stored));
    }
    // The header only, read in place: a copy of the body per stamp would let
    // one large row and many stamps multiply admission's work (Astra R11 F2
    // on #1432).
    Ok(match source_entities.get(&id.to_hex()) {
        Some(loro::ValueOrContainer::Value(loro::LoroValue::Binary(blob))) => {
            EntityMetadataHeader::parse(&blob[..]).map(|header| header.entity_type)
        }
        _ => None,
    })
}
