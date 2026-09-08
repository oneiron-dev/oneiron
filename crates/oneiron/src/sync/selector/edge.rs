//! Admitted-edge copy with reserved-kind rejection and the FacetOf off-table verdict.

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::sync::loro_support::{map_for_each_value_bytes, map_insert_bytes};
#[cfg(feature = "sync")]
use crate::sync::quarantine::{self, QuarantineContainer};
use crate::sync::types::WindowKey;

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
///   typed [`Error::InvalidFacetOfEdge`] quarantine record. The row is not
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
#[cfg(feature = "sync")]
pub(super) fn copy_admitted_edges(
    vault: &Vault,
    window_key: &WindowKey,
    source_entities: &loro::LoroMap,
    source: &loro::LoroMap,
    target: &loro::LoroMap,
) -> Result<()> {
    let rtxn = vault.store.env.read_txn()?;
    let mut rejections = quarantine::TerminalRejectionBatch::new(window_key.as_str());
    let mut result = Ok(());
    map_for_each_value_bytes(source, |key, value| {
        if result.is_err() {
            return;
        }
        if let Some((src, kind, tgt)) = super::bridge::parse_edge_key(key) {
            if let Err(reserved) = crate::edge::validate_public_edge_kind(kind) {
                result = Err(reserved);
                return;
            }
            match admitted_facet_of_verdict(vault, &rtxn, source_entities, src, kind, tgt) {
                Ok(AdmittedEdgeVerdict::Copy) => {}
                Ok(AdmittedEdgeVerdict::DropOffTable(off_table)) => {
                    // Quarantine-and-continue: the peer's forged row gets
                    // typed durable evidence, the window's other N-1 rows
                    // still admit. `payload` is the raw value when present.
                    rejections.push(
                        QuarantineContainer::Edges,
                        key,
                        &off_table,
                        value.unwrap_or(&[]),
                    );
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
        result = value
            .ok_or(Error::InvalidKey)
            .and_then(|bytes| map_insert_bytes(target, key, bytes));
    });
    result?;
    // Evidence commits only once the copy pass itself succeeded: a pass that
    // fails closed admits nothing, so recording peer rejections from a frame
    // this vault refused whole would be an account of a thing that never
    // happened.
    drop(rtxn);
    rejections.commit(vault)
}

/// What the admission boundary does with one parsed edge row.
#[cfg(feature = "sync")]
enum AdmittedEdgeVerdict {
    /// On-table, not a `FacetOf` row at all, or a row whose DECIDING endpoint
    /// type is not knowable yet — copy it and let the replay gate own it.
    Copy,
    /// PROVABLY off-table on the facts in hand: a known off-table source, or a
    /// known non-FACET target, is each sufficient alone. Drop with this typed
    /// rejection.
    DropOffTable(Error),
}

/// Resolves the ONE-1645 `FacetOf` table for ONE admitted row.
///
/// Endpoint types resolve from two sources, in this order:
///
/// 1. the LOCAL vault row (`batch::stored_entity_type`) — entity type is
///    immutable per id ([`Error::EntityTypeImmutable`]), so a stored type is
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
/// treating it as one would wedge out-of-order delivery permanently. That
/// residue is inert on the export path regardless, because
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
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
) -> Result<AdmittedEdgeVerdict> {
    if kind != EdgeKind::FacetOf {
        return Ok(AdmittedEdgeVerdict::Copy);
    }
    let src_type = admitted_endpoint_type(vault, rtxn, source_entities, &src)?;
    let tgt_type = admitted_endpoint_type(vault, rtxn, source_entities, &tgt)?;
    if !crate::batch::facet_of_endpoints_provably_off_table(src_type, tgt_type) {
        return Ok(AdmittedEdgeVerdict::Copy);
    }
    Ok(AdmittedEdgeVerdict::DropOffTable(
        Error::InvalidFacetOfEdge {
            src,
            src_type,
            tgt,
            tgt_type,
        },
    ))
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
    Ok(
        super::loro_support::map_get_bytes(source_entities, &id.to_hex())
            .as_deref()
            .and_then(EntityMetadataHeader::parse)
            .map(|header| header.entity_type),
    )
}
