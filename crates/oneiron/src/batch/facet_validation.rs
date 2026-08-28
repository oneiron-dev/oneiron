use super::*;

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_TURN};
use crate::store::Store;

/// Reads an entity's registry type byte. `None` means no entity row exists —
/// the type is unknowable, not merely unexpected. A row that exists but whose
/// header will not parse is a LOCAL defect ([`Error::CorruptedIndex`]), never
/// an unknowable type: callers must fail closed on it rather than charge it to
/// a peer.
pub(crate) fn stored_entity_type(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<u8>> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    Ok(Some(header.entity_type))
}

/// ONE-1645 write-time type table for `FacetOf` (u8 17) edges: a facet stamp
/// may only run `CLAIM | TURN | EVENT → FACET`. Anything else — including an
/// endpoint with no entity row, whose type is unknowable — is a typed
/// [`Error::InvalidFacetOfEdge`] that aborts the batch atomically. This
/// mirrors the fail-closed-on-missing shape [`Error::InvalidFacet`] already
/// uses on the read side: a stamp's endpoints must be established facts
/// before the stamp.
///
/// TWO SEMANTICS ride one edge kind, and the table admits both:
///
/// * `CLAIM | TURN → FACET` — DISCLOSURE-SCOPING. These are the stamps
///   [`crate::pipeline`]'s facet filter reads: `claim_facet_scope`
///   prefix-scans `edges_out` under a CLAIM source, and strict mode drops
///   claims scoped exclusively to other facets. TURN is admitted alongside
///   CLAIM because per-turn facet stamps are what transcript filtering rides;
///   the write door must accept the stamp the design requires.
/// * `EVENT → FACET` — WORLD-MODEL traversal, and disclosure-effective on the
///   FEDERATION door. It exists for ARCH-0039 PPR traversal, where `facet_of`
///   carries a pinned λ of 0.05 ([`crate::ppr::lambda_for_kind`]) — rejecting
///   it would make a ratified traversal contract unwritable — but "world-model"
///   is not "disclosure-inert". See the two-door reading below.
///
/// TWO DISCLOSURE DOORS read `FacetOf`, and a source type may be effective on
/// one while inert on the other. Neither door is the whole exposure surface:
///
/// * LOCAL QUERY door — [`crate::pipeline`]'s facet filter. `apply_facet_filter`
///   keeps every non-CLAIM entity unconditionally and `claim_facet_scope`
///   prefix-scans `edges_out` under a CLAIM source only. CLAIM-sourced stamps
///   are effective here; TURN- and EVENT-sourced stamps are INERT on this door.
/// * FEDERATION door — `crate::sync::selector`. `facet_scope_by_source` builds
///   a `FacetScope` for every `FacetOf` row THIS TABLE ADMITS ON BOTH ENDS (it
///   runs [`facet_of_endpoint_types_on_table`] as a read mirror), and
///   `entity_selector_decision` withholds an entity of ANY type whose scope is
///   malformed or touches an unselected facet from a facet-limited peer.
///   CLAIM-, TURN-, AND EVENT-sourced stamps are all disclosure-EFFECTIVE here:
///   an EVENT stamped to an unselected facet is withheld from that peer. A row
///   OFF the table on either end carries no scope on this door — the shape is
///   unwritable, so a copy that slipped past a write door is not honored on
///   read.
///
/// The teeth are unchanged by the widening: a missing endpoint still fails
/// closed, the target must still be a FACET, and every source type outside
/// {CLAIM, TURN, EVENT} is still rejected.
///
/// Ordering: ops apply in order inside one write txn, so an entity put and
/// the edge that stamps it commit together in a single batch. An edge that
/// precedes its endpoint's put fails closed.
///
/// Seam (ONE-1646): the exposure-consent gate — rejecting a private→public
/// restamp without a consent-ledger row, and gating `FacetOf` deletes on
/// exposure state — lands at THIS call site once facet exposure state exists.
/// That gate keys on ALL admitted source types (`CLAIM | TURN | EVENT`): each
/// is disclosure-effective on at least one of the two doors above, so none may
/// bypass exposure gating. The gate table is derived from CURRENT door
/// behavior — `crate::sync::selector::tests` pins the federation half — and it
/// stays derivable BY CONSTRUCTION now that the selector mirrors this very
/// pair predicate: widening or narrowing the table here moves both doors and
/// the gate table together. This function is the hook; it deliberately
/// validates types only.
pub(crate) fn validate_facet_of_edge(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
) -> Result<()> {
    if kind != EdgeKind::FacetOf {
        return Ok(());
    }
    let src_type = stored_entity_type(store, rtxn, &src)?;
    let tgt_type = stored_entity_type(store, rtxn, &tgt)?;
    if let (Some(src_type), Some(tgt_type)) = (src_type, tgt_type)
        && facet_of_endpoint_types_on_table(src_type, tgt_type)
    {
        return Ok(());
    }
    Err(Error::InvalidFacetOfEdge {
        src,
        src_type,
        tgt,
        tgt_type,
    })
}

/// The ONE-1645 `FacetOf` table as a pure predicate over KNOWN endpoint types.
///
/// Every door runs the same table and they resolve types differently, so the
/// table itself lives here exactly once, decomposed into its two independent
/// per-endpoint halves ([`facet_of_source_type_admitted`] /
/// [`facet_of_target_type_admitted`]) so a door that knows only ONE endpoint
/// can still consult it without forking a second copy:
///
/// * [`validate_facet_of_edge`] — the write/replay door. Types come from
///   STORED entity rows, and an endpoint with no row is unknowable, which that
///   door treats as fail-closed (a stamp's endpoints must be established facts
///   before the stamp).
/// * the FEDERATION ADMISSION boundary
///   (`crate::sync::selector::admit_federated_window_update`). Types come from
///   the local vault OR from the admitted update's own entities map, and it
///   rejects on ANY SUFFICIENT FACT via
///   [`facet_of_endpoints_provably_off_table`] — an endpoint that stays
///   unknowable DEFERS to the replay door instead of failing closed, because a
///   not-yet-arrived endpoint must not wedge out-of-order delivery (H2).
/// * the FEDERATION SELECTOR's read mirror
///   (`crate::sync::selector::facet_scope_by_source`). It honors a `FacetOf`
///   scope only when BOTH endpoints resolve onto this table, so it calls the
///   PAIR predicate. Types resolve STORED-FIRST (as at the admission door),
///   and where the stored row and the document blob DISAGREE the stored type
///   WINS, in BOTH endpoint roles: the conflicting blob is a write the
///   immutability gate rejected, and a rejected write is never consulted for
///   anything. STORED TRUTH NEVER LOSES TO A REJECTED WRITE, IN EITHER ROLE,
///   so a peer-controlled conflict can never move a row from withheld to
///   exported, nor from contained to seeded. A row failing either half is
///   SCOPE-INERT — never a seed, never a withhold — because letting an
///   unwritable row DENY would hand a peer a suppression primitive against
///   the host's own entities.
///
/// A second copy of the pair table would drift from this one silently; the
/// admission door's whole job is to reject exactly what the replay door
/// rejects, one layer earlier, and the selector's is to READ exactly what the
/// write doors would have let be WRITTEN.
#[must_use]
pub(crate) const fn facet_of_endpoint_types_on_table(src_type: u8, tgt_type: u8) -> bool {
    facet_of_source_type_admitted(src_type) && facet_of_target_type_admitted(tgt_type)
}

/// Source half of the table: the types that may STAMP a facet.
#[must_use]
pub(crate) const fn facet_of_source_type_admitted(src_type: u8) -> bool {
    matches!(
        src_type,
        ENTITY_TYPE_CLAIM | ENTITY_TYPE_TURN | ENTITY_TYPE_EVENT
    )
}

/// Target half of the table: the only type a facet stamp may point AT.
#[must_use]
pub(super) const fn facet_of_target_type_admitted(tgt_type: u8) -> bool {
    tgt_type == ENTITY_TYPE_FACET
}

/// ONE-SIDED verdict over PARTIALLY-known endpoint types: is this row's
/// off-table status already PROVEN by the facts in hand?
///
/// The table is a CONJUNCTION of two independent per-endpoint predicates, so
/// either conjunct alone can falsify it. Requiring both endpoints to be known
/// before rejecting — the over-narrow reading fix-4 shipped — hands a forger a
/// free pass: bundle a provably-bad PERSON source with a target that has not
/// arrived, and a "both known" check reads the row as merely unknowable and
/// copies it through.
///
/// * source known and outside the admitted set → PROVEN off-table, whatever
///   the target turns out to be;
/// * target known and not a FACET → PROVEN off-table, whatever the source
///   turns out to be;
/// * everything else (both known and on-table, or the deciding endpoint still
///   unknowable) → NOT proven here. Both-known-and-on-table is a genuine pass;
///   genuinely-unknowable defers to the replay door (H2).
///
/// `false` therefore means "no proof yet", never "proven fine".
///
/// The only caller is `sync::selector`, but the fn stays COMPILED without the
/// feature so the ungated `crate::batch::` re-export keeps resolving; the
/// attribute mirrors that re-export's own `cfg_attr`.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
#[must_use]
pub(crate) const fn facet_of_endpoints_provably_off_table(
    src_type: Option<u8>,
    tgt_type: Option<u8>,
) -> bool {
    let source_disproves = match src_type {
        Some(src_type) => !facet_of_source_type_admitted(src_type),
        None => false,
    };
    let target_disproves = match tgt_type {
        Some(tgt_type) => !facet_of_target_type_admitted(tgt_type),
        None => false,
    };
    source_disproves || target_disproves
}
