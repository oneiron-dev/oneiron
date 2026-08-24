use super::*;

use heed::RwTxn;

use crate::affect::Vad;
use crate::edge::{
    EDGE_KEY_LEN, EDGE_VALUE_SEMANTIC_LEN, EDGE_VALUE_SEMANTIC_PROVENANCED_LEN,
    EDGE_VALUE_STRUCTURAL_LEN, EdgeKind, EdgeProvenanceFlags, encode_edge_value,
    validate_edge_weight,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;

/// Applies one PUBLIC plain edge put (`BatchOp::Edge` — the op behind
/// `Vault::put_edge`, `Vault::put_edge_with_vad`, and the `edge` /
/// `edge_checked` / `edge_with_vad` batch builders).
///
/// ONE-1113 reject-and-route gate (ARCH-0034 #write-protection, ratified
/// 2026-06-13): a plain put carries no provenance, so re-encoding an edge
/// whose stored value is the 26-byte provenanced layout would silently drop
/// the two hot-flag bytes to 24 bytes in BOTH directions while the truth
/// `edge.provenance` Claim stays live. "An unattributed write can never
/// displace attributed truth as current state" — the put is rejected with
/// the typed [`Error::EdgeIsProvenanced`], whose message routes the caller
/// to the provenance path (`put_edge_provenance` / the `as_actor`-bound
/// surface) and the operational setters (`set_edge_weight` /
/// `set_edge_vad`). Layout dispatch is VALUE LENGTH (no tag byte; the
/// read-back mirrors `restamp_edge_flags`). A plain put on a bare or absent
/// edge is unchanged: absence of provenance is itself the anonymous
/// representation.
pub(super) fn apply_edge(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
    weight: f32,
    vad: Vad,
) -> Result<()> {
    reject_if_existing_edge_is_provenanced(store, wtxn, src, kind, tgt)?;
    apply_edge_with_created_at(
        store,
        wtxn,
        src,
        kind,
        tgt,
        weight,
        crate::unix_seconds_now(),
        vad,
        None,
    )
}

pub(super) fn reject_if_existing_edge_is_provenanced(
    store: &Store,
    wtxn: &RwTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
) -> Result<()> {
    debug_assert_eq!(
        EDGE_VALUE_SEMANTIC_PROVENANCED_LEN,
        EDGE_VALUE_SEMANTIC_LEN + 2,
        "provenanced-edge detection is layout-length based; update the reject gate if the hot-flag layout changes"
    );
    let key_out = Store::encode_edge_key(&src, kind, &tgt);
    if let Some(existing) = store.edges_out.get(wtxn, &key_out)?
        && existing.len() == EDGE_VALUE_SEMANTIC_PROVENANCED_LEN
    {
        return Err(Error::EdgeIsProvenanced { kind: kind as u8 });
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "decomposing would obscure direct LMDB write logic"
)]
pub(super) fn apply_public_edge_with_created_at(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
    weight: f32,
    created_at: u64,
    vad: Vad,
) -> Result<()> {
    reject_if_existing_edge_is_provenanced(store, wtxn, src, kind, tgt)?;
    apply_edge_with_created_at(store, wtxn, src, kind, tgt, weight, created_at, vad, None)
}

/// Reads the existing edge value for an operational setter (ONE-1113):
/// the setters rewrite bytes of an EXISTING value and never upsert —
/// a missing edge is the typed [`Error::EdgeNotFound`]. The value length
/// must be one of the three contract layouts (12/24/26 B); anything else is
/// [`Error::CorruptedIndex`], mirroring `restamp_edge_flags`.
pub(super) fn read_edge_value_for_setter(
    store: &Store,
    wtxn: &RwTxn<'_>,
    key_out: &[u8; EDGE_KEY_LEN],
) -> Result<Vec<u8>> {
    let existing = store
        .edges_out
        .get(wtxn, key_out)?
        .map(|value| value.to_vec())
        .ok_or(Error::EdgeNotFound)?;
    match existing.len() {
        EDGE_VALUE_STRUCTURAL_LEN
        | EDGE_VALUE_SEMANTIC_LEN
        | EDGE_VALUE_SEMANTIC_PROVENANCED_LEN => Ok(existing),
        _ => Err(Error::CorruptedIndex("edge value")),
    }
}

/// ONE-1113 operational weight setter: rewrites ONLY the weight bytes
/// (f32 LE at offset 0..4 — present on ALL three layouts) of an existing
/// edge value and writes IDENTICAL bytes to both `edges_out` and `edges_in`.
/// Every other byte — `created_at`, VAD, and the provenance hot flags at
/// offsets 24/25 when the value is 26 B — is preserved verbatim, so the
/// setter can never displace attributed truth (exempt from the
/// reject-and-route gate by construction; M3 weight pin: weight is a LOCAL
/// operational field).
pub(super) fn apply_set_edge_weight(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
    weight: f32,
) -> Result<()> {
    validate_edge_weight(weight)?;
    let key_out = Store::encode_edge_key(&src, kind, &tgt);
    let key_in = Store::encode_edge_key(&tgt, kind, &src);
    let mut value = read_edge_value_for_setter(store, wtxn, &key_out)?;
    value[0..4].copy_from_slice(&weight.to_le_bytes());
    store.edges_out.put(wtxn, &key_out, &value)?;
    store.edges_in.put(wtxn, &key_in, &value)?;
    Ok(())
}

/// ONE-1113 operational VAD setter: rewrites ONLY the VAD bytes (three
/// f32 LE at offset 12..24) of an existing SEMANTIC edge value and writes
/// IDENTICAL bytes to both `edges_out` and `edges_in`. Weight, `created_at`,
/// the value LENGTH (24 B stays 24 B, 26 B stays 26 B), and the provenance
/// hot flags at offsets 24/25 are preserved verbatim. Structural 12-byte
/// edges carry no VAD (contract layout table) and fail typed — never a
/// silent widen.
pub(super) fn apply_set_edge_vad(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
    vad: Vad,
) -> Result<()> {
    if let Some((component, value)) = vad.invalid_component() {
        return Err(Error::InvalidVad { component, value });
    }
    let key_out = Store::encode_edge_key(&src, kind, &tgt);
    let key_in = Store::encode_edge_key(&tgt, kind, &src);
    let mut value = read_edge_value_for_setter(store, wtxn, &key_out)?;
    if value.len() == EDGE_VALUE_STRUCTURAL_LEN {
        return Err(Error::InvariantViolation(
            "structural edges do not carry VAD",
        ));
    }
    value[12..16].copy_from_slice(&vad.valence.to_le_bytes());
    value[16..20].copy_from_slice(&vad.arousal.to_le_bytes());
    value[20..24].copy_from_slice(&vad.dominance.to_le_bytes());
    store.edges_out.put(wtxn, &key_out, &value)?;
    store.edges_in.put(wtxn, &key_in, &value)?;
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "decomposing would obscure direct LMDB write logic"
)]
// UNGATED by design — this is the replicated/replay shape. A
// bare-over-provenanced LWW edge is a legitimate remote winner; gating here
// would turn a legitimate remote merge into a permanent local sync-wedging
// abort (H2). The public timestamped builders route through the gated
// `PublicEdgeWithCreatedAt` arm instead.
pub(super) fn apply_edge_with_created_at(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
    weight: f32,
    created_at: u64,
    vad: Vad,
    provenance: Option<EdgeProvenanceFlags>,
) -> Result<()> {
    validate_edge_weight(weight)?;
    if let Some((component, value)) = vad.invalid_component() {
        return Err(Error::InvalidVad { component, value });
    }

    let value = encode_edge_value(kind, weight, created_at, vad, provenance)?;
    stage_edge_rows(store, wtxn, &src, kind, &tgt, &value)
}

pub(super) fn apply_delete_edge(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
) -> Result<bool> {
    let key_out = Store::encode_edge_key(&src, kind, &tgt);
    let key_in = Store::encode_edge_key(&tgt, kind, &src);
    let deleted_out = store.edges_out.delete(wtxn, &key_out)?;
    let _deleted_in = store.edges_in.delete(wtxn, &key_in)?;
    Ok(deleted_out)
}
