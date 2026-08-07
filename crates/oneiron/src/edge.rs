//! Edge kinds, layouts, value codec, strict edge-record parsing, `EdgeInfo`.

use crate::affect::Vad;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};

pub(crate) const EDGE_KEY_LEN: usize = 33;

pub(crate) const EDGE_VALUE_STRUCTURAL_LEN: usize = 12;

pub(crate) const EDGE_VALUE_SEMANTIC_LEN: usize = 24;

pub(crate) const EDGE_VALUE_SEMANTIC_PROVENANCED_LEN: usize = 26;

/// Relationship kind used by graph edges.
///
/// Storage ABI: these discriminants are pinned to the ARCH-0034 `edgeKinds`
/// registry. They are encoded into `edges_out`/`edges_in` keys and EdgeRef/CRDT
/// edge-key refs; vaults written with the pre-M0-1 order need the M0-4
/// schema-version migration (ONE-1081) before those bytes are read under this
/// ordering.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EdgeKind {
    /// Entity belongs to another entity.
    BelongsTo = 4,
    /// Entity participates in another entity.
    ParticipatesIn = 13,
    /// Entity is attached to another entity.
    Attached = 14,
    /// Entity was authored by another entity.
    AuthoredBy = 0,
    /// Entity mentions another entity.
    Mentions = 9,
    /// Entity is about another entity.
    About = 10,
    /// Entity supports another entity.
    Supports = 11,
    /// Entity opposes another entity.
    Opposes = 12,
    /// Entity is a claim of another entity.
    ClaimOf = 5,
    /// Entity is scoped to another entity.
    ScopedTo = 1,
    /// Entity supersedes another entity.
    Supersedes = 3,
    /// Entity is derived from another entity.
    DerivedFrom = 8,
    /// Entity is part of another entity.
    PartOf = 2,
    /// Person is employed by an organization.
    EmployedBy = 15,
    /// Person has a behavioral facet.
    HasFacet = 16,
    /// Person exists in a world context.
    InWorld = 18,
    /// Claim is scoped to a facet.
    FacetOf = 17,
    /// Relationship is set in a world context.
    SetIn = 19,
    /// Task is a child of another task (tree hierarchy).
    /// Never traversed by PPR (contract `lambda: null`, "Not traversed.");
    /// read via the dedicated `subtree` / `ancestors` tree APIs.
    ChildOf = 6,
    /// Task is assigned to a machine for execution.
    /// Never traversed by PPR (contract `lambda: null`, "Not traversed.").
    AssignedTo = 7,
    /// Entity was merged into a surviving entity (ARCH-0055 r1). Canonical
    /// D11 redirect edge — sole source of truth, no body-field twin; the
    /// source entity is a `merged` redirect shell, never a tombstone.
    /// Writes are reserved to the identity-topology apply/undo door.
    MergedInto = 21,
    /// Entity was split into a head entity (ARCH-0055 r2). Canonical D11
    /// redirect edge — the original resolves to its head SET. Writes are
    /// reserved to the identity-topology apply/undo door.
    SplitInto = 22,
    /// Two PERSON entities are the same person across vaults (ONE-1414).
    ///
    /// A structural, NON-TRAVERSING identity link: `lambda_for_kind` is
    /// `None`, which IS the no-pooling contract. The link states coreference
    /// and nothing else — no claim of either endpoint is copied, rewritten,
    /// re-sourced, or re-worlded, and retrieval seeded on one endpoint never
    /// reaches the other's claims through it. It carries no stored-weight
    /// prior (writers pass an explicit `0.0`), and its status and per-pact
    /// share consent live in `core.coreference.*` edge-subject Claims rather
    /// than in the edge bytes.
    SameAs = 20,
    /// Task is blocked by another task — a directed TASK → TASK ordering
    /// dependency; wave DAGs ride it. Never traversed by PPR or the
    /// context-pack walk (contract `lambda: null`, "Not traversed."), like
    /// `child_of`. Readiness stays COMPUTED at read time over task status
    /// plus outgoing `blocked_by` edges (ARCH-0068 §RC5): this edge is the
    /// sole source of truth, with no stored counter, `blocked` status, or
    /// materialized projection twinning it.
    BlockedBy = 23,
}

impl EdgeKind {
    /// Returns the default STORED edge weight for this edge kind — the
    /// LITERAL `pprWeight` column of the contract's `edgeKinds` table
    /// (oneiron-docs `site/src/data/oneiron-contracts.ts`, ARCH-0019 PPR
    /// edge-kinds priors). `None` mirrors the contract's `pprWeight: null`
    /// rows exactly: `child_of`, `assigned_to`, and `blocked_by` carry no
    /// stored-weight prior, so callers writing such edges must choose a
    /// weight explicitly. `same_as` joins that set: an identity link carries
    /// no retrieval prior at all, and its owning door writes an explicit
    /// `0.0`.
    ///
    /// This is NOT the PPR traversal multiplier: per-kind traversal budgets
    /// are the λ_τ table (`ppr::lambda_for_kind`), which deliberately differs
    /// from this prior for the five world-model kinds, and `ChildOf` /
    /// `AssignedTo` / `BlockedBy` are never traversed by PPR regardless of
    /// the weight stored on their edges.
    pub const fn default_weight(self) -> Option<f32> {
        match self {
            Self::BelongsTo => Some(1.0),
            Self::ParticipatesIn => Some(1.0),
            Self::Attached => Some(0.8),
            Self::AuthoredBy => Some(0.9),
            Self::Mentions => Some(0.6),
            Self::About => Some(0.5),
            Self::Supports => Some(1.0),
            Self::Opposes => Some(0.0),
            Self::ClaimOf => Some(1.0),
            Self::ScopedTo => Some(0.7),
            Self::Supersedes => Some(0.3),
            Self::DerivedFrom => Some(0.2),
            Self::PartOf => Some(0.8),
            Self::EmployedBy => Some(0.8),
            Self::HasFacet => Some(0.7),
            Self::InWorld => Some(0.7),
            Self::FacetOf => Some(0.7),
            Self::SetIn => Some(0.7),
            Self::ChildOf => None,
            Self::AssignedTo => None,
            Self::BlockedBy => None,
            Self::SameAs => None,
            // Identity-plumbing prior mirroring `supersedes` (0.3).
            Self::MergedInto => Some(0.3),
            Self::SplitInto => Some(0.3),
        }
    }

    /// Converts a raw discriminant into an edge kind.
    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::AuthoredBy),
            1 => Some(Self::ScopedTo),
            2 => Some(Self::PartOf),
            3 => Some(Self::Supersedes),
            4 => Some(Self::BelongsTo),
            5 => Some(Self::ClaimOf),
            6 => Some(Self::ChildOf),
            7 => Some(Self::AssignedTo),
            8 => Some(Self::DerivedFrom),
            9 => Some(Self::Mentions),
            10 => Some(Self::About),
            11 => Some(Self::Supports),
            12 => Some(Self::Opposes),
            13 => Some(Self::ParticipatesIn),
            14 => Some(Self::Attached),
            15 => Some(Self::EmployedBy),
            16 => Some(Self::HasFacet),
            17 => Some(Self::FacetOf),
            18 => Some(Self::InWorld),
            19 => Some(Self::SetIn),
            20 => Some(Self::SameAs),
            21 => Some(Self::MergedInto),
            22 => Some(Self::SplitInto),
            23 => Some(Self::BlockedBy),
            _ => None,
        }
    }
}

/// Storage layout class for an edge value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeValueLayout {
    Structural,
    SemanticBare,
    SemanticProvenanced,
}

impl EdgeValueLayout {
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::Structural => EDGE_VALUE_STRUCTURAL_LEN,
            Self::SemanticBare => EDGE_VALUE_SEMANTIC_LEN,
            Self::SemanticProvenanced => EDGE_VALUE_SEMANTIC_PROVENANCED_LEN,
        }
    }

    fn from_len(len: usize) -> Option<Self> {
        match len {
            EDGE_VALUE_STRUCTURAL_LEN => Some(Self::Structural),
            EDGE_VALUE_SEMANTIC_LEN => Some(Self::SemanticBare),
            EDGE_VALUE_SEMANTIC_PROVENANCED_LEN => Some(Self::SemanticProvenanced),
            _ => None,
        }
    }
}

/// Hot confirmation flag cached on a 26-byte semantic-provenanced edge.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeConfirmationStatus {
    Proposed = 0,
    Confirmed = 1,
    Disputed = 2,
    Retracted = 3,
}

impl EdgeConfirmationStatus {
    fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Proposed),
            1 => Some(Self::Confirmed),
            2 => Some(Self::Disputed),
            3 => Some(Self::Retracted),
            _ => None,
        }
    }
}

/// Hot actor-class flag cached on a 26-byte semantic-provenanced edge.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeActorClass {
    Human = 0,
    Agent = 1,
    System = 2,
}

impl EdgeActorClass {
    pub(crate) fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Human),
            1 => Some(Self::Agent),
            2 => Some(Self::System),
            _ => None,
        }
    }

    /// Actor-class key used by Gate `actor_ceilings` policy rows.
    #[must_use]
    pub const fn gate_actor_class(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
            Self::System => "system",
        }
    }
}

/// Two hot provenance flags derived from the `edge.provenance` Claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeProvenanceFlags {
    pub confirmation_status: EdgeConfirmationStatus,
    pub actor_class: EdgeActorClass,
}

/// Decoded fixed-width edge value fields.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DecodedEdgeValue {
    pub layout: EdgeValueLayout,
    pub weight: f32,
    pub created_at: u64,
    pub vad: Option<Vad>,
    pub provenance: Option<EdgeProvenanceFlags>,
}

/// Selects the value layout for writes. Reads dispatch on value length.
pub(crate) fn edge_value_layout_for_kind(
    kind: EdgeKind,
    has_provenance_claim: bool,
) -> EdgeValueLayout {
    match kind {
        EdgeKind::AuthoredBy
        | EdgeKind::ScopedTo
        | EdgeKind::PartOf
        | EdgeKind::Supersedes
        | EdgeKind::BelongsTo
        | EdgeKind::ClaimOf
        | EdgeKind::ChildOf
        | EdgeKind::AssignedTo
        | EdgeKind::DerivedFrom
        | EdgeKind::MergedInto
        | EdgeKind::SplitInto
        | EdgeKind::BlockedBy
        | EdgeKind::SameAs => EdgeValueLayout::Structural,
        EdgeKind::Mentions
        | EdgeKind::About
        | EdgeKind::Supports
        | EdgeKind::Opposes
        | EdgeKind::ParticipatesIn
        | EdgeKind::Attached
        | EdgeKind::EmployedBy
        | EdgeKind::HasFacet
        | EdgeKind::FacetOf
        | EdgeKind::InWorld
        | EdgeKind::SetIn => {
            if has_provenance_claim {
                EdgeValueLayout::SemanticProvenanced
            } else {
                EdgeValueLayout::SemanticBare
            }
        }
    }
}

/// Edge info for hydrated context entities.
#[derive(Debug, Clone)]
pub struct EdgeInfo {
    pub kind: EdgeKind,
    pub target: EntityId,
    pub target_short_id: Option<String>,
    pub weight: f32,
    pub created_at: u64,
    pub vad: Option<Vad>,
    pub provenance: Option<EdgeProvenanceFlags>,
}

fn read_f32_le(value: &[u8], offset: usize) -> crate::error::Result<f32> {
    let bytes = value
        .get(offset..offset + 4)
        .and_then(|b| b.try_into().ok())
        .ok_or(crate::error::Error::CorruptedIndex("edge value"))?;
    Ok(f32::from_le_bytes(bytes))
}

fn read_u64_le(value: &[u8], offset: usize) -> crate::error::Result<u64> {
    let bytes = value
        .get(offset..offset + 8)
        .and_then(|b| b.try_into().ok())
        .ok_or(crate::error::Error::CorruptedIndex("edge value"))?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_vad(value: &[u8]) -> crate::error::Result<Vad> {
    Ok(Vad {
        valence: read_f32_le(value, 12)?,
        arousal: read_f32_le(value, 16)?,
        dominance: read_f32_le(value, 20)?,
    })
}

pub(crate) fn decode_edge_value(value: &[u8]) -> crate::error::Result<DecodedEdgeValue> {
    let layout = EdgeValueLayout::from_len(value.len())
        .ok_or(crate::error::Error::CorruptedIndex("edge value"))?;
    let weight = read_f32_le(value, 0)?;
    if !weight.is_finite() {
        return Err(crate::error::Error::CorruptedIndex("edge value"));
    }
    let created_at = read_u64_le(value, 4)?;
    let vad = match layout {
        EdgeValueLayout::Structural => None,
        EdgeValueLayout::SemanticBare | EdgeValueLayout::SemanticProvenanced => {
            let vad = read_vad(value)?;
            if !vad.is_finite() || !vad.is_in_range() {
                return Err(crate::error::Error::CorruptedIndex("edge value"));
            }
            Some(vad)
        }
    };
    let provenance = match layout {
        EdgeValueLayout::SemanticProvenanced => {
            let confirmation_status = EdgeConfirmationStatus::try_from_u8(value[24])
                .ok_or(crate::error::Error::CorruptedIndex("edge value"))?;
            let actor_class = EdgeActorClass::try_from_u8(value[25])
                .ok_or(crate::error::Error::CorruptedIndex("edge value"))?;
            Some(EdgeProvenanceFlags {
                confirmation_status,
                actor_class,
            })
        }
        EdgeValueLayout::Structural | EdgeValueLayout::SemanticBare => None,
    };

    Ok(DecodedEdgeValue {
        layout,
        weight,
        created_at,
        vad,
        provenance,
    })
}

pub(crate) fn decode_edge_value_for_kind(
    kind: EdgeKind,
    value: &[u8],
) -> crate::error::Result<DecodedEdgeValue> {
    let decoded = decode_edge_value(value)?;
    let legal = match edge_value_layout_for_kind(kind, false) {
        EdgeValueLayout::Structural => decoded.layout == EdgeValueLayout::Structural,
        EdgeValueLayout::SemanticBare | EdgeValueLayout::SemanticProvenanced => matches!(
            decoded.layout,
            EdgeValueLayout::SemanticBare | EdgeValueLayout::SemanticProvenanced
        ),
    };

    if !legal {
        return Err(crate::error::Error::CorruptedIndex("edge value"));
    }

    Ok(decoded)
}

/// Fully parsed strict edge row shared by fail-closed graph readers.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct StrictEdgeRecord {
    pub source: EntityId,
    pub kind: EdgeKind,
    pub target: EntityId,
    pub decoded: DecodedEdgeValue,
}

impl StrictEdgeRecord {
    pub(crate) fn into_edge_info(self) -> EdgeInfo {
        EdgeInfo {
            kind: self.kind,
            target: self.target,
            target_short_id: None,
            weight: self.decoded.weight,
            created_at: self.decoded.created_at,
            vad: self.decoded.vad,
            provenance: self.decoded.provenance,
        }
    }
}

/// Parses one `edges_out` / `edges_in` row fail-closed.
///
/// A key that is not `EDGE_KEY_LEN` bytes, an unknown edge-kind byte,
/// a reserved/invalid source or peer id, or a value that does not decode as
/// a valid layout for the kind (12/24/26 B per ARCH-0034) is normalized to
/// `Error::CorruptedIndex("edge record")`.
pub(crate) fn parse_strict_edge_record(
    key: &[u8],
    value: &[u8],
) -> crate::error::Result<StrictEdgeRecord> {
    let (source, kind, target) = parse_strict_edge_record_key(key)?;
    let decoded = decode_edge_value_for_kind(kind, value).map_err(|_| edge_record_error())?;

    Ok(StrictEdgeRecord {
        source,
        kind,
        target,
        decoded,
    })
}

pub(crate) fn parse_strict_edge_record_key(
    key: &[u8],
) -> crate::error::Result<(EntityId, EdgeKind, EntityId)> {
    if key.len() != EDGE_KEY_LEN {
        return Err(edge_record_error());
    }

    let source = EntityId::from_bytes(
        key[..ENTITY_ID_LEN]
            .try_into()
            .map_err(|_| edge_record_error())?,
    )
    .map_err(|_| edge_record_error())?;
    let kind = EdgeKind::try_from_u8(key[ENTITY_ID_LEN]).ok_or_else(edge_record_error)?;
    let target = EntityId::from_bytes(
        key[ENTITY_ID_LEN + 1..EDGE_KEY_LEN]
            .try_into()
            .map_err(|_| edge_record_error())?,
    )
    .map_err(|_| edge_record_error())?;

    Ok((source, kind, target))
}

fn edge_record_error() -> crate::error::Error {
    crate::error::Error::CorruptedIndex("edge record")
}

/// Rejects edge kinds whose topology writes are reserved to an engine door:
/// `merged_into` / `split_into` carry redirect-shell lifecycle meaning
/// derived at read time, so a raw public write could forge or tear shell
/// state (ARCH-0055). Applied by the public batch edge builders; the
/// identity-topology door and sync replay materialize through internal ops.
pub(crate) fn validate_public_edge_kind(kind: EdgeKind) -> crate::error::Result<()> {
    match kind {
        EdgeKind::MergedInto => Err(crate::error::Error::ReservedEdgeKind("merged_into")),
        EdgeKind::SplitInto => Err(crate::error::Error::ReservedEdgeKind("split_into")),
        _ => Ok(()),
    }
}

/// Validates a stored edge weight against the contract-pinned range.
///
/// Contract: edge `weight` ∈ \[0, 1\] (oneiron-docs
/// `site/src/data/oneiron-contracts.ts` `edgeKinds` — every non-null
/// `pprWeight` prior lives in this closed interval, and the weight gloss pins
/// the stored range). NaN, ±infinity, and finite values outside \[0, 1\] are
/// rejected with the typed [`Error::InvalidEdgeWeight`] on EVERY write path
/// (public batch ops and sync replay materialization alike); the read path is
/// unchanged.
///
/// [`Error::InvalidEdgeWeight`]: crate::error::Error::InvalidEdgeWeight
pub(crate) fn validate_edge_weight(weight: f32) -> crate::error::Result<()> {
    if !(0.0..=1.0).contains(&weight) {
        return Err(crate::error::Error::InvalidEdgeWeight { value: weight });
    }
    Ok(())
}

pub(crate) fn encode_edge_value(
    kind: EdgeKind,
    weight: f32,
    created_at: u64,
    vad: Vad,
    provenance: Option<EdgeProvenanceFlags>,
) -> crate::error::Result<Vec<u8>> {
    validate_edge_weight(weight)?;
    if let Some((component, value)) = vad.invalid_component() {
        return Err(crate::error::Error::InvalidVad { component, value });
    }
    if provenance.is_some()
        && edge_value_layout_for_kind(kind, false) == EdgeValueLayout::Structural
    {
        return Err(crate::error::Error::InvariantViolation(
            "structural edges do not carry provenance hot flags",
        ));
    }
    if vad != Vad::NEUTRAL && edge_value_layout_for_kind(kind, false) == EdgeValueLayout::Structural
    {
        return Err(crate::error::Error::InvariantViolation(
            "structural edges do not carry VAD",
        ));
    }

    let layout = edge_value_layout_for_kind(kind, provenance.is_some());
    let mut value = vec![0_u8; layout.bytes()];
    value[0..4].copy_from_slice(&weight.to_le_bytes());
    value[4..12].copy_from_slice(&created_at.to_le_bytes());

    match layout {
        EdgeValueLayout::Structural => {}
        EdgeValueLayout::SemanticBare | EdgeValueLayout::SemanticProvenanced => {
            value[12..16].copy_from_slice(&vad.valence.to_le_bytes());
            value[16..20].copy_from_slice(&vad.arousal.to_le_bytes());
            value[20..24].copy_from_slice(&vad.dominance.to_le_bytes());
        }
    }

    if let Some(flags) = provenance {
        value[24] = flags.confirmation_status as u8;
        value[25] = flags.actor_class as u8;
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::EDGE_KEY_LEN;
    use super::EDGE_VALUE_STRUCTURAL_LEN;
    use super::ENTITY_ID_LEN;
    use super::EdgeKind;
    use super::EntityId;
    use super::Vad;
    use super::encode_edge_value;
    use super::parse_strict_edge_record;

    #[test]
    fn strict_edge_record_parser_decodes_key_and_value() {
        let source = EntityId::from_bytes([0x11; ENTITY_ID_LEN]).unwrap();
        let target = EntityId::from_bytes([0x22; ENTITY_ID_LEN]).unwrap();
        let kind = EdgeKind::Supports;
        let mut key = [0_u8; EDGE_KEY_LEN];
        key[..ENTITY_ID_LEN].copy_from_slice(source.as_bytes());
        key[ENTITY_ID_LEN] = kind as u8;
        key[ENTITY_ID_LEN + 1..].copy_from_slice(target.as_bytes());
        let value = encode_edge_value(kind, 0.75, 42, Vad::NEUTRAL, None).unwrap();

        let record = parse_strict_edge_record(&key, &value).unwrap();
        assert_eq!(record.source, source);
        assert_eq!(record.kind, kind);
        assert_eq!(record.target, target);
        assert_eq!(record.decoded.weight, 0.75);
        assert_eq!(record.decoded.created_at, 42);

        let info = record.into_edge_info();
        assert_eq!(info.kind, kind);
        assert_eq!(info.target, target);
        assert_eq!(info.target_short_id, None);
        assert_eq!(info.weight, 0.75);
        assert_eq!(info.created_at, 42);
    }

    /// ONE-1414 done-means 10 + the no-pooling contract, at the byte level.
    ///
    /// One test because these are one decision: `same_as` is byte 20, carries
    /// the 12-byte structural layout, has NO stored-weight prior, and is never
    /// traversed. A future edit that gave it a λ or a default weight would have
    /// to delete a line here to pass.
    #[test]
    fn same_as_is_byte_20_structural_unweighted_and_never_traversed() {
        assert_eq!(EdgeKind::SameAs as u8, 20);
        assert_eq!(EdgeKind::try_from_u8(20), Some(EdgeKind::SameAs));
        assert_eq!(EdgeKind::SameAs.default_weight(), None);
        assert_eq!(crate::ppr::lambda_for_kind(EdgeKind::SameAs), None);
        assert_eq!(
            super::edge_value_layout_for_kind(EdgeKind::SameAs, false),
            super::EdgeValueLayout::Structural
        );

        // Byte 20 is the ONLY byte this ticket allocates: 21/22 keep their
        // reserved identity-topology meaning untouched.
        assert_eq!(EdgeKind::try_from_u8(21), Some(EdgeKind::MergedInto));
        assert_eq!(EdgeKind::try_from_u8(22), Some(EdgeKind::SplitInto));
    }

    /// The owning write door stores an EXPLICIT `0.0`, and the row decodes back
    /// as a 12-byte structural value carrying exactly that weight.
    #[test]
    fn same_as_encodes_explicit_zero_weight_as_a_structural_row() {
        let value = encode_edge_value(EdgeKind::SameAs, 0.0, 1_772_000_300, Vad::NEUTRAL, None)
            .expect("same_as encodes at explicit zero weight");
        assert_eq!(value.len(), EDGE_VALUE_STRUCTURAL_LEN);

        let decoded = super::decode_edge_value_for_kind(EdgeKind::SameAs, &value)
            .expect("structural same_as value decodes for its kind");
        assert_eq!(decoded.weight.to_bits(), 0.0_f32.to_bits());
        assert_eq!(decoded.created_at, 1_772_000_300);
        assert_eq!(decoded.vad, None);
        assert_eq!(decoded.provenance, None);
    }

    /// A raw byte-20 edge key parses back to `SameAs` with its endpoints
    /// intact — the decode half of the wire contract.
    #[test]
    fn same_as_edge_record_decodes_from_raw_bytes() {
        let source = EntityId::from_bytes([0x31; ENTITY_ID_LEN]).unwrap();
        let target = EntityId::from_bytes([0x32; ENTITY_ID_LEN]).unwrap();
        let mut key = [0_u8; EDGE_KEY_LEN];
        key[..ENTITY_ID_LEN].copy_from_slice(source.as_bytes());
        key[ENTITY_ID_LEN] = 20;
        key[ENTITY_ID_LEN + 1..].copy_from_slice(target.as_bytes());
        let value = encode_edge_value(EdgeKind::SameAs, 0.0, 7, Vad::NEUTRAL, None).unwrap();

        let record = parse_strict_edge_record(&key, &value).expect("byte-20 edge record parses");
        assert_eq!(record.kind, EdgeKind::SameAs);
        assert_eq!(record.source, source);
        assert_eq!(record.target, target);
    }

    #[test]
    fn strict_edge_record_parser_normalizes_corruption_errors() {
        let source = EntityId::from_bytes([0x11; ENTITY_ID_LEN]).unwrap();
        let target = EntityId::from_bytes([0x22; ENTITY_ID_LEN]).unwrap();
        let mut key = [0_u8; EDGE_KEY_LEN];
        key[..ENTITY_ID_LEN].copy_from_slice(source.as_bytes());
        key[ENTITY_ID_LEN] = EdgeKind::Supports as u8;
        key[ENTITY_ID_LEN + 1..].copy_from_slice(target.as_bytes());

        let truncated_value = [0_u8; EDGE_VALUE_STRUCTURAL_LEN - 1];
        let err = parse_strict_edge_record(&key, &truncated_value)
            .expect_err("truncated edge value must fail closed");
        assert!(matches!(
            err,
            crate::error::Error::CorruptedIndex("edge record")
        ));

        key[ENTITY_ID_LEN + 1..].fill(0xFF);
        let value = encode_edge_value(EdgeKind::Supports, 0.5, 1, Vad::NEUTRAL, None).unwrap();
        let err = parse_strict_edge_record(&key, &value)
            .expect_err("reserved target id must fail closed");
        assert!(matches!(
            err,
            crate::error::Error::CorruptedIndex("edge record")
        ));
    }
}
