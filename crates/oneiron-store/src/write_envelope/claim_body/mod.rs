//! The stored CLAIM body, its MessagePack codec, scope stamps and citations.

use super::claim_predicate::{validate_predicate, validate_session_tag};
use oneiron_base::edge::EdgeKind;
use oneiron_contracts::claim::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ConfidenceBand, ConfidenceDetails,
    VerdictBasis,
};
use oneiron_contracts::entity_id::{ENTITY_ID_LEN, EntityId};
use oneiron_contracts::error::{Error, Result};
use oneiron_contracts::temporal::TimeRange;
use rmpv::Value;

mod codec;
mod evidence_refs;
pub mod lexical_query_hint;
mod made_by;
mod relationship_scope;
mod scope;
pub mod scope_stamp;
mod source_trust;

pub use codec::decode_claim_body;
pub use codec::encode_claim_body;
pub use evidence_refs::{CursorSpan, EvidenceKind, EvidenceRef};
pub use evidence_refs::{EVIDENCE_REFS_KEY, public_evidence_refs, public_evidence_value};
pub use made_by::MadeByClass;
pub use relationship_scope::{
    RelationshipScope, meet_relationship_scopes, relationship_scope_includes,
    relationship_scope_of, relationship_scope_transcript,
};
pub use relationship_scope::{decode_relationship_scope, encode_relationship_scope};
pub use scope::claim_principal_id;
pub(crate) use scope::validate_known_claim_scope_entries;
pub use scope_stamp::{
    PREDICATE_VAULT_DEFAULT_FACET, base_world_id, default_project_id, substrate_facet_id,
};
pub use source_trust::*;
pub use source_trust::{ClaimDemotion, ClaimDemotionAction, ClaimDemotionRung};

/// Pinned ON-DISK MessagePack key set for type-0 (CLAIM) bodies (D11).
///
/// Order is canonical: the engine's encoder emits present fields in this
/// order. The context-pack field profiles are drawn from this list (Minimal
/// = its first 2; Standard and Full add the confidence band and basis, so a
/// profile that carries `conf` carries what it means; the lifecycle keys
/// `appr`/`life`/`stale` and optional session tag `sess` are excluded from
/// every serialization profile).
pub const CLAIM_BODY_KEYS: [&str; 21] = [
    "pred",
    "val",
    "conf",
    "sal",
    "evid",
    "from",
    "to",
    "src",
    "worldId",
    "scopeRelationshipId",
    "subj",
    "scope",
    "appr",
    "life",
    "stale",
    "sess",
    "scopeFacetId",
    "scopeProjectId",
    "scopeVersion",
    "confBand",
    "confBasis",
];

const KEY_PRED: &str = CLAIM_BODY_KEYS[0];
const KEY_VAL: &str = CLAIM_BODY_KEYS[1];
pub const KEY_CONF: &str = CLAIM_BODY_KEYS[2];
pub const KEY_SAL: &str = CLAIM_BODY_KEYS[3];
const KEY_EVID: &str = CLAIM_BODY_KEYS[4];
const KEY_FROM: &str = CLAIM_BODY_KEYS[5];
const KEY_TO: &str = CLAIM_BODY_KEYS[6];
const KEY_SRC: &str = CLAIM_BODY_KEYS[7];
pub const KEY_WORLD: &str = CLAIM_BODY_KEYS[8];
const KEY_REL: &str = CLAIM_BODY_KEYS[9];
const KEY_SUBJ: &str = CLAIM_BODY_KEYS[10];
pub const KEY_SCOPE: &str = CLAIM_BODY_KEYS[11];
const KEY_APPR: &str = CLAIM_BODY_KEYS[12];
const KEY_LIFE: &str = CLAIM_BODY_KEYS[13];
const KEY_STALE: &str = CLAIM_BODY_KEYS[14];
pub const KEY_SESSION: &str = CLAIM_BODY_KEYS[15];
const KEY_CONF_BAND: &str = CLAIM_BODY_KEYS[19];
const KEY_CONF_BASIS: &str = CLAIM_BODY_KEYS[20];

/// Context-pack CLAIM field profiles, derived from [`CLAIM_BODY_KEYS`] so the
/// serializer cannot drift from the storage ABI.
pub const CLAIM_FIELDS_MINIMAL: &[&str] = claim_keys_prefix(2);
pub const CLAIM_FIELDS_STANDARD: &[&str] = &[
    "pred",
    "val",
    "conf",
    "sal",
    "evid",
    KEY_CONF_BAND,
    KEY_CONF_BASIS,
];
pub const CLAIM_FIELDS_FULL: &[&str] = &[
    "pred",
    "val",
    "conf",
    "sal",
    "evid",
    "from",
    "to",
    "src",
    "worldId",
    "scopeRelationshipId",
    "subj",
    "scope",
    "scopeFacetId",
    "scopeProjectId",
    "scopeVersion",
    KEY_CONF_BAND,
    KEY_CONF_BASIS,
];

const fn claim_keys_prefix(len: usize) -> &'static [&'static str] {
    let whole: &[&str] = &CLAIM_BODY_KEYS;
    whole.split_at(len).0
}

/// Length of an EdgeRef subject encoding: source 16 ‖ kind u8 ‖ target 16.
pub const EDGE_REF_LEN: usize = 33;

/// A claim's subject reference (`subj`). Two pinned encodings:
///
/// * 16 bytes — an entity UUID;
/// * 33 bytes — an EdgeRef `(source_id 16 B ‖ edge_kind u8 ‖ target_id 16 B)`
///   addressing an edge (used by `edge.provenance` Claims; the kind byte must
///   parse as a registered [`EdgeKind`]).
///
/// Anything else fails validation with [`Error::InvalidClaimBody`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimSubject {
    /// Subject is an entity (16-byte UUID).
    Entity(EntityId),
    /// Subject is an edge, addressed as a 33-byte EdgeRef.
    Edge {
        source: EntityId,
        kind: EdgeKind,
        target: EntityId,
    },
}

impl ClaimSubject {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Entity(id) => id.as_bytes().to_vec(),
            Self::Edge {
                source,
                kind,
                target,
            } => {
                let mut out = Vec::with_capacity(EDGE_REF_LEN);
                out.extend_from_slice(source.as_bytes());
                out.push(*kind as u8);
                out.extend_from_slice(target.as_bytes());
                out
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        match bytes.len() {
            ENTITY_ID_LEN => {
                let arr: [u8; ENTITY_ID_LEN] = bytes
                    .try_into()
                    .map_err(|_| Error::InvalidClaimBody("subj entity id is malformed"))?;
                let id = EntityId::from_bytes(arr)
                    .map_err(|_| Error::InvalidClaimBody("subj entity id is reserved"))?;
                Ok(Self::Entity(id))
            }
            EDGE_REF_LEN => {
                let source = entity_id_from(&bytes[..ENTITY_ID_LEN], "subj EdgeRef source id")?;
                let kind = EdgeKind::try_from_u8(bytes[ENTITY_ID_LEN]).ok_or(
                    Error::InvalidClaimBody("subj EdgeRef kind byte is not a registered EdgeKind"),
                )?;
                let target = entity_id_from(&bytes[ENTITY_ID_LEN + 1..], "subj EdgeRef target id")?;
                Ok(Self::Edge {
                    source,
                    kind,
                    target,
                })
            }
            _ => Err(Error::InvalidClaimBody(
                "subj must be a 16-byte entity id or a 33-byte EdgeRef",
            )),
        }
    }
}

fn entity_id_from(bytes: &[u8], context: &'static str) -> Result<EntityId> {
    let arr: [u8; ENTITY_ID_LEN] = bytes
        .try_into()
        .map_err(|_| Error::InvalidClaimBody(context))?;
    EntityId::from_bytes(arr).map_err(|_| Error::InvalidClaimBody(context))
}

/// Decoded type-0 (CLAIM) body — the engine-pinned structural fields only.
///
/// Per-predicate columns (ARCH-0003 §G.1) are NOT modeled here: the typed
/// `val` payload is an opaque MessagePack value the crate never interprets.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimBody {
    /// `pred` — predicate string, validated against the D17 grammar. Crate
    /// well-known predicates use the first-segment layer convention
    /// documented by [`PREDICATE_LAYER_NAMESPACES`].
    pub predicate: String,
    /// `subj` — subject reference (entity UUID or EdgeRef).
    pub subject: ClaimSubject,
    /// `val` — typed claim value; opaque MessagePack at the storage layer.
    pub value: Value,
    /// `conf` — confidence, finite in `[0, 1]`.
    pub confidence: f32,
    /// `confBand` — the band `conf` is read in, as its producer gave it or
    /// the house table put it (FIX 7761). Readers hedge and compare by this
    /// band, never by a fixed cutoff over `conf`.
    pub confidence_band: ConfidenceBand,
    /// `confBasis` — where `confBand` came from: a calibrated decider, or
    /// the house table for a confidence given as a number alone.
    pub confidence_basis: VerdictBasis,
    /// `appr` — approval status.
    pub approval: ClaimApprovalStatus,
    /// `life` — lifecycle status.
    pub lifecycle: ClaimLifecycleStatus,
    /// `sal` — optional salience, finite in `[0, 1]`.
    pub salience: Option<f32>,
    /// `evid` — optional evidence payload (opaque MessagePack).
    pub evidence: Option<Value>,
    /// `from` — optional valid-time start (Unix seconds).
    pub valid_from: Option<u64>,
    /// `to` — optional valid-time end (Unix seconds).
    pub valid_to: Option<u64>,
    /// `src` — optional provenance source.
    pub source: Option<ClaimSource>,
    /// `worldId` — the 16-byte WORLD scope member. The wire always stamps it.
    /// The in-memory `None` convenience encodes the reserved base id, never absence.
    /// The WORLD entity id this claim
    /// is scoped to (ARCH-0004 claim world filter; ARCH-0022 world model).
    /// On disk it is exactly 16 MessagePack-binary bytes;
    /// any other shape is rejected fail-closed with [`Error::InvalidClaimBody`].
    /// The referenced WORLD entity is NOT required to exist at write time —
    /// extraction may create claims before their world; the read side groups
    /// by id regardless.
    pub world: Option<EntityId>,
    /// `scopeRelationshipId` holds `all` or a set of 16-byte ids.
    /// The in-memory `None` convenience encodes `all`; `Some(empty)` is the
    /// explicit empty set; `Some(ids)` is every RELATIONSHIP [`EntityId`] the
    /// writer named. The claim codec validates this on-disk shape only and
    /// does not require the referenced relationships to exist at write time,
    /// matching `world`. Retrieval validates the active relationship's
    /// existence and type when relationship filtering executes.
    pub rel: RelationshipScope,
    /// `scope` — optional relationship/facet scope (opaque MessagePack).
    pub scope: Option<Value>,
    /// Required provenance mask id. A mask does not grant authority.
    pub scope_facet: EntityId,
    /// Required project audience id.
    pub scope_project: EntityId,
    /// `sess` — optional agent-session tag. Proposed claims sharing a tag
    /// form a review bundle; the tag remains as provenance after approval.
    pub session_tag: Option<String>,
    /// `stale` — derived-data staleness marker; absent on disk means `false`.
    pub stale: bool,
}

/// One session-tagged claim returned for bundle review or merge.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionClaimBundleClaim {
    /// Durable CLAIM entity id.
    pub id: EntityId,
    /// Current typed claim body.
    pub body: ClaimBody,
}

/// Coherent proposed-claim bundle for one agent session.
///
/// A bundle is a data-native projection over CLAIM rows sharing `sess` and
/// the envelope-stamped producer actor; it does not introduce an independent
/// branch record or storage table.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionClaimBundle {
    /// Stable tag supplied by the writing agent session.
    pub session_tag: String,
    /// Active proposed claims currently belonging to the session.
    pub claims: Vec<SessionClaimBundleClaim>,
}

#[derive(Debug, Clone)]
pub struct SessionClaimBundleMember {
    pub id: EntityId,
    pub body: ClaimBody,
    pub occurred: TimeRange,
    pub learned_at: u64,
}

impl ClaimBody {
    /// Creates a claim body from the six required fields; all optional
    /// fields start absent and `stale` starts `false`. The confidence starts
    /// in its house band ([`Self::set_confidence`]). The scope facet starts
    /// as the subject's `substrate` FACET, a derived id, so construction
    /// refuses with an error where that derivation does.
    pub fn new(
        predicate: impl Into<String>,
        subject: ClaimSubject,
        value: Value,
        confidence: f32,
        approval: ClaimApprovalStatus,
        lifecycle: ClaimLifecycleStatus,
    ) -> Result<Self> {
        Ok(Self {
            predicate: predicate.into(),
            subject,
            value,
            confidence,
            confidence_band: ConfidenceBand::house(confidence),
            confidence_basis: VerdictBasis::DeterministicFallback,
            approval,
            lifecycle,
            salience: None,
            evidence: None,
            valid_from: None,
            valid_to: None,
            source: None,
            world: None,
            rel: None,
            scope: None,
            scope_facet: scope_stamp::subject_facet(subject)?,
            scope_project: scope_stamp::default_project_id(),
            session_tag: None,
            stale: false,
        })
    }

    /// The band and basis kept beside `confidence`.
    #[must_use]
    pub const fn confidence_details(&self) -> ConfidenceDetails {
        ConfidenceDetails {
            band: self.confidence_band,
            basis: self.confidence_basis,
        }
    }

    /// Sets `confidence` with the band and basis its producer gave, or the
    /// house band for a number given alone: a changed number never keeps
    /// another number's band (FIX 7761).
    pub fn set_confidence(&mut self, confidence: f32, details: Option<ConfidenceDetails>) {
        let details = details.unwrap_or_else(|| ConfidenceDetails::house(confidence));
        self.confidence = confidence;
        self.confidence_band = details.band;
        self.confidence_basis = details.basis;
    }
}
