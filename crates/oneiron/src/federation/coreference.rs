//! Cross-vault same_as links and per-pact share consent (FED-07).

use rmpv::Value;

use crate::affect::Vad;
use crate::batch::BatchOp;
use crate::claim::{
    COREFERENCE_PACT_ID_LEN, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource,
    ClaimSubject,
};
use crate::edge::EdgeKind;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

// ---------------------------------------------------------------------------
// Cross-vault coreference (FED-07, ONE-1414).
//
// A `same_as` link says two PERSON entities are one person. It says NOTHING
// about their claims: `ppr::lambda_for_kind(SameAs)` is `None`, so no
// retrieval mass crosses the link in either direction, and no claim body,
// source, or world scope is ever rewritten. Identity and claim POOLING are
// deliberately different things, and only the first one ships here.
//
// The link is LOCAL BY DEFAULT. Nothing about it leaves this vault until the
// owner writes a `core.coreference.share_consent` claim naming ONE pact, and
// the export filter then honors that consent for that pact alone.
//
// This module is the OWNING WRITE DOOR. The link and its status claim are
// meaningless apart — a link with no status is an unattributed identity
// assertion, a status with no link is a statement about nothing — so they are
// written in ONE transaction or not at all, behind an actor gate.
// ---------------------------------------------------------------------------

/// Status of a cross-vault coreference link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreferenceStatus {
    /// Asserted, not yet owner-confirmed. Written `Proposed`.
    Proposed,
    /// Owner-confirmed identity. Written `Approved`.
    Confirmed,
}

impl CoreferenceStatus {
    /// The `core.coreference.status` value string.
    const fn wire(self) -> &'static str {
        match self {
            Self::Proposed => crate::claim::COREFERENCE_STATUS_PROPOSED,
            Self::Confirmed => crate::claim::COREFERENCE_STATUS_CONFIRMED,
        }
    }

    /// The approval a status is written at.
    ///
    /// `Confirmed` means the owner ruled, and the claim validator enforces the
    /// same pairing at the write door — so the two cannot drift.
    const fn approval(self) -> ClaimApprovalStatus {
        match self {
            Self::Proposed => ClaimApprovalStatus::Proposed,
            Self::Confirmed => ClaimApprovalStatus::Approved,
        }
    }
}

/// Writes a `same_as` link plus its status claim ATOMICALLY.
///
/// `src` is `local_person`, `tgt` is `other_person`, and the stored weight is
/// an explicit `0.0` — `same_as` has no default prior because it carries no
/// retrieval meaning to prior over.
///
/// Either person may be foreign-world scoped; both must EXIST, and existence is
/// checked here rather than left to the claim door, because the claim's subject
/// is an EdgeRef and the door shape-validates those without resolving them.
///
/// ATOMICITY IS THE POINT. Prevalidation failure writes nothing, and a batch
/// failure rolls back the whole transaction, so a link never outlives its
/// status and a status never outlives its link. Returns the status CLAIM id.
///
/// # Errors
///
/// Returns [`Error::EntityNotFound`] when `actor` is unattributed or either
/// person is absent, [`ClaimError::ActorClassMismatch`](crate::error::ClaimError::ActorClassMismatch) when `actor` is not a
/// principal of the class it asserts, and propagates any batch failure.
pub fn put_coreference_link(
    vault: &Vault,
    actor: &WriteActor,
    local_person: EntityId,
    other_person: EntityId,
    status: CoreferenceStatus,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<EntityId> {
    require_coreference_actor(vault, actor)?;
    if !vault.entity_exists(&local_person)? || !vault.entity_exists(&other_person)? {
        return Err(Error::EntityNotFound);
    }

    let claim_id = EntityId::now();
    let body = coreference_claim_body(
        crate::claim::PREDICATE_COREFERENCE_STATUS,
        local_person,
        other_person,
        Value::from(status.wire()),
        status.approval(),
    );
    let mut ops = vec![BatchOp::Edge {
        src: local_person,
        kind: EdgeKind::SameAs,
        tgt: other_person,
        weight: COREFERENCE_LINK_WEIGHT,
        vad: Vad::NEUTRAL,
    }];
    ops.extend(coreference_claim_ops(
        claim_id,
        local_person,
        &body,
        occurred,
        learned_at,
    )?);
    apply_coreference_ops(vault, ops)?;
    Ok(claim_id)
}

/// Consents to sharing an existing coreference link into ONE pact.
///
/// Consent attaches to the LINK and the PACT, never to a storage direction, so
/// the link is looked up in BOTH orientations and the claim is filed against
/// whichever one actually exists. Consent for pact P says nothing about pact Q.
///
/// Returns the consent CLAIM id.
///
/// # Errors
///
/// Returns [`Error::EdgeNotFound`] when no `same_as` link joins the two people
/// in either orientation — consent to share a link that does not exist is not a
/// no-op, it is a caller error — plus the actor-gate errors of
/// [`put_coreference_link`].
pub fn coreference_share_consent(
    vault: &Vault,
    actor: &WriteActor,
    local_person: EntityId,
    other_person: EntityId,
    pact_id: &[u8; COREFERENCE_PACT_ID_LEN],
    occurred: TimeRange,
    learned_at: u64,
) -> Result<EntityId> {
    require_coreference_actor(vault, actor)?;
    let (source, target) = coreference_link_orientation(vault, local_person, other_person)?
        .ok_or(Error::EdgeNotFound)?;

    let claim_id = EntityId::now();
    let body = coreference_claim_body(
        crate::claim::PREDICATE_COREFERENCE_SHARE_CONSENT,
        source,
        target,
        Value::Map(vec![(
            Value::from(crate::claim::COREFERENCE_SHARE_CONSENT_PACT_KEY),
            Value::from(bytes_to_hex_lower(pact_id)),
        )]),
        ClaimApprovalStatus::Approved,
    );
    let ops = coreference_claim_ops(claim_id, source, &body, occurred, learned_at)?;
    apply_coreference_ops(vault, ops)?;
    Ok(claim_id)
}

/// Whether the link between `a` and `b` carries live LOCAL consent for EXACTLY
/// `pact_id`.
///
/// EVERY stored orientation is scanned, not just the first one found. Consent is
/// a property of the link, never of which endpoint happened to be written as the
/// source, and nothing local guarantees a single direction — the write door
/// files consent against the orientation it finds, and a peer can replicate the
/// mirror row. Stopping at the first stored direction would make the answer
/// depend on the caller's argument order in a reachable state.
///
/// The LINK must exist. A consent claim outliving its link vouches for nothing.
pub fn coreference_shared_for_pact(
    vault: &Vault,
    a: EntityId,
    b: EntityId,
    pact_id: &[u8; COREFERENCE_PACT_ID_LEN],
) -> Result<bool> {
    for (source, target) in [(a, b), (b, a)] {
        if vault.edge_exists(&source, EdgeKind::SameAs, &target)?
            && coreference_consent_names_pact(vault, source, target, pact_id)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The consent scan for ONE stored orientation of a link.
///
/// The claim must be Active AND Approved AND name this exact pact: a claim
/// naming another pact is not weaker evidence for this one, it is evidence about
/// something else.
///
/// It must also be LOCALLY AUTHORED. Federation admission restamps every
/// inbound claim to [`ClaimSource::Imported`]
/// (`claim::restamp_federated_claim_source`), and an imported consent row is a
/// PEER asserting that WE consented to disclose. Whether this vault shares a
/// coreference link is its owner's decision alone, so a replicated row vouches
/// for nothing — otherwise a peer that lands a consent-shaped claim plus its
/// `claim_of` edge would launder itself into our own export filter and pull our
/// local-by-default links across the grant.
fn coreference_consent_names_pact(
    vault: &Vault,
    source: EntityId,
    target: EntityId,
    pact_id: &[u8; COREFERENCE_PACT_ID_LEN],
) -> Result<bool> {
    for claim in vault.claims_for_subject(&source)? {
        let Some(body) = vault.get_claim(&claim)? else {
            continue;
        };
        if body.predicate != crate::claim::PREDICATE_COREFERENCE_SHARE_CONSENT
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.approval != ClaimApprovalStatus::Approved
            || body.source == Some(ClaimSource::Imported)
            || body.subject
                != (ClaimSubject::Edge {
                    source,
                    kind: EdgeKind::SameAs,
                    target,
                })
        {
            continue;
        }
        // A malformed stored consent body is not consent. It cannot have been
        // written through this door (the claim validator rejects it), so
        // skipping is the fail-closed reading rather than a swallowed error.
        if crate::claim::coreference_share_consent_pact_id(&body)
            .is_ok_and(|claimed| claimed == *pact_id)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Stored weight of a `same_as` edge: explicitly `0.0`.
///
/// Not a retrieval prior — PPR never traverses the kind at all. The byte is
/// pinned so the row is bit-stable and so no reader can mistake a default for a
/// decision.
pub const COREFERENCE_LINK_WEIGHT: f32 = 0.0;

/// The orientation a new consent claim is FILED against, if the link exists.
///
/// `(a, b)` is checked before `(b, a)` so a link stored both ways resolves
/// deterministically; the caller's argument order therefore decides only the
/// tiebreak, never whether a link is found. Deliberately first-match rather than
/// exhaustive: this picks ONE row to hang a claim on, while
/// [`coreference_shared_for_pact`] reads every orientation, so consent filed on
/// either direction answers for the link.
fn coreference_link_orientation(
    vault: &Vault,
    a: EntityId,
    b: EntityId,
) -> Result<Option<(EntityId, EntityId)>> {
    for (source, target) in [(a, b), (b, a)] {
        if vault.edge_exists(&source, EdgeKind::SameAs, &target)? {
            return Ok(Some((source, target)));
        }
    }
    Ok(None)
}

/// The ordinary write-gate principal check, run BEFORE any transaction opens.
///
/// Same rule the claim write path applies to a stamped envelope
/// (`code_run::check_write_gate_against_vault`): the actor entity must exist and
/// its asserted class must fit its entity type. An absent ref is an
/// unattributed write; a class that does not fit the type is a wrong principal.
/// Confirmed identity and share consent both alter what this vault asserts and
/// what it discloses, so neither may be written anonymously.
fn require_coreference_actor(vault: &Vault, actor: &WriteActor) -> Result<()> {
    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .entities
        .get(&rtxn, actor.entity_ref().as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("entity header"))?;
    crate::provenance::validate_actor_class(header.entity_type, actor.actor_class())
}

fn coreference_claim_body(
    predicate: &'static str,
    source: EntityId,
    target: EntityId,
    value: Value,
    approval: ClaimApprovalStatus,
) -> ClaimBody {
    ClaimBody::new(
        predicate,
        ClaimSubject::Edge {
            source,
            kind: EdgeKind::SameAs,
            target,
        },
        value,
        1.0,
        approval,
        ClaimLifecycleStatus::Active,
    )
}

/// The claim put plus its `claim_of` edge to the link's SOURCE person.
///
/// EdgeRef-subject claims carry no `claim_of` wiring from the generic claim
/// door, so the owning door supplies it — the same D12 arrangement
/// `edge.provenance` uses. Without it the claim is stored but unreachable, and
/// an unreachable consent claim is a consent nobody can honor.
fn coreference_claim_ops(
    claim_id: EntityId,
    source: EntityId,
    body: &ClaimBody,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<Vec<BatchOp>> {
    let data = crate::claim::encode_claim_body(body)?;
    crate::claim::validate_claim_body_bytes(&data, false)?;
    Ok(vec![
        BatchOp::Put {
            id: claim_id,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        },
        BatchOp::Edge {
            src: claim_id,
            kind: EdgeKind::ClaimOf,
            tgt: source,
            weight: crate::vault::CLAIM_OF_DEFAULT_WEIGHT,
            vad: Vad::NEUTRAL,
        },
    ])
}

fn apply_coreference_ops(vault: &Vault, ops: Vec<BatchOp>) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        crate::batch::apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            wtxn,
            ops,
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    })
}
