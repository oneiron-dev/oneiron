//! The role rung (ARCH-0024 signal 3): a mention that names a person by
//! their relationship to the speaker, `my manager`, is looked up through the
//! speaker's role edges.
//!
//! A role edge is an ordinary claim `relationship.<word>` whose subject is
//! the person the role is relative to and whose value is the related
//! person's id in canonical 32-hex form (Engine ruling 13 Nov 12:58, as
//! `actor.subject_ref` holds its anchor): "Owen is my manager", said by the
//! owner, is `relationship.manager` on the owner valued with Owen's id. The
//! `relationship` root is multi-valued, so a second edge of one word stands
//! beside the first. The words are the fixed relationship labels
//! ([`relationship_trust_class`]): no synonym is read, so `my boss` never
//! reads a `relationship.manager` edge. The possessor of `my` is the one
//! author of the mention's message, never the vault's owner by default; a
//! message of no single author has none.
//!
//! Confirming a role phrase's provisional person asserts the relation it
//! names (Engine ruling LINKER-ROLE-CONFIRM-ASSERTS-ROLE-EDGE = A, 20 Nov
//! 19:31): the confirm writes one role edge on the possessor naming the
//! person ([`assert_role_edge_in_txn`]), so the possessor's next phrase
//! reads it, and another speaker's phrase, which reads its own speaker's
//! edges, never does.

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    RelationshipRead,
};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_consolidation::{ConsolidationEvidenceEnvelope, encode_consolidation_evidence};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::error::Result;
use crate::federation::{RelationshipTrustClass, relationship_trust_class};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};
use crate::{ClaimCandidate, EntityId, TimeRange, Vault};

/// The role edge predicate for `word`: `relationship.<word>`.
fn role_edge_predicate(word: &str) -> String {
    format!("relationship.{word}")
}

/// The role word of a person mention that names someone by their
/// relationship to the speaker: `my <word>`, any case, with `<word>` one of
/// the fixed relationship labels. Any other mention, and a mention of any
/// other kind, has none.
pub(super) fn role_word(kind: u8, mention: &str) -> Option<String> {
    if kind != ENTITY_TYPE_PERSON {
        return None;
    }
    let mut parts = mention.split_whitespace();
    let (Some(possessive), Some(word), None) = (parts.next(), parts.next(), parts.next()) else {
        return None;
    };
    if !possessive.eq_ignore_ascii_case("my") {
        return None;
    }
    let word = word.to_lowercase();
    (relationship_trust_class(&word) != RelationshipTrustClass::Unlabeled).then_some(word)
}

/// The possessor of the mention `mention` of `kind` said in `message`: for
/// a role phrase ([`role_word`]), the one author of the message, whose
/// relation it names; `None` for any other mention, and for a role phrase
/// of no single author. A provisional person minted for a role phrase is
/// its possessor's alone (FIX LINKER-ROLE-PROVISIONAL-PER-SPEAKER).
pub(crate) fn possessor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    kind: u8,
    mention: &str,
    message: &EntityId,
) -> Result<Option<EntityId>> {
    if role_word(kind, mention).is_none() {
        return Ok(None);
    }
    speaker_in_txn(vault, txn, message)
}

/// The one author of `message`, whom its `my` names; `None` when it has no
/// author or several.
pub(super) fn speaker_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    message: &EntityId,
) -> Result<Option<EntityId>> {
    let mut authors = BTreeSet::new();
    for edge in vault.store.port_edges(
        txn,
        message,
        EdgeDirection::Out,
        Some(EdgeKind::AuthoredBy),
        None,
    )? {
        authors.insert(edge?.target);
    }
    let mut authors = authors.into_iter();
    Ok(match (authors.next(), authors.next()) {
        (Some(author), None) => Some(author),
        _ => None,
    })
}

/// The role edge a claim body is, when it is one of `possessor`'s for
/// `predicate` that stands at `now`: Active and not marked stale, valid at
/// `now`, about `possessor` itself, and valued with an entity id in
/// canonical 32-hex form. The answer pairs that id with whether the edge is Approved. Auto
/// and Proposed edges are unsure; a Rejected edge, which the owner refused,
/// names no one.
fn role_edge(
    body: &ClaimBody,
    possessor: &EntityId,
    predicate: &str,
    now: u64,
) -> Option<(EntityId, bool)> {
    if body.subject != ClaimSubject::Entity(*possessor)
        || body.predicate != predicate
        || body.lifecycle != ClaimLifecycleStatus::Active
        || body.stale
        || body.valid_from.is_some_and(|start| start > now)
        || body.valid_to.is_some_and(|end| end <= now)
    {
        return None;
    }
    let approved = match body.approval {
        ClaimApprovalStatus::Approved => true,
        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Proposed => false,
        ClaimApprovalStatus::Rejected => return None,
    };
    let hex = body.value.as_str()?;
    let person = EntityId::from_hex(hex)
        .ok()
        .filter(|id| id.to_hex() == hex)?;
    Some((person, approved))
}

/// The ids `possessor`'s role edges for `word` name at `now`
/// ([`role_edge`]), each with whether an Approved edge names it, as stored:
/// the caller resolves each to its head. `admits` keeps the claims the
/// reader may see. An Approved edge whose owner-answer obligation is open
/// (ARCH-0026 §G3, [`crate::gate::claim_critical_confirm_settled_in_txn`])
/// is held from every effect reader, so it names its person only as an
/// unsure edge does: a held edge never hard-links.
pub(super) fn role_edges_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    possessor: &EntityId,
    word: &str,
    now: u64,
    mut admits: impl FnMut(&EntityId) -> Result<bool>,
) -> Result<BTreeMap<EntityId, bool>> {
    let predicate = role_edge_predicate(word);
    let mut edges = Vec::new();
    vault.find_claim_for_subject_in_txn(txn, possessor, |claim, body| {
        if let Some(edge) = role_edge(body, possessor, &predicate, now) {
            edges.push((*claim, edge));
        }
        None::<()>
    })?;
    let mut found = BTreeMap::new();
    for (claim, (person, approved)) in edges {
        if admits(&claim)? {
            let settled = approved
                && crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, txn, &claim)?;
            let sure: &mut bool = found.entry(person).or_default();
            *sure |= settled;
        }
    }
    Ok(found)
}

/// Who confirms a provisional person. A possessed role person's confirm
/// asserts its role edge with their word ([`assert_role_edge_in_txn`]).
#[derive(Clone)]
pub(crate) struct ConfirmedBy<'a> {
    /// The owner's proof, when the owner's own answer confirms: the edge is
    /// Approved while the proof holds owner tier in the writing transaction.
    /// Without it, or when it no longer holds, the edge is unsure.
    pub(crate) owner: Option<&'a AuthenticatedOwner>,
    /// The envelope an unsure edge is written under, at the approval the
    /// write sets: the confirming session's own, its host origin's source,
    /// lineage and provenance when one is bound, so the Gate judges the edge
    /// as it judges that session's other claims. `None` writes it under the
    /// Dreamer's own authority with `source`, for a confirm the engine's
    /// seal decides.
    pub(crate) envelope: Option<WriteEnvelope>,
    /// Where the confirming word came from: the edge's source when no
    /// envelope names one.
    pub(crate) source: ClaimSource,
}

/// The provenance a confirm's role edge is written with when no host origin
/// supplies one.
pub(crate) fn role_edge_provenance() -> Result<WriteProvenance> {
    WriteProvenance::new(Value::Map(vec![(
        Value::from("op"),
        Value::from("tagging.confirm_role_person"),
    )]))
}

/// Asserts that `person`, a role person just confirmed from `possessor`'s
/// role phrase for `word`, is the possessor's `word`: one role edge
/// `relationship.<word>` on the possessor valued with the person's id, in
/// the caller's write (Engine ruling LINKER-ROLE-CONFIRM-ASSERTS-ROLE-EDGE =
/// A). The owner's own answer, under the owner's proof, asserts it Approved,
/// so the possessor's next phrase links to the person. Any other confirm
/// asserts it Auto, or Proposed where the Gate would park an Auto write, as
/// a memory commit lands it: an unsure edge, which the re-check asks about.
///
/// The edge is a fact derived from `message`, the possessor's MESSAGE that
/// names the person: it cites that MESSAGE and is born with its audience,
/// in the project and world it is read at and under its TURN's facet, so it
/// reaches no reader the words do not. Returns the edge it wrote; `None`
/// when the possessor is gone, already holds a standing edge for `word`
/// naming the person, or the MESSAGE's audience or place does not resolve:
/// nothing is derived from words no reader reads.
pub(crate) fn assert_role_edge_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (possessor, word): (EntityId, &str),
    person: EntityId,
    message: EntityId,
    by: ConfirmedBy<'_>,
    now: u64,
) -> Result<Option<EntityId>> {
    if !vault.store.port_entity_present(txn, &possessor)? {
        return Ok(None);
    }
    let predicate = role_edge_predicate(word);
    let standing = vault.find_claim_for_subject_in_txn(txn, &possessor, |_, body| {
        role_edge(body, &possessor, &predicate, now)
            .filter(|(named, _)| *named == person)
            .map(|_| ())
    })?;
    if standing.is_some() {
        return Ok(None);
    }
    let id = vault.store.clock.entity_id()?;
    let edge = (&id, predicate.as_str(), possessor, person);
    let source = by
        .envelope
        .as_ref()
        .map_or(by.source, WriteEnvelope::source);
    let Some(candidate) = role_edge_candidate_in_txn(vault, txn, edge, message, source)? else {
        return Ok(None);
    };
    let occurred = TimeRange {
        start: now,
        end: now,
    };
    let authored = match by.owner {
        Some(owner) => owner
            .owner_answer_in_txn(vault, txn)?
            .map(|write| (owner, write)),
        None => None,
    };
    if let Some((owner, authored)) = authored {
        let envelope = WriteEnvelope::new(
            WriteActor::new(owner.revalidate_in_txn(vault, txn)?, EdgeActorClass::Human),
            by.source,
            role_edge_provenance()?,
            ClaimApprovalStatus::Approved,
        );
        vault
            .batch_in()
            .with_owner_authored(Some(authored))
            .claim_candidate(&id, candidate, &envelope, occurred, now)
            .apply(txn)?;
        return Ok(Some(id));
    }
    let unsure = match by.envelope {
        Some(envelope) => envelope,
        None => WriteEnvelope::new(
            vault.dreamer_authority_in_txn(txn, now)?,
            by.source,
            role_edge_provenance()?,
            ClaimApprovalStatus::Auto,
        ),
    };
    // As a memory commit lands it: only a Gate verdict that pends the Auto
    // write is resubmitted as Proposed, in a savepoint the refusal leaves
    // empty; a deny is never resubmitted.
    for approval in [ClaimApprovalStatus::Auto, ClaimApprovalStatus::Proposed] {
        let envelope = unsure.clone().with_approval(approval);
        let mut staged = vault.store.env.nested_write_txn(txn)?;
        match vault
            .batch_in()
            .claim_candidate(&id, candidate.clone(), &envelope, occurred, now)
            .apply(&mut staged)
        {
            Ok(()) => {
                staged.commit()?;
                return Ok(Some(id));
            }
            Err(error)
                if approval == ClaimApprovalStatus::Auto
                    && crate::gate::gate_rejection_pends(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Err(crate::Error::InvariantViolation(
        "a role edge's Proposed write pends",
    ))
}

/// The role edge `id`, `predicate` on `possessor` valued with `person`'s
/// id, as a claim candidate derived from `message` with `source`: it cites
/// the MESSAGE and carries its audience, project, world and TURN's facet.
/// `None` when the MESSAGE's audience or place does not resolve, or it is
/// in more than one TURN.
fn role_edge_candidate_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    (id, predicate, possessor, person): (&EntityId, &str, EntityId, EntityId),
    message: EntityId,
    source: ClaimSource,
) -> Result<Option<ClaimCandidate>> {
    let Some(raw) = vault.get_raw_in(txn, &message)? else {
        return Ok(None);
    };
    // A gated MESSAGE that names no relationship reads only through a grant
    // on its conversation, which a CLAIM never carries: the edge is private.
    let (relationships, private) =
        match crate::claim::relationship_read(&vault.store, txn, &message, &raw)? {
            RelationshipRead::Decided(true) => (None, false),
            RelationshipRead::Decided(false) => return Ok(None),
            RelationshipRead::Gated { space: None, .. } => (None, true),
            RelationshipRead::Gated { space, private, .. } => (space, private),
        };
    let Some((project, world)) = vault.derivation_project_and_world_in_txn(txn, message)? else {
        return Ok(None);
    };
    let turns = vault.filtered_edge_peers(
        txn,
        EdgeDirection::Out,
        &message,
        EdgeKind::PartOf,
        Some(ENTITY_TYPE_TURN),
    )?;
    // Born under its source TURN's facet, as a derivation is (FIX
    // INTENT-FACET-FROM-SOURCE-TURN), or the vault default for a MESSAGE in
    // no TURN.
    let facet = match turns.as_slice() {
        [] => vault.claim_put_facet_in_txn(txn, id)?,
        [turn] => vault.claim_put_facet_of_record_in_txn(txn, id, *turn)?,
        _ => return Ok(None),
    };
    let mut candidate = ClaimCandidate::new(
        predicate,
        ClaimSubject::Entity(possessor),
        Value::from(person.to_hex()),
        1.0,
    )
    .with_evidence(encode_consolidation_evidence(
        &ConsolidationEvidenceEnvelope {
            refs: vec![message],
            chain: Vec::new(),
            source_meet: source,
        },
    ))
    .with_scope_stamps(facet, project);
    if world != crate::claim::base_world_id() {
        candidate = candidate.with_world(world);
    }
    if relationships.is_some() {
        candidate = candidate.with_relationships(relationships);
    }
    if private {
        candidate = candidate.with_scope(Value::Map(vec![(
            Value::from("private"),
            Value::Boolean(true),
        )]));
    }
    Ok(Some(candidate))
}
