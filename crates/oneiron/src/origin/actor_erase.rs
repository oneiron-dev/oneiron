//! An erased actor out of origin's claim bodies (FIX 3877).
//!
//! The intent, publication and change claims, and the receive-pack admission
//! and outcome claims, name their pusher in the value and, some of them, in
//! the subject. The receive-pack claims also name the host their authority
//! stamp was admitted under. The journal scrub does not reach them. An erase
//! rewrites each claim in place: it keeps its id, header, status, outcomes and
//! scope stamp and names no one, and its revision ledger starts over from the
//! rewritten row. A subject that named the pusher names a real id of the claim
//! instead: an intent its own id, an outcome its operation, an admission its
//! operation alone. No such claim authorizes a new effect: the acting readers
//! compare it with the live request, which always names someone.

use rmpv::Value;

use super::change_index::ORIGIN_CHANGE_PREDICATE;
use super::publication::{
    ORIGIN_PUBLICATION_INTENT_PREDICATE, ORIGIN_PUBLICATION_PREDICATE, OriginActor,
    OriginPublicationRecord,
};
use super::residence::ORIGIN_ERASED_WRITER;
use super::smart_http::{RECEIVE_PACK_ADMISSION_PREDICATE, RECEIVE_PACK_OUTCOME_PREDICATE};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimSubject, decode_claim_body};
use crate::deletion::carrier_actor_merged;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::GitWireRepo;
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::temporal::TimeRange;

/// How an erase reaches an origin claim that names its actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OriginClaimErase {
    /// The same claim, rewritten naming no one. A superseding copy would
    /// leave the old body readable.
    RewriteInPlace,
}

/// Origin claims are rewritten in place (FIX 3877; a call).
pub(crate) const ORIGIN_ACTOR_ERASE_CLAIMS: OriginClaimErase = OriginClaimErase::RewriteInPlace;

/// What becomes of the local proof that pins a rewritten claim's bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OriginProofErase {
    /// A proof that held the old bytes is re-hashed over the rewritten body
    /// in the same transaction. It then pins the current authorized body,
    /// not the bytes at publication.
    RehashRedactedBody,
}

/// The change receipt and the receive-pack evidence follow the rewrite
/// (FIX 3877; a call).
pub(crate) const ORIGIN_ACTOR_ERASE_PROOF: OriginProofErase = OriginProofErase::RehashRedactedBody;

/// What an erased actor's pending origin work may still do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OriginPendingErase {
    /// No new ref effect starts for it. An effect that already happened is
    /// still observed and finalized, and its journal and evidence stay.
    RefuseNewEffectsKeepObservedFacts,
}

/// An erased publication or push starts nothing new (FIX 3877; a call).
pub(crate) const ORIGIN_ACTOR_ERASE_PENDING: OriginPendingErase =
    OriginPendingErase::RefuseNewEffectsKeepObservedFacts;

/// An origin claim family that names an actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OriginClaimKind {
    Intent,
    Publication,
    Change,
    Admission,
    Outcome,
}

impl OriginClaimKind {
    /// The families the publication protocol writes.
    pub(crate) const PUBLICATION: [Self; 3] = [Self::Intent, Self::Publication, Self::Change];
    /// The families the receive-pack observer writes beside its receipts.
    pub(crate) const RECEIVE_PACK: [Self; 2] = [Self::Admission, Self::Outcome];

    /// The family `predicate` names, if it is one.
    pub(crate) fn of(predicate: &str) -> Option<Self> {
        Self::PUBLICATION
            .into_iter()
            .chain(Self::RECEIVE_PACK)
            .find(|kind| kind.predicate() == predicate)
    }

    pub(crate) const fn predicate(self) -> &'static str {
        match self {
            Self::Intent => ORIGIN_PUBLICATION_INTENT_PREDICATE,
            Self::Publication => ORIGIN_PUBLICATION_PREDICATE,
            Self::Change => ORIGIN_CHANGE_PREDICATE,
            Self::Admission => RECEIVE_PACK_ADMISSION_PREDICATE,
            Self::Outcome => RECEIVE_PACK_OUTCOME_PREDICATE,
        }
    }
}

/// Who one origin claim names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OriginClaimActors {
    /// The pusher: the value's `actor_id`, and for some the subject.
    pub(crate) pusher: OriginActor,
    /// The host a receive-pack claim's authority stamp names, if it has one.
    pub(crate) host: Option<OriginActor>,
}

/// Which roles of one copy must name no one: its pusher, its host.
type Roles = (bool, bool);

fn field<'a>(body: &'a ClaimBody, key: &str) -> Option<&'a Value> {
    body.value
        .as_map()?
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
}

fn field_mut<'a>(body: &'a mut ClaimBody, key: &str) -> Option<&'a mut Value> {
    let Value::Map(fields) = &mut body.value else {
        return None;
    };
    fields
        .iter_mut()
        .find(|entry| entry.0.as_str() == Some(key))
        .map(|entry| &mut entry.1)
}

/// Who `body` of `kind` names, or `None` when it does not spell them.
pub(crate) fn claim_actors(kind: OriginClaimKind, body: &ClaimBody) -> Option<OriginClaimActors> {
    let pusher = OriginActor::from_hex(field(body, "actor_id")?.as_str()?).ok()?;
    let host = match (kind, field(body, "origin_authority")) {
        (OriginClaimKind::Admission | OriginClaimKind::Outcome, Some(Value::Array(stamp))) => {
            Some(OriginActor::from_hex(stamp.get(2)?.as_str()?).ok()?)
        }
        _ => None,
    };
    Some(OriginClaimActors { pusher, host })
}

/// `body` of `kind` at `id` with its pusher, its host or both naming no one.
/// A subject that named the pusher names a real id of the claim instead.
pub(crate) fn erased_claim(
    kind: OriginClaimKind,
    id: &EntityId,
    body: &ClaimBody,
    (pusher, host): Roles,
) -> Option<ClaimBody> {
    let mut erased = body.clone();
    if pusher {
        *field_mut(&mut erased, "actor_id")? = Value::from(ERASED_CALL_IDENTITY);
        if let ClaimSubject::Edge {
            source,
            kind: edge,
            target,
        } = body.subject
        {
            erased.subject = match kind {
                OriginClaimKind::Intent => ClaimSubject::Edge {
                    source: *id,
                    kind: edge,
                    target,
                },
                OriginClaimKind::Outcome => ClaimSubject::Edge {
                    source: EntityId::from_hex(field(body, "operation_id")?.as_str()?).ok()?,
                    kind: edge,
                    target,
                },
                OriginClaimKind::Admission => ClaimSubject::Entity(source),
                OriginClaimKind::Publication | OriginClaimKind::Change => body.subject,
            };
        }
    }
    if host && let Some(Value::Array(stamp)) = field_mut(&mut erased, "origin_authority") {
        *stamp.get_mut(2)? = Value::from(ORIGIN_ERASED_WRITER);
    }
    Some(erased)
}

/// `body` naming no one where it names `actor`, when it names it.
pub(crate) fn erased_for(
    kind: OriginClaimKind,
    id: &EntityId,
    body: &ClaimBody,
    actor: &EntityId,
) -> Option<ClaimBody> {
    let actors = claim_actors(kind, body)?;
    let pusher = actors.pusher == *actor;
    let host = actors.host.is_some_and(|host| host == *actor);
    (pusher || host)
        .then(|| erased_claim(kind, id, body, (pusher, host)))
        .flatten()
}

/// Where `held` and `carried` differ only in who they name, the roles each
/// must erase to settle by [`crate::deletion::ACTOR_ERASE_CARRIER_MERGE`]
/// (`None` for a copy that already stands). `None` when they differ in
/// anything else, or two live actors meet.
fn merged_erasure(
    kind: OriginClaimKind,
    id: &EntityId,
    held: &ClaimBody,
    carried: &ClaimBody,
) -> Option<(Option<Roles>, Option<Roles>)> {
    let (in_held, in_carried) = (claim_actors(kind, held)?, claim_actors(kind, carried)?);
    if erased_claim(kind, id, held, (true, true))? != erased_claim(kind, id, carried, (true, true))?
    {
        return None;
    }
    let pusher = carrier_actor_merged(in_held.pusher, in_carried.pusher, OriginActor::Erased)?;
    let host = carrier_actor_merged(in_held.host, in_carried.host, Some(OriginActor::Erased))?;
    let erases = |copy: OriginClaimActors| {
        let roles = (copy.pusher != pusher, copy.host != host);
        (roles.0 || roles.1).then_some(roles)
    };
    Some((erases(in_held), erases(in_carried)))
}

/// Whether `to` is `from` with more of whom it names erased, and nothing
/// else changed.
pub(crate) fn erases_more(
    kind: OriginClaimKind,
    id: &EntityId,
    from: &ClaimBody,
    to: &ClaimBody,
) -> bool {
    merged_erasure(kind, id, from, to)
        .is_some_and(|(held, carried)| held.is_some() && carried.is_none())
}

/// How a held and a carried copy of one origin claim settle (FIX 3877), the
/// one rule ingest, the reverse mirror and the export scrub share. The
/// carried copy names no one where this vault erased whom it names
/// ([`crate::deletion::ACTOR_ERASE_CARRIER_SOURCE`]). Where the two then
/// differ only in who they name, each role settles by
/// [`crate::deletion::ACTOR_ERASE_CARRIER_MERGE`]; two live actors still
/// conflict, as any other difference does. Never an authority or replay
/// check.
#[cfg(feature = "sync")]
#[derive(Debug, Default)]
pub(crate) struct Settled {
    /// The held copy's form, when the meeting erases more of it.
    pub(crate) held: Option<ClaimBody>,
    /// The carried copy's form, when that differs from it.
    pub(crate) carried: Option<ClaimBody>,
}

/// [`Settled`] for `carried`, at `id`, beside `held`.
///
/// # Errors
///
/// A hard-delete marker that cannot be read.
#[cfg(feature = "sync")]
pub(crate) fn settle_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    kind: OriginClaimKind,
    id: &EntityId,
    held: Option<&ClaimBody>,
    carried: &ClaimBody,
) -> Result<Settled> {
    let Some(named) = claim_actors(kind, carried) else {
        return Ok(Settled::default());
    };
    let erased_here = |actor: Option<OriginActor>| match actor.and_then(OriginActor::id) {
        Some(actor) => vault.carrier_actor_erased_in_txn(txn, &actor),
        None => Ok(false),
    };
    let roles = (erased_here(Some(named.pusher))?, erased_here(named.host)?);
    let mut now = carried.clone();
    if roles.0 || roles.1 {
        now = erased_claim(kind, id, carried, roles).unwrap_or(now);
    }
    let mut settled = Settled::default();
    if let Some(held) = held
        && let Some((in_held, in_now)) = merged_erasure(kind, id, held, &now)
    {
        settled.held = in_held.and_then(|roles| erased_claim(kind, id, held, roles));
        if let Some(roles) = in_now {
            now = erased_claim(kind, id, &now, roles).unwrap_or(now);
        }
    }
    settled.carried = (now != *carried).then_some(now);
    Ok(settled)
}

/// The canonical form of a captured row `raw` at `id` (FIX 5023): an origin
/// claim settled against the copy this vault holds by [`settle_in_txn`], as
/// every export carries it, so a recovery artifact never names an actor this
/// vault erased. Its id, header, status and outcomes stay, and two live
/// actors still conflict and keep the captured bytes. `None` for a row that
/// is not an origin claim, or one that settles as captured.
///
/// # Errors
///
/// Storage errors, or a settled body that does not encode.
#[cfg(feature = "sync")]
pub(crate) fn canonical_origin_claim_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<Option<Vec<u8>>> {
    let Some((kind, captured)) = origin_claim_row(raw) else {
        return Ok(None);
    };
    let held = held_claim_in_txn(vault, txn, kind, id)?;
    let Some(settled) = settle_in_txn(vault, txn, kind, id, held.as_ref(), &captured)?.carried
    else {
        return Ok(None);
    };
    let mut blob = raw
        .get(..ENTITY_METADATA_HEADER_LEN)
        .ok_or(Error::CorruptedIndex("origin claim header"))?
        .to_vec();
    blob.extend_from_slice(&crate::claim::encode_claim_body(&settled)?);
    Ok(Some(blob))
}

/// The origin family and body of a whole CLAIM row, if it is one.
pub(crate) fn origin_claim_row(raw: &[u8]) -> Option<(OriginClaimKind, ClaimBody)> {
    let header = EntityMetadataHeader::parse(raw)?;
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return None;
    }
    let body = decode_claim_body(raw.get(ENTITY_METADATA_HEADER_LEN..)?, true).ok()?;
    Some((OriginClaimKind::of(&body.predicate)?, body))
}

/// The claim of `kind` this vault holds at `id`, if any.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn held_claim_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    kind: OriginClaimKind,
    id: &EntityId,
) -> Result<Option<ClaimBody>> {
    let Some(raw) = vault.get_raw_in(txn, id)? else {
        return Ok(None);
    };
    Ok(origin_claim_row(&raw)
        .filter(|(held, _)| *held == kind)
        .map(|(_, body)| body))
}

/// Refuses writing `body` at `id` where the claim this vault holds there is
/// its erased form: no writer names erased history again.
///
/// # Errors
///
/// That refusal, or storage errors.
pub(crate) fn refuse_renaming_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
) -> Result<()> {
    let Some(kind) = OriginClaimKind::of(&body.predicate) else {
        return Ok(());
    };
    if let Some(held) = held_claim_in_txn(vault, txn, kind, id)?
        && erases_more(kind, id, body, &held)
    {
        return Err(Error::InvariantViolation(
            "an erased origin claim is not named again",
        ));
    }
    Ok(())
}

/// One stored claim's rewrite in place.
pub(crate) struct ClaimRewrite<'a> {
    pub(crate) id: &'a EntityId,
    /// The body bytes the claim holds now.
    pub(crate) held: &'a [u8],
    header: EntityMetadataHeader,
    pub(crate) erased: &'a ClaimBody,
}

impl ClaimRewrite<'_> {
    /// Writes the rewritten body over the claim, its header times unchanged.
    pub(crate) fn put_in_txn(&self, vault: &Vault, wtxn: &mut heed::RwTxn<'_>) -> Result<()> {
        let occurred = TimeRange {
            start: self.header.occurred_start,
            end: self.header.occurred_end,
        };
        vault.put_reserved_claim_in_txn(
            wtxn,
            self.id,
            self.erased,
            occurred,
            self.header.learned_at,
        )
    }
}

/// Rewrites the stored claim `id` of `kind` as `erased` in place
/// ([`ORIGIN_ACTOR_ERASE_CLAIMS`]). Its header times stay, its local proof
/// follows it ([`ORIGIN_ACTOR_ERASE_PROOF`]), and its revision ledger starts
/// over from the rewritten row, so no retained revision keeps the old body.
///
/// # Errors
///
/// Storage errors, or a body the claim door refuses.
pub(crate) fn redact_origin_claim_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    kind: OriginClaimKind,
    id: &EntityId,
    erased: &ClaimBody,
) -> Result<()> {
    let raw = vault.get_raw_in(wtxn, id)?.ok_or(Error::EntityNotFound)?;
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("origin claim header"))?;
    let rewrite = ClaimRewrite {
        id,
        held: &raw[ENTITY_METADATA_HEADER_LEN..],
        header,
        erased,
    };
    match ORIGIN_ACTOR_ERASE_CLAIMS {
        OriginClaimErase::RewriteInPlace => match kind {
            OriginClaimKind::Change => vault.redact_origin_change_in_txn(wtxn, &rewrite)?,
            OriginClaimKind::Admission | OriginClaimKind::Outcome => {
                vault.redact_receive_pack_claim_in_txn(wtxn, &rewrite)?;
            }
            OriginClaimKind::Intent | OriginClaimKind::Publication => {
                rewrite.put_in_txn(vault, wtxn)?;
            }
        },
    }
    crate::vault::entity_revision::remove_entity_revisions(&vault.store, wtxn, id)?;
    let raw = vault.get_raw_in(wtxn, id)?.ok_or(Error::EntityNotFound)?;
    crate::vault::entity_revision::capture_entity_revision(&vault.store, wtxn, id, &raw)
}

/// Rewrites every stored claim of `kinds` that names `actor`, whether or not
/// a journal row or receipt stands beside it.
///
/// # Errors
///
/// Storage errors, or a claim that cannot be rewritten.
pub(crate) fn erase_claims_naming_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
    kinds: &[OriginClaimKind],
) -> Result<()> {
    let mut rewrites = Vec::new();
    for kind in kinds {
        vault.for_each_claim_with_predicate_in_txn(wtxn, kind.predicate(), |id, body| {
            rewrites.extend(erased_for(*kind, &id, &body, actor).map(|erased| (*kind, id, erased)));
            Ok(())
        })?;
    }
    for (kind, id, erased) in &rewrites {
        redact_origin_claim_in_txn(vault, wtxn, *kind, id, erased)?;
    }
    Ok(())
}

/// Erasing `actor` from origin's publication claims (FIX 3877): each intent,
/// publication and change claim that names it, with a journal row or none,
/// is rewritten in place naming no one. Its state, ref, objects and times
/// stay, and nothing is retried. One-way, in the erase's own transaction. An
/// id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a claim that cannot be rewritten.
pub(crate) fn erase_publication_claim_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::typed_body::names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    erase_claims_naming_in_txn(vault, wtxn, actor, &OriginClaimKind::PUBLICATION)
}

impl Vault {
    /// Why a `Prepared` publication may not start its ref effect now, or
    /// `None` when it may. An erased actor's publication starts none
    /// ([`ORIGIN_ACTOR_ERASE_PENDING`]), and the current authority epoch must
    /// permit it. A publication whose effect already happened is observed and
    /// finalized as before; this is not asked of it.
    pub(in crate::origin) fn origin_new_effect_refusal(
        &self,
        repo: &GitWireRepo,
        record: &OriginPublicationRecord,
    ) -> Option<&'static str> {
        match ORIGIN_ACTOR_ERASE_PENDING {
            OriginPendingErase::RefuseNewEffectsKeepObservedFacts
                if record.actor_id == OriginActor::Erased =>
            {
                return Some("the actor of this origin publication was erased");
            }
            OriginPendingErase::RefuseNewEffectsKeepObservedFacts => {}
        }
        self.require_origin_authority(repo, record.publication_id)
            .is_err()
            .then_some("origin authority epoch no longer permits this publication")
    }
}
