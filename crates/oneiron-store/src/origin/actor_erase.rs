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

use crate::git_wire::repo::GitWireRepo;
use crate::origin::publication::publication_types::ORIGIN_PUBLICATION_INTENT_PREDICATE;
use crate::origin::publication::publication_types::ORIGIN_PUBLICATION_PREDICATE;
use crate::origin::publication::publication_types::OriginActor;
use crate::origin::publication::publication_types::OriginPublicationRecord;
use crate::receipt_identity::ERASED_CALL_IDENTITY;
use crate::write_envelope::claim_body::ClaimBody;
use crate::write_envelope::claim_body::ClaimSubject;
use crate::write_envelope::claim_body::decode_claim_body;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_CLAIM;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_contracts::record_layout::EntityMetadataHeader;
use oneiron_contracts::temporal::TimeRange;

/// How an erase reaches an origin claim that names its actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginClaimErase {
    /// The same claim, rewritten naming no one. A superseding copy would
    /// leave the old body readable.
    RewriteInPlace,
}

/// Origin claims are rewritten in place (FIX 3877; a call).
pub const ORIGIN_ACTOR_ERASE_CLAIMS: OriginClaimErase = OriginClaimErase::RewriteInPlace;

/// What becomes of the local proof that pins a rewritten claim's bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginProofErase {
    /// A proof that held the old bytes is re-hashed over the rewritten body
    /// in the same transaction. It then pins the current authorized body,
    /// not the bytes at publication.
    RehashRedactedBody,
}

/// The change receipt and the receive-pack evidence follow the rewrite
/// (FIX 3877; a call).
pub const ORIGIN_ACTOR_ERASE_PROOF: OriginProofErase = OriginProofErase::RehashRedactedBody;

/// What an erased actor's pending origin work may still do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginPendingErase {
    /// No new ref effect starts for it. An effect that already happened is
    /// still observed and finalized, and its journal and evidence stay while
    /// the effect is live; a receive-pack intent nothing can resume any more
    /// is observed and then pruned (FIX 5022).
    RefuseNewEffectsKeepObservedFacts,
}

/// An erased publication or push starts nothing new (FIX 3877; a call).
pub const ORIGIN_ACTOR_ERASE_PENDING: OriginPendingErase =
    OriginPendingErase::RefuseNewEffectsKeepObservedFacts;

/// Who one origin claim names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginClaimActors {
    /// The pusher: the value's `actor_id`, and for some the subject.
    pub pusher: OriginActor,
    /// The host a receive-pack claim's authority stamp names, if it has one.
    pub host: Option<OriginActor>,
}

/// Which roles of one copy must name no one: its pusher, its host.
pub type Roles = (bool, bool);

pub fn field<'a>(body: &'a ClaimBody, key: &str) -> Option<&'a Value> {
    body.value
        .as_map()?
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
}

pub fn field_mut<'a>(body: &'a mut ClaimBody, key: &str) -> Option<&'a mut Value> {
    let Value::Map(fields) = &mut body.value else {
        return None;
    };
    fields
        .iter_mut()
        .find(|entry| entry.0.as_str() == Some(key))
        .map(|entry| &mut entry.1)
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
pub struct Settled {
    /// The held copy's form, when the meeting erases more of it.
    pub held: Option<ClaimBody>,
    /// The carried copy's form, when that differs from it.
    pub carried: Option<ClaimBody>,
}
