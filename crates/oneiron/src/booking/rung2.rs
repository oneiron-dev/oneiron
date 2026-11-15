//! Rung 2 gets its FROM (ARCH-0062:145-147, ARCH-0063:48; INBOX-RESIDUE
//! PR-3b-1).
//!
//! When no slot fits, the page's own agent continues the conversation over
//! email. That email's FROM is the identity the vault's selection law picks
//! for scheduling among the agent's email identities: by default the agent's
//! own named work address (`builtin.scheduling_logistics`). The law never
//! falls through to another face, so a page whose agent holds no live
//! identity of that face does not offer rung 2 at all. It answers with the
//! owner's no-fit line and its slot links, and never asks for an email it
//! cannot use (RUNG2-NO-SENDER = A).
//!
//! The face of each identity is the host's ([`ChannelIdentityFaceClassifier`]),
//! as at every other selection: a face is a role, and no stored fact states
//! it.
//!
//! The first send (INBOX-RESIDUE PR-3b-2) is the page agent's native-mail
//! `send` to the visitor, from that identity. The vault keeps it before it is
//! dispatched ([`Vault::keep_booking_rung2_first_send`]): the exact message,
//! which the owner's press releases when the cold-send law holds it, and the
//! continuation, whose canonical constraint a reply on its thread re-solves
//! on ([`Vault::booking_rung2_thread_first_send`]). The kept copy is keyed by
//! the Message-ID the send goes out under, the one its sent passport files,
//! so the thread finds it with no other row. The email itself carries no
//! machine block, and the visitor's own words are in neither.

use serde::{Deserialize, Serialize};

use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::channel_identity::{
    ChannelIdentityFaceClassifier, channel_identity_selection_candidates_in_txn,
};
use crate::channel_identity_provider::native_mail::{NativeMailAdapter, NativeMailHost};
use crate::channel_identity_provider::stalwart::NativeMailMessage;
use crate::channel_identity_selection::{
    ChannelIdentityFace, ChannelIdentitySelectionError, ChannelIdentitySelectionQuery,
    RelationshipContext, channel_identity_selection_rules_in_txn,
    resolve_channel_identity_selection,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::derived_domains::BOOKING_RUNG2_FIRST_SEND_BLOB;
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchRequest, OutboundIntent, OutboundIntentDraft, OutboundIntentTrigger,
};
use crate::write_envelope::thread_claim::CanonicalMessageId;
use crate::{EntityId, Error, Result, TimeRange, Vault, WriteActor};

use super::agent_front::ConstraintContinuation;
use super::publication::load_public_booking_page_in_txn;

/// The channel a rung-2 continuation is sent on.
pub const BOOKING_RUNG2_CHANNEL: &str = "email";

/// Every rung-2 send ref starts with this prefix.
pub const BOOKING_RUNG2_SEND_REF_PREFIX: &str = "booking-rung2:";

/// The verb of a rung-2 first send.
pub const BOOKING_RUNG2_SEND_VERB: &str = "send";

/// The schema version of a kept rung-2 first send.
pub const BOOKING_RUNG2_FIRST_SEND_SCHEMA_VERSION: u16 = 1;

/// The media type a kept rung-2 first send is stored under.
const RUNG2_FIRST_SEND_MEDIA_TYPE: &str = "application/vnd.oneiron.booking-rung2-first-send+json";

/// Why a page offers no rung 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rung2Unavailable {
    /// The page has no live, published publication.
    PageNotLive,
    /// The publication serves no constraint front.
    NoConstraintFront,
    /// The front names no agent ([`super::agent_front::ConstraintFrontConfig::agent_ref`]).
    NoPageAgent,
    /// The page's agent holds no live email identity of the face the
    /// selection law names for scheduling: by default, no live named work
    /// address.
    NoNamedAddress,
}

/// Who sends a page's rung-2 email: the page's agent, wearing the identity
/// the selection law picked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rung2Sender {
    pub page_ref: EntityId,
    pub agent_ref: EntityId,
    pub identity_ref: EntityId,
    pub facet_ref: Option<EntityId>,
    pub face: ChannelIdentityFace,
}

/// Whether a page offers rung 2 now, and from whom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rung2Offer {
    Offered(Rung2Sender),
    NotOffered(Rung2Unavailable),
}

/// The one ref of a session's rung-2 first send: its intent ref and its
/// idempotency key, so a retried press sends once.
#[must_use]
pub fn rung2_send_ref(page_ref: &EntityId, session_ref: &str) -> String {
    format!(
        "{BOOKING_RUNG2_SEND_REF_PREFIX}{}:{session_ref}",
        page_ref.to_hex()
    )
}

/// A session's rung-2 first send as the vault keeps it: who sends it, the
/// exact message the owner's press releases, and the continuation a reply on
/// its thread re-solves on. The message is the agent's words, and the
/// continuation holds only the canonical constraint, so the visitor's own
/// words are in neither.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rung2FirstSend {
    pub schema_version: u16,
    pub page_ref: EntityId,
    pub agent_ref: EntityId,
    pub identity_ref: EntityId,
    /// [`rung2_send_ref`] of the page and the continuation's session.
    pub send_ref: String,
    /// The canonical Message-ID the send goes out under.
    pub message_id: String,
    pub continuation: ConstraintContinuation,
    pub message: NativeMailMessage,
    /// When it was kept: its dispatch request's time on every attempt.
    pub requested_at: u64,
}

impl Rung2FirstSend {
    /// The send's dispatch request: the page agent's email `send` of this
    /// message from its identity, in the scheduling relationship
    /// (ARCH-0063:48). Its receipt id, intent ref, idempotency key and dedupe
    /// key are the session's send ref, so a retried press sends once; its
    /// content ref is the message's own, so the owner's one-send approval
    /// names these exact words. The same kept send builds the same request
    /// on every attempt.
    ///
    /// # Errors
    ///
    /// A kept message that no longer validates.
    pub fn dispatch_request(&self) -> Result<OutboundDispatchRequest> {
        let draft = OutboundIntentDraft::new(
            self.agent_ref.to_hex(),
            BOOKING_RUNG2_SEND_VERB,
            BOOKING_RUNG2_CHANNEL,
            self.message.to.clone(),
        )
        .content_ref(self.message.content_ref()?)
        .idempotency_key(self.send_ref.clone())
        .dedupe_key(self.send_ref.clone());
        let intent = OutboundIntent::from_trigger(
            draft,
            OutboundIntentTrigger::agent_immediate(self.send_ref.clone()),
        );
        Ok(OutboundDispatchRequest::new(
            self.send_ref.clone(),
            self.send_ref.clone(),
            intent,
            OutboundDispatchActor::agent(self.agent_ref),
            OutboundDispatchGate::allow_when_policy_grants(),
            self.requested_at,
            OutboundDeliveryWindowDecision::DeliverNow,
        )
        .channel_identity_ref(self.identity_ref)
        .send_autonomy(RelationshipContext::SchedulingLogistics, None))
    }
}

impl Vault {
    /// Whether `page_ref` offers rung 2 at `now`, and its FROM, read on one
    /// snapshot: the live publication's front names the page's agent, and the
    /// selection law picks, among that agent's email identities as
    /// `classify_face` classifies them, the scheduling face's active
    /// identity. A refusal of the law for want of a live identity of that
    /// face is [`Rung2Offer::NotOffered`], never another face.
    ///
    /// # Errors
    ///
    /// Storage errors, a stored publication that does not decode, and a
    /// stored selection rule set the law refuses.
    pub fn booking_rung2_offer(
        &self,
        page_ref: EntityId,
        now: u64,
        classify_face: &mut ChannelIdentityFaceClassifier<'_>,
    ) -> Result<Rung2Offer> {
        let txn = self.store.env.read_txn()?;
        let Some(publication) = load_public_booking_page_in_txn(self, &txn, page_ref, now)? else {
            return Ok(Rung2Offer::NotOffered(Rung2Unavailable::PageNotLive));
        };
        let Some(front) = publication.constraint_front else {
            return Ok(Rung2Offer::NotOffered(Rung2Unavailable::NoConstraintFront));
        };
        let Some(agent_ref) = front.agent_ref else {
            return Ok(Rung2Offer::NotOffered(Rung2Unavailable::NoPageAgent));
        };
        let candidates = channel_identity_selection_candidates_in_txn(
            &self.store,
            &txn,
            BOOKING_RUNG2_CHANNEL,
            &agent_ref,
            classify_face,
        )?;
        let decision =
            channel_identity_selection_rules_in_txn(&self.store, &txn).and_then(|rules| {
                resolve_channel_identity_selection(
                    &rules,
                    ChannelIdentitySelectionQuery {
                        relationship: RelationshipContext::SchedulingLogistics,
                        applicable_scopes: &[],
                        candidates: &candidates,
                        thread_pin: None,
                    },
                )
            });
        match decision {
            Ok(decision) => Ok(Rung2Offer::Offered(Rung2Sender {
                page_ref,
                agent_ref,
                identity_ref: decision.identity_ref,
                facet_ref: decision.facet_ref,
                face: decision.face,
            })),
            Err(
                ChannelIdentitySelectionError::NoCandidateForFace
                | ChannelIdentitySelectionError::NoRuleForRelationship
                | ChannelIdentitySelectionError::PinnedCandidateMissing
                | ChannelIdentitySelectionError::PinnedCandidateInactive
                | ChannelIdentitySelectionError::PinnedCandidateFaceMismatch,
            ) => Ok(Rung2Offer::NotOffered(Rung2Unavailable::NoNamedAddress)),
            Err(ChannelIdentitySelectionError::Storage(error)) => Err(error),
            Err(error) => Err(Error::InvalidConfig(error.to_string())),
        }
    }
}

impl Vault {
    /// Keeps `sender`'s rung-2 first send of `message` for the session
    /// `continuation` names, once, written as the page's agent: a send
    /// already kept for that session is returned as it is, whatever
    /// `message` says, so a retried press dispatches the words first kept.
    /// `adapter` names the Message-ID the send goes out under.
    ///
    /// The host composes `message` (the agent's words, never the visitor's)
    /// to the visitor's address; the continuation carries the canonical
    /// constraint. `None` when the agent has been hard-erased; nothing is
    /// written.
    ///
    /// # Errors
    ///
    /// An identity not bound to the sender's agent, an empty session ref, a
    /// constraint or message that does not validate, and storage errors.
    pub fn keep_booking_rung2_first_send<H: NativeMailHost>(
        &self,
        adapter: &NativeMailAdapter<H>,
        sender: &Rung2Sender,
        continuation: ConstraintContinuation,
        message: NativeMailMessage,
        now: u64,
    ) -> Result<Option<Rung2FirstSend>> {
        let invalid = |reason: &str| Error::InvalidConfig(format!("rung-2 first send: {reason}"));
        if continuation.session_ref.trim().is_empty() {
            return Err(invalid("the continuation names no session"));
        }
        continuation
            .constraint
            .validate()
            .map_err(|error| invalid(&error.to_string()))?;
        message.validate()?;
        let bound = self
            .channel_identity_facts(&sender.identity_ref)?
            .is_some_and(|facts| facts.binding.actor_ref() == Some(sender.agent_ref));
        if !bound {
            return Err(invalid("the identity is not the page agent's"));
        }
        let send_ref = rung2_send_ref(&sender.page_ref, &continuation.session_ref);
        let message_id = adapter.send_message_id(&send_ref)?;
        let artifact_id = rung2_first_send_artifact(&message_id)?;
        let kept = Rung2FirstSend {
            schema_version: BOOKING_RUNG2_FIRST_SEND_SCHEMA_VERSION,
            page_ref: sender.page_ref,
            agent_ref: sender.agent_ref,
            identity_ref: sender.identity_ref,
            send_ref,
            message_id: message_id.into_string(),
            continuation,
            message,
            requested_at: now,
        };
        let bytes =
            serde_json::to_vec(&kept).map_err(|_| invalid("the kept send did not encode"))?;
        self.with_write_txn_grouped(|wtxn| {
            if self.local_hard_delete_marker_exists_in_txn(wtxn, &kept.agent_ref)? {
                return Ok(None);
            }
            let existing = self.get_blob_artifact_in_txn(wtxn, &artifact_id)?;
            if existing.is_some() {
                if let Some(first) = self.kept_rung2_first_send_in_txn(wtxn, &artifact_id)? {
                    return Ok(Some(first));
                }
            } else {
                let at = TimeRange {
                    start: now,
                    end: now,
                };
                crate::ports::EntityStore::port_entity_put(
                    self,
                    wtxn,
                    &artifact_id,
                    &crate::ports::EntityRecord {
                        entity_type: crate::registry::ENTITY_TYPE_BLOB_ARTIFACT,
                        occurred: at,
                        learned_at: now,
                        row_version: 0,
                        body: crate::blob_artifact::encode_blob_artifact_body(
                            &BlobArtifactBody::new(
                                kept.send_ref.clone(),
                                RUNG2_FIRST_SEND_MEDIA_TYPE,
                            ),
                        )?,
                    },
                )?;
            }
            self.append_blob_artifact_version_in_txn(
                wtxn,
                &artifact_id,
                &bytes,
                &BlobVersionProvenance::AgentRun {
                    run_ref: kept.send_ref.clone(),
                },
                WriteActor::new(kept.agent_ref, EdgeActorClass::Agent),
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )?;
            Ok(Some(kept.clone()))
        })
    }

    /// The session's kept rung-2 first send on `page_ref`, the one the
    /// owner's press releases: `None` before it is kept. `adapter` names the
    /// Message-ID it is kept under.
    ///
    /// # Errors
    ///
    /// Storage errors, and a kept send that does not decode.
    pub fn booking_rung2_first_send<H: NativeMailHost>(
        &self,
        adapter: &NativeMailAdapter<H>,
        page_ref: EntityId,
        session_ref: &str,
    ) -> Result<Option<Rung2FirstSend>> {
        let message_id = adapter.send_message_id(&rung2_send_ref(&page_ref, session_ref))?;
        let artifact_id = rung2_first_send_artifact(&message_id)?;
        let rtxn = self.store.env.read_txn()?;
        self.kept_rung2_first_send_in_txn(&rtxn, &artifact_id)
    }

    /// The rung-2 first send `thread_ref`'s thread began with: the kept send
    /// whose Message-ID a passport on the thread names, from the identity
    /// that passport names. A delivered first send files that passport
    /// itself, and the visitor's reply lands on its thread, so the reply
    /// re-solves on this send's continuation. `None` for a thread no rung-2
    /// first send began.
    ///
    /// # Errors
    ///
    /// A malformed `thread_ref`, storage errors, and a kept send that does
    /// not decode.
    pub fn booking_rung2_thread_first_send(
        &self,
        thread_ref: &str,
    ) -> Result<Option<Rung2FirstSend>> {
        let passports = self.thread_passports(thread_ref)?;
        let rtxn = self.store.env.read_txn()?;
        for passport in passports {
            let artifact_id = rung2_first_send_artifact(&passport.message_id)?;
            if let Some(kept) = self.kept_rung2_first_send_in_txn(&rtxn, &artifact_id)?
                && kept.identity_ref == passport.identity_ref
                && kept.message_id == passport.message_id.as_str()
            {
                return Ok(Some(kept));
            }
        }
        Ok(None)
    }

    /// The first kept version of the rung-2 first send `artifact_id`: a live
    /// artifact of the kept media type, written by its own send's run.
    fn kept_rung2_first_send_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        artifact_id: &EntityId,
    ) -> Result<Option<Rung2FirstSend>> {
        match self.get_blob_artifact_in_txn(rtxn, artifact_id)? {
            Some(body) if body.media_type == RUNG2_FIRST_SEND_MEDIA_TYPE => {}
            _ => return Ok(None),
        }
        let Some(first) = self
            .blob_artifact_versions_in_txn(rtxn, artifact_id)?
            .into_iter()
            .next()
        else {
            return Ok(None);
        };
        let Some(bytes) =
            self.read_blob_artifact_version_in_txn(rtxn, artifact_id, first.version)?
        else {
            return Ok(None);
        };
        let kept: Rung2FirstSend = serde_json::from_slice(&bytes)
            .map_err(|_| Error::InvalidClaimBody("a kept rung-2 first send does not decode"))?;
        let own_run = matches!(
            &first.provenance,
            BlobVersionProvenance::AgentRun { run_ref } if *run_ref == kept.send_ref
        );
        if kept.schema_version != BOOKING_RUNG2_FIRST_SEND_SCHEMA_VERSION || !own_run {
            return Err(Error::InvalidClaimBody(
                "a kept rung-2 first send is not its own send's",
            ));
        }
        Ok(Some(kept))
    }
}

/// The BLOB artifact a rung-2 first send going out under `message_id` is
/// kept in.
fn rung2_first_send_artifact(message_id: &CanonicalMessageId) -> Result<EntityId> {
    EntityId::derive(
        BOOKING_RUNG2_FIRST_SEND_BLOB,
        &[message_id.as_str().as_bytes()],
    )
}
