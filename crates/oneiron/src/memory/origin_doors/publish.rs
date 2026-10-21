//! The exact publish doors (FIX 6866): request, review, get, approve,
//! execute and cancel one exact-commit publish to a repository's mirror.
//!
//! Unlike the owner-only setup doors beside them, these admit two callers:
//! the owner's own live proof, or this handle's own actor under one live
//! Grant, which the engine judges in each snapshot the act reads or commits
//! in (`origin::publish`). The handle's actor is the caller; a request field
//! never names one, and no embedded-owner shortcut stands in for a Grant.

use super::*;
use crate::origin::publish::{
    OriginPublishApproveRequest, OriginPublishCaller, OriginPublishDenial, OriginPublishIdRequest,
    OriginPublishRequestInput, OriginPublishRequestView, OriginPublishReviewRequest,
    OriginPublishReviewView, PublishAnswer,
};

/// Who calls a publish door, as its host bound it.
#[derive(Debug, Clone)]
pub enum OriginPublishProof {
    /// The owner's live proof, naming this handle's own human actor.
    Owner(AuthenticatedOwner),
    /// This handle's own actor, admitted by one Grant in the door's snapshot.
    Member,
}

impl Memory<'_> {
    /// An embedded handle's publish caller: the vault owner's proof when the
    /// handle is the embedded owner's, else the handle's own actor.
    pub fn origin_publish_proof(&self, verb: &str) -> OriginPublishProof {
        self.embedded_owner(verb)
            .map_or(OriginPublishProof::Member, OriginPublishProof::Owner)
    }

    pub fn origin_publish_request_as(
        &self,
        proof: &OriginPublishProof,
        input: OriginPublishRequestInput,
    ) -> MemoryResult<OriginPublishRequestView> {
        publish_answer(
            self.vault
                .origin_publish_request(&self.publish_caller(proof), input)?,
        )
    }

    pub fn origin_publish_review_as(
        &self,
        proof: &OriginPublishProof,
        input: OriginPublishReviewRequest,
    ) -> MemoryResult<OriginPublishReviewView> {
        publish_answer(
            self.vault
                .origin_publish_review(&self.publish_caller(proof), input)?,
        )
    }

    pub fn origin_publish_get_as(
        &self,
        proof: &OriginPublishProof,
        input: OriginPublishIdRequest,
    ) -> MemoryResult<OriginPublishRequestView> {
        publish_answer(
            self.vault
                .origin_publish_get(&self.publish_caller(proof), input)?,
        )
    }

    pub fn origin_publish_approve_as(
        &self,
        proof: &OriginPublishProof,
        input: OriginPublishApproveRequest,
    ) -> MemoryResult<OriginPublishRequestView> {
        publish_answer(
            self.vault
                .origin_publish_approve(&self.publish_caller(proof), input)?,
        )
    }

    pub fn origin_publish_execute_as(
        &self,
        proof: &OriginPublishProof,
        input: OriginPublishIdRequest,
    ) -> MemoryResult<OriginPublishRequestView> {
        publish_answer(
            self.vault
                .origin_publish_execute(&self.publish_caller(proof), input)?,
        )
    }

    pub fn origin_publish_cancel_as(
        &self,
        proof: &OriginPublishProof,
        input: OriginPublishIdRequest,
    ) -> MemoryResult<OriginPublishRequestView> {
        publish_answer(
            self.vault
                .origin_publish_cancel(&self.publish_caller(proof), input)?,
        )
    }

    fn publish_caller<'a>(&self, proof: &'a OriginPublishProof) -> OriginPublishCaller<'a> {
        OriginPublishCaller {
            actor: self.actor,
            class: self.actor_class,
            owner: match proof {
                OriginPublishProof::Owner(owner) => Some(owner),
                OriginPublishProof::Member => None,
            },
        }
    }
}

/// A publish answer at the door: a denied caller is `FORBIDDEN`, its code
/// leading the message.
fn publish_answer<T>(answer: PublishAnswer<T>) -> MemoryResult<T> {
    answer.map_err(|OriginPublishDenial { code, message }| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{code}: {message}"),
            &[
                "Act as the vault's owner, or under one live Grant whose repo bounds admit this \
                 branch and every reviewed path and whose Scope lists publish.",
            ],
        )
    })
}
