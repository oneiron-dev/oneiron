//! White-box tests for the batch apply pipeline, split by topic across child files.

use super::*;
use crate::Vault;
use crate::affect::Vad;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::deletion::DeleteReason;
use crate::edge::EdgeActorClass;
use crate::edge::{
    EDGE_VALUE_SEMANTIC_LEN, EDGE_VALUE_SEMANTIC_PROVENANCED_LEN, EDGE_VALUE_STRUCTURAL_LEN,
    EdgeKind,
};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, ErrorKind, Result};
use crate::habit::TaskRole;
use crate::off_record::OffRecordBackendClass;
use crate::provenance::{EdgeProvenanceClaimBody, EdgeRef, SupersessionStatus};
#[cfg(feature = "sync")]
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_TURN,
};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::test_util::{assert_secret_scan_rejected, embedding_test_config, entity};
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY;
use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY;
use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY;
use crate::write_envelope::WriteActor;
use crate::write_envelope::WriteEnvelope;
use crate::write_envelope::WriteProvenance;
use core::assert_matches;
#[cfg(feature = "sync")]
use ed25519_dalek::{Signer, SigningKey};
use rmpv::Value;
use std::str;

#[cfg(feature = "sync")]
mod authority_log;
mod facet_taint_session;
mod habit_streak;
mod lexical_hints_lifecycle;
mod lexical_hints_policy;
mod provenance_edges;
mod secret_policy_claim;
mod seeded_actors;
mod support;
mod tree_child_of;
mod vectors_embeddings;

use self::support::*;
