//! Workspace roster preset + member onboarding (ONEIRON-ARCH-0065).
//!
//! # This module assembles; it does not invent
//!
//! A workplace is a house mind plus one companion per principal,
//! sharing one presence. Every part of that already exists as a generic rail:
//! the house mind is a seeded `AGENT_DEF` row ([`crate::agent_def`]) anchored
//! to the workspace `ORG` through [`crate::subject_model`], a companion is a
//! model-substrate `PERSON` with its own actor anchor and PERSON persona baseline,
//! membership is a [`crate::federation::FederationGrant`], and a
//! delegated mailbox is a [`crate::channel_identity::ChannelIdentity`]. This
//! module is the assembly order and the crash-safe journal around it. It adds
//! no entity kind, no compiled persona, and no product name.
//!
//! # Names are runtime data
//!
//! [`WorkspaceRosterPreset::venture_name`] and every display name arrive in the
//! intent. Nothing venture- or product-named compiles into this file: the same
//! binary, pointed at two vaults with different venture names, produces two
//! differently named house minds. `@Oneiron` is not a constant here — it is
//! merely what the roster reads back when a deployment's venture name happens
//! to be `Oneiron`.
//!
//! The house mind's display name defaults to `venture_name` and is overridden
//! by [`WorkspaceRosterPreset::house_display_name`] when an owner has set one.
//! It deliberately does NOT read the seeded row's own `display_name`: that
//! field is the system ROLE label an L1-ENTITY seed ships ("Scout", "Keeper"),
//! which is a different thing from what a house is called. Keeping the house
//! name in this module's preset also means onboarding never writes into an
//! L1-ENTITY-owned seeded row.
//!
//! # There is still no ACTOR entity kind
//!
//! Onboarding links an existing member `PERSON` to an `AGENT_DEF` through
//! [`crate::subject_model::anchor_actor_subject`]. It never mints an `ACTOR`
//! type byte — see the [`crate::subject_model`] module header for why that door
//! stays closed.
//!
//! # The journal is the resume contract
//!
//! Caller-supplied entity ids and the exact desired bounds are digest-pinned.
//! A crash resumes at the next unfinished step without re-minting grants.
//! Completed mailbox replays re-prove live autonomy before returning the prior
//! outcome. Different input under the same id fails typed, never overwrites.
//!
//! # Ownership fences
//!
//! FED-SYNC owns `federation.rs`, L1-ENTITY owns the seeded agent-definition
//! rows, ONE-1831 owns subject anchoring. This module calls their public
//! contracts and writes only its own `vault_meta` prefixes plus the entities
//! the intent explicitly names.

use std::io::Cursor;

use rmpv::Value;

use crate::Vault;
use crate::access_grant::AccessGrant;
use crate::agent_def::{AgentDefinition, encode_agent_definition};
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::channel_identity::{
    AssignmentKey, ChannelIdentityBinding, ChannelIdentityState, DelegatedGrant,
    DelegatedGrantScope, DelegatedProvisionRequest,
};
use crate::channel_identity_autonomy::{
    ChannelIdentityAutonomyRequest, ChannelIdentityAutonomyRung,
};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
    decode_federation_grant_body, encode_federation_grant_body,
};
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_FACET,
    ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON,
};
use crate::side_table::{self, CodecError, HexId, Raw, RawValue, SideKey, SideTable};
use crate::subject_model::actor_subject_anchor;
#[cfg(test)]
use crate::subject_model::{PersonSubstrate, person_substrate};
use crate::temporal::TimeRange;

use crate::write_envelope::WriteActor;

mod codec;
mod intent;
mod records;
mod runner;
mod sharing;
mod steps;
mod work_companion;

use codec::*;
use steps::*;

pub use self::intent::CompanionChoice;
pub use self::intent::{
    CompanionBirthIntent, DelegatedMailboxOnboarding, MemberGrantBundle, MemberOnboardingIntent,
    WorkspaceRosterPreset,
};
use self::records::{
    MAX_NAME_BYTES, MEMBER, ONBOARDING, ONBOARDING_STEPS, OnboardingJournal, OnboardingJournalRow,
    PRESET, ROSTER_KEY_SEPARATOR, RosterMemberKey, RosterMemberRow,
};
pub use self::records::{
    MemberOnboardingOutcome, MemberOnboardingStep, WORKSPACE_ROSTER_SCHEMA_VERSION,
    WorkspaceRosterEntry, WorkspaceRosterRole,
};
pub use self::sharing::{
    CompanionSharingStored, CompanionSharingTarget, CompanionSharingView, RoomSharingClamp,
    RoomSharingView,
};
pub use self::work_companion::WorkCompanionPolicy;

#[cfg(test)]
mod tests;

mod project;
#[cfg(all(test, feature = "sync"))]
pub(crate) use project::create_project_signed_for_test;
#[cfg(test)]
pub(crate) use project::set_project_depth_signed_for_test;
pub(crate) use project::{
    ClaimedProjectDetection, ProjectDetectionAnswer, ProjectDetectionSource,
    ProjectDetectionVerdict, claim_project_detection, fail_project_detection, project_house_agent,
    settle_project_detection, stage_project_detection_in_txn,
};
pub use project::{
    DEFAULT_PROJECT_CYCLE_WORLDS_MAX, DEFAULT_PROJECT_HISTORY_MAX_REVISIONS, OwnerProjectSigner,
    ProjectAsk, ProjectCycleQuestion, ProjectDisposition, ProjectEffective, ProjectForkConflict,
    ProjectForkEvidence, ProjectForkOutcome, ProjectFrontier, ProjectHistoryOverBudget,
    ProjectHistoryPolicy, ProjectHistoryQuestion, ProjectParentWitness, ProjectRank,
    ProjectResolution, ProjectRevision, ProjectRevisionHash, ProjectRevisionProof,
    ProjectRosterWriteOutcome, ProjectRosterWriteRequest, ProjectSeal, ProjectWitness,
    ProjectWriteOutcome,
};
pub use project::{
    GoalAxis, GoalExplorationBudget, GoalInterviewTurns, GoalPreference, GoalRecord,
    LEADER_CHAT_RULE_PREDICATE, LeaderChat, MessageHangs, PROJECT_TYPE_BYTE, ProjectAnchor,
    ProjectAuthority, ProjectBudgetShare, ProjectGoalRecord, ProjectMintReceipt,
    ProjectProofVersion, ProjectQuarantine, ProjectRecord, ProjectRole, ProjectRoom,
    ProjectRoomChange, ProjectVerdict, ProjectWidenAsk, ProjectWidenAxis, ProjectWriteProof,
    RoomOriginCard,
};
pub(crate) use project::{
    GoalLimits, HUB_BELONGS_TO_LAMBDA, LEADER_CHAT_FIELD, PROJECT_PACK, PROJECT_SHORT_ID_PREFIX,
    ProjectReader, admit_leader_chat_turn, admit_leader_chat_witness, deindex_project_room,
    guard_goal_claim_put, guard_goal_delete, guard_goal_pointer_put, is_project_entity,
    is_project_type, leader_chat_allowed, leader_chat_record_permitted, normalize_project_body,
    note_project_proof, permit_leader_chat_record, precheck_goal_delete,
    project_mint_gate_refs_in_txn, project_room_dependency, reconcile_project_rooms,
    retire_goal_for_delete, room_facets_in, root_project_in, seed_root_project,
    settle_leader_chat_record, validate_local_leader_chat_turns, validate_project_body,
    validate_project_edge_delete, validate_project_edge_put, validate_project_graph,
    validate_project_transition, validate_room_body, verify_existing_leader_chat_turn,
};
pub(crate) use project::{
    PROJECT_REVISION_SHORT_ID_PREFIX, ProjectForks, capture_before_tear, capture_project_put,
    check_revision_put, is_project_revision_type, project_revision_type, projects_touched_by_put,
    rebuild_project_revision_indexes, refresh_project_frontiers, refuse_revision_delete,
};
pub use project::{
    ProjectCardConfirmRequest, ProjectCardRecord, ProjectCardState, ProjectGoalInterviewContext,
    ProjectProposalRequest,
};
#[cfg(feature = "sync")]
pub(crate) use project::{
    decode_revision, exportable_revisions_in_txn, forged_revision_in_txn,
    inadmissible_revision_carriers,
};

mod rooms;
pub(crate) use rooms::admit_witness as admit_room_witness;
pub(crate) use rooms::{
    ROOM_THREAD_KEY, ThreadBinding, ThreadPlace, record_thread_admits_in,
    require_thread_audience_in, stamp_thread, thread_audience_allows_in, thread_audience_in,
    thread_binding, thread_members_in, thread_root_readable_in, validate_private_audience_in,
};
pub use rooms::{
    RoomClaimOutcome, RoomClaimReceipt, RoomHosting, RoomPage, RoomSpeakingRole, RoomStanding,
    RoomThread, RoomThreadList, RoomThreadPage, RoomThreadPolicy, RoomThreadWait, RoomThreads,
    RoomTrunk, RoomTrunkHeader, RoomTrunkItem, RoomTurn, RoomWaitKind,
};

pub(crate) use rooms::RoomThreadTask;
pub use rooms::{HostPin, HostPinKind, RoomHostHand, RoomHostPin};
pub use rooms::{
    OfferAnswer, OfferAnswerRequest, OfferCard, OfferDraft, OfferReopenRequest, OfferSettlement,
    OfferState, OfferVoteRequest, OffersPage, OffersRequest,
};
pub(crate) use rooms::{ROOM_OFFER_IDLE_SECS, record_offer_append_in_txn};
pub use rooms::{RoomUpkeepInput, RoomUpkeepThread, room_upkeep_input};

pub(crate) use rooms::erase_room_side_rows;
pub(crate) use rooms::room_project_in;
pub(crate) use rooms::room_thread_turns_in_txn;
pub(crate) use rooms::{
    RoomSideRow, SideMerge, TurnMerge, clear_replicated_side_cell_in_txn,
    merge_replicated_responses_in_txn, merge_replicated_side_row_in_txn,
    merge_replicated_turn_in_txn, replicated_side_carriers_in, replicated_side_rows_in,
    replicated_turn_in,
};
pub(crate) use rooms::{project_room_audience_in, room_join_audience_in};

pub(crate) use rooms::{
    Admitted, admit_participation_in_txn, join_subject_for_actor_in_txn,
    record_participation_in_txn, require_join_covering_in_txn,
};
pub use rooms::{JoinCause, ParticipantView, ParticipantsPage, ParticipantsRequest};

pub use crate::gate::RoomThreadFill;

mod join_consent;
mod join_door;
mod join_receipt;
mod workplace_join;
pub(crate) use join_consent::person_of_actor_in_txn;
pub use join_consent::{
    AdmissionBasis, AdmissionConsent, ConsentDenial, ConsentNeed, ConsentPart, ConsentSet,
    ConsentState, JoinDecision, JoinRefusal, JoinRequest, JoinSubject, MembershipConsent,
    RequiredParty, RoomJoinHold, RoomWork, SpendConsent, decide_join_in_txn,
    require_actor_join_in_txn, require_join_for_branch_in_txn, require_join_in_txn,
};
pub use join_door::{
    ConsentAnswer, JoinDecisionView, JoinOutcome, rooms_consent_in_txn, rooms_join_in_txn,
};
pub use join_receipt::{JoinParticipation, JoinReceipt, JoinReceiptRef, RecordedAnswer};
