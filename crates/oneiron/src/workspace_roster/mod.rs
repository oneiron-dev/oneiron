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
mod steps;

use codec::*;
use steps::*;

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

#[cfg(test)]
mod tests;

mod project;
#[cfg(all(test, feature = "sync"))]
pub(crate) use project::create_project_signed_for_test;
#[cfg(test)]
pub(crate) use project::set_project_depth_signed_for_test;
pub use project::{
    GoalAxis, GoalExplorationBudget, GoalInterviewTurns, GoalPreference, GoalRecord,
    LEADER_CHAT_RULE_PREDICATE, LeaderChat, MessageHangs, PROJECT_TYPE_BYTE, ProjectAnchor,
    ProjectAuthority, ProjectBudgetShare, ProjectGoalRecord, ProjectMintReceipt, ProjectQuarantine,
    ProjectRecord, ProjectRole, ProjectRoom, ProjectRoomChange, ProjectVerdict, ProjectWidenAsk,
    ProjectWidenAxis, ProjectWriteProof, RoomOriginCard,
};
pub(crate) use project::{
    GoalLimits, HUB_BELONGS_TO_LAMBDA, LEADER_CHAT_FIELD, PROJECT_SHORT_ID_PREFIX, ProjectReader,
    admit_leader_chat_turn, admit_leader_chat_witness, deindex_project_room, guard_goal_claim_put,
    guard_goal_delete, guard_goal_pointer_put, is_project_entity, is_project_type,
    leader_chat_record_permitted, normalize_project_body, note_project_proof,
    permit_leader_chat_record, precheck_goal_delete, project_mint_gate_refs_in_txn,
    project_room_dependency, reconcile_project_rooms, retire_goal_for_delete, root_project_in,
    seed_root_project, settle_leader_chat_record, validate_local_leader_chat_turns,
    validate_project_body, validate_project_edge_delete, validate_project_edge_put,
    validate_project_graph, validate_project_transition, validate_room_body,
    verify_existing_leader_chat_turn,
};

mod rooms;
pub(crate) use rooms::admit_witness as admit_room_witness;
pub use rooms::{
    RoomClaimOutcome, RoomClaimReceipt, RoomPage, RoomThread, RoomThreadList, RoomThreadPage,
    RoomThreadPolicy, RoomThreadWait, RoomThreads, RoomTrunk, RoomTrunkHeader, RoomTrunkItem,
    RoomTurn, RoomWaitKind,
};

pub(crate) use rooms::RoomThreadTask;

pub(crate) use rooms::project_room_audience_in;

pub use crate::gate::RoomThreadFill;
