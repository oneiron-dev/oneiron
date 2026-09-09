//! Workspace roster preset + member onboarding (ONEIRON-ARCH-0065).
//!
//! # This module assembles; it does not invent
//!
//! A workplace is a house mind plus one companion per principal,
//! sharing one presence. Every part of that already exists as a generic rail:
//! the house mind is a seeded `AGENT_DEF` row ([`crate::agent_def`]) anchored
//! to the workspace `ORG` through [`crate::subject_model`], a companion is a
//! model-substrate `PERSON` with its own actor anchor and companion-register
//! record, membership is a [`crate::federation::FederationGrant`], and a
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
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::companion::{
    CompanionExportClassification, CompanionProvenance, CompanionRecord, CompanionScope,
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
use crate::subject_model::actor_subject_anchor;
#[cfg(test)]
use crate::subject_model::{PersonSubstrate, person_substrate};
use crate::temporal::TimeRange;
use crate::vault::entity_id_from_type_index_key;
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
    MAX_NAME_BYTES, ONBOARDING_STEPS, OnboardingJournal, ROSTER_KEY_SEPARATOR, RosterMemberRow,
};
pub use self::records::{
    MemberOnboardingOutcome, MemberOnboardingStep, WORKSPACE_ONBOARDING_KEY_PREFIX,
    WORKSPACE_ROSTER_MEMBER_KEY_PREFIX, WORKSPACE_ROSTER_PRESET_KEY_PREFIX,
    WORKSPACE_ROSTER_SCHEMA_VERSION, WorkspaceRosterEntry, WorkspaceRosterRole,
};

#[cfg(test)]
mod tests;
