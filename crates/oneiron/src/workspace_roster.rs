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

/// Body schema version for every record this module writes.
pub const WORKSPACE_ROSTER_SCHEMA_VERSION: u64 = 1;

/// `vault_meta` prefix owned by the onboarding journal.
pub const WORKSPACE_ONBOARDING_KEY_PREFIX: &[u8] = b"workspace_roster:onboarding:v1:";

/// `vault_meta` prefix owned by the per-workspace preset row.
pub const WORKSPACE_ROSTER_PRESET_KEY_PREFIX: &[u8] = b"workspace_roster:preset:v1:";

/// `vault_meta` prefix owned by the per-member roster row.
///
/// Full key is `prefix ++ workspace_ref ++ 0x00 ++ member_person_hex`. The NUL
/// separator is unambiguous because [`WorkspaceRosterPreset::validate`] refuses
/// a `workspace_ref` containing one.
pub const WORKSPACE_ROSTER_MEMBER_KEY_PREFIX: &[u8] = b"workspace_roster:member:v1:";

/// Upper bound on every caller-supplied name/reference string in this module.
const MAX_NAME_BYTES: usize = 256;

/// Byte that separates `workspace_ref` from the member id in a roster key.
const ROSTER_KEY_SEPARATOR: u8 = 0x00;

/// The deployment-level facts a workspace roster hangs from.
///
/// This is the caller's statement of "which workplace, whose org, which seeded
/// row wears the house pen, and what the venture is called". It is stored
/// verbatim under [`WORKSPACE_ROSTER_PRESET_KEY_PREFIX`] the first time a
/// member is onboarded into `workspace_ref`, and every later onboarding into
/// the same `workspace_ref` must agree with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRosterPreset {
    /// Host-side workspace handle (e.g. a Slack workspace key). Opaque here.
    pub workspace_ref: String,
    /// Shared vault the member grant is scoped to. Never zero.
    pub workspace_vault_id: u64,
    /// The `ORG` the house mind stands behind.
    pub org_ref: EntityId,
    /// Runtime venture name; the house mind's display-name default.
    pub venture_name: String,
    /// Owner override for the house mind's display name.
    ///
    /// `None` means the deployment's `venture_name` stands. Not in the ONE-1832
    /// keystone sketch: the sketch assumed the name could live on the seeded
    /// row, but that row's `display_name` is its L1-ENTITY system role label,
    /// so an owner rename needed a home this module actually owns.
    pub house_display_name: Option<String>,
    /// Seeded `AGENT_DEF` row that wears the house pen.
    pub house_actor_ref: EntityId,
    /// Optional shared-presence `CHANNEL_IDENTITY` the deployment speaks through.
    pub house_identity_ref: Option<EntityId>,
}

impl WorkspaceRosterPreset {
    fn validate(&self) -> Result<()> {
        validate_name(
            &self.workspace_ref,
            "workspace_ref must be 1..=256 bytes and contain no NUL",
        )?;
        validate_name(
            &self.venture_name,
            "venture_name must be 1..=256 bytes and contain no NUL",
        )?;
        if let Some(house_display_name) = &self.house_display_name {
            validate_name(
                house_display_name,
                "house_display_name must be 1..=256 bytes and contain no NUL",
            )?;
        }
        if self.workspace_vault_id == 0 {
            return Err(invalid("workspace_vault_id must be nonzero"));
        }
        Ok(())
    }
}

/// The minimum membership a workspace member receives.
///
/// Role and preset are carried rather than hardcoded so the door can REJECT a
/// widened bundle instead of silently narrowing it: a caller that asks for
/// admin gets a typed error, not a quietly downgraded grant it never learns
/// about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberGrantBundle {
    /// Caller-supplied id for the `FEDERATION_GRANT` row.
    pub federation_grant_ref: EntityId,
    /// Must be [`FederationGrantRole::Member`].
    pub role: FederationGrantRole,
    /// Must be [`FederationGrantPreset::Member`].
    pub preset: FederationGrantPreset,
    /// Must name the required [`CompanionBirthIntent::profile_grant_ref`].
    /// `None` is rejected during intent validation.
    pub companion_profile_grant_ref: Option<EntityId>,
}

/// Everything needed to bring one principal's companion into being.
///
/// `display_name` is quiz-born host copy. This module stores it as data — into
/// the companion actor's runtime-editable `display_name` slot — and contains no
/// questionnaire, ritual, or default persona of its own.
#[derive(Debug, Clone, PartialEq)]
pub struct CompanionBirthIntent {
    /// Caller-supplied id for the companion `PERSON`.
    pub person_ref: EntityId,
    /// Caller-supplied id for the companion's `AGENT_DEF` actor.
    pub actor_ref: EntityId,
    /// Existing work `FACET` the companion is associated with.
    pub work_facet_ref: EntityId,
    /// Caller-supplied id for the companion-register record.
    pub companion_record_ref: EntityId,
    /// Caller-supplied id for the scoped companion-profile read grant.
    pub profile_grant_ref: EntityId,
    /// Caller-supplied composition for the companion's actor.
    ///
    /// Not in the ONE-1832 keystone sketch, which predates this module having
    /// to CALL [`Vault::define_agent`]. The alternative — synthesizing an
    /// `AgentDefinition` here — would have put an engine-authored agent id and
    /// description into Rust, which is exactly the compiled-persona outcome the
    /// blueprint rejects.
    pub actor_definition: AgentDefinition,
    /// Display name for this companion; written into `actor_definition`.
    pub display_name: String,
}

/// Optional delegated-mailbox step.
///
/// Carries a custody record NAME and read scopes. There is no field on this
/// struct, and no key in any body it produces, that can hold an OAuth token:
/// raw grant material is unrepresentable here by construction, not by
/// convention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedMailboxOnboarding {
    /// Caller-supplied id for the `CHANNEL_IDENTITY` row.
    pub identity_ref: EntityId,
    /// Channel key the mailbox lives on (e.g. `gmail`).
    pub channel: String,
    /// Mailbox address.
    pub address: String,
    /// Custody record name; never a token.
    pub custody_name: String,
    /// Read scopes the grant covers.
    ///
    /// [`DelegatedGrantScope`] has no write variant, so this cannot name one.
    pub scopes: Vec<DelegatedGrantScope>,
    /// Exact owner-requested bounds, pinned in the onboarding digest.
    /// Delegated onboarding admits read/draft authority, never a send grant.
    pub autonomy: ChannelIdentityAutonomyRequest,
}

impl DelegatedMailboxOnboarding {
    fn validate(&self) -> Result<()> {
        validate_name(
            &self.channel,
            "delegated mailbox channel must be 1..=256 bytes and contain no NUL",
        )?;
        validate_name(
            &self.address,
            "delegated mailbox address must be 1..=256 bytes and contain no NUL",
        )?;
        validate_name(
            &self.custody_name,
            "delegated mailbox custody_name must be 1..=256 bytes and contain no NUL",
        )?;
        validate_mailbox_request(self)?;
        DelegatedGrant::new(&self.custody_name, self.scopes.clone()).validate()
    }
}

/// One idempotent, resumable member-onboarding request.
///
/// Not `Eq`: [`AgentDefinition`] carries an `f32` confidence and is `PartialEq`
/// only. Equality of two intents is decided by
/// [`WORKSPACE_ONBOARDING_KEY_PREFIX`] digest comparison anyway, which hashes
/// the canonical encoding rather than the in-memory value.
#[derive(Debug, Clone, PartialEq)]
pub struct MemberOnboardingIntent {
    /// Caller-chosen idempotency key for this onboarding.
    pub onboarding_id: String,
    /// The workspace this member joins.
    pub workspace: WorkspaceRosterPreset,
    /// The member's existing `PERSON`.
    pub person_ref: EntityId,
    /// Caller-supplied id for the member's `AGENT_DEF` actor.
    pub actor_ref: EntityId,
    /// Caller-supplied composition for the member's actor.
    pub actor_definition: AgentDefinition,
    /// The member's existing work `FACET`.
    pub work_facet_ref: EntityId,
    /// The minimum membership bundle.
    pub grant_bundle: MemberGrantBundle,
    /// Required quiz-named companion birth; `None` is rejected before writes.
    pub companion_birth: Option<CompanionBirthIntent>,
    /// Optional delegated mailbox.
    pub delegated_mailbox: Option<DelegatedMailboxOnboarding>,
    /// Event time stamped into every record this onboarding writes.
    pub occurred_at: u64,
}

impl MemberOnboardingIntent {
    /// Structural validation that runs before authority and before the journal.
    fn validate(&self) -> Result<()> {
        validate_name(
            &self.onboarding_id,
            "onboarding_id must be 1..=256 bytes and contain no NUL",
        )?;
        self.workspace.validate()?;
        let companion = self.required_companion()?;
        self.validate_grant_bundle()?;
        validate_name(
            &companion.display_name,
            "companion display_name must be 1..=256 bytes and contain no NUL",
        )?;
        if companion.display_name.trim().is_empty() {
            return Err(invalid("companion display_name must not be blank"));
        }
        if let Some(mailbox) = &self.delegated_mailbox {
            mailbox.validate()?;
            if mailbox.autonomy.actor_ref != self.actor_ref {
                return Err(invalid("mailbox autonomy must name the member actor"));
            }
        }
        self.validate_minted_ids()
    }

    fn required_companion(&self) -> Result<&CompanionBirthIntent> {
        self.companion_birth
            .as_ref()
            .ok_or_else(|| invalid("every onboarded principal requires a quiz-named companion"))
    }

    fn validate_grant_bundle(&self) -> Result<()> {
        if self.grant_bundle.role != FederationGrantRole::Member
            || self.grant_bundle.preset != FederationGrantPreset::Member
        {
            return Err(invalid(
                "member grant bundle must be exactly role=Member and preset=Member",
            ));
        }
        // The two blueprint fields that name the companion-profile grant must
        // agree. Preferring one silently would let a caller believe it minted a
        // grant that the other field says does not exist.
        let bundle_ref = self.grant_bundle.companion_profile_grant_ref;
        let birth_ref = self.companion_birth.as_ref().map(|c| c.profile_grant_ref);
        if bundle_ref != birth_ref {
            return Err(invalid(
                "companion_profile_grant_ref must match the requested companion birth",
            ));
        }
        Ok(())
    }

    /// Every id this onboarding MINTS must be distinct from every other minted
    /// id and from every id it merely REFERENCES.
    ///
    /// Aliasing a minted id onto a referenced one would have this module write
    /// an `AGENT_DEF` body over the member's own `PERSON` row.
    fn validate_minted_ids(&self) -> Result<()> {
        let mut minted = vec![self.actor_ref, self.grant_bundle.federation_grant_ref];
        let mut referenced = vec![
            self.person_ref,
            self.work_facet_ref,
            self.workspace.org_ref,
            self.workspace.house_actor_ref,
        ];
        referenced.extend(self.workspace.house_identity_ref);
        if let Some(companion) = &self.companion_birth {
            minted.extend([
                companion.person_ref,
                companion.actor_ref,
                companion.companion_record_ref,
                companion.profile_grant_ref,
            ]);
            referenced.push(companion.work_facet_ref);
        }
        if let Some(mailbox) = &self.delegated_mailbox {
            minted.push(mailbox.identity_ref);
        }

        if minted
            .iter()
            .chain(&referenced)
            .any(|id| id.as_bytes() == &[0; 16])
        {
            return Err(invalid("entity ids must be nonzero"));
        }
        for (index, id) in minted.iter().enumerate() {
            if minted[..index].contains(id) || referenced.contains(id) {
                return Err(invalid(
                    "every minted entity id must be distinct from every other id in the intent",
                ));
            }
        }
        Ok(())
    }
}

/// Ordered onboarding progress marker.
///
/// The rank order is the pinned step order; a journal never moves backwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemberOnboardingStep {
    /// Inputs reserved before the first write door; no step is complete yet.
    Started,
    /// Entity kinds checked, house mind anchored, preset row settled.
    Validated,
    /// Member actor defined and anchored to the member `PERSON`.
    ActorLinked,
    /// `(Member, Member)` federation grant written.
    MemberGranted,
    /// Required companion person/actor/facet/record/grant written.
    CompanionBorn,
    /// Delegated mailbox bound and its exact autonomy verified, when requested.
    MailboxBound,
    /// Roster row written; the outcome is final.
    Complete,
}

impl MemberOnboardingStep {
    /// Pinned on-disk step spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Validated => "validated",
            Self::ActorLinked => "actor_linked",
            Self::MemberGranted => "member_granted",
            Self::CompanionBorn => "companion_born",
            Self::MailboxBound => "mailbox_bound",
            Self::Complete => "complete",
        }
    }

    /// Parses a pinned step spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "started" => Some(Self::Started),
            "validated" => Some(Self::Validated),
            "actor_linked" => Some(Self::ActorLinked),
            "member_granted" => Some(Self::MemberGranted),
            "companion_born" => Some(Self::CompanionBorn),
            "mailbox_bound" => Some(Self::MailboxBound),
            "complete" => Some(Self::Complete),
            _ => None,
        }
    }

    /// Position in the pinned order, counting from 1.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Started => 0,
            Self::Validated => 1,
            Self::ActorLinked => 2,
            Self::MemberGranted => 3,
            Self::CompanionBorn => 4,
            Self::MailboxBound => 5,
            Self::Complete => 6,
        }
    }
}

/// The pinned step order the runner walks.
const ONBOARDING_STEPS: [MemberOnboardingStep; 6] = [
    MemberOnboardingStep::Validated,
    MemberOnboardingStep::ActorLinked,
    MemberOnboardingStep::MemberGranted,
    MemberOnboardingStep::CompanionBorn,
    MemberOnboardingStep::MailboxBound,
    MemberOnboardingStep::Complete,
];

/// Stable refs a completed onboarding produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberOnboardingOutcome {
    /// Echo of the idempotency key.
    pub onboarding_id: String,
    /// The member `PERSON`.
    pub person_ref: EntityId,
    /// The member's `AGENT_DEF` actor.
    pub actor_ref: EntityId,
    /// The `(Member, Member)` federation grant.
    pub federation_grant_ref: EntityId,
    /// The companion `PERSON`, when one was born.
    pub companion_person_ref: Option<EntityId>,
    /// The companion's `AGENT_DEF` actor, when one was born.
    pub companion_actor_ref: Option<EntityId>,
    /// The delegated mailbox identity, when one was bound.
    pub delegated_identity_ref: Option<EntityId>,
    /// Time the journal first reached [`MemberOnboardingStep::Complete`].
    pub completed_at: u64,
}

/// What a roster row is in the workplace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WorkspaceRosterRole {
    /// The org given a pen.
    HouseMind,
    /// One principal's own companion.
    PrincipalCompanion,
}

impl WorkspaceRosterRole {
    /// Pinned wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HouseMind => "house_mind",
            Self::PrincipalCompanion => "principal_companion",
        }
    }
}

/// One named persona visible in a workspace.
///
/// Memory scope is carried by `actor_ref` / `subject_ref` / `facet_ref` and the
/// grants around them. `display_name` is presentation only and never selects
/// what a persona can read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRosterEntry {
    /// Workspace this persona appears in.
    pub workspace_ref: String,
    /// House mind or principal companion.
    pub role: WorkspaceRosterRole,
    /// The principal this companion belongs to; `None` for the house mind.
    pub principal_ref: Option<EntityId>,
    /// The `AGENT_DEF` that speaks.
    pub actor_ref: EntityId,
    /// The `PERSON`/`ORG` standing behind `actor_ref`.
    pub subject_ref: EntityId,
    /// Work facet this persona wears, when it has one.
    pub facet_ref: Option<EntityId>,
    /// Channel identity this persona speaks through, when it has one.
    pub identity_ref: Option<EntityId>,
    /// Runtime display name. Never an engine constant.
    pub display_name: String,
}

/// A member roster row as stored under [`WORKSPACE_ROSTER_MEMBER_KEY_PREFIX`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct RosterMemberRow {
    person_ref: EntityId,
    actor_ref: EntityId,
    companion_person_ref: Option<EntityId>,
    companion_actor_ref: Option<EntityId>,
    companion_facet_ref: Option<EntityId>,
    identity_ref: Option<EntityId>,
}

/// A journal record as stored under [`WORKSPACE_ONBOARDING_KEY_PREFIX`].
///
/// Deliberately does NOT store outcome refs: every ref is caller-supplied, so
/// the outcome is derivable from the intent whose digest this record pins. Two
/// copies of the same refs could disagree; one cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OnboardingJournal {
    intent_digest: [u8; 32],
    step: MemberOnboardingStep,
    completed_at: Option<u64>,
}

impl Vault {
    /// Onboards one member into a workspace, idempotently and resumably.
    ///
    /// The writer needs an admin federation grant over the target vault;
    /// `mailbox_owner` authenticates the member PERSON, independently of the writer.
    /// Requested/PendingFulfillment stay resumable. External fulfillment requires
    /// policy-gated Bind ([`Vault::apply_channel_identity_lifecycle_intent`]), then
    /// trusted manual/API completion ([`Vault::fulfill_channel_identity`]). Onboarding
    /// does neither. Exact replay verifies live grants without writes; different
    /// inputs under the same id fail with [`Error::InvalidClaimBody`].
    pub fn onboard_workspace_member(
        &self,
        intent: MemberOnboardingIntent,
        authenticated_writer: &WriteActor,
        mailbox_owner: Option<&AuthenticatedOwner>,
    ) -> Result<MemberOnboardingOutcome> {
        self.onboard_workspace_member_halting_after(
            intent,
            authenticated_writer,
            mailbox_owner,
            MemberOnboardingStep::Complete,
        )?
        .ok_or(Error::InvariantViolation(
            "workspace onboarding halted before Complete",
        ))
    }

    /// [`Vault::onboard_workspace_member`], stopping after `halt_after`.
    ///
    /// Crate-internal because "stop half way" is not a product verb — it is how
    /// the resume path is exercised without staging a real crash. `None` means
    /// the run halted before [`MemberOnboardingStep::Complete`], leaving a
    /// journal a later call resumes from.
    pub(crate) fn onboard_workspace_member_halting_after(
        &self,
        intent: MemberOnboardingIntent,
        authenticated_writer: &WriteActor,
        mailbox_owner: Option<&AuthenticatedOwner>,
        halt_after: MemberOnboardingStep,
    ) -> Result<Option<MemberOnboardingOutcome>> {
        intent.validate()?;
        if intent.delegated_mailbox.is_some() {
            require_mailbox_owner(&intent, mailbox_owner)?;
        }
        require_workspace_authority(
            self,
            intent.workspace.workspace_vault_id,
            authenticated_writer,
        )?;

        let digest = intent_digest(&intent)?;
        let key = onboarding_key(&intent.onboarding_id);
        let mut done = match read_journal(self, &key)? {
            Some(record) => {
                if record.intent_digest != digest {
                    return Err(invalid(
                        "onboarding_id was already used with different inputs",
                    ));
                }
                if let Some(completed_at) = record.completed_at {
                    let revision = verify_mailbox_revision(self, &intent, mailbox_owner)?;
                    with_workspace_authority(
                        self,
                        intent.workspace.workspace_vault_id,
                        authenticated_writer,
                        |_| require_mailbox_revision(self, revision),
                    )?;
                    return Ok(Some(outcome_of(&intent, completed_at)));
                }
                record.step.rank()
            }
            None => {
                validate_workspace_references(self, &intent)?;
                if read_preset(self, &intent.workspace.workspace_ref)?
                    .is_some_and(|stored| stored != intent.workspace)
                {
                    return Err(invalid(
                        "workspace_ref is already bound to a different workspace preset",
                    ));
                }
                write_journal(
                    self,
                    &key,
                    &intent,
                    &OnboardingJournal {
                        intent_digest: digest,
                        step: MemberOnboardingStep::Started,
                        completed_at: None,
                    },
                    authenticated_writer,
                    mailbox_owner,
                )?;
                0
            }
        };

        for step in ONBOARDING_STEPS {
            if step.rank() <= done {
                continue;
            }
            require_workspace_authority(
                self,
                intent.workspace.workspace_vault_id,
                authenticated_writer,
            )?;
            self.run_onboarding_step(step, &intent, authenticated_writer, mailbox_owner)?;
            let completed_at =
                (step == MemberOnboardingStep::Complete).then_some(intent.occurred_at);
            write_journal(
                self,
                &key,
                &intent,
                &OnboardingJournal {
                    intent_digest: digest,
                    step,
                    completed_at,
                },
                authenticated_writer,
                mailbox_owner,
            )?;
            done = step.rank();
            if step == halt_after {
                break;
            }
        }

        if done < MemberOnboardingStep::Complete.rank() {
            return Ok(None);
        }
        Ok(Some(outcome_of(&intent, intent.occurred_at)))
    }

    /// Runs one pinned step. Each arm is individually idempotent, so a resumed
    /// run that re-executes a partially applied step adds nothing.
    fn run_onboarding_step(
        &self,
        step: MemberOnboardingStep,
        intent: &MemberOnboardingIntent,
        writer: &WriteActor,
        mailbox_owner: Option<&AuthenticatedOwner>,
    ) -> Result<()> {
        match step {
            MemberOnboardingStep::Started => Ok(()),
            MemberOnboardingStep::Validated => establish_workspace(self, intent, writer),
            MemberOnboardingStep::ActorLinked => link_member_actor(self, intent, writer),
            MemberOnboardingStep::MemberGranted => grant_member_bundle(self, intent, writer),
            MemberOnboardingStep::CompanionBorn => {
                birth_companion(self, intent, intent.required_companion()?, writer)
            }
            MemberOnboardingStep::MailboxBound => match &intent.delegated_mailbox {
                Some(mailbox) => {
                    bind_delegated_mailbox(self, intent, mailbox, writer)?;
                    let owner = require_mailbox_owner(intent, mailbox_owner)?;
                    self.apply_channel_identity_autonomy(&mailbox.autonomy, owner)?;
                    self.verify_channel_identity_autonomy(&mailbox.autonomy, owner)?;
                    Ok(())
                }
                None => Ok(()),
            },
            MemberOnboardingStep::Complete => {
                record_roster_member(self, intent, writer, mailbox_owner)
            }
        }
    }

    /// Changes only the runtime house name. `None` restores the venture name.
    ///
    /// The seeded agent definition and completed onboarding outcomes are not
    /// rewritten. Authority and the preset compare-and-set share one write txn.
    pub fn set_workspace_house_display_name(
        &self,
        workspace_ref: &str,
        display_name: Option<String>,
        authenticated_writer: &WriteActor,
    ) -> Result<()> {
        validate_name(
            workspace_ref,
            "workspace_ref must be 1..=256 bytes and contain no NUL",
        )?;
        if let Some(name) = &display_name {
            validate_name(
                name,
                "house_display_name must be 1..=256 bytes and contain no NUL",
            )?;
        }
        let mut preset = read_preset(self, workspace_ref)?.ok_or(Error::EntityNotFound)?;
        let prior = encode_value(&preset_value(&preset))?;
        let vault_id = preset.workspace_vault_id;
        preset.house_display_name = display_name;
        let next = encode_value(&preset_value(&preset))?;
        let key = preset_key(workspace_ref);
        self.with_write_txn(|txn| {
            require_workspace_authority_in_txn(self, txn, vault_id, authenticated_writer)?;
            if self.store.vault_meta.get(txn, &key)?.as_deref() != Some(prior.as_slice()) {
                return Err(invalid(
                    "workspace preset changed during rename; retry from current state",
                ));
            }
            if prior != next {
                self.store.vault_meta.put(txn, &key, &next)?;
            }
            Ok(())
        })
    }

    /// The personas visible in `workspace_ref`: the house mind, then each
    /// principal's companion, as separate rows under one shared presence.
    ///
    /// An unknown `workspace_ref` is an empty roster, not an error — asking
    /// about a workspace nobody has onboarded into yet is a legal question.
    pub fn workspace_roster(
        &self,
        workspace_ref: &str,
        at: u64,
    ) -> Result<Vec<WorkspaceRosterEntry>> {
        let Some(preset) = read_preset(self, workspace_ref)? else {
            return Ok(Vec::new());
        };

        let mut entries = vec![house_mind_entry(self, &preset, at)?];
        let mut prefix = roster_member_prefix(workspace_ref);
        prefix.push(ROSTER_KEY_SEPARATOR);

        let rows = {
            let rtxn = self.store.env.read_txn()?;
            let mut rows = Vec::new();
            for entry in self.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
                let (_, raw) = entry?;
                rows.push(decode_roster_member_row(&raw)?);
            }
            rows
        };

        for row in rows {
            entries.push(companion_entry(self, &preset, &row, at)?);
        }
        Ok(entries)
    }
}

mod codec;
mod steps;

use codec::*;
use steps::*;

#[cfg(test)]
mod tests;
