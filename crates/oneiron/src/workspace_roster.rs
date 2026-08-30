//! Workspace roster preset + member onboarding (ONEIRON-ARCH-0065).
//!
//! # This module assembles; it does not invent
//!
//! A workplace is a house mind plus one optional companion per principal,
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
//! Every entity id in [`MemberOnboardingIntent`] is caller-supplied and stable,
//! so the outcome is a pure function of the intent. The journal therefore only
//! has to remember HOW FAR a given `onboarding_id` got, plus a digest of the
//! inputs it got that far on. A crash between two public write doors resumes at
//! the next unfinished step; a replay of identical input returns the prior
//! outcome and writes nothing; the same id with different input fails typed
//! rather than silently rewriting someone's workspace.
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
    ChannelIdentity, ChannelIdentityBinding, DelegatedGrant, DelegatedGrantScope,
};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::companion::{
    CompanionExportClassification, CompanionProvenance, CompanionRecord, CompanionScope,
};
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
use crate::subject_model::{
    PersonSubstrate, actor_subject_anchor, anchor_actor_subject, person_substrate,
    set_person_substrate,
};
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
    /// Mirrors [`CompanionBirthIntent::profile_grant_ref`] when a companion is
    /// requested, and is `None` when one is not.
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
        Ok(())
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
    /// Optional companion birth.
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
        self.validate_grant_bundle()?;
        if let Some(companion) = &self.companion_birth {
            validate_name(
                &companion.display_name,
                "companion display_name must be 1..=256 bytes and contain no NUL",
            )?;
        }
        if let Some(mailbox) = &self.delegated_mailbox {
            mailbox.validate()?;
        }
        self.validate_minted_ids()
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
    /// Entity kinds checked, house mind anchored, preset row settled.
    Validated,
    /// Member actor defined and anchored to the member `PERSON`.
    ActorLinked,
    /// `(Member, Member)` federation grant written.
    MemberGranted,
    /// Companion person/actor/facet/record/grant written, when requested.
    CompanionBorn,
    /// Delegated mailbox identity written, when requested.
    MailboxBound,
    /// Roster row written; the outcome is final.
    Complete,
}

impl MemberOnboardingStep {
    /// Pinned on-disk step spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
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
    /// Authority comes from `authenticated_writer`: the writer must already
    /// hold an administrative [`FederationGrant`] over
    /// `intent.workspace.workspace_vault_id`. That check runs BEFORE the
    /// journal is touched, so an unprivileged caller leaves no trace and
    /// cannot burn an `onboarding_id`.
    ///
    /// Replaying an identical intent under the same `onboarding_id` returns the
    /// prior outcome and writes nothing. Replaying a DIFFERENT intent under
    /// that id is [`Error::InvalidClaimBody`], never an overwrite.
    pub fn onboard_workspace_member(
        &self,
        intent: MemberOnboardingIntent,
        authenticated_writer: &WriteActor,
    ) -> Result<MemberOnboardingOutcome> {
        self.onboard_workspace_member_halting_after(
            intent,
            authenticated_writer,
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
        halt_after: MemberOnboardingStep,
    ) -> Result<Option<MemberOnboardingOutcome>> {
        intent.validate()?;
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
                    return Ok(Some(outcome_of(&intent, completed_at)));
                }
                record.step.rank()
            }
            None => 0,
        };

        for step in ONBOARDING_STEPS {
            if step.rank() <= done {
                continue;
            }
            self.run_onboarding_step(step, &intent, authenticated_writer)?;
            let completed_at =
                (step == MemberOnboardingStep::Complete).then_some(intent.occurred_at);
            write_journal(
                self,
                &key,
                &intent.onboarding_id,
                &OnboardingJournal {
                    intent_digest: digest,
                    step,
                    completed_at,
                },
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
    ) -> Result<()> {
        match step {
            MemberOnboardingStep::Validated => establish_workspace(self, intent, writer),
            MemberOnboardingStep::ActorLinked => link_member_actor(self, intent, writer),
            MemberOnboardingStep::MemberGranted => grant_member_bundle(self, intent),
            MemberOnboardingStep::CompanionBorn => match &intent.companion_birth {
                Some(companion) => birth_companion(self, intent, companion, writer),
                None => Ok(()),
            },
            MemberOnboardingStep::MailboxBound => match &intent.delegated_mailbox {
                Some(mailbox) => bind_delegated_mailbox(self, intent, mailbox),
                None => Ok(()),
            },
            MemberOnboardingStep::Complete => record_roster_member(self, intent),
        }
    }

    /// The personas visible in `workspace_ref`: the house mind, then each
    /// principal's companion, as separate rows under one shared presence.
    ///
    /// An unknown `workspace_ref` is an empty roster, not an error — asking
    /// about a workspace nobody has onboarded into yet is a legal question.
    pub fn workspace_roster(&self, workspace_ref: &str) -> Result<Vec<WorkspaceRosterEntry>> {
        let Some(preset) = read_preset(self, workspace_ref)? else {
            return Ok(Vec::new());
        };

        let mut entries = vec![house_mind_entry(self, &preset)?];
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
            if let Some(entry) = companion_entry(self, &preset, &row)? {
                entries.push(entry);
            }
        }
        Ok(entries)
    }
}

// ---------------------------------------------------------------------------
// Authority
// ---------------------------------------------------------------------------

/// Requires the writer to hold an administrative federation grant over
/// `vault_id`.
///
/// Authority is a STORED grant, never an asserted actor class: a caller can
/// spell any [`crate::edge::EdgeActorClass`] it likes into a [`WriteActor`], so
/// treating `System` as privileged would make the check decorative.
/// [`FederationGrantRole::is_admin`] is the crate's own predicate for "may
/// administer membership", and `Delegate` is excluded by it — a one-hop
/// delegate cannot enroll members.
fn require_workspace_authority(vault: &Vault, vault_id: u64, writer: &WriteActor) -> Result<()> {
    let member_ref = writer.entity_ref();
    let scope = FederationGrantScope::vault(vault_id);
    let rtxn = vault.store.env.read_txn()?;
    for entry in vault
        .store
        .type_index
        .prefix_iter(&rtxn, &[ENTITY_TYPE_FEDERATION_GRANT])?
    {
        let (key, _) = entry?;
        let id = entity_id_from_type_index_key(&key)?;
        let Some(grant) = read_federation_grant_in_txn(vault, &rtxn, &id)? else {
            continue;
        };
        if grant.scope == scope && grant.member_ref == member_ref && grant.role.is_admin() {
            return Ok(());
        }
    }
    Err(invalid(
        "workspace onboarding requires an admin federation grant over the target vault",
    ))
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

/// Step 1: check every referenced entity kind, anchor the house mind to the
/// workspace `ORG`, and settle the preset row.
fn establish_workspace(
    vault: &Vault,
    intent: &MemberOnboardingIntent,
    writer: &WriteActor,
) -> Result<()> {
    let workspace = &intent.workspace;
    require_kind(
        vault,
        &intent.person_ref,
        ENTITY_TYPE_PERSON,
        "member person_ref must name a live PERSON",
    )?;
    require_kind(
        vault,
        &workspace.org_ref,
        ENTITY_TYPE_ORG,
        "workspace org_ref must name a live ORG",
    )?;
    require_kind(
        vault,
        &intent.work_facet_ref,
        ENTITY_TYPE_FACET,
        "member work_facet_ref must name a live FACET",
    )?;
    require_kind(
        vault,
        &workspace.house_actor_ref,
        ENTITY_TYPE_AGENT_DEF,
        "house_actor_ref must name a live AGENT_DEF",
    )?;
    if let Some(identity_ref) = workspace.house_identity_ref {
        require_kind(
            vault,
            &identity_ref,
            ENTITY_TYPE_CHANNEL_IDENTITY,
            "house_identity_ref must name a live CHANNEL_IDENTITY",
        )?;
    }
    if let Some(companion) = &intent.companion_birth {
        require_kind(
            vault,
            &companion.work_facet_ref,
            ENTITY_TYPE_FACET,
            "companion work_facet_ref must name a live FACET",
        )?;
    }

    // The house mind IS the org holding a pen: the seeded row's subject anchor
    // is what makes that true, and it is the same generic anchor a member actor
    // uses. Nothing about it is house-specific except which subject it names.
    ensure_subject_anchor(
        vault,
        workspace.house_actor_ref,
        workspace.org_ref,
        writer,
        intent.occurred_at,
    )?;
    ensure_preset_row(vault, workspace)
}

/// Step 2: define the member's actor and anchor it to the member `PERSON`.
fn link_member_actor(
    vault: &Vault,
    intent: &MemberOnboardingIntent,
    writer: &WriteActor,
) -> Result<()> {
    ensure_agent_definition(
        vault,
        &intent.actor_ref,
        &intent.actor_definition,
        intent.occurred_at,
    )?;
    ensure_subject_anchor(
        vault,
        intent.actor_ref,
        intent.person_ref,
        writer,
        intent.occurred_at,
    )
}

/// Step 3: write the one `(Member, Member)` grant for the shared org vault.
///
/// The role/preset pair comes from the already-validated bundle rather than
/// from constants here, so the widening fence lives in exactly one place
/// ([`MemberOnboardingIntent::validate_grant_bundle`]) and this writer cannot
/// disagree with it.
fn grant_member_bundle(vault: &Vault, intent: &MemberOnboardingIntent) -> Result<()> {
    let id = intent.grant_bundle.federation_grant_ref;
    let expected = FederationGrant::new(
        FederationGrantScope::vault(intent.workspace.workspace_vault_id),
        intent.person_ref,
        intent.grant_bundle.role,
        intent.grant_bundle.preset,
    );

    let rtxn = vault.store.env.read_txn()?;
    let existing = read_federation_grant_in_txn(vault, &rtxn, &id)?;
    drop(rtxn);
    if let Some(existing) = existing {
        if existing != expected {
            return Err(invalid(
                "federation_grant_ref is already bound to a different grant",
            ));
        }
        return Ok(());
    }

    // FEDERATION_GRANT is a Maintenance kind, so the public `put_entity` gate
    // refuses it by design and FED-SYNC owns `federation.rs`. The engine-side
    // `allow_maintenance` Put is the same door `access_grant.rs` and
    // `channel_identity.rs` use for their own maintenance kinds; the encoded
    // bytes are FED-SYNC's canonical encoder's, and `put_apply` re-validates
    // them on the way in. Moving this behind a future public
    // `Vault::create_federation_grant` is a pure refactor: the bytes do not
    // change.
    let data = encode_federation_grant_body(&expected)?;
    let occurred = TimeRange {
        start: intent.occurred_at,
        end: intent.occurred_at,
    };
    vault.with_write_txn(|wtxn| {
        apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_FEDERATION_GRANT,
                occurred,
                learned_at: intent.occurred_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    })
}

/// Step 4: a companion is a full someone, not a mode of the member.
///
/// PERSON, substrate, actor, anchor, work facet, register record, and exactly
/// the one companion-profile read grant the intent named — nothing wider.
fn birth_companion(
    vault: &Vault,
    intent: &MemberOnboardingIntent,
    companion: &CompanionBirthIntent,
    writer: &WriteActor,
) -> Result<()> {
    ensure_companion_person(vault, companion, intent.occurred_at)?;
    ensure_model_substrate(vault, companion.person_ref, writer, intent.occurred_at)?;

    // The quiz-born name lands in the actor's runtime-editable `display_name`
    // slot — the one place the engine already reads a persona name from, and
    // the one an owner can later edit through `update_agent_definition`.
    let mut definition = companion.actor_definition.clone();
    definition.display_name = Some(companion.display_name.clone());
    ensure_agent_definition(vault, &companion.actor_ref, &definition, intent.occurred_at)?;

    ensure_subject_anchor(
        vault,
        companion.actor_ref,
        companion.person_ref,
        writer,
        intent.occurred_at,
    )?;
    ensure_work_facet_edge(vault, companion.person_ref, companion.work_facet_ref)?;
    ensure_companion_record(vault, intent, companion, writer)?;
    ensure_companion_profile_grant(vault, intent, companion)
}

/// Step 5: bind a member-held mailbox through the landed delegated door.
///
/// The custody NAME travels; the token does not exist in this call stack.
fn bind_delegated_mailbox(
    vault: &Vault,
    intent: &MemberOnboardingIntent,
    mailbox: &DelegatedMailboxOnboarding,
) -> Result<()> {
    if vault.get_channel_identity(&mailbox.identity_ref)?.is_some() {
        return Ok(());
    }
    let identity = ChannelIdentity::requested_delegated(
        mailbox.channel.as_str(),
        mailbox.address.as_str(),
        ChannelIdentityBinding::actor(intent.actor_ref),
        DelegatedGrant::new(mailbox.custody_name.as_str(), mailbox.scopes.clone()),
        intent.occurred_at,
    );
    vault.create_channel_identity(&mailbox.identity_ref, &identity)
}

/// Step 6: record the member's roster row so the workspace read can find it.
fn record_roster_member(vault: &Vault, intent: &MemberOnboardingIntent) -> Result<()> {
    let row = RosterMemberRow {
        person_ref: intent.person_ref,
        actor_ref: intent.actor_ref,
        companion_person_ref: intent.companion_birth.as_ref().map(|c| c.person_ref),
        companion_actor_ref: intent.companion_birth.as_ref().map(|c| c.actor_ref),
        companion_facet_ref: intent.companion_birth.as_ref().map(|c| c.work_facet_ref),
        identity_ref: intent.delegated_mailbox.as_ref().map(|m| m.identity_ref),
    };
    let key = roster_member_key(&intent.workspace.workspace_ref, &intent.person_ref);
    let encoded = encode_value(&roster_member_value(&row))?;
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, &encoded)?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Idempotent primitives
// ---------------------------------------------------------------------------

/// Anchors `actor_ref` to `subject_ref` unless it is already anchored there.
///
/// A DIFFERENT live anchor is a typed refusal, not a silent re-anchor: the
/// anchor answers "who is this", and quietly changing that answer would
/// re-attribute every routed event this actor has ever spoken.
fn ensure_subject_anchor(
    vault: &Vault,
    actor_ref: EntityId,
    subject_ref: EntityId,
    writer: &WriteActor,
    at: u64,
) -> Result<()> {
    match actor_subject_anchor(vault, &actor_ref)? {
        Some(existing) if existing == subject_ref => Ok(()),
        Some(_) => Err(invalid("actor is already anchored to a different subject")),
        None => anchor_actor_subject(vault, actor_ref, subject_ref, *writer, at).map(|_| ()),
    }
}

/// Defines `id` from `definition` unless an `AGENT_DEF` already sits there.
///
/// Existing rows are left alone rather than rewritten: the caller-supplied id
/// may already carry owner edits (a renamed `display_name`, a disabled row),
/// and onboarding is not the door that reconciles those.
fn ensure_agent_definition(
    vault: &Vault,
    id: &EntityId,
    definition: &AgentDefinition,
    at: u64,
) -> Result<()> {
    if vault.get_agent_definition(id)?.is_some() {
        return Ok(());
    }
    vault.define_agent(id, definition, TimeRange { start: at, end: at }, at)
}

/// Mints the companion `PERSON` row if it is absent.
///
/// The body is this module's own tiny map carrying the caller's display name —
/// the `comm.rs` party-person precedent. `PERSON` has no engine-wide body
/// contract, so inventing a richer one here would be inventing product shape.
fn ensure_companion_person(vault: &Vault, companion: &CompanionBirthIntent, at: u64) -> Result<()> {
    match vault.get_entity_type(&companion.person_ref)? {
        Some(ENTITY_TYPE_PERSON) => return Ok(()),
        Some(other) => return Err(Error::InvalidEntityType(other)),
        None => {}
    }
    let body = encode_value(&Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(WORKSPACE_ROSTER_SCHEMA_VERSION),
        ),
        (
            Value::from("display_name"),
            Value::from(companion.display_name.as_str()),
        ),
    ]))?;
    vault.put_entity(
        &companion.person_ref,
        ENTITY_TYPE_PERSON,
        TimeRange { start: at, end: at },
        at,
        &body,
    )
}

/// Records `person_ref` as model-substrate unless it already is.
///
/// A person already recorded as `meat` is a typed refusal: substrate is a fact
/// about a someone, and overwriting it here would silently reclassify a human.
fn ensure_model_substrate(
    vault: &Vault,
    person_ref: EntityId,
    writer: &WriteActor,
    at: u64,
) -> Result<()> {
    match person_substrate(vault, &person_ref)? {
        Some(PersonSubstrate::Model) => Ok(()),
        Some(PersonSubstrate::Meat) => Err(invalid(
            "companion person_ref is already recorded as meat substrate",
        )),
        None => {
            set_person_substrate(vault, person_ref, PersonSubstrate::Model, *writer, at).map(|_| ())
        }
    }
}

/// Associates the companion person with its work facet.
fn ensure_work_facet_edge(vault: &Vault, person_ref: EntityId, facet_ref: EntityId) -> Result<()> {
    let already = vault
        .edges_out(&person_ref)?
        .into_iter()
        .any(|edge| edge.kind == EdgeKind::HasFacet && edge.target == facet_ref);
    if already {
        return Ok(());
    }
    vault.put_edge(&person_ref, EdgeKind::HasFacet, &facet_ref, 1.0)
}

/// Writes the companion-register persona record if it is absent.
fn ensure_companion_record(
    vault: &Vault,
    intent: &MemberOnboardingIntent,
    companion: &CompanionBirthIntent,
    writer: &WriteActor,
) -> Result<()> {
    if vault
        .get_companion_record(&companion.companion_record_ref)?
        .is_some()
    {
        return Ok(());
    }
    let provenance = CompanionProvenance::new(
        writer.entity_ref(),
        writer.actor_class(),
        ClaimSource::Observed,
        ClaimApprovalStatus::Auto,
        Value::Map(vec![
            (
                Value::from("workspace_ref"),
                Value::from(intent.workspace.workspace_ref.as_str()),
            ),
            (
                Value::from("onboarding_id"),
                Value::from(intent.onboarding_id.as_str()),
            ),
        ]),
    );
    let record = CompanionRecord::persona(
        CompanionScope::personal(intent.person_ref),
        companion.actor_ref,
        Value::Map(vec![
            (
                Value::from("schema_version"),
                Value::from(WORKSPACE_ROSTER_SCHEMA_VERSION),
            ),
            (
                Value::from("display_name"),
                Value::from(companion.display_name.as_str()),
            ),
            (
                Value::from("work_facet_ref"),
                Value::from(companion.work_facet_ref.to_hex()),
            ),
        ]),
        provenance,
        CompanionExportClassification::LocalOnly,
    );
    vault.create_companion_record(&companion.companion_record_ref, &record, intent.occurred_at)
}

/// Mints exactly the companion-profile READ grant the intent named.
///
/// One capability, one scope. Nothing here can widen: the constructor pins the
/// capability to the scope shape and [`AccessGrant::validate`] refuses any
/// other pairing.
fn ensure_companion_profile_grant(
    vault: &Vault,
    intent: &MemberOnboardingIntent,
    companion: &CompanionBirthIntent,
) -> Result<()> {
    let expected = AccessGrant::companion_profile_read(
        intent.person_ref,
        intent.person_ref,
        companion.actor_ref,
        intent.occurred_at,
    );
    if let Some(existing) = vault.get_access_grant(&companion.profile_grant_ref)? {
        if existing != expected {
            return Err(invalid(
                "profile_grant_ref is already bound to a different access grant",
            ));
        }
        return Ok(());
    }
    vault.create_access_grant(&companion.profile_grant_ref, &expected)
}

/// Writes the preset row, or verifies the stored one agrees with it.
fn ensure_preset_row(vault: &Vault, preset: &WorkspaceRosterPreset) -> Result<()> {
    if let Some(stored) = read_preset(vault, &preset.workspace_ref)? {
        if &stored != preset {
            return Err(invalid(
                "workspace_ref is already bound to a different workspace preset",
            ));
        }
        return Ok(());
    }
    let key = preset_key(&preset.workspace_ref);
    let encoded = encode_value(&preset_value(preset))?;
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, &encoded)?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Roster reads
// ---------------------------------------------------------------------------

/// Builds the house-mind row.
///
/// `display_name` is the owner override when present and the deployment's
/// `venture_name` otherwise; both are runtime intent data and neither is
/// compiled in. `subject_ref` resolves through the anchor so a merged ORG reads
/// as its survivor, and falls back to the stated `org_ref` when the anchor is
/// ambiguous (a split shell) — the roster answers with what the writer stated
/// rather than guessing a head.
fn house_mind_entry(vault: &Vault, preset: &WorkspaceRosterPreset) -> Result<WorkspaceRosterEntry> {
    let display_name = preset
        .house_display_name
        .clone()
        .unwrap_or_else(|| preset.venture_name.clone());
    let subject_ref =
        actor_subject_anchor(vault, &preset.house_actor_ref)?.unwrap_or(preset.org_ref);
    Ok(WorkspaceRosterEntry {
        workspace_ref: preset.workspace_ref.clone(),
        role: WorkspaceRosterRole::HouseMind,
        principal_ref: None,
        actor_ref: preset.house_actor_ref,
        subject_ref,
        facet_ref: None,
        identity_ref: preset.house_identity_ref,
        display_name,
    })
}

/// Builds one principal-companion row, or `None` for a member who has no
/// companion. Membership without a companion is a legal roster state; it simply
/// contributes no persona.
fn companion_entry(
    vault: &Vault,
    preset: &WorkspaceRosterPreset,
    row: &RosterMemberRow,
) -> Result<Option<WorkspaceRosterEntry>> {
    let (Some(actor_ref), Some(person_ref)) = (row.companion_actor_ref, row.companion_person_ref)
    else {
        return Ok(None);
    };
    let definition = vault.get_agent_definition(&actor_ref)?;
    let display_name = definition
        .map(|definition| {
            definition
                .display_name
                .unwrap_or_else(|| definition.agent_id.clone())
        })
        .unwrap_or_default();
    let subject_ref = actor_subject_anchor(vault, &actor_ref)?.unwrap_or(person_ref);
    Ok(Some(WorkspaceRosterEntry {
        workspace_ref: preset.workspace_ref.clone(),
        role: WorkspaceRosterRole::PrincipalCompanion,
        principal_ref: Some(row.person_ref),
        actor_ref,
        subject_ref,
        facet_ref: row.companion_facet_ref,
        identity_ref: row.identity_ref,
        display_name,
    }))
}

// ---------------------------------------------------------------------------
// Keys, journal, codecs
// ---------------------------------------------------------------------------

fn onboarding_key(onboarding_id: &str) -> Vec<u8> {
    let mut key = WORKSPACE_ONBOARDING_KEY_PREFIX.to_vec();
    key.extend_from_slice(onboarding_id.as_bytes());
    key
}

fn preset_key(workspace_ref: &str) -> Vec<u8> {
    let mut key = WORKSPACE_ROSTER_PRESET_KEY_PREFIX.to_vec();
    key.extend_from_slice(workspace_ref.as_bytes());
    key
}

fn roster_member_prefix(workspace_ref: &str) -> Vec<u8> {
    let mut key = WORKSPACE_ROSTER_MEMBER_KEY_PREFIX.to_vec();
    key.extend_from_slice(workspace_ref.as_bytes());
    key
}

fn roster_member_key(workspace_ref: &str, person_ref: &EntityId) -> Vec<u8> {
    let mut key = roster_member_prefix(workspace_ref);
    key.push(ROSTER_KEY_SEPARATOR);
    key.extend_from_slice(person_ref.to_hex().as_bytes());
    key
}

fn read_journal(vault: &Vault, key: &[u8]) -> Result<Option<OnboardingJournal>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, key)? else {
        return Ok(None);
    };
    decode_journal(&raw).map(Some)
}

fn write_journal(
    vault: &Vault,
    key: &[u8],
    onboarding_id: &str,
    record: &OnboardingJournal,
) -> Result<()> {
    let encoded = encode_value(&Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(WORKSPACE_ROSTER_SCHEMA_VERSION),
        ),
        (Value::from("onboarding_id"), Value::from(onboarding_id)),
        (
            Value::from("intent_digest"),
            Value::Binary(record.intent_digest.to_vec()),
        ),
        (Value::from("step"), Value::from(record.step.as_str())),
        (
            Value::from("completed_at"),
            record.completed_at.map_or(Value::Nil, Value::from),
        ),
    ]))?;
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, key, &encoded)?;
        Ok(())
    })
}

fn decode_journal(bytes: &[u8]) -> Result<OnboardingJournal> {
    let entries = decode_map(bytes)?;
    if required(&entries, "schema_version")?.as_u64() != Some(WORKSPACE_ROSTER_SCHEMA_VERSION) {
        return Err(invalid("onboarding journal schema_version is unsupported"));
    }
    let digest_bytes = match required(&entries, "intent_digest")? {
        Value::Binary(bytes) => bytes.clone(),
        _ => return Err(invalid("onboarding journal intent_digest must be binary")),
    };
    let intent_digest: [u8; 32] = digest_bytes
        .try_into()
        .map_err(|_| invalid("onboarding journal intent_digest must be 32 bytes"))?;
    let step = required(&entries, "step")?
        .as_str()
        .and_then(MemberOnboardingStep::parse)
        .ok_or_else(|| invalid("onboarding journal step is unrecognized"))?;
    let completed_at = match required(&entries, "completed_at")? {
        Value::Nil => None,
        value => Some(
            value
                .as_u64()
                .ok_or_else(|| invalid("onboarding journal completed_at must be a u64"))?,
        ),
    };
    Ok(OnboardingJournal {
        intent_digest,
        step,
        completed_at,
    })
}

fn preset_value(preset: &WorkspaceRosterPreset) -> Value {
    Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(WORKSPACE_ROSTER_SCHEMA_VERSION),
        ),
        (
            Value::from("workspace_ref"),
            Value::from(preset.workspace_ref.as_str()),
        ),
        (
            Value::from("workspace_vault_id"),
            Value::from(preset.workspace_vault_id),
        ),
        (Value::from("org_ref"), Value::from(preset.org_ref.to_hex())),
        (
            Value::from("venture_name"),
            Value::from(preset.venture_name.as_str()),
        ),
        (
            Value::from("house_display_name"),
            preset
                .house_display_name
                .as_deref()
                .map_or(Value::Nil, Value::from),
        ),
        (
            Value::from("house_actor_ref"),
            Value::from(preset.house_actor_ref.to_hex()),
        ),
        (
            Value::from("house_identity_ref"),
            optional_ref(preset.house_identity_ref),
        ),
    ])
}

fn read_preset(vault: &Vault, workspace_ref: &str) -> Result<Option<WorkspaceRosterPreset>> {
    let key = preset_key(workspace_ref);
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, &key)? else {
        return Ok(None);
    };
    let entries = decode_map(&raw)?;
    if required(&entries, "schema_version")?.as_u64() != Some(WORKSPACE_ROSTER_SCHEMA_VERSION) {
        return Err(invalid("workspace preset schema_version is unsupported"));
    }
    Ok(Some(WorkspaceRosterPreset {
        workspace_ref: required_str(&entries, "workspace_ref")?,
        workspace_vault_id: required(&entries, "workspace_vault_id")?
            .as_u64()
            .ok_or_else(|| invalid("workspace preset workspace_vault_id must be a u64"))?,
        org_ref: required_ref(&entries, "org_ref")?,
        venture_name: required_str(&entries, "venture_name")?,
        house_display_name: optional_string(&entries, "house_display_name")?,
        house_actor_ref: required_ref(&entries, "house_actor_ref")?,
        house_identity_ref: optional_entity(&entries, "house_identity_ref")?,
    }))
}

fn roster_member_value(row: &RosterMemberRow) -> Value {
    Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(WORKSPACE_ROSTER_SCHEMA_VERSION),
        ),
        (
            Value::from("person_ref"),
            Value::from(row.person_ref.to_hex()),
        ),
        (
            Value::from("actor_ref"),
            Value::from(row.actor_ref.to_hex()),
        ),
        (
            Value::from("companion_person_ref"),
            optional_ref(row.companion_person_ref),
        ),
        (
            Value::from("companion_actor_ref"),
            optional_ref(row.companion_actor_ref),
        ),
        (
            Value::from("companion_facet_ref"),
            optional_ref(row.companion_facet_ref),
        ),
        (Value::from("identity_ref"), optional_ref(row.identity_ref)),
    ])
}

fn decode_roster_member_row(bytes: &[u8]) -> Result<RosterMemberRow> {
    let entries = decode_map(bytes)?;
    if required(&entries, "schema_version")?.as_u64() != Some(WORKSPACE_ROSTER_SCHEMA_VERSION) {
        return Err(invalid("roster member schema_version is unsupported"));
    }
    Ok(RosterMemberRow {
        person_ref: required_ref(&entries, "person_ref")?,
        actor_ref: required_ref(&entries, "actor_ref")?,
        companion_person_ref: optional_entity(&entries, "companion_person_ref")?,
        companion_actor_ref: optional_entity(&entries, "companion_actor_ref")?,
        companion_facet_ref: optional_entity(&entries, "companion_facet_ref")?,
        identity_ref: optional_entity(&entries, "identity_ref")?,
    })
}

// ---------------------------------------------------------------------------
// Intent digest
// ---------------------------------------------------------------------------

/// Fingerprints the intent so a replay can prove it is the SAME request.
///
/// Hashing the canonical encoding rather than comparing structs keeps the
/// journal small and total: `AgentDefinition` is only `PartialEq`, so a stored
/// value comparison would have had to hand-roll float equality.
fn intent_digest(intent: &MemberOnboardingIntent) -> Result<[u8; 32]> {
    let encoded = encode_value(&intent_canonical_value(intent)?)?;
    Ok(*blake3::hash(&encoded).as_bytes())
}

fn intent_canonical_value(intent: &MemberOnboardingIntent) -> Result<Value> {
    let companion = match &intent.companion_birth {
        Some(companion) => companion_canonical_value(companion)?,
        None => Value::Nil,
    };
    Ok(Value::Map(vec![
        (
            Value::from("onboarding_id"),
            Value::from(intent.onboarding_id.as_str()),
        ),
        (Value::from("workspace"), preset_value(&intent.workspace)),
        (
            Value::from("person_ref"),
            Value::from(intent.person_ref.to_hex()),
        ),
        (
            Value::from("actor_ref"),
            Value::from(intent.actor_ref.to_hex()),
        ),
        (
            Value::from("actor_definition"),
            Value::Binary(encode_agent_definition(&intent.actor_definition)?),
        ),
        (
            Value::from("work_facet_ref"),
            Value::from(intent.work_facet_ref.to_hex()),
        ),
        (
            Value::from("grant_bundle"),
            grant_bundle_canonical_value(&intent.grant_bundle),
        ),
        (Value::from("companion_birth"), companion),
        (
            Value::from("delegated_mailbox"),
            intent
                .delegated_mailbox
                .as_ref()
                .map_or(Value::Nil, mailbox_canonical_value),
        ),
        (Value::from("occurred_at"), Value::from(intent.occurred_at)),
    ]))
}

fn grant_bundle_canonical_value(bundle: &MemberGrantBundle) -> Value {
    Value::Map(vec![
        (
            Value::from("federation_grant_ref"),
            Value::from(bundle.federation_grant_ref.to_hex()),
        ),
        (Value::from("role"), Value::from(bundle.role.as_str())),
        (Value::from("preset"), Value::from(bundle.preset.as_str())),
        (
            Value::from("companion_profile_grant_ref"),
            optional_ref(bundle.companion_profile_grant_ref),
        ),
    ])
}

fn companion_canonical_value(companion: &CompanionBirthIntent) -> Result<Value> {
    Ok(Value::Map(vec![
        (
            Value::from("person_ref"),
            Value::from(companion.person_ref.to_hex()),
        ),
        (
            Value::from("actor_ref"),
            Value::from(companion.actor_ref.to_hex()),
        ),
        (
            Value::from("work_facet_ref"),
            Value::from(companion.work_facet_ref.to_hex()),
        ),
        (
            Value::from("companion_record_ref"),
            Value::from(companion.companion_record_ref.to_hex()),
        ),
        (
            Value::from("profile_grant_ref"),
            Value::from(companion.profile_grant_ref.to_hex()),
        ),
        (
            Value::from("actor_definition"),
            Value::Binary(encode_agent_definition(&companion.actor_definition)?),
        ),
        (
            Value::from("display_name"),
            Value::from(companion.display_name.as_str()),
        ),
    ]))
}

fn mailbox_canonical_value(mailbox: &DelegatedMailboxOnboarding) -> Value {
    Value::Map(vec![
        (
            Value::from("identity_ref"),
            Value::from(mailbox.identity_ref.to_hex()),
        ),
        (
            Value::from("channel"),
            Value::from(mailbox.channel.as_str()),
        ),
        (
            Value::from("address"),
            Value::from(mailbox.address.as_str()),
        ),
        (
            Value::from("custody_name"),
            Value::from(mailbox.custody_name.as_str()),
        ),
        (
            Value::from("scopes"),
            Value::Array(
                mailbox
                    .scopes
                    .iter()
                    .map(|scope| Value::from(scope.as_str()))
                    .collect(),
            ),
        ),
    ])
}

fn outcome_of(intent: &MemberOnboardingIntent, completed_at: u64) -> MemberOnboardingOutcome {
    MemberOnboardingOutcome {
        onboarding_id: intent.onboarding_id.clone(),
        person_ref: intent.person_ref,
        actor_ref: intent.actor_ref,
        federation_grant_ref: intent.grant_bundle.federation_grant_ref,
        companion_person_ref: intent.companion_birth.as_ref().map(|c| c.person_ref),
        companion_actor_ref: intent.companion_birth.as_ref().map(|c| c.actor_ref),
        delegated_identity_ref: intent.delegated_mailbox.as_ref().map(|m| m.identity_ref),
        completed_at,
    }
}

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

fn validate_name(value: &str, reason: &'static str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_NAME_BYTES
        || value.as_bytes().contains(&ROSTER_KEY_SEPARATOR)
    {
        return Err(invalid(reason));
    }
    Ok(())
}

fn require_kind(vault: &Vault, id: &EntityId, expected: u8, reason: &'static str) -> Result<()> {
    if vault.get_entity_type(id)? != Some(expected) {
        return Err(invalid(reason));
    }
    Ok(())
}

fn read_federation_grant_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<FederationGrant>> {
    let Some(raw) = vault.store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_FEDERATION_GRANT {
        return Err(Error::InvalidEntityType(header.entity_type));
    }
    decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
}

fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, value)
        .map_err(|_| invalid("workspace roster MessagePack encode failed"))?;
    Ok(buf)
}

fn decode_map(bytes: &[u8]) -> Result<Vec<(Value, Value)>> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| invalid("workspace roster MessagePack decode failed"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid("workspace roster body has trailing bytes"));
    }
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(invalid("workspace roster body must be a map")),
    }
}

fn required<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(|| invalid("workspace roster body is missing a required key"))
}

fn required_str(entries: &[(Value, Value)], key: &str) -> Result<String> {
    required(entries, key)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("workspace roster body field must be a string"))
}

fn required_ref(entries: &[(Value, Value)], key: &str) -> Result<EntityId> {
    let hex = required(entries, key)?
        .as_str()
        .ok_or_else(|| invalid("workspace roster body ref must be a hex string"))?;
    EntityId::from_hex(hex).map_err(|_| invalid("workspace roster body ref is malformed"))
}

fn optional_entity(entries: &[(Value, Value)], key: &str) -> Result<Option<EntityId>> {
    match required(entries, key)? {
        Value::Nil => Ok(None),
        value => {
            let hex = value
                .as_str()
                .ok_or_else(|| invalid("workspace roster body ref must be a hex string"))?;
            EntityId::from_hex(hex)
                .map(Some)
                .map_err(|_| invalid("workspace roster body ref is malformed"))
        }
    }
}

fn optional_string(entries: &[(Value, Value)], key: &str) -> Result<Option<String>> {
    match required(entries, key)? {
        Value::Nil => Ok(None),
        value => value
            .as_str()
            .map(|text| Some(text.to_owned()))
            .ok_or_else(|| invalid("workspace roster body field must be a string")),
    }
}

fn optional_ref(id: Option<EntityId>) -> Value {
    id.map_or(Value::Nil, |id| Value::from(id.to_hex()))
}

#[cfg(test)]
mod tests;
