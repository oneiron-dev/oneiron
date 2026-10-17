//! Onboarding request shapes and their structural validation.

use super::*;

/// The deployment-level facts a workspace roster hangs from.
///
/// This is the caller's statement of "which workplace, whose org, which seeded
/// row wears the house pen, and what the venture is called". It is stored
/// verbatim under `PRESET` the first time a
/// member is onboarded into `workspace_ref`, or earlier when an owner
/// establishes the workspace, and every later onboarding into the same
/// `workspace_ref` must agree with it.
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
    pub(super) fn validate(&self) -> Result<()> {
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
    /// Names the work companion's [`CompanionBirthIntent::profile_grant_ref`],
    /// and is `None` exactly when the member brings her own companion: a
    /// brought companion's profile grant already exists and is not reminted.
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

/// How a member's companion enters the workspace (ONEIRON-ARCH-0063
/// `work_companion`). A companion is a person everywhere and an agent only
/// where she holds the pen: either way she is one someone, never a mode of
/// her member.
///
/// Not `Eq` for the same reason as [`MemberOnboardingIntent`].
#[derive(Debug, Clone, PartialEq)]
pub enum CompanionChoice {
    /// The member brings the companion she already has. Her PERSON, its
    /// substrate, her actor and its anchor stand as they are, and the
    /// member's existing companion-profile grant must already name her:
    /// nothing is reminted and the personal vault is not annexed. Only the
    /// work facet she wears here is associated.
    Bring {
        /// The companion's existing `PERSON`.
        person: EntityId,
        /// The companion's existing `AGENT_DEF` actor, anchored to `person`.
        actor: EntityId,
        /// The existing work `FACET` she wears in this workspace.
        work_facet: EntityId,
        /// The member's own authenticated consent to bring her, revalidated
        /// in the transaction that binds her. No part of the intent digest:
        /// a retry under a fresh authentication is the same request.
        proof: AuthenticatedOwner,
    },
    /// A work companion born for this workspace.
    Work(CompanionBirthIntent),
}

impl CompanionChoice {
    /// The companion `PERSON`, brought or born.
    #[must_use]
    pub fn person_ref(&self) -> EntityId {
        match self {
            Self::Bring { person, .. } => *person,
            Self::Work(birth) => birth.person_ref,
        }
    }

    /// The companion's `AGENT_DEF` actor, brought or born.
    #[must_use]
    pub fn actor_ref(&self) -> EntityId {
        match self {
            Self::Bring { actor, .. } => *actor,
            Self::Work(birth) => birth.actor_ref,
        }
    }

    /// The work `FACET` the companion wears in this workspace.
    #[must_use]
    pub fn work_facet_ref(&self) -> EntityId {
        match self {
            Self::Bring { work_facet, .. } => *work_facet,
            Self::Work(birth) => birth.work_facet_ref,
        }
    }

    /// The birth, when this is a work companion.
    #[must_use]
    pub fn birth(&self) -> Option<&CompanionBirthIntent> {
        match self {
            Self::Bring { .. } => None,
            Self::Work(birth) => Some(birth),
        }
    }

    /// Whether the member brings her own companion.
    #[must_use]
    pub fn is_bring(&self) -> bool {
        matches!(self, Self::Bring { .. })
    }
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
/// `ONBOARDING` digest comparison anyway, which hashes
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
    /// The member's companion: brought, or born as a work companion. The
    /// workspace's `work_companion` policy decides which it admits, read in
    /// the transaction that binds her, never from this intent.
    pub companion: CompanionChoice,
    /// Optional delegated mailbox.
    pub delegated_mailbox: Option<DelegatedMailboxOnboarding>,
    /// Event time stamped into every record this onboarding writes.
    pub occurred_at: u64,
}

impl MemberOnboardingIntent {
    /// Structural validation that runs before authority and before the journal.
    pub(super) fn validate(&self) -> Result<()> {
        validate_name(
            &self.onboarding_id,
            "onboarding_id must be 1..=256 bytes and contain no NUL",
        )?;
        self.workspace.validate()?;
        self.validate_grant_bundle()?;
        if let Some(companion) = self.companion.birth() {
            validate_name(
                &companion.display_name,
                "companion display_name must be 1..=256 bytes and contain no NUL",
            )?;
            if companion.display_name.trim().is_empty() {
                return Err(invalid("companion display_name must not be blank"));
            }
        }
        if self.companion.person_ref() == self.person_ref {
            return Err(invalid("a member is not her own companion"));
        }
        if let Some(mailbox) = &self.delegated_mailbox {
            mailbox.validate()?;
            if mailbox.autonomy.actor_ref != self.actor_ref {
                return Err(invalid("mailbox autonomy must name the member actor"));
            }
        }
        self.validate_minted_ids()
    }

    pub(super) fn validate_grant_bundle(&self) -> Result<()> {
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
        let birth_ref = self.companion.birth().map(|c| c.profile_grant_ref);
        if bundle_ref != birth_ref {
            return Err(invalid(
                "companion_profile_grant_ref must match the work companion birth, or be absent for a brought companion",
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
        match &self.companion {
            CompanionChoice::Work(companion) => {
                minted.extend([
                    companion.person_ref,
                    companion.actor_ref,
                    companion.profile_grant_ref,
                ]);
                referenced.push(companion.work_facet_ref);
            }
            // A brought companion is referenced, never minted: her ids must
            // not alias anything this onboarding writes.
            CompanionChoice::Bring {
                person,
                actor,
                work_facet,
                ..
            } => referenced.extend([*person, *actor, *work_facet]),
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
