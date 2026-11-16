//! ARCH-0063 [INB-01] worked example (Engine RULING INB-01-WORKED-EXAMPLE = A,
//! 15 Nov): the selection law's owner override, driven through the doors a
//! host uses. Canon's case is one campaign sent from the owner's own mailbox:
//! at micro-campaign volume a warm human account beats a cold side domain, and
//! the owner's wording pass is the approval step.
//!
//! - A fresh vault reads the six compiled defaults at revision 0; campaign
//!   outreach wears the side-domain address.
//! - The owner connects their mailbox as a `delegated_grant` identity and
//!   writes one brief-scoped campaign row that pins it. In that brief the
//!   campaign sends from the owner's mailbox; every other campaign keeps the
//!   side-domain default.
//! - No vault ships that row: a row that pins an identity must pin a live
//!   identity of its own vault, and the update door refuses one it does not
//!   hold.
//!
//! Public paths only:
//! `cargo test --locked -p oneiron --all-features --test channel_selection_worked_example`.

use oneiron::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityShape,
    ChannelIdentityState, ChannelIdentityStep, DelegatedGrant, DelegatedGrantScope,
    DelegatedProvisionRequest, SelfHeldShape, delegated_custody_scopes_for_grant,
};
use oneiron::channel_identity_selection::{
    ChannelIdentityFace, RelationshipContext, SelectionRuleScope, SelectionRuleWriterKind,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::channel_doors::{
    ChannelSelectionCandidateInput, ChannelSelectionPatchInput, ChannelSelectionRequest,
    ChannelSelectionRuleInput, ChannelSelectionUpdateRequest, ChannelSelectionView,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::secret_custody::{SECRET_CUSTODY_SCHEMA_VERSION, decode_secret_custody_body};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Maps any error into the test's error with the step that failed.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

const AT: u64 = 1_800_000_000;
/// The owner's own mailbox, connected under an OAuth grant.
const OWNER_MAILBOX: &str = "owen@example.com";
const OWNER_MAILBOX_CUSTODY: &str = "oauth/gmail/owen";
/// The agent's sticky sender on a side domain, the campaign default.
const SIDE_DOMAIN_ADDRESS: &str = "outreach@example-outreach.net";
/// The one campaign the owner sends from their own mailbox.
const CAMPAIGN_BRIEF: &str = "brief:spring-launch";
const OWNER_CAMPAIGN_RULE: &str = "owner.campaign.spring-launch";

/// A vault, its embedded owner, the campaign agent, and the two identities
/// the agent may wear on a campaign. The vault closes before its directory.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    side_domain: EntityId,
    owner_mailbox: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), VaultConfig::default()).map_err(at("open"))?;
        let owner = vault
            .ensure_embedded_owner_actor()
            .map_err(at("embedded owner"))?;
        let agent = EntityId::now();
        vault
            .put_entity(
                &agent,
                ENTITY_TYPE_PERSON,
                TimeRange { start: AT, end: AT },
                AT,
                b"campaign agent",
            )
            .map_err(at("seat the campaign agent"))?;
        let side_domain = side_domain_identity(&vault, agent)?;
        let owner_mailbox = owner_mailbox_identity(&vault, agent)?;
        Ok(Self {
            vault,
            owner,
            side_domain,
            owner_mailbox,
            _dir: dir,
        })
    }

    /// The owner proof the host's owner door builds from the owner's
    /// credential.
    fn owner_proof(&self) -> TestResult<AuthenticatedOwner> {
        Ok(self
            .vault
            .authenticate_owner(
                self.owner,
                &self.owner.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .map_err(at("owner proof"))?)
    }

    /// `vault.channel_identities.selection.update` as the owner.
    fn owner_update(&self, expected_revision: u64, rule: ChannelSelectionRuleInput) -> TestResult {
        let proof = self.owner_proof()?;
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .channel_selection_update_as(
                Some(&proof),
                ChannelSelectionUpdateRequest {
                    expected_revision,
                    patch: ChannelSelectionPatchInput::Upsert { rule },
                },
            )
            .map_err(at("the owner's rule write"))?;
        Ok(())
    }

    /// `vault.channel_identities.selection.select` for a campaign send, as
    /// the owner's host asks it: both campaign identities classified by face.
    fn select_campaign_sender(
        &self,
        scopes: Vec<SelectionRuleScope>,
    ) -> TestResult<ChannelSelectionView> {
        Ok(self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .channel_identity_select(ChannelSelectionRequest {
                relationship: RelationshipContext::CampaignOutreach,
                applicable_scopes: scopes,
                candidates: vec![
                    ChannelSelectionCandidateInput {
                        identity_ref: self.side_domain,
                        face: ChannelIdentityFace::SideDomainAddress,
                    },
                    ChannelSelectionCandidateInput {
                        identity_ref: self.owner_mailbox,
                        face: ChannelIdentityFace::DelegatedOwnerAccount,
                    },
                ],
                thread_ref: None,
            })
            .map_err(at("campaign sender selection"))?)
    }
}

/// The agent's own side-domain address, live.
fn side_domain_identity(vault: &Vault, agent: EntityId) -> TestResult<EntityId> {
    let id = EntityId::now();
    let requested = ChannelIdentity::requested(
        "email",
        SIDE_DOMAIN_ADDRESS,
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(agent),
        AT,
    );
    vault
        .create_channel_identity(&id, &requested)
        .map_err(at("birth the side-domain address"))?;
    step_live(vault, id)?;
    Ok(id)
}

/// The owner's own mailbox as a `delegated_grant` identity, live: the OAuth
/// grant is in custody for this mailbox, read and send, and the agent holds
/// the pen.
fn owner_mailbox_identity(vault: &Vault, agent: EntityId) -> TestResult<EntityId> {
    let grant = DelegatedGrant::new(
        OWNER_MAILBOX_CUSTODY,
        vec![DelegatedGrantScope::MailRead, DelegatedGrantScope::MailSend],
    );
    register_mailbox_custody(vault, &grant)?;
    let id = EntityId::now();
    vault
        .provision_delegated_identity(
            &id,
            DelegatedProvisionRequest {
                channel: "email".to_owned(),
                address_or_handle: OWNER_MAILBOX.to_owned(),
                binding: ChannelIdentityBinding::agent(agent),
                grant,
            },
            AT,
        )
        .map_err(at("connect the owner's mailbox"))?;
    step_live(vault, id)?;
    Ok(id)
}

/// Requested -> pending fulfillment -> active, through the vault's lifecycle
/// door.
fn step_live(vault: &Vault, id: EntityId) -> TestResult {
    vault
        .step_channel_identity(
            &id,
            ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
            AT + 10,
        )
        .map_err(at("bind the identity"))?;
    let live = vault
        .step_channel_identity(&id, ChannelIdentityStep::Fulfill, AT + 20)
        .map_err(at("fulfill the identity"))?;
    assert_eq!(live.state(), ChannelIdentityState::Active);
    Ok(())
}

/// The OAuth token for the owner's mailbox, in custody: one `connector:gmail`
/// binding that grants read, names this mailbox, and carries the provider's
/// granted send scope.
fn register_mailbox_custody(vault: &Vault, grant: &DelegatedGrant) -> TestResult {
    use rmpv::Value;
    let band = |min: u64, max: u64| {
        Value::Map(vec![
            (Value::from("min"), Value::from(min)),
            (Value::from("max"), Value::from(max)),
        ])
    };
    let floor = Value::Map(vec![
        (Value::from("portable"), band(0, 2)),
        (Value::from("device_bound"), band(0, 2)),
        (Value::from("cross_vault"), band(0, 0)),
        (Value::from("rotation_max_age_secs"), Value::Nil),
        (Value::from("env_bindings"), Value::Map(vec![])),
    ]);
    let scopes = delegated_custody_scopes_for_grant("email", OWNER_MAILBOX, &grant.scopes)
        .into_iter()
        .map(Value::from)
        .collect();
    let binding = Value::Map(vec![
        (Value::from("effector"), Value::from("connector:gmail")),
        (Value::from("tier_ceiling"), Value::from(0_u64)),
        (Value::from("scopes"), Value::Array(scopes)),
    ]);
    let body = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(u64::from(SECRET_CUSTODY_SCHEMA_VERSION)),
        ),
        (Value::from("name"), Value::from(OWNER_MAILBOX_CUSTODY)),
        (Value::from("class"), Value::from("custody-portable")),
        (Value::from("device_only"), Value::from(false)),
        (
            Value::from("value_bytes"),
            Value::Binary(b"test-mailbox-token".to_vec()),
        ),
        (Value::from("status"), Value::from("active")),
        (Value::from("registered_at"), Value::from(AT)),
        (Value::from("rotated_at"), Value::Nil),
        (Value::from("rotation_generation"), Value::from(0_u64)),
        (Value::from("bindings"), Value::Array(vec![binding])),
        (Value::from("manifest_ref"), Value::from("")),
        (Value::from("declared_paths"), Value::Array(vec![])),
        (Value::from("policy_floor_snapshot"), floor),
        (Value::from("model_reveal_allowed"), Value::from(false)),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body)?;
    vault
        .register_secret(decode_secret_custody_body(&bytes)?)
        .map_err(at("register the mailbox custody"))?;
    Ok(())
}

/// The owner's override: in this one campaign's brief, campaign outreach
/// wears the owner's own mailbox.
fn owner_campaign_rule(pinned: EntityId) -> ChannelSelectionRuleInput {
    ChannelSelectionRuleInput {
        rule_id: OWNER_CAMPAIGN_RULE.to_owned(),
        relationship: RelationshipContext::CampaignOutreach,
        scope: SelectionRuleScope::Brief {
            brief_ref: CAMPAIGN_BRIEF.to_owned(),
        },
        face: ChannelIdentityFace::DelegatedOwnerAccount,
        pinned_identity_ref: Some(pinned),
        priority: 0,
        enabled: true,
        agent_amendable: true,
    }
}

fn campaign_brief() -> Vec<SelectionRuleScope> {
    vec![SelectionRuleScope::Brief {
        brief_ref: CAMPAIGN_BRIEF.to_owned(),
    }]
}

/// Before any rule exists, the vault reads the six compiled defaults at
/// revision 0, each a system default for the whole vault, and nothing is
/// stored. A campaign sends from the side-domain address.
#[test]
fn a_fresh_vault_reads_the_six_defaults_and_campaigns_wear_the_side_domain() -> TestResult {
    let fixture = Fixture::open()?;
    let rules = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .channel_selection_rules()
        .map_err(at("rules"))?;
    assert_eq!(rules.revision, 0);
    let defaults: Vec<(RelationshipContext, ChannelIdentityFace)> = rules
        .rows
        .iter()
        .map(|row| {
            assert_eq!(row.scope, SelectionRuleScope::VaultDefault);
            assert_eq!(row.writer_kind, SelectionRuleWriterKind::SystemDefault);
            assert!(row.enabled && row.agent_amendable);
            assert_eq!(row.pinned_identity_ref, None);
            (row.relationship, row.face)
        })
        .collect();
    assert_eq!(
        defaults,
        vec![
            (
                RelationshipContext::WorkDeal,
                ChannelIdentityFace::DelegatedOwnerAccount
            ),
            (
                RelationshipContext::SchedulingLogistics,
                ChannelIdentityFace::AgentNamedAddress
            ),
            (
                RelationshipContext::CampaignOutreach,
                ChannelIdentityFace::SideDomainAddress
            ),
            (
                RelationshipContext::TransactionalSystem,
                ChannelIdentityFace::HouseIdentity
            ),
            (
                RelationshipContext::PersonalFriends,
                ChannelIdentityFace::CompanionIdentity
            ),
            (
                RelationshipContext::GroupSpace,
                ChannelIdentityFace::NamedGroupParticipant
            ),
        ]
    );
    assert!(
        fixture
            .vault
            .stored_channel_identity_selection_rules()
            .map_err(at("stored rules"))?
            .is_none(),
        "a fresh vault stores no rule",
    );

    let chosen = fixture.select_campaign_sender(campaign_brief())?;
    assert_eq!(chosen.decision.identity_ref, fixture.side_domain);
    assert_eq!(chosen.decision.face, ChannelIdentityFace::SideDomainAddress);
    assert_eq!(
        chosen.decision.rule_id.as_deref(),
        Some("builtin.campaign_outreach")
    );
    Ok(())
}

/// The worked example. The owner writes one brief-scoped campaign row that
/// pins their own delegated mailbox. That campaign sends from the owner's
/// mailbox; a campaign outside the brief keeps the side-domain default.
#[test]
fn the_owners_campaign_row_sends_its_brief_from_the_owners_mailbox() -> TestResult {
    let fixture = Fixture::open()?;
    fixture.owner_update(0, owner_campaign_rule(fixture.owner_mailbox))?;

    let stored = fixture
        .vault
        .stored_channel_identity_selection_rules()
        .map_err(at("stored rules"))?
        .ok_or("the owner's write stored no rule set")?;
    assert_eq!(stored.revision, 1);
    let [row] = stored.rows.as_slice() else {
        return Err(format!("one stored row expected, got {}", stored.rows.len()).into());
    };
    assert_eq!(row.rule_id, OWNER_CAMPAIGN_RULE);
    assert_eq!(row.writer_kind, SelectionRuleWriterKind::Owner);
    assert_eq!(row.updated_by, Some(fixture.owner));
    assert_eq!(row.pinned_identity_ref, Some(fixture.owner_mailbox));

    let in_brief = fixture.select_campaign_sender(campaign_brief())?;
    assert_eq!(in_brief.revision, 1);
    assert_eq!(in_brief.decision.identity_ref, fixture.owner_mailbox);
    assert_eq!(
        in_brief.decision.face,
        ChannelIdentityFace::DelegatedOwnerAccount
    );
    assert_eq!(
        in_brief.decision.shape,
        ChannelIdentityShape::DelegatedGrant
    );
    assert_eq!(
        in_brief.decision.rule_id.as_deref(),
        Some(OWNER_CAMPAIGN_RULE)
    );
    assert!(!in_brief.decision.used_thread_pin);
    assert_eq!(in_brief.mask.identity_ref, fixture.owner_mailbox);

    for scopes in [
        Vec::new(),
        vec![SelectionRuleScope::Brief {
            brief_ref: "brief:autumn-launch".to_owned(),
        }],
    ] {
        let elsewhere = fixture.select_campaign_sender(scopes)?;
        assert_eq!(elsewhere.decision.identity_ref, fixture.side_domain);
        assert_eq!(
            elsewhere.decision.rule_id.as_deref(),
            Some("builtin.campaign_outreach")
        );
    }
    Ok(())
}

/// Why no vault ships the example as a row: a row that pins an identity the
/// vault does not hold is refused at the update door, and nothing is stored.
#[test]
fn a_row_pinning_an_identity_the_vault_does_not_hold_is_refused() -> TestResult {
    let fixture = Fixture::open()?;
    let refused = fixture.owner_update(0, owner_campaign_rule(EntityId::now()));
    assert!(
        refused.is_err(),
        "a row pinned to an identity this vault does not hold was accepted",
    );
    assert!(
        fixture
            .vault
            .stored_channel_identity_selection_rules()
            .map_err(at("stored rules"))?
            .is_none(),
        "the refused write stored a rule",
    );
    let chosen = fixture.select_campaign_sender(campaign_brief())?;
    assert_eq!(chosen.decision.identity_ref, fixture.side_domain);
    Ok(())
}
