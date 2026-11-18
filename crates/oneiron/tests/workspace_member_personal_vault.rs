//! The member's personal vault on the workspace roster (ARCH-0063:359
//! [INB-07]: "the member's personal vault minted under the org account. A
//! matching offboarding verb hands the vault over. An Eiri user who already
//! owns a personal vault brings it: member onboarding links it"; Engine
//! RULING INB-07-VAULT-LINK = A, the engine half).
//!
//! The host passes the vault in, brought or minted: onboarding links it on
//! the member's roster row and pins it in the request's digest, and the
//! offboarding answers it, read from that row, as the vault handed over.
//! The seat's inquiry route to the vault ends with the seat, as every seat
//! end does (`federation/shared_act/membership.rs`, INQUIRE-1 PR 4).
//!
//! A replay of the offboarding names the vault it handed over again, and a
//! share the leaver's actor holds is revoked through the share door rather
//! than stopping the offboarding (review #8311 round 1).
//!
//! Public paths only, no `cfg` flag (the share case's policy door is the
//! `test-support` feature's): `cargo test --locked -p oneiron
//! --all-features --test workspace_member_personal_vault`. On #8125's head
//! the file does not build: the intent has no `personal_vault`.

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{FederationGrantPreset, FederationGrantRole as Role};
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::workspace_roster::{
    MemberOffboardingIntent, MemberOffboardingOutcome, MemberOnboardingOutcome, PersonalVaultLink,
    PersonalVaultLinkView, PersonalVaultOrigin,
};
use oneiron::{
    CompanionBirthIntent, CompanionChoice, EntityId, Error, MemberGrantBundle,
    MemberOnboardingIntent, Result, TimeRange, Vault, VaultConfig, WorkspaceRosterPreset,
    WorkspaceRosterRole, WriteActor,
};

const WORKSPACE: &str = "workspace-member-personal-vault";
/// The workspace's shared vault. Not 7, the own-device residence scope's id.
const VAULT_ID: u64 = 43;
/// A member's own vault, as a host names it: its genesis id.
const BROUGHT_VAULT: [u8; 32] = [0x5a; 32];
/// The vault a host minted for a member under the org account.
const MINTED_VAULT: [u8; 32] = [0x6b; 32];

fn seed_row(vault: &Vault, entity_type: u8) -> Result<EntityId> {
    let row = EntityId::now();
    vault.put_entity(
        &row,
        entity_type,
        TimeRange {
            start: 100,
            end: 100,
        },
        100,
        b"workspace member personal vault fixture",
    )?;
    Ok(row)
}

fn definition(agent_id: &str) -> AgentDefinition {
    AgentDefinition::new(
        agent_id,
        "workspace member personal vault fixture",
        "1",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::Imported,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("fixture"),
            rmpv::Value::from(agent_id),
        )]),
        None,
        true,
        None,
    )
}

/// A vault whose embedded owner owns the workspace's shared vault.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    preset: WorkspaceRosterPreset,
}

fn fixture() -> Result<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner_proof =
        vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    vault.initialize_shared_vault(&owner_proof, VAULT_ID, None, &[], vault.now_recorded_at())?;
    let (house, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .expect("sys.default is seeded on open");
    let preset = WorkspaceRosterPreset {
        workspace_ref: WORKSPACE.to_owned(),
        workspace_vault_id: VAULT_ID,
        org_ref: seed_row(&vault, ENTITY_TYPE_ORG)?,
        venture_name: "Garden Works".to_owned(),
        house_display_name: None,
        house_actor_ref: house,
        house_identity_ref: None,
    };
    Ok(Fixture {
        _dir: dir,
        vault,
        owner,
        owner_proof,
        preset,
    })
}

impl Fixture {
    /// The owner's onboarding of a new member with a work companion born
    /// here, linking `personal_vault`.
    fn intent(
        &self,
        onboarding_id: &str,
        personal_vault: Option<PersonalVaultLink>,
    ) -> Result<MemberOnboardingIntent> {
        let companion = CompanionBirthIntent {
            person_ref: EntityId::now(),
            actor_ref: EntityId::now(),
            work_facet_ref: seed_row(&self.vault, ENTITY_TYPE_FACET)?,
            profile_grant_ref: EntityId::now(),
            actor_definition: definition(&format!("garden.companion.{onboarding_id}")),
            display_name: "yuki".to_owned(),
        };
        Ok(MemberOnboardingIntent {
            onboarding_id: onboarding_id.to_owned(),
            workspace: self.preset.clone(),
            person_ref: seed_row(&self.vault, ENTITY_TYPE_PERSON)?,
            actor_ref: EntityId::now(),
            actor_definition: definition(&format!("garden.member.{onboarding_id}")),
            work_facet_ref: seed_row(&self.vault, ENTITY_TYPE_FACET)?,
            grant_bundle: MemberGrantBundle {
                federation_grant_ref: EntityId::now(),
                role: Role::Member,
                preset: FederationGrantPreset::Member,
                companion_profile_grant_ref: Some(companion.profile_grant_ref),
            },
            companion: CompanionChoice::Work(companion),
            delegated_mailbox: None,
            personal_vault,
            occurred_at: self.vault.now_recorded_at(),
        })
    }

    fn onboard(&self, intent: MemberOnboardingIntent) -> Result<MemberOnboardingOutcome> {
        self.vault.onboard_workspace_member(
            intent,
            &WriteActor::new(self.owner, EdgeActorClass::Human),
            None,
        )
    }

    fn offboard(&self, offboarding_id: &str, member: EntityId) -> Result<MemberOffboardingOutcome> {
        self.vault.offboard_workspace_member(
            MemberOffboardingIntent {
                offboarding_id: offboarding_id.to_owned(),
                workspace_ref: WORKSPACE.to_owned(),
                person_ref: member,
                check_in_ref: None,
            },
            &self.owner_proof,
            oneiron::authority::ActSurface::ThisInstall,
        )
    }

    /// Whether the workspace roster still lists `member`'s companion row.
    fn on_roster(&self, member: EntityId) -> Result<bool> {
        Ok(self
            .vault
            .workspace_roster(WORKSPACE, self.vault.now_recorded_at())?
            .into_iter()
            .any(|entry| {
                entry.role == WorkspaceRosterRole::PrincipalCompanion
                    && entry.principal_ref == Some(member)
            }))
    }
}

fn view(vault: [u8; 32], origin: PersonalVaultOrigin) -> PersonalVaultLinkView {
    PersonalVaultLink { vault, origin }.view()
}

#[test]
fn a_member_who_brings_her_own_vault_has_it_linked_and_handed_back_at_offboarding() -> Result<()> {
    let fixture = fixture()?;
    let link = PersonalVaultLink {
        vault: BROUGHT_VAULT,
        origin: PersonalVaultOrigin::Brought,
    };
    let intent = fixture.intent("vault-link-brought", Some(link))?;
    let member = intent.person_ref;

    let onboarded = fixture.onboard(intent)?;
    assert_eq!(
        onboarded.personal_vault,
        Some(PersonalVaultLinkView {
            vault: "5a".repeat(32),
            origin: PersonalVaultOrigin::Brought,
        }),
        "the onboarding answers the vault it linked, as 64 hex"
    );
    assert!(fixture.on_roster(member)?);

    // The offboarding reads the link from the roster row onboarding wrote.
    let offboarded = fixture.offboard("vault-link-brought-off", member)?;
    assert_eq!(
        offboarded.personal_vault,
        Some(view(BROUGHT_VAULT, PersonalVaultOrigin::Brought)),
        "the offboarding hands the member's own vault back"
    );
    assert!(
        offboarded.seat_receipt.is_some(),
        "the seat, and with it the seat's inquiry route, ended in the same writer"
    );
    assert!(!fixture.on_roster(member)?, "the link went with the row");
    Ok(())
}

#[test]
fn a_vault_the_host_minted_is_linked_minted_and_handed_over_at_offboarding() -> Result<()> {
    let fixture = fixture()?;
    let link = PersonalVaultLink {
        vault: MINTED_VAULT,
        origin: PersonalVaultOrigin::Minted,
    };
    let intent = fixture.intent("vault-link-minted", Some(link))?;
    let member = intent.person_ref;

    let onboarded = fixture.onboard(intent)?;
    assert_eq!(
        serde_json::to_value(&onboarded.personal_vault).expect("outcome json"),
        serde_json::json!({ "vault": "6b".repeat(32), "origin": "minted" }),
        "the wire spells the link as its hex id and origin"
    );

    let offboarded = fixture.offboard("vault-link-minted-off", member)?;
    assert_eq!(
        offboarded.personal_vault,
        Some(view(MINTED_VAULT, PersonalVaultOrigin::Minted)),
        "the offboarding names the minted vault as handed over"
    );
    Ok(())
}

#[test]
fn a_replay_naming_another_vault_is_refused_and_the_first_link_stands() -> Result<()> {
    let fixture = fixture()?;
    let link = PersonalVaultLink {
        vault: BROUGHT_VAULT,
        origin: PersonalVaultOrigin::Brought,
    };
    let intent = fixture.intent("vault-link-replay", Some(link))?;
    let member = intent.person_ref;
    fixture.onboard(intent.clone())?;

    let other_vault = MemberOnboardingIntent {
        personal_vault: Some(PersonalVaultLink {
            vault: MINTED_VAULT,
            ..link
        }),
        ..intent.clone()
    };
    let other_origin = MemberOnboardingIntent {
        personal_vault: Some(PersonalVaultLink {
            origin: PersonalVaultOrigin::Minted,
            ..link
        }),
        ..intent.clone()
    };
    let no_link = MemberOnboardingIntent {
        personal_vault: None,
        ..intent.clone()
    };
    for changed in [other_vault, other_origin, no_link] {
        let refused = fixture.onboard(changed);
        assert!(
            matches!(&refused, Err(Error::InvalidClaimBody(reason)) if reason.contains("already used")),
            "the link is part of what the request is: {refused:?}"
        );
    }

    let again = fixture.onboard(intent)?;
    assert_eq!(again.personal_vault, Some(link.view()));
    let offboarded = fixture.offboard("vault-link-replay-off", member)?;
    assert_eq!(
        offboarded.personal_vault,
        Some(link.view()),
        "the first link stands on the roster row"
    );
    Ok(())
}

#[test]
fn a_zero_vault_id_is_refused_and_journals_nothing() -> Result<()> {
    let fixture = fixture()?;
    let intent = fixture.intent(
        "vault-link-zero",
        Some(PersonalVaultLink {
            vault: [0; 32],
            origin: PersonalVaultOrigin::Minted,
        }),
    )?;
    let member = intent.person_ref;

    let refused = fixture.onboard(intent.clone());
    assert!(
        matches!(&refused, Err(Error::InvalidClaimBody(reason)) if reason.contains("nonzero vault id")),
        "a zero vault id names no vault: {refused:?}"
    );
    assert!(!fixture.on_roster(member)?);

    // Nothing was journaled: the same id with a real vault onboards.
    let link = PersonalVaultLink {
        vault: MINTED_VAULT,
        origin: PersonalVaultOrigin::Minted,
    };
    let onboarded = fixture.onboard(MemberOnboardingIntent {
        personal_vault: Some(link),
        ..intent
    })?;
    assert_eq!(onboarded.personal_vault, Some(link.view()));
    Ok(())
}

/// GUARD (green before and after): an onboarding with no personal vault
/// links none and its offboarding hands none over.
#[test]
fn an_onboarding_with_no_personal_vault_links_none_and_hands_none_over() -> Result<()> {
    let fixture = fixture()?;
    let intent = fixture.intent("vault-link-none", None)?;
    let member = intent.person_ref;

    let onboarded = fixture.onboard(intent.clone())?;
    assert_eq!(onboarded.personal_vault, None);
    assert_eq!(
        fixture.onboard(intent)?.personal_vault,
        None,
        "a replay answers the same"
    );
    assert!(fixture.on_roster(member)?);

    let offboarded = fixture.offboard("vault-link-none-off", member)?;
    assert_eq!(offboarded.personal_vault, None);
    assert!(!fixture.on_roster(member)?);
    Ok(())
}

/// GUARD (green before and after): the wire's vault id is 32 bytes of hex.
#[test]
fn a_vault_id_that_is_not_32_bytes_of_hex_is_refused() {
    for vault in ["5a".repeat(31), "5a".repeat(33), "zz".repeat(32)] {
        let refused = PersonalVaultLink::from_view(&PersonalVaultLinkView {
            vault,
            origin: PersonalVaultOrigin::Brought,
        });
        assert!(
            matches!(&refused, Err(Error::InvalidClaimBody(reason)) if reason.contains("32 bytes of hex")),
            "{refused:?}"
        );
    }
    let parsed = PersonalVaultLink::from_view(&view(BROUGHT_VAULT, PersonalVaultOrigin::Brought))
        .expect("64 hex parse");
    assert_eq!(parsed.vault, BROUGHT_VAULT);
}

/// A replay of the offboarding after the host lost its answer names the
/// vault it handed over again: the roster row that linked it is gone, so
/// the offboarding's journal keeps it.
#[test]
fn a_replayed_offboarding_names_the_vault_it_handed_over() -> Result<()> {
    let fixture = fixture()?;
    let link = PersonalVaultLink {
        vault: MINTED_VAULT,
        origin: PersonalVaultOrigin::Minted,
    };
    let intent = fixture.intent("vault-link-lost-answer", Some(link))?;
    let member = intent.person_ref;
    fixture.onboard(intent)?;

    let first = fixture.offboard("vault-link-lost-answer-off", member)?;
    let replayed = fixture.offboard("vault-link-lost-answer-off", member)?;
    assert_eq!(
        replayed.personal_vault,
        Some(view(MINTED_VAULT, PersonalVaultOrigin::Minted)),
        "the replay names the vault the first call handed over"
    );
    assert_eq!(replayed.personal_vault, first.personal_vault);
    Ok(())
}

/// The share case reads the policy manifest through the `test-support`
/// feature's doors, which `--all-features` turns on.
#[cfg(feature = "test-support")]
mod share_held_by_leaver {
    use std::collections::BTreeSet;

    use oneiron::access_grant::AccessGrantStatus;
    use oneiron::note::TakeTarget;
    use oneiron::share::Share;

    use super::*;

    /// The owner's scoped grant that lets a brief share be created, beside the
    /// shipped policy.
    fn permit_brief_share(fixture: &Fixture) -> Result<()> {
        let id = oneiron_store::policy_record::default_policy_manifest_id()
            .expect("the default manifest id");
        let bytes = fixture
            .vault
            .get(&id)?
            .expect("the shipped manifest is stored");
        let mut manifest: serde_json::Value =
            rmp_serde::from_slice(&bytes).expect("decode shipped manifest");
        manifest["scoped_grants"]
            .as_array_mut()
            .expect("the shipped scoped-grant table")
            .push(serde_json::json!({
                "actor_ref": fixture.owner.to_hex(),
                "effector": "external:share_brief",
                "scope": oneiron::test_support::effect_preset(),
                "selectors": { "channel": "shared_brief" },
            }));
        oneiron::test_support::put_policy_manifest_bytes(
            &fixture.vault,
            id,
            &rmp_serde::to_vec_named(&manifest).expect("encode share permission"),
        )
        .expect("store the share permission beside the shipped policy");
        Ok(())
    }

    /// A brief shared with the leaver's actor is revoked with the rest of the
    /// leaver's grants, through the share door's own writer: the generic grant
    /// revoker refuses a share, which stopped the whole offboarding.
    #[test]
    fn a_share_the_leavers_actor_holds_is_revoked_at_offboarding() -> Result<()> {
        let fixture = fixture()?;
        let intent = fixture.intent("share-held-by-leaver", None)?;
        let member = intent.person_ref;
        let actor = intent.actor_ref;
        fixture.onboard(intent)?;

        permit_brief_share(&fixture)?;
        let brief = fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .author_take(TakeTarget::Subject(member), "A brief for the member")
            .expect("stored NOTE brief")
            .id_hex;
        let share_id = EntityId::now();
        let now = fixture.vault.now_recorded_at();
        fixture.vault.create_share(
            &share_id,
            &WriteActor::new(fixture.owner, EdgeActorClass::Human),
            &Share {
                recipient_ref: actor,
                brief_ref: brief,
                world_refs: BTreeSet::new(),
                facet_refs: BTreeSet::new(),
                include_unscoped: true,
                status: AccessGrantStatus::Active,
                created_at: now,
                revoked_at: None,
                expires_at: None,
                mention: None,
            },
        )?;

        let offboarded = fixture.offboard("share-held-by-leaver-off", member)?;
        assert!(
            offboarded.access_grants_revoked.contains(&share_id),
            "the share is among the revoked grants: {:?}",
            offboarded.access_grants_revoked
        );
        let share = fixture
            .vault
            .get_share(&share_id)?
            .expect("the share reads");
        assert_eq!(share.status, AccessGrantStatus::Revoked);
        assert!(!fixture.on_roster(member)?, "the offboarding completed");
        Ok(())
    }
}
