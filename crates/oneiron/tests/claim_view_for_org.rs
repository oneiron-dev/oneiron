//! A bound house's claims read "<agent>, for <org>" (HOUSE-BIND = A,
//! ARCH-0063 #house-bind: "Its statements carry both the agent and the org:
//! “pr2, for Antevon”."; ARCH-0067 #people-house-link; Engine RULING L3-18
//! = A, 13 Nov 20:49, claim half; FIX row SPEAKER-BYLINE-FOR-ORG-CLAIMS).
//!
//! A claim reply (`vault.claims.list` and every reply built on the same
//! claim view) answers `for_org`: the org the claim's maker (`made_by`'s
//! actor) ran as its house at `made_by.at`, read from the house link
//! receipts on each read. Nothing is stored on the claim, so an unbind never
//! changes how a claim made before it reads, and a claim made after the
//! unbind reads no org. A maker that is no house (the owner) reads none.
//!
//! The fixture is tests/house_bind_interval.rs's: the seeded `sys.default`
//! agent is the house of a workspace that runs the org, on an injected
//! clock. Each claim is put through the raw claim door and its birth stamped
//! through a test door, so the claim reads as made by the house (or the
//! owner) at the time it names. The views are read as JSON, the shape the
//! verbs answer.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test claim_view_for_org`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::federation::FederationGrantRole;
use oneiron::memory::ClaimListFilter;
use oneiron::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::test_doors::house_link::put_claim_made_by;
use oneiron::workspace_roster::{WorkCompanionPolicy, WorkspaceRosterPreset};
use oneiron::write_envelope::provenance::made_by::{MadeBy, MadeByClass, MadeByProcess};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const WORKSPACE: &str = "claim-view-for-org-workspace";

/// The org the house runs.
const ORG: [u8; 16] = [0xB4; 16];

/// A vault on an injected clock whose seeded `sys.default` agent is the
/// house of a workspace that runs [`ORG`], bound at `start`, and a PERSON
/// the claims are about.
struct BoundHouse {
    vault: Vault,
    clock: Arc<ManualClock>,
    start: u64,
    owner: EntityId,
    house: EntityId,
    subject: EntityId,
    owner_proof: oneiron::consent::AuthenticatedOwner,
    issuer: oneiron::authority::HostSlipIssuer,
    _dir: tempfile::TempDir,
}

fn bound_house() -> TestResult<BoundHouse> {
    let start = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let clock = ManualClock::new(start);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), config)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    let owner_proof =
        vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let signer = vault.owner_project_signer(&issuer)?;
    vault.sign_owner_project(&owner_proof, &signer, vault.root_project()?)?;
    vault.put_entity(
        &EntityId::from_bytes(ORG)?,
        ENTITY_TYPE_ORG,
        TimeRange { start: 1, end: 1 },
        1,
        b"claim view for org",
    )?;
    let (house, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .ok_or("sys.default is seeded on open")?;
    let preset = WorkspaceRosterPreset {
        workspace_ref: WORKSPACE.to_owned(),
        workspace_vault_id: 44,
        org_ref: EntityId::from_bytes(ORG)?,
        venture_name: "Garden Works".to_owned(),
        house_display_name: None,
        house_actor_ref: house,
        house_identity_ref: None,
    };
    vault.establish_workspace_preset(&preset, WorkCompanionPolicy::Choose, &owner_proof)?;
    vault.bind_workspace_house_leader(
        WORKSPACE,
        FederationGrantRole::Member,
        &owner_proof,
        &signer,
    )?;
    drop(signer);
    // A PERSON subject: a claim about it is born in its stored facet.
    let subject = EntityId::now();
    let mut person = Vec::new();
    rmpv::encode::write_value(
        &mut person,
        &rmpv::Value::Map(vec![(rmpv::Value::from("name"), rmpv::Value::from("owen"))]),
    )?;
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        &person,
    )?;
    Ok(BoundHouse {
        vault,
        clock,
        start,
        owner,
        house,
        subject,
        owner_proof,
        issuer,
        _dir: dir,
    })
}

/// A claim about the fixture's subject, made by `maker` at `at`.
fn claim_made_by(
    fixture: &BoundHouse,
    maker: EntityId,
    at: u64,
    value: &str,
) -> TestResult<EntityId> {
    let id = EntityId::now();
    let body = ClaimBody::new(
        format!("profile.note_{}", &id.to_hex()[..8]),
        ClaimSubject::Entity(fixture.subject),
        rmpv::Value::from(value),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    let made_by = MadeBy {
        inputs: Vec::new(),
        process: MadeByProcess {
            actor: maker,
            class: MadeByClass::Stated,
            identity: "claim-view-for-org-fixture".to_owned(),
            version: "1".to_owned(),
            params_hash: "fixture".to_owned(),
        },
        at,
        trigger: None,
    };
    put_claim_made_by(&fixture.vault, id, &body, made_by)?;
    Ok(id)
}

/// The owner's `vault.claims.list` of the subject's claims, as JSON.
fn listed(fixture: &BoundHouse) -> TestResult<Vec<serde_json::Value>> {
    let views = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .claim_list(&ClaimListFilter {
            subject_ref: Some(fixture.subject.to_hex()),
            limit: 50,
            ..Default::default()
        })?
        .value;
    Ok(views
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()?)
}

/// The listed view of `claim`, after checking that it names `maker`: a
/// fixture fault, never this case's finding, when it does not.
fn view_of<'a>(
    views: &'a [serde_json::Value],
    claim: EntityId,
    maker: EntityId,
) -> TestResult<&'a serde_json::Value> {
    let view = views
        .iter()
        .find(|view| view["claim_ref"] == claim.to_hex())
        .ok_or_else(|| format!("fixture: claim {} is not listed: {views:?}", claim.to_hex()))?;
    if view["made_by"]["process"]["actor"] != maker.to_hex() {
        return Err(format!("fixture: the claim's birth names another maker: {view}").into());
    }
    Ok(view)
}

#[test]
fn claim_view_names_the_org_its_house_ran_when_it_made_the_claim() -> TestResult {
    let fixture = bound_house()?;
    let made_at = fixture.start + 60;
    fixture.clock.set(made_at);
    let by_house = claim_made_by(&fixture, fixture.house, made_at, "owen waters the beds")?;
    let by_owner = claim_made_by(&fixture, fixture.owner, made_at, "owen likes mint")?;
    let views = listed(&fixture)?;
    let org = EntityId::from_bytes(ORG)?.to_hex();
    let house_view = view_of(&views, by_house, fixture.house)?;
    assert_eq!(
        house_view
            .get("for_org")
            .and_then(serde_json::Value::as_str),
        Some(org.as_str()),
        "a claim the bound house made reads for its org: {house_view}",
    );
    let owner_view = view_of(&views, by_owner, fixture.owner)?;
    assert_eq!(
        owner_view.get("for_org"),
        None,
        "the owner is no house: {owner_view}",
    );
    Ok(())
}

#[test]
fn claim_view_after_unbind_reads_no_org_for_a_later_claim() -> TestResult {
    let fixture = bound_house()?;
    let in_bind = fixture.start + 60;
    fixture.clock.set(in_bind);
    let before = claim_made_by(&fixture, fixture.house, in_bind, "owen waters the beds")?;
    fixture.clock.set(fixture.start + 600);
    let signer = fixture.vault.owner_project_signer(&fixture.issuer)?;
    if !fixture
        .vault
        .unbind_house_leader(&fixture.owner_proof, &signer)?
    {
        return Err("fixture: the unbind found no bound house".into());
    }
    drop(signer);
    let after_unbind = fixture.start + 1_200;
    fixture.clock.set(after_unbind);
    let after = claim_made_by(&fixture, fixture.house, after_unbind, "owen moved the shed")?;
    let views = listed(&fixture)?;
    let org = EntityId::from_bytes(ORG)?.to_hex();
    let before_view = view_of(&views, before, fixture.house)?;
    assert_eq!(
        before_view
            .get("for_org")
            .and_then(serde_json::Value::as_str),
        Some(org.as_str()),
        "a claim the house made inside its bind reads for its org after the unbind too: \
         {before_view}",
    );
    let after_view = view_of(&views, after, fixture.house)?;
    assert_eq!(
        after_view.get("for_org"),
        None,
        "a claim made after the unbind reads no org: {after_view}",
    );
    Ok(())
}
