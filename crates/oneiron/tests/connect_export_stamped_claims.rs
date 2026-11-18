//! A Connect export carries the source owner's stamped claims up to the
//! Connect grant's own sensitivity ceiling; every other member that is not
//! homed in the vault keeps the home withhold (ANSWER
//! FED-CONNECT-STAMPED-HOME = A, Engine 19 Nov 05:05; DEC-0006
//! `#home-clearance`, RULING SECREAD-HOME-SELECTOR-EXPORT = A). E2E cases
//! FEDERATION-03 and FEDERATION-07 found the export dropping every stamped
//! claim of a Connect world, because a Connect guest is never homed.
//!
//! Each fixture holds one claim stamped public beside the private and the
//! sensitive one: the home withhold passes it and every grant here reads it,
//! so a case cannot pass on an export that carries no claim at all. (An
//! unstamped claim reads as sensitive at the grant's scope check,
//! `UNSTAMPED_CLAIM_SENSITIVITY_BAND`, so it is no control under a private
//! ceiling.)
//!
//! On main `a_connect_grant_carries_a_private_claim_up_to_its_ceiling` fails:
//! the home withhold drops the private claim from the Connect export. The
//! other two cases pass on main and on the head.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test connect_export_stamped_claims`
#![cfg(oneiron_test_support)]
#![cfg(feature = "sync")]

use std::sync::Arc;

use loro::{LoroDoc, LoroValue, ValueOrContainer};
use oneiron::authority::{HostSlipIssuer, PeerMachine};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationDirectionScope, FederationGrantRole, FederationGrantScope, Scope, ScopeAxis, ScopeId,
    Sensitivity, SensitivityCeiling,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST};
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
use oneiron::sync::{
    ConnectExportRequest, SyncClient, SyncSelector, SyncSelectorWorld, filtered_window_doc_for_peer,
};
use oneiron::test_doors::membership::stand_member_grant;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
    VaultConfig,
};
use rmpv::Value;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const WINDOW: &str = "2026-03";
const LEARNED_AT: u64 = 1_773_532_800;
const SHARED: u64 = 42;
/// The scope-map key a claim's sensitivity stamp sits under
/// (`disclosure/home.rs` `SENSITIVITY_STAMP_KEY`).
const STAMP_KEY: &str = "sensitivity";
const STAMP_PUBLIC: u8 = 0;
const STAMP_PRIVATE: u8 = 1;
const STAMP_SENSITIVE: u8 = 2;

fn at_learned() -> TimeRange {
    TimeRange {
        start: LEARNED_AT,
        end: LEARNED_AT,
    }
}

fn open_vault() -> TestResult<(tempfile::TempDir, Arc<Vault>)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    Ok((dir, Arc::new(vault)))
}

fn authenticate_owner(vault: &Vault) -> TestResult<AuthenticatedOwner> {
    let owner_id = vault.ensure_embedded_owner_actor()?;
    Ok(vault.authenticate_owner(owner_id, "owen@example.com", true, GateDecisionId::now())?)
}

fn put_person(vault: &Vault, name: &str) -> TestResult<EntityId> {
    let person = EntityId::now();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from(name))]),
    )?;
    vault.put_entity(&person, ENTITY_TYPE_PERSON, at_learned(), LEARNED_AT, &body)?;
    Ok(person)
}

/// A claim about `subject` in `world` (base reality when `None`), stamped
/// `stamp` in its scope map.
fn put_claim(
    vault: &Vault,
    subject: EntityId,
    world: Option<EntityId>,
    stamp: u8,
) -> TestResult<EntityId> {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        Value::from("lighthouse keeper"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.world = world;
    body.scope = Some(Value::Map(vec![(
        Value::from(STAMP_KEY),
        Value::from(stamp),
    )]));
    vault.put_claim(&id, &body, at_learned(), LEARNED_AT)?;
    Ok(id)
}

/// One public, one private and one sensitive claim about one PERSON.
struct Claims {
    public: EntityId,
    private: EntityId,
    sensitive: EntityId,
}

fn put_claims(vault: &Vault, world: Option<EntityId>) -> TestResult<Claims> {
    let subject = put_person(vault, "kenji")?;
    Ok(Claims {
        public: put_claim(vault, subject, world, STAMP_PUBLIC)?,
        private: put_claim(vault, subject, world, STAMP_PRIVATE)?,
        sensitive: put_claim(vault, subject, world, STAMP_SENSITIVE)?,
    })
}

fn manager(vault: &Arc<Vault>) -> Arc<WindowManager> {
    Arc::new(WindowManager::new(
        Arc::clone(vault),
        Arc::new(Materializer::new()),
        "owen",
    ))
}

fn carries(doc: &LoroDoc, id: EntityId) -> bool {
    matches!(
        doc.get_map("entities").get(&id.to_hex()),
        Some(ValueOrContainer::Value(LoroValue::Binary(_)))
    )
}

/// Raises the seeded policy's Connect guest ceiling to sensitive, so a grant
/// may be minted at any band up to it.
fn admit_sensitive_guest_rows(vault: &Vault, owner: &AuthenticatedOwner) -> TestResult {
    let ids = vault.entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)?;
    assert_eq!(ids.len(), 1, "a fresh vault has one seeded policy manifest");
    let id = ids[0];
    let mut manifest: serde_json::Value =
        rmp_serde::from_slice(&vault.get(&id)?.expect("seeded policy"))?;
    let rows = manifest["federation_grant_rows"]
        .as_array_mut()
        .expect("grant policy rows");
    let row = rows
        .iter_mut()
        .find(|row| row["kind"] == "connect_guest_ceiling")
        .expect("Connect guest ceiling");
    let mut scope: Scope = serde_json::from_value(row["scope"].clone())?;
    scope.sensitivity = SensitivityCeiling::AtMost(Sensitivity::Sensitive);
    row["scope"] = serde_json::to_value(scope)?;
    vault.install_owner_policy_manifest(
        owner,
        id,
        rmp_serde::to_vec_named(&manifest)?,
        LEARNED_AT,
    )?;
    Ok(())
}

fn guest_scope(world: EntityId, ceiling: Sensitivity) -> Scope {
    let mut scope = Scope::top();
    scope.worlds = ScopeAxis::Some([ScopeId(world)].into());
    scope.verbs = ScopeAxis::Some(["read".to_owned(), "propose".to_owned()].into());
    scope.sensitivity = SensitivityCeiling::AtMost(ceiling);
    scope
}

fn guest_direction(world: EntityId) -> FederationDirectionScope {
    FederationDirectionScope {
        worlds: ScopeAxis::Some([ScopeId(world)].into()),
        facets: ScopeAxis::All,
        bands: ScopeAxis::All,
    }
}

/// The source vault's Connect export of its world under an accepted pact
/// whose guest grant reads up to `ceiling`, imported as a Loro document,
/// with the claims it was cut from.
fn connect_export(ceiling: Sensitivity) -> TestResult<(LoroDoc, Claims)> {
    let (_source_dir, vault) = open_vault()?;
    let owner = authenticate_owner(&vault)?;
    let issuer = HostSlipIssuer::from_secret(b"connect-stamped-claims-source")?;
    vault.ensure_host_root_slip(&issuer)?;
    admit_sensitive_guest_rows(&vault, &owner)?;
    let world = vault.create_world(&owner, "owen", LEARNED_AT)?;
    let claims = put_claims(&vault, Some(world))?;

    let (_recipient_dir, recipient) = open_vault()?;
    let recipient_owner = authenticate_owner(&recipient)?;
    let recipient_issuer = HostSlipIssuer::from_secret(b"connect-stamped-claims-recipient")?;
    recipient.ensure_host_root_slip(&recipient_issuer)?;
    admit_sensitive_guest_rows(&recipient, &recipient_owner)?;
    let recipient_world = recipient.create_world(&recipient_owner, "yuki", LEARNED_AT)?;
    let source_id = vault.authority_fold()?.vault_id.expect("rooted source");
    let recipient_id = recipient
        .authority_fold()?
        .vault_id
        .expect("rooted recipient");
    let minted = vault.mint_connect_grant(
        &owner,
        recipient_id,
        guest_scope(world, ceiling),
        None,
        None,
    )?;
    assert_eq!(
        minted.resolved_scope.sensitivity,
        SensitivityCeiling::AtMost(ceiling),
        "the guest grant reads up to the ceiling the owner picked"
    );
    let reciprocal = recipient.mint_connect_grant(
        &recipient_owner,
        source_id,
        guest_scope(recipient_world, ceiling),
        None,
        None,
    )?;
    let offer = vault.propose_connect_as(
        &owner,
        &issuer,
        minted.grant,
        recipient_id,
        guest_direction(world),
        guest_direction(recipient_world),
    )?;
    let (_, counter) = recipient.accept_connect_as(
        &recipient_owner,
        &recipient_issuer,
        reciprocal.grant,
        &offer,
    )?;
    vault.accept_connect_as(&owner, &issuer, minted.grant, &counter)?;
    let pact = offer
        .pact_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let manager = manager(&vault);
    manager.open_window(&WindowKey::new(WINDOW))?;
    let delivery = SyncClient::export_connect_window_as(
        &manager,
        &owner,
        &issuer,
        ConnectExportRequest {
            pact,
            window_key: WINDOW.to_owned(),
            world_ref: world,
            facets: vec![],
            bands: vec![],
        },
    )?;
    let doc = LoroDoc::new();
    doc.import(&delivery.body.update)
        .expect("import the exported Loro update");
    Ok((doc, claims))
}

#[test]
fn a_connect_grant_carries_a_private_claim_up_to_its_ceiling() -> TestResult {
    let (doc, claims) = connect_export(Sensitivity::Private)?;
    assert!(
        carries(&doc, claims.public),
        "the Connect export carries the world's public claim"
    );
    assert!(
        carries(&doc, claims.private),
        "a grant at most private carries the private stamped claim"
    );
    Ok(())
}

#[test]
fn a_connect_grant_withholds_a_sensitive_claim_above_its_ceiling() -> TestResult {
    let (doc, claims) = connect_export(Sensitivity::Private)?;
    assert!(
        carries(&doc, claims.public),
        "the Connect export carries the world's public claim"
    );
    assert!(
        !carries(&doc, claims.sensitive),
        "a grant at most private withholds the sensitive stamped claim"
    );
    Ok(())
}

#[test]
fn a_guest_without_a_connect_grant_still_reads_no_stamped_claim() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = authenticate_owner(&vault)?;
    let issuer = HostSlipIssuer::from_secret(b"connect-stamped-claims-member")?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.initialize_shared_vault(&owner, SHARED, None, &[], 1)?;
    let claims = put_claims(&vault, None)?;
    let member = put_person(&vault, "yuki")?;
    let grant = stand_member_grant(&vault, member, SHARED, FederationGrantRole::Member)?;
    let selector = SyncSelector::new(grant, member, SyncSelectorWorld::Base, vec![], vec![]);
    let key = WindowKey::new(WINDOW);
    let window = manager(&vault).open_window(&key)?;
    let doc = filtered_window_doc_for_peer(
        &vault,
        &window.doc,
        &key,
        FederationGrantScope::vault(SHARED),
        &selector,
        PeerMachine::Unknown,
    )?;
    assert!(
        carries(&doc, claims.public),
        "the member's window carries the public claim"
    );
    assert!(
        !carries(&doc, claims.private),
        "a member homed in another vault and outside a Connect grant reads no stamped claim"
    );
    assert!(
        !carries(&doc, claims.sensitive),
        "a member homed in another vault and outside a Connect grant reads no stamped claim"
    );
    Ok(())
}
