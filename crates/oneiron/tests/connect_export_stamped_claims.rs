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
//! Cases:
//! - A Connect grant carries a private claim at its ceiling, but not a
//!   sensitive claim above it; a non-Connect guest still reads neither.
//! - A private conversation summary covering a private claim in another
//!   world is withheld; the same shape covering its own world is carried.
//! - A causally admitted MACHINE-signed private claim in the granted world
//!   is withheld, while the plain private claim still rides.
//! - A summary in the granted world whose covered claim is use-limited (a
//!   privacy erase a standing customer hold refused) is withheld, as the
//!   claim itself is.
//!
//! Traced red/green (not executed): on main `9622dba76276` the private carry
//! and same-world summary control fail; the cross-world and MACHINE LEAK
//! assertions pass, but their private-carry FIXTURE assertions fail too.
//! On `cf45cbc3` both LEAK assertions fail and the other cases pass. With
//! the review fix all six cases pass. The use-limit case (review round 2)
//! fails its LEAK assertion at `dcb16249` and passes with the round-2 fix;
//! on main its private-carry FIXTURE fails, as above.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test connect_export_stamped_claims`
#![cfg(oneiron_test_support)]
#![cfg(feature = "sync")]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use loro::{LoroDoc, LoroValue, ValueOrContainer};
use oneiron::authority::{CausalWriteDisposition, HostSlipIssuer, PeerMachine};
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::LegalHoldTarget;
use oneiron::federation::{
    FederationDirectionScope, FederationGrantRole, FederationGrantScope, Scope, ScopeAxis, ScopeId,
    Sensitivity, SensitivityCeiling,
};
use oneiron::memory::{EraseOptions, EraseReason};
use oneiron::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST};
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
use oneiron::sync::{
    ConnectExportRequest, SyncClient, SyncSelector, SyncSelectorWorld, filtered_window_doc_for_peer,
};
use oneiron::test_doors::disclosure_word_sources::install_shipped_policy_with_ordinary_predicate;
use oneiron::test_doors::membership::stand_member_grant;
use oneiron::write_envelope::MachineWriteSignature;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimCandidate, ClaimLifecycleStatus, ClaimSource,
    ClaimSubject, EdgeActorClass, EntityId, HostingPrivacyPosture, TimeRange, Vault, VaultConfig,
    WriteActor, WriteEnvelope, WriteProvenance,
};
use oneiron_store::conversation_summary::conversation_summary_covers;
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
    open_vault_with(VaultConfig::default())
}

fn open_vault_with(config: VaultConfig) -> TestResult<(tempfile::TempDir, Arc<Vault>)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), config)?;
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
    predicate: &str,
    value: Value,
) -> TestResult<EntityId> {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        value,
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
    let stored = vault.get_claim(&id)?.expect("FIXTURE: claim landed");
    assert_eq!(stored.world, world, "FIXTURE: claim keeps its world");
    assert_eq!(stored.scope, body.scope, "FIXTURE: claim keeps its stamp");
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
        public: put_claim(
            vault,
            subject,
            world,
            STAMP_PUBLIC,
            "profile.note",
            "lighthouse keeper".into(),
        )?,
        private: put_claim(
            vault,
            subject,
            world,
            STAMP_PRIVATE,
            "profile.note",
            "lighthouse keeper".into(),
        )?,
        sensitive: put_claim(
            vault,
            subject,
            world,
            STAMP_SENSITIVE,
            "profile.note",
            "lighthouse keeper".into(),
        )?,
    })
}

/// A private summary in `world` with typed coverage of exactly `covered`.
fn put_summary(vault: &Vault, world: EntityId, covered: EntityId) -> TestResult<EntityId> {
    let subject = put_person(vault, "kenji")?;
    let summary = put_claim(
        vault,
        subject,
        Some(world),
        STAMP_PRIVATE,
        "conversation.summary",
        Value::Map(vec![
            ("text".into(), "lighthouse keeper".into()),
            (
                "covers".into(),
                Value::Array(vec![Value::Binary(covered.as_bytes().to_vec())]),
            ),
        ]),
    )?;
    let stored = vault.get_claim(&summary)?.expect("FIXTURE: summary landed");
    assert_eq!(stored.world, Some(world), "FIXTURE: summary belongs to W");
    assert_eq!(
        conversation_summary_covers(&stored)?,
        Some(vec![covered]),
        "FIXTURE: the stored summary decodes to exactly its covered claim"
    );
    Ok(summary)
}

/// An enrolled MACHINE's real private birth, signed after its world and
/// sensitivity are set. The candidate writer lands its history too.
fn put_machine_claim(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    world: EntityId,
) -> TestResult<EntityId> {
    let machine = EntityId::now();
    vault.put_entity(
        &machine,
        ENTITY_TYPE_MACHINE,
        at_learned(),
        LEARNED_AT,
        b"machine",
    )?;
    let signing = SigningKey::from_bytes(&[0x4d; 32]);
    vault.enroll_machine_identity(
        issuer,
        machine,
        signing.verifying_key().to_bytes(),
        [0x54; 32],
        |transcript| Ok(signing.sign(transcript).to_bytes()),
    )?;
    let candidate = ClaimCandidate::new(
        "profile.note",
        ClaimSubject::Entity(machine),
        "lighthouse keeper".into(),
        1.0,
    )
    .with_world(world)
    .with_scope(Value::Map(vec![(STAMP_KEY.into(), STAMP_PRIVATE.into())]));
    let envelope = WriteEnvelope::new(
        WriteActor::new(machine, EdgeActorClass::System),
        ClaimSource::Observed,
        WriteProvenance::new("machine output".into())?,
        ClaimApprovalStatus::Proposed,
    );
    let id = EntityId::now();
    let transcript = vault.machine_claim_transcript(&id, &candidate, &envelope)?;
    let signed = envelope.with_machine_signature(MachineWriteSignature {
        public_key: signing.verifying_key().to_bytes(),
        signature: signing.sign(&transcript).to_bytes(),
    });
    vault
        .batch()
        .claim_candidate(&id, candidate, &signed, at_learned(), LEARNED_AT)
        .commit()?;
    Ok(id)
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
    let (doc, claims, ()) = connect_export_with(ceiling, |_, _, _, _, _| Ok(()))?;
    Ok((doc, claims))
}

/// Prepares extra rows before opening the window and exporting it.
fn connect_export_with<T>(
    ceiling: Sensitivity,
    prepare: impl FnOnce(
        &Vault,
        &AuthenticatedOwner,
        &HostSlipIssuer,
        EntityId,
        &Claims,
    ) -> TestResult<T>,
) -> TestResult<(LoroDoc, Claims, T)> {
    connect_export_from(VaultConfig::default(), ceiling, prepare)
}

/// As `connect_export_with`, from a source vault opened with `config`.
fn connect_export_from<T>(
    config: VaultConfig,
    ceiling: Sensitivity,
    prepare: impl FnOnce(
        &Vault,
        &AuthenticatedOwner,
        &HostSlipIssuer,
        EntityId,
        &Claims,
    ) -> TestResult<T>,
) -> TestResult<(LoroDoc, Claims, T)> {
    let (_source_dir, vault) = open_vault_with(config)?;
    let owner = authenticate_owner(&vault)?;
    // The raw claim door needs an ordinary rule to land a summary. Install
    // it before raising the Connect ceiling, since this door resets policy.
    install_shipped_policy_with_ordinary_predicate(&vault, "conversation.summary")?;
    let issuer = HostSlipIssuer::from_secret(b"connect-stamped-claims-source")?;
    vault.ensure_host_root_slip(&issuer)?;
    admit_sensitive_guest_rows(&vault, &owner)?;
    let world = vault.create_world(&owner, "owen", LEARNED_AT)?;
    let claims = put_claims(&vault, Some(world))?;
    let extra = prepare(&vault, &owner, &issuer, world, &claims)?;

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
    Ok((doc, claims, extra))
}

/// Pins the cross-world word-source fence under a private Connect ceiling.
/// On main 9622dba76276 the LEAK assertion passes, but the private-carry
/// FIXTURE fails. On cf45cbc3 the LEAK fails; with the review fix both pass.
#[test]
fn a_connect_grant_withholds_a_summary_whose_words_come_from_another_world() -> TestResult {
    let (doc, claims, (summary, covered)) =
        connect_export_with(Sensitivity::Private, |vault, owner, _, world, _| {
            let other_world = vault.create_world(owner, "haru", LEARNED_AT)?;
            assert_ne!(
                other_world, world,
                "FIXTURE: B differs from granted world W"
            );
            let subject = put_person(vault, "kenji")?;
            let covered = put_claim(
                vault,
                subject,
                Some(other_world),
                STAMP_PRIVATE,
                "profile.note",
                "lighthouse keeper".into(),
            )?;
            Ok((put_summary(vault, world, covered)?, covered))
        })?;
    assert!(
        carries(&doc, claims.private),
        "FIXTURE: the Connect export carries the plain private claim in W"
    );
    assert!(
        !carries(&doc, covered),
        "FIXTURE: the claim in ungranted world B is not directly exported"
    );
    assert!(
        !carries(&doc, summary),
        "LEAK: a summary in W must not carry private words from ungranted world B"
    );
    Ok(())
}

/// Pins the same-world control: a Connect ceiling must still admit a
/// summary whose private source is selected. On main 9622dba76276 the
/// private-carry FIXTURE and the final carry assertion fail; on cf45cbc3
/// and with the review fix both pass.
#[test]
fn a_connect_grant_carries_a_summary_whose_words_come_from_its_world() -> TestResult {
    let (doc, claims, summary) =
        connect_export_with(Sensitivity::Private, |vault, _, _, world, claims| {
            put_summary(vault, world, claims.private)
        })?;
    assert!(
        carries(&doc, claims.private),
        "FIXTURE: the Connect export carries the summary's private source in W"
    );
    assert!(
        carries(&doc, summary),
        "OVER-REFUSAL: the source fence must not withhold a summary backed by selected private words"
    );
    Ok(())
}

/// Pins the use limit on a stamped word source (review round 2 of #9526). A
/// privacy erase that a standing customer hold refuses keeps the covered
/// claim stored but use-limited (only where Oneiron hosts the bytes, so the
/// source vault is Hosted), and the export withholds the claim itself; a
/// summary in W quoting it must be withheld too. On main 9622dba76276 the
/// LEAK assertion passes, but the private-carry FIXTURE fails. On dcb16249
/// the LEAK fails; with the round-2 fix both pass.
#[test]
fn a_connect_grant_withholds_a_summary_whose_words_come_from_a_use_limited_claim() -> TestResult {
    let mut hosted = VaultConfig::default();
    hosted.privacy.posture = HostingPrivacyPosture::Hosted;
    let (doc, claims, (summary, covered)) =
        connect_export_from(hosted, Sensitivity::Private, |vault, owner, _, world, _| {
            let subject = put_person(vault, "kenji")?;
            let covered = put_claim(
                vault,
                subject,
                Some(world),
                STAMP_PRIVATE,
                "profile.note",
                "lighthouse keeper".into(),
            )?;
            let summary = put_summary(vault, world, covered)?;
            let hold = vault.place_legal_hold(
                owner,
                vec![LegalHoldTarget::Record(covered)],
                Some("matter-9526".to_owned()),
            )?;
            assert!(hold.stands(), "FIXTURE: the customer hold stands: {hold:?}");
            let actor = vault.ensure_embedded_owner_actor()?;
            let memory = vault.memory(actor, EdgeActorClass::Human);
            let preview = memory
                .preview_entity_delete(&covered)
                .expect("FIXTURE: preview the covered claim's erase");
            let outcome = memory
                .confirm_entity_erase(
                    &preview,
                    EraseOptions {
                        reason: EraseReason::GdprDelete,
                        also_same_bytes: false,
                        veto_starter: None,
                    },
                )
                .expect("FIXTURE: the privacy erase runs");
            assert_eq!(
                outcome.first.reason.as_str(),
                "privacy_erase_kept",
                "FIXTURE: the held privacy erase is kept: {outcome:?}"
            );
            assert!(
                vault.legal_hold_use_limit(&covered)?.is_some(),
                "FIXTURE: the kept erase use-limits the covered claim"
            );
            Ok((summary, covered))
        })?;
    assert!(
        carries(&doc, claims.private),
        "FIXTURE: the Connect export carries the plain private claim in W"
    );
    assert!(
        !carries(&doc, covered),
        "FIXTURE: the use-limited claim itself is not exported"
    );
    assert!(
        !carries(&doc, summary),
        "LEAK: a summary in W must not carry the words of a use-limited claim"
    );
    Ok(())
}

/// Pins the MACHINE-proof withhold at Connect egress, after causal admission.
/// On main 9622dba76276 the LEAK assertion passes, but the private-carry
/// FIXTURE fails. On cf45cbc3 the LEAK fails; with the review fix both pass.
#[test]
fn a_connect_grant_withholds_a_machine_signed_private_claim() -> TestResult {
    let (doc, claims, machine_claim) =
        connect_export_with(Sensitivity::Private, |vault, _, issuer, world, _| {
            let id = put_machine_claim(vault, issuer, world)?;
            let body = vault
                .get_claim(&id)?
                .expect("FIXTURE: MACHINE claim landed");
            assert_eq!(
                body.world,
                Some(world),
                "FIXTURE: signed claim belongs to W"
            );
            assert_eq!(
                body.scope,
                Some(Value::Map(vec![(STAMP_KEY.into(), STAMP_PRIVATE.into())])),
                "FIXTURE: signed claim is stamped private"
            );
            assert!(
                body.evidence
                    .as_ref()
                    .and_then(Value::as_map)
                    .is_some_and(|fields| {
                        fields
                            .iter()
                            .any(|(key, _)| key.as_str() == Some("machine_signature"))
                    }),
                "FIXTURE: the stored claim carries its MACHINE proof"
            );
            assert_eq!(
                vault.claim_write_disposition(&id)?,
                Some(CausalWriteDisposition::Admitted),
                "FIXTURE: the signed claim passes the causal predicate, not a forged-proof drop"
            );
            Ok(id)
        })?;
    assert!(
        carries(&doc, claims.private),
        "FIXTURE: the Connect export still carries the plain private claim in W"
    );
    assert!(
        !carries(&doc, machine_claim),
        "LEAK: a Connect grant must not export a private CLAIM bound by a MACHINE proof"
    );
    Ok(())
}

/// Pins Connect's private ceiling exception: fails on main 9622dba76276,
/// passes on cf45cbc3 and with the review fix.
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

/// Pins the grant's sensitivity ceiling: passes on main 9622dba76276,
/// cf45cbc3 and with the review fix.
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

/// Pins the unchanged non-Connect home withhold: passes on main
/// 9622dba76276, cf45cbc3 and with the review fix.
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
