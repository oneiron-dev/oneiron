//! The serve start mints the default read Grant of each named agent paired
//! before Grants, once per self-hosted vault (FIX AGENT-GRANTLESS-VISIBLE
//! item 1; Engine RULING GRANTLESS-SHAPE Q1-Q7 = A, 12 Nov 03:02). A holder
//! whose Grant the owner revoked gets none back. A dead slip, a principal
//! that is no named agent and a slip with no read verb mint nothing. A
//! refused signer writes neither a Grant nor the completion marker. A vault
//! that is not self-hosted runs nothing.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test agent_grant_backfill`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActSurface, CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip,
};
use oneiron::claim::{ScopedReadActorKey, base_world_id, default_project_id};
use oneiron::consent::{AuthenticatedOwner, ConsentRegistryQuery, ConsentRegistryRow};
use oneiron::federation::{DefaultAgentGrantBackfill, Scope, ScopeAxis, ScopeId};
use oneiron::graph_fs::GraphFsOptions;
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, AgentGrantRevokeRequest,
    create_agent_definition_as, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, HostingPrivacyPosture, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use serde_json::json;

const OCCURRED_AT: u64 = 1_769_947_200;
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:agent-grant-backfill";
const SLIP_LIFETIME_SECS: u64 = 3_600;

struct Fixture {
    vault: Vault,
    dir: tempfile::TempDir,
    keystore: Arc<MemoryKeystore>,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    /// The graph path of the owner's base-world claim; empty when the
    /// fixture has no install profile and so wrote no claim.
    base_path: String,
}

/// A self-hosted vault with this install's engine machines. With
/// `profiled`, this install's live machine profile carries the owner's acts,
/// as a serve start enrols it, and the owner has written one base-world
/// claim; without it, the owner's acts have no carrier.
fn fixture(profiled: bool) -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let keystore = Arc::new(MemoryKeystore::default());
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let base_path = if profiled {
        enrol_install_profile(&vault, &issuer);
        let claim = write_owner_claim(&vault, owner, &owner_proof);
        format!("/worlds/base/claims/{}", claim.to_hex())
    } else {
        String::new()
    };
    Fixture {
        vault,
        dir,
        keystore,
        issuer,
        owner,
        owner_proof,
        base_path,
    }
}

/// The fixture's vault closed and opened again, as a second serve start
/// opens it, with a fresh owner proof.
fn reopen(fixture: Fixture) -> Fixture {
    let Fixture {
        vault,
        dir,
        keystore,
        issuer,
        base_path,
        ..
    } = fixture;
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("reopened vault");
    vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
    let (owner, owner_proof) = embedded_owner(&vault).expect("owner proof after the reopen");
    Fixture {
        vault,
        dir,
        keystore,
        issuer,
        owner,
        owner_proof,
        base_path,
    }
}

/// This install's live machine profile, as a serving start enrols it (FIX
/// 4648): it carries the owner's agent Grant acts.
fn enrol_install_profile(vault: &Vault, issuer: &HostSlipIssuer) {
    vault
        .ensure_serving_install_profile(issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
}

fn write_owner_claim(vault: &Vault, owner: EntityId, owner_proof: &AuthenticatedOwner) -> EntityId {
    let id = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(owner_proof)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(id.to_hex()),
            predicate: "profile.preference".to_owned(),
            subject_ref: owner.to_hex(),
            value: json!("base-world claim"),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: base_world_id().to_hex(),
                scope_facet_id: vault.default_facet().expect("owner default facet").to_hex(),
                scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                scope_project_id: default_project_id().to_hex(),
            },
            sensitivity: None,
            evidence_turn_refs: Vec::new(),
            valid_from: None,
            valid_to: None,
            occurred_at: Some(OCCURRED_AT),
            learned_at: Some(OCCURRED_AT),
            salience: None,
        })
        .expect("owner writes a base-world claim");
    id
}

/// The pairing Scope `oneiron token read` gives: every world, `core:read`.
fn read_slip_scope() -> Scope {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned()]));
    scope
}

/// The Scope of the default read Grant for a slip of `slip` Scope: verbs
/// `read`, the slip's other axes.
fn default_grant_scope(slip: &Scope) -> Scope {
    let mut scope = slip.clone();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    scope
}

/// `holder` pairs as class `agent` on a link the host issues with no owner
/// proof, as every agent paired before Grants did, and redeems it with the
/// key `binding_seed` derives. No Grant is minted.
fn host_paired_agent_slip(
    fixture: &Fixture,
    holder: EntityId,
    scope: Scope,
    lifetime_secs: u64,
    binding_seed: u8,
) -> CapabilitySlip {
    let holder_ref = holder.to_hex();
    let link = fixture
        .vault
        .issue_pairing_link_for_principal(
            &fixture.issuer,
            scope,
            lifetime_secs,
            PairingPrincipal {
                holder_ref: Some(holder_ref.clone()),
                actor_class: Some("agent".to_owned()),
                ..PairingPrincipal::default()
            },
        )
        .expect("host issues the agent's pairing link with no owner proof");
    let signing_key = SigningKey::from_bytes(&[binding_seed; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &holder_ref,
        link.pin.as_ref(),
    )
    .expect("agent pairing transcript");
    fixture
        .vault
        .redeem_pairing_link(
            &fixture.issuer,
            &link.code,
            &holder_ref,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )
        .expect("agent redeems its pairing link")
}

/// The holder of `slip`, whose key `binding_seed` derives, proves possession.
fn prove_possession(fixture: &Fixture, slip: &CapabilitySlip, binding_seed: u8) -> VerifiedSlip {
    let signing_key = SigningKey::from_bytes(&[binding_seed; 32]);
    let signature = signing_key
        .sign(
            &slip
                .binding_transcript(REQUEST_CHALLENGE)
                .expect("agent request transcript"),
        )
        .to_bytes();
    fixture
        .vault
        .verify_capability_slip(
            &fixture.issuer.public_key(),
            slip,
            REQUEST_CHALLENGE,
            &signature,
        )
        .expect("agent proves possession of its credential")
}

/// The live owner-agent Grants of the registry that name `holder`.
fn grants_naming(vault: &Vault, holder: EntityId) -> Vec<ConsentRegistryRow> {
    vault
        .consent_registry(ConsentRegistryQuery::new(1_000, false))
        .expect("owner's consent registry")
        .rows
        .into_iter()
        .filter(|row| {
            row.agent_grant
                .as_ref()
                .is_some_and(|grant| grant.agent == holder)
        })
        .collect()
}

fn grant_ids(rows: &[ConsentRegistryRow]) -> BTreeSet<EntityId> {
    rows.iter()
        .map(|row| EntityId::from_hex(&row.grant_ref).expect("Grant id hex"))
        .collect()
}

/// The paths of `paths` that `key` reads back a row at.
fn readable(vault: &Vault, key: ScopedReadActorKey, paths: &[&str]) -> Vec<String> {
    let lane = vault
        .scoped_read(key)
        .recorded_lane()
        .expect("graph filesystem record lane");
    let tree = lane.graph_fs(GraphFsOptions::default());
    paths
        .iter()
        .filter(|path| {
            tree.read_file(path)
                .expect("graph filesystem read")
                .value
                .is_some()
        })
        .map(|path| (*path).to_owned())
        .collect()
}

/// The paths of `paths` a fresh read key for `slip` reads; none when the
/// slip grants no read key at all.
fn slip_reads(fixture: &Fixture, slip: &VerifiedSlip, paths: &[&str]) -> Vec<String> {
    fixture
        .vault
        .credential_read_key(slip)
        .expect("agent credential read key")
        .map_or_else(Vec::new, |key| readable(&fixture.vault, key, paths))
}

fn backfill(fixture: &Fixture) -> DefaultAgentGrantBackfill {
    fixture
        .vault
        .backfill_default_agent_grants(&fixture.owner_proof)
        .expect("the serve-start backfill runs")
}

/// Q1/Q4/Q5: owen paired on a host link before Grants: no Grant names him
/// and his slip reads the base world. The backfill mints one default read
/// Grant (verbs `read`, the slip's other axes, no expiry, wallet, repo
/// bounds or classes), his reach is unchanged, and a second call, also
/// after the vault is closed and opened again, mints nothing.
#[test]
fn serve_start_backfill_mints_once_for_a_never_granted_named_agent() {
    let fixture = fixture(true);
    let base = fixture.base_path.clone();
    let owen = fixture
        .vault
        .ensure_agent_principal("owen")
        .expect("named agent principal");
    let slip = host_paired_agent_slip(&fixture, owen, read_slip_scope(), SLIP_LIFETIME_SECS, 0x71);
    let slip = prove_possession(&fixture, &slip, 0x71);
    let before = grants_naming(&fixture.vault, owen);
    assert!(
        before.is_empty(),
        "actor=named agent {owen:?}; expected no Grant before the backfill (paired with no owner proof); seen grants={before:?}"
    );
    let reads_before = slip_reads(&fixture, &slip, &[base.as_str()]);
    assert_eq!(
        reads_before,
        vec![base.clone()],
        "actor=named agent {owen:?}; expected the never-granted slip to read [{base}]; seen names={reads_before:?}"
    );

    let first = backfill(&fixture);
    let DefaultAgentGrantBackfill::Completed { grants } = &first else {
        panic!("actor=owner; expected the first backfill to complete; seen {first:?}");
    };
    let rows = grants_naming(&fixture.vault, owen);
    assert_eq!(
        rows.len(),
        1,
        "actor=named agent {owen:?}; expected one default Grant naming him; seen grants={rows:?}"
    );
    assert_eq!(
        grant_ids(&rows),
        grants.iter().copied().collect::<BTreeSet<_>>(),
        "actor=owner; expected the backfill to report the Grant it minted; seen outcome={first:?} rows={rows:?}"
    );
    let row = &rows[0];
    let grant = row.agent_grant.as_ref().expect("an owner-agent Grant row");
    assert_eq!(
        row.scope.as_ref(),
        Some(&default_grant_scope(&read_slip_scope())),
        "actor=named agent {owen:?}; expected the default Grant at the slip's axes with verbs [read]; seen row={row:?}"
    );
    assert!(
        grant.expires_at.is_none()
            && grant.wallet_ref.is_none()
            && grant.repo_bounds.is_none()
            && grant.verb_classes.is_empty()
            && grant.confers,
        "actor=named agent {owen:?}; expected a standing Grant with no expiry, wallet, repo bounds or classes; seen grant={grant:?}"
    );
    let reads_after = slip_reads(&fixture, &slip, &[base.as_str()]);
    assert_eq!(
        reads_after,
        vec![base.clone()],
        "actor=named agent {owen:?}; expected the default Grant to keep the slip's reach [{base}]; seen names={reads_after:?}"
    );
    let minted = grant_ids(&rows);

    let second = backfill(&fixture);
    assert_eq!(
        second,
        DefaultAgentGrantBackfill::AlreadyComplete,
        "actor=owner; expected a second call to run nothing"
    );
    let after_second = grant_ids(&grants_naming(&fixture.vault, owen));
    assert_eq!(
        after_second, minted,
        "actor=named agent {owen:?}; expected a second call to keep his one Grant"
    );

    let fixture = reopen(fixture);
    let after_reopen = backfill(&fixture);
    assert_eq!(
        after_reopen,
        DefaultAgentGrantBackfill::AlreadyComplete,
        "actor=owner; expected the marker to hold across a close and open"
    );
    let after_restart = grant_ids(&grants_naming(&fixture.vault, owen));
    assert_eq!(
        after_restart, minted,
        "actor=named agent {owen:?}; expected the reopened vault to keep his one Grant"
    );
}

/// Q2: yuki paired before Grants; the owner minted her a Grant, then
/// revoked it, so her slip reads nothing. The backfill mints her nothing,
/// and her slip still reads nothing (AGENT-REVOKE-WIDENS stays closed).
#[test]
fn backfill_does_not_restore_a_previously_revoked_grant() {
    let fixture = fixture(true);
    let base = fixture.base_path.clone();
    let yuki = fixture
        .vault
        .ensure_agent_principal("yuki")
        .expect("named agent principal");
    let slip = host_paired_agent_slip(&fixture, yuki, read_slip_scope(), SLIP_LIFETIME_SECS, 0x72);
    let slip = prove_possession(&fixture, &slip, 0x72);
    let mut authority_scope = Scope::top();
    authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let grant_ref = mint_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent: yuki,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
        },
    )
    .expect("owner mints yuki a base-world read Grant")
    .grant
    .grant_ref;
    let revoked = revoke_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref,
            seen: None,
        },
    )
    .expect("owner revokes yuki's Grant");
    assert!(
        revoked.changed,
        "grant={grant_ref:?}; expected the revoke to sign an act; seen {revoked:?}"
    );
    let reads_before = slip_reads(&fixture, &slip, &[base.as_str()]);
    assert!(
        reads_before.is_empty(),
        "actor=named agent {yuki:?}; expected no readable names after her last Grant's revoke; seen names={reads_before:?}"
    );

    let outcome = backfill(&fixture);
    assert_eq!(
        outcome,
        DefaultAgentGrantBackfill::Completed { grants: Vec::new() },
        "actor=owner; expected the backfill to complete with no mint for a holder a Grant once named"
    );
    let rows = grants_naming(&fixture.vault, yuki);
    assert!(
        rows.is_empty(),
        "actor=named agent {yuki:?}; expected no Grant back after the backfill; seen grants={rows:?}"
    );
    let reads_after = slip_reads(&fixture, &slip, &[base.as_str()]);
    assert!(
        reads_after.is_empty(),
        "actor=named agent {yuki:?}; expected her slip to read nothing after the backfill; seen names={reads_after:?}"
    );
}

/// Q5: on an install with no live machine profile the owner's act has no
/// carrier, so the backfill refuses: no Grant and no completion marker. Once
/// the profile is enrolled the next call runs and mints owen's Grant.
#[test]
fn failed_backfill_leaves_no_grants_or_completion_marker() {
    let fixture = fixture(false);
    let owen = fixture
        .vault
        .ensure_agent_principal("owen")
        .expect("named agent principal");
    let _slip = host_paired_agent_slip(&fixture, owen, read_slip_scope(), SLIP_LIFETIME_SECS, 0x73);

    let refused = fixture
        .vault
        .backfill_default_agent_grants(&fixture.owner_proof);
    assert!(
        refused.is_err(),
        "actor=owner; expected the backfill to refuse with no carrier for the owner's act; seen {refused:?}"
    );
    let rows = grants_naming(&fixture.vault, owen);
    assert!(
        rows.is_empty(),
        "actor=named agent {owen:?}; expected no Grant from a refused backfill; seen grants={rows:?}"
    );

    enrol_install_profile(&fixture.vault, &fixture.issuer);
    let retried = backfill(&fixture);
    let DefaultAgentGrantBackfill::Completed { grants } = &retried else {
        panic!(
            "actor=owner; expected the refused run to leave no completion marker, so the next call runs; seen {retried:?}"
        );
    };
    let rows = grants_naming(&fixture.vault, owen);
    assert_eq!(
        grant_ids(&rows),
        grants.iter().copied().collect::<BTreeSet<_>>(),
        "actor=named agent {owen:?}; expected the retried backfill to mint his one Grant; seen outcome={retried:?} rows={rows:?}"
    );
    assert_eq!(rows.len(), 1, "seen grants={rows:?}");
}

/// Q4: a revoked slip, an expired slip, a slip with no read verb (an
/// artifact backend's shape), an agent-class slip held by an agent
/// definition and one held by the owner's own PERSON mint nothing; owen's
/// live read slip beside them mints his Grant.
#[test]
fn backfill_skips_dead_slips_and_non_named_principals() {
    let fixture = fixture(true);
    let named = |name: &str| {
        fixture
            .vault
            .ensure_agent_principal(name)
            .expect("named agent principal")
    };
    let revoked_holder = named("owen_revoked_slip");
    let revoked = host_paired_agent_slip(
        &fixture,
        revoked_holder,
        read_slip_scope(),
        SLIP_LIFETIME_SECS,
        0x81,
    );
    let revoked = prove_possession(&fixture, &revoked, 0x81);
    fixture
        .vault
        .revoke_capability_slip(&fixture.issuer, revoked.claims().slip_id)
        .expect("host revokes the slip");
    let expired_holder = named("owen_expired_slip");
    let _expired = host_paired_agent_slip(&fixture, expired_holder, read_slip_scope(), 1, 0x82);
    let backend = named("yuki_backend");
    let mut no_verbs = Scope::top();
    no_verbs.verbs = ScopeAxis::Some(BTreeSet::new());
    let _backend_slip =
        host_paired_agent_slip(&fixture, backend, no_verbs, SLIP_LIFETIME_SECS, 0x83);
    let definition = EntityId::now();
    create_agent_definition_as(
        &fixture.vault,
        &fixture.owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: definition,
            definition: serde_json::from_value(json!({
                "agent_id": "backfill_definition",
                "desc": "Backfill control: an agent definition",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates an enabled, active agent definition");
    let _definition_slip = host_paired_agent_slip(
        &fixture,
        definition,
        read_slip_scope(),
        SLIP_LIFETIME_SECS,
        0x84,
    );
    let owner = fixture.owner;
    let _owner_slip =
        host_paired_agent_slip(&fixture, owner, read_slip_scope(), SLIP_LIFETIME_SECS, 0x85);
    let owen = named("owen");
    let _owen_slip =
        host_paired_agent_slip(&fixture, owen, read_slip_scope(), SLIP_LIFETIME_SECS, 0x86);
    // The expired slip's one-second lifetime has passed on the vault clock.
    std::thread::sleep(Duration::from_secs(3));

    let outcome = backfill(&fixture);
    let DefaultAgentGrantBackfill::Completed { grants } = &outcome else {
        panic!("actor=owner; expected the backfill to complete; seen {outcome:?}");
    };
    let owen_rows = grants_naming(&fixture.vault, owen);
    assert_eq!(
        grant_ids(&owen_rows),
        grants.iter().copied().collect::<BTreeSet<_>>(),
        "actor=owner; expected owen's Grant to be the only one minted; seen outcome={outcome:?} rows={owen_rows:?}"
    );
    assert_eq!(owen_rows.len(), 1, "seen grants={owen_rows:?}");
    for (label, holder) in [
        ("revoked slip", revoked_holder),
        ("expired slip", expired_holder),
        ("slip with no read verb", backend),
        ("agent definition", definition),
        ("owner's PERSON", owner),
    ] {
        let rows = grants_naming(&fixture.vault, holder);
        assert!(
            rows.is_empty(),
            "actor={label} {holder:?}; expected no Grant from the backfill; seen grants={rows:?}"
        );
    }
}

/// Q3: a holder with live slips of two Scopes gets one default Grant for
/// each; a third slip whose Scope differs only in its verbs shares the
/// first one's Grant.
#[test]
fn backfill_mints_one_grant_per_distinct_slip_scope() {
    let fixture = fixture(true);
    let owen = fixture
        .vault
        .ensure_agent_principal("owen")
        .expect("named agent principal");
    let every_world = read_slip_scope();
    let mut base_world = read_slip_scope();
    base_world.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    let mut every_world_more_verbs = read_slip_scope();
    every_world_more_verbs.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:propose".to_owned(),
    ]));
    for (seed, scope) in [
        (0x91, every_world.clone()),
        (0x92, base_world.clone()),
        (0x93, every_world_more_verbs),
    ] {
        let _slip = host_paired_agent_slip(&fixture, owen, scope, SLIP_LIFETIME_SECS, seed);
    }

    let outcome = backfill(&fixture);
    let DefaultAgentGrantBackfill::Completed { grants } = &outcome else {
        panic!("actor=owner; expected the backfill to complete; seen {outcome:?}");
    };
    let rows = grants_naming(&fixture.vault, owen);
    assert_eq!(
        grant_ids(&rows),
        grants.iter().copied().collect::<BTreeSet<_>>(),
        "actor=owner; expected the backfill to report the Grants it minted; seen outcome={outcome:?} rows={rows:?}"
    );
    let mut scopes: Vec<Scope> = rows.iter().filter_map(|row| row.scope.clone()).collect();
    let expected = [
        default_grant_scope(&every_world),
        default_grant_scope(&base_world),
    ];
    assert_eq!(
        scopes.len(),
        expected.len(),
        "actor=named agent {owen:?}; expected one Grant per distinct Scope; seen grants={rows:?}"
    );
    for scope in expected {
        let at = scopes.iter().position(|seen| *seen == scope);
        assert!(
            at.is_some(),
            "actor=named agent {owen:?}; expected a default Grant at {scope:?}; seen grants={rows:?}"
        );
        if let Some(at) = at {
            scopes.remove(at);
        }
    }
}

/// Q6: a vault that is not self-hosted runs nothing: the operator of a
/// hosted vault acts as nobody inside it (cross-arch-0024:136).
#[test]
fn backfill_skips_a_vault_that_is_not_self_hosted() {
    let self_hosted = fixture(true);
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    let hosted = Vault::open(dir.path(), config).expect("hosted vault");
    let outcome = hosted
        .backfill_default_agent_grants(&self_hosted.owner_proof)
        .expect("the backfill answers on a hosted vault");
    assert_eq!(
        outcome,
        DefaultAgentGrantBackfill::NotSelfHosted,
        "actor=hosted vault; expected the backfill to run nothing"
    );
}
