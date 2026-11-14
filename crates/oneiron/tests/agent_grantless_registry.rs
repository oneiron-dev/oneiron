//! The owner's registry lists each live slip of a named agent that no Grant
//! has ever named, and `vault.agents.grants.from_slip` converts one into its
//! holder's default read Grants (FIX AGENT-GRANTLESS-VISIBLE, PR B; Engine
//! RULING GRANTLESS-SHAPE Q8/Q9 = A, 12 Nov 03:02). The list is additive: a
//! registry with no such slip serializes as before. A converted, revoked,
//! dead or ineligible slip mints nothing, and a repeat never mints twice.
//!
//! The conversion widens an agent's grant (ROLES-CHECKIN 2k7; Engine RULING
//! P25-SHAPE Q1 = A): the owner's own conversion records his own proof once
//! in the answer, and he applies another asker's approved check-in for one
//! slip's conversion, spent in the writer that mints. On 2k7a's head the
//! two tests for it do not build: the request has no `check_in_ref`, and
//! the answer no `check_in`.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test agent_grantless_registry`.
#![cfg(oneiron_test_support)]

#[allow(dead_code)]
#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActSurface, CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip,
};
use oneiron::check_in::{ActClass, agent_grant_from_slip_effect_digest};
use oneiron::claim::{ScopedReadActorKey, base_world_id, default_project_id};
use oneiron::consent::{
    AuthenticatedOwner, ConsentRegistry, ConsentRegistryQuery, ConsentRegistryRow,
    GrantlessAgentRow,
};
use oneiron::federation::{
    AgentGrantFromSlipUnchangedReason, DefaultAgentGrantBackfill, Scope, ScopeAxis, ScopeId,
};
use oneiron::graph_fs::GraphFsOptions;
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentGrantFromSlipOutcome, AgentGrantFromSlipRequest, AgentGrantMinted,
    AgentGrantRevokeRequest, mint_agent_grants_from_slip_as, revoke_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use owner_apply_fixture::{approved, owner_decision, spent};
use serde_json::json;

const OCCURRED_AT: u64 = 1_769_947_200;
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:agent-grantless-registry";
const SLIP_LIFETIME_SECS: u64 = 3_600;
const FROM_SLIP_COMMAND: &str = "vault.agents.grants.from_slip";

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    /// The graph path of the owner's base-world claim.
    base_path: String,
}

/// A self-hosted vault with this install's engine machines and live machine
/// profile (it carries the owner's acts), where the owner has written one
/// base-world claim.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let keystore = Arc::new(MemoryKeystore::default());
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(keystore);
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let claim = write_owner_claim(&vault, owner, &owner_proof);
    Fixture {
        vault,
        _dir: dir,
        issuer,
        owner,
        owner_proof,
        base_path: format!("/worlds/base/claims/{}", claim.to_hex()),
    }
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

/// [`read_slip_scope`] narrowed to the base world.
fn base_world_slip_scope() -> Scope {
    let mut scope = read_slip_scope();
    scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
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
/// proof, as every agent paired before Grants did, redeems it with the key
/// `binding_seed` derives, and proves possession. No Grant is minted.
fn host_paired_agent_slip(
    fixture: &Fixture,
    holder: EntityId,
    scope: Scope,
    binding_seed: u8,
) -> VerifiedSlip {
    let holder_ref = holder.to_hex();
    let link = fixture
        .vault
        .issue_pairing_link_for_principal(
            &fixture.issuer,
            scope,
            SLIP_LIFETIME_SECS,
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
    let slip = fixture
        .vault
        .redeem_pairing_link(
            &fixture.issuer,
            &link.code,
            &holder_ref,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )
        .expect("agent redeems its pairing link");
    prove_possession(fixture, &slip, binding_seed)
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

fn slip_ref(slip: &VerifiedSlip) -> String {
    slip.claims()
        .slip_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn registry(vault: &Vault) -> ConsentRegistry {
    vault
        .consent_registry(ConsentRegistryQuery::new(1_000, false))
        .expect("owner's consent registry")
}

/// The registry's grantless rows that name `holder`.
fn grantless_naming(vault: &Vault, holder: EntityId) -> Vec<GrantlessAgentRow> {
    registry(vault)
        .grantless_agents
        .into_iter()
        .filter(|row| row.holder == holder)
        .collect()
}

/// The live owner-agent Grant rows of the registry that name `holder`.
fn grants_naming(vault: &Vault, holder: EntityId) -> Vec<ConsentRegistryRow> {
    registry(vault)
        .rows
        .into_iter()
        .filter(|row| {
            row.agent_grant
                .as_ref()
                .is_some_and(|grant| grant.agent == holder)
        })
        .collect()
}

/// The paths of `paths` a fresh read key for `slip` reads; none when the
/// slip grants no read key at all.
fn slip_reads(fixture: &Fixture, slip: &VerifiedSlip, paths: &[&str]) -> Vec<String> {
    let Some(key) = fixture
        .vault
        .credential_read_key(slip)
        .expect("agent credential read key")
    else {
        return Vec::new();
    };
    readable(&fixture.vault, key, paths)
}

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

fn convert(fixture: &Fixture, slip_ref: &str) -> AgentGrantFromSlipOutcome {
    mint_agent_grants_from_slip_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantFromSlipRequest {
            slip_ref: slip_ref.to_owned(),
            check_in_ref: None,
        },
    )
    .expect("the owner's conversion answers")
}

fn minted_grants(outcome: &AgentGrantFromSlipOutcome) -> &[AgentGrantMinted] {
    match outcome {
        AgentGrantFromSlipOutcome::Minted { grants, .. } => grants,
        AgentGrantFromSlipOutcome::Unchanged { reason } => {
            panic!("actor=owner; expected the conversion to mint; seen unchanged reason={reason:?}")
        }
    }
}

/// Q8: a registry with no grantless slip serializes with no
/// `grantless_agents` key. Once owen pairs on a host link with no Grant, the
/// registry lists his live slip with its logged reach, no Grant id and no
/// revoke, and his conversion. Dead, ineligible and non-named slips are not
/// listed. After the serve-start backfill mints his Grant, the list is
/// empty.
#[test]
fn registry_lists_a_never_granted_agent_slip_with_its_reach() {
    let fixture = fixture();
    let before = serde_json::to_value(registry(&fixture.vault)).expect("registry JSON");
    assert!(
        before.get("grantless_agents").is_none(),
        "actor=owner; expected no grantless_agents key with no grantless slip; seen registry={before}"
    );

    let owen = fixture
        .vault
        .ensure_agent_principal("owen")
        .expect("named agent principal");
    let slip = host_paired_agent_slip(&fixture, owen, read_slip_scope(), 0x61);
    let revoked_holder = fixture
        .vault
        .ensure_agent_principal("owen_revoked_slip")
        .expect("named agent principal");
    let revoked = host_paired_agent_slip(&fixture, revoked_holder, read_slip_scope(), 0x62);
    fixture
        .vault
        .revoke_capability_slip(&fixture.issuer, revoked.claims().slip_id)
        .expect("host revokes the slip");
    let backend = fixture
        .vault
        .ensure_agent_principal("yuki_backend")
        .expect("named agent principal");
    let mut no_verbs = Scope::top();
    no_verbs.verbs = ScopeAxis::Some(BTreeSet::new());
    let _backend_slip = host_paired_agent_slip(&fixture, backend, no_verbs, 0x63);
    let owner = fixture.owner;
    let _owner_slip = host_paired_agent_slip(&fixture, owner, read_slip_scope(), 0x64);

    let listed = registry(&fixture.vault).grantless_agents;
    let claims = slip.claims();
    let expected = GrantlessAgentRow {
        holder: owen,
        slip_ref: slip_ref(&slip),
        issued_at: claims.issued_at,
        expires_at: claims.expires_at,
        scope: read_slip_scope(),
        records: claims.records.clone(),
        channels: claims.channels.clone(),
        comm: claims.comm.clone(),
        convert_action: oneiron::consent::GrantlessAgentConvertAction {
            command: FROM_SLIP_COMMAND.to_owned(),
            slip_ref: slip_ref(&slip),
        },
    };
    assert_eq!(
        listed,
        vec![expected],
        "actor=owner; expected only owen's live read slip listed, with its logged reach and conversion"
    );
    let owen_grants = grants_naming(&fixture.vault, owen);
    assert!(
        owen_grants.is_empty(),
        "actor=named agent {owen:?}; expected no Grant row naming him; seen grants={owen_grants:?}"
    );
    let listed_json = serde_json::to_value(registry(&fixture.vault)).expect("registry JSON");
    let row_json = &listed_json["grantless_agents"][0];
    assert!(
        row_json.get("revoke_action").is_none() && row_json.get("grant_ref").is_none(),
        "actor=owner; expected the grantless row to carry no Grant id and no revoke; seen row={row_json}"
    );

    let outcome = fixture
        .vault
        .backfill_default_agent_grants(&fixture.owner_proof)
        .expect("the serve-start backfill runs");
    assert!(
        matches!(outcome, DefaultAgentGrantBackfill::Completed { ref grants } if grants.len() == 1),
        "actor=owner; expected the backfill to mint owen's one Grant; seen {outcome:?}"
    );
    let after = registry(&fixture.vault).grantless_agents;
    assert!(
        after.is_empty(),
        "actor=owner; expected the list empty once a counted mint names owen; seen {after:?}"
    );
}

/// Q9: the owner converts owen's listed slip. One default read Grant
/// (verbs `read`, the slip's other axes, no expiry, wallet, repo bounds or
/// classes) names him, his row leaves the list and his reach is unchanged.
/// Revoking that Grant leaves his slip reading nothing and lists no row
/// again.
#[test]
fn owner_converts_a_grantless_slip_to_its_default_read_grant() {
    let fixture = fixture();
    let base = fixture.base_path.clone();
    let owen = fixture
        .vault
        .ensure_agent_principal("owen")
        .expect("named agent principal");
    let slip = host_paired_agent_slip(&fixture, owen, read_slip_scope(), 0x65);
    let reads_before = slip_reads(&fixture, &slip, &[base.as_str()]);
    assert_eq!(
        reads_before,
        vec![base.clone()],
        "actor=named agent {owen:?}; expected the never-granted slip to read [{base}]; seen names={reads_before:?}"
    );
    let row = grantless_naming(&fixture.vault, owen);
    assert_eq!(row.len(), 1, "seen grantless rows={row:?}");

    let outcome = convert(&fixture, &row[0].convert_action.slip_ref);
    let grants = minted_grants(&outcome);
    assert_eq!(
        grants.len(),
        1,
        "actor=owner; expected one Grant for one Scope; seen {outcome:?}"
    );
    let grant = &grants[0].grant;
    assert!(
        grant.agent == owen
            && grant.authority_scope == default_grant_scope(&read_slip_scope())
            && grant.expires_at.is_none()
            && grant.wallet_ref.is_none()
            && grant.repo_bounds.is_none()
            && grant.verb_classes.is_empty()
            && grant.confers,
        "actor=named agent {owen:?}; expected his default read Grant at the slip's axes; seen grant={grant:?}"
    );
    let rows = grants_naming(&fixture.vault, owen);
    let ids: BTreeSet<EntityId> = rows
        .iter()
        .map(|row| EntityId::from_hex(&row.grant_ref).expect("Grant id hex"))
        .collect();
    assert_eq!(
        ids,
        BTreeSet::from([grant.grant_ref]),
        "actor=owner; expected the registry to show the Grant the conversion minted; seen rows={rows:?}"
    );
    let listed = grantless_naming(&fixture.vault, owen);
    assert!(
        listed.is_empty(),
        "actor=owner; expected owen's row to leave the list; seen {listed:?}"
    );
    let reads_after = slip_reads(&fixture, &slip, &[base.as_str()]);
    assert_eq!(
        reads_after,
        vec![base.clone()],
        "actor=named agent {owen:?}; expected the Grant to keep the slip's reach [{base}]; seen names={reads_after:?}"
    );

    let revoked = revoke_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref: grant.grant_ref,
            seen: None,
        },
    )
    .expect("owner revokes owen's Grant");
    assert!(revoked.changed, "seen {revoked:?}");
    let reads_revoked = slip_reads(&fixture, &slip, &[base.as_str()]);
    assert!(
        reads_revoked.is_empty(),
        "actor=named agent {owen:?}; expected his slip to read nothing once his Grant is revoked; seen names={reads_revoked:?}"
    );
    let relisted = grantless_naming(&fixture.vault, owen);
    assert!(
        relisted.is_empty(),
        "actor=owner; expected no row for a holder a Grant once named; seen {relisted:?}"
    );
}

/// Q9: a converted slip converts again to `already_granted`; a revoked slip
/// to `slip_not_live`; a slip with no read verb to `not_eligible`. None of
/// them mints. An id that names no slip and a malformed id are refused.
#[test]
fn conversion_answers_unchanged_and_never_mints_twice() {
    let fixture = fixture();
    let owen = fixture
        .vault
        .ensure_agent_principal("owen")
        .expect("named agent principal");
    let slip = host_paired_agent_slip(&fixture, owen, read_slip_scope(), 0x66);
    let first = convert(&fixture, &slip_ref(&slip));
    let minted: BTreeSet<EntityId> = minted_grants(&first)
        .iter()
        .map(|minted| minted.grant.grant_ref)
        .collect();
    let again = convert(&fixture, &slip_ref(&slip));
    assert_eq!(
        again,
        AgentGrantFromSlipOutcome::Unchanged {
            reason: AgentGrantFromSlipUnchangedReason::AlreadyGranted,
        },
        "actor=owner; expected a repeat to mint nothing"
    );
    let after_again: BTreeSet<EntityId> = grants_naming(&fixture.vault, owen)
        .iter()
        .map(|row| EntityId::from_hex(&row.grant_ref).expect("Grant id hex"))
        .collect();
    assert_eq!(
        after_again, minted,
        "actor=named agent {owen:?}; expected a repeat to keep his one Grant"
    );

    let yuki = fixture
        .vault
        .ensure_agent_principal("yuki")
        .expect("named agent principal");
    let revoked = host_paired_agent_slip(&fixture, yuki, read_slip_scope(), 0x67);
    fixture
        .vault
        .revoke_capability_slip(&fixture.issuer, revoked.claims().slip_id)
        .expect("host revokes the slip");
    let backend = fixture
        .vault
        .ensure_agent_principal("yuki_backend")
        .expect("named agent principal");
    let mut no_verbs = Scope::top();
    no_verbs.verbs = ScopeAxis::Some(BTreeSet::new());
    let backend_slip = host_paired_agent_slip(&fixture, backend, no_verbs, 0x68);
    for (label, holder, slip, reason) in [
        (
            "revoked slip",
            yuki,
            &revoked,
            AgentGrantFromSlipUnchangedReason::SlipNotLive,
        ),
        (
            "slip with no read verb",
            backend,
            &backend_slip,
            AgentGrantFromSlipUnchangedReason::NotEligible,
        ),
    ] {
        let outcome = convert(&fixture, &slip_ref(slip));
        assert_eq!(
            outcome,
            AgentGrantFromSlipOutcome::Unchanged { reason },
            "actor={label} {holder:?}; expected the conversion to mint nothing"
        );
        let rows = grants_naming(&fixture.vault, holder);
        assert!(
            rows.is_empty(),
            "actor={label} {holder:?}; expected no Grant; seen grants={rows:?}"
        );
    }

    for (label, slip_ref) in [
        ("an id no slip has", "ab".repeat(32)),
        ("a malformed id", "not hex".to_owned()),
    ] {
        let refused = mint_agent_grants_from_slip_as(
            &fixture.vault,
            &fixture.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantFromSlipRequest {
                slip_ref,
                check_in_ref: None,
            },
        );
        assert!(
            refused.is_err(),
            "actor=owner; expected {label} to be refused; seen {refused:?}"
        );
    }
}

/// Q9 with Q3: owen holds live slips of two Scopes. The registry lists both.
/// Converting one mints his default Grant for each distinct Scope, the named
/// slip's first, so neither slip reads less, and both rows leave the list.
#[test]
fn conversion_mints_one_grant_per_distinct_scope_of_the_holder() {
    let fixture = fixture();
    let owen = fixture
        .vault
        .ensure_agent_principal("owen")
        .expect("named agent principal");
    let every_world = host_paired_agent_slip(&fixture, owen, read_slip_scope(), 0x69);
    let base_world = host_paired_agent_slip(&fixture, owen, base_world_slip_scope(), 0x6a);
    let listed: BTreeSet<String> = grantless_naming(&fixture.vault, owen)
        .into_iter()
        .map(|row| row.slip_ref)
        .collect();
    assert_eq!(
        listed,
        BTreeSet::from([slip_ref(&every_world), slip_ref(&base_world)]),
        "actor=owner; expected both of owen's live slips listed"
    );

    let outcome = convert(&fixture, &slip_ref(&base_world));
    let scopes: Vec<Scope> = minted_grants(&outcome)
        .iter()
        .map(|minted| minted.grant.authority_scope.clone())
        .collect();
    assert_eq!(
        scopes,
        vec![
            default_grant_scope(&base_world_slip_scope()),
            default_grant_scope(&read_slip_scope()),
        ],
        "actor=named agent {owen:?}; expected the named slip's Grant first, then one for his other Scope"
    );
    let rows = grants_naming(&fixture.vault, owen);
    assert_eq!(rows.len(), 2, "seen grants={rows:?}");
    let left = grantless_naming(&fixture.vault, owen);
    assert!(
        left.is_empty(),
        "actor=owner; expected both of owen's rows to leave the list; seen {left:?}"
    );
}

/// ROLES-CHECKIN 2k7: the owner's own conversion goes on his own proof, and
/// the answer records that decision once, not on each Grant.
#[test]
fn the_owners_conversion_records_his_own_proof_once() {
    let fixture = fixture();
    let owen = fixture
        .vault
        .ensure_agent_principal("owen")
        .expect("named agent principal");
    let slip = host_paired_agent_slip(&fixture, owen, read_slip_scope(), 0x71);

    let AgentGrantFromSlipOutcome::Minted { grants, check_in } =
        convert(&fixture, &slip_ref(&slip))
    else {
        panic!("actor=owner; expected the conversion to mint");
    };
    assert_eq!(grants.len(), 1, "seen grants={grants:?}");
    assert!(
        grants.iter().all(|minted| minted.check_in.is_none()),
        "actor=owner; expected the decision named once, on the answer; seen {grants:?}"
    );
    assert_eq!(
        check_in,
        Some(owner_decision(ActClass::GrantWiden, None, None)),
        "actor=owner; expected the conversion to record his own proof"
    );
}

/// ROLES-CHECKIN 2k7: the owner applies another asker's approved check-in
/// for converting owen's slip. Applied to yuki's slip it mints nothing and
/// stays unspent; applied to owen's, the writer that mints spends it, and
/// the answer names it and its asker.
#[test]
fn the_owner_applies_an_approved_ask_to_convert_that_slip_only() {
    let fixture = fixture();
    let [owen, yuki] = ["owen", "yuki"].map(|name| {
        fixture
            .vault
            .ensure_agent_principal(name)
            .expect("named agent principal")
    });
    let owen_slip = host_paired_agent_slip(&fixture, owen, read_slip_scope(), 0x71);
    let yuki_slip = host_paired_agent_slip(&fixture, yuki, read_slip_scope(), 0x72);
    let (check_in, asker) = approved(
        &fixture.vault,
        fixture.owner,
        &fixture.owner_proof,
        FROM_SLIP_COMMAND,
        ActClass::GrantWiden,
        &agent_grant_from_slip_effect_digest(&owen_slip.claims().slip_id),
    );
    let apply = |slip: &VerifiedSlip| {
        mint_agent_grants_from_slip_as(
            &fixture.vault,
            &fixture.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantFromSlipRequest {
                slip_ref: slip_ref(slip),
                check_in_ref: Some(check_in.to_hex()),
            },
        )
    };

    let refused = apply(&yuki_slip);
    assert!(
        refused.is_err(),
        "actor=owner; expected the approval for owen's slip to refuse yuki's; seen {refused:?}"
    );
    let rows = grants_naming(&fixture.vault, yuki);
    assert!(
        rows.is_empty(),
        "actor=owner; expected no Grant for yuki; seen {rows:?}"
    );
    assert!(
        !spent(&fixture.vault, &check_in),
        "a refused conversion leaves the check-in unspent"
    );

    let AgentGrantFromSlipOutcome::Minted {
        grants,
        check_in: decision,
    } = apply(&owen_slip).expect("the owner applies the approved ask")
    else {
        panic!("actor=owner; expected owen's conversion to mint");
    };
    assert_eq!(grants.len(), 1, "seen grants={grants:?}");
    assert!(
        spent(&fixture.vault, &check_in),
        "the conversion spent the check-in"
    );
    assert_eq!(
        decision,
        Some(owner_decision(
            ActClass::GrantWiden,
            Some(check_in),
            Some(asker)
        )),
        "actor=owner; expected the answer to name the check-in and its asker"
    );
}
