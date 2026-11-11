//! `vault.assets.masked_read`: an agent with an ordinary read permit but no Grant is
//! refused, the holder reads its lane's repo ASSET always masked with no secret bytes
//! left, and a revoked Grant is refused again. An ASSET outside the lane answers none.
//! The verb is called by name through the string-keyed embedded door, and the output
//! is read as JSON, so this file uses no item the row adds.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test verb_vault_assets_masked_read`
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::Engine as _;
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::authority::{ActSurface, MachineRole};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError};
use oneiron::registry::ENTITY_TYPE_ASSET;
use oneiron::secret_custody::{
    CustodyClass, CustodyTier, OwnerSecretRegistration, RequestedBinding,
};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    AgentGrantMintRequest, AgentGrantRevokeRequest, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EdgeActorClass, EdgeKind, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor,
};
use serde_json::{Value, json};

const MASKED_ASSET_READ_TEST_NOW: u64 = 1_700_000_000;
const MASKED_ASSET_READ_TEST_VERB: &str = "vault.assets.masked_read";

// Fixture ids are `[seed; 16]`, in the batch's `0x70..=0x7F` range, off the
// pinned bytes a fresh vault holds.
const MASKED_ASSET_READ_AGENT: u8 = 0x70;
const MASKED_ASSET_READ_GRANTLESS: u8 = 0x71;

// A plain custody value no detector names: the write stores it raw, and the
// read masks it as a value custody knows.
const MASKED_ASSET_READ_SECRET: &str = "masked-asset-read-fixture-value-7f3a9c1e";
const MASKED_ASSET_READ_EXCLUDED_BODY: &str = "excluded world asset body without secrets";

/// An enabled, active agent definition the owner creates as `name`.
fn masked_asset_read_definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "masked asset read fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}

/// The repo snapshot ASSET id for `content_hash`, the BLAKE3 of the body's own
/// bytes: the domain-separated derivation the engine's codebase id uses, so the
/// row this fixture puts is a repo file the masked read projects.
fn masked_asset_read_asset_id(content_hash: &[u8; 32]) -> EntityId {
    const MASKED_ASSET_READ_ID_DOMAIN: &[u8] = b"oneiron:codebase-asset-entity:v1";
    for salt in 0_u64..=u64::MAX {
        let mut hasher = blake3::Hasher::new();
        hasher.update(MASKED_ASSET_READ_ID_DOMAIN);
        hasher.update(&salt.to_le_bytes());
        hasher.update(&(content_hash.len() as u64).to_le_bytes());
        hasher.update(content_hash);
        let digest = hasher.finalize();
        let mut id = [0_u8; 16];
        id.copy_from_slice(&digest.as_bytes()[..16]);
        if let Ok(id) = EntityId::from_bytes(id) {
            return id;
        }
    }
    unreachable!("codebase asset id derivation exhausted its salt space");
}

struct MaskedAssetReadFixture {
    vault: Vault,
    owner: EntityId,
    holder: EntityId,
    grantless: EntityId,
    base_asset: EntityId,
    excluded_asset: EntityId,
    _dir: tempfile::TempDir,
}

fn masked_asset_read_fixture() -> MaskedAssetReadFixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let holder = EntityId::from_bytes([MASKED_ASSET_READ_AGENT; 16]).expect("holder id");
    vault
        .create_agent_definition_as(
            &owner_proof,
            &holder,
            &masked_asset_read_definition("kiran"),
            TimeRange {
                start: MASKED_ASSET_READ_TEST_NOW,
                end: MASKED_ASSET_READ_TEST_NOW,
            },
            MASKED_ASSET_READ_TEST_NOW,
        )
        .expect("owner creates the holder");
    let grantless = EntityId::from_bytes([MASKED_ASSET_READ_GRANTLESS; 16]).expect("grantless id");
    vault
        .create_agent_definition_as(
            &owner_proof,
            &grantless,
            &masked_asset_read_definition("selin"),
            TimeRange {
                start: MASKED_ASSET_READ_TEST_NOW,
                end: MASKED_ASSET_READ_TEST_NOW,
            },
            MASKED_ASSET_READ_TEST_NOW,
        )
        .expect("owner creates the grantless agent");
    // The grantless agent alone takes an ordinary read permit, once: its rows
    // read under today's policy admission, but with no Grant naming the verb
    // the verb's own Grant check still refuses it. The holder takes no permit,
    // so its lane admits only what its live Grant covers, world-limited.
    vault
        .install_read_permits_for_test(&[WriteActor::new(grantless, EdgeActorClass::Agent)])
        .expect("owner installs the grantless read permit");
    let other_world = vault
        .create_world(&owner_proof, "Excluded world", MASKED_ASSET_READ_TEST_NOW)
        .expect("owner creates the second world");
    // Both ASSETs are put before custody knows the value, so the secret body
    // is stored raw and only the read masks it. The base ASSET takes no world
    // edge, so it sits in base reality alone; the excluded one is edged into
    // the other world.
    let secret_body = format!(
        "staging deploy uses {} for access",
        MASKED_ASSET_READ_SECRET
    );
    let base_asset = masked_asset_read_asset_id(blake3::hash(secret_body.as_bytes()).as_bytes());
    vault
        .put_entity(
            &base_asset,
            ENTITY_TYPE_ASSET,
            TimeRange {
                start: MASKED_ASSET_READ_TEST_NOW,
                end: MASKED_ASSET_READ_TEST_NOW,
            },
            MASKED_ASSET_READ_TEST_NOW,
            secret_body.as_bytes(),
        )
        .expect("owner stores the secret repo asset");
    let excluded_asset = masked_asset_read_asset_id(
        blake3::hash(MASKED_ASSET_READ_EXCLUDED_BODY.as_bytes()).as_bytes(),
    );
    vault
        .batch()
        .put(
            &excluded_asset,
            ENTITY_TYPE_ASSET,
            TimeRange {
                start: MASKED_ASSET_READ_TEST_NOW,
                end: MASKED_ASSET_READ_TEST_NOW,
            },
            MASKED_ASSET_READ_TEST_NOW,
            MASKED_ASSET_READ_EXCLUDED_BODY.as_bytes(),
        )
        .edge(&excluded_asset, EdgeKind::InWorld, &other_world, 0.7)
        .commit()
        .expect("owner stores the excluded repo asset in its world");
    vault
        .register_secret_as_owner(
            &owner_proof,
            &OwnerSecretRegistration {
                name: "masked-asset-read-fixture",
                class: CustodyClass::CustodyPortable,
                device_only: false,
                rung: CustodyTier::T1Leased,
                bindings: vec![RequestedBinding {
                    effector: "deploy".to_owned(),
                    tier_ceiling: None,
                    scopes: vec!["read".to_owned()],
                }],
                manifest: None,
                value: MASKED_ASSET_READ_SECRET.as_bytes(),
            },
            MASKED_ASSET_READ_TEST_NOW,
        )
        .expect("owner registers the fixture secret");
    MaskedAssetReadFixture {
        vault,
        owner,
        holder,
        grantless,
        base_asset,
        excluded_asset,
        _dir: dir,
    }
}

/// The owner grants `agent` the base world with `read` and this verb, rooted
/// and enrolled first as a serving start does. Returns the grant's row.
fn masked_asset_read_mint_lane_grant(
    fixture: &MaskedAssetReadFixture,
    agent: EntityId,
) -> EntityId {
    let issuer = fixture
        .vault
        .bootstrap_host_slip_issuer()
        .expect("host issuer");
    fixture
        .vault
        .ensure_host_root_slip(&issuer)
        .expect("host root");
    fixture
        .vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("install carries the owner's grant act");
    let owner_proof = fixture
        .vault
        .authenticate_owner(
            fixture.owner,
            &fixture.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let mut authority_scope = Scope::top();
    authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "read".to_owned(),
        MASKED_ASSET_READ_TEST_VERB.to_owned(),
    ]));
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
        },
    )
    .expect("owner mints the masked asset grant");
    assert!(minted.grant.confers, "the grant confers");
    minted.grant.grant_ref
}

fn masked_asset_read_revoke_grant(fixture: &MaskedAssetReadFixture, grant_ref: EntityId) {
    let owner_proof = fixture
        .vault
        .authenticate_owner(
            fixture.owner,
            &fixture.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let revoked = revoke_agent_grant_as(
        &fixture.vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref,
            seen: None,
        },
    )
    .expect("owner revokes the grant");
    assert!(revoked.changed, "the revoke lands");
}

fn masked_asset_read_call(memory: &Memory<'_>, entity_ref: &str) -> Result<Value, MemoryError> {
    oneiron::task_verb::sdk::invoke(
        memory,
        MASKED_ASSET_READ_TEST_VERB,
        json!({ "entity_ref": entity_ref }),
    )
}

#[test]
fn masked_asset_read_agent_with_no_grant_is_refused() {
    let fixture = masked_asset_read_fixture();
    let memory = fixture
        .vault
        .memory(fixture.grantless, EdgeActorClass::Agent);
    let error = masked_asset_read_call(&memory, &fixture.base_asset.to_hex())
        .expect_err("a read-permitted agent with no grant is refused");
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "a no-grant refusal names FORBIDDEN, not the unknown-verb code; got {}: {}",
        error.code, error.message,
    );
    assert!(
        error.message.contains(MASKED_ASSET_READ_TEST_VERB),
        "the refusal names the verb; got {}",
        error.message,
    );
}

#[test]
fn masked_asset_read_holder_reads_masked_body_and_not_excluded_asset() {
    let fixture = masked_asset_read_fixture();
    masked_asset_read_mint_lane_grant(&fixture, fixture.holder);
    let memory = fixture.vault.memory(fixture.holder, EdgeActorClass::Agent);
    let out = masked_asset_read_call(&memory, &fixture.base_asset.to_hex())
        .expect("the holder reads its lane");
    let served = out
        .get("value")
        .and_then(Value::as_object)
        .expect("the value is the masked asset");
    assert_eq!(
        served.get("entity_ref").and_then(Value::as_str),
        Some(fixture.base_asset.to_hex()).as_deref(),
        "the served ref is the base asset; got {served:?}",
    );
    let encoded = served
        .get("body_base64")
        .and_then(Value::as_str)
        .expect("the served body is base64");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("standard base64 decodes");
    let secret = MASKED_ASSET_READ_SECRET.as_bytes();
    assert!(
        !decoded.windows(secret.len()).any(|window| window == secret),
        "the decoded body holds no secret bytes",
    );
    assert!(
        out.get("narrowing").and_then(Value::as_object).is_some(),
        "the read keeps its narrowing receipt; got {out}",
    );
    let excluded = masked_asset_read_call(&memory, &fixture.excluded_asset.to_hex())
        .expect("the excluded asset answers");
    assert!(
        excluded.get("value").is_some_and(Value::is_null),
        "the row outside the lane is withheld as none; got {excluded}",
    );
    assert!(
        excluded
            .get("narrowing")
            .and_then(Value::as_object)
            .is_some(),
        "the withheld read keeps its narrowing receipt; got {excluded}",
    );
}

#[test]
fn masked_asset_read_revoked_grant_is_refused_again() {
    let fixture = masked_asset_read_fixture();
    let grant_ref = masked_asset_read_mint_lane_grant(&fixture, fixture.holder);
    let memory = fixture.vault.memory(fixture.holder, EdgeActorClass::Agent);
    let before = masked_asset_read_call(&memory, &fixture.base_asset.to_hex())
        .expect("the holder reads before the revoke");
    assert!(
        before.get("value").and_then(Value::as_object).is_some(),
        "the pre-revoke read holds the row; got {before}",
    );
    masked_asset_read_revoke_grant(&fixture, grant_ref);
    let error = masked_asset_read_call(&memory, &fixture.base_asset.to_hex())
        .expect_err("the revoked grant is refused");
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "a revoked-grant refusal names FORBIDDEN; got {}: {}",
        error.code, error.message,
    );
}
