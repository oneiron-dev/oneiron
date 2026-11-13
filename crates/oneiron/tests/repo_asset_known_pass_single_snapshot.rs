//! A repo snapshot ASSET read by a masked reader takes its known-value pass
//! (FIX 8966) in the read's own snapshot, so the thread holds one LMDB read
//! transaction (FIX REPO-ASSET-KNOWN-PASS-NESTED-SNAPSHOT). The store has no
//! NOTLS: a second read transaction opened on a thread that already holds one
//! fails `MDB_BAD_RSLOT`. Each case reads the one repo ASSET whose bytes hold a
//! value custody knows, through one door that took the pass inside a snapshot
//! it already held: the native raw body, a graph-fs cat, a `vault.get` and the
//! in-process hydrate an MCP tool reads by. Each is served, with the value as
//! its handle wherever the door returns the bytes.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test repo_asset_known_pass_single_snapshot`
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::Engine as _;
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::authority::{ActSurface, MachineRole, SlipCaveat};
use oneiron::claim::{ScopedReadActorKey, base_world_id};
use oneiron::code_run::vault_read::{
    CoreHydrateRequest, InProcessVaultReadAdapter, VaultReadClient, View,
};
use oneiron::federation::{Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling};
use oneiron::graph_fs::GraphFsReference;
use oneiron::memory::graph_fs_doors::{GraphFsEncoding, GraphFsMountRequest, GraphFsPathRequest};
use oneiron::memory::{Memory, MemoryError};
use oneiron::registry::ENTITY_TYPE_ASSET;
use oneiron::secret_custody::{
    CustodyClass, CustodyTier, OwnerSecretRegistration, RequestedBinding,
};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange,
    Vault, VaultConfig,
};

const KNOWN_PASS_TEST_NOW: u64 = 1_700_000_000;

// The holder's id is `[seed; 16]`, off the pinned bytes a fresh vault holds.
const KNOWN_PASS_AGENT: u8 = 0x7A;

// A plain custody value no detector names: the write stores it raw, and only
// the known-value pass masks it.
const KNOWN_PASS_SECRET: &str = "known-pass-fixture-value-5c2e8b1d";

/// An enabled, active agent definition the owner creates as `name`.
fn known_pass_definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "known pass fixture",
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
/// row this fixture puts is a repo file a masked reader projects.
fn known_pass_asset_id(content_hash: &[u8; 32]) -> EntityId {
    const KNOWN_PASS_ID_DOMAIN: &[u8] = b"oneiron:codebase-asset-entity:v1";
    for salt in 0_u64..=u64::MAX {
        let mut hasher = blake3::Hasher::new();
        hasher.update(KNOWN_PASS_ID_DOMAIN);
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

struct KnownPassFixture {
    vault: Vault,
    holder: EntityId,
    asset: EntityId,
    _dir: tempfile::TempDir,
}

/// A vault holding one repo snapshot ASSET in base reality whose bytes hold
/// a value custody knows, and an agent the owner granted base `read`.
fn known_pass_fixture() -> KnownPassFixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let holder = EntityId::from_bytes([KNOWN_PASS_AGENT; 16]).expect("holder id");
    vault
        .create_agent_definition_as(
            &owner_proof,
            &holder,
            &known_pass_definition("owen"),
            TimeRange {
                start: KNOWN_PASS_TEST_NOW,
                end: KNOWN_PASS_TEST_NOW,
            },
            KNOWN_PASS_TEST_NOW,
        )
        .expect("owner creates the holder");
    // The ASSET is put before custody knows the value, so its bytes are
    // stored raw and only a masked read's known-value pass masks them.
    let body = format!("staging deploy uses {KNOWN_PASS_SECRET} for access");
    let asset = known_pass_asset_id(blake3::hash(body.as_bytes()).as_bytes());
    vault
        .put_entity(
            &asset,
            ENTITY_TYPE_ASSET,
            TimeRange {
                start: KNOWN_PASS_TEST_NOW,
                end: KNOWN_PASS_TEST_NOW,
            },
            KNOWN_PASS_TEST_NOW,
            body.as_bytes(),
        )
        .expect("owner stores the repo asset");
    vault
        .register_secret_as_owner(
            &owner_proof,
            &OwnerSecretRegistration {
                name: "known-pass-fixture",
                class: CustodyClass::CustodyPortable,
                device_only: false,
                rung: CustodyTier::T1Leased,
                bindings: vec![RequestedBinding {
                    effector: "deploy".to_owned(),
                    tier_ceiling: None,
                    scopes: vec!["read".to_owned()],
                }],
                manifest: None,
                value: KNOWN_PASS_SECRET.as_bytes(),
            },
            KNOWN_PASS_TEST_NOW,
        )
        .expect("owner registers the fixture secret");
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("install carries the owner's grant act");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let minted = mint_agent_grant_as(
        &vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent: holder,
            authority_scope: known_pass_base_read_scope(),
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("owner mints the holder's base read grant");
    assert!(minted.grant.confers, "the grant confers");
    KnownPassFixture {
        vault,
        holder,
        asset,
        _dir: dir,
    }
}

/// Base reality with the `read` verb.
fn known_pass_base_read_scope() -> Scope {
    let mut scope = Scope::top();
    scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    scope
}

/// A read key from the host root slip narrowed to base `read`, as an MCP
/// tool's in-process read is bound.
fn known_pass_slip_read_key(vault: &Vault) -> ScopedReadActorKey {
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    let mut slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("host root slip");
    let mut scope = known_pass_base_read_scope();
    scope.sensitivity = SensitivityCeiling::AtMost(Sensitivity::Restricted);
    issuer
        .attenuate(
            &mut slip,
            SlipCaveat {
                scope: Some(scope),
                ..Default::default()
            },
        )
        .expect("narrow root to base read");
    let challenge = b"known-pass-single-snapshot";
    let proof_bytes = issuer
        .binding_proof(&slip, challenge)
        .expect("binding proof");
    let verified = vault
        .verify_capability_slip(&issuer.public_key(), &slip, challenge, &proof_bytes)
        .expect("verified base-read slip");
    ScopedReadActorKey::from_verified_slip(&verified).expect("read key")
}

fn known_pass_holds(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

/// `bytes` hold the known value as its handle and not the value itself.
fn known_pass_assert_masked(bytes: &[u8], door: &str) {
    assert!(
        !known_pass_holds(bytes, KNOWN_PASS_SECRET.as_bytes()),
        "{door} served the value custody knows: {}",
        String::from_utf8_lossy(bytes)
    );
    assert!(
        known_pass_holds(bytes, b"[secret "),
        "{door} served no handle in its place: {}",
        String::from_utf8_lossy(bytes)
    );
}

fn known_pass_memory(fixture: &KnownPassFixture) -> Memory<'_> {
    fixture.vault.memory(fixture.holder, EdgeActorClass::Agent)
}

#[test]
fn native_raw_entity_body_serves_a_repo_asset_with_the_known_value_as_its_handle() {
    let fixture = known_pass_fixture();
    let memory = known_pass_memory(&fixture);
    let body = memory
        .with_credential_raw_read(|read| read.entity_body(&fixture.asset))
        .map_err(|error: MemoryError| error.to_string())
        .expect("the native raw read takes its known-value pass in its own snapshot")
        .expect("the holder's lane admits the repo asset");
    known_pass_assert_masked(&body, "the native raw body");
}

#[test]
fn graph_fs_cat_serves_a_repo_asset_with_the_known_value_as_its_handle() {
    let fixture = known_pass_fixture();
    let memory = known_pass_memory(&fixture);
    let output = memory
        .graph_fs_cat(GraphFsPathRequest {
            mount: GraphFsMountRequest {
                reference: GraphFsReference::LiveHead,
                page_byte_cap: None,
                max_entries: None,
            },
            path: format!("/entities/{}/body", fixture.asset.to_hex()),
            cursor: None,
        })
        .map_err(|error| error.to_string())
        .expect("the graph-fs cat takes its known-value pass in its own snapshot");
    let bytes = match output.encoding {
        GraphFsEncoding::Utf8 => output.output.into_bytes(),
        GraphFsEncoding::Base64 => base64::engine::general_purpose::STANDARD
            .decode(output.output)
            .expect("the cat's base64 decodes"),
    };
    known_pass_assert_masked(&bytes, "the graph-fs cat");
}

#[test]
fn vault_get_reads_a_repo_asset_for_an_agent() {
    let fixture = known_pass_fixture();
    let memory = known_pass_memory(&fixture);
    let view = memory
        .get_entity(&fixture.asset.to_hex())
        .map_err(|error| error.to_string())
        .expect("the agent's vault.get takes its known-value pass in its own snapshot")
        .value
        .expect("the holder's lane admits the repo asset");
    let shown = serde_json::to_string(&view).expect("the view encodes");
    assert!(
        !shown.contains(KNOWN_PASS_SECRET),
        "the agent's view holds the value custody knows: {shown}"
    );
}

#[test]
fn in_process_hydrate_serves_a_repo_asset_with_the_known_value_masked() {
    let fixture = known_pass_fixture();
    let reference = oneiron::retrieval_depth::short_ref_or_hex(&fixture.vault, &fixture.asset)
        .expect("the asset's short ref");
    assert!(
        reference.contains(':'),
        "the repo asset has a short ref, not only its hex id: {reference}"
    );
    let adapter =
        InProcessVaultReadAdapter::new(&fixture.vault, known_pass_slip_read_key(&fixture.vault));
    let response = adapter
        .hydrate(CoreHydrateRequest {
            reference: Some(reference),
            short_id: None,
            content_hash: None,
            view: Some(View::Full),
            filter: None,
            image_input: false,
            task: None,
        })
        .map_err(|error| error.to_string())
        .expect("the in-process hydrate takes its known-value pass in its own snapshot");
    let item = response
        .item
        .expect("the slip's base read admits the repo asset");
    let shown = serde_json::to_string(&item).expect("the item encodes");
    assert!(
        !shown.contains(KNOWN_PASS_SECRET),
        "the hydrated item holds the value custody knows: {shown}"
    );
}
