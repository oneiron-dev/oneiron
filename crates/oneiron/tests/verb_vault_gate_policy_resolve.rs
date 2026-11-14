//! `vault.gate.policy.resolve` through the generated verb dispatch
//! (`oneiron::task_verb::sdk::invoke`), as a client calls it: JSON in, JSON out, on the
//! caller's own `Memory`. An agent with no Grant listing the verb is refused FORBIDDEN,
//! never unknown-verb BAD_REQUEST; the holder of a live Grant reads the trusted
//! contributor its record-scoped lane admits, never a contributor outside that lane, a
//! quarantined row, and no frontier, default ref, resolved
//! value or omitted count travels; a revoked Grant is refused again on the same handle.
//!
//! The owner door carries no world field and every ordinary POLICY_MANIFEST the batch
//! path stamps sits in base reality, so two trusted rows cannot be placed into two
//! worlds through public/test-support paths. The lane split here is record-scoped: the
//! holder's paired slip carries a records caveat naming the admitted row (plus the
//! quarantined row, to prove its absence is the contributor fold, not
//! the lane), and the second trusted row stays outside that caveat. The default
//! manifest stays outside the caveat too, so the admitted set is exact.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test verb_vault_gate_policy_resolve`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::authority::{
    ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, SlipCaveat, VerifiedSlip,
    pairing_binding_transcript_pinned,
};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError};
use oneiron::policy_manifest_doors::{
    PolicyManifest, PolicyManifestPut, PolicyManifestRead, policy_manifests_as_owner,
    put_policy_manifest_as_owner,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{
    AgentGrantMintRequest, AgentGrantRevokeRequest, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange,
    Vault, VaultConfig, WriteActor,
};
use serde_json::{Value, json};

const GATE_POLICY_RESOLVE_NOW: u64 = 1_700_000_000;
const GATE_POLICY_RESOLVE_VERB: &str = "vault.gate.policy.resolve";
const GATE_POLICY_RESOLVE_CHALLENGE: &[u8] = b"oneiron-request:verb-vault-gate-policy-resolve";

// Fixture ids are `[seed; 16]` with seeds `0x80..=0x8F`, off the pinned bytes a
// fresh vault holds (`0x00 0x11 0x42 0x47 0xA1..=0xA6 0xD7 0xE1 0xFF`).
const GATE_POLICY_RESOLVE_HOLDER_SEED: u8 = 0x80;
const GATE_POLICY_RESOLVE_READER_SEED: u8 = 0x81;
const GATE_POLICY_RESOLVE_BINDING_SEED: u8 = 0x8A;

const GATE_POLICY_RESOLVE_FIRST_PACK: &str = "fixture-pack-first";
const GATE_POLICY_RESOLVE_SECOND_PACK: &str = "fixture-pack-second";
const GATE_POLICY_RESOLVE_THIRD_PACK: &str = "fixture-pack-third";

/// An enabled, active agent definition the owner creates as `name`.
fn gate_policy_resolve_definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "gate policy resolve fixture",
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

/// A rooted personal vault with its install enrolled, its embedded owner and proof, and
/// two named agents. No Grant, no read permit, no policy edit yet.
struct GatePolicyResolveFixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner_proof: AuthenticatedOwner,
    holder: EntityId,
    reader: EntityId,
    issuer: HostSlipIssuer,
}

fn gate_policy_resolve_fixture() -> GatePolicyResolveFixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("personal vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let staging_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let holder = EntityId::from_bytes([GATE_POLICY_RESOLVE_HOLDER_SEED; 16]).expect("holder id");
    vault
        .create_agent_definition_as(
            &staging_proof,
            &holder,
            &gate_policy_resolve_definition("caleb"),
            TimeRange {
                start: GATE_POLICY_RESOLVE_NOW,
                end: GATE_POLICY_RESOLVE_NOW,
            },
            GATE_POLICY_RESOLVE_NOW,
        )
        .expect("owner creates the holder");
    let reader = EntityId::from_bytes([GATE_POLICY_RESOLVE_READER_SEED; 16]).expect("reader id");
    vault
        .create_agent_definition_as(
            &staging_proof,
            &reader,
            &gate_policy_resolve_definition("miriam"),
            TimeRange {
                start: GATE_POLICY_RESOLVE_NOW,
                end: GATE_POLICY_RESOLVE_NOW,
            },
            GATE_POLICY_RESOLVE_NOW,
        )
        .expect("owner creates the reader");
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("install carries the owner's grant act");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof after rooting");
    GatePolicyResolveFixture {
        vault,
        _dir: dir,
        owner_proof,
        holder,
        reader,
        issuer,
    }
}

/// The owner's live Grant for `agent` naming `verbs`, over the base world alone.
/// Returns the grant's row. The verbs axis always lists `read`, so the holder's
/// own Grant lane (FIX 7462) reads base rows even without a paired slip.
fn gate_policy_resolve_mint(
    fixture: &GatePolicyResolveFixture,
    agent: EntityId,
    verbs: Vec<String>,
) -> EntityId {
    let mut authority_scope = Scope::top();
    authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    authority_scope.verbs = ScopeAxis::Some(verbs.into_iter().collect());
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("owner mints the agent Grant");
    assert!(minted.grant.confers, "the Grant confers");
    minted.grant.grant_ref
}

/// The vault's live default manifest body, as the owner reads it: the template every
/// fixture contribution clones, so each put meets the decoder.
fn gate_policy_resolve_template(fixture: &GatePolicyResolveFixture) -> PolicyManifest {
    let view = policy_manifests_as_owner(
        &fixture.vault,
        &fixture.owner_proof,
        &PolicyManifestRead { manifest_ref: None },
    )
    .expect("owner reads the live policy");
    view.manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .expect("default policy manifest")
        .manifest
        .clone()
}

/// One fresh trusted contribution carrying `pack_id`, through the owner door. Returns
/// its 32-hex ref.
fn gate_policy_resolve_put(fixture: &GatePolicyResolveFixture, pack_id: &str) -> String {
    let mut manifest = gate_policy_resolve_template(fixture);
    manifest.pack_id = pack_id.to_owned();
    manifest.pack_version = "1".to_owned();
    let receipt = put_policy_manifest_as_owner(
        &fixture.vault,
        &fixture.owner_proof,
        PolicyManifestPut {
            manifest_ref: None,
            expected_body_hash: None,
            manifest,
        },
    )
    .expect("owner installs the fixture pack");
    assert!(
        receipt.manifest.trusted,
        "the fixture pack is trusted: {receipt:?}"
    );
    assert!(
        !receipt.manifest.quarantined,
        "the fixture pack is not quarantined: {receipt:?}"
    );
    receipt.manifest.manifest_ref
}

/// The holder's paired credential narrowed to exactly `records`: the lane admits a
/// row in the set and withholds every other row, while the Grant still supplies the
/// verb standing. Only the verbs axis narrows the pairing scope; the records caveat
/// is the holder's own offline narrowing.
fn gate_policy_resolve_paired_slip(
    fixture: &GatePolicyResolveFixture,
    agent: EntityId,
    records: BTreeSet<String>,
) -> VerifiedSlip {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:write".to_owned(),
    ]));
    let holder = agent.to_hex();
    let link = fixture
        .vault
        .issue_owner_pairing_link(
            &fixture.issuer,
            &fixture.owner_proof,
            scope,
            3_600,
            PairingPrincipal {
                holder_ref: Some(holder.clone()),
                actor_class: Some("agent".to_owned()),
                ..PairingPrincipal::default()
            },
        )
        .expect("owner issues the agent pairing link");
    let signing_key = SigningKey::from_bytes(&[GATE_POLICY_RESOLVE_BINDING_SEED; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript =
        pairing_binding_transcript_pinned(&link.code, &binding_key, &holder, link.pin.as_ref())
            .expect("agent pairing transcript");
    let mut slip = fixture
        .vault
        .redeem_pairing_link(
            &fixture.issuer,
            &link.code,
            &holder,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )
        .expect("agent redeems its pairing link");
    slip.attenuate(
        SlipCaveat {
            records: Some(records),
            ..SlipCaveat::default()
        },
        &signing_key,
    )
    .expect("holder narrows its slip to the admitted records");
    let signature = signing_key
        .sign(
            &slip
                .binding_transcript(GATE_POLICY_RESOLVE_CHALLENGE)
                .expect("agent request transcript"),
        )
        .to_bytes();
    fixture
        .vault
        .verify_capability_slip(
            &fixture.issuer.public_key(),
            &slip,
            GATE_POLICY_RESOLVE_CHALLENGE,
            &signature,
        )
        .expect("paired agent proves possession of its narrowed credential")
}

/// The verb by name, as a client calls it: JSON in, JSON out. The input is empty.
fn gate_policy_resolve_call(memory: &Memory<'_>) -> Result<Value, MemoryError> {
    invoke(memory, GATE_POLICY_RESOLVE_VERB, json!({}))
}

/// No Grant at all: refused FORBIDDEN, never served. On main the name is unknown
/// and the refusal is BAD_REQUEST, so the code assertion fails there.
#[test]
fn gate_policy_resolve_grantless_refused() {
    let fixture = gate_policy_resolve_fixture();
    let memory = fixture.vault.memory(fixture.reader, EdgeActorClass::Agent);
    let error = gate_policy_resolve_call(&memory).expect_err("a grantless agent is refused");
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "unexpected refusal: {error:?}"
    );
    assert!(
        error.message.contains(GATE_POLICY_RESOLVE_VERB),
        "the refusal names the verb: {error:?}"
    );
}

/// A live Grant naming `read` but not this verb: still refused FORBIDDEN. The Grant
/// confers and its base-only lane reads base rows (FIX 7462), so the verb check, not
/// a missing lane, is what refuses. On main the name is unknown (BAD_REQUEST).
#[test]
fn gate_policy_resolve_read_only_refused() {
    let fixture = gate_policy_resolve_fixture();
    gate_policy_resolve_mint(&fixture, fixture.reader, vec!["read".to_owned()]);
    let memory = fixture.vault.memory(fixture.reader, EdgeActorClass::Agent);
    let error =
        gate_policy_resolve_call(&memory).expect_err("a read-only Grant is refused the verb");
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "unexpected refusal: {error:?}"
    );
    assert!(
        error.message.contains(GATE_POLICY_RESOLVE_VERB),
        "the refusal names the verb: {error:?}"
    );
}

/// The holder reads the trusted row its lane admits, never the trusted row outside
/// it or a quarantined row, and no frontier, default ref,
/// resolved value or omitted count travels. On main the name is unknown and the
/// call errors, so the unwrap fails there.
#[test]
fn gate_policy_resolve_holder_reads() {
    let fixture = gate_policy_resolve_fixture();
    // Once per vault: the holder's read-only lane for ordinary rows. The Grant below
    // supplies the verb standing; the paired slip narrows this lane to records.
    fixture
        .vault
        .install_read_permit_for_test(WriteActor::new(fixture.holder, EdgeActorClass::Agent))
        .expect("holder read permit");
    gate_policy_resolve_mint(
        &fixture,
        fixture.holder,
        vec!["read".to_owned(), GATE_POLICY_RESOLVE_VERB.to_owned()],
    );
    let first = gate_policy_resolve_put(&fixture, GATE_POLICY_RESOLVE_FIRST_PACK);
    let second = gate_policy_resolve_put(&fixture, GATE_POLICY_RESOLVE_SECOND_PACK);
    let third = gate_policy_resolve_put(&fixture, GATE_POLICY_RESOLVE_THIRD_PACK);
    fixture
        .vault
        .quarantine_manifest_contribution(
            &fixture.owner_proof,
            EntityId::from_hex(&third).expect("third manifest id"),
        )
        .expect("owner quarantines the third pack");
    // Both rows named here pass the records caveat; quarantine alone keeps the
    // third row out of the contributor scan. The second and default are outside.
    let records = BTreeSet::from([first.clone(), third.clone()]);
    let slip = gate_policy_resolve_paired_slip(&fixture, fixture.holder, records);
    let memory = fixture
        .vault
        .memory(fixture.holder, EdgeActorClass::Agent)
        .with_read_proof(&slip);
    let quarantined = invoke(&memory, "vault.get", json!({"entity_ref": third}))
        .expect("the lane can read the quarantined manifest");
    assert!(
        quarantined["value"].is_object(),
        "quarantine does not exclude this row from the read lane: {quarantined}"
    );
    let out = gate_policy_resolve_call(&memory).expect("the holder reads its lane");
    let manifests = out["value"]["manifests"]
        .as_array()
        .expect("manifests array");
    let refs: Vec<String> = manifests
        .iter()
        .filter_map(|entry| entry["manifest_ref"].as_str().map(str::to_owned))
        .collect();
    assert!(refs.contains(&first), "the admitted row reads: {out}");
    assert!(
        !refs.contains(&second),
        "the row outside the lane stays out: {out}"
    );
    assert!(
        !refs.contains(&third),
        "the quarantined row stays out: {out}"
    );
    assert_eq!(
        refs.len(),
        1,
        "only the admitted row reads, not the seeded default: {out}"
    );
    let first_view = manifests
        .iter()
        .find(|entry| entry["manifest_ref"].as_str() == Some(first.as_str()))
        .expect("admitted view");
    assert_eq!(first_view["trusted"], json!(true), "{out}");
    assert_eq!(first_view["quarantined"], json!(false), "{out}");
    assert_eq!(
        first_view["manifest"]["pack_id"],
        json!(GATE_POLICY_RESOLVE_FIRST_PACK),
        "{out}"
    );
    // No frontier, default ref, resolved value or omitted count travels: the value
    // is the admitted rows, and hidden rows are never counted.
    for key in [
        "read_frontier_hash",
        "default_manifest_ref",
        "resolved",
        "omitted",
        "omitted_count",
        "suppressed_count",
    ] {
        assert!(
            out["value"].get(key).is_none(),
            "the value carries no {key}: {out}"
        );
    }
    assert!(
        out.get("read_frontier_hash").is_none(),
        "the top level carries no frontier: {out}"
    );
    assert!(
        out.get("default_manifest_ref").is_none(),
        "the top level carries no default ref: {out}"
    );
    assert_eq!(
        out["narrowing"]["suppressed_count"],
        json!(0),
        "hidden rows are never counted: {out}"
    );
}

/// The same call, which reads before the revoke, after the owner revokes the Grant:
/// refused again on the same handle, live. On main the name is unknown and the
/// first call errors, so the unwrap fails there.
#[test]
fn gate_policy_resolve_revoked_refused() {
    let fixture = gate_policy_resolve_fixture();
    fixture
        .vault
        .install_read_permit_for_test(WriteActor::new(fixture.holder, EdgeActorClass::Agent))
        .expect("holder read permit");
    let grant = gate_policy_resolve_mint(
        &fixture,
        fixture.holder,
        vec!["read".to_owned(), GATE_POLICY_RESOLVE_VERB.to_owned()],
    );
    let first = gate_policy_resolve_put(&fixture, GATE_POLICY_RESOLVE_FIRST_PACK);
    let slip =
        gate_policy_resolve_paired_slip(&fixture, fixture.holder, BTreeSet::from([first.clone()]));
    let memory = fixture
        .vault
        .memory(fixture.holder, EdgeActorClass::Agent)
        .with_read_proof(&slip);
    let before = gate_policy_resolve_call(&memory).expect("the holder reads before the revoke");
    let refs: Vec<String> = before["value"]["manifests"]
        .as_array()
        .expect("manifests array")
        .iter()
        .filter_map(|entry| entry["manifest_ref"].as_str().map(str::to_owned))
        .collect();
    assert!(refs.contains(&first), "the admitted row reads: {before}");
    let revoked = revoke_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref: grant,
            seen: None,
        },
    )
    .expect("the owner revokes the Grant");
    assert!(
        revoked.changed,
        "the revoke of {} changed nothing",
        grant.to_hex()
    );
    let error = gate_policy_resolve_call(&memory).expect_err("a revoked Grant is refused");
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "unexpected refusal: {error:?}"
    );
}
