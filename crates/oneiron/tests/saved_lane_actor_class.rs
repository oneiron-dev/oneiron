//! A saved lane reads under the actor class its live key was proved as (FIX
//! SAVED-LANE-REBUILD-SUBSTITUTES-ACTOR-CLASS, Sol F5 on #8061; Engine
//! RULING F5-BASE = A, 15 Nov 15:56).
//!
//! A person's credential may name the agent class: a PERSON acts as human
//! or as agent (`validate_actor_class`), and a policy row may bind one class
//! alone. The owner pairs an agent-class credential on their own PERSON, and
//! the vault's one read row holds agent-class reads to a receipt, so that
//! credential's live lane refuses the owner's open claim. Saved work froze
//! the lane with no class, and every rebuild took the class from the
//! principal's row type, a PERSON's being human: no row bound the rebuilt
//! key, its frozen Scope stood as read authority, and the saved lane read
//! the claim. The lane's grant basis now keeps the class, and each rebuild
//! from the principal's row reads under it: the saved question's asker
//! reader, its source reader (the refresh, artifact and wake reads), and a
//! key rebuilt and frozen again. A caller's own key of another class has no
//! meet with the lane and reads nothing, even where the lane's own row
//! admits the claim: a current credential that proves another class, the
//! owner's own human-class key, and a key with no proof that names the
//! agent class over a human-class lane (Sol F1 on #8134). A lane that kept
//! no class, its live key having named none, reads under its principal's
//! row class through each rebuild from that row, as before the class was
//! kept: taking no class would free the rebuilt key from the row bound to
//! that class, and the lane's frozen Scope would stand as read authority its
//! live key lacked (Astra F1/F2 on #8134).
//!
//! Red at 4fe9a03288f (#8118's head 25e1b9d9f61 plus the shared
//! source-reader helper, which moves no behaviour): each of the first five
//! reads the claim. Red at 382d40476b6 (the first fix, under which every
//! key with no proof took the lane's class, a caller's own key among them):
//! the owner's own key over the agent-class lane, and the agent-class key
//! over the human-class lane, each read the claim, and so do a classless
//! lane's asker and source readers under the human-class row (this file at
//! that commit). Guards: a human-class credential's saved lane still reads
//! the claim no row binds its class from, and an agent-class lane still
//! reads a claim its own row admits.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test saved_lane_actor_class`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, SlipCaveat, VerifiedSlip,
};
use oneiron::claim::{
    FrozenReadLane, ScopedRead, ScopedReadActorKey, base_world_id, default_project_id,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::Scope;
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::question_saved_lane::{
    question_read, saved_question_reader, saved_source_reader,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WorldAuthoritySet};
use serde_json::json;

const OCCURRED_AT: u64 = 1_769_947_200;
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:saved-lane-actor-class";
/// The binding key seed of the owner's agent-class credential.
const AGENT_BINDING_SEED: u8 = 0x6A;
/// The binding key seed of the owner's own human-class device.
const DEVICE_BINDING_SEED: u8 = 0x6B;
/// The caveat that narrows only the device credential's lifetime.
const CAVEAT_TTL_SECS: u64 = 1_800;

/// The vault's one read row: the class it binds, and what it lets a key of
/// that class read.
#[derive(Clone, Copy)]
enum ReadRow {
    /// The agent class, in the base world, each read held to a receipt: no
    /// read passes it.
    AgentHeldToReceipt,
    /// The agent class, in the base world, with no receipt.
    AgentAdmitsBaseWorld,
    /// The human class, in the base world, each read held to a receipt.
    HumanHeldToReceipt,
}

/// A vault whose owner wrote a base-world claim open to every relationship,
/// paired an agent-class credential and a human-class device on their own
/// PERSON, and keeps one read row, bound to one class.
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner: EntityId,
    claim: EntityId,
    agent_slip: CapabilitySlip,
    device_slip: CapabilitySlip,
}

fn fixture(row: ReadRow) -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    // The owner's pairing link is an owner act this install's live machine
    // profile carries (FIX 4648).
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let claim = write_owner_claim(&vault, owner, &owner_proof);
    let agent_slip = paired_slip(
        &vault,
        &issuer,
        &owner_proof,
        owner,
        "agent",
        AGENT_BINDING_SEED,
    );
    let device_slip = paired_slip(
        &vault,
        &issuer,
        &owner_proof,
        owner,
        "human",
        DEVICE_BINDING_SEED,
    );
    keep_one_read_row(&vault, row);
    Fixture {
        vault,
        _dir: dir,
        issuer,
        owner,
        claim,
        agent_slip,
        device_slip,
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
            value: json!("saved lane actor class claim"),
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

/// A credential on the owner's own PERSON, naming `class`, paired on a link
/// the owner issues and redeemed by the key whose seed is `seed`.
fn paired_slip(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner_proof: &AuthenticatedOwner,
    owner: EntityId,
    class: &str,
    seed: u8,
) -> CapabilitySlip {
    let holder = owner.to_hex();
    let link = vault
        .issue_owner_pairing_link(
            issuer,
            owner_proof,
            Scope::top(),
            3_600,
            PairingPrincipal {
                holder_ref: Some(holder.clone()),
                actor_class: Some(class.to_owned()),
                ..PairingPrincipal::default()
            },
        )
        .expect("the owner issues a pairing link on their own PERSON");
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &holder,
        link.pin.as_ref(),
    )
    .expect("the pairing transcript");
    vault
        .redeem_pairing_link(
            issuer,
            &link.code,
            &holder,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )
        .expect("the credential's key redeems the link")
}

/// Keeps the shipped policy, but replaces every read row with `row`, which
/// binds one class alone, to the base world.
fn keep_one_read_row(vault: &Vault, row: ReadRow) {
    let class = match row {
        ReadRow::AgentHeldToReceipt | ReadRow::AgentAdmitsBaseWorld => "agent",
        ReadRow::HumanHeldToReceipt => "human",
    };
    let id = oneiron_store::policy_record::default_policy_manifest_id()
        .expect("the default manifest id");
    let bytes = vault
        .get(&id)
        .expect("read the default manifest")
        .expect("the shipped manifest is stored");
    let mut manifest: serde_json::Value =
        rmp_serde::from_slice(&bytes).expect("decode the shipped manifest");
    let grants = manifest["scoped_grants"]
        .as_array_mut()
        .expect("the shipped scoped-grant table");
    grants.retain(|grant| {
        !matches!(
            grant["effector"].as_str().map(str::trim),
            Some("core:read" | "oneiron:read")
        )
    });
    grants.push(json!({
        "actor_class": class,
        "effector": "core:read",
        "scope": oneiron_authority::federation::scope_codec::read_preset(),
        "selectors": { "world_ref": "base" },
        "receipt_required": !matches!(row, ReadRow::AgentAdmitsBaseWorld),
    }));
    oneiron::test_support::put_policy_manifest_bytes(
        vault,
        id,
        &rmp_serde::to_vec_named(&manifest).expect("encode the policy"),
    )
    .expect("store the one class-bound read row beside the shipped policy");
}

/// `slip`, proved by the key whose seed is `seed`.
fn verified(fixture: &Fixture, slip: &CapabilitySlip, seed: u8) -> VerifiedSlip {
    let signature = SigningKey::from_bytes(&[seed; 32])
        .sign(
            &slip
                .binding_transcript(REQUEST_CHALLENGE)
                .expect("the holder's request transcript"),
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
        .expect("the holder proves possession of the credential")
}

fn credential_key(fixture: &Fixture, proof: &VerifiedSlip) -> ScopedReadActorKey {
    fixture
        .vault
        .credential_read_key(proof)
        .expect("the credential's read key")
        .expect("the credential grants read")
}

/// The owner's agent-class credential's live key.
fn agent_key(fixture: &Fixture) -> ScopedReadActorKey {
    let key = credential_key(
        fixture,
        &verified(fixture, &fixture.agent_slip, AGENT_BINDING_SEED),
    );
    assert!(
        key.actor_class() == Some("agent") && !key.reads_as_vault_owner(),
        "precondition: the owner's agent-class credential reads as an agent, below the owner's floor; seen class {:?}",
        key.actor_class()
    );
    key
}

/// The owner's device credential narrowed by the device itself, kept on its
/// key: a human-class key below the owner's floor.
fn attenuated_device_key(fixture: &Fixture) -> ScopedReadActorKey {
    let mut slip = fixture.device_slip.clone();
    slip.attenuate(
        SlipCaveat {
            ttl_secs: Some(CAVEAT_TTL_SECS),
            ..Default::default()
        },
        &SigningKey::from_bytes(&[DEVICE_BINDING_SEED; 32]),
    )
    .expect("the device narrows its own credential");
    let key = credential_key(fixture, &verified(fixture, &slip, DEVICE_BINDING_SEED));
    assert!(
        key.actor_class() == Some("human") && !key.reads_as_vault_owner(),
        "precondition: the device's attenuated credential reads as a human, below the owner's floor; seen class {:?}",
        key.actor_class()
    );
    key
}

/// Whether `lane` point-reads `row`; the text names the answer.
fn reads(lane: &ScopedRead<'_>, row: EntityId) -> (bool, String) {
    let read = lane
        .get_entity_parts_with_receipt(&row, None)
        .map(|read| read.value.is_some());
    (matches!(read, Ok(true)), format!("point={read:?}"))
}

fn held_lane(fixture: &Fixture, key: ScopedReadActorKey) -> ScopedRead<'_> {
    fixture
        .vault
        .scoped_read(key)
        .recorded_lane()
        .expect("record read lane")
}

/// A saved question's lane under `key`, with its reader's own live owner
/// authority, reading recorded claims as `held_lane` does.
fn question_lane(fixture: &Fixture, key: ScopedReadActorKey) -> ScopedRead<'_> {
    question_read(&fixture.vault, key)
        .recorded_lane()
        .expect("record question lane")
}

/// `key`'s lane frozen as saved work keeps it, read back from its stored
/// MessagePack form, as a saved question's and a queued summary's lane is.
fn saved_lane(fixture: &Fixture, key: ScopedReadActorKey) -> FrozenReadLane {
    let frozen = fixture
        .vault
        .scoped_read(key)
        .freeze()
        .expect("the read lane freezes");
    let stored = rmp_serde::to_vec_named(&frozen).expect("frozen lane encodes");
    rmp_serde::from_slice(&stored).expect("frozen lane decodes")
}

/// The agent-class credential's saved lane, once its live lane is shown to
/// read the claim exactly as its row allows: `live_reads`.
fn agent_saved_lane(fixture: &Fixture, live_reads: bool) -> FrozenReadLane {
    let key = agent_key(fixture);
    let (live, seen) = reads(&held_lane(fixture, key.clone()), fixture.claim);
    assert!(
        live == live_reads,
        "precondition: the agent-class credential's live lane {} the owner's claim under the agent-class row; seen {seen}",
        if live_reads { "reads" } else { "refuses" }
    );
    let frozen = saved_lane(fixture, key);
    assert!(
        !frozen.reads_as_principal(),
        "precondition: the agent-class credential's saved lane keeps its Scope and basis, not its holder's principal lane"
    );
    frozen
}

/// What a saved question's asker reader reads of `row`: the owner's key
/// with its class from its PERSON row, narrowed by `frozen`.
fn asker_reads(fixture: &Fixture, frozen: &FrozenReadLane, row: EntityId) -> (bool, String) {
    match saved_question_reader(&fixture.vault, fixture.owner, frozen) {
        Ok(key) => reads(&question_lane(fixture, key), row),
        Err(error) => (false, format!("rebuild={error:?}")),
    }
}

/// What a saved question's source reader (its refresh, artifact and wake
/// reads) reads of `row`.
fn source_reads(fixture: &Fixture, frozen: &FrozenReadLane, row: EntityId) -> (bool, String) {
    match saved_source_reader(&fixture.vault, fixture.owner, frozen) {
        Ok(key) => reads(&question_lane(fixture, key), row),
        Err(error) => (false, format!("rebuild={error:?}")),
    }
}

/// What `frozen`, met with the owner's own in-process key of the human
/// class, reads of `row`.
fn owner_key_reads(fixture: &Fixture, frozen: &FrozenReadLane, row: EntityId) -> (bool, String) {
    let key = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .read_key()
        .expect("owner read key");
    match frozen.narrow(&fixture.vault, key) {
        Ok(key) => reads(&held_lane(fixture, key), row),
        Err(error) => (false, format!("rebuild={error:?}")),
    }
}

/// The lane of a key of the owner's id that names no class and holds no
/// proof, floor or Scope (`ScopedReadActorKey::new`), bound to the base
/// world.
fn classless_lane(fixture: &Fixture) -> ScopedRead<'_> {
    let key = ScopedReadActorKey::new(fixture.owner.to_hex()).expect("a key that names no class");
    assert!(
        key.actor_class().is_none() && !key.reads_as_vault_owner(),
        "precondition: the key names no class and reads below the owner's floor; seen class {:?}",
        key.actor_class()
    );
    fixture.vault.scoped_read(key).within_worlds(
        WorldAuthoritySet::new(true, std::iter::empty::<EntityId>()).expect("the base world alone"),
    )
}

/// The classless lane's saved form, once its live lane is shown to refuse
/// the claim: no row binds a key of no class, and it holds no Scope to read
/// through. Under the human-class row, a key built from the owner's PERSON
/// row reads as human.
fn classless_saved_lane(fixture: &Fixture) -> FrozenReadLane {
    let (live, seen) = reads(
        &classless_lane(fixture)
            .recorded_lane()
            .expect("record read lane"),
        fixture.claim,
    );
    assert!(
        !live,
        "precondition: the classless key's live lane, with no Scope and no row of its class, refuses the owner's claim; seen {seen}"
    );
    let frozen = classless_lane(fixture)
        .freeze()
        .expect("the classless lane freezes");
    let stored = rmp_serde::to_vec_named(&frozen).expect("frozen lane encodes");
    let frozen: FrozenReadLane = rmp_serde::from_slice(&stored).expect("frozen lane decodes");
    assert!(
        !frozen.reads_as_principal(),
        "precondition: the base-world bound keeps the classless lane from reading as its principal's own"
    );
    frozen
}

#[test]
fn an_agent_class_saved_question_reads_no_claim_its_receipt_bound_row_refused() {
    let fixture = fixture(ReadRow::AgentHeldToReceipt);
    let frozen = agent_saved_lane(&fixture, false);
    let (read, seen) = asker_reads(&fixture, &frozen, fixture.claim);
    assert!(
        !read,
        "actor=the owner's agent-class credential; expected its saved question's asker reader to read as the agent class and refuse the claim its receipt-bound row refused, not to read it as human; seen {seen}"
    );
}

#[test]
fn an_agent_class_saved_question_source_reads_no_claim_its_receipt_bound_row_refused() {
    let fixture = fixture(ReadRow::AgentHeldToReceipt);
    let frozen = agent_saved_lane(&fixture, false);
    let (read, seen) = source_reads(&fixture, &frozen, fixture.claim);
    assert!(
        !read,
        "actor=the owner's agent-class credential; expected its saved question's source reader (refresh, artifact and wake reads) to read as the agent class and refuse the claim its receipt-bound row refused; seen {seen}"
    );
}

#[test]
fn an_agent_class_saved_lane_over_the_owners_key_reads_no_claim_its_receipt_bound_row_refused() {
    let fixture = fixture(ReadRow::AgentHeldToReceipt);
    let frozen = agent_saved_lane(&fixture, false);
    let (read, seen) = owner_key_reads(&fixture, &frozen, fixture.claim);
    assert!(
        !read,
        "actor=the owner's agent-class credential; expected its saved lane, met with the owner's own human-class key, to read nothing, not the claim as human; seen {seen}"
    );
}

/// A key rebuilt from the lane, frozen again, keeps the class it read under.
#[test]
fn an_agent_class_saved_lane_frozen_again_from_its_rebuilt_reader_reads_no_claim_its_row_refused() {
    let fixture = fixture(ReadRow::AgentHeldToReceipt);
    let frozen = agent_saved_lane(&fixture, false);
    let rebuilt = saved_question_reader(&fixture.vault, fixture.owner, &frozen)
        .expect("the saved question's asker reader rebuilds");
    let again = saved_lane(&fixture, rebuilt);
    let (read, seen) = asker_reads(&fixture, &again, fixture.claim);
    assert!(
        !read,
        "actor=the owner's agent-class credential; expected its lane, frozen again from its rebuilt asker reader, to keep the agent class and refuse the claim its receipt-bound row refused; seen {seen}"
    );
}

/// A current credential proving another class has no meet with the lane:
/// the lane reads the claim under its own row, and neither as the
/// credential's class nor as its own once met with that credential.
#[test]
fn an_agent_class_saved_lane_over_a_human_class_credential_reads_nothing() {
    let fixture = fixture(ReadRow::AgentAdmitsBaseWorld);
    let frozen = agent_saved_lane(&fixture, true);
    let current = credential_key(
        &fixture,
        &verified(&fixture, &fixture.device_slip, DEVICE_BINDING_SEED),
    );
    let (live, seen) = reads(&held_lane(&fixture, current.clone()), fixture.claim);
    assert!(
        live,
        "precondition: the owner's human-class device reads the claim no row binds its class from; seen {seen}"
    );
    let (read, seen) = match frozen.narrow(&fixture.vault, current) {
        Ok(key) => reads(&held_lane(&fixture, key), fixture.claim),
        Err(error) => (false, format!("rebuild={error:?}")),
    };
    assert!(
        !read,
        "actor=the owner's agent-class credential; expected its saved lane, met with the owner's human-class device credential, to read nothing, not the claim as human; seen {seen}"
    );
}

/// The owner's own key, of the human class, has no meet with an agent-class
/// lane either: met with it, the lane reads nothing, not even the claim its
/// own row admits (Sol F1 on #8134).
#[test]
fn an_agent_class_saved_lane_over_the_owners_own_human_class_key_reads_nothing() {
    let fixture = fixture(ReadRow::AgentAdmitsBaseWorld);
    let frozen = agent_saved_lane(&fixture, true);
    let (read, seen) = owner_key_reads(&fixture, &frozen, fixture.claim);
    assert!(
        !read,
        "actor=the owner's agent-class credential; expected its saved lane, met with the owner's own human-class key, to read nothing, not the claim as the agent class; seen {seen}"
    );
}

/// A key with no proof that names the agent class keeps it over a
/// human-class lane: met with that lane, it reads nothing, not the claim
/// its own receipt-bound row refused as human (Sol F1 on #8134).
#[test]
fn a_human_class_saved_lane_over_an_agent_class_key_reads_no_claim_its_row_refused() {
    let fixture = fixture(ReadRow::AgentHeldToReceipt);
    let frozen = saved_lane(&fixture, attenuated_device_key(&fixture));
    let current = ScopedReadActorKey::with_actor_class(fixture.owner.to_hex(), "agent")
        .expect("the owner's agent-class key");
    let (live, seen) = reads(&held_lane(&fixture, current.clone()), fixture.claim);
    assert!(
        !live,
        "precondition: a key that names the agent class refuses the claim its receipt-bound row holds to a receipt; seen {seen}"
    );
    let (read, seen) = match frozen.narrow(&fixture.vault, current) {
        Ok(key) => reads(&held_lane(&fixture, key), fixture.claim),
        Err(error) => (false, format!("rebuild={error:?}")),
    };
    assert!(
        !read,
        "actor=the owner's device under an attenuated human-class credential; expected its saved lane, met with a key that names the agent class, to read nothing, not the claim as human; seen {seen}"
    );
}

/// Guard: a human-class credential's saved lane keeps its class, which the
/// agent-class row does not bind, and reads the claim through every rebuild.
#[test]
fn a_human_class_saved_lane_still_reads_the_claim_no_row_binds_its_class_from() {
    let fixture = fixture(ReadRow::AgentHeldToReceipt);
    let key = attenuated_device_key(&fixture);
    let (live, seen) = reads(&held_lane(&fixture, key.clone()), fixture.claim);
    assert!(
        live,
        "precondition: the device's attenuated credential reads the claim no row binds its class from; seen {seen}"
    );
    let frozen = saved_lane(&fixture, key);
    for (reader, (read, seen)) in [
        ("asker", asker_reads(&fixture, &frozen, fixture.claim)),
        ("source", source_reads(&fixture, &frozen, fixture.claim)),
        (
            "owner's key",
            owner_key_reads(&fixture, &frozen, fixture.claim),
        ),
    ] {
        assert!(
            read,
            "actor=the owner's device under an attenuated human-class credential; expected its saved lane's {reader} rebuild to read the claim; seen {seen}"
        );
    }
}

/// Guard: an agent-class lane keeps reading what its own row admits
/// through each rebuild from the principal's row.
#[test]
fn an_agent_class_saved_lane_still_reads_a_claim_its_row_admits() {
    let fixture = fixture(ReadRow::AgentAdmitsBaseWorld);
    let frozen = agent_saved_lane(&fixture, true);
    for (reader, (read, seen)) in [
        ("asker", asker_reads(&fixture, &frozen, fixture.claim)),
        ("source", source_reads(&fixture, &frozen, fixture.claim)),
    ] {
        assert!(
            read,
            "actor=the owner's agent-class credential; expected its saved lane's {reader} rebuild to read, as the agent class, the claim its base-world row admits; seen {seen}"
        );
    }
}

/// A lane saved with no class reads under its principal's row class through
/// the saved question's asker reader: taking no class frees the rebuilt key
/// from the human-class row, and the lane's frozen Scope then reads the
/// claim its live lane refused (Astra F2 on #8134).
#[test]
fn a_classless_saved_question_reads_no_claim_its_principals_human_class_row_refused() {
    let fixture = fixture(ReadRow::HumanHeldToReceipt);
    let frozen = classless_saved_lane(&fixture);
    let (read, seen) = asker_reads(&fixture, &frozen, fixture.claim);
    assert!(
        !read,
        "actor=a key of the owner's id that names no class; expected its saved question's asker reader to read as the human class of the owner's PERSON row and refuse the claim the human-class receipt-bound row refused, not to read it with no class through its frozen Scope; seen {seen}"
    );
}

/// The saved question's source reader (its refresh, artifact and wake reads)
/// reads a classless lane under its principal's row class as well.
#[test]
fn a_classless_saved_question_source_reads_no_claim_its_principals_human_class_row_refused() {
    let fixture = fixture(ReadRow::HumanHeldToReceipt);
    let frozen = classless_saved_lane(&fixture);
    let (read, seen) = source_reads(&fixture, &frozen, fixture.claim);
    assert!(
        !read,
        "actor=a key of the owner's id that names no class; expected its saved question's source reader to read as the human class of the owner's PERSON row and refuse the claim the human-class receipt-bound row refused, not to read it with no class through its frozen Scope; seen {seen}"
    );
}
