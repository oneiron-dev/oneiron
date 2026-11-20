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
//! agent class over a human-class lane (Sol F1 on #8134). A lane whose live
//! key named no class keeps that it named none, and reads with no class
//! through each rebuild from its principal's row, as its live key did; a
//! caller's key that names a class has no meet with it (round 2 review P1
//! of #9590, frozen.rs:719). It keeps no Scope its key lacked, so no frozen
//! Scope stands as read authority (Astra F1/F2 on #8134): under a
//! human-class row that holds reads to a receipt it refuses the claim, and
//! under one that admits the base world it refuses it too, as its live key
//! did, where the principal's human row class read it. A lane saved before
//! the class was kept still reads under its principal's row class.
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
//!
//! A lane whose key held no Scope keeps none (FIX
//! FROZEN-LANE-FREEZES-ABSENT-AUTHORITY-AS-TOP, Astra threats 1-2 on
//! #8134). The classless key's base-world bound used to freeze as a top
//! Scope, and the rebuild handed it to a caller's key that held none. Where
//! no row binds a key's class, a key with no Scope reads nothing and a key
//! with a Scope reads what it admits. So the same classless key, met with
//! its own saved lane through the public rebuild, read the claim its live
//! lane refused. It now refuses it, and so does that rebuild frozen again.
//! Red at fcbc264c20c (#9583's head): the first rebuild reads the claim.
//! Red at 5b967df3d2f (#9590's head with round 2 fix D): under the
//! human-class row that admits the base world, the classless lane's asker
//! and source readers, its rebuild over the owner's own key and over the
//! principal's human-class key under its access gate each read the claim.
//!
//! A live owner's key that names no class freezes with its grant basis too,
//! even where nothing narrows its lane (FIX
//! OWNER-LANE-WITHOUT-CLASS-REBUILDS-AS-HUMAN, Sol F2 on #8134): only a
//! human-class key of a live owner freezes as its principal's own. Its
//! question, saved through `create_question_with_lane`, froze as the
//! principal's own lane, and each rebuild read as the owner's human PERSON.
//! Red at 07a1b03a9b1 (#9711's head) plus these cases: the saved question's
//! asker and source readers, and the owner's own key met with its lane, each
//! read the claim only the human-class row admits. Guard: the owner's own
//! human-class key still saves its question as its principal's own lane.
//!
//! That basis keeps the reach its live key had past the relationship gate
//! (blind review P1 on #9716, rebuild.rs:117). No gate binds that key, so
//! under a class-neutral row it reads the owner's claim inside a
//! relationship the owner holds no grant on and is no member of. Each
//! rebuild from the principal's row starts under the relationship gate,
//! lifted by the owner's exemption, and the meet with the basis kept the
//! gate and dropped the exemption: the saved question's asker and source
//! readers refused that claim. Red at 2aa095cbe59 (#9716's head) plus this
//! case: both readers refuse it.
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
use oneiron::registry::ENTITY_TYPE_RELATIONSHIP;
use oneiron::temporal::TimeRange;
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
    /// The human class, in the base world, with no receipt.
    HumanAdmitsBaseWorld,
    /// No class, in the base world, with no receipt: a key of any class, or
    /// of none, reads through it.
    ClassNeutralAdmitsBaseWorld,
}

/// A vault whose owner wrote a base-world claim open to every relationship,
/// paired an agent-class credential and a human-class device on their own
/// PERSON, and keeps one read row, bound to one class or to none.
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner: EntityId,
    /// The owner's proof the fixture's claims were written under.
    owner_proof: AuthenticatedOwner,
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
    let claim = write_owner_claim(
        &vault,
        owner,
        &owner_proof,
        ClaimRelationships::All(AllRelationships::All),
    );
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
        owner_proof,
        claim,
        agent_slip,
        device_slip,
    }
}

/// A base-world claim the owner writes about themselves, inside
/// `relationships`.
fn write_owner_claim(
    vault: &Vault,
    owner: EntityId,
    owner_proof: &AuthenticatedOwner,
    relationships: ClaimRelationships,
) -> EntityId {
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
                scope_relationship_id: relationships,
                scope_project_id: default_project_id().to_hex(),
            }
            .into(),
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
/// binds one class alone, or none, to the base world.
fn keep_one_read_row(vault: &Vault, row: ReadRow) {
    let class = match row {
        ReadRow::AgentHeldToReceipt | ReadRow::AgentAdmitsBaseWorld => Some("agent"),
        ReadRow::HumanHeldToReceipt | ReadRow::HumanAdmitsBaseWorld => Some("human"),
        ReadRow::ClassNeutralAdmitsBaseWorld => None,
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
    let mut grant = json!({
        "effector": "core:read",
        "scope": oneiron_authority::federation::scope_codec::read_preset(),
        "selectors": { "world_ref": "base" },
        "receipt_required": matches!(
            row,
            ReadRow::AgentHeldToReceipt | ReadRow::HumanHeldToReceipt
        ),
    });
    if let Some(class) = class {
        grant["actor_class"] = json!(class);
    }
    grants.push(grant);
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
/// through. Each rebuild reads with no class, as its live key did.
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

/// A lane saved with no class refuses, through the saved question's asker
/// reader, the claim its live lane refused: it keeps no frozen Scope to
/// read through (Astra F2 on #8134), and reads with no class.
#[test]
fn a_classless_saved_question_reads_no_claim_its_principals_human_class_row_refused() {
    let fixture = fixture(ReadRow::HumanHeldToReceipt);
    let frozen = classless_saved_lane(&fixture);
    let (read, seen) = asker_reads(&fixture, &frozen, fixture.claim);
    assert!(
        !read,
        "actor=a key of the owner's id that names no class; expected its saved question's asker reader to refuse the claim its live lane refused under the human-class receipt-bound row, not to read it through a frozen Scope; seen {seen}"
    );
}

/// The saved question's source reader (its refresh, artifact and wake reads)
/// refuses it as well.
#[test]
fn a_classless_saved_question_source_reads_no_claim_its_principals_human_class_row_refused() {
    let fixture = fixture(ReadRow::HumanHeldToReceipt);
    let frozen = classless_saved_lane(&fixture);
    let (read, seen) = source_reads(&fixture, &frozen, fixture.claim);
    assert!(
        !read,
        "actor=a key of the owner's id that names no class; expected its saved question's source reader to refuse the claim its live lane refused under the human-class receipt-bound row, not to read it through a frozen Scope; seen {seen}"
    );
}

/// What `frozen`, met with a key of the owner's id that names no class and
/// holds no proof, floor or Scope, reads of `row`.
fn classless_key_reads(
    fixture: &Fixture,
    frozen: &FrozenReadLane,
    row: EntityId,
) -> (bool, String) {
    let key = ScopedReadActorKey::new(fixture.owner.to_hex()).expect("a key that names no class");
    match frozen.narrow(&fixture.vault, key) {
        Ok(key) => reads(&held_lane(fixture, key), row),
        Err(error) => (false, format!("rebuild={error:?}")),
    }
}

/// The classless lane, met with the same classless key through the public
/// rebuild, reads what that key read live: nothing. It keeps no Scope the
/// key lacked, so no top Scope stands as read authority where no row binds
/// the key's class; and the key it rebuilds, frozen again, keeps none
/// either (FIX FROZEN-LANE-FREEZES-ABSENT-AUTHORITY-AS-TOP, Astra threats
/// 1-2 on #8134).
#[test]
fn a_classless_saved_lane_over_its_own_classless_key_reads_no_claim_its_live_lane_refused() {
    let fixture = fixture(ReadRow::HumanHeldToReceipt);
    let frozen = classless_saved_lane(&fixture);
    let (read, seen) = classless_key_reads(&fixture, &frozen, fixture.claim);
    assert!(
        !read,
        "actor=a key of the owner's id that names no class; expected its saved lane, met with the same key, to refuse the claim its live lane refused, not to read it through a top Scope the key never held; seen {seen}"
    );
    let key = ScopedReadActorKey::new(fixture.owner.to_hex()).expect("a key that names no class");
    let rebuilt = frozen
        .narrow(&fixture.vault, key)
        .expect("the classless lane rebuilds over its own key");
    let again = saved_lane(&fixture, rebuilt);
    let (read, seen) = classless_key_reads(&fixture, &again, fixture.claim);
    assert!(
        !read,
        "actor=a key of the owner's id that names no class; expected its saved lane, rebuilt over the same key and frozen again, to keep no Scope and refuse the claim; seen {seen}"
    );
}

/// The classless lane under a human-class row that admits the base world,
/// once a human-class key below the owner's floor is shown to read the claim
/// there: the classless key's live lane still refuses it, as no row binds a
/// key of no class and it holds no Scope.
fn classless_saved_lane_beside_human_row(fixture: &Fixture) -> FrozenReadLane {
    let (read, seen) = reads(
        &held_lane(fixture, attenuated_device_key(fixture)),
        fixture.claim,
    );
    assert!(
        read,
        "control: the human-class row admits the claim to the device's attenuated human-class credential; seen {seen}"
    );
    classless_saved_lane(fixture)
}

/// Each rebuild of the classless lane from its principal's row reads with
/// no class, as its live key did, not as the human class of the owner's
/// PERSON row, which the human-class row admits (round 2 review P1 of #9590,
/// frozen.rs:719).
#[test]
fn a_classless_saved_question_reads_no_claim_a_human_class_row_admits() {
    let fixture = fixture(ReadRow::HumanAdmitsBaseWorld);
    let frozen = classless_saved_lane_beside_human_row(&fixture);
    for (reader, (read, seen)) in [
        ("asker", asker_reads(&fixture, &frozen, fixture.claim)),
        ("source", source_reads(&fixture, &frozen, fixture.claim)),
    ] {
        assert!(
            !read,
            "actor=a key of the owner's id that names no class; expected its saved question's {reader} reader to read with no class, as its live key did, and refuse the claim only the human-class row admits; seen {seen}"
        );
    }
}

/// A caller's key that names a class has no meet with the classless lane:
/// the owner's own human-class key, and the principal's human-class key
/// under its access gate, as a question's arrival judge builds it
/// (`arrival::saved_lane_verdict_in_txn`), each read nothing (round 2 review
/// P1 of #9590, frozen.rs:719).
#[test]
fn a_classless_saved_lane_over_a_human_class_key_reads_nothing() {
    let fixture = fixture(ReadRow::HumanAdmitsBaseWorld);
    let frozen = classless_saved_lane_beside_human_row(&fixture);
    let gated = ScopedReadActorKey::with_actor_class(fixture.owner.to_hex(), "human")
        .expect("the principal's human-class key")
        .require_access_grants(Some(fixture.owner));
    let gated_reads = match frozen.narrow(&fixture.vault, gated) {
        Ok(key) => reads(&question_lane(&fixture, key), fixture.claim),
        Err(error) => (false, format!("rebuild={error:?}")),
    };
    for (reader, (read, seen)) in [
        (
            "the owner's own key",
            owner_key_reads(&fixture, &frozen, fixture.claim),
        ),
        (
            "the principal's human-class key under its access gate",
            gated_reads,
        ),
    ] {
        assert!(
            !read,
            "actor=a key of the owner's id that names no class; expected its saved lane, rebuilt over {reader}, to read nothing, not the claim only the human-class row admits; seen {seen}"
        );
    }
}

/// A key of the owner's id that names no class and holds no proof, floor,
/// exemption, Scope or bound (`ScopedReadActorKey::new`): unlike the
/// classless lane above, nothing narrows its lane.
fn unbound_classless_key(fixture: &Fixture) -> ScopedReadActorKey {
    let key = ScopedReadActorKey::new(fixture.owner.to_hex()).expect("a key that names no class");
    assert!(
        key.actor_class().is_none() && !key.reads_as_vault_owner(),
        "precondition: the key names no class and reads below the owner's floor; seen class {:?}",
        key.actor_class()
    );
    key
}

/// The lane the owner's standing question over the claim keeps, saved
/// through `key`'s live lane (`create_question_with_lane`) and read back
/// from the store, as the question's own reads find it.
fn stored_question_lane(fixture: &Fixture, key: ScopedReadActorKey) -> FrozenReadLane {
    use oneiron::WriteActor;
    use oneiron::llm::decision::questions::{
        QuestionActivation, QuestionDefinitionInput, RefreshPolicy, create_question_with_lane,
        read_question,
    };
    use oneiron::llm::decision::{
        AnswerContract, DecisionBand, DecisionClass, DecisionDial, DecisionQuestionInput,
        DecisionRung,
    };
    let definition = QuestionDefinitionInput {
        question: DecisionQuestionInput {
            text: "Does the owner still prefer the saved lane?".into(),
            class: DecisionClass::Judgment,
            contract: AnswerContract::Noul,
            accept_type: false,
        },
        adapter: "graph".into(),
        units: vec![fixture.claim],
        recipe: "unit".into(),
        profile: "fixture".into(),
        dial: DecisionDial {
            first: DecisionRung::Local,
            ceiling: DecisionRung::Local,
            band: DecisionBand::default(),
        },
        activation: QuestionActivation::Standing,
        refresh: RefreshPolicy {
            on_arrival: false,
            every_seconds: None,
        },
        delivery: "none".into(),
        learning: false,
        binding: None,
        criteria: Default::default(),
        audience: Default::default(),
        posture: None,
        media: Default::default(),
        deadline_ms: None,
        artifacts: Vec::new(),
    };
    let record = create_question_with_lane(
        &fixture.vault,
        WriteActor::new(fixture.owner, EdgeActorClass::Human),
        &fixture.vault.scoped_read(key),
        definition,
        2,
    )
    .expect("the owner's standing question over the claim is stored");
    read_question(
        &fixture.vault,
        fixture.owner,
        record.definition.question.id,
        None,
    )
    .expect("the stored question reads back")
    .expect("the stored question is found")
    .read_lane
}

/// A live owner's key that names no class, under no bound, refuses the
/// claim only the human-class row admits, as no row binds a key of no
/// class. Its question saved through that lane froze as its principal's
/// own, since the census names its actor a live owner, and every rebuild
/// read as the owner's PERSON, human, and read the claim (FIX
/// OWNER-LANE-WITHOUT-CLASS-REBUILDS-AS-HUMAN, Sol F2 on #8134). The lane
/// now keeps its grant basis, and each rebuild reads with no class, as its
/// live key did: the asker reader, the source reader, and the owner's own
/// human-class key met with the lane.
#[test]
fn an_unbound_classless_owner_key_saved_question_reads_no_claim_a_human_class_row_admits() {
    let fixture = fixture(ReadRow::HumanAdmitsBaseWorld);
    let (control, seen) = reads(
        &held_lane(&fixture, attenuated_device_key(&fixture)),
        fixture.claim,
    );
    assert!(
        control,
        "control: the human-class row admits the claim to the device's attenuated human-class credential; seen {seen}"
    );
    let key = unbound_classless_key(&fixture);
    let (live, seen) = reads(&held_lane(&fixture, key.clone()), fixture.claim);
    assert!(
        !live,
        "precondition: the unbound classless key's live lane, with no Scope and no row of its class, refuses the owner's claim; seen {seen}"
    );
    let frozen = stored_question_lane(&fixture, key);
    for (reader, (read, seen)) in [
        ("asker", asker_reads(&fixture, &frozen, fixture.claim)),
        ("source", source_reads(&fixture, &frozen, fixture.claim)),
        (
            "owner's own key",
            owner_key_reads(&fixture, &frozen, fixture.claim),
        ),
    ] {
        assert!(
            !read,
            "actor=a live owner's key that names no class, under no bound; expected its saved question's lane, rebuilt for the {reader} reader, to read with no class as its live key did and refuse the claim only the human-class row admits, not to read it as the owner's human PERSON; seen {seen}"
        );
    }
}

/// Guard: the owner's own human-class key still saves its question as its
/// principal's own lane, and the asker reader reads the claim.
#[test]
fn the_owners_own_key_saved_question_still_reads_as_its_principal() {
    let fixture = fixture(ReadRow::HumanAdmitsBaseWorld);
    let key = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .read_key()
        .expect("owner read key");
    let frozen = stored_question_lane(&fixture, key);
    assert!(
        frozen.is_principal(),
        "actor=the owner's own human-class key; expected its saved question to keep its principal's own lane"
    );
    let (read, seen) = asker_reads(&fixture, &frozen, fixture.claim);
    assert!(
        read,
        "actor=the owner's own human-class key; expected its saved question's asker reader to read the owner's claim; seen {seen}"
    );
}

/// A base-world claim the owner writes inside a relationship that no grant
/// names the owner on and that the owner is no member of: only a key no
/// gate binds, or one an owner's live binding lifts the gate of, reads it.
fn write_relationship_claim(fixture: &Fixture) -> EntityId {
    let relationship = EntityId::now();
    fixture
        .vault
        .put_entity(
            &relationship,
            ENTITY_TYPE_RELATIONSHIP,
            TimeRange { start: 1, end: 1 },
            1,
            b"relationship",
        )
        .expect("a relationship");
    write_owner_claim(
        &fixture.vault,
        fixture.owner,
        &fixture.owner_proof,
        ClaimRelationships::Relationships(vec![relationship.to_hex()]),
    )
}

/// A live owner's key that names no class, under no bound, reads the
/// owner's claim inside a relationship the owner holds no grant on: no gate
/// binds the key, and the class-neutral row admits a key of no class. Its
/// saved question keeps that reach while the owner's binding holds: each
/// rebuild from its principal's row lifts the relationship gate on that
/// binding, as the live key read past the gate, and reads with no class
/// and below the owner's floor (blind review P1 on #9716, rebuild.rs:117).
#[test]
fn an_unbound_classless_owner_key_saved_question_still_reads_its_ungated_relationship_claim() {
    let fixture = fixture(ReadRow::ClassNeutralAdmitsBaseWorld);
    let relationship_claim = write_relationship_claim(&fixture);
    let key = unbound_classless_key(&fixture);
    let (live, seen) = reads(&held_lane(&fixture, key.clone()), relationship_claim);
    assert!(
        live,
        "precondition: the unbound classless key's live lane, which no gate binds, reads the owner's relationship claim the class-neutral row admits; seen {seen}"
    );
    let frozen = stored_question_lane(&fixture, key);
    assert!(
        !frozen.is_principal() && !frozen.reads_as_principal(),
        "precondition: the classless key's saved question keeps its grant basis, not its principal's own lane"
    );
    for (reader, rebuilt) in [
        (
            "asker",
            saved_question_reader(&fixture.vault, fixture.owner, &frozen),
        ),
        (
            "source",
            saved_source_reader(&fixture.vault, fixture.owner, &frozen),
        ),
    ] {
        let rebuilt = rebuilt.expect("the saved question's reader rebuilds");
        assert!(
            rebuilt.actor_class().is_none() && !rebuilt.reads_as_vault_owner(),
            "actor=a live owner's key that names no class, under no bound; expected its saved question's {reader} reader to read with no class and below the owner's floor; seen class {:?}",
            rebuilt.actor_class()
        );
        let (read, seen) = reads(&question_lane(&fixture, rebuilt), relationship_claim);
        assert!(
            read,
            "actor=a live owner's key that names no class, under no bound; expected its saved question's {reader} reader to read the relationship claim its live lane read past the relationship gate, while the owner's binding holds; seen {seen}"
        );
    }
}
