//! `vault.lenses.export_pack` keeps a reader narrowed to some worlds inside
//! its scope (FIX 2136, `crates/oneiron/src/lens/pack_export.rs`): such a
//! reader is given a lens's frozen tree only where its read admits the
//! lens's intent NOTE, and it is answered FORBIDDEN, never NOT_FOUND, both
//! for a lens outside that scope and for a ref that names no lens, so it
//! learns of no lens outside its scope. Every call enters through
//! `oneiron_testkit::door::invoke`, the generated verb dispatch every
//! transport shares (ruling L4-23 = A).
//!
//! The narrowed reader is the owner on a credential whose scope grants one
//! world: not owner-grade, so its reads keep the credential's world
//! ceiling. The owner's own un-narrowed handle is the control: it exports
//! the lens the reader is refused, and a missing ref answers it NOT_FOUND.
//!
//! Red proof (one seeded head, two faults in `lens/pack_export.rs`): the
//! out-of-scope refusal is skipped (`if false && !in_scope`), and a missing
//! ref answers NOT_FOUND to a narrowed reader (`if false && narrowed`).
//! The two refusal tests fail there; the in-scope export passes.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test lens_export_narrowed_reader`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{HostSlipIssuer, MachineRole, VerifiedSlip};
use oneiron::federation::{ScopeAxis, ScopeId};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND, Memory, MemoryError};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_testkit::door;
use serde_json::{Value, json};

/// A 32-hex id nothing is stored under.
const SOME_ID: &str = "019a7218240070008000000000000001";

const CHALLENGE: &[u8] = b"oneiron-request:lens-export-narrowed-reader";

/// An owned vault rooted under the test host, its two worlds, a lens
/// proposed into each, and the owner's credential narrowed to `world_a`.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    narrowed: VerifiedSlip,
    lens_a: String,
    lens_b: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("a tempdir");
        // The open seeds the engine's weave lens pack Active
        // (`skill_hub/pack_catalog/lenses.rs`), the slot both lenses fill.
        let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("an owned open");
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("a live install profile to carry owner acts");
        let owner = vault.ensure_embedded_owner_actor().expect("the owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("an authenticated owner");
        let world_a = vault
            .create_world(&owner_proof, "Lens world", vault.now_recorded_at())
            .expect("the owner creates world A");
        let world_b = vault
            .create_world(&owner_proof, "Other lens world", vault.now_recorded_at())
            .expect("the owner creates world B");

        let (lens_a, lens_b) = {
            let memory = door::owner(&vault).expect("the owner's handle");
            (
                propose_in(&memory, world_a, "A card in world A."),
                propose_in(&memory, world_b, "A card in world B."),
            )
        };
        let narrowed = owner_credential(&vault, &issuer, owner, world_a);
        Self {
            _dir: dir,
            vault,
            owner,
            narrowed,
            lens_a,
            lens_b,
        }
    }

    /// The owner's un-narrowed handle.
    fn owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// The owner reading on the credential that grants world A only.
    fn narrowed_reader(&self) -> Memory<'_> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .with_read_proof(&self.narrowed)
    }
}

/// A credential minted for the owner as a `human` from the host root's
/// claims (as `tests/key_value_credential_read.rs` mints one), whose scope
/// grants `world` only, verified with its holder's signature.
fn owner_credential(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner: EntityId,
    world: EntityId,
) -> VerifiedSlip {
    let key = SigningKey::from_bytes(&[0x5a; 32]);
    let root = vault.ensure_host_root_slip(issuer).expect("the host root");
    let mut claims = root.claims;
    claims.slip_id = [0x5a; 32];
    claims.parent_id = None;
    claims.holder_ref = owner.to_hex();
    claims.binding_key = key.verifying_key().to_bytes();
    claims.actor_class = Some("human".to_owned());
    claims.scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(world)]));
    let slip = vault
        .mint_capability_slip(issuer, claims)
        .expect("mint the narrowed credential");
    let signature = key
        .sign(&slip.binding_transcript(CHALLENGE).expect("transcript"))
        .to_bytes();
    vault
        .verify_capability_slip(&issuer.public_key(), &slip, CHALLENGE, &signature)
        .expect("verify the narrowed credential")
}

/// The weave pack's slot as the owner reads its install, and a lens of one
/// closed `throbber` atom proposed into `world`, with `intent`. Answers the
/// lens ref.
fn propose_in(owner: &Memory<'_>, world: EntityId, intent: &str) -> String {
    let install = answered(
        door::invoke(owner, "vault.packs.get", json!({"name": "oneiron.weave"})),
        "packs.get oneiron.weave",
    );
    assert_eq!(
        install["status"],
        json!("active"),
        "the weave pack is Active: {install}"
    );
    let receipt = answered(
        door::invoke(
            owner,
            "vault.lenses.propose",
            json!({
                "slot": {
                    "pack_name": install["pack_name"],
                    "skill_id": install["skills"][0]
                },
                "pack_content_hash": install["content_hash"],
                "compiled": {
                    "kit_version": 3,
                    "apps_contract_version": 1,
                    "root": {
                        "id": "root",
                        "atom": {"kind": "throbber", "props": {"label": "loading"}},
                        "fallbackText": "loading"
                    }
                },
                "intent_prompt": intent,
                "scope": {"world": world.to_hex()}
            }),
        ),
        "propose",
    );
    assert_eq!(receipt["approval"], json!("proposed"), "{receipt}");
    receipt["lens_ref"].as_str().expect("lens_ref").to_owned()
}

fn export(caller: &Memory<'_>, lens_ref: &str) -> Result<Value, MemoryError> {
    door::invoke(
        caller,
        "vault.lenses.export_pack",
        json!({"lens_ref": lens_ref}),
    )
}

#[track_caller]
fn refused(result: Result<Value, MemoryError>, what: &str) -> MemoryError {
    match result {
        Err(error) => error,
        Ok(value) => panic!("{what} was answered, want a refusal: {value}"),
    }
}

#[track_caller]
fn answered(result: Result<Value, MemoryError>, what: &str) -> Value {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{what} was refused: {error:?}"),
    }
}

/// A reader narrowed to world A exports the lens placed in world A: the
/// file carries its frozen tree and the receipt names it.
#[test]
fn a_reader_narrowed_to_a_world_exports_a_lens_placed_there() {
    let fixture = Fixture::new();
    let reader = fixture.narrowed_reader();

    let export = answered(
        export(&reader, &fixture.lens_a),
        "the narrowed export of lens A",
    );
    let file: Value = serde_json::from_str(export["pack_json"].as_str().expect("pack_json"))
        .expect("a pack file");
    assert_eq!(
        file["compiled"]["root"]["atom"]["kind"],
        json!("throbber"),
        "the file carries the frozen tree: {file}"
    );
    assert_eq!(export["receipt"]["lens_ref"], json!(fixture.lens_a));
}

/// A reader narrowed to world A is refused the lens placed in world B with
/// FORBIDDEN, while the owner's own handle exports it.
/// Red: `if false && !in_scope` in `lenses_export_pack`.
#[test]
fn a_lens_outside_the_readers_worlds_is_refused_as_forbidden() {
    let fixture = Fixture::new();

    let control = answered(
        export(&fixture.owner(), &fixture.lens_b),
        "the owner's export of lens B",
    );
    assert_eq!(control["receipt"]["lens_ref"], json!(fixture.lens_b));

    let error = refused(
        export(&fixture.narrowed_reader(), &fixture.lens_b),
        "the narrowed export of lens B",
    );
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{error:?}");
}

/// A ref that names no lens answers a reader narrowed to some worlds
/// FORBIDDEN, as an out-of-scope lens does, so the answer tells it nothing
/// about lenses outside its scope; the owner's own handle is told
/// NOT_FOUND.
/// Red: `if false && narrowed` in the missing-lens arm.
#[test]
fn a_missing_lens_is_refused_to_a_narrowed_reader_as_forbidden_never_not_found() {
    let fixture = Fixture::new();

    let control = refused(
        export(&fixture.owner(), SOME_ID),
        "the owner's export of a missing lens",
    );
    assert_eq!(control.code, MEMORY_CODE_NOT_FOUND, "{control:?}");

    let error = refused(
        export(&fixture.narrowed_reader(), SOME_ID),
        "the narrowed export of a missing lens",
    );
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{error:?}");
}
