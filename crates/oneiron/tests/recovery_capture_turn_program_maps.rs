//! A canonical window capture takes a month whose reverse pass filed the
//! turn-program carrier maps (FIX-LIST row RECOVERY-CAPTURE-TURN-PROGRAM-MAPS)
//! or the origin-position map (FIX 26753): `turn_program_arms`,
//! `turn_program_wakes` and `origin_positions` ride base windows, and the
//! capture allowlists them as not captured instead of refusing the month with
//! "unknown Layer-1 window container".
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test recovery_capture_turn_program_maps`.
#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use loro::{LoroDoc, LoroValue};
use oneiron::dreamer_runner::{ArmTurnProgram, ProgramTrigger};
use oneiron::recovery::capture_canonical_window;
use oneiron::registry::ENTITY_TYPE_ASSET;
use oneiron::skill::{
    SkillCallContract, SkillLifecycle, SkillRecord, SkillRole, canonical_skill_tree_hash,
};
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::reverse_rematerialize;
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault,
    VaultConfig,
};

#[cfg(oneiron_test_support)]
use ed25519_dalek::{Signer, SigningKey};
#[cfg(oneiron_test_support)]
use oneiron::authority::holder_proof_challenge;
#[cfg(oneiron_test_support)]
use oneiron::federation::ScopeAxis;
#[cfg(oneiron_test_support)]
use oneiron::registry::ENTITY_TYPE_TURN;
#[cfg(oneiron_test_support)]
use oneiron::test_doors::turn_programs as doors;
#[cfg(oneiron_test_support)]
use oneiron::test_support::test_host_issuer;

/// The base window the wake test lands in: March 2026.
#[cfg(oneiron_test_support)]
const WINDOW: &str = "2026-03";
/// 2026-03-15 00:00 UTC, inside [`WINDOW`].
#[cfg(oneiron_test_support)]
const T0: u64 = 1_773_532_800;

fn open() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    (dir, vault)
}

/// An active callable SKILL, enough to arm: arming pins the record and never loads its source.
fn active_callable_skill(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    let files: [(&str, &[u8]); 2] = [
        (
            "SKILL.md",
            b"---\nname: fixture.callable\ndescription: Increment a number\nversion: 1\nrole: callable\ncall:\n  reference: scripts/call.js\n  arguments: {\"value\":\"integer\"}\n  returns: {\"result\":\"integer\"}\n---\nAn executable fixture.\n",
        ),
        (
            "scripts/call.js",
            b"finish(JSON.stringify({result:skillArgs.value + 1}));",
        ),
    ];
    let hash = canonical_skill_tree_hash(files).expect("hash the fixture tree");
    let mut record = SkillRecord::new(
        "fixture.callable",
        "Increment a number",
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        0.5,
        true,
        false,
        vec![],
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("fixture"),
        )]),
    )
    .with_role(
        SkillRole::Callable,
        Some(SkillCallContract {
            reference: "scripts/call.js".into(),
            arguments: serde_json::json!({"value": "integer"}),
            returns: serde_json::json!({"result": "integer"}),
        }),
    )
    .with_content_hash(hash);
    vault
        .put_skill_record(&id, &record, TimeRange { start: 1, end: 1 }, 1)
        .expect("put the callable candidate");
    record.lifecycle_status = SkillLifecycle::Active;
    vault
        .update_skill_record(&id, &record, TimeRange { start: 2, end: 2 }, 2)
        .expect("activate the callable");
    id
}

/// Whether the document holds the root map `name`. A shallow read: looking a
/// root up by name would create it.
fn has_root(doc: &LoroDoc, name: &str) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key(name))
}

/// A month in which a turn program was armed captures: the reverse pass files
/// its `turn_program_arms` map, and the capture takes the month anyway.
#[test]
fn armed_turn_program_month_captures_with_its_arms_map() {
    let (_dir, vault) = open();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let skill = active_callable_skill(&vault);
    vault
        .memory(owner, EdgeActorClass::Human)
        .arm_turn_program(&ArmTurnProgram {
            skill,
            executor: "fixture.executor@1".into(),
            args: serde_json::json!({"value": 41}),
            conversation: None,
            trigger: ProgramTrigger::Turn,
        })
        .expect("arm");
    let window = WindowKey::from_timestamp(vault.now_recorded_at());
    let doc = LoroDoc::new();
    reverse_rematerialize(&vault, &doc, &window).expect("reverse");
    assert!(
        has_root(&doc, "turn_program_arms"),
        "the reverse pass filed no arms map for the armed month"
    );
    capture_canonical_window(&vault, window.as_str(), &doc).expect("capture the armed month");
}

/// On `vault`: an agent principal, a read/write capability slip bound to its
/// own holder key, and the slip's instrument, verified as a host binds a
/// request's.
#[cfg(oneiron_test_support)]
fn agent_slip(
    vault: &Vault,
) -> (
    EntityId,
    oneiron::authority::VerifiedSlip,
    oneiron::authority::InvocationSlipBinding,
) {
    let issuer = test_host_issuer();
    let agent = vault.ensure_agent_principal("turn-program-agent").unwrap();
    let holder = SigningKey::from_bytes(&[7; 32]);
    let mut claims = vault.ensure_host_root_slip(&issuer).unwrap().claims;
    claims.slip_id = [0x5a; 32];
    claims.parent_id = None;
    claims.holder_ref = agent.to_hex();
    claims.binding_key = holder.verifying_key().to_bytes();
    claims.actor_class = Some("agent".into());
    claims.scope.verbs = ScopeAxis::Some(["read".into(), "write".into()].into());
    let slip = vault.mint_capability_slip(&issuer, claims).unwrap();
    let challenge = holder_proof_challenge(vault.now_recorded_at(), "turn-program-sync");
    let signature = holder
        .sign(&slip.binding_transcript(&challenge).unwrap())
        .to_bytes();
    let binding = vault
        .bind_invocation_slip(&slip, &challenge, &signature)
        .unwrap();
    let verified = vault.verify_invocation_slip(&binding).unwrap();
    (agent, verified, binding)
}

/// A TURN learned at [`T0`], so it lands in [`WINDOW`].
#[cfg(oneiron_test_support)]
fn put_turn(vault: &Vault) -> EntityId {
    let turn = EntityId::from_bytes([0x61; 16]).unwrap();
    let body =
        rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")])).unwrap();
    vault
        .put_entity(
            &turn,
            ENTITY_TYPE_TURN,
            TimeRange { start: T0, end: T0 },
            T0,
            &body,
        )
        .unwrap();
    turn
}

/// A month whose TURN owes a program a wake captures: the reverse pass files
/// its `turn_program_wakes` map beside the arming, and the capture takes the
/// month anyway.
#[cfg(oneiron_test_support)]
#[test]
fn landed_turn_wake_month_captures_with_its_wakes_map() {
    let (_dir, vault) = open();
    // No home is elected, so the wake rides for the home to admit.
    let (agent, slip, instrument) = agent_slip(&vault);
    let turn = put_turn(&vault);
    let conversation = EntityId::from_bytes([0x62; 16]).unwrap();
    doors::plant_slip_wake(
        &vault,
        agent,
        &slip,
        &instrument,
        conversation,
        turn,
        T0 - 60,
        T0,
    )
    .unwrap();
    let window = WindowKey::new(WINDOW);
    let doc = LoroDoc::new();
    reverse_rematerialize(&vault, &doc, &window).expect("reverse");
    assert!(
        has_root(&doc, "turn_program_wakes"),
        "the reverse pass filed no wakes map for the owed wake"
    );
    assert!(
        has_root(&doc, "turn_program_arms"),
        "the reverse pass filed no arms map beside the owed wake"
    );
    capture_canonical_window(&vault, WINDOW, &doc).expect("capture the wake month");
}

/// A month in which an ASSET was born captures: the reverse pass files its
/// `origin_positions` map beside the carrier, and the capture takes the month
/// anyway (FIX 26753).
#[test]
fn asset_birth_month_captures_with_its_origin_positions_map() {
    let (_dir, vault) = open();
    let at = vault.now_recorded_at();
    let asset = EntityId::now();
    let facet = vault.default_facet().expect("default facet");
    vault
        .batch()
        .put(
            &asset,
            ENTITY_TYPE_ASSET,
            TimeRange { start: at, end: at },
            at,
            b"origin-positions fixture body",
        )
        .edge(&asset, EdgeKind::FacetOf, &facet, 1.0)
        .commit()
        .expect("birth the asset with its facet");
    let window = WindowKey::from_timestamp(at);
    let doc = LoroDoc::new();
    reverse_rematerialize(&vault, &doc, &window).expect("reverse");
    assert!(
        has_root(&doc, "origin_positions"),
        "the reverse pass filed no origin positions for the asset birth month"
    );
    capture_canonical_window(&vault, window.as_str(), &doc).expect("capture the asset month");
}
