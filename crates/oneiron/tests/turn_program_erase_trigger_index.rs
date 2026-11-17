//! An erased actor keeps no trigger index row (FIX-LIST L23270): a timer arming whose row
//! does not decode keeps no due row past the erase, and an idle arming whose row does not
//! decode keeps no trigger row. A decodable arming's rows go as before, and another actor's
//! rows are left alone.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test turn_program_erase_trigger_index`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::holder_proof_challenge;
use oneiron::dreamer_runner::{ArmTurnProgram, ProgramTrigger};
use oneiron::federation::ScopeAxis;
use oneiron::skill::{
    SkillCallContract, SkillLifecycle, SkillRecord, SkillRole, canonical_skill_tree_hash,
};
use oneiron::test_doors::turn_programs as doors;
use oneiron::test_support::test_host_issuer;
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};

/// A due time well past any clock the vault records in a test.
const T0: u64 = 4_000_000_000;

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

/// The vault's owner, its active callable, and arming on `trigger` for that owner.
struct Fixture {
    owner: EntityId,
    skill: EntityId,
}

impl Fixture {
    fn new(vault: &Vault) -> Self {
        Self {
            owner: vault.ensure_embedded_owner_actor().expect("owner"),
            skill: active_callable_skill(vault),
        }
    }

    fn arm(&self, vault: &Vault, trigger: ProgramTrigger) -> EntityId {
        vault
            .memory(self.owner, EdgeActorClass::Human)
            .arm_turn_program(&ArmTurnProgram {
                skill: self.skill,
                executor: "fixture.executor@1".into(),
                args: serde_json::json!({"value": 41}),
                conversation: None,
                trigger,
            })
            .expect("arm")
            .registration
    }
}

/// An agent principal, a read/write capability slip bound to its own holder key, and the
/// slip's instrument, verified as a host binds a request's.
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
    let challenge = holder_proof_challenge(vault.now_recorded_at(), "turn-program-erase");
    let signature = holder
        .sign(&slip.binding_transcript(&challenge).unwrap())
        .to_bytes();
    let binding = vault
        .bind_invocation_slip(&slip, &challenge, &signature)
        .unwrap();
    let verified = vault.verify_invocation_slip(&binding).unwrap();
    (agent, verified, binding)
}

/// A damaged timer arming keeps no due row past its actor's erase: the erase takes the due
/// index row it cannot read the due time from.
#[test]
fn a_damaged_timer_keeps_no_due_row_past_its_actors_erase() {
    let (_dir, vault) = open();
    let fixture = Fixture::new(&vault);
    let registration = fixture.arm(
        &vault,
        ProgramTrigger::Timer {
            first_at: T0,
            every_secs: 0,
        },
    );
    assert_eq!(
        doors::timer_due_rows_for_actor(&vault, fixture.owner).expect("due rows"),
        vec![(T0, registration)]
    );

    doors::damage_arming_row(&vault, fixture.owner, registration).expect("damage the arming");
    doors::erase_actor_programs(&vault, fixture.owner).expect("erase");

    assert!(
        !doors::program_armed_here(&vault, fixture.owner, registration).expect("armed read"),
        "the erase takes the damaged arming"
    );
    let rows = doors::timer_due_rows_for_actor(&vault, fixture.owner).expect("due rows");
    assert!(
        rows.is_empty(),
        "the damaged timer's due row lingers past the erase: {rows:?}"
    );
}

/// A damaged idle arming keeps no trigger row past its actor's erase.
#[test]
fn a_damaged_idle_program_keeps_no_trigger_row_past_its_actors_erase() {
    let (_dir, vault) = open();
    let fixture = Fixture::new(&vault);
    let registration = fixture.arm(&vault, ProgramTrigger::Idle { quiet_secs: 600 });
    let rows = doors::trigger_rows_for_actor(&vault, fixture.owner).expect("trigger rows");
    assert_eq!(rows.len(), 1, "the idle arming keeps one trigger row");
    assert_eq!(rows[0].1, registration);

    doors::damage_arming_row(&vault, fixture.owner, registration).expect("damage the arming");
    doors::erase_actor_programs(&vault, fixture.owner).expect("erase");

    assert!(
        !doors::program_armed_here(&vault, fixture.owner, registration).expect("armed read"),
        "the erase takes the damaged arming"
    );
    let rows = doors::trigger_rows_for_actor(&vault, fixture.owner).expect("trigger rows");
    assert!(
        rows.is_empty(),
        "the damaged idle program's trigger row lingers past the erase: {rows:?}"
    );
}

/// An erase still drops a decodable arming's trigger rows: the timer's due row and the idle
/// program's trigger row go with their armings.
#[test]
fn an_erase_drops_a_decodable_armings_trigger_rows() {
    let (_dir, vault) = open();
    let fixture = Fixture::new(&vault);
    let timer = fixture.arm(
        &vault,
        ProgramTrigger::Timer {
            first_at: T0,
            every_secs: 0,
        },
    );
    let idle = fixture.arm(&vault, ProgramTrigger::Idle { quiet_secs: 600 });
    assert_eq!(
        doors::timer_due_rows_for_actor(&vault, fixture.owner).expect("due rows"),
        vec![(T0, timer)]
    );
    assert_eq!(
        doors::trigger_rows_for_actor(&vault, fixture.owner)
            .expect("trigger rows")
            .len(),
        1
    );

    doors::erase_actor_programs(&vault, fixture.owner).expect("erase");

    assert!(
        doors::timer_due_rows_for_actor(&vault, fixture.owner)
            .expect("due rows")
            .is_empty()
    );
    assert!(
        doors::trigger_rows_for_actor(&vault, fixture.owner)
            .expect("trigger rows")
            .is_empty()
    );
    assert!(!doors::program_armed_here(&vault, fixture.owner, timer).expect("armed read"));
    assert!(!doors::program_armed_here(&vault, fixture.owner, idle).expect("armed read"));
}

/// An erase leaves another actor's trigger rows alone: only the erased actor's rows go.
#[test]
fn an_erase_leaves_another_actors_trigger_rows() {
    let (_dir, vault) = open();
    let fixture = Fixture::new(&vault);
    let damaged = fixture.arm(
        &vault,
        ProgramTrigger::Timer {
            first_at: T0,
            every_secs: 0,
        },
    );
    doors::damage_arming_row(&vault, fixture.owner, damaged).expect("damage the arming");
    let (bystander, proof, binding) = agent_slip(&vault);
    let kept = doors::plant_timer_arming(&vault, bystander, &proof, &binding, 100, T0 + 3_600)
        .expect("plant the bystander's timer");

    doors::erase_actor_programs(&vault, fixture.owner).expect("erase");

    assert!(
        doors::timer_due_rows_for_actor(&vault, fixture.owner)
            .expect("due rows")
            .is_empty(),
        "the erased actor's damaged timer keeps its due row"
    );
    assert_eq!(
        doors::timer_due_rows_for_actor(&vault, bystander).expect("due rows"),
        vec![(T0 + 3_600, kept)]
    );
}
