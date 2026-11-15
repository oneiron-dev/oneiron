//! L1-03 PR 3 (PLAN-L1-03 D12; ARCH-0028 `#mcp-tasks`, form questions):
//! `tasks.decline`, a seat holder's decline of an ask.
//!
//! The vault's owner asks two people, itself and a friend, one question about
//! a TURN. The owner declines through the verb by name: its own seat is void,
//! the friend's seat is untouched, and the ask stays open, to settle by its
//! own rules (a decline settles nothing and is never an approval). A repeat
//! changes nothing. A person the ask does not ask is refused in the words an
//! unknown handle gets, so the refusal never tells that the ask exists, and
//! voids no seat.
//!
//! Public paths only; no test door.
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test tasks_decline`.

use std::collections::BTreeSet;

use oneiron::federation::Scope;
use oneiron::policy_manifest_doors::{
    PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow, policy_manifests_as_owner,
    put_policy_manifest_as_owner,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::task_verb::{
    ConsultPayloadRef, TaskAskHandle, TaskAskOption, TaskAskOptionId, TaskAskQuestion, TaskAskSpec,
    TaskAskStatus, TaskAskTarget,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A vault, its owner, the friend the owner's ask also seats, an outsider it
/// does not ask, and the owner's open ask of both about one TURN.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    friend: EntityId,
    outsider: EntityId,
    ask: TaskAskHandle,
    _dir: tempfile::TempDir,
}

fn put_record(vault: &Vault, kind: u8, body: &[u8]) -> TestResult<EntityId> {
    let id = EntityId::now();
    let now = vault.now_recorded_at();
    vault.put_entity(
        &id,
        kind,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        body,
    )?;
    Ok(id)
}

fn fixture() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let friend = put_record(&vault, ENTITY_TYPE_PERSON, b"yuki")?;
    let outsider = put_record(&vault, ENTITY_TYPE_PERSON, b"owen")?;
    let question = put_record(
        &vault,
        ENTITY_TYPE_TURN,
        &rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "question")]))?,
    )?;
    // The ask's census binds a TURN only inside both parties' record scope,
    // and a bare holder's record reads are closed by default: the owner, the
    // friend and the outsider read the vault's records. The shipped rows stay.
    let proof = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        oneiron::store::GateDecisionId::now(),
    )?;
    let view =
        policy_manifests_as_owner(&vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .ok_or("default policy manifest missing")?;
    let mut manifest = default.manifest.clone();
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    for actor in [owner, friend, outsider] {
        rows.push(PolicyScopedGrantRow {
            // Bare census keys carry no actor class.
            actor_class: None,
            actor_ref: Some(actor.to_hex()),
            effector: "core:read".into(),
            scope: Scope::top(),
            selectors: None,
            budget: None,
            receipt_required: false,
        });
    }
    manifest.scoped_grants = Some(rows);
    put_policy_manifest_as_owner(
        &vault,
        &proof,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref.clone()),
            expected_body_hash: Some(default.body_hash.clone()),
            manifest,
        },
    )?;
    let mut what = TaskAskQuestion::new(ConsultPayloadRef::Turn(question));
    for (id, label) in [("shipped", "Shipped"), ("held", "Held back")] {
        what.options
            .insert(TaskAskOptionId::new(id)?, TaskAskOption::new(label));
    }
    let mut spec = TaskAskSpec::shorthand(
        Some(TaskAskTarget::People(BTreeSet::from([owner, friend]))),
        what,
        Some(vault.now_recorded_at() + 3600),
        Default::default(),
    );
    spec.intent_key = "release-shipped".into();
    let ask = vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_ask(&spec)?
        .handle;
    Ok(Fixture {
        vault,
        owner,
        friend,
        outsider,
        ask,
        _dir: dir,
    })
}

impl Fixture {
    /// `tasks.decline` on the ask, by name, as `person`.
    fn decline(&self, person: EntityId) -> Result<Value, oneiron::memory::MemoryError> {
        self.decline_handle(person, self.ask.group_ref)
    }

    /// `tasks.decline` on the ask handle `group_ref`, by name, as `person`.
    fn decline_handle(
        &self,
        person: EntityId,
        group_ref: EntityId,
    ) -> Result<Value, oneiron::memory::MemoryError> {
        oneiron::verbs::invoke(
            &self.vault.memory(person, EdgeActorClass::Human),
            "tasks.decline",
            json!({ "handle": { "group_ref": group_ref.to_hex() } }),
        )
    }

    /// The seats voided on the ask, as its asker reads them.
    fn voided(&self) -> TestResult<Vec<EntityId>> {
        Ok(self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .tasks_ask_option_link_voids(self.ask)?)
    }
}

#[test]
fn a_person_declines_only_their_own_seat() -> TestResult {
    let fx = fixture()?;
    assert!(fx.voided()?.is_empty(), "no seat is void before a decline");

    let declined = fx.decline(fx.owner).map_err(|error| {
        format!(
            "the owner declines its own seat: {}: {}",
            error.code, error.message
        )
    })?;
    assert_eq!(
        declined["handle"]["group_ref"],
        json!(fx.ask.group_ref.to_hex()),
        "{declined}"
    );
    let generation = declined["void_generation"]
        .as_u64()
        .ok_or_else(|| format!("a decline answers the void generation: {declined}"))?;
    assert!(generation >= 1, "{declined}");
    assert_eq!(
        fx.voided()?,
        vec![fx.owner],
        "only the decliner's seat is void; the friend's seat is untouched"
    );
    assert!(
        matches!(
            fx.vault
                .memory(fx.owner, EdgeActorClass::Human)
                .tasks_ask_status(fx.ask)?,
            TaskAskStatus::Pending { .. }
        ),
        "a decline settles nothing: the ask goes on to settle by its own rules"
    );

    let again = fx.decline(fx.owner).map_err(|error| {
        format!(
            "a repeated decline answers: {}: {}",
            error.code, error.message
        )
    })?;
    assert_eq!(
        again["void_generation"],
        json!(generation),
        "a repeat changes nothing"
    );

    let refused = fx
        .decline(fx.outsider)
        .err()
        .ok_or("a person the ask does not ask is refused")?;
    let unknown = fx
        .decline_handle(fx.outsider, EntityId::now())
        .err()
        .ok_or("an unknown ask handle is refused")?;
    assert_eq!(
        (&refused.code, &refused.message),
        (&unknown.code, &unknown.message),
        "a person the ask does not ask is refused as an unknown handle is: \
         the refusal never tells that the ask exists"
    );
    assert_eq!(
        fx.voided()?,
        vec![fx.owner],
        "a refused decline voids no seat"
    );
    assert!(
        !fx.voided()?.contains(&fx.friend),
        "the friend's seat stays"
    );
    Ok(())
}
