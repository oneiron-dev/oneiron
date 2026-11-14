//! A foreign copy is never a source for a write, nor re-shared to a third
//! party (L7-02; federation.md #model, Guest federation row: "Non-re-shareable
//! also means not a source for a write or for an answer to a third vault";
//! ARCH-0043 #leaving-a-company). A foreign copy is a claim in a WORLD of the
//! received foreign range: a pact's WORLD copy or a copied inquiry answer
//! (WORLD-COPY-SOURCE = A applies the rule to both). Each test puts one copy
//! with `Vault::put_claim`, as the inquiry landing writes one.
//!
//! Red on main: the batch citing the copy commits, the evidence predicate
//! admits the copy, the brief share naming its world is created, and the
//! guest ask's disclosure check does not refuse it. Guards (green on main
//! too): the same doors take a local claim, a local world, a TURN.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test foreign_copy_sources`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::access_grant::AccessGrantStatus;
use oneiron::authority::{HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole};
use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::consent::{AudienceBound, DisclosureClass, DisclosureEnvelope, GrantBound};
use oneiron::entity_id::ForeignWorldId;
use oneiron::note::TakeTarget;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::share::Share;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::task_verb::{
    ConsultPayloadRef, TaskAskDefault, TaskAskGuest, TaskAskQuestion, TaskAskSpec, TaskAskTarget,
};
use oneiron::test_doors::ask_guest::check_disclosure;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{
    Claim, Derived, Evidence, Named, batches_of, claim_evidence_admissible, commit,
    commit_with_sources, grant_core_read, source_version, supports,
};
use oneiron::test_doors::steward::dreamer;
use oneiron::test_doors::untangle_regressions::embedding_test_config;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::json;

const READER: &str = "reader";
const FOREIGN_COPY_REFUSAL: &str = "gate.deny.derive.source_foreign_copy";
/// The ask's own refusal (`tasks.ask.fact`), which tells nothing more.
const ASK_FACT_REFUSAL: &str = "tasks.ask.fact";
const T0: u64 = 1_800_000_000;

/// A received foreign WORLD, as a pact or an inquiry lands its copies in.
fn foreign_world() -> EntityId {
    ForeignWorldId::from_entity_id(EntityId::from_bytes([0xF0; 16]).expect("an id"))
        .expect("the seed sits in the foreign world id range")
        .entity_id()
}

/// A WORLD of this vault's own.
fn local_world() -> EntityId {
    EntityId::from_bytes([0x61; 16]).expect("an id")
}

fn put(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(&id, entity_type, TimeRange { start: at, end: at }, at, body)
        .expect("a row");
    id
}

/// An approved, active `profile.note` claim about `person`, with `source`,
/// in `world` (base reality when `None`).
fn put_claim(
    vault: &Vault,
    person: EntityId,
    value: &str,
    source: ClaimSource,
    world: Option<EntityId>,
) -> EntityId {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(person),
        rmpv::Value::from(value),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .expect("a claim body");
    body.source = Some(source);
    body.world = world;
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_claim(&id, &body, TimeRange { start: at, end: at }, at)
        .expect("the claim is stored");
    id
}

/// A local claim and its foreign copy about one person.
struct Rows {
    person: EntityId,
    local: EntityId,
    copy: EntityId,
}

fn rows(vault: &Vault) -> Rows {
    let person = put(vault, ENTITY_TYPE_PERSON, b"owen");
    let local = put_claim(
        vault,
        person,
        "owen takes his coffee black",
        ClaimSource::UserStated,
        None,
    );
    let copy = put_claim(
        vault,
        person,
        "owen is out Thursday",
        ClaimSource::Imported,
        Some(foreign_world()),
    );
    Rows {
        person,
        local,
        copy,
    }
}

/// A Dreamer vault holding the two claims.
struct DeriveFixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    dreamer: EntityId,
    rows: Rows,
}

fn derive_fixture() -> DeriveFixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let rows = rows(&vault);
    DeriveFixture {
        _dir: dir,
        vault,
        dreamer,
        rows,
    }
}

impl DeriveFixture {
    /// The version of `id` the Dreamer reads now. Guard: it reads the row, so
    /// a refusal below is never the withheld one.
    fn version(&self, id: EntityId) -> oneiron::snapshot_read::SourceVersion {
        source_version(&self.vault, self.dreamer, EdgeActorClass::System, id)
            .expect("read")
            .expect("the Dreamer reads the row")
    }

    /// A derived claim about the person, citing `evidence`.
    fn claim_citing(&self, evidence: EntityId) -> Derived {
        Derived::Claim(Claim {
            local: "coffee",
            predicate: "preference.coffee",
            subject: Named::Stored(self.rows.person),
            value: json!("an oat milk flat white"),
            evidence: vec![Named::Stored(evidence)],
        })
    }
}

#[test]
fn a_derived_claim_citing_a_foreign_copy_is_refused() {
    let fixture = derive_fixture();
    let copy = fixture.version(fixture.rows.copy);
    let refused = commit_with_sources(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-copy",
        &[fixture.claim_citing(fixture.rows.copy)],
        vec![copy],
    )
    .expect("commit");
    assert_eq!(
        refused,
        Err(vec![FOREIGN_COPY_REFUSAL.to_owned()]),
        "a batch citing a foreign copy aborts whole"
    );
    assert!(
        batches_of(&fixture.vault, fixture.dreamer)
            .expect("read")
            .is_empty(),
        "no batch is recorded"
    );

    // Guard: the same claim citing the local claim commits.
    let local = fixture.version(fixture.rows.local);
    let committed = commit_with_sources(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-local",
        &[fixture.claim_citing(fixture.rows.local)],
        vec![local],
    )
    .expect("commit");
    assert!(committed.is_ok(), "{committed:?}");
}

#[test]
fn evidence_from_a_foreign_copy_is_refused() {
    let fixture = derive_fixture();
    // Guard: the Dreamer reads the copy.
    fixture.version(fixture.rows.copy);
    let refused = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-evidence",
        &[Derived::Evidence(Evidence {
            local: "evidence",
            head: Named::Stored(fixture.rows.local),
            sources: vec![Named::Stored(fixture.rows.copy)],
        })],
    )
    .map(|committed| committed.items)
    .expect_err("evidence from a foreign copy aborts the batch");
    assert!(
        format!("{refused:?}").contains(FOREIGN_COPY_REFUSAL),
        "{refused:?}"
    );
    assert!(
        !supports(&fixture.vault, fixture.rows.copy, fixture.rows.local).expect("read"),
        "the copy supports nothing"
    );
}

#[test]
fn the_evidence_predicate_never_admits_a_foreign_copy() {
    let fixture = derive_fixture();
    assert!(
        !claim_evidence_admissible(&fixture.vault, fixture.rows.copy).expect("read"),
        "a foreign copy is no evidence for a write"
    );
    // Guard: an approved user-stated claim is.
    assert!(claim_evidence_admissible(&fixture.vault, fixture.rows.local).expect("read"));
}

/// One rooted, owner-bound vault, as `delegation_expiry_wall_clock.rs` opens
/// it for a brief share. The vault drops first.
struct ShareFixture {
    vault: Vault,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

fn share_fixture() -> ShareFixture {
    let clock = ManualClock::new(T0);
    let dir = tempfile::tempdir().expect("vault directory");
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("vault on its manual clock");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = HostSlipIssuer::from_seed(&[0x33; HOST_ISSUER_SEED_BYTES])
        .expect("independent host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
    ShareFixture {
        vault,
        owner,
        _dir: dir,
    }
}

/// Keeps the shipped policy, adding only the owner's permission to create a
/// brief share.
fn permit_brief_share(fixture: &ShareFixture) {
    let id = oneiron_store::policy_record::default_policy_manifest_id()
        .expect("the default manifest id");
    let bytes = fixture
        .vault
        .get(&id)
        .expect("read default manifest")
        .expect("the shipped manifest is stored");
    let mut manifest: serde_json::Value =
        rmp_serde::from_slice(&bytes).expect("decode shipped manifest");
    manifest["scoped_grants"]
        .as_array_mut()
        .expect("the shipped scoped-grant table")
        .push(json!({
            "actor_ref": fixture.owner.to_hex(),
            "effector": "external:share_brief",
            "scope": oneiron::test_support::effect_preset(),
            "selectors": { "channel": "shared_brief" },
        }));
    oneiron::test_support::put_policy_manifest_bytes(
        &fixture.vault,
        id,
        &rmp_serde::to_vec_named(&manifest).expect("encode share permission"),
    )
    .expect("store the share permission beside the shipped policy");
}

#[test]
fn a_brief_share_never_names_a_foreign_world() {
    let fixture = share_fixture();
    let recipient = EntityId::now();
    fixture
        .vault
        .put_entity(
            &recipient,
            ENTITY_TYPE_PERSON,
            TimeRange { start: T0, end: T0 },
            T0,
            b"yuki",
        )
        .expect("live recipient PERSON");
    let brief = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .author_take(TakeTarget::Subject(recipient), "A brief for yuki")
        .expect("stored NOTE brief")
        .id_hex;
    permit_brief_share(&fixture);
    let share = |world: EntityId| Share {
        recipient_ref: recipient,
        brief_ref: brief.clone(),
        world_refs: BTreeSet::from([world]),
        facet_refs: BTreeSet::new(),
        include_unscoped: false,
        status: AccessGrantStatus::Active,
        created_at: T0,
        revoked_at: None,
        expires_at: Some(T0 + 100),
        mention: None,
    };
    let issuer = WriteActor::new(fixture.owner, EdgeActorClass::Human);

    let foreign = EntityId::now();
    let created = fixture
        .vault
        .create_share(&foreign, &issuer, &share(foreign_world()));
    assert!(
        created.is_err(),
        "a brief share naming a foreign WORLD is refused: {created:?}"
    );
    assert!(
        fixture.vault.get_share(&foreign).expect("read").is_none(),
        "no share is stored"
    );

    // Guard: the same share over a local WORLD is created.
    let local = EntityId::now();
    fixture
        .vault
        .create_share(&local, &issuer, &share(local_world()))
        .expect("a brief share over a local WORLD");
    assert!(fixture.vault.get_share(&local).expect("read").is_some());
}

/// An owner-bound vault holding the two claims, a question TURN, and a
/// guest's companion who reads them, with the owner's record of the guest's
/// consent to see the question, the local claim and the copy.
struct AskFixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    rows: Rows,
    question: EntityId,
    guest: TaskAskGuest,
}

fn ask_fixture() -> AskFixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), embedding_test_config()).expect("vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
    let rows = rows(&vault);
    let companion = put(&vault, ENTITY_TYPE_PERSON, b"companion");
    // The companion reads what the ask shows (the answer unit check reads
    // each fact as the asker and as the companion).
    grant_core_read(&vault, companion).expect("the companion's read");
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "question")]))
        .expect("a TURN body");
    let question = put(&vault, ENTITY_TYPE_TURN, &body);
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let bound = GrantBound::disclosure(
        AudienceBound::new([owner.to_hex(), rows.person.to_hex()]).expect("audience"),
        DisclosureClass::new("meeting").expect("class"),
        DisclosureEnvelope::new([question, rows.local, rows.copy].map(|id| id.to_hex()))
            .expect("envelope"),
    )
    .expect("a disclosure bound");
    let disclosure_grant_ref = bound.digest().to_hex();
    vault
        .create_standing_grant(&proof, bound)
        .expect("the owner records the guest's consent");
    let guest = TaskAskGuest {
        companion_ref: companion,
        disclosure_grant_ref,
        holder_key: None,
    };
    AskFixture {
        _dir: dir,
        vault,
        owner,
        rows,
        question,
        guest,
    }
}

impl AskFixture {
    /// The owner's ask of the guest about the question, showing `context`.
    fn spec(&self, context: &[EntityId]) -> TaskAskSpec {
        let mut question = TaskAskQuestion::new(ConsultPayloadRef::Turn(self.question));
        question.class_key = Some("meeting".into());
        question.context_refs = context
            .iter()
            .map(|id| ConsultPayloadRef::Claim(*id))
            .collect();
        TaskAskSpec::shorthand(
            Some(TaskAskTarget::Guests(
                [(self.rows.person, self.guest.clone())].into(),
            )),
            question,
            None,
            TaskAskDefault::AskMe,
        )
    }

    fn check(&self, context: &[EntityId]) -> oneiron::Result<BTreeSet<EntityId>> {
        check_disclosure(
            &self.vault,
            self.rows.person,
            self.owner,
            &self.guest,
            &self.spec(context),
        )
    }
}

#[test]
fn an_ask_never_discloses_a_foreign_copy_to_a_guest() {
    let fixture = ask_fixture();
    // Guard: the ask showing only its question is admitted.
    assert_eq!(
        fixture.check(&[]).expect("the question alone is disclosed"),
        BTreeSet::from([fixture.question])
    );
    let shown = fixture.check(&[fixture.rows.copy]);
    assert!(
        shown
            .as_ref()
            .is_err_and(|error| format!("{error:?}").contains(ASK_FACT_REFUSAL)),
        "an ask showing a foreign copy to a guest is refused as the ask's own: {shown:?}"
    );
}

#[test]
fn an_ask_discloses_a_local_claim_to_a_guest() {
    let fixture = ask_fixture();
    assert_eq!(
        fixture
            .check(&[fixture.rows.local])
            .expect("a local claim the owner disclosed"),
        BTreeSet::from([fixture.question, fixture.rows.local])
    );
}
