//! A foreign copy is never a source for a write, nor re-shared to a third
//! party (L7-02; federation.md #model, Guest federation row: "Non-re-shareable
//! also means not a source for a write or for an answer to a third vault";
//! ARCH-0043 #leaving-a-company). A foreign copy is a claim in a WORLD of the
//! received foreign range: a pact's WORLD copy or a copied inquiry answer
//! (WORLD-COPY-SOURCE = A applies the rule to both). Each test puts one copy
//! with `Vault::put_claim`, as the inquiry landing writes one.
//!
//! Red on main: the batch citing the copy commits, the evidence predicate
//! admits the copy, a SameAs link with the copy as an endpoint lands, the
//! person's `about` facts take the copy in, a profile read from the copy is
//! stored (through a derivation and directly), a model's proposal whose
//! prompt carried the copy is stored (also when the copy was erased between
//! the prompt and the proposal), the brief share naming its world is
//! created, and the guest ask's disclosure check does not refuse it. Guards
//! (green on main too): the same doors take a local claim, a local world, a
//! TURN.
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
use oneiron::deletion::DeleteEntityOptions;
use oneiron::entity_id::ForeignWorldId;
use oneiron::memory::{ClaimInput, CommitReceipt, MemoryResult};
use oneiron::note::TakeTarget;
use oneiron::psych_profile::{
    PsychProfile, PsychProfileConfidence, PsychProfileKey, PsychProfileSource,
    PsychProfileSourceWords, psych_profile_entity_id,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::share::Share;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::store::revision_ref::RevisionRef;
use oneiron::task_verb::{
    ConsultPayloadRef, TaskAskDefault, TaskAskGuest, TaskAskQuestion, TaskAskSpec, TaskAskTarget,
};
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{
    Claim, Derived, Evidence, Named, Profile, SameAs, about_facts, batches_of,
    claim_evidence_admissible, commit, commit_with_sources, grant_core_read, profile_stored,
    source_version, supports,
};
use oneiron::test_doors::guest_ask_disclosure::check_disclosure;
use oneiron::test_doors::steward::dreamer;
use oneiron::test_doors::untangle_regressions::embedding_test_config;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::json;

const READER: &str = "reader";
const FOREIGN_COPY_REFUSAL: &str = "gate.deny.source_foreign_copy";
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

impl DeriveFixture {
    /// Commits the Dreamer's SameAs link of `source` to `target`: whether it
    /// landed, and its reasons.
    fn commit_same_as(&self, run: &str, source: EntityId, target: EntityId) -> (bool, Vec<String>) {
        let committed = commit(
            &self.vault,
            self.dreamer,
            EdgeActorClass::System,
            run,
            &[Derived::SameAs(SameAs {
                local: "same_as",
                source: Named::Stored(source),
                target: Named::Stored(target),
            })],
        )
        .expect("commit");
        let [item] = committed.items.as_slice() else {
            panic!("one item: {:?}", committed.items);
        };
        (item.landed, item.reasons.clone())
    }
}

#[test]
fn a_same_as_link_with_a_foreign_copy_endpoint_is_refused() {
    let fixture = derive_fixture();
    // Guard: the Dreamer reads the copy, so the refusal is never the unread one.
    fixture.version(fixture.rows.copy);
    let (local, copy) = (fixture.rows.local, fixture.rows.copy);
    for (run, source, target) in [
        ("run-link-to-copy", local, copy),
        ("run-link-from-copy", copy, local),
    ] {
        assert_eq!(
            fixture.commit_same_as(run, source, target),
            (false, vec![FOREIGN_COPY_REFUSAL.to_owned()]),
            "{run}: the link's status claim would cite the foreign copy"
        );
    }

    // Guard: a link between two local claims lands.
    let other = put_claim(
        &fixture.vault,
        fixture.rows.person,
        "owen drinks his coffee black",
        ClaimSource::UserStated,
        None,
    );
    let (landed, reasons) = fixture.commit_same_as("run-link-local", local, other);
    assert!(landed, "the local link lands: {reasons:?}");
}

/// The digest and bands of `person`'s facts the Dreamer's `about` lines are
/// asked from.
fn person_about_facts(vault: &Vault, dreamer: EntityId, person: EntityId) -> ([u8; 32], Vec<u8>) {
    about_facts(vault, dreamer, EdgeActorClass::System, person).expect("the person's facts")
}

#[test]
fn a_persons_about_facts_never_hold_a_foreign_copy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let person = put(&vault, ENTITY_TYPE_PERSON, b"owen");
    put_claim(
        &vault,
        person,
        "owen takes his coffee black",
        ClaimSource::UserStated,
        None,
    );
    let before = person_about_facts(&vault, dreamer, person);
    // Guard: the local claim is a fact the lines are asked from.
    assert!(!before.1.is_empty(), "the person has a local fact");

    let copy = put_claim(
        &vault,
        person,
        "owen is out Thursday",
        ClaimSource::Imported,
        Some(foreign_world()),
    );
    // Guard: the Dreamer reads the copy, so it is left out as a copy, not
    // as a row it cannot read.
    assert!(
        source_version(&vault, dreamer, EdgeActorClass::System, copy)
            .expect("read")
            .is_some(),
        "the Dreamer reads the copy"
    );
    assert_eq!(
        person_about_facts(&vault, dreamer, person),
        before,
        "the foreign copy adds no fact to the person's about lines"
    );

    // Guard: another local claim does.
    put_claim(
        &vault,
        person,
        "owen works from the Lisbon office",
        ClaimSource::UserStated,
        None,
    );
    assert_ne!(
        person_about_facts(&vault, dreamer, person).0,
        before.0,
        "a local fact is taken in"
    );
}

impl DeriveFixture {
    /// Commits the Dreamer's profile of the person read from `document`:
    /// whether it landed, and its reasons.
    fn commit_profile(&self, run: &str, document: EntityId) -> (bool, Vec<String>) {
        let committed = commit(
            &self.vault,
            self.dreamer,
            EdgeActorClass::System,
            run,
            &[Derived::Profile(Profile {
                local: "profile",
                subject: self.rows.person,
                document,
            })],
        )
        .expect("commit");
        let [item] = committed.items.as_slice() else {
            panic!("one item: {:?}", committed.items);
        };
        (item.landed, item.reasons.clone())
    }
}

#[test]
fn a_derived_profile_read_from_a_foreign_copy_is_refused() {
    let fixture = derive_fixture();
    // Guard: the Dreamer reads the copy, so the refusal is never the unread one.
    fixture.version(fixture.rows.copy);
    assert_eq!(
        fixture.commit_profile("run-profile-copy", fixture.rows.copy),
        (false, vec![FOREIGN_COPY_REFUSAL.to_owned()]),
        "a profile read from a foreign copy is refused"
    );
    assert!(
        !profile_stored(&fixture.vault, fixture.rows.person).expect("read"),
        "no profile is stored"
    );

    // Guard: the same profile read from the local claim lands.
    let (landed, reasons) = fixture.commit_profile("run-profile-local", fixture.rows.local);
    assert!(landed, "the profile lands: {reasons:?}");
    assert!(profile_stored(&fixture.vault, fixture.rows.person).expect("read"));
}

/// The profile of `subject` read whole from `document`, as the derive
/// door's `Profile` item builds it.
fn whole_record_profile(subject: EntityId, document: EntityId) -> PsychProfile {
    PsychProfile::new(
        subject,
        "steady and curious",
        "A steady, curious person.",
        "They meet new things steadily and with curiosity.",
        vec![document],
        PsychProfileConfidence::new(0.8, 0.7, 0.6).expect("a confidence"),
    )
    .expect("a profile")
    .with_sources(vec![PsychProfileSource {
        revision_ref: document,
        document_ref: document,
        world_ref: None,
        document_revision: RevisionRef([0; 16]),
        words: PsychProfileSourceWords::Record { content: [0; 32] },
    }])
    .expect("its source")
}

#[test]
fn a_profile_put_from_a_foreign_copy_is_refused() {
    let fixture = derive_fixture();
    let person = fixture.rows.person;
    let id = psych_profile_entity_id(&PsychProfileKey {
        person,
        facet: None,
        world: None,
    });
    let refused = fixture
        .vault
        .put_psych_profile(&id, &whole_record_profile(person, fixture.rows.copy))
        .expect_err("a profile read from a foreign copy is refused");
    assert!(
        format!("{refused:?}").contains(FOREIGN_COPY_REFUSAL),
        "{refused:?}"
    );
    assert!(
        !profile_stored(&fixture.vault, person).expect("read"),
        "no profile is stored"
    );

    // Guard: the same profile read from the local claim is stored.
    fixture
        .vault
        .put_psych_profile(&id, &whole_record_profile(person, fixture.rows.local))
        .expect("a profile read from a local claim is stored");
    assert!(profile_stored(&fixture.vault, person).expect("read"));
}

/// A vault where an agent that reads proposes, as
/// `claim_approval_recall.rs` opens one.
struct PromptFixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    agent: EntityId,
    rows: Rows,
}

fn prompt_fixture() -> PromptFixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    vault.ensure_embedded_owner_actor().expect("the owner");
    let rows = rows(&vault);
    let agent = put(&vault, ENTITY_TYPE_PERSON, b"yuki");
    vault
        .install_read_permit_for_test(WriteActor::new(agent, EdgeActorClass::Agent))
        .expect("the agent reads");
    PromptFixture {
        _dir: dir,
        vault,
        agent,
        rows,
    }
}

impl PromptFixture {
    /// The agent's proposal `id` about the person, from a prompt that
    /// carried `producers`.
    fn propose(&self, id: EntityId, producers: &[EntityId]) -> MemoryResult<CommitReceipt> {
        let input = ClaimInput {
            id: Some(id.to_hex()),
            predicate: "profile.note".to_owned(),
            subject_ref: self.rows.person.to_hex(),
            value: json!("owen is away this week"),
            confidence: 0.8,
            source: "generated".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
            confidence_details: None,
        };
        self.vault
            .memory(self.agent, EdgeActorClass::Agent)
            .claim_propose_prompted(
                &input,
                "test.prompted",
                producers,
                &[b"what the model read".as_slice()],
            )
    }

    /// `id` was refused as a proposal sourced from a foreign copy, and is
    /// not stored.
    fn assert_refused(&self, id: EntityId, producers: &[EntityId]) {
        let refused = self
            .propose(id, producers)
            .expect_err("a proposal from a prompt that carried a foreign copy is refused");
        assert_eq!(
            refused
                .gate_denial
                .as_ref()
                .map(|denial| denial.reason_codes.clone()),
            Some(vec![FOREIGN_COPY_REFUSAL.to_owned()]),
            "{refused:?}"
        );
        assert!(
            self.vault.get_claim(&id).expect("read").is_none(),
            "no proposal is stored"
        );
    }

    /// `id` is stored, proposed.
    fn assert_proposed(&self, id: EntityId, producers: &[EntityId]) {
        let receipt = self
            .propose(id, producers)
            .expect("a proposal from a prompt that carried local claims is stored");
        assert_eq!(receipt.approval, "proposed");
        assert!(self.vault.get_claim(&id).expect("read").is_some());
    }
}

#[test]
fn a_proposal_from_a_prompt_that_carried_a_foreign_copy_is_refused() {
    let fixture = prompt_fixture();
    fixture.assert_refused(EntityId::now(), &[fixture.rows.copy]);
    // Guard: the same proposal from a prompt that carried the local claim is
    // stored, proposed.
    fixture.assert_proposed(EntityId::now(), &[fixture.rows.local]);
}

#[test]
fn a_proposal_from_a_prompt_whose_foreign_copy_was_erased_since_is_refused() {
    // The copy was in the prompt, and is deleted (its shell kept) or purged
    // before the model's words are proposed: it is still their source.
    let fixture = prompt_fixture();
    let purged = put_claim(
        &fixture.vault,
        fixture.rows.person,
        "owen is back Friday",
        ClaimSource::Imported,
        Some(foreign_world()),
    );
    assert!(
        fixture
            .vault
            .delete_entity(&fixture.rows.copy)
            .expect("delete")
    );
    assert!(
        fixture
            .vault
            .delete_entity_with_options(&purged, DeleteEntityOptions { purge: true })
            .expect("purge")
    );
    for erased in [fixture.rows.copy, purged] {
        assert!(
            fixture.vault.get_claim(&erased).expect("read").is_none(),
            "the copy no longer reads"
        );
        fixture.assert_refused(EntityId::now(), &[erased]);
    }

    // Guard: a prompt whose local claim was erased since still proposes.
    let erased_local = put_claim(
        &fixture.vault,
        fixture.rows.person,
        "owen likes the window seat",
        ClaimSource::UserStated,
        None,
    );
    assert!(fixture.vault.delete_entity(&erased_local).expect("delete"));
    fixture.assert_proposed(EntityId::now(), &[fixture.rows.local, erased_local]);
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
