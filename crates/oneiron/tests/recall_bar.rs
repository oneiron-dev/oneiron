//! RECALL-CARRIER-THRESHOLD (owner 26 Nov 18:53 "Can we just skip the recall if nothing
//! useful? To not pester"; 18:59 "keep line by line but with some relevance threshold
//! (adjustable)"; Engine NOTE 27 Nov 03:23): a recall that asks the owner's relevance bar
//! (`spec.bar`) keeps only lines whose raw cosine to the query, in the vault's embedding space,
//! clears the owner's floor for that source and harness; a line under the bar takes no slot; a
//! push answers at most 3 CLAIM lines, only inside a project, and nothing when nothing clears;
//! each kept line says its similarity. The floor is `recall.bar.<source>`, per harness (the row's
//! item) and per project (its scope); the default is the bar the host measured for the vault's
//! space (0.52 for pplx-embed-v1-0.6b on its measured profile), quiet where the host measured
//! none, and on a vault with no embedder a direct match of a rare query term, or of every term.
//!
//! Red on the base: `spec.bar` is no field of `vault.recall` and no `recall.bar.*` key exists,
//! so this file does not compile there.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! recall_bar`.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole};
use oneiron::claim::{base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::memory::{
    AllRelationships, ClaimRelationships, ClaimScope, Effort, MemoryPack, RecallBarAsk,
    RecallBarRule, RecallEffort, RecallRequest, RecallScope, RecallSource, ScopedClaimInput,
};
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_TURN};
use oneiron::retrieval_depth::RecallExecution;
use oneiron::session_project::WorkspaceBindRequest;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingScope};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::recall_with_vector;
use oneiron::workspace_roster::ProjectRecord;
use oneiron::write_envelope::WriteActor;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

/// pplx-embed-v1-0.6b's space at its pinned revision, where 0.52 was measured.
const PPLX: &str = "perplexity-ai/pplx-embed-v1-0.6b@2c4d510dd4a732063c31a0f70193e35067b51fd8";
/// A space no one measured.
const UNMEASURED: &str = "test/model@v1";
/// The bar a host on pplx's measured profile states at admission.
const MEASURED: Option<f32> = Some(0.52);
const LEARNED_AT: u64 = 1_780_000_000;
const QUERY: [f32; 4] = [1.0, 0.0, 0.0, 0.0];
const QUERY_TEXT: &str = "granite drafter plan";
const HARNESS: &str = "claude-code";
const FOLDER: &str = "blake3:a0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9f";

/// A unit vector at `cosine` to [`QUERY`].
fn at(cosine: f32) -> [f32; 4] {
    [cosine, (1.0 - cosine * cosine).sqrt(), 0.0, 0.0]
}

/// A rooted vault, its owner's proof and the test's PROJECT. The vault drops first.
struct Fixture {
    vault: Vault,
    proof: AuthenticatedOwner,
    owner: EntityId,
    project: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// A vault whose vectors are pinned to `space`, or with no embedder for `None`, whose host
    /// states `measured` as the bar it measured in that space, as an embedder on the measured
    /// profile does when the vault admits it.
    fn open(space: Option<&str>, measured: Option<f32>) -> Self {
        Self::open_in(space, measured, None)
    }

    fn open_in(space: Option<&str>, measured: Option<f32>, child: Option<EntityId>) -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let mut config = VaultConfig::device();
        config.dimensions = QUERY.len();
        config.embedding_model = space.map(str::to_owned);
        let vault = Vault::open(dir.path(), config).expect("seeded vault");
        let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
        let root = vault.root_project().expect("the seeded root PROJECT");
        if let Some(child) = child {
            // Seed the folder's project before rooting: once the vault is rooted, a new project
            // would need a signed birth.
            let record = ProjectRecord::new(child, Some(root), root, owner).expect("child project");
            vault
                .put_project(child, &record, vault.now_recorded_at())
                .expect("seed the child PROJECT");
        }
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = HostSlipIssuer::from_seed(&[0x5c; HOST_ISSUER_SEED_BYTES])
            .expect("independent host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile");
        // This install is not the owner's machine, so it holds the root's key, which proves the
        // owner's acts, as a serving host holds its own (row CARRIER-OWNER-PROOF;
        // setting_pack_accept.rs). Without it the owner's set waits for an owner key and is
        // refused OwnerKeyRequired.
        vault.hold_checkpoint_root_signer(Arc::new(issuer));
        let proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        vault
            .set_measured_recall_bar(measured)
            .expect("the host's measured bar");
        Self {
            vault,
            proof,
            owner,
            project: child.unwrap_or(root),
            _dir: dir,
        }
    }

    /// A TURN holding `text`, with `vector` when the vault embeds.
    fn put_turn(&self, text: &str, vector: Option<[f32; 4]>) -> EntityId {
        let id = EntityId::now();
        let body = rmp_serde::to_vec_named(&json!({ "content": text })).expect("turn body");
        let mut batch = self.vault.batch().put(
            &id,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
            &body,
        );
        batch = batch.text(&id, &[("body", text)]);
        if let Some(vector) = vector {
            batch = batch.vector(&id, &vector);
        }
        batch.commit().expect("the turn, its text and its vector");
        id
    }

    /// A CLAIM in the fixture's project about the owner holding `value`, with `predicate`.
    fn put_claim(&self, predicate: &str, value: &str) -> EntityId {
        self.put_claim_in(self.project, predicate, value, None)
    }

    /// A scoped CLAIM, with `vector` when the vault embeds.
    fn put_claim_in(
        &self,
        project: EntityId,
        predicate: &str,
        value: &str,
        vector: Option<[f32; 4]>,
    ) -> EntityId {
        // A distinct facet keeps each seed on its own claim key, even for repeated values.
        let facet = EntityId::now();
        let facet_body =
            rmp_serde::to_vec_named(&json!({ "name": "bar test facet" })).expect("facet body");
        self.vault
            .put_entity(
                &facet,
                ENTITY_TYPE_FACET,
                TimeRange {
                    start: LEARNED_AT,
                    end: LEARNED_AT,
                },
                LEARNED_AT,
                &facet_body,
            )
            .expect("facet row");
        let id = EntityId::now();
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .claim_upsert_scoped(&ScopedClaimInput {
                id: Some(id.to_hex()),
                predicate: predicate.to_owned(),
                subject_ref: self.owner.to_hex(),
                value: json!(value),
                confidence: 1.0,
                source: "user_stated".to_owned(),
                scope: ClaimScope {
                    world_id: base_world_id().to_hex(),
                    scope_facet_id: facet.to_hex(),
                    scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                    scope_project_id: project.to_hex(),
                }
                .into(),
                sensitivity: None,
                evidence_turn_refs: Vec::new(),
                valid_from: None,
                valid_to: None,
                occurred_at: Some(LEARNED_AT),
                learned_at: Some(LEARNED_AT),
                salience: None,
            })
            .expect("the owner's claim");
        if let Some(vector) = vector {
            self.vault
                .put_vector(&id, &vector)
                .expect("the claim vector");
        }
        id
    }

    /// A research NOTE holding `markdown`, published as the idle loop publishes it.
    fn put_note(&self, markdown: &str) -> EntityId {
        let actor = WriteActor::new(self.owner, EdgeActorClass::Human);
        let id = self
            .vault
            .create_note("research", markdown, actor)
            .expect("note");
        self.vault
            .set_indexed_idle_delay_ms(0)
            .expect("idle delay row");
        let published = self
            .vault
            .refresh_staged_indexed_at_idle(u64::MAX)
            .expect("idle publication");
        assert!(
            published.failed.is_empty(),
            "every staged text publishes: {published:?}"
        );
        id
    }

    /// Three lines over 0.52 and two traps under it that repeat the query's words, so they rank
    /// high by words alone: `(passing, traps)`.
    fn seed_lines(&self) -> (BTreeSet<EntityId>, BTreeSet<EntityId>) {
        let passing = [0.60, 0.58, 0.55]
            .into_iter()
            .enumerate()
            .map(|(step, cosine)| {
                self.put_claim_in(
                    self.project,
                    "profile.note",
                    &format!("granite drafter plan, step {step} of the D1 test"),
                    Some(at(cosine)),
                )
            })
            .collect();
        let traps = [0.40, 0.10]
            .into_iter()
            .map(|cosine| {
                self.put_claim_in(
                    self.project,
                    "profile.note",
                    "granite drafter plan: granite drafter plan, the granite drafter plan outline",
                    Some(at(cosine)),
                )
            })
            .collect();
        (passing, traps)
    }

    /// The owner's change of `key` at `scope` for `item`: `value`.
    fn owner_sets(&self, key: &str, scope: SettingScope, item: Option<&str>, value: Value) {
        let mut change = SetSetting::vault_value(key, value);
        change.scope = scope;
        change.item = item.map(str::to_owned);
        let outcome = self
            .vault
            .set_setting(SettingCaller::Owner(&self.proof), change)
            .unwrap_or_else(|error| panic!("the owner sets {key}: {error}"));
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "the owner's change applies at once: {outcome:?}"
        );
    }

    /// The owner's recall of [`QUERY_TEXT`] in the fixture's project, asking `bar`.
    fn recall(
        &self,
        bar: Option<RecallBarAsk>,
        limit: usize,
    ) -> oneiron::memory::MemoryResult<MemoryPack> {
        self.recall_in(bar, limit, vec![self.project.to_hex()], None)
    }

    fn recall_in(
        &self,
        bar: Option<RecallBarAsk>,
        limit: usize,
        project_refs: Vec<String>,
        folder: Option<&str>,
    ) -> oneiron::memory::MemoryResult<MemoryPack> {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        let memory = match folder {
            Some(folder) => memory.in_session_workspace(&[folder.to_owned()]),
            None => memory,
        };
        recall_with_vector(
            &memory,
            RecallRequest {
                query: QUERY_TEXT.to_owned(),
                limit: Some(limit),
                scope: Some(RecallScope {
                    project_refs,
                    ..RecallScope::default()
                }),
                bar,
                ..RecallRequest::default()
            },
            |_| Some(QUERY.to_vec()),
        )
    }
}

fn ask(source: RecallSource, harness: &str) -> Option<RecallBarAsk> {
    Some(RecallBarAsk {
        source,
        harness: Some(harness.to_owned()),
        session: None,
    })
}

fn ids(pack: &MemoryPack) -> BTreeSet<EntityId> {
    pack.items
        .iter()
        .map(|item| {
            let record = item
                .record
                .as_ref()
                .expect("a recalled item names its record");
            EntityId::from_hex(&record.id).expect("a record id is 32 hex")
        })
        .collect()
}

/// The CLAIM lines of `pack`. A pull, like a recall that asks no bar, is not CLAIMs only: at
/// medium effort the now anchor also brings the vault's freshly seeded pack SKILLs, ranked
/// below every line the query matched (FIX 22182), into the slots the matches leave.
fn claim_ids(pack: &MemoryPack) -> BTreeSet<EntityId> {
    pack.items
        .iter()
        .filter(|item| item.kind == "CLAIM")
        .map(|item| {
            let record = item
                .record
                .as_ref()
                .expect("a recalled item names its record");
            EntityId::from_hex(&record.id).expect("a record id is 32 hex")
        })
        .collect()
}

fn quiet_reason(pack: &MemoryPack) -> Option<&str> {
    match &pack.bar.as_ref()?.rule {
        RecallBarRule::Quiet { reason } => Some(reason),
        _ => None,
    }
}

#[test]
fn a_carrier_keeps_only_lines_over_the_measured_floor_and_says_each_similarity() {
    let fixture = Fixture::open(Some(PPLX), MEASURED);
    let (passing, _traps) = fixture.seed_lines();
    let pack = fixture
        .recall(ask(RecallSource::Carrier, HARNESS), 8)
        .expect("the recall runs");
    assert_eq!(ids(&pack), passing, "the three lines over 0.52, no trap");
    for item in &pack.items {
        let similarity = item.similarity.expect("a kept line says its similarity");
        assert!(similarity >= 0.52 && similarity <= 0.61, "{similarity}");
    }
    let bar = pack.bar.as_ref().expect("the pack says the rule");
    assert_eq!(bar.source, RecallSource::Carrier);
    assert!(
        matches!(&bar.rule, RecallBarRule::Cosine { floor, model } if (floor - 0.52).abs() < 1e-6 && model == PPLX),
        "{:?}",
        bar.rule
    );
    assert!(!bar.receipt, "no receipt unless the owner asks for one");
}

#[test]
fn a_line_under_the_bar_takes_no_slot() {
    let fixture = Fixture::open(Some(PPLX), MEASURED);
    let (passing, traps) = fixture.seed_lines();
    let open = fixture
        .recall(ask(RecallSource::Pull, HARNESS), 3)
        .expect("the open recall runs");
    assert!(
        !ids(&open).is_disjoint(&traps),
        "fixture: a trap ranks in the top three by the recall's own order: {:?}",
        ids(&open)
    );
    let barred = fixture
        .recall(ask(RecallSource::Carrier, HARNESS), 3)
        .expect("the barred recall runs");
    assert_eq!(
        ids(&barred),
        passing,
        "the bar judges before the cut: three passing lines fill the three slots"
    );
}

#[test]
fn a_pull_is_open_by_default_and_a_recall_with_no_bar_is_unchanged() {
    let fixture = Fixture::open(Some(PPLX), MEASURED);
    let (passing, traps) = fixture.seed_lines();
    let every: BTreeSet<_> = passing.union(&traps).copied().collect();
    let pull = fixture
        .recall(ask(RecallSource::Pull, HARNESS), 8)
        .expect("the pull runs");
    assert_eq!(
        claim_ids(&pull),
        every,
        "a pull returns every seeded line, the traps included"
    );
    assert!(pull.items.iter().all(|item| item.similarity.is_none()));
    assert_eq!(
        pull.bar.as_ref().map(|bar| &bar.rule),
        Some(&RecallBarRule::Open)
    );
    let plain = fixture.recall(None, 8).expect("the plain recall runs");
    assert_eq!(claim_ids(&plain), every);
    assert_eq!(
        ids(&pull),
        ids(&plain),
        "an open pull returns the items of a recall that asks no bar"
    );
    assert!(
        plain.bar.is_none(),
        "a recall that asks no bar reports none"
    );
    let serialized = serde_json::to_value(&plain).expect("the pack serializes");
    assert!(serialized.get("bar").is_none());
    assert!(
        serialized["items"]
            .as_array()
            .expect("items")
            .iter()
            .all(|item| item.get("similarity").is_none()),
        "an unbarred pack's bytes carry no new field"
    );
}

#[test]
fn at_most_three_lines_are_pushed() {
    let fixture = Fixture::open(Some(PPLX), MEASURED);
    let seeded: BTreeSet<_> = (0..5)
        .map(|step| {
            fixture.put_claim_in(
                fixture.project,
                "profile.note",
                &format!("granite drafter plan, note {step}"),
                Some(at(0.70)),
            )
        })
        .collect();
    let pack = fixture
        .recall(ask(RecallSource::Start, HARNESS), 8)
        .expect("the start recall runs");
    assert_eq!(pack.items.len(), 3, "a push answers at most three lines");
    let pull = fixture
        .recall(ask(RecallSource::Pull, HARNESS), 8)
        .expect("the pull runs");
    assert_eq!(
        claim_ids(&pull),
        seeded,
        "a pull keeps its limit: all five seeded lines, not three"
    );
}

#[test]
fn a_push_outside_any_project_is_quiet() {
    let fixture = Fixture::open(Some(PPLX), MEASURED);
    fixture.seed_lines();
    let pack = fixture
        .recall_in(ask(RecallSource::Carrier, HARNESS), 8, Vec::new(), None)
        .expect("the recall runs");
    assert!(pack.items.is_empty());
    assert_eq!(quiet_reason(&pack), Some("no_project"));
}

#[test]
fn the_session_folders_project_scopes_a_push_and_its_rows() {
    let fixture = Fixture::open_in(Some(PPLX), MEASURED, Some(EntityId::now()));
    let (passing, _traps) = fixture.seed_lines();
    let other_project = fixture.vault.root_project().expect("the root PROJECT");
    fixture.put_claim_in(other_project, "profile.note", QUERY_TEXT, Some(QUERY));
    fixture
        .vault
        .bind_workspace_as_owner(
            &fixture.proof,
            Some(ActSurface::ThisInstall),
            WorkspaceBindRequest {
                folder_digest: FOLDER.to_owned(),
                project: fixture.project,
                label: Some("granite".to_owned()),
            },
        )
        .expect("the owner binds the folder");
    let pack = fixture
        .recall_in(
            ask(RecallSource::Carrier, HARNESS),
            8,
            Vec::new(),
            Some(FOLDER),
        )
        .expect("the session's recall runs");
    assert_eq!(ids(&pack), passing, "the bound project scopes the push");
    fixture.owner_sets(
        "recall.bar.carrier",
        SettingScope::Project(fixture.project),
        None,
        json!("quiet"),
    );
    let quiet = fixture
        .recall_in(
            ask(RecallSource::Carrier, HARNESS),
            8,
            Vec::new(),
            Some(FOLDER),
        )
        .expect("the session's recall runs");
    assert!(quiet.items.is_empty(), "the bound project's own row judges");
    assert_eq!(quiet_reason(&quiet), Some("owner"));
}

#[test]
fn a_space_no_one_measured_is_quiet() {
    let fixture = Fixture::open(Some(UNMEASURED), None);
    fixture.seed_lines();
    let pack = fixture
        .recall(ask(RecallSource::Carrier, HARNESS), 8)
        .expect("the recall runs");
    assert!(pack.items.is_empty());
    assert_eq!(quiet_reason(&pack), Some("unmeasured"));
}

/// Engine ANSWER 27 Nov 03:42: `measured` is the host's, keyed like the space's floors, so
/// pplx served by a server that names no profile (vel today) is quiet until the owner gives
/// that space its floor, naming it.
#[test]
fn a_space_its_host_did_not_measure_is_quiet_until_the_owner_sets_its_floor() {
    let fixture = Fixture::open(Some(PPLX), None);
    let (passing, _traps) = fixture.seed_lines();
    let pack = fixture
        .recall(ask(RecallSource::Carrier, HARNESS), 8)
        .expect("the recall runs");
    assert!(pack.items.is_empty());
    assert_eq!(quiet_reason(&pack), Some("unmeasured"));
    fixture.owner_sets(
        "recall.bar.carrier",
        SettingScope::Vault,
        None,
        json!({ "cosine": { "floor": 0.52, "model": UNMEASURED } }),
    );
    let other = fixture
        .recall(ask(RecallSource::Carrier, HARNESS), 8)
        .expect("the recall runs");
    assert!(
        other.items.is_empty(),
        "a floor measured in another space judges nothing here"
    );
    assert_eq!(quiet_reason(&other), Some("other_space"));
    fixture.owner_sets(
        "recall.bar.carrier",
        SettingScope::Vault,
        None,
        json!({ "cosine": { "floor": 0.52, "model": PPLX } }),
    );
    let owners = fixture
        .recall(ask(RecallSource::Carrier, HARNESS), 8)
        .expect("the recall runs");
    assert_eq!(ids(&owners), passing, "the owner's floor for this space");
}

#[test]
fn a_host_bar_outside_zero_one_is_refused() {
    let fixture = Fixture::open(Some(PPLX), MEASURED);
    for bar in [-0.1, 1.5, f32::NAN] {
        assert!(
            fixture.vault.set_measured_recall_bar(Some(bar)).is_err(),
            "{bar}"
        );
    }
    let (passing, _traps) = fixture.seed_lines();
    let pack = fixture
        .recall(ask(RecallSource::Carrier, HARNESS), 8)
        .expect("the recall runs");
    assert_eq!(ids(&pack), passing, "the bar in force stays");
}

#[test]
fn the_harness_row_and_the_project_row_decide() {
    let fixture = Fixture::open(Some(PPLX), MEASURED);
    let (passing, traps) = fixture.seed_lines();
    fixture.owner_sets(
        "recall.bar.carrier",
        SettingScope::Vault,
        None,
        json!("quiet"),
    );
    let quiet = fixture
        .recall(ask(RecallSource::Carrier, HARNESS), 8)
        .expect("the recall runs");
    assert!(quiet.items.is_empty());
    assert_eq!(quiet_reason(&quiet), Some("owner"));
    fixture.owner_sets(
        "recall.bar.carrier",
        SettingScope::Vault,
        Some(HARNESS),
        json!("open"),
    );
    let open = fixture
        .recall(ask(RecallSource::Carrier, HARNESS), 8)
        .expect("the recall runs");
    assert_eq!(
        open.items.len(),
        3,
        "the harness's own row opens it, still at most three lines"
    );
    assert!(ids(&open).is_subset(&passing.union(&traps).copied().collect()));
    let codex = fixture
        .recall(ask(RecallSource::Carrier, "codex"), 8)
        .expect("the recall runs");
    assert!(
        codex.items.is_empty(),
        "another harness keeps the row that names none"
    );
    fixture.owner_sets(
        "recall.bar.carrier",
        SettingScope::Project(fixture.project),
        Some(HARNESS),
        json!("measured"),
    );
    let project = fixture
        .recall(ask(RecallSource::Carrier, HARNESS), 8)
        .expect("the recall runs");
    assert_eq!(
        ids(&project),
        passing,
        "the project's row overrides the vault's"
    );
}

#[test]
fn a_vault_with_no_embedder_passes_a_direct_match() {
    let fixture = Fixture::open(None, None);
    for step in 0..24 {
        fixture.put_claim("profile.note", &format!("the weekly plan for item {step}"));
    }
    let rare = fixture.put_claim("profile.note", "the quillwort plan for the quarter");
    let both = fixture.put_claim("profile.note", "granite drafter results");
    fixture.put_claim("profile.note", "granite countertop order");
    fixture.put_claim("profile.note", "drafter table order");
    for _ in 0..2 {
        fixture.put_claim("profile.note", "granite drafter");
    }
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let recall = |query: &str| {
        recall_with_vector(
            &memory,
            RecallRequest {
                query: query.to_owned(),
                limit: Some(8),
                scope: Some(RecallScope {
                    project_refs: vec![fixture.project.to_hex()],
                    ..RecallScope::default()
                }),
                bar: ask(RecallSource::Carrier, HARNESS),
                ..RecallRequest::default()
            },
            |_| None,
        )
        .expect("the recall runs")
    };
    let pack = recall("quillwort plan");
    assert_eq!(
        ids(&pack),
        BTreeSet::from([rare]),
        "the rare term passes; the common one does not"
    );
    assert_eq!(
        pack.bar.as_ref().map(|bar| &bar.rule),
        Some(&RecallBarRule::DirectMatch)
    );
    assert!(pack.items.iter().all(|item| item.similarity.is_none()));
    assert!(
        recall("plan").items.is_empty(),
        "one common word never passes"
    );
    let pair = ids(&recall("granite drafter results"));
    assert!(
        pair.contains(&both),
        "a line holding every term passes: {pair:?}"
    );
}

#[test]
fn a_bad_harness_and_a_bar_under_an_operation_id_are_refused() {
    let fixture = Fixture::open(Some(PPLX), MEASURED);
    fixture.seed_lines();
    for harness in ["", "Claude", "claude code", "-x", &"a".repeat(41)] {
        assert!(
            fixture
                .recall(ask(RecallSource::Carrier, harness), 8)
                .is_err(),
            "{harness:?} is no harness name"
        );
    }
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let refused = recall_with_vector(
        &memory,
        RecallRequest {
            query: QUERY_TEXT.to_owned(),
            operation_id: Some("op-1".to_owned()),
            bar: ask(RecallSource::Carrier, HARNESS),
            ..RecallRequest::default()
        },
        |_| Some(QUERY.to_vec()),
    );
    assert!(refused.is_err(), "a push is no operation a caller replays");
}

#[test]
fn the_empty_receipt_is_one_setting_away() {
    let fixture = Fixture::open(Some(PPLX), MEASURED);
    fixture.put_turn("granite drafter plan bookkeeping", Some(at(0.20)));
    let pack = fixture
        .recall(ask(RecallSource::Carrier, HARNESS), 8)
        .expect("the recall runs");
    assert!(pack.items.is_empty(), "nothing clears the bar");
    assert!(
        !pack.bar.as_ref().expect("the rule").receipt,
        "the default says nothing"
    );
    fixture.owner_sets(
        "recall.bar.empty_receipt",
        SettingScope::Vault,
        Some(HARNESS),
        json!(true),
    );
    let receipt = fixture
        .recall(ask(RecallSource::Carrier, HARNESS), 8)
        .expect("the recall runs");
    assert!(receipt.bar.as_ref().expect("the rule").receipt);
    let codex = fixture
        .recall(ask(RecallSource::Carrier, "codex"), 8)
        .expect("the recall runs");
    assert!(
        !codex.bar.as_ref().expect("the rule").receipt,
        "per harness"
    );
}

// REVIEW-10566 round 1: a project named twice is judged by that project's own bar.
#[test]
fn a_project_named_twice_is_judged_by_that_projects_own_bar() {
    let fixture = Fixture::open(Some(PPLX), MEASURED);
    fixture.seed_lines();
    fixture.owner_sets("recall.bar.pull", SettingScope::Vault, None, json!("open"));
    fixture.owner_sets(
        "recall.bar.pull",
        SettingScope::Project(fixture.project),
        None,
        json!("quiet"),
    );
    let once = fixture
        .recall_in(
            ask(RecallSource::Pull, HARNESS),
            8,
            vec![fixture.project.to_hex()],
            None,
        )
        .expect("the recall runs");
    assert!(
        once.items.is_empty(),
        "one ref reads the project's quiet row"
    );
    assert_eq!(quiet_reason(&once), Some("owner"));
    let twice = fixture
        .recall_in(
            ask(RecallSource::Pull, HARNESS),
            8,
            vec![fixture.project.to_hex(), fixture.project.to_hex()],
            None,
        )
        .expect("the recall runs");
    assert!(
        twice.items.is_empty(),
        "[P, P] reads the same corpus under the project's own bar, not the vault's open row"
    );
    assert_eq!(quiet_reason(&twice), Some("owner"));
}

// REVIEW-10566 round 1: a push keeps CLAIMs only, whatever `scope.kinds` asks.
#[test]
fn a_start_push_returns_no_note_even_when_kinds_asks_for_note_and_a_matching_claim_takes_the_slot()
{
    let fixture = Fixture::open(Some(PPLX), MEASURED);
    fixture.owner_sets("recall.bar.start", SettingScope::Vault, None, json!("open"));
    let note = fixture.put_note("granite drafter plan: the weekly outline");
    let claim = fixture.put_claim("profile.note", "granite drafter plan for the quarter");
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let kinds_note = recall_with_vector(
        &memory,
        RecallRequest {
            query: QUERY_TEXT.to_owned(),
            limit: Some(8),
            scope: Some(RecallScope {
                project_refs: vec![fixture.project.to_hex()],
                kinds: Some(vec!["NOTE".to_owned()]),
                ..RecallScope::default()
            }),
            bar: ask(RecallSource::Start, HARNESS),
            ..RecallRequest::default()
        },
        |_| Some(QUERY.to_vec()),
    )
    .expect("the recall runs");
    assert!(
        kinds_note.items.is_empty(),
        "kinds=[NOTE] names no CLAIM, so a push returns nothing"
    );
    let pack = recall_with_vector(
        &memory,
        RecallRequest {
            query: QUERY_TEXT.to_owned(),
            limit: Some(8),
            scope: Some(RecallScope {
                project_refs: vec![fixture.project.to_hex()],
                ..RecallScope::default()
            }),
            bar: ask(RecallSource::Start, HARNESS),
            ..RecallRequest::default()
        },
        |_| Some(QUERY.to_vec()),
    )
    .expect("the recall runs");
    let served = ids(&pack);
    assert!(
        served.contains(&claim),
        "the project's matching CLAIM takes the slot: {served:?}"
    );
    assert!(!served.contains(&note), "no NOTE is pushed: {served:?}");
    assert!(
        pack.items.iter().all(|item| item.kind == "CLAIM"),
        "a push returns CLAIMs only"
    );
}

// REVIEW-10566 round 1: a barred recall renders from its admitted items only.
#[test]
fn a_quiet_barred_recall_renders_no_text_from_outside_its_items() {
    let fixture = Fixture::open(Some(PPLX), MEASURED);
    fixture.put_claim("profile.note", "the owner's favourite colour is chartreuse");
    fixture.owner_sets(
        "recall.bar.carrier",
        SettingScope::Project(fixture.project),
        None,
        json!("quiet"),
    );
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let pack = recall_with_vector(
        &memory,
        RecallRequest {
            query: QUERY_TEXT.to_owned(),
            limit: Some(8),
            format: Some("json".to_owned()),
            scope: Some(RecallScope {
                project_refs: vec![fixture.project.to_hex()],
                ..RecallScope::default()
            }),
            bar: ask(RecallSource::Carrier, HARNESS),
            ..RecallRequest::default()
        },
        |_| Some(QUERY.to_vec()),
    )
    .expect("the recall runs");
    assert!(pack.items.is_empty());
    assert_eq!(quiet_reason(&pack), Some("owner"));
    let rendered = pack.rendered.as_deref().unwrap_or("");
    assert!(
        !rendered.contains("chartreuse"),
        "no L2 prefix leaks into a quiet barred rendering: {rendered}"
    );
}

// REVIEW-10566 round 1: a wrong-width query vector quiets instead of erroring.
#[test]
fn a_query_vector_of_the_wrong_width_gives_a_quiet_pack_with_reason_no_query_vector_not_an_error() {
    let fixture = Fixture::open(Some(PPLX), MEASURED);
    fixture.seed_lines();
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let pack = recall_with_vector(
        &memory,
        RecallRequest {
            query: QUERY_TEXT.to_owned(),
            limit: Some(8),
            scope: Some(RecallScope {
                project_refs: vec![fixture.project.to_hex()],
                ..RecallScope::default()
            }),
            bar: ask(RecallSource::Carrier, HARNESS),
            ..RecallRequest::default()
        },
        |_| Some(vec![1.0]),
    )
    .expect("a wrong-width vector quiets the barred recall instead of erroring");
    assert!(pack.items.is_empty());
    assert_eq!(quiet_reason(&pack), Some("no_query_vector"));
}

// REVIEW-10566 round 1: an undecodable deciding row reports `unreadable`, not `owner`.
#[test]
fn an_undecodable_bar_row_reports_reason_unreadable() {
    let fixture = Fixture::open(Some(PPLX), MEASURED);
    fixture.seed_lines();
    oneiron::test_doors::setting::plant_undecodable_row(
        &fixture.vault,
        "recall.bar.carrier",
        SettingScope::Project(fixture.project),
    )
    .expect("a damaged bar row");
    let pack = fixture
        .recall(ask(RecallSource::Carrier, HARNESS), 8)
        .expect("the recall runs");
    assert!(pack.items.is_empty());
    assert_eq!(
        quiet_reason(&pack),
        Some("unreadable"),
        "an unreadable deciding row is not the owner's quiet"
    );
}

// REVIEW-10566 round 2: a redundant child does not open its parent's quiet bar.
#[test]
fn a_redundant_child_project_does_not_open_its_parents_quiet_bar() {
    let child = EntityId::now();
    let fixture = Fixture::open_in(Some(PPLX), MEASURED, Some(child));
    let parent = fixture.vault.root_project().expect("the root PROJECT");
    fixture.put_claim_in(parent, "profile.note", QUERY_TEXT, Some(at(0.90)));
    fixture.owner_sets(
        "recall.bar.carrier",
        SettingScope::Vault,
        None,
        json!("open"),
    );
    fixture.owner_sets(
        "recall.bar.carrier",
        SettingScope::Project(parent),
        None,
        json!("quiet"),
    );
    let once = fixture
        .recall_in(
            ask(RecallSource::Carrier, HARNESS),
            8,
            vec![parent.to_hex()],
            None,
        )
        .expect("the recall runs");
    assert!(once.items.is_empty(), "[P] reads the parent's quiet row");
    assert_eq!(quiet_reason(&once), Some("owner"));
    let both = fixture
        .recall_in(
            ask(RecallSource::Carrier, HARNESS),
            8,
            vec![parent.to_hex(), child.to_hex()],
            None,
        )
        .expect("the recall runs");
    assert!(
        both.items.is_empty(),
        "[P, C] reads the same corpus under the same quiet row, not the vault's open row"
    );
    assert_eq!(quiet_reason(&both), Some("owner"));
}

// REVIEW-10566 round 2: the reserved unscoped stamp is no project for a push.
#[test]
fn a_push_naming_only_the_reserved_default_stamp_is_quiet_no_project() {
    let fixture = Fixture::open(Some(PPLX), MEASURED);
    let unscoped = default_project_id();
    fixture.put_claim_in(unscoped, "profile.note", QUERY_TEXT, Some(at(0.90)));
    let pack = fixture
        .recall_in(
            ask(RecallSource::Carrier, HARNESS),
            8,
            vec![unscoped.to_hex()],
            None,
        )
        .expect("the recall runs");
    assert!(
        pack.items.is_empty(),
        "a push outside any project pushes nothing, not even its matching unscoped claim"
    );
    assert_eq!(quiet_reason(&pack), Some("no_project"));
}

// REVIEW-10566/10567 round 2: a passing claim ranked below the text window's under-bar hits
// is still pushed.
#[test]
fn a_passing_claim_ranked_below_the_text_windows_under_bar_hits_is_still_pushed() {
    let fixture = Fixture::open(None, None);
    // One hundred single-term claims, short with a high term count, so every one outranks
    // the passing claim by BM25: fifty per term, and neither term distinctive at fifty-one
    // postings against a cap of about five.
    for step in 0..50 {
        fixture.put_claim(
            "profile.note",
            &format!("telescope survey note {step}: {}", "telescope ".repeat(30)),
        );
        fixture.put_claim(
            "profile.note",
            &format!("granite survey note {step}: {}", "granite ".repeat(30)),
        );
    }
    // The passing claim holds both terms once, in a long value that ranks it below every
    // under-bar hit.
    let both = fixture.put_claim(
        "profile.note",
        &format!(
            "telescope granite observation: {}",
            "weekly plan item ledger for the quarter ".repeat(40)
        ),
    );
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let scope = RecallScope {
        project_refs: vec![fixture.project.to_hex()],
        ..RecallScope::default()
    };
    let bar = ask(RecallSource::Carrier, HARNESS).expect("a bar");
    let pack = memory
        .recall_with_execution(
            "telescope granite",
            Effort::Light,
            &scope,
            8,
            None,
            None,
            &RecallExecution {
                bar: Some(&bar),
                ..Default::default()
            },
        )
        .expect("the recall runs");
    assert_eq!(
        ids(&pack),
        BTreeSet::from([both]),
        "more under-bar hits than the window, yet the both-term claim is pushed"
    );
}

// REVIEW-10566 round 2: the shared engine recall pushes at most three lines.
#[test]
fn the_shared_engine_recall_pushes_at_most_three_lines() {
    let fixture = Fixture::open(Some(PPLX), MEASURED);
    for step in 0..5 {
        fixture.put_claim_in(
            fixture.project,
            "profile.note",
            &format!("granite drafter plan, note {step}"),
            Some(at(0.70)),
        );
    }
    let query = QUERY.to_vec();
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let scope = RecallScope {
        project_refs: vec![fixture.project.to_hex()],
        ..RecallScope::default()
    };
    let bar = ask(RecallSource::Carrier, HARNESS).expect("a bar");
    let pack = memory
        .recall_with_execution(
            QUERY_TEXT,
            Effort::Medium,
            &scope,
            4,
            None,
            None,
            &RecallExecution {
                bar: Some(&bar),
                embedding: Some(&query),
                ..Default::default()
            },
        )
        .expect("the recall runs");
    assert_eq!(
        pack.items.len(),
        3,
        "a push answers at most three lines, whatever its limit, on the shared path too"
    );
}

// REVIEW-10566 round 2: a term held by every document of a small vault is not distinctive.
#[test]
fn a_term_held_by_every_document_of_a_small_vault_is_not_distinctive() {
    let fixture = Fixture::open(None, None);
    fixture.put_claim("profile.note", "quillwort ledger entry");
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let recall = |query: &str| {
        recall_with_vector(
            &memory,
            RecallRequest {
                query: query.to_owned(),
                limit: Some(8),
                scope: Some(RecallScope {
                    project_refs: vec![fixture.project.to_hex()],
                    ..RecallScope::default()
                }),
                bar: ask(RecallSource::Carrier, HARNESS),
                ..RecallRequest::default()
            },
            |_| None,
        )
        .expect("the recall runs")
    };
    assert!(
        recall("quillwort").items.is_empty(),
        "one document holds every posting of the term, so it is not distinctive by rarity"
    );
    assert_eq!(
        recall("quillwort ledger").items.len(),
        1,
        "the every-term rule still passes a line holding every term"
    );
}

// REVIEW-10567 round 2 (engine side): a light barred recall finds no claim by cosine alone.
#[test]
fn a_light_barred_recall_finds_no_claim_by_cosine_alone() {
    let fixture = Fixture::open(Some(PPLX), MEASURED);
    let query = QUERY.to_vec();
    fixture.put_claim_in(
        fixture.project,
        "profile.note",
        "chartreuse harbour lantern",
        Some(at(0.90)),
    );
    fixture.put_claim_in(
        fixture.project,
        "profile.note",
        "granite drafter plan outline",
        Some(at(0.10)),
    );
    let over = fixture.put_claim_in(
        fixture.project,
        "profile.note",
        "granite drafter plan notes",
        Some(at(0.90)),
    );
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let scope = RecallScope {
        project_refs: vec![fixture.project.to_hex()],
        ..RecallScope::default()
    };
    let bar = ask(RecallSource::Carrier, HARNESS).expect("a bar");
    let pack = memory
        .recall_with_execution(
            QUERY_TEXT,
            Effort::Light,
            &scope,
            8,
            None,
            None,
            &RecallExecution {
                bar: Some(&bar),
                bar_query_vector: Some(&query),
                ..Default::default()
            },
        )
        .expect("the recall runs");
    assert_eq!(
        ids(&pack),
        BTreeSet::from([over]),
        "no dense list runs at light: the termless claim at 0.9 is not found, and the bar \
         still judges the lexical hits by the comparison vector"
    );
    let similarity = pack
        .items
        .first()
        .expect("one line")
        .similarity
        .expect("the bar says the cosine it judged");
    // A vector row is stored as f16 (oneiron-store vector_row.rs), so the bar judges the
    // stored vector: at(0.90) reads back as [0.89990234, 0.43579102], whose cosine to the
    // query is 0.90002024. Half precision is good to about 1e-3 here.
    assert!(
        (similarity - 0.90).abs() < 1e-3,
        "the kept line says its judged cosine: {similarity}"
    );
}

// REVIEW-10567 round 2 (the door): a light or call push through the SDK door, whose host embeds
// a barred query at any effort, still runs no dense list; the bar judges that vector alone.
#[test]
fn a_light_or_call_barred_push_through_the_door_finds_no_claim_by_cosine_alone() {
    let fixture = Fixture::open(Some(PPLX), MEASURED);
    fixture.put_claim_in(
        fixture.project,
        "profile.note",
        "chartreuse harbour lantern",
        Some(at(0.90)),
    );
    let over = fixture.put_claim_in(
        fixture.project,
        "profile.note",
        "granite drafter plan notes",
        Some(at(0.90)),
    );
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    for effort in [RecallEffort::Light, RecallEffort::Call] {
        let pack = recall_with_vector(
            &memory,
            RecallRequest {
                query: QUERY_TEXT.to_owned(),
                effort: Some(effort),
                // The longest deadline a request may ask: call's 100 ms default would cut a
                // loaded test host's stages; the effort level is light either way.
                deadline_ms: Some(60_000),
                limit: Some(8),
                scope: Some(RecallScope {
                    project_refs: vec![fixture.project.to_hex()],
                    ..RecallScope::default()
                }),
                bar: ask(RecallSource::Carrier, HARNESS),
                ..RecallRequest::default()
            },
            |_| Some(QUERY.to_vec()),
        )
        .expect("the recall runs");
        assert_eq!(
            ids(&pack),
            BTreeSet::from([over]),
            "{effort:?}: the door's vector is the bar's alone: the termless claim at 0.9 is not \
             found, the lexical hit over the floor is"
        );
    }
}
