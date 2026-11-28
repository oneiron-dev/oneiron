#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole};
use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::{EdgeActorClass, EdgeKind};
use oneiron::ingest::history::{
    HistoryConversation, HistoryMessage, HistoryRole, HistorySource, HistoryThreadKind,
};
use oneiron::memory::{MemoryPack, RecallBarAsk, RecallRequest, RecallScope, RecallSource};
use oneiron::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN,
};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingScope};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::recall_with_vector;
use oneiron::test_doors::derivation_floor::define_agent;
use oneiron::test_doors::derive::{grant_core_read_of_kinds, reader_reads_row};
use oneiron::test_doors::recall_line_provenance::put_claim;
use oneiron::{EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

const SPACE: &str = "test/model@v1";
const LEARNED_AT: u64 = 1_780_000_000;
const QUERY: &str = "granite drafter plan";
const VECTOR: [f32; 4] = [1.0, 0.0, 0.0, 0.0];
const HARNESS: &str = "claude-code";

struct Fixture {
    vault: Vault,
    proof: AuthenticatedOwner,
    owner: EntityId,
    project: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open(space: Option<&str>, measured: Option<f32>) -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let mut config = VaultConfig::device();
        config.dimensions = VECTOR.len();
        config.embedding_model = space.map(str::to_owned);
        let vault = Vault::open(dir.path(), config).expect("seeded vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = HostSlipIssuer::from_seed(&[0x5c; HOST_ISSUER_SEED_BYTES])
            .expect("independent host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("install profile");
        vault.hold_checkpoint_root_signer(Arc::new(issuer));
        let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
        let proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        let project = vault.root_project().expect("root project");
        vault
            .set_measured_recall_bar(measured)
            .expect("measured bar");
        Self {
            vault,
            proof,
            owner,
            project,
            _dir: dir,
        }
    }

    fn set(&self, key: &str, scope: SettingScope, value: Value) {
        let mut change = SetSetting::vault_value(key, value);
        change.scope = scope;
        let outcome = self
            .vault
            .set_setting(SettingCaller::Owner(&self.proof), change)
            .expect("owner sets a recall setting");
        assert!(matches!(outcome, SetSettingOutcome::Applied { .. }));
    }

    fn import(&self, session: &str) -> (EntityId, EntityId) {
        let conversation = HistoryConversation {
            native_id: session.to_owned(),
            kind: HistoryThreadKind::Main,
            parent: None,
            title: None,
            started_at_ms: Some(LEARNED_AT * 1000),
            own_started_at_ms: None,
            cwd: None,
            messages: vec![HistoryMessage {
                native_id: format!("{session}-prompt"),
                parent_id: None,
                role: HistoryRole::User,
                text: "Evidence attached to a recall test claim.".to_owned(),
                at_ms: Some(LEARNED_AT * 1000),
                said_by: None,
                tools: Vec::new(),
                alias: None,
            }],
            skipped: Default::default(),
            sharing: None,
        };
        let report = self
            .vault
            .import_history(
                &self.proof,
                HistorySource::ClaudeCode,
                &conversation,
                LEARNED_AT,
            )
            .expect("history imports");
        assert_eq!(report.new, 1, "{report:?}");
        let turn = report.turns[0];
        let conversations = self
            .vault
            .targets(&turn, EdgeKind::ChildOf, Some(ENTITY_TYPE_CONVERSATION))
            .expect("turn's parent");
        assert_eq!(conversations.len(), 1);
        (turn, conversations[0])
    }

    fn claim(
        &self,
        predicate: &str,
        text: &str,
        evidence: Option<EntityId>,
        cosine: f32,
    ) -> EntityId {
        let id = EntityId::now();
        let mut body = ClaimBody::new(
            predicate,
            ClaimSubject::Entity(self.owner),
            text.into(),
            0.95,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .expect("claim body");
        body.scope_project = self.project;
        body.source = Some(ClaimSource::UserStated);
        body.session_tag = Some("private-fixture-tag".to_owned());
        put_claim(&self.vault, &id, body, evidence, LEARNED_AT, self.owner)
            .expect("land fixture claim");
        let vector = [cosine, (1.0 - cosine * cosine).sqrt(), 0.0, 0.0];
        self.vault
            .batch()
            .text(&id, &[("body", text)])
            .vector(&id, &vector)
            .commit()
            .expect("index the claim's text and vector");
        id
    }

    fn recall(&self, bar: Option<RecallBarAsk>, limit: usize) -> MemoryPack {
        self.recall_as(self.owner, EdgeActorClass::Human, bar, limit)
    }

    fn recall_as(
        &self,
        reader: EntityId,
        class: EdgeActorClass,
        bar: Option<RecallBarAsk>,
        limit: usize,
    ) -> MemoryPack {
        recall_with_vector(
            &self.vault.memory(reader, class),
            RecallRequest {
                query: QUERY.to_owned(),
                limit: Some(limit),
                scope: Some(RecallScope {
                    project_refs: vec![self.project.to_hex()],
                    kinds: Some(vec!["CLAIM".to_owned()]),
                    ..RecallScope::default()
                }),
                bar,
                ..RecallRequest::default()
            },
            |_| Some(VECTOR.to_vec()),
        )
        .expect("recall answers")
    }
}

fn ask(source: RecallSource, session: Option<&str>) -> Option<RecallBarAsk> {
    Some(RecallBarAsk {
        source,
        harness: Some(HARNESS.to_owned()),
        session: session.map(str::to_owned),
    })
}

fn ids(pack: &MemoryPack) -> BTreeSet<EntityId> {
    pack.items
        .iter()
        .map(|item| {
            let record = item.record.as_ref().expect("record");
            EntityId::from_hex(&record.id).expect("entity id")
        })
        .collect()
}

#[test]
fn a_barred_item_names_its_standing_time_and_admitted_source_but_an_unbarred_item_does_not() {
    let fixture = Fixture::open(Some(SPACE), Some(0.52));
    let (turn, conversation) = fixture.import("prior-session");
    let claim = fixture.claim("profile.hobby", QUERY, Some(turn), 0.95);
    let pack = fixture.recall(ask(RecallSource::Pull, None), 5);
    assert_eq!(ids(&pack), BTreeSet::from([claim]));
    let item = serde_json::to_value(&pack.items[0]).expect("item wire");
    assert_eq!(item["provenance"]["source"], "user_stated");
    let line = &item["line_provenance"];
    assert_eq!(line["approval"], "auto");
    assert_eq!(line["learned_at"], json!(LEARNED_AT));
    let [source] = line["source_conversations"]
        .as_array()
        .expect("source conversations")
        .as_slice()
    else {
        panic!("exactly one source conversation: {line}");
    };
    let short = source.as_str().expect("short conversation ref");
    assert!(short.contains(':'));
    assert_eq!(
        oneiron::memory::resolve_entity_ref(&fixture.vault, short).expect("resolve source"),
        conversation
    );
    assert!(!item.to_string().contains("private-fixture-tag"));

    let pack = fixture.recall(None, 5);
    assert_eq!(ids(&pack), BTreeSet::from([claim]));
    let item = serde_json::to_value(&pack.items[0]).expect("unbarred item wire");
    assert!(item.get("line_provenance").is_none());
}

#[test]
fn a_bookkeeping_predicate_takes_no_push_slot_unless_the_owner_clears_the_list() {
    let fixture = Fixture::open(Some(SPACE), Some(0.52));
    let bookkeeping = fixture.claim("skill.scan_verdict", QUERY, None, 1.0);
    let next = fixture.claim(
        "profile.hobby",
        "granite drafter plan for the workshop",
        None,
        0.7,
    );
    assert_eq!(
        ids(&fixture.recall(ask(RecallSource::Start, None), 1)),
        BTreeSet::from([next])
    );
    assert_eq!(
        ids(&fixture.recall(ask(RecallSource::Pull, None), 5)),
        BTreeSet::from([bookkeeping, next])
    );
    fixture.set(
        "recall.bar.excluded_predicates",
        SettingScope::Project(fixture.project),
        json!([]),
    );
    let pack = fixture.recall(ask(RecallSource::Start, None), 1);
    assert_eq!(ids(&pack), BTreeSet::from([bookkeeping]));
    assert!(pack.items[0].similarity.is_some_and(|value| value >= 0.52));
}

#[test]
fn start_and_carrier_leave_the_sessions_own_conversation_out_but_keep_another() {
    let fixture = Fixture::open(Some(SPACE), Some(0.52));
    let (own, _) = fixture.import("own-session");
    let (other, _) = fixture.import("other-session");
    let own_claim = fixture.claim("profile.hobby", QUERY, Some(own), 0.95);
    let other_claim = fixture.claim("profile.occupation", QUERY, Some(other), 0.90);
    for source in [RecallSource::Start, RecallSource::Carrier] {
        assert_eq!(
            ids(&fixture.recall(ask(source, None), 5)),
            BTreeSet::from([own_claim, other_claim])
        );
        assert_eq!(
            ids(&fixture.recall(ask(source, Some("own-session")), 5)),
            BTreeSet::from([other_claim])
        );
    }
    assert_eq!(
        ids(&fixture.recall(ask(RecallSource::Pull, Some("own-session")), 5)),
        BTreeSet::from([own_claim, other_claim])
    );
}

#[test]
fn a_claim_does_not_name_a_source_conversation_outside_the_readers_lane() {
    let fixture = Fixture::open(Some(SPACE), Some(0.52));
    let (turn, conversation) = fixture.import("unread-session");
    let claim = fixture.claim("profile.hobby", QUERY, Some(turn), 0.95);
    let reader = define_agent(&fixture.vault).expect("an agent");
    grant_core_read_of_kinds(
        &fixture.vault,
        reader,
        &[ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN],
    )
    .expect("a read lane that does not admit conversations");
    assert!(
        !reader_reads_row(&fixture.vault, reader, EdgeActorClass::Agent, conversation)
            .expect("lane judges conversation")
    );
    let pack = fixture.recall_as(
        reader,
        EdgeActorClass::Agent,
        ask(RecallSource::Pull, None),
        5,
    );
    assert_eq!(ids(&pack), BTreeSet::from([claim]));
    let line = pack.items[0]
        .line_provenance
        .as_ref()
        .expect("barred item provenance");
    assert!(line.source_conversations.is_empty());
}
