//! CROSS-ARCH-0011 amendment "workingSet", with the epoch summary as the
//! stored compaction packet (CROSS-ARCH-0011 "Unification"; CROSS-ARCH-0002b
//! #ep-6-2-3 `packetId`; Engine RULING L10-03-PACKET-STORE = B):
//! `host.compact` lands the host's working set on the summary it mints as
//! `carries` edges, and a context pack that rehydrates from that summary
//! seeds the rows it carries first, in the host's order, before the ranked
//! fill. A stale packet (a later epoch of its lineage, or no epoch summary at
//! all) leaves today's pack. Erasing a carried row keeps the summary, and no
//! public edge door writes the kind.
//!
//! Public crate surface only: the owner's `host.compact` door
//! (`runtime_hooks::host_doors::compact_as_owner`) on a fixture cheap
//! backend, the witness door, `Vault::put_claim`, `Vault::edges_out`,
//! `Vault::delete_entity`, `Vault::put_edge` and the context pack builder.
//!
//! Fleet command: `cargo test --locked -p oneiron --all-features --test
//! compaction_carry_rehydrate`.

use std::sync::Arc;
use std::time::Duration;

use oneiron::compaction::{CompactionCheck, CompactionGatePolicy, CompactionRefusal};
use oneiron::consent::AuthenticatedOwner;
use oneiron::context_pack::MAX_WORKING_SET_REFS;
use oneiron::edge::EdgeActorClass;
use oneiron::memory::{MemoryResult, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::runtime_hooks::host_doors::{HostCompactRequest, HostCompactResult, compact_as_owner};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    CompactionBackend, CompactionProduct, CompactionRequest, CompactionTierClass,
    CompactionWindowMessage, ContextPackBuilder, EdgeKind, EntityId, FinishReason,
    SessionMintOutcome, TimeRange, Vault, VaultConfig,
};

const LEARNED_AT: u64 = 1_780_000_000;
const QUERY: [f32; 4] = [1.0, 0.0, 0.0, 0.0];
/// The one conversation every fixture turn is witnessed into.
const CONVERSATION_SEED: u8 = 0x70;
/// What the fixture backend summarizes each window as.
const SUMMARY_TEXT: &str = "The owner and the host walked through the harbor ledger, agreed \
     which rows stay in view after the swap, and set the next review for the morning shift.";

/// A cheap backend that answers every window with [`SUMMARY_TEXT`] over the
/// window's own span, in the reply schema the gate parses.
struct SummaryBackend;

impl CompactionBackend for SummaryBackend {
    fn backend_key(&self) -> &str {
        "test.cheap.carry"
    }

    fn tier_class(&self) -> CompactionTierClass {
        CompactionTierClass::Cheap
    }

    fn compact(
        &self,
        request: &CompactionRequest,
        _retry: Option<CompactionCheck>,
    ) -> Result<CompactionProduct, CompactionRefusal> {
        let through = request
            .window
            .last()
            .map_or(request.turn_start, |message| message.turn);
        Ok(CompactionProduct {
            summary_text: serde_json::json!({
                "from": request.turn_start,
                "through": through,
                "summary": SUMMARY_TEXT,
            })
            .to_string(),
            finish: FinishReason::Stop,
            latency: Duration::from_millis(5),
        })
    }
}

/// One owner vault: a SESSION, three ranked claims the query finds (`fill`,
/// best first) and two claims only a working set reaches (`carried`).
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
    session: EntityId,
    fill: [EntityId; 3],
    carried: [EntityId; 2],
}

fn fixture_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("valid entity id")
}

fn occurred() -> TimeRange {
    TimeRange {
        start: LEARNED_AT,
        end: LEARNED_AT,
    }
}

fn put_claim(vault: &Vault, subject: EntityId, id: EntityId, value: &str) {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    body.source = Some(ClaimSource::UserStated);
    vault
        .put_claim(&id, &body, occurred(), LEARNED_AT)
        .expect("fixture claim");
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let mut config = VaultConfig::device();
    config.dimensions = QUERY.len();
    config.embedding_model = Some("test/model@v1".to_owned());
    config.map_size = 32 * 1024 * 1024;
    let vault = Vault::open(dir.path(), config).expect("open vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let session = match vault
        .mint_session(
            vault.local_session_key(owner).expect("session key"),
            LEARNED_AT,
        )
        .expect("mint session")
    {
        SessionMintOutcome::Minted(session) => session,
        other => panic!("expected a fresh session, got {other:?}"),
    };

    let subject = fixture_id(0x21);
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            occurred(),
            LEARNED_AT,
            b"subject",
        )
        .expect("subject entity");
    let fill = [fixture_id(0x31), fixture_id(0x32), fixture_id(0x33)];
    let fill_rows: [(EntityId, &str, [f32; 4]); 3] = [
        (fill[0], "fill row alpha", [0.99, 0.141, 0.0, 0.0]),
        (fill[1], "fill row beta", [0.9, 0.436, 0.0, 0.0]),
        (fill[2], "fill row gamma", [0.8, 0.6, 0.0, 0.0]),
    ];
    for (id, value, _) in &fill_rows {
        put_claim(&vault, subject, *id, value);
    }
    let mut vectors = vault.batch();
    for (id, _, vector) in &fill_rows {
        vectors = vectors.vector(id, vector);
    }
    vectors.commit().expect("fill vectors");
    let carried = [fixture_id(0x41), fixture_id(0x42)];
    put_claim(&vault, subject, carried[0], "carried row one");
    put_claim(&vault, subject, carried[1], "carried row two");

    Fixture {
        _dir: dir,
        vault,
        owner,
        proof,
        session,
        fill,
        carried,
    }
}

impl Fixture {
    /// Witnesses turns `first..first + count` into the SESSION and returns
    /// the host's window over them.
    fn window(&self, first: u64, count: u64) -> Vec<CompactionWindowMessage> {
        (first..first + count)
            .map(|turn| {
                let seed = 0x80 + u8::try_from(turn).expect("a small fixture turn number");
                let turn_id = fixture_id(seed);
                let content = format!(
                    "turn {turn}: the owner reads the harbor ledger aloud, row by row, while \
                     the host notes which entries the next shift must keep in view, which \
                     ones close today, and which ones wait on the berth schedule"
                );
                self.vault
                    .memory(self.owner, EdgeActorClass::Human)
                    .with_session(
                        self.vault
                            .local_session_key(self.owner)
                            .expect("session key"),
                    )
                    .witness(&WitnessTurn {
                        conversation_ref: fixture_id(CONVERSATION_SEED).to_hex(),
                        turn_ref: Some(turn_id.to_hex()),
                        thread_audience: None,
                        messages: vec![WitnessMessage {
                            id: None,
                            author: WitnessAuthor::User,
                            message_type: "dialogue".to_owned(),
                            content: content.clone(),
                            parts: None,
                            metadata: None,
                            is_visible: true,
                            order: 0,
                            quote: None,
                        }],
                        occurred_at: LEARNED_AT + turn,
                        assertions: Default::default(),
                    })
                    .expect("witness a window turn");
                CompactionWindowMessage {
                    message_id: EntityId::now(),
                    turn_id,
                    content,
                    turn,
                    tokens: 40,
                }
            })
            .collect()
    }

    /// The owner's `host.compact` over turns `first..first + count`, carrying
    /// `working_set`.
    fn compact(
        &self,
        first: u64,
        count: u64,
        working_set: &[EntityId],
    ) -> MemoryResult<HostCompactResult> {
        let window = self.window(first, count);
        compact_as_owner(
            &self.vault.memory(self.owner, EdgeActorClass::Human),
            &self.proof,
            HostCompactRequest {
                session_ref: self.session,
                window,
                keep_list: Vec::new(),
                token_ceiling: 400,
                working_set: working_set.to_vec(),
            },
            &SummaryBackend,
            &CompactionGatePolicy::default(),
        )
    }

    fn builder(&self) -> ContextPackBuilder<'_> {
        self.vault
            .context_pack()
            .search_vector(&QUERY, 10)
            .limit(10)
    }

    /// The fixture rows of a pack's results, in pack order.
    fn rows(&self, pack: &oneiron::ContextPack) -> Vec<EntityId> {
        let known: Vec<EntityId> = self.fill.iter().chain(&self.carried).copied().collect();
        pack.results
            .iter()
            .map(|entity| entity.id)
            .filter(|id| known.contains(id))
            .collect()
    }

    /// The fill alone, as a pack with no packet serves it.
    fn todays_rows(&self) -> Vec<EntityId> {
        let pack = self.builder().run().expect("today's pack");
        let rows = self.rows(&pack);
        assert_eq!(rows, self.fill.to_vec(), "today's pack is the ranked fill");
        rows
    }
}

#[test]
fn host_compact_carries_its_working_set_on_the_epoch_summary() {
    let fixture = fixture();
    let never_stored = fixture_id(0x4F);
    let result = fixture
        .compact(
            1,
            2,
            &[fixture.carried[0], fixture.carried[1], never_stored],
        )
        .expect("host.compact with a working set");
    assert_eq!(
        result.carried, 2,
        "the ref that names no row is not carried"
    );

    let carries: Vec<(EntityId, f32)> = fixture
        .vault
        .edges_out(&result.summary)
        .expect("the summary's edges")
        .into_iter()
        .filter(|edge| edge.kind == EdgeKind::Carries)
        .map(|edge| (edge.target, edge.weight))
        .collect();
    assert_eq!(carries.len(), 2, "one carries edge per carried row");
    let weight_of = |row: EntityId| {
        carries
            .iter()
            .find(|(target, _)| *target == row)
            .map(|(_, weight)| *weight)
            .expect("each carried row has its edge")
    };
    assert_eq!(weight_of(fixture.carried[0]).to_bits(), 1.0_f32.to_bits());
    assert_eq!(
        weight_of(fixture.carried[1]).to_bits(),
        (1.0_f32 - 1.0 / 64.0).to_bits(),
        "each later row weighs 1/64 less"
    );
}

#[test]
fn rehydrate_from_the_summary_seeds_the_carried_rows() {
    let fixture = fixture();
    let today = fixture.todays_rows();
    // Carried in the reverse of their id order: the host's order is kept.
    let result = fixture
        .compact(1, 2, &[fixture.carried[1], fixture.carried[0]])
        .expect("host.compact with a working set");

    let pack = fixture
        .builder()
        .rehydrate_from(result.summary)
        .run()
        .expect("rehydrated pack");
    let mut expected = vec![fixture.carried[1], fixture.carried[0]];
    expected.extend(today);
    assert_eq!(fixture.rows(&pack), expected);
    let working_set = &pack.stats.working_set;
    assert!(!working_set.stale);
    assert_eq!(working_set.asked, 2);
    assert_eq!(
        working_set.served,
        vec![fixture.carried[1], fixture.carried[0]]
    );
    assert_eq!(working_set.dropped, 0);
}

#[test]
fn a_later_epoch_makes_the_summary_a_stale_packet() {
    let fixture = fixture();
    let today = fixture.todays_rows();
    let first = fixture
        .compact(1, 2, &[fixture.carried[0]])
        .expect("first compaction");
    let second = fixture
        .compact(3, 2, &[fixture.carried[1]])
        .expect("second compaction");
    assert_eq!(second.epoch, first.epoch + 1);

    let stale = fixture
        .builder()
        .rehydrate_from(first.summary)
        .run()
        .expect("pack from a passed epoch");
    assert_eq!(
        fixture.rows(&stale),
        today,
        "a stale packet is today's pack"
    );
    assert!(stale.stats.working_set.stale);
    assert!(stale.stats.working_set.served.is_empty());

    let newest = fixture
        .builder()
        .rehydrate_from(second.summary)
        .run()
        .expect("pack from the newest epoch");
    let mut expected = vec![fixture.carried[1]];
    expected.extend(today);
    assert_eq!(fixture.rows(&newest), expected);
    assert!(!newest.stats.working_set.stale);
}

#[test]
fn an_id_that_names_no_epoch_summary_is_a_stale_packet() {
    let fixture = fixture();
    let today = fixture.todays_rows();
    for packet in [fixture.carried[0], fixture_id(0x4E)] {
        let pack = fixture
            .builder()
            .rehydrate_from(packet)
            .run()
            .expect("pack from a ref that is no packet");
        assert_eq!(fixture.rows(&pack), today);
        assert!(pack.stats.working_set.stale);
        assert_eq!(pack.stats.working_set.asked, 0);
    }
}

#[test]
fn erasing_a_carried_row_keeps_the_summary() {
    let fixture = fixture();
    let today = fixture.todays_rows();
    let result = fixture
        .compact(1, 2, &fixture.carried)
        .expect("host.compact with a working set");
    assert!(
        fixture
            .vault
            .delete_entity(&fixture.carried[0])
            .expect("erase a carried row")
    );

    let pack = fixture
        .builder()
        .rehydrate_from(result.summary)
        .run()
        .expect("rehydrated pack");
    let mut expected = vec![fixture.carried[1]];
    expected.extend(today);
    assert_eq!(fixture.rows(&pack), expected);
    assert!(
        !pack.stats.working_set.stale,
        "a carried row's erasure never retires the summary"
    );
    assert_eq!(pack.stats.working_set.served, vec![fixture.carried[1]]);
}

#[test]
fn carries_is_refused_on_the_public_edge_door() {
    let fixture = fixture();
    let result = fixture.compact(1, 2, &[]).expect("host.compact");
    assert_eq!(result.carried, 0);
    let refused = fixture
        .vault
        .put_edge(&result.summary, EdgeKind::Carries, &fixture.carried[0], 1.0)
        .expect_err("only the epoch mint writes carries");
    assert_eq!(refused.kind(), oneiron::ErrorKind::ReservedEdgeKind);
    assert!(oneiron::edge::validate_public_edge_creation_kind(EdgeKind::Carries).is_err());
    assert_eq!(EdgeKind::from_name("carries"), Some(EdgeKind::Carries));
    assert_eq!(EdgeKind::Carries.default_weight(), None);
}

#[test]
fn a_working_set_over_the_cap_is_refused() {
    let fixture = fixture();
    let refs: Vec<EntityId> = (0..=MAX_WORKING_SET_REFS)
        .map(|_| EntityId::now())
        .collect();
    let refused = fixture
        .compact(1, 2, &refs)
        .expect_err("a working set over the cap");
    assert!(
        format!("{refused:?}").contains("at most"),
        "the refusal names the cap: {refused:?}"
    );
}
