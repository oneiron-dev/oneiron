//! L9-13 (ARCH-0004 #rerank-door-open, "the pinned body for assembly's later
//! stages"; Sol R14 S2 on #1426): a context pack reads each claim it serves
//! at the body it serves. A pin serves its own words: a hit a reranker scored
//! at its words, an Indexed pack, a history pin. Retrieval's claim gate read
//! the live row. Before, hydration handed back only the projected fields, and
//! the stages after it (world grouping, reference validation, source
//! ranking) read the gate's live body: a pinned claim was checked and ranked
//! as another body than the one it showed.
//!
//! Public crate surface only: `Vault::put_entity`, `Vault::put_claim`, a
//! vector batch, `Vault::pin_entity_revision`, and the context pack builder.
//!
//! Fleet: `cargo test --locked -p oneiron --all-features --test context_pack_served_claim_body`

use std::collections::BTreeMap;

use oneiron::context_pack::source_ranking::SourceRankingPolicy;
use oneiron::error::RecordError;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, ContextPack,
    EntityId, Error, TimeRange, Vault, VaultConfig,
};
use oneiron_store::vault::entity_revision::types::ReadMode;

const LEARNED_AT: u64 = 1_780_000_000;
const QUERY: [f32; 4] = [1.0, 0.0, 0.0, 0.0];

fn seed_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("valid entity id")
}

fn occurred() -> TimeRange {
    TimeRange {
        start: LEARNED_AT,
        end: LEARNED_AT,
    }
}

/// One claim about a stored PERSON, the query's nearest vector.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    claim: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let mut config = VaultConfig::device();
    config.dimensions = QUERY.len();
    config.embedding_model = Some("test/model@v1".to_owned());
    config.map_size = 16 * 1024 * 1024;
    let vault = Vault::open(dir.path(), config).expect("open vault");
    vault
        .put_entity(
            &seed_id(0x21),
            ENTITY_TYPE_PERSON,
            occurred(),
            LEARNED_AT,
            b"subject",
        )
        .expect("subject entity");
    Fixture {
        _dir: dir,
        vault,
        claim: seed_id(0x31),
    }
}

/// A claim about the fixture's PERSON saying `words`, from `source`.
fn claim_body(words: &str, source: ClaimSource) -> ClaimBody {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(seed_id(0x21)),
        rmpv::Value::from(words),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    body.source = Some(source);
    body
}

impl Fixture {
    /// Puts the claim as `pinned`, pins that revision, then puts it again as
    /// `live`, the row retrieval's claim gate reads, and gives it the query's
    /// vector. Returns the pin.
    fn pin_then_rewrite(&self, pinned: &ClaimBody, live: &ClaimBody) -> ReadMode {
        self.vault
            .put_claim(&self.claim, pinned, occurred(), LEARNED_AT)
            .expect("pinned claim body");
        let pin = self
            .vault
            .pin_entity_revision(&self.claim)
            .expect("pin the first revision");
        self.vault
            .put_claim(&self.claim, live, occurred(), LEARNED_AT)
            .expect("live claim body");
        self.vault
            .batch()
            .vector(&self.claim, &QUERY)
            .commit()
            .expect("claim vector");
        ReadMode::Pinned(pin)
    }

    fn pack(
        &self,
        read_mode: ReadMode,
        policy: Option<SourceRankingPolicy>,
    ) -> oneiron::Result<ContextPack> {
        let mut builder = self
            .vault
            .context_pack()
            .search_vector(&QUERY, 10)
            .read_mode(read_mode)
            .limit(10);
        if let Some(policy) = policy {
            builder = builder.source_ranking(policy);
        }
        builder.run()
    }

    /// The served claim's words and source, as the pack shows them.
    fn served(&self, pack: &ContextPack) -> Option<(serde_json::Value, serde_json::Value)> {
        pack.results
            .iter()
            .find(|entity| entity.id == self.claim)
            .and_then(|entity| entity.fields.as_ref())
            .map(|fields| {
                let field = |key: &str| fields.get(key).cloned().unwrap_or_default();
                (field("val"), field("src"))
            })
    }
}

/// Control: a consistent history pin is served at its own words, and the
/// pack reads its live row at the live words. This passes on main too.
#[test]
fn a_history_pin_serves_its_own_claim_words() {
    let fixture = fixture();
    let pin = fixture.pin_then_rewrite(
        &claim_body("old-words", ClaimSource::UserStated),
        &claim_body("new-words", ClaimSource::UserStated),
    );

    let live = fixture.pack(ReadMode::Live, None).expect("live pack");
    assert_eq!(
        fixture.served(&live),
        Some((
            serde_json::json!("new-words"),
            serde_json::json!("user_stated")
        )),
        "FIXTURE: a live pack serves the claim's live words: {:?}",
        live.results
    );
    let pinned = fixture.pack(pin, None).expect("pinned pack");
    assert_eq!(
        fixture.served(&pinned),
        Some((
            serde_json::json!("old-words"),
            serde_json::json!("user_stated")
        )),
        "a history pin serves the words its revision holds: {:?}",
        pinned.results
    );
}

/// Reference validation reads the served body. The pinned revision's
/// validity ends before it starts; the live revision states no validity.
/// A pack that serves the pinned body refuses it as it would refuse the
/// live row with that body. On main the pack checked the live row and served
/// the impossible window.
#[test]
fn a_pack_validates_the_claim_body_it_serves_at_a_pin() {
    let fixture = fixture();
    let mut impossible = claim_body("old-words", ClaimSource::UserStated);
    impossible.valid_from = Some(2_000);
    impossible.valid_to = Some(1_000);
    let pin = fixture.pin_then_rewrite(
        &impossible,
        &claim_body("new-words", ClaimSource::UserStated),
    );

    let live = fixture.pack(ReadMode::Live, None).expect("live pack");
    assert_eq!(
        fixture.served(&live).map(|(words, _)| words),
        Some(serde_json::json!("new-words")),
        "FIXTURE: the live row is consistent and served: {:?}",
        live.results
    );

    match fixture.pack(pin, None) {
        Err(Error::Record(RecordError::ContextPackValidation { id, reason })) => {
            assert_eq!(id, fixture.claim, "the refusal names the pinned claim");
            assert_eq!(reason, "impossible time ordering");
        }
        Err(other) => panic!("expected the pinned claim's validation refusal, got {other:?}"),
        Ok(pack) => panic!(
            "a pack validates the claim body it serves at a pin, not the live row the gate \
             read: it served {:?}",
            fixture.served(&pack)
        ),
    }
}

/// Source ranking reads the served body. The pinned revision is observed,
/// the live one user-stated, and the pack's policy weighs an observation at
/// zero. The pinned row is served as observed, so it scores zero. On main it
/// kept its retrieval score, ranked by the live row's source.
#[test]
fn a_pack_ranks_a_pinned_claim_by_the_source_it_serves() {
    let fixture = fixture();
    let pin = fixture.pin_then_rewrite(
        &claim_body("old-words", ClaimSource::Observed),
        &claim_body("new-words", ClaimSource::UserStated),
    );
    let policy = SourceRankingPolicy {
        pack: "test.served_claim_body".to_owned(),
        multipliers: BTreeMap::from([
            ("observed".to_owned(), 0.0),
            ("user_stated".to_owned(), 1.0),
        ]),
    };

    let live = fixture
        .pack(ReadMode::Live, Some(policy.clone()))
        .expect("live pack");
    let live_score = live
        .results
        .iter()
        .find(|entity| entity.id == fixture.claim)
        .map(|entity| entity.score);
    assert!(
        live_score.is_some_and(|score| score > 0.0),
        "FIXTURE: the live user-stated row keeps a positive score: {:?}",
        live.results
    );

    let pinned = fixture.pack(pin, Some(policy)).expect("pinned pack");
    assert_eq!(
        fixture.served(&pinned),
        Some((
            serde_json::json!("old-words"),
            serde_json::json!("observed")
        )),
        "FIXTURE: the pin serves its observed words: {:?}",
        pinned.results
    );
    let pinned_score = pinned
        .results
        .iter()
        .find(|entity| entity.id == fixture.claim)
        .map(|entity| entity.score);
    assert_eq!(
        pinned_score,
        Some(0.0),
        "a pinned claim is ranked by the source it serves, observed, which this policy weighs at zero"
    );
}
