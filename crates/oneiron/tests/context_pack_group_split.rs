//! A context pack whose rows fit its token budget keeps every row (FIX
//! [CONTEXT-PACK-GROUP-SPLIT-DROPS-ROW]). A section that fits is handed
//! exactly its need, and the per-type split then floored each type's share
//! of that need: in a mixed CLAIM + TURN pack one type ended a token short and
//! lost its row, at 8192 tokens as at 65536 (E2E MEMORY-05). A pack whose
//! need does not fit still cuts by type share.
//!
//! The door is the one `POST /v1/core/context-pack` takes: the context-pack
//! builder's `run_projected_json_with_telemetry`, with the JSON projection
//! config that route builds for `view: full` and a `token_budget`.
//!
//! `cargo test --locked -p oneiron --all-features --test context_pack_group_split`

use std::collections::BTreeMap;

use oneiron::context_pack::DEFAULT_MAX_FIELD_CHARS;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::serialize::SerializeConfig;
use oneiron::serialize::pack_accounting::PackItemAccountingReason;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, ContextPack,
    EntityId, FieldProfile, PackFormat, TimeRange, TokenAllocation, Vault, VaultConfig,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const LEARNED_AT: u64 = 1_780_000_000;
const QUERY: [f32; 4] = [1.0, 0.0, 0.0, 0.0];
/// 49 characters; nine of them stay under the 500-character field cap.
const TURN_SENTENCE: &str = "the harbour pilot logged a calm crossing at dawn ";
/// The budgets E2E MEMORY-05 lost a row at.
const FITTING_BUDGETS: [usize; 2] = [8192, 65_536];

/// One claim about a person and one TURN that outranks it.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    claim: EntityId,
    turn: EntityId,
}

fn sentences(count: usize) -> String {
    TURN_SENTENCE.repeat(count)
}

fn fixture(turn_fields: &[(&str, String)]) -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.dimensions = QUERY.len();
    config.embedding_model = Some("test/model@v1".to_owned());
    config.map_size = 16 * 1024 * 1024;
    let vault = Vault::open(dir.path(), config)?;

    let occurred = TimeRange {
        start: LEARNED_AT,
        end: LEARNED_AT,
    };
    let subject = EntityId::now();
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        occurred,
        LEARNED_AT,
        b"subject",
    )?;

    let claim = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("prefers the window seat on the morning ferry"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    vault.put_claim(&claim, &body, occurred, LEARNED_AT)?;

    let turn = EntityId::now();
    let turn_body: BTreeMap<&str, &str> = turn_fields
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect();
    // Cosine to QUERY: turn 0.99 > claim 0.8.
    vault
        .batch()
        .put(
            &turn,
            ENTITY_TYPE_TURN,
            occurred,
            LEARNED_AT,
            &rmp_serde::to_vec_named(&turn_body)?,
        )
        .vector(&turn, &[0.99, 0.141, 0.0, 0.0])
        .vector(&claim, &[0.8, 0.6, 0.0, 0.0])
        .commit()?;

    Ok(Fixture {
        _dir: dir,
        vault,
        claim,
        turn,
    })
}

impl Fixture {
    /// The pack `POST /v1/core/context-pack` answers for `view: full`, with
    /// `budget.token_budget` when `token_budget` is set.
    fn pack(&self, token_budget: Option<usize>) -> Result<ContextPack, Box<dyn std::error::Error>> {
        let mut builder = self
            .vault
            .context_pack()
            .search_vector(&QUERY, 10)
            .limit(10)
            .field_profile(FieldProfile::Full);
        if let Some(budget) = token_budget {
            builder = builder.token_budget(budget);
        }
        let projection = SerializeConfig {
            format: PackFormat::Json,
            profile: FieldProfile::Full,
            budget: token_budget.unwrap_or(0),
            allocation: TokenAllocation::default(),
            include_stats: false,
            merge_neighbors: false,
            max_field_chars: DEFAULT_MAX_FIELD_CHARS,
            max_item_tokens: 0,
        };
        Ok(builder
            .run_projected_json_with_telemetry(&projection)?
            .value)
    }

    /// Which of the fixture's two rows the pack's results hold.
    fn kept(&self, pack: &ContextPack) -> (bool, bool) {
        let holds = |id: EntityId| pack.results.iter().any(|entity| entity.id == id);
        (holds(self.claim), holds(self.turn))
    }

    fn score(&self, pack: &ContextPack, id: EntityId) -> Option<f32> {
        pack.results
            .iter()
            .find(|entity| entity.id == id)
            .map(|entity| entity.score)
    }
}

/// The row lost on main depends on which type's share the floor cut: four
/// TURN sizes give four different needs, and each must keep both rows.
#[test]
fn a_claim_and_turn_pack_that_fits_its_token_budget_keeps_both_rows() -> TestResult {
    for count in [1, 3, 6, 9] {
        let fixture = fixture(&[("txt", sentences(count)), ("spkr", "user".to_owned())])?;
        let unbudgeted = fixture.pack(None)?;
        assert_eq!(
            fixture.kept(&unbudgeted),
            (true, true),
            "fixture ({count} sentences): a pack with no token budget holds the claim and the turn"
        );

        for budget in FITTING_BUDGETS {
            let pack = fixture.pack(Some(budget))?;
            let (claim_kept, turn_kept) = fixture.kept(&pack);
            assert!(
                claim_kept && turn_kept,
                "a {count}-sentence turn beside one claim fits {budget} tokens, yet the pack \
                 dropped {}; items_dropped {{count {}, reason {}}}",
                match (claim_kept, turn_kept) {
                    (false, false) => "both rows",
                    (false, true) => "the claim",
                    _ => "the turn",
                },
                pack.stats.items_dropped.count,
                pack.stats.items_dropped.reason.as_str(),
            );
            assert_eq!(
                pack.stats.items_dropped.count, 0,
                "a pack that fits {budget} tokens drops nothing ({count} sentences)"
            );
        }
    }
    Ok(())
}

/// A turn longer than the whole budget beside one short claim: the summed
/// need does not fit, so the per-type split still runs. The turn outranks the
/// claim, yet the claims' share keeps the claim and the turn is the row cut,
/// as before the fix.
#[test]
fn a_claim_and_turn_pack_over_its_token_budget_still_cuts_by_type_share() -> TestResult {
    let long = sentences(9);
    let fixture = fixture(&[
        ("txt", long.clone()),
        ("sess", long.clone()),
        ("spkr", long),
    ])?;
    let unbudgeted = fixture.pack(None)?;
    assert_eq!(
        fixture.kept(&unbudgeted),
        (true, true),
        "fixture: a pack with no token budget holds the claim and the turn"
    );
    let (turn_score, claim_score) = (
        fixture.score(&unbudgeted, fixture.turn),
        fixture.score(&unbudgeted, fixture.claim),
    );
    assert!(
        turn_score > claim_score,
        "fixture: the turn outranks the claim (turn {turn_score:?}, claim {claim_score:?})"
    );

    let pack = fixture.pack(Some(256))?;
    assert_eq!(
        fixture.kept(&pack),
        (true, false),
        "over 256 tokens the claims' share keeps the claim and the turn is cut"
    );
    assert_eq!(pack.stats.items_dropped.count, 1, "one row dropped");
    assert_eq!(
        pack.stats.items_dropped.reason,
        PackItemAccountingReason::TokenBudget,
        "the token budget dropped it"
    );
    Ok(())
}
