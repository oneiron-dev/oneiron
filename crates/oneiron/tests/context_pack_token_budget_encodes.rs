//! A context pack's serialized-output token budget costs at most seven
//! whole-pack encodes per serialized pack (F21-RULINGS-ENGINE B5, H68; FIX 198
//! F21(c)): "One estimated batch plus a minimal-pack fallback. At most 3 exact
//! measurements, or 6 with the L2 restart, so 7 encodes in all." Main measured
//! the whole pack again after each row it dropped, inside a fixed-point loop of
//! up to 16 passes, so a request with many rows and a tight `token_budget` paid
//! one more encode for each row cut.
//!
//! The pack is a real one: the context-pack builder over a seeded vault, then
//! `serialize::serialize_pack` in JSON with stats, as a rendered recall uses
//! them. One door counts the encodes (`test_doors::pack_encode_work`). The rows
//! that survive a cut are not pinned: the ruling accepts that the fallback can
//! drop more than one-at-a-time trimming did.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test context_pack_token_budget_encodes`
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::context_pack::{ContextPack, DEFAULT_MAX_FIELD_CHARS, L2BaseSummary, TokenAllocation};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::serialize::pack_format::{FieldProfile, PackFormat};
use oneiron::serialize::{SerializeConfig, project_pack_for_json_response, serialize_pack};
use oneiron::test_doors::pack_encode_work::count_pack_encodes;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig, count_context_pack_tokens,
};
use serde_json::Value;

const LEARNED_AT: u64 = 1_780_000_000;
const QUERY: [f32; 4] = [1.0, 0.0, 0.0, 0.0];
/// The ruling's bound: three exact measurements per preparation, two
/// preparations with the L2 restart, and the emission.
const MAX_ENCODES: usize = 7;
/// TURN rows in the fixture, beside the two critical claims.
const TURNS: usize = 96;
/// Text only the critical claims carry.
const CRITICAL_MARKERS: [&str; 2] = ["critical-claim-alpha", "critical-claim-beta"];
/// Text only the L2 base carries.
const L2_MARKER: &str = "l2-base-summary-marker";

struct Fixture {
    _dir: tempfile::TempDir,
    pack: ContextPack,
    turn_ids: Vec<EntityId>,
}

/// One rendering of the fixture pack.
struct Rendered {
    text: String,
    root: Value,
    tokens: usize,
    encodes: usize,
}

fn occurred() -> TimeRange {
    TimeRange {
        start: LEARNED_AT,
        end: LEARNED_AT,
    }
}

/// A vault with two claims about one person and `TURNS` turns, ranked by
/// their vectors: the claims first, then the turns in order. The claims are
/// marked critical in the built pack, as a manifest's critical predicate
/// class marks them at hydration.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let mut config = VaultConfig::device();
    config.dimensions = QUERY.len();
    config.embedding_model = Some("test/model@v1".to_owned());
    config.map_size = 64 * 1024 * 1024;
    let vault = Vault::open(dir.path(), config).expect("open vault");

    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            occurred(),
            LEARNED_AT,
            b"subject",
        )
        .expect("subject entity");

    let mut claims = Vec::new();
    for marker in CRITICAL_MARKERS {
        let claim = EntityId::now();
        let mut body = ClaimBody::new(
            "profile.note",
            ClaimSubject::Entity(subject),
            rmpv::Value::from(format!("{marker} prefers the window seat")),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .expect("claim body");
        body.source = Some(ClaimSource::UserStated);
        vault
            .put_claim(&claim, &body, occurred(), LEARNED_AT)
            .expect("seed claim");
        claims.push(claim);
    }

    let mut batch = vault.batch();
    for (index, claim) in claims.iter().enumerate() {
        batch = batch.vector(claim, &[1.0, 0.001 * index as f32, 0.0, 0.0]);
    }
    let mut turn_ids = Vec::with_capacity(TURNS);
    for index in 0..TURNS {
        let turn = EntityId::now();
        let text = format!("the harbour pilot logged crossing number {index} at dawn");
        let body: BTreeMap<&str, &str> = [("txt", text.as_str()), ("spkr", "user")]
            .into_iter()
            .collect();
        batch = batch
            .put(
                &turn,
                ENTITY_TYPE_TURN,
                occurred(),
                LEARNED_AT,
                &rmp_serde::to_vec_named(&body).expect("turn body"),
            )
            .vector(&turn, &[1.0, 0.01 * (index + 1) as f32, 0.0, 0.0]);
        turn_ids.push(turn);
    }
    batch.commit().expect("seed turns and vectors");

    let limit = TURNS + claims.len();
    let mut pack = vault
        .context_pack()
        .search_vector(&QUERY, limit)
        .limit(limit)
        .field_profile(FieldProfile::Full)
        .run()
        .expect("context pack");
    for entity in &mut pack.results {
        if claims.contains(&entity.id) {
            entity.critical = true;
        }
    }
    let critical = pack.results.iter().filter(|entity| entity.critical).count();
    assert_eq!(critical, 2, "fixture: the pack holds both critical claims");
    assert!(
        pack.results.len() >= 34,
        "fixture: the pack holds the claims and at least 32 turns, got {} rows",
        pack.results.len()
    );
    assert!(
        pack.l2_base.is_none(),
        "fixture: no L2 base until a test adds one"
    );

    Fixture {
        _dir: dir,
        pack,
        turn_ids,
    }
}

fn config(budget: usize) -> SerializeConfig {
    SerializeConfig {
        format: PackFormat::Json,
        profile: FieldProfile::Full,
        budget,
        allocation: TokenAllocation::default(),
        include_stats: true,
        merge_neighbors: false,
        max_field_chars: DEFAULT_MAX_FIELD_CHARS,
        max_item_tokens: 0,
    }
}

/// `budget` 0 is no budget.
fn render(pack: &ContextPack, budget: usize) -> Rendered {
    let (bytes, encodes) = count_pack_encodes(|| serialize_pack(pack, &config(budget)));
    let text = String::from_utf8(bytes).expect("serialized pack is UTF-8");
    let root = serde_json::from_str(&text).expect("serialized pack is JSON");
    let tokens = count_context_pack_tokens(&text);
    Rendered {
        text,
        root,
        tokens,
        encodes,
    }
}

impl Rendered {
    /// The pack under an L2 prefix sits in `delta`.
    fn body(&self) -> &Value {
        self.root.get("delta").unwrap_or(&self.root)
    }

    /// Rows across the results and neighbors sections.
    fn rows(&self) -> usize {
        ["results", "neighbors"]
            .iter()
            .filter_map(|section| self.body().get(section)?.as_object())
            .flat_map(|groups| groups.values())
            .filter_map(Value::as_array)
            .map(Vec::len)
            .sum()
    }

    /// The stats' `dropped` count and reason; (0, "") when nothing dropped.
    fn dropped(&self) -> (u64, String) {
        let dropped = &self.body()["stats"]["dropped"];
        (
            dropped["count"].as_u64().unwrap_or(0),
            dropped["reason"].as_str().unwrap_or("").to_owned(),
        )
    }

    fn critical_over_budget(&self) -> bool {
        self.body()["stats"]["critical_over_budget"] == Value::Bool(true)
    }
}

/// The encode bound, the budget, and the token stats' total against the bytes
/// (`project_pack_for_json_response` prepares the same JSON pack and keeps
/// its stats).
fn assert_budgeted(pack: &ContextPack, budget: usize, rendered: &Rendered, case: &str) {
    assert!(
        rendered.encodes <= MAX_ENCODES,
        "{case}: serializing at token_budget {budget} took {} whole-pack encodes, over the \
         ruling's {MAX_ENCODES}",
        rendered.encodes
    );
    assert!(
        rendered.tokens <= budget,
        "{case}: the serialized pack is {} tokens, over its token_budget {budget}",
        rendered.tokens
    );
    let projected = project_pack_for_json_response(pack.clone(), &config(budget));
    assert_eq!(
        projected.stats.tokens.total_tokens, rendered.tokens,
        "{case}: the token stats' total is the serialized pack's exact count"
    );
}

/// A budget the per-row estimates fit but the serialized rows do not (each
/// JSON row also carries its score): preparation keeps every row, and the
/// serialized-output budget must drop the overflow. Main dropped it one row
/// and one whole-pack encode at a time.
#[test]
fn late_token_budget_drops_stay_within_seven_encodes() {
    let fixture = fixture();
    let full = render(&fixture.pack, 0);
    let rows = full.rows();
    for overflow_per_row in [1, 2, 4] {
        let budget = full.tokens - overflow_per_row * rows;
        let case = format!("late drops, {overflow_per_row} token(s) per row over");
        let rendered = render(&fixture.pack, budget);
        assert_budgeted(&fixture.pack, budget, &rendered, &case);

        let (dropped, reason) = rendered.dropped();
        assert!(dropped > 0, "{case}: the pack over its budget drops rows");
        assert_eq!(
            reason, "token_budget",
            "{case}: the token budget drops them"
        );
        assert!(
            rendered.rows() * 4 >= rows * 3,
            "{case}: a cut of a few tokens per row keeps at least three quarters of the {rows} \
             rows, kept {}",
            rendered.rows()
        );
        for marker in CRITICAL_MARKERS {
            assert!(
                rendered.text.contains(marker),
                "{case}: the critical claim {marker} outlasts the non-critical turns"
            );
        }
        assert!(
            !rendered.critical_over_budget(),
            "{case}: no critical row was cut"
        );
    }
}

/// A budget a quarter of the pack's size: the per-type split cuts rows first,
/// and the serialized-output budget then trims what the estimates missed.
#[test]
fn deep_token_budget_cuts_stay_within_seven_encodes() {
    let fixture = fixture();
    let full = render(&fixture.pack, 0);
    let budget = full.tokens / 4;
    let rendered = render(&fixture.pack, budget);
    assert_budgeted(&fixture.pack, budget, &rendered, "deep cut");
    assert!(
        rendered.rows() > 0,
        "deep cut: a quarter of the pack's tokens still holds rows"
    );
    assert!(rendered.dropped().0 > 0, "deep cut: rows were dropped");
}

/// An L2 base whose evidence is two of the turns. Under a budget that leaves
/// room for it the cut takes rows and keeps the base; under a budget smaller
/// than the base the base goes too, and the pack is prepared once more
/// without it (the L2 restart): six measurements and the emission at most.
#[test]
fn an_l2_base_pack_stays_within_seven_encodes_through_the_restart() {
    let mut fixture = fixture();
    let mut evidence_ids = fixture.turn_ids[..2].to_vec();
    evidence_ids.sort();
    let body = format!("{L2_MARKER} ").repeat(120);
    fixture.pack.l2_base = Some(L2BaseSummary {
        content_hash: [0x5A; 32],
        body: Arc::from(body.as_str()),
        evidence_ids,
        subjects: Vec::new(),
        max_field_chars: 0,
    });
    let pack = &fixture.pack;

    let full = render(pack, 0);
    assert!(
        full.text.contains(L2_MARKER),
        "fixture: the unbudgeted pack carries the L2 base"
    );
    let base_tokens = count_context_pack_tokens(&body);

    let roomy = full.tokens - 2 * full.rows();
    let rendered = render(pack, roomy);
    assert_budgeted(pack, roomy, &rendered, "L2 base kept");
    assert!(
        rendered.text.contains(L2_MARKER),
        "L2 base kept: a cut of two tokens per row takes rows, not the base"
    );
    assert!(rendered.dropped().0 > 0, "L2 base kept: rows were dropped");

    let tight = base_tokens / 2;
    let rendered = render(pack, tight);
    assert_budgeted(pack, tight, &rendered, "L2 base dropped");
    assert!(
        !rendered.text.contains(L2_MARKER),
        "L2 base dropped: a budget half the base's size cannot hold it"
    );
    assert!(
        rendered.root.get("l2_base").is_none(),
        "L2 base dropped: no L2 prefix"
    );
    assert_eq!(
        rendered.dropped().1,
        "token_budget",
        "L2 base dropped: the token budget dropped it"
    );
}

/// Control, green on main too: a budget the pack fits, and a zero budget
/// (no budget), emit the unbudgeted bytes and drop nothing.
#[test]
fn a_fitting_or_zero_budget_keeps_every_row() {
    let fixture = fixture();
    let full = render(&fixture.pack, 0);
    assert!(
        full.encodes <= MAX_ENCODES,
        "zero budget: {} whole-pack encodes",
        full.encodes
    );
    assert_eq!(full.dropped().0, 0, "zero budget: nothing dropped");
    assert_eq!(
        full.rows(),
        fixture.pack.results.len() + fixture.pack.neighbors.len(),
        "zero budget: every row emitted"
    );

    let rendered = render(&fixture.pack, full.tokens);
    assert_budgeted(&fixture.pack, full.tokens, &rendered, "fitting budget");
    assert_eq!(
        rendered.text, full.text,
        "fitting budget: the pack it fits is emitted unchanged"
    );
}
