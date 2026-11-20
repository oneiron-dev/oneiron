//! The narrowed PPR walk spreads no mass along a hub group (row [PPR-NARROWED-WALK-CACHE]; Engine
//! ANSWER PPR-NARROWED-CACHE-DESIGN Q2 = A, 20 Nov 17:18). A (node, kind, direction) group with
//! more than K edges that pass the walk's gates and the reader's visibility spreads no mass; K is
//! the owner's Setting `retrieval.ppr.narrowed_hub_fanout_cap`. The unscoped walk keeps its cached
//! ranking.
//!
//! The fixture is one hub TASK row and leaf rows, each joined to the hub by one About edge. Leaf 0
//! carries the query's one text match and is the walk's one seed. At depth 2 the walk reaches the
//! hub through leaf 0's one outgoing About edge, and every other leaf only through the hub's
//! incoming About group. A type filter (TASK) narrows the walk, as in
//! `tests/scoped_community_prior.rs`; PERSON leaves are the rows that filter hides.
//!
//! `cargo test --locked -p oneiron --all-features --test ppr_narrowed_hub_fanout_cap`
#![allow(clippy::expect_used)]

use oneiron::habit::TaskRole;
use oneiron::pipeline::ScoredEntity;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeKind, EntityId, TimeRange, Vault, VaultConfig};

const LEARNED_AT: u64 = 1_772_400_000;
const QUERY: &str = "narrowedhubfanoutcap";
const LIMIT: usize = 64;
const CAP_KEY: &str = "retrieval.ppr.narrowed_hub_fanout_cap";
/// Visible leaves of the hub that is above the default cap: the default is below this count.
const ABOVE_DEFAULT_LEAVES: u16 = 1_025;

fn id(group: u8, index: u16) -> EntityId {
    let [high, low] = index.to_be_bytes();
    EntityId::from_bytes([
        0x6b, 0x1d, 0x4e, group, high, low, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
        0x44,
    ])
    .expect("FIXTURE: an id")
}

fn task_body() -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("role"),
            rmpv::Value::from(TaskRole::Task.role_byte()),
        )]),
    )
    .expect("FIXTURE: a TASK body");
    body
}

fn at() -> TimeRange {
    TimeRange {
        start: LEARNED_AT,
        end: LEARNED_AT,
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    vault: Vault,
    hub: EntityId,
    /// Leaf 0 (the seed) first.
    leaves: Vec<EntityId>,
    hidden: Vec<EntityId>,
}

impl Fixture {
    /// One hub with `visible` TASK leaves and `hidden` PERSON leaves, every leaf joined to the
    /// hub by one About edge.
    fn new(visible: u16, hidden: u16) -> Self {
        let directory = tempfile::tempdir().expect("FIXTURE: a vault directory");
        let mut config = VaultConfig::device();
        config.embedding_model = None;
        let vault = Vault::open(directory.path(), config).expect("FIXTURE: a vault");
        let body = task_body();
        let hub = id(0x01, 0);
        let leaves: Vec<_> = (0..visible).map(|index| id(0x02, index)).collect();
        let hidden: Vec<_> = (0..hidden).map(|index| id(0x03, index)).collect();
        let mut batch = vault
            .batch()
            .put(&hub, ENTITY_TYPE_TASK, at(), LEARNED_AT, &body);
        for leaf in &leaves {
            batch = batch
                .put(leaf, ENTITY_TYPE_TASK, at(), LEARNED_AT, &body)
                .edge(leaf, EdgeKind::About, &hub, 1.0);
        }
        for leaf in &hidden {
            batch = batch
                .put(leaf, ENTITY_TYPE_PERSON, at(), LEARNED_AT, b"human")
                .edge(leaf, EdgeKind::About, &hub, 1.0);
        }
        batch.commit().expect("FIXTURE: the hub and its leaves");
        vault
            .batch()
            .text(&leaves[0], &[("body", QUERY)])
            .commit()
            .expect("FIXTURE: the query's one text match");
        let hits: Vec<_> = vault
            .search_text(QUERY, LIMIT)
            .expect("FIXTURE: the text index")
            .into_iter()
            .map(|hit| hit.id)
            .collect();
        assert_eq!(hits, vec![leaves[0]], "FIXTURE: the query matches leaf 0");
        Self {
            _directory: directory,
            vault,
            hub,
            leaves,
            hidden,
        }
    }

    /// The owner sets the cap.
    fn set_cap(&self, cap: u32) {
        let owner = self
            .vault
            .ensure_embedded_owner_actor()
            .expect("FIXTURE: the embedded owner");
        let proof = self
            .vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("FIXTURE: the owner proof");
        let outcome = self
            .vault
            .set_setting(
                SettingCaller::Owner(&proof),
                SetSetting::vault_value(CAP_KEY, serde_json::json!(cap)),
            )
            .expect("FIXTURE: the owner sets the hub cap");
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "FIXTURE: the owner's change applies: {outcome:?}"
        );
    }

    fn walk(&self, narrowed: bool) -> Vec<ScoredEntity> {
        let mut query = self
            .vault
            .query()
            .search_text(QUERY, LIMIT)
            .expand_ppr(&[self.leaves[0]], 2);
        if narrowed {
            query = query.filter_types(&[ENTITY_TYPE_TASK]);
        }
        query.limit(LIMIT).run().expect("the walk runs")
    }

    /// How many leaves other than the seed the walk returned.
    fn other_leaves_in(&self, scores: &[ScoredEntity]) -> usize {
        scores
            .iter()
            .filter(|row| self.leaves[1..].contains(&row.id))
            .count()
    }

    fn holds_hub(&self, scores: &[ScoredEntity]) -> bool {
        scores.iter().any(|row| row.id == self.hub)
    }
}

#[test]
fn a_hub_group_above_the_default_cap_spreads_no_narrowed_mass() {
    let fixture = Fixture::new(ABOVE_DEFAULT_LEAVES, 0);
    let narrowed = fixture.walk(true);
    assert!(
        fixture.holds_hub(&narrowed),
        "FIXTURE: the narrowed walk reaches the hub through leaf 0's one About edge"
    );
    assert_eq!(
        fixture.other_leaves_in(&narrowed),
        0,
        "a hub group of {ABOVE_DEFAULT_LEAVES} visible About edges is above the default cap: \
         the narrowed walk spreads no mass from the hub to the other leaves"
    );
}

#[test]
fn the_unnarrowed_walk_still_spreads_along_the_hub_group() {
    let fixture = Fixture::new(ABOVE_DEFAULT_LEAVES, 0);
    let unnarrowed = fixture.walk(false);
    assert!(
        fixture.other_leaves_in(&unnarrowed) > 0,
        "the cached unscoped walk takes no cap: it reaches the other leaves through the hub"
    );
}

#[test]
fn the_owner_cap_decides_which_group_is_a_hub() {
    let over = Fixture::new(4, 0);
    over.set_cap(3);
    let narrowed = over.walk(true);
    assert!(
        over.holds_hub(&narrowed),
        "FIXTURE: the narrowed walk reaches the hub"
    );
    assert_eq!(
        over.other_leaves_in(&narrowed),
        0,
        "at cap 3, a group of 4 visible About edges spreads no narrowed mass"
    );

    let at_cap = Fixture::new(3, 0);
    at_cap.set_cap(3);
    assert_eq!(
        at_cap.other_leaves_in(&at_cap.walk(true)),
        2,
        "at cap 3, a group of 3 visible About edges spreads to both other leaves"
    );

    let raised = Fixture::new(ABOVE_DEFAULT_LEAVES, 0);
    raised.set_cap(u32::from(ABOVE_DEFAULT_LEAVES));
    assert!(
        raised.other_leaves_in(&raised.walk(true)) > 0,
        "the owner's cap of {ABOVE_DEFAULT_LEAVES} lets a group of that many edges spread"
    );
}

#[test]
fn a_hidden_leaf_never_counts_toward_the_cap() {
    let fixture = Fixture::new(3, 2);
    fixture.set_cap(3);
    let narrowed = fixture.walk(true);
    assert!(
        narrowed.iter().all(|row| !fixture.hidden.contains(&row.id)),
        "a PERSON leaf the type filter hides is never returned"
    );
    assert_eq!(
        fixture.other_leaves_in(&narrowed),
        2,
        "the hub's group holds 5 About edges but only 3 the reader sees: at cap 3 it still \
         spreads to both other visible leaves"
    );
}
