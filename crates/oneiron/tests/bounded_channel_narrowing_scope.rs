//! [BOUNDED-CHANNEL-NARROWING-OMITS-CRITICALITY-STALE-DISCLOSURE]: a call
//! narrowed by the manifest's criticality tier asks that tier at the vector,
//! text and temporal fetches, so a claim of the other tier takes no rank in
//! the first blend; a run under every world asks the stale federated worlds
//! there too, so a claim of a world a terminal pact stamped stale takes none
//! either. Before, these channels decided whether to ask the call's scope by
//! a narrowing test that left both out: such a run fetched the claim
//! unasked, counted it as a candidate in scope, and the post-blend filter
//! that dropped it made the run read `FilterMatchedNone`, the defect class
//! of [PHONETIC-EXACT-HITS-UNSCOPED-BEFORE-BLEND].
//!
//! Each tier test first asks with the claim's own tier, and each stale-world
//! test first stamps another world stale: the narrowed fetch still finds the
//! claim.
//!
//! A narrowed text scan keeps what the unnarrowed scan gave (REVIEW-10311
//! round 1): a clamped pack's scan still counts a hidden claim of its tier
//! among the rows its clamp withheld, and a HyDE retry's widened bound
//! still holds, for the main query and for each subquery the retry asks.
//!
//! The temporal window's reader asks the tier and the stale worlds too
//! (REVIEW-10311 round 2): claims of the other tier or of a stale world that
//! fill the widened bound nearer the anchor stop no round of the adaptive
//! window, so it still grows to the eligible claim behind them.
//!
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test bounded_channel_narrowing_scope` (the
//! stale stamp, the clamp's contact and Tier-A mark are stored through test
//! doors).

#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::counterparty_contact::CounterpartyFirstTouch;
use oneiron::entity_id::ForeignWorldId;
use oneiron::federation::Scope;
use oneiron::interlocutor::{Interlocutor, InterlocutorSet};
use oneiron::pipeline::RetrievalParams;
use oneiron::query_expansion::{
    CompletionRequest, EvidenceVerdict, GroundingContext, HydeExpander, HydeExpansion, HydeOptions,
    HydeRequest,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::RetrievalRunRecord;
use oneiron::temporal::TemporalAnchorMode;
use oneiron::test_doors::disclosure_word_sources::{
    clamp_admits_with_contact, mark_tier_a, seed_cleared_contact,
};
use oneiron::test_doors::stale_world_stamp::stamp_world_stale;
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, DisclosureContext,
    EdgeActorClass, EntityId, PipelineBuilder, TimeRange, Vault, VaultConfig, WriteActor,
    WriteEnvelope, WriteProvenance,
};
use oneiron_retrieval::fusion::FUSION_LIST_LENGTH;

const DAY: u64 = 86_400;
const ANCHOR: u64 = 1_700_000_000;
/// The temporal runs' clock: a day after the claim occurred and was learned.
const NOW: u64 = ANCHOR + DAY;
const DIMENSIONS: usize = 4;
/// The text runs' query word; the claim's indexed body holds it alone.
const WORD: &str = "quokka";
/// A word no claim holding [`WORD`] holds: only a HyDE retry's subquery asks it.
const SUBQUERY_WORD: &str = "numbat";
/// No rule of the shipped manifest names this predicate, so it resolves
/// critical by fallback (`tests/owner_approval_criticality_floor.rs`).
const UNDECLARED_PREDICATE: &str = "loop.alpha";
/// The shipped manifest's `profile.` rule resolves this predicate normal.
const NORMAL_PREDICATE: &str = "profile.nickname";
/// How far from [`ANCHOR`] the eligible claim of the window tests occurred:
/// past the first round's 30 days at a 10-day sigma, inside the second's 60.
const BEHIND_THE_FIRST_ROUND: u64 = 45 * DAY;
/// The foreign world the stale-world tests' claim is scoped to.
const CLAIM_WORLD: u8 = 0xf5;
/// A foreign world no claim names.
const OTHER_WORLD: u8 = 0xf6;
/// The contact a clamped pack is assembled for.
const COUNTERPARTY: &str = "owen@example.com";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
}

/// A vault whose runs record their telemetry, so a test reads each run's
/// candidate count and empty reason.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), fixture_config()).expect("open vault");
    Fixture { _dir: dir, vault }
}

fn fixture_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.dimensions = DIMENSIONS;
    // A vector write needs a declared embedding model.
    config.embedding_model = Some("test/model@v1".to_owned());
    config.retrieval_telemetry_capture = true;
    config
}

/// A vault its owner opened, and a contact cleared for every axis: only a
/// Tier-A mark keeps a row from it.
fn clamp_fixture() -> (Fixture, EntityId) {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open_owned(dir.path(), fixture_config()).expect("open vault");
    vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault's owner");
    let contact = EntityId::now();
    seed_cleared_contact(&vault, contact, COUNTERPARTY, Scope::top())
        .expect("FIXTURE: seed the cleared contact");
    (Fixture { _dir: dir, vault }, contact)
}

/// The clamp of a pack the owner holds with `contact` present.
fn with_contact(vault: &Vault, contact: EntityId) -> DisclosureContext {
    DisclosureContext::resolve(
        vault,
        InterlocutorSet::with_session_owner(vec![Interlocutor::known_contact(
            contact,
            COUNTERPARTY,
            CounterpartyFirstTouch::UserIntroduction,
        )]),
    )
    .expect("FIXTURE: resolve the contact's clamp")
}

/// The foreign-range world whose id is `byte` sixteen times.
fn foreign_world(byte: u8) -> ForeignWorldId {
    ForeignWorldId::from_entity_id(EntityId::from_bytes([byte; 16]).expect("FIXTURE: world id"))
        .expect("FIXTURE: a foreign-range world id")
}

/// `query` narrowed to the `critical` tier, or asking every tier on `None`.
fn in_tier(query: PipelineBuilder<'_>, tier: Option<bool>) -> PipelineBuilder<'_> {
    match tier {
        Some(critical) => query.criticality(critical),
        None => query,
    }
}

/// The query vector every vector run asks with.
fn query_vector() -> Vec<f32> {
    vec![1.0, 0.0, 0.0, 0.0]
}

/// What a run returned and what its record says of it.
#[derive(Debug, PartialEq, Eq)]
struct Run {
    ids: Vec<EntityId>,
    total_in_scope: usize,
    empty_reason: Option<String>,
}

/// A run that returned `id` alone, its one candidate in scope.
fn found(id: EntityId) -> Run {
    Run {
        ids: vec![id],
        total_in_scope: 1,
        empty_reason: None,
    }
}

/// A run that met no candidate in scope.
fn no_data() -> Run {
    Run {
        ids: Vec::new(),
        total_in_scope: 0,
        empty_reason: Some("NoData".to_owned()),
    }
}

impl Fixture {
    /// One live critical claim, the vault's only row any channel finds: its
    /// vector is the query's, its indexed body is [`WORD`], and it occurred
    /// and was learned at [`ANCHOR`].
    fn critical_claim(&self) -> EntityId {
        self.claim(None)
    }

    /// As [`Self::critical_claim`], scoped to the foreign `world`.
    fn claim_of_world(&self, world: ForeignWorldId) -> EntityId {
        self.claim(Some(world))
    }

    fn claim(&self, world: Option<ForeignWorldId>) -> EntityId {
        let claim = self.text_claim(world);
        self.vault
            .put_vector(&claim, &query_vector())
            .expect("FIXTURE: put the claim's vector");
        claim
    }

    /// As [`Self::claim`], with no vector: only the text scan finds it.
    fn text_claim(&self, world: Option<ForeignWorldId>) -> EntityId {
        self.text_claim_holding(world, WORD)
    }

    /// A claim as [`Self::text_claim`] writes it, whose indexed body holds
    /// `word` alone.
    fn text_claim_holding(&self, world: Option<ForeignWorldId>, word: &str) -> EntityId {
        let claim = self.claim_at(world, UNDECLARED_PREDICATE, ANCHOR);
        self.vault
            .batch()
            .text(&claim, &[("body", word)])
            .commit()
            .expect("FIXTURE: index the claim's text");
        claim
    }

    /// One live claim on `predicate`, scoped to `world`, that occurred and
    /// was learned at `at`, with no text and no vector: only the temporal
    /// window finds it.
    fn claim_at(&self, world: Option<ForeignWorldId>, predicate: &str, at: u64) -> EntityId {
        let vault = &self.vault;
        let actor = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
        let subject = EntityId::now();
        for id in [actor.entity_ref(), subject] {
            vault
                .put_entity(
                    &id,
                    ENTITY_TYPE_PERSON,
                    TimeRange { start: 1, end: 1 },
                    1,
                    b"",
                )
                .expect("FIXTURE: put person");
        }
        let envelope = WriteEnvelope::new(
            actor,
            ClaimSource::UserStated,
            WriteProvenance::new(rmpv::Value::from("bounded channel narrowing"))
                .expect("FIXTURE: provenance"),
            ClaimApprovalStatus::Auto,
        );
        let mut candidate = ClaimCandidate::new(
            predicate,
            ClaimSubject::Entity(subject),
            rmpv::Value::from("fact"),
            1.0,
        );
        if let Some(world) = world {
            candidate = candidate.with_world(world.entity_id());
        }
        let claim = EntityId::now();
        vault
            .batch()
            .claim_candidate(
                &claim,
                candidate,
                &envelope,
                TimeRange { start: at, end: at },
                at,
            )
            .commit()
            .expect("FIXTURE: write the claim");
        claim
    }

    /// A vector run in `tier` ([`in_tier`]).
    fn vector(&self, tier: Option<bool>) -> Run {
        self.recorded(in_tier(
            self.vault.query().search_vector(&query_vector(), 1),
            tier,
        ))
    }

    /// A text run in `tier`, with no recency blend.
    fn text(&self, tier: Option<bool>) -> Run {
        self.recorded(in_tier(
            self.vault.query().search_text(WORD, 1).boost_recency(0.0),
            tier,
        ))
    }

    /// A temporal run at [`ANCHOR`] in `tier`, with no recency blend.
    fn temporal(&self, tier: Option<bool>) -> Run {
        self.recorded(in_tier(
            self.vault
                .query()
                .with_temporal_now(NOW)
                .search_temporal(ANCHOR, ANCHOR, 1)
                .boost_recency(0.0),
            tier,
        ))
    }

    /// An adaptive temporal run in `tier` at [`ANCHOR`], with a 10-day
    /// sigma, no recency blend and a widened bound at the fusion floor: a
    /// widening multiple of 1 and no floor, so [`FUSION_LIST_LENGTH`] rows
    /// fill it.
    fn adaptive_temporal(&self, tier: Option<bool>) -> Run {
        self.recorded(in_tier(
            self.vault
                .query()
                .with_temporal_now(NOW)
                .search_temporal_with_sigma(
                    ANCHOR,
                    ANCHOR + 1,
                    10 * DAY,
                    TemporalAnchorMode::Occurred,
                    1,
                )
                .temporal_adaptive(true)
                .boost_recency(0.0)
                .retrieval_params(RetrievalParams {
                    temporal_widening_multiple: 1,
                    temporal_widening_floor: 0,
                    ..RetrievalParams::shipped()
                }),
            tier,
        ))
    }

    fn recorded(&self, query: PipelineBuilder<'_>) -> Run {
        self.recorded_at_limit(query, 10)
    }

    fn recorded_at_limit(&self, query: PipelineBuilder<'_>, limit: usize) -> Run {
        let run = query
            .limit(limit)
            .capture_retrieval_trace(true)
            .run_with_telemetry()
            .expect("query");
        let run_id = run
            .run_id
            .expect("FIXTURE: a captured run names its record");
        let record: RetrievalRunRecord = self
            .vault
            .retrieval_run(run_id)
            .expect("read the run record")
            .expect("FIXTURE: the run record is readable");
        Run {
            ids: run.value.into_iter().map(|row| row.id).collect(),
            total_in_scope: record.total_in_scope,
            empty_reason: record.empty_reason,
        }
    }
}

/// A vector run narrowed to the normal tier, whose only hit is a critical
/// claim, counts no candidate in scope and reads `NoData`.
#[test]
fn a_tier_narrowed_vector_run_counts_no_claim_of_the_other_tier() {
    let fixture = fixture();
    let claim = fixture.critical_claim();
    assert_eq!(
        fixture.vector(Some(true)),
        found(claim),
        "GUARD: narrowed to its own tier, the vector fetch finds the claim"
    );
    assert_eq!(
        fixture.vector(Some(false)),
        no_data(),
        "FAILBEFORE BOUNDED-CHANNEL-NARROWING-OMITS-CRITICALITY-STALE-DISCLOSURE: the vector \
         fetch left the tier unasked, so the critical claim counted as a candidate and the \
         post-blend filter made the run read FilterMatchedNone"
    );
}

/// A text run narrowed to the normal tier, whose only hit is a critical
/// claim, counts no candidate in scope and reads `NoData`.
#[test]
fn a_tier_narrowed_text_run_counts_no_claim_of_the_other_tier() {
    let fixture = fixture();
    let claim = fixture.critical_claim();
    assert_eq!(
        fixture.text(Some(true)),
        found(claim),
        "GUARD: narrowed to its own tier, the text scan finds the claim"
    );
    assert_eq!(
        fixture.text(Some(false)),
        no_data(),
        "FAILBEFORE BOUNDED-CHANNEL-NARROWING-OMITS-CRITICALITY-STALE-DISCLOSURE: the text \
         scan left the tier unasked, so the critical claim counted as a candidate and the \
         post-blend filter made the run read FilterMatchedNone"
    );
}

/// A temporal run narrowed to the normal tier, whose only hit is a critical
/// claim, counts no candidate in scope and reads `NoData`.
#[test]
fn a_tier_narrowed_temporal_run_counts_no_claim_of_the_other_tier() {
    let fixture = fixture();
    let claim = fixture.critical_claim();
    assert_eq!(
        fixture.temporal(Some(true)),
        found(claim),
        "GUARD: narrowed to its own tier, the temporal window finds the claim"
    );
    assert_eq!(
        fixture.temporal(Some(false)),
        no_data(),
        "FAILBEFORE BOUNDED-CHANNEL-NARROWING-OMITS-CRITICALITY-STALE-DISCLOSURE: the temporal \
         window left the tier unasked, so the critical claim counted as a candidate and the \
         post-blend filter made the run read FilterMatchedNone"
    );
}

/// A run under every world whose only hit is a claim of a world a terminal
/// pact stamped stale counts no candidate in scope and reads `NoData`. With
/// only another world stale, the narrowed fetch still finds the claim.
fn assert_stale_world_claim_counts_as_no_candidate(run: impl Fn(&Fixture) -> Run, fetch: &str) {
    let fixture = fixture();
    let world = foreign_world(CLAIM_WORLD);
    let claim = fixture.claim_of_world(world);
    stamp_world_stale(&fixture.vault, foreign_world(OTHER_WORLD))
        .expect("FIXTURE: stamp another world stale");
    assert_eq!(
        run(&fixture),
        found(claim),
        "GUARD: with another world stale, the {fetch} finds the claim of a live world"
    );
    stamp_world_stale(&fixture.vault, world).expect("FIXTURE: stamp the claim's world stale");
    assert_eq!(
        run(&fixture),
        no_data(),
        "FAILBEFORE BOUNDED-CHANNEL-NARROWING-OMITS-CRITICALITY-STALE-DISCLOSURE: the {fetch} \
         left the stale worlds unasked, so the stale world's claim counted as a candidate and \
         the post-blend filter made the run read FilterMatchedNone"
    );
}

#[test]
fn a_vector_run_counts_no_claim_of_a_stale_world() {
    assert_stale_world_claim_counts_as_no_candidate(|fixture| fixture.vector(None), "vector fetch");
}

#[test]
fn a_text_run_counts_no_claim_of_a_stale_world() {
    assert_stale_world_claim_counts_as_no_candidate(|fixture| fixture.text(None), "text scan");
}

#[test]
fn a_temporal_run_counts_no_claim_of_a_stale_world() {
    assert_stale_world_claim_counts_as_no_candidate(
        |fixture| fixture.temporal(None),
        "temporal window",
    );
}

/// REVIEW-10311 round 2: a temporal run narrowed to the normal tier, whose
/// widened bound [`FUSION_LIST_LENGTH`] critical claims at the anchor fill,
/// still grows its adaptive window to the normal claim that occurred
/// [`BEHIND_THE_FIRST_ROUND`] before it. The critical claims stop no round.
#[test]
fn a_tier_narrowed_temporal_window_grows_past_claims_of_the_other_tier() {
    let fixture = fixture();
    let normal = fixture.claim_at(None, NORMAL_PREDICATE, ANCHOR - BEHIND_THE_FIRST_ROUND);
    assert_eq!(
        fixture.adaptive_temporal(Some(false)),
        found(normal),
        "GUARD: alone in the vault, the normal claim is live, of the normal tier, and inside \
         the adaptive window's later rounds"
    );
    for _ in 0..FUSION_LIST_LENGTH {
        fixture.claim_at(None, UNDECLARED_PREDICATE, ANCHOR);
    }
    assert_eq!(
        fixture.adaptive_temporal(Some(false)),
        found(normal),
        "FAILBEFORE REVIEW-10311 round 2: the temporal window asked no reader for the tier, so \
         the critical claims filled its bound in the first round and stopped it there, and the \
         scope's cut dropped them all"
    );
}

/// REVIEW-10311 round 2: a temporal run under every world, whose widened
/// bound [`FUSION_LIST_LENGTH`] claims of a stale world at the anchor fill,
/// still grows its adaptive window to the live claim that occurred
/// [`BEHIND_THE_FIRST_ROUND`] before it. The stale world's claims stop no
/// round.
#[test]
fn a_temporal_window_grows_past_claims_of_a_stale_world() {
    let fixture = fixture();
    let live = fixture.claim_at(None, UNDECLARED_PREDICATE, ANCHOR - BEHIND_THE_FIRST_ROUND);
    stamp_world_stale(&fixture.vault, foreign_world(OTHER_WORLD))
        .expect("FIXTURE: stamp another world stale");
    assert_eq!(
        fixture.adaptive_temporal(None),
        found(live),
        "GUARD: with another world stale, the live claim is inside the adaptive window's \
         later rounds"
    );
    let world = foreign_world(CLAIM_WORLD);
    for _ in 0..FUSION_LIST_LENGTH {
        fixture.claim_at(Some(world), UNDECLARED_PREDICATE, ANCHOR);
    }
    stamp_world_stale(&fixture.vault, world).expect("FIXTURE: stamp the claims' world stale");
    assert_eq!(
        fixture.adaptive_temporal(None),
        found(live),
        "FAILBEFORE REVIEW-10311 round 2: the temporal window asked no reader for the stale \
         worlds, so the stale world's claims filled its bound in the first round and stopped it \
         there, and the scope's cut dropped them all"
    );
}

/// REVIEW-10311 round 1, P1 1: a clamped pack's text scan narrowed to a tier
/// scores only the postings its scope admits, and still counts a live claim
/// of that tier its audience may not read among the rows its clamp withheld,
/// as the unnarrowed scan's memory-lane read counted it. Narrowed to the
/// other tier, the hidden claim counts nowhere.
#[test]
fn a_tier_narrowed_clamped_text_pack_counts_a_hidden_claim_of_its_tier() {
    let (fixture, contact) = clamp_fixture();
    let vault = &fixture.vault;
    let readable = fixture.text_claim(None);
    let hidden = fixture.text_claim(None);
    mark_tier_a(vault, &hidden).expect("FIXTURE: mark the claim Tier A");
    for (claim, admitted) in [(readable, true), (hidden, false)] {
        assert_eq!(
            clamp_admits_with_contact(vault, contact, COUNTERPARTY, &claim)
                .expect("FIXTURE: ask the clamp"),
            admitted,
            "FIXTURE: only the Tier-A claim is kept from the contact"
        );
    }
    let pack = |critical: bool, clamped: bool| -> (BTreeSet<EntityId>, u64) {
        let mut builder = vault
            .context_pack()
            .search_text(WORD, 10)
            .limit(10)
            .boost_recency(0.0)
            .criticality(critical);
        if clamped {
            builder = builder.disclosure_context(with_contact(vault, contact));
        }
        let run = builder.run_unfinalized_with_telemetry().expect("the pack");
        let served = run.value.results.iter().map(|entity| entity.id).collect();
        (served, run.clamped_out())
    };
    assert_eq!(
        pack(true, false).0,
        BTreeSet::from([readable, hidden]),
        "FIXTURE: the owner's pack narrowed to the critical tier serves both claims"
    );
    assert_eq!(
        pack(false, true),
        (BTreeSet::new(), 0),
        "GUARD: narrowed to the normal tier, the clamped pack serves neither claim and counts \
         neither among the rows its clamp withheld"
    );
    assert_eq!(
        pack(true, true),
        (BTreeSet::from([readable]), 1),
        "FAILBEFORE REVIEW-10311 round 1: the narrowed scan's scope dropped the hidden claim \
         before the memory lane's read counted it, so the clamp's withheld rows missed it"
    );
}

/// A host that finds the evidence short until the run hands it `needed`
/// candidates. Its expansion asks [`WORD`], `subquery` on a retry, and the
/// query vector, which no claim of the HyDE tests holds.
struct NeedsCandidates {
    needed: usize,
    subquery: Option<&'static str>,
}

impl HydeExpander for NeedsCandidates {
    fn id(&self) -> &str {
        "test/needs-candidates"
    }

    fn expand(&self, _: &HydeRequest) -> oneiron::Result<HydeExpansion> {
        Ok(HydeExpansion {
            grounded_query: WORD.to_owned(),
            hypothetical_answer: WORD.to_owned(),
            embedding: query_vector(),
            subqueries: self.subquery.map(str::to_owned).into_iter().collect(),
        })
    }

    fn assess_evidence(&self, request: &CompletionRequest) -> oneiron::Result<EvidenceVerdict> {
        Ok(if request.candidates.len() < self.needed {
            EvidenceVerdict::Insufficient {
                gaps: vec![WORD.to_owned()],
            }
        } else {
            EvidenceVerdict::Sufficient
        })
    }
}

/// REVIEW-10311 round 1, P1 2: a HyDE retry widens the text fetch past the
/// first attempt's bound, and a tier-narrowed scan keeps the widened bound.
/// One claim more than the text bound matches, and the host needs them all:
/// the first attempt hands it the bound, and the retry hands it every claim.
#[test]
fn a_tier_narrowed_text_run_keeps_the_hyde_retry_bound() {
    let fixture = fixture();
    let claims: BTreeSet<EntityId> = (0..=FUSION_LIST_LENGTH)
        .map(|_| fixture.text_claim(None))
        .collect();
    let host = NeedsCandidates {
        needed: claims.len(),
        subquery: None,
    };
    let run = |tier: Option<bool>| -> (BTreeSet<EntityId>, Option<String>) {
        let query = in_tier(
            fixture
                .vault
                .query()
                .search_text(WORD, FUSION_LIST_LENGTH)
                .boost_recency(0.0),
            tier,
        )
        .hyde(
            &host,
            GroundingContext::default(),
            HydeOptions {
                channel_limit: 10,
                retry_once: true,
            },
        );
        let run = fixture.recorded_at_limit(query, claims.len());
        (run.ids.into_iter().collect(), run.empty_reason)
    };
    assert_eq!(
        run(None),
        (claims.clone(), None),
        "GUARD: the unnarrowed run's retry hands the host every claim"
    );
    assert_eq!(
        run(Some(true)),
        (claims.clone(), None),
        "FAILBEFORE REVIEW-10311 round 1: the narrowed scan cut the retry's widened read back \
         to the first bound, so the host found the evidence short twice and the run read \
         BelowThreshold"
    );
}

/// REVIEW-10311 round 2: a HyDE retry's subquery reads past the first
/// attempt's bound as the main query does, and a tier-narrowed scan keeps
/// that bound for the subquery too. One claim holds the query's [`WORD`];
/// one claim more than the text bound holds [`SUBQUERY_WORD`], which only
/// the retry's subquery asks; the host needs every claim.
#[test]
fn a_tier_narrowed_hyde_subquery_keeps_the_retry_bound() {
    let fixture = fixture();
    let mut claims: BTreeSet<EntityId> = (0..=FUSION_LIST_LENGTH)
        .map(|_| fixture.text_claim_holding(None, SUBQUERY_WORD))
        .collect();
    claims.insert(fixture.text_claim(None));
    let host = NeedsCandidates {
        needed: claims.len(),
        subquery: Some(SUBQUERY_WORD),
    };
    let run = |tier: Option<bool>| -> (BTreeSet<EntityId>, Option<String>) {
        let query = in_tier(
            fixture
                .vault
                .query()
                .search_text(WORD, FUSION_LIST_LENGTH)
                .boost_recency(0.0),
            tier,
        )
        .hyde(
            &host,
            GroundingContext::default(),
            HydeOptions {
                channel_limit: 10,
                retry_once: true,
            },
        );
        let run = fixture.recorded_at_limit(query, claims.len());
        (run.ids.into_iter().collect(), run.empty_reason)
    };
    assert_eq!(
        run(None),
        (claims.clone(), None),
        "GUARD: the unnarrowed run's retry subquery hands the host every claim it holds"
    );
    assert_eq!(
        run(Some(true)),
        (claims.clone(), None),
        "FAILBEFORE REVIEW-10311 round 2: the narrowed scan cut the retry subquery's widened \
         read back to the first bound, so the host found the evidence short twice and the run \
         read BelowThreshold"
    );
}
