//! The engine labels gated retrieval outcomes itself (census L9-06, ARCH-0037
//! #reward: "Production writes no gated outcomes" until now). The owner's
//! `vault.retrieval.policy.update` labels, before it learns, every run whose
//! served claim the user later corrected or confirmed in the same
//! conversation. Rulings: PLAN-L9-06 GATE, HIT, CONTRIBUTORS and COST = A;
//! UNBUILT-03-TURN-LINK = A (a run's `turn.episode_id` names its
//! CONVERSATION and `turn.turn_id` its TURN).
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test retrieval_gated_outcome_producer`.
#![cfg(oneiron_test_support)]

use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_consolidation::{
    ConsolidationEvidenceEnvelope, encode_consolidation_evidence,
};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON};
use oneiron::store::{
    GateDecisionId, RetrievalAction, RetrievalOutcomeRecord, RetrievalRunId, RetrievalRunRecord,
    RetrievalScoreBreakdown, RetrievalScoreComponent, RetrievalSignal, RetrievalState,
    RetrievalTurn,
};
use oneiron::test_doors::retrieval_policy_default_floor::record_retrieval_run;
use oneiron::verbs::{RetrievalPolicyTrainRequest, retrieval_policy_update_as_owner};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig,
};

/// When the run's own turn was spoken.
const RUN_TURN_AT: u64 = 1_772_400_000;
/// When the run started: after its turn, before the user's next one.
const RUN_STARTED_AT: u64 = RUN_TURN_AT + 30;
/// When the user's next turn was spoken.
const NEXT_TURN_AT: u64 = RUN_TURN_AT + 60;
/// Every fixture run's latency, so the window's p95 is this too.
const RUN_ELAPSED_US: u64 = 40;
const PREDICATE: &str = "profile.note";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner_id: EntityId,
    owner: AuthenticatedOwner,
    subject: EntityId,
    /// The conversation refs the fixture's turns are witnessed in.
    conversation_a: String,
    conversation_b: String,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(owner_id, "principal:owner", true, GateDecisionId::now())
        .expect("authenticate owner");
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            at(RUN_TURN_AT - 600),
            RUN_TURN_AT - 600,
            b"subject",
        )
        .expect("subject PERSON");
    Fixture {
        _dir: dir,
        vault,
        owner_id,
        owner,
        subject,
        conversation_a: EntityId::now().to_hex(),
        conversation_b: EntityId::now().to_hex(),
    }
}

fn at(seconds: u64) -> TimeRange {
    TimeRange {
        start: seconds,
        end: seconds,
    }
}

/// A TURN and the CONVERSATION it is a `ChildOf`.
#[derive(Clone, Copy)]
struct Turn {
    turn: EntityId,
    conversation: EntityId,
}

impl Turn {
    /// The run's turn under UNBUILT-03-TURN-LINK = A.
    fn retrieval_turn(self) -> RetrievalTurn {
        RetrievalTurn {
            turn_id: *self.turn.as_bytes(),
            episode_id: *self.conversation.as_bytes(),
            turn_idx: 0,
        }
    }
}

impl Fixture {
    /// Witnesses one user turn in the conversation `conversation_ref` names.
    fn witness(&self, conversation_ref: &str, occurred_at: u64, words: &str) -> Turn {
        let memory = self.vault.memory(self.owner_id, EdgeActorClass::Human);
        let turn = memory
            .witness(&WitnessTurn {
                conversation_ref: conversation_ref.to_owned(),
                turn_ref: None,
                thread_audience: None,
                messages: vec![WitnessMessage {
                    id: None,
                    author: WitnessAuthor::User,
                    message_type: "dialogue".to_owned(),
                    content: words.to_owned(),
                    parts: None,
                    metadata: None,
                    is_visible: true,
                    order: 0,
                    quote: None,
                }],
                occurred_at,
                assertions: WitnessAssertions::default(),
            })
            .expect("witness a user turn")
            .turn_id;
        let conversations = self
            .vault
            .targets(&turn, EdgeKind::ChildOf, Some(ENTITY_TYPE_CONVERSATION))
            .expect("read the TURN's conversation");
        assert_eq!(conversations.len(), 1, "a TURN is ChildOf one conversation");
        Turn {
            turn,
            conversation: conversations[0],
        }
    }

    /// A claim about the fixture's PERSON saying `words`.
    fn put_claim(
        &self,
        words: &str,
        source: Option<ClaimSource>,
        evidence: Option<Turn>,
    ) -> EntityId {
        let mut body = ClaimBody::new(
            PREDICATE,
            ClaimSubject::Entity(self.subject),
            rmpv::Value::from(words),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .expect("claim body");
        body.source = source;
        let learned_at = match evidence {
            Some(turn) => {
                // The consolidation envelope a promoted claim stores names the
                // TURN its words came from.
                body.evidence = Some(encode_consolidation_evidence(
                    &ConsolidationEvidenceEnvelope {
                        refs: vec![turn.turn],
                        chain: Vec::new(),
                        source_meet: ClaimSource::UserStated,
                    },
                ));
                NEXT_TURN_AT + 5
            }
            None => RUN_TURN_AT - 300,
        };
        let id = EntityId::now();
        self.vault
            .put_claim(&id, &body, at(learned_at), learned_at)
            .expect("put claim");
        id
    }

    /// A claim the user stated in `turn`.
    fn user_stated(&self, words: &str, turn: Turn) -> EntityId {
        self.put_claim(words, Some(ClaimSource::UserStated), Some(turn))
    }

    fn supersede(&self, new: &EntityId, old: &EntityId) {
        self.vault
            .batch()
            .edge(new, EdgeKind::Supersedes, old, 1.0)
            .commit()
            .expect("supersede the served claim");
    }

    /// A finalized run of `turn` that served `served`.
    fn run(&self, turn: Turn, served: &[EntityId]) -> RetrievalRunId {
        let run = run_record(turn.retrieval_turn(), served);
        record_retrieval_run(&self.vault, &run).expect("record finalized run");
        run.run_id
    }

    /// The owner's `vault.retrieval.policy.update`.
    fn policy_update(&self) {
        let memory = self.vault.memory(
            self.owner.actor_for_read(&self.vault).expect("owner actor"),
            EdgeActorClass::Human,
        );
        retrieval_policy_update_as_owner(
            &memory,
            &self.owner,
            RetrievalPolicyTrainRequest::default(),
        )
        .expect("owner policy update");
    }

    fn outcomes(&self, run: RetrievalRunId) -> Vec<RetrievalOutcomeRecord> {
        self.vault
            .retrieval_outcomes(run)
            .expect("read run outcomes")
    }
}

fn run_record(turn: RetrievalTurn, served: &[EntityId]) -> RetrievalRunRecord {
    let score_breakdown = served
        .iter()
        .enumerate()
        .map(|(index, id)| {
            let rank = u32::try_from(index + 1).expect("a small served set");
            RetrievalScoreBreakdown {
                result_id: *id.as_bytes(),
                final_rank: rank,
                final_score: 1.0,
                components: vec![RetrievalScoreComponent {
                    signal: RetrievalSignal::Relevance,
                    rank,
                    score: 1.0,
                }],
                access_factor: None,
            }
        })
        .collect();
    RetrievalRunRecord {
        version: 0,
        run_id: RetrievalRunId::now(),
        action: RetrievalAction::Pipeline,
        started_at: RUN_STARTED_AT,
        elapsed_us: RUN_ELAPSED_US,
        state: RetrievalState {
            result_count: u8::try_from(served.len()).expect("a small served set"),
            ..Default::default()
        },
        policy_trace: None,
        replay_inputs: None,
        turn: Some(turn),
        query_expander_id: None,
        dispatch_attempt: None,
        policy_manifest_ref: None,
        policy_manifest_body_hash: None,
        reranker_id: None,
        signals: vec![RetrievalSignal::Text],
        result_ids: served.iter().map(|id| *id.as_bytes()).collect(),
        score_breakdown,
        total_in_scope: served.len(),
        claims_suppressed: 0,
        empty_reason: None,
        trace: None,
        quality: None,
        degradation: Vec::new(),
        confidence_adjustment: None,
    }
}

/// The one natural outcome `outcomes` holds, checked against the ruled
/// gate, cost weight and latency scale.
fn sole_natural_outcome(
    outcomes: &[RetrievalOutcomeRecord],
    kind: &str,
    signal: &EntityId,
    turn: Turn,
    hit: bool,
) -> f32 {
    assert_eq!(
        outcomes.len(),
        1,
        "the run holds exactly one natural outcome: {outcomes:?}"
    );
    let outcome = &outcomes[0];
    assert_eq!(outcome.key, format!("natural.{kind}:{}", signal.to_hex()));
    assert_eq!(outcome.accepted, Some(hit));
    assert_eq!(
        outcome.metadata.get("source").map(String::as_str),
        Some("natural")
    );
    let signal_ref = signal.to_hex();
    assert_eq!(
        outcome.metadata.get("signal_ref").map(String::as_str),
        Some(signal_ref.as_str())
    );
    let evidence = outcome
        .reward_evidence
        .as_ref()
        .expect("a gated outcome carries reward evidence");
    assert_eq!(evidence.turn_id, *turn.turn.as_bytes());
    assert_eq!(evidence.gate_score, 1.0);
    assert_eq!(evidence.confirmed_fact_hit, hit);
    assert_eq!(evidence.cost_weight, 0.1);
    assert_eq!(evidence.latency_scale_us, RUN_ELAPSED_US);
    outcome.reward.expect("a gated outcome carries its reward")
}

#[test]
fn the_policy_update_writes_a_gated_outcome_for_a_corrected_served_claim() {
    let f = fixture();
    let asked = f.witness(&f.conversation_a, RUN_TURN_AT, "what do I drink?");
    let served = f.put_claim("tea", None, None);
    let run = f.run(asked, &[served]);
    let next = f.witness(&f.conversation_a, NEXT_TURN_AT, "no, coffee");
    assert_eq!(next.conversation, asked.conversation);
    let correction = f.user_stated("coffee", next);
    f.supersede(&correction, &served);

    f.policy_update();

    let reward = sole_natural_outcome(&f.outcomes(run), "correction", &correction, asked, false);
    // reward = gate * 0 - 0.1 * (40 / 40 + 0 hops)
    assert!((reward + 0.1).abs() < 1e-6, "reward {reward}");
}

#[test]
fn a_confirmation_of_a_served_claim_is_a_hit() {
    let f = fixture();
    let asked = f.witness(&f.conversation_a, RUN_TURN_AT, "what do I drink?");
    let served = f.put_claim("tea", None, None);
    let run = f.run(asked, &[served]);
    let next = f.witness(&f.conversation_a, NEXT_TURN_AT, "yes, tea");
    let confirmation = f.user_stated("tea", next);

    f.policy_update();

    let reward = sole_natural_outcome(&f.outcomes(run), "confirmation", &confirmation, asked, true);
    // reward = gate * 1 - 0.1 * (40 / 40 + 0 hops)
    assert!((reward - 0.9).abs() < 1e-6, "reward {reward}");
}

#[test]
fn a_correction_of_a_claim_no_run_served_writes_no_label() {
    let f = fixture();
    let asked = f.witness(&f.conversation_a, RUN_TURN_AT, "what do I drink?");
    let served = f.put_claim("tea", None, None);
    let unserved = f.put_claim("water", None, None);
    let run = f.run(asked, &[served]);
    let next = f.witness(&f.conversation_a, NEXT_TURN_AT, "no, juice");
    let correction = f.put_claim("juice", Some(ClaimSource::UserStated), Some(next));
    f.supersede(&correction, &unserved);

    f.policy_update();

    assert_eq!(
        f.outcomes(run),
        Vec::new(),
        "a generation signal labels no run"
    );
}

#[test]
fn only_the_run_that_served_the_claim_is_named() {
    let f = fixture();
    let asked = f.witness(&f.conversation_a, RUN_TURN_AT, "what do I drink?");
    let served = f.put_claim("tea", None, None);
    let other = f.put_claim("water", None, None);
    let serving = f.run(asked, &[served]);
    let not_serving = f.run(asked, &[other]);
    let next = f.witness(&f.conversation_a, NEXT_TURN_AT, "no, coffee");
    let correction = f.user_stated("coffee", next);
    f.supersede(&correction, &served);

    f.policy_update();

    let outcomes = f.outcomes(serving);
    sole_natural_outcome(&outcomes, "correction", &correction, asked, false);
    let named = &outcomes[0]
        .reward_evidence
        .as_ref()
        .expect("reward evidence")
        .retrieval_run_ids;
    assert_eq!(named, &vec![serving], "only the serving run is named");
    assert_eq!(f.outcomes(not_serving), Vec::new());
}

#[test]
fn a_second_update_adds_no_second_label() {
    let f = fixture();
    let asked = f.witness(&f.conversation_a, RUN_TURN_AT, "what do I drink?");
    let served = f.put_claim("tea", None, None);
    let run = f.run(asked, &[served]);
    let next = f.witness(&f.conversation_a, NEXT_TURN_AT, "no, coffee");
    let correction = f.user_stated("coffee", next);
    f.supersede(&correction, &served);

    f.policy_update();
    f.policy_update();

    sole_natural_outcome(&f.outcomes(run), "correction", &correction, asked, false);
}

#[test]
fn a_correction_in_another_conversation_writes_no_label() {
    let f = fixture();
    let asked = f.witness(&f.conversation_a, RUN_TURN_AT, "what do I drink?");
    let served = f.put_claim("tea", None, None);
    let run = f.run(asked, &[served]);
    let elsewhere = f.witness(&f.conversation_b, NEXT_TURN_AT, "no, coffee");
    assert_ne!(elsewhere.conversation, asked.conversation);
    let correction = f.user_stated("coffee", elsewhere);
    f.supersede(&correction, &served);

    f.policy_update();

    assert_eq!(
        f.outcomes(run),
        Vec::new(),
        "HIT = A: the same conversation only"
    );
}

#[test]
fn a_run_whose_episode_names_no_conversation_gets_no_label() {
    let f = fixture();
    let asked = f.witness(&f.conversation_a, RUN_TURN_AT, "what do I drink?");
    let served = f.put_claim("tea", None, None);
    let opaque = RetrievalTurn {
        turn_id: *asked.turn.as_bytes(),
        episode_id: [0x5a; 16],
        turn_idx: 0,
    };
    let run = run_record(opaque, &[served]);
    record_retrieval_run(&f.vault, &run).expect("record finalized run");
    let next = f.witness(&f.conversation_a, NEXT_TURN_AT, "no, coffee");
    let correction = f.user_stated("coffee", next);
    f.supersede(&correction, &served);

    f.policy_update();

    assert_eq!(
        f.outcomes(run.run_id),
        Vec::new(),
        "a run without the turn convention gets no label"
    );
}

#[test]
fn a_run_whose_turn_is_no_turn_of_its_conversation_gets_no_label() {
    let f = fixture();
    let asked = f.witness(&f.conversation_a, RUN_TURN_AT, "what do I drink?");
    let elsewhere = f.witness(&f.conversation_b, RUN_TURN_AT, "what do I drink?");
    assert_ne!(elsewhere.conversation, asked.conversation);
    let served = f.put_claim("tea", None, None);
    let linked = f.run(asked, &[served]);
    let foreign_turn = f.run(
        Turn {
            turn: elsewhere.turn,
            conversation: asked.conversation,
        },
        &[served],
    );
    let opaque = RetrievalTurn {
        turn_id: [0x5a; 16],
        episode_id: *asked.conversation.as_bytes(),
        turn_idx: 0,
    };
    let opaque_turn = run_record(opaque, &[served]);
    record_retrieval_run(&f.vault, &opaque_turn).expect("record finalized run");
    let next = f.witness(&f.conversation_a, NEXT_TURN_AT, "no, coffee");
    let correction = f.user_stated("coffee", next);
    f.supersede(&correction, &served);

    f.policy_update();

    sole_natural_outcome(&f.outcomes(linked), "correction", &correction, asked, false);
    assert_eq!(
        f.outcomes(foreign_turn),
        Vec::new(),
        "a run whose TURN is in another conversation gets no label"
    );
    assert_eq!(
        f.outcomes(opaque_turn.run_id),
        Vec::new(),
        "a run whose turn names no TURN gets no label"
    );
}
