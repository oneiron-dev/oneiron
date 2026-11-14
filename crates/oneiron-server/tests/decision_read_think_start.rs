//! L2-33 (FIX 22360; lead ruling THINK-START = C, 13 Nov 2026): a served
//! host's ThinkThreshold row starts at 0.277, the p90 of run 2's house reads
//! (FIX 22229), so a house read whose paired "does this need more thinking?"
//! reading reaches it steps up to the Big rung. The old start, 0.8, was above
//! every reading run 2 measured (max 0.559), so on a host with the default
//! config the Big rung never ran.
//!
//! The config is a `[models]` body whose `[decision_read]` sets no
//! `think_threshold`, resolved by `ModelsConfig::from_toml`. Its start value
//! seeds the host's `DecisionBandPolicy` as `DecisionHost::with_house_read`
//! does, and a ladder with the house read on the escalation rung and a Big
//! rung above it routes one read. The host also counts the route of each read
//! it weighs against the think row, over every clone of its policy. Run with:
//! `cargo test --locked -p oneiron-server --no-fail-fast --test decision_read_think_start`.

use std::path::Path;
use std::time::{Duration, Instant};

use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionClass,
    DecisionDial, DecisionLadder, DecisionProvider, DecisionQuestion, DecisionRung,
    HumanDecisionQueue, HumanDecisionRequest, PairedAnswer, ProviderDecision, ProviderPin,
    Reasoning, ReasoningCause, Reversibility, ThinkRouteCounts, TypedDecision,
};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::{EntityId, Error, Result};
use oneiron_server::config::models::ModelsConfig;

/// The version the host gives its configured start row; a Coach row replaces
/// it with a higher one.
const START_ROW_VERSION: u32 = 1;

const RECIPE: &str = r#"format = 3
template = "plain.txt"
joint_template = "joint.txt"
row = "{token}: {label}"
joint_row = "{token}: {label}; more thinking {think}"
yes = "yes"
no = "no"
tokens = ["A", "B", "C", "D"]
eos = "<eos>"
n_probs = 8

[probe]
paired = "Does this need more thinking?"
"#;

/// A `[models]` body with the house read on `local_reasoner` and no
/// `think_threshold`: the host default.
const MODELS: &str = r#"[providers.house]
kind = "local-openai-compat"
base_url = "http://127.0.0.1:18134"
revision = "house-r1"

[roles.local_reasoner]
model = "house:house-model"

[decision_read]
recipe = "recipe.toml"
"#;

/// The ThinkThreshold start value a host with the default config gives its
/// policy: the recipe and templates are written under `dir`.
fn default_think_start(dir: &Path) -> anyhow::Result<f64> {
    std::fs::write(dir.join("plain.txt"), "{question}\n{labels}\n{state}\n")?;
    std::fs::write(
        dir.join("joint.txt"),
        "{question}\n{paired}\n{labels}\n{state}\n",
    )?;
    std::fs::write(dir.join("recipe.toml"), RECIPE)?;
    let models = ModelsConfig::from_toml(MODELS, Some(dir))?;
    let settings = models
        .decision_read
        .ok_or_else(|| anyhow::anyhow!("the config binds the decision read"))?;
    Ok(settings.think_threshold)
}

/// The host's policy, its think row at `threshold` as the house read seeds it.
fn host_policy(threshold: f64) -> Result<DecisionBandPolicy> {
    let mut policy = DecisionBandPolicy::default();
    policy.set_think_threshold(threshold, START_ROW_VERSION)?;
    Ok(policy)
}

fn pin(rung: DecisionRung) -> ProviderPin {
    ProviderPin {
        rung,
        model: format!("fixture-{rung:?}"),
        version: "1".into(),
    }
}

/// A rung that answers `reply`.
struct Rung {
    rung: DecisionRung,
    reply: ProviderDecision,
}

impl DecisionProvider for Rung {
    fn pin(&self) -> ProviderPin {
        pin(self.rung)
    }

    fn decide(&self, _call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        Ok(self.reply.clone())
    }
}

/// No read here reaches the person rung.
struct NoPerson;

impl HumanDecisionQueue for NoPerson {
    fn queue(&self, _request: HumanDecisionRequest) -> Result<()> {
        Err(Error::InvalidConfig("no read here asks a person".into()))
    }
}

/// A yes at 0.9 from the house read, with its paired reading at `think`.
fn house_answer(think: f64) -> ProviderDecision {
    ProviderDecision {
        answer: DecisionAnswer::Noul(true),
        probability: Some(0.9),
        paired: Some(PairedAnswer {
            question: EntityId::now(),
            question_version: 1,
            probability: think,
        }),
        person: None,
        served: None,
        cost_per_thousand: None,
    }
}

/// The Big rung's answer: a no, so a step-up shows in the answer too.
fn big_answer() -> ProviderDecision {
    ProviderDecision {
        answer: DecisionAnswer::Noul(false),
        probability: Some(0.2),
        paired: None,
        person: None,
        served: None,
        cost_per_thousand: None,
    }
}

/// One reversible read through the house read on the escalation rung, with the
/// Big rung above it, under `policy`; the house read's paired reading is `think`.
fn route_one(policy: &DecisionBandPolicy, think: f64) -> Result<TypedDecision> {
    let house = Rung {
        rung: DecisionRung::Escalation,
        reply: house_answer(think),
    };
    let big = Rung {
        rung: DecisionRung::Big,
        reply: big_answer(),
    };
    let question = DecisionQuestion {
        id: EntityId::now(),
        version: 1,
        text: "Does this note answer the task?".into(),
        class: DecisionClass::Judgment,
        contract: AnswerContract::Noul,
        accept_type: false,
    };
    let paired = DecisionQuestion {
        id: EntityId::now(),
        version: 1,
        text: "Does this need more thinking?".into(),
        class: DecisionClass::Judgment,
        contract: AnswerContract::Noul,
        accept_type: false,
    };
    // A wide clock: no read here is cut.
    let deadline = RetrievalDeadline::hard(Instant::now(), Duration::from_secs(600));
    DecisionLadder {
        rule: None,
        local: None,
        system_one: None,
        escalation: Some(&house),
        big: Some(&big),
        human: &NoPerson,
        human_pin: pin(DecisionRung::Human),
        ask_to: None,
        paired: Some(&paired),
        person: None,
        presence: None,
        correlation: None,
    }
    .run(
        &question,
        EntityId::now(),
        &[],
        &serde_json::json!({}),
        DecisionDial {
            first: DecisionRung::Escalation,
            ceiling: DecisionRung::Big,
            band: DecisionBand::default(),
        },
        policy,
        Reversibility::ReversibleRead,
        &deadline,
    )
}

/// The rung that answered and why more thinking ran, from the receipt.
fn routed(decision: &TypedDecision) -> (Option<DecisionRung>, Reasoning) {
    let time = decision
        .receipt
        .time
        .expect("the receipt records the call's clock");
    (time.answered, time.reasoning)
}

#[test]
fn default_host_steps_a_think_reading_of_0_30_up_to_the_big_rung() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let policy = host_policy(default_think_start(dir.path())?)?;
    let decision = route_one(&policy, 0.30)?;
    assert_eq!(
        routed(&decision),
        (
            Some(DecisionRung::Big),
            Reasoning::Ran(ReasoningCause::PairedHigh)
        ),
        "a think reading of 0.30 under the default start value steps up to the Big rung"
    );
    assert_eq!(
        decision.answer,
        DecisionAnswer::Noul(false),
        "the Big rung's answer stands"
    );
    Ok(())
}

#[test]
fn default_host_keeps_a_think_reading_of_0_25_direct() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let policy = host_policy(default_think_start(dir.path())?)?;
    let decision = route_one(&policy, 0.25)?;
    assert_eq!(
        routed(&decision),
        (Some(DecisionRung::Escalation), Reasoning::NotNeeded),
        "a think reading of 0.25 stays with the house read"
    );
    assert_eq!(
        decision.answer,
        DecisionAnswer::Noul(true),
        "the house read's answer stands"
    );
    Ok(())
}

#[test]
fn host_counts_each_think_route_over_every_policy_clone() -> Result<()> {
    let policy = host_policy(0.5)?;
    let first = policy.clone();
    let second = policy.clone();
    assert_eq!(policy.think_route_counts(), ThinkRouteCounts::default());
    assert_eq!(policy.think_route_counts().step_up_rate(), None);

    route_one(&first, 0.6)?;
    route_one(&second, 0.1)?;
    let counts = policy.think_route_counts();
    assert_eq!(
        counts,
        ThinkRouteCounts {
            direct: 1,
            stepped_up: 1,
            step_unfinished: 0,
        },
        "each clone's read counts toward the one host tally"
    );
    assert_eq!(counts.weighed(), 2);
    assert_eq!(counts.step_up_rate(), Some(0.5));

    // A ladder whose policy has no think row weighs nothing against it.
    let unrowed = DecisionBandPolicy::default();
    route_one(&unrowed, 0.9)?;
    assert_eq!(unrowed.think_route_counts(), ThinkRouteCounts::default());
    Ok(())
}
