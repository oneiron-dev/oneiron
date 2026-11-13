//! DECIDE-PATH row 14: a self-heal telemetry detector asks its question through the shared
//! decision ladder. The host fills a rung; the engine owns the question and keeps the receipt
//! on the proposed diagnostic. An unanswered question fails the call, as a failed judge did.

use std::sync::Mutex;

use oneiron::llm::decision::{
    DecisionAnswer, DecisionBandPolicy, DecisionCall, DecisionLadder, DecisionProvider,
    DecisionQuestion, DecisionRung, HumanDecisionQueue, HumanDecisionRequest, ProviderDecision,
    ProviderPin,
};
use oneiron::self_heal::DiagnosticEventClass;
use oneiron::self_heal::tiered::{DETECTOR_DIAL, DetectorDecisions, DetectorPolicy, ProposedTier};
use oneiron::store::RetrievalRunRecord;
use oneiron::{EntityId, Error, HnswConfig, Result, Vault, VaultConfig};

/// The host's head on the Local rung. It records what it was asked.
struct HostHead {
    answer: DecisionAnswer,
    asked: Mutex<Vec<(DecisionQuestion, Vec<EntityId>)>>,
}

impl HostHead {
    fn new(answer: DecisionAnswer) -> Self {
        Self {
            answer,
            asked: Mutex::new(Vec::new()),
        }
    }
}

impl DecisionProvider for HostHead {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Local,
            model: "host-head".into(),
            version: "3".into(),
        }
    }
    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        self.asked
            .lock()
            .expect("the asked log is never poisoned")
            .push((call.question.clone(), call.evidence.to_vec()));
        let probability = (self.answer != DecisionAnswer::Abstain).then_some(0.9);
        Ok(ProviderDecision {
            answer: self.answer.clone(),
            probability,
            paired: None,
            person: None,
            served: None,
            cost_per_thousand: None,
        })
    }
}

struct NoPerson;
impl HumanDecisionQueue for NoPerson {
    fn queue(&self, _: HumanDecisionRequest) -> Result<()> {
        Err(Error::InvalidConfig("no person here".into()))
    }
}

/// The host's decision path: `local` on the Local rung, no person, and the
/// state the host built from the window (here an empty object).
fn decisions<'a>(
    local: Option<&'a dyn DecisionProvider>,
    principal: EntityId,
    state: &'a serde_json::Value,
) -> DetectorDecisions<'a> {
    DetectorDecisions {
        ladder: DecisionLadder {
            rule: None,
            local,
            system_one: None,
            precision: None,
            escalation: None,
            big: None,
            human: &NoPerson,
            human_pin: ProviderPin {
                rung: DecisionRung::Human,
                model: "host-queue".into(),
                version: "1".into(),
            },
            ask_to: None,
            paired: None,
            person: None,
            presence: None,
            correlation: None,
        },
        principal,
        dial: DETECTOR_DIAL,
        bands: DecisionBandPolicy::default(),
        state,
        budget: std::time::Duration::from_secs(3600),
    }
}

fn policy() -> DetectorPolicy {
    DetectorPolicy {
        family: "retrieval_quality".into(),
        class: DiagnosticEventClass::RetrievalMiss,
        prompt: "Did this retrieval miss what the user asked for?".into(),
        rubric: "Yes only when no returned item answers the query.".into(),
        consecutive: 1,
    }
}

/// A vault with one recorded retrieval run, made through the public context-pack path.
fn vault_with_run() -> Result<(tempfile::TempDir, Vault, RetrievalRunRecord)> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    config.retrieval_telemetry_capture = true;
    let vault = Vault::open(dir.path(), config)?;
    vault.context_pack().search_text("matcha", 8).run()?;
    let mut runs = vault.retrieval_runs(8)?;
    assert_eq!(runs.len(), 1, "a context pack records one retrieval run");
    let run = runs.remove(0);
    Ok((dir, vault, run))
}

#[test]
fn telemetry_detector_asks_the_ladder_and_keeps_the_receipt() -> Result<()> {
    let (_dir, vault, run) = vault_with_run()?;
    let principal = EntityId::now();
    let head = HostHead::new(DecisionAnswer::Noul(true));
    let state = serde_json::json!({});
    let host = decisions(Some(&head), principal, &state);
    let policy = policy();

    let proposed = vault
        .judge_retrieval_trace(&policy, &host, std::slice::from_ref(&run))?
        .expect("a raised question proposes a diagnostic");

    let question = policy.question(ProposedTier::Judge, (0, 0))?;
    let asked = head.asked.lock().unwrap();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].0, question);
    assert!(question.text.contains(&policy.prompt));
    assert!(question.text.contains(&policy.rubric));
    assert_eq!(asked[0].1, [EntityId::from_bytes(run.run_id.as_bytes())?]);

    assert_eq!(proposed.tier, ProposedTier::Judge);
    assert_eq!(proposed.decisions.len(), 1);
    let receipt = &proposed.decisions[0];
    assert_eq!(receipt.question, question.id);
    assert_eq!(receipt.question_version, 1);
    assert_eq!(receipt.principal, principal);
    assert_eq!(receipt.providers, [head.pin()]);

    // Another rubric is another question, so its bands are learned apart.
    let reworded = DetectorPolicy {
        rubric: "Yes when fewer than three items answer the query.".into(),
        ..policy
    };
    let reworded = reworded.question(ProposedTier::Judge, (0, 0))?;
    assert_ne!(reworded.id, question.id);
    Ok(())
}

#[test]
fn an_unanswered_telemetry_question_fails_like_a_failed_judge() -> Result<()> {
    let (_dir, vault, run) = vault_with_run()?;
    let principal = EntityId::now();
    let policy = policy();

    let state = serde_json::json!({});
    let abstains = HostHead::new(DecisionAnswer::Abstain);
    let host = decisions(Some(&abstains), principal, &state);
    let abstained = vault.judge_retrieval_trace(&policy, &host, std::slice::from_ref(&run));
    assert!(matches!(abstained, Err(Error::InvalidConfig(_))));

    let no_slot = vault.judge_retrieval_trace(&policy, &decisions(None, principal, &state), &[run]);
    assert!(matches!(no_slot, Err(Error::InvalidConfig(_))));
    Ok(())
}
