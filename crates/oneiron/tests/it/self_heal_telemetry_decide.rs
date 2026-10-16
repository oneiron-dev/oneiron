//! DECIDE-PATH row 14: a self-heal telemetry detector asks its question through the shared
//! decision ladder. The host fills a rung; the engine owns the question and keeps the receipt
//! on the proposed diagnostic. An unanswered question fails the call, as a failed judge did.

use std::sync::Mutex;

use oneiron::llm::decision::{
    DecisionAnswer, DecisionBandPolicy, DecisionLadder, DecisionProvider, DecisionQuestion,
    DecisionRung, HumanDecisionQueue, HumanDecisionRequest, ProviderDecision, ProviderPin,
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
    fn decide(
        &self,
        question: &DecisionQuestion,
        evidence: &[EntityId],
    ) -> Result<ProviderDecision> {
        self.asked
            .lock()
            .unwrap()
            .push((question.clone(), evidence.to_vec()));
        let probability = (self.answer != DecisionAnswer::Abstain).then_some(0.9);
        Ok(ProviderDecision {
            answer: self.answer.clone(),
            probability,
            paired: None,
        })
    }
}

struct NoPerson;
impl HumanDecisionQueue for NoPerson {
    fn queue(&self, _: HumanDecisionRequest) -> Result<()> {
        Err(Error::InvalidConfig("no person here".into()))
    }
}

fn decisions(local: Option<&dyn DecisionProvider>, principal: EntityId) -> DetectorDecisions<'_> {
    DetectorDecisions {
        ladder: DecisionLadder {
            rule: None,
            local,
            system_one: None,
            escalation: None,
            big: None,
            human: &NoPerson,
            human_pin: ProviderPin {
                rung: DecisionRung::Human,
                model: "host-queue".into(),
                version: "1".into(),
            },
        },
        principal,
        dial: DETECTOR_DIAL,
        bands: DecisionBandPolicy::default(),
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
    let host = decisions(Some(&head), principal);
    let policy = policy();

    let proposed = vault
        .judge_retrieval_trace(&policy, &host, &[run.clone()])?
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

    let abstains = HostHead::new(DecisionAnswer::Abstain);
    let host = decisions(Some(&abstains), principal);
    let abstained = vault.judge_retrieval_trace(&policy, &host, &[run.clone()]);
    assert!(matches!(abstained, Err(Error::InvalidConfig(_))));

    let no_slot = vault.judge_retrieval_trace(&policy, &decisions(None, principal), &[run]);
    assert!(matches!(no_slot, Err(Error::InvalidConfig(_))));
    Ok(())
}
