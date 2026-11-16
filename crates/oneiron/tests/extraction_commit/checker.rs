//! A scripted write-gate auto-checker and the test lender that lends it, for the extraction
//! commit checker tests: a provider that answers a fixed choice and counts its consults, its
//! hold reasons, the bounded checker over it, the test lender, and the policy-manifest knob
//! that names a checker. Copied in shape from `tests/live_run_claim_put.rs:53-127`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use oneiron::claim_check::AutoCheckNotes;
use oneiron::llm::decision::{
    DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionDial, DecisionLadder,
    DecisionProvider, DecisionRung, HeldLadder, ProviderDecision, ProviderPin, TypedDecision,
};
use oneiron::llm::{AutoCheckCandidate, AutoCheckDecisions, BoundedAutoChecker};
use oneiron::{EntityId, Result, Vault};

use crate::support::TestResult;

/// The host checker reference the tests name in the policy manifest.
pub(crate) const CHECKER_REF: &str = "host-checker-v1";

/// A host names its hold reasons in prose.
pub(crate) const HOLD_REASON: &str = "checker: hedged verdict";

/// How long a loan's turn and consults may take: far longer than one test commit, so a
/// slow host never turns a consult into `Unavailable`.
const LOAN_DEADLINE: Duration = Duration::from_secs(60);

/// The fixed answer of [`FixedChoiceProvider`].
#[derive(Clone, Copy)]
pub(crate) enum FixedChoice {
    /// The checker allows the write.
    Allow,
    /// The checker holds the write.
    Hold,
}

/// The host's decision head on the checker's Big rung: it answers every auto check with its
/// fixed choice and counts each consult.
pub(crate) struct FixedChoiceProvider {
    choice: FixedChoice,
    calls: AtomicUsize,
}

impl FixedChoiceProvider {
    /// A provider that allows every auto check.
    pub(crate) fn allow() -> Self {
        Self {
            choice: FixedChoice::Allow,
            calls: AtomicUsize::new(0),
        }
    }

    /// A provider that holds every auto check.
    pub(crate) fn hold() -> Self {
        Self {
            choice: FixedChoice::Hold,
            calls: AtomicUsize::new(0),
        }
    }

    /// The consults served so far.
    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl DecisionProvider for FixedChoiceProvider {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Big,
            model: "host-checker".into(),
            version: "1".into(),
        }
    }

    fn decide(&self, _call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        let _ = self.calls.fetch_add(1, Ordering::Relaxed);
        let answer = match self.choice {
            FixedChoice::Allow => "allow",
            FixedChoice::Hold => "hold",
        };
        Ok(ProviderDecision {
            answer: DecisionAnswer::Choice(answer.to_owned()),
            probability: Some(0.99),
            paired: None,
            person: None,
            served: None,
            cost_per_thousand: None,
        })
    }
}

/// The host's hold reasons: one, in prose.
pub(crate) struct HoldReasons;

impl AutoCheckNotes for HoldReasons {
    fn hold_reasons(
        &self,
        _candidate: &AutoCheckCandidate<'_>,
        _due: Instant,
    ) -> Result<Vec<String>> {
        Ok(vec![HOLD_REASON.to_owned()])
    }
}

/// The host's bounded checker over `head`, assembled as a host assembles it
/// (`oneiron-server` `decision_host`): a decision ladder whose Big rung is the
/// host's head, its dial at Big.
pub(crate) fn bounded(head: Arc<FixedChoiceProvider>) -> BoundedAutoChecker {
    BoundedAutoChecker::new(AutoCheckDecisions {
        ladder: HeldLadder {
            big: Some(head as Arc<dyn DecisionProvider>),
            ..HeldLadder::unstaffed()
        },
        principal: EntityId::from_bytes([0x51; 16]).expect("test id"),
        dial: DecisionDial {
            first: DecisionRung::Big,
            ceiling: DecisionRung::Big,
            band: DecisionBand::default(),
        },
        bands: DecisionBandPolicy::default(),
        wording: "May this write land without the owner's review?".to_owned(),
        notes: Arc::new(HoldReasons),
        calibrated: None,
        world_hold: None,
    })
}

/// The test lender: it lends `checker` as the attempt's write-gate auto-checker with a
/// deadline formed at the loan, as the production lender forms it, or none, and counts
/// each time it is asked. Settlement is refused: the commit path never asks for it.
pub(crate) struct TestAutoCheckerLender {
    checker: Option<BoundedAutoChecker>,
    asked: AtomicUsize,
}

impl TestAutoCheckerLender {
    /// A lender that lends `checker`.
    pub(crate) fn lending(checker: Option<BoundedAutoChecker>) -> Self {
        Self {
            checker,
            asked: AtomicUsize::new(0),
        }
    }

    /// How many times a commit asked for the checker so far.
    pub(crate) fn asked(&self) -> usize {
        self.asked.load(Ordering::Relaxed)
    }
}

impl oneiron::dreamer_runner::DreamerDecisionLender for TestAutoCheckerLender {
    fn lend(
        &self,
        _decide: &mut dyn FnMut(&DecisionLadder<'_>, &DecisionBandPolicy) -> Result<TypedDecision>,
    ) -> Result<TypedDecision> {
        Err(oneiron::Error::InvalidConfig(
            "the checker test lender lends no settlement ladder".into(),
        ))
    }

    fn lend_auto_checker(&self) -> oneiron::memory::MemoryResult<Option<BoundedAutoChecker>> {
        let _ = self.asked.fetch_add(1, Ordering::Relaxed);
        Ok(self
            .checker
            .as_ref()
            .map(|checker| checker.with_deadline(Instant::now() + LOAN_DEADLINE)))
    }
}

/// Names the host checker in the vault's default policy manifest, leaving every other entry
/// unchanged: the manifest body is read through `Vault::get` as `agent_interrupt_cut.rs` reads
/// it, and written back through `oneiron::test_support::put_policy_manifest_bytes`, the same
/// write `seed_extraction_single_valued_predicates` uses on this vault kind.
pub(crate) fn name_checker(vault: &Vault) -> TestResult<()> {
    let id = oneiron_store::policy_record::default_policy_manifest_id()?;
    let body = vault
        .get(&id)?
        .ok_or("the default policy manifest is stored")?;
    let rmpv::Value::Map(mut fields) = rmpv::decode::read_value(&mut body.as_slice())? else {
        return Err("the default policy manifest is a map".into());
    };
    match fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("auto_checker"))
    {
        Some((_, value)) => *value = rmpv::Value::from(CHECKER_REF),
        None => fields.push((
            rmpv::Value::from("auto_checker"),
            rmpv::Value::from(CHECKER_REF),
        )),
    }
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &rmpv::Value::Map(fields))?;
    oneiron::test_support::put_policy_manifest_bytes(vault, id, &bytes)?;
    Ok(())
}
