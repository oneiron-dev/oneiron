//! The sealed referee of a market ([RSI-SEALED-EVAL]).
//!
//! ARCH-0079 #market: "The record names the rule, its digest, who set it and
//! when, and each score must carry that digest ... A CEO who overrides the
//! referee writes a logged entry with its own receipt." ARCH-0053 §10a:
//! "measure and decide run outside an experiment's write scope".
//!
//! A matching digest is not evidence that the test ran. So the referee's
//! contract is a sealed NOTE, pinned when the ledger opens, before any member
//! runs: the comparator, the sealed cohort, the development cohorts screens
//! run on (disjoint from the sealed one), the harness commit and workload,
//! the output that holds the verdict, and the paired bar. A member submits
//! its candidate's digest under the member key the host queued it as. A
//! verdict is the referee run's own output: its bytes must hash to the output
//! the machine hashed on the run's unit claim, and that claim must have run
//! the contract's harness to a clean exit. Only the sealed cohort scores;
//! a screen never does. Evidence that does not hold leaves the submission
//! invalid, never a loss, until a valid verdict replaces it; a valid sealed
//! verdict is final.

use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{
    ContractBar, ContractComparator, InvalidVerdict, LedgerKind, MARKET, MarketResult,
    RefereeContract, ScreenScore, Submission, VerdictEvidence,
};
use crate::agent_dispatch::{AGENT_DISPATCH_ATTEMPT_TYPE, attempt_team_stamp};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::error::Result;
use crate::gpu_line::{ClaimKey, ClaimState, UnitClaim, UnitEnd, UnitTerminal, claim_in_txn};
use crate::side_table::{self, Named, SideTable};
use crate::team::run::{
    TeamMarketOutcome, TeamMarketSubmitInput, TeamMarketVerdictInput, TeamMarketVerdictOutcome,
    TeamOverrideInput, TeamOverrideView, TeamRunAnswer,
};
use crate::{EntityId, Vault};

/// CEO overrides, by team reference: one per market.
const OVERRIDE: SideTable<String, MarketOverride, Named> =
    SideTable::new(&side_table::TEAM_MARKET_OVERRIDE);

/// The contract a sealed NOTE's text must be.
pub const CONTRACT_SCHEMA: &str = "oneiron.market_referee_contract.v1";
/// The verdict a referee run's output must be.
pub const VERDICT_SCHEMA: &str = "oneiron.market_referee_verdict.v1";
/// The machine's end of a run that exited by itself with status 0.
const CLEAN_EXIT: &str = "exited(0)";
/// Longest reference, name or metric kept.
const MAX_TEXT_BYTES: usize = 256;
/// Longest override reason kept.
const MAX_REASON_BYTES: usize = 2048;
/// Most development cohorts one contract names.
const MAX_SCREENS: usize = 64;
/// Most bytes one relayed verdict holds.
const MAX_VERDICT_BYTES: usize = 64 * 1024;
/// Most continuations followed back to the attempt the host queued.
const MAX_RETRY_HOPS: usize = 64;

type Answered = std::result::Result<TeamRunAnswer, &'static str>;

/// A CEO's override of the referee, with its own receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketOverride {
    pub team_ref: String,
    /// The referee's winning submission; none when nothing won.
    pub referee_winner: Option<String>,
    /// The submission the team adopts.
    pub chosen: String,
    pub reason: String,
    /// The CEO's AGENT_DEF.
    pub by: EntityId,
    /// The vault's time.
    pub at: u64,
    /// The ledger line that logs it.
    pub ledger_seq: u64,
}

/// The contract a sealed NOTE holds, as its author writes it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ContractText {
    schema: String,
    comparator: ComparatorText,
    cohort_sha256: String,
    #[serde(default)]
    screens: Vec<String>,
    harness: HarnessText,
    verdict_output: String,
    bar: BarText,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ComparatorText {
    name: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct HarnessText {
    commit: String,
    workload: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BarText {
    metric: String,
    margin: f64,
    min_tasks: u64,
}

/// A referee run's verdict output. Fields beyond these (per-task metrics)
/// are the harness's own: the machine's hash covers them all.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerdictText {
    schema: String,
    contract_sha256: String,
    cohort_sha256: String,
    candidate_sha256: String,
    comparator_sha256: String,
    tasks: u64,
    score: f64,
    paired_low: f64,
}

/// Which cohort a verdict ran on.
enum VerdictRead {
    Sealed(VerdictText),
    Screen(VerdictText),
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn text_ok(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && !text.contains('\0')
}

impl ContractText {
    fn pinned(
        self,
        note: EntityId,
        sha256: String,
    ) -> std::result::Result<RefereeContract, &'static str> {
        if self.schema != CONTRACT_SCHEMA {
            return Err("a referee contract is oneiron.market_referee_contract.v1");
        }
        let digests = [
            &self.comparator.sha256,
            &self.cohort_sha256,
            &self.harness.workload,
        ];
        if !digests.iter().all(|digest| is_lower_hex(digest, 64))
            || !self.screens.iter().all(|digest| is_lower_hex(digest, 64))
        {
            return Err("a contract's digests are 64 lower hex characters");
        }
        if !is_lower_hex(&self.harness.commit, 40) {
            return Err("a contract's harness commit is 40 lower hex characters");
        }
        if ![
            &self.comparator.name,
            &self.verdict_output,
            &self.bar.metric,
        ]
        .iter()
        .all(|text| text_ok(text, MAX_TEXT_BYTES))
        {
            return Err("a contract's names are 1..=256 bytes without NUL");
        }
        if self.screens.len() > MAX_SCREENS {
            return Err("a contract names at most 64 screen cohorts");
        }
        if self.screens.contains(&self.cohort_sha256) {
            return Err("a screen's development cohort is disjoint from the sealed cohort");
        }
        let mut screens = self.screens.clone();
        screens.sort();
        screens.dedup();
        if screens.len() != self.screens.len() {
            return Err("a contract names each screen cohort once");
        }
        if !self.bar.margin.is_finite() || self.bar.margin < 0.0 {
            return Err("a bar's margin is finite and not negative");
        }
        if self.bar.min_tasks == 0 {
            return Err("a bar judges at least one task");
        }
        Ok(RefereeContract {
            note,
            sha256,
            comparator: ContractComparator {
                name: self.comparator.name,
                sha256: self.comparator.sha256,
            },
            cohort_sha256: self.cohort_sha256,
            screens: self.screens,
            harness_commit: self.harness.commit,
            harness_workload: self.harness.workload,
            verdict_output: self.verdict_output,
            bar: ContractBar {
                metric: self.bar.metric,
                margin: self.bar.margin,
                min_tasks: self.bar.min_tasks,
            },
        })
    }
}

/// The contract the sealed NOTE `note` holds, read in the caller's writer:
/// the NOTE is sealed, its text hashes to `digest` and is a contract. A
/// refusal says why, and nothing is pinned.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn sealed_contract_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    digest: &str,
) -> Result<std::result::Result<RefereeContract, &'static str>> {
    if crate::note::note_seal_in_txn(&vault.store, txn, note)?.is_none() {
        return Ok(Err(
            "the referee's contract NOTE is not sealed; seal it with vault.notes.seal first",
        ));
    }
    let text = vault.note_text_in_txn(txn, note)?;
    let sha256 = sha256_hex(text.as_bytes());
    if sha256 != digest {
        return Ok(Err(
            "the contract NOTE's sealed text does not hash to the referee's digest",
        ));
    }
    let Ok(contract) = serde_json::from_str::<ContractText>(&text) else {
        return Ok(Err(
            "the contract NOTE's text is no oneiron.market_referee_contract.v1",
        ));
    };
    Ok(contract.pinned(note, sha256))
}

/// The member key `caller` was queued as in the team `team_ref`, read from
/// host rows only: the attempt carries the team's stamp, and it (or the
/// attempt it continues) was queued under the dispatch key the team's start
/// or launch gave that member. `None` for any other attempt.
fn participant_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: AttemptId,
    team_ref: &str,
) -> Result<Option<String>> {
    let queue = AttemptQueue::new(vault);
    let Some(mut row) = queue.get_in_txn(txn, caller)? else {
        return Ok(None);
    };
    if !attempt_team_stamp(&row)?.is_some_and(|stamp| stamp.team_ref == team_ref) {
        return Ok(None);
    }
    let Some((leader, key)) = team_ref
        .strip_prefix("team:")
        .and_then(|rest| rest.split_once(':'))
    else {
        return Ok(None);
    };
    // A code-mode start queues `code:<leader>:team:<start key>:<member key>`
    // and a planned launch `planned:<intent digest>:member:<n>`.
    let started = format!("{AGENT_DISPATCH_ATTEMPT_TYPE}:code:{leader}:team:{key}:");
    let launched = format!("{AGENT_DISPATCH_ATTEMPT_TYPE}:planned:{key}:");
    for _ in 0..MAX_RETRY_HOPS {
        if let Some(dedupe) = row.dedupe_key.as_deref() {
            return Ok(dedupe
                .strip_prefix(started.as_str())
                .or_else(|| {
                    dedupe
                        .strip_prefix(launched.as_str())
                        .filter(|member| member.starts_with("member:"))
                })
                .filter(|member| !member.is_empty())
                .map(str::to_owned));
        }
        let Some(prior) = row.retry_of else {
            return Ok(None);
        };
        let Some(next) = queue.get_in_txn(txn, prior)? else {
            return Ok(None);
        };
        row = next;
    }
    Ok(None)
}

/// Whether `caller` leads `team_ref`: the attempt the reference names, or
/// that attempt's newest retry.
fn leads_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: AttemptId,
    team_ref: &str,
) -> Result<bool> {
    let root = team_ref
        .strip_prefix("team:")
        .and_then(|rest| rest.split_once(':'))
        .and_then(|(root, _)| EntityId::from_hex(root).ok())
        .and_then(|root| AttemptId::from_bytes(root.as_bytes()).ok());
    let Some(root) = root else {
        return Ok(false);
    };
    if root == caller {
        return Ok(true);
    }
    let queue = AttemptQueue::new(vault);
    if queue.get_in_txn(txn, root)?.is_none() {
        return Ok(false);
    }
    Ok(queue.retry_tip_in_txn(txn, root)?.id == caller)
}

fn submitted(team_ref: &str, submission: &Submission, replay: bool) -> TeamRunAnswer {
    TeamRunAnswer::MarketSubmitted {
        team_ref: team_ref.to_owned(),
        submission_ref: submission.submission_ref.clone(),
        participant: submission.agent.clone(),
        at: submission.at,
        replay,
    }
}

/// `self.team.market.submit`: records the calling member's candidate in its
/// team's market at the vault's time. The member key is the host's. One
/// candidate digest is one submission in a market; the same submission again
/// answers it.
///
/// # Errors
///
/// Storage errors and a malformed dispatch payload.
pub(crate) fn submit_candidate(
    vault: &Vault,
    caller: AttemptId,
    input: &TeamMarketSubmitInput,
) -> Result<Answered> {
    if !text_ok(&input.submission_ref, MAX_TEXT_BYTES) || !is_lower_hex(&input.candidate_sha256, 64)
    {
        return Ok(Err("team_market_invalid_input"));
    }
    vault.with_write_txn_grouped(|txn| {
        let Some(participant) = participant_in_txn(vault, txn, caller, &input.team_ref)? else {
            return Ok(Err("team_market_outside_team"));
        };
        let Some(mut market) = MARKET.get(&vault.store, txn, &input.team_ref)? else {
            return Ok(Err("team_market_unbound"));
        };
        if let Some(kept) = market
            .submissions
            .iter()
            .find(|kept| kept.submission_ref == input.submission_ref)
        {
            let same = kept.agent == participant
                && kept.candidate_sha256.as_deref() == Some(input.candidate_sha256.as_str());
            return Ok(if same {
                Ok(submitted(&input.team_ref, kept, true))
            } else {
                Err("team_market_submission_taken")
            });
        }
        if market
            .submissions
            .iter()
            .any(|kept| kept.candidate_sha256.as_deref() == Some(input.candidate_sha256.as_str()))
        {
            return Ok(Err("team_market_candidate_taken"));
        }
        if market.result.is_some() {
            return Ok(Err("team_market_closed"));
        }
        match market.participants.get(&participant) {
            Some(member) if member.active => {}
            Some(_) => return Ok(Err("team_market_retired")),
            None => return Ok(Err("team_market_outside_team")),
        }
        let submission = Submission {
            agent: participant,
            submission_ref: input.submission_ref.clone(),
            at: vault.now_recorded_at().max(market.referee.signed_at),
            score: None,
            passed: None,
            candidate_sha256: Some(input.candidate_sha256.clone()),
            evidence: None,
            screen: None,
            invalid: None,
        };
        let answer = submitted(&input.team_ref, &submission, false);
        market.submissions.push(submission);
        MARKET.put(&vault.store, txn, &market.team_ref, &market)?;
        Ok(Ok(answer))
    })
}

fn verdict_answer(
    input: &TeamMarketVerdictInput,
    outcome: TeamMarketVerdictOutcome,
    replay: bool,
) -> TeamRunAnswer {
    TeamRunAnswer::MarketVerdict {
        team_ref: input.team_ref.clone(),
        submission_ref: input.submission_ref.clone(),
        outcome,
        replay,
    }
}

/// What the evidence shows, or why it does not hold: the run ended cleanly
/// under the contract's harness and workload, the bytes are the output the
/// machine hashed, and the verdict names this contract, its comparator and
/// the submission's candidate on a cohort the contract names.
fn read_evidence(
    contract: &RefereeContract,
    claim: &UnitClaim,
    terminal: &UnitTerminal,
    verdict: &str,
    sha256: &str,
    candidate: Option<&str>,
) -> std::result::Result<VerdictRead, &'static str> {
    let _ = (claim, terminal, sha256, UnitEnd::Settled, CLEAN_EXIT);
    let Ok(body) = serde_json::from_str::<VerdictText>(verdict) else {
        return Err("verdict_malformed");
    };
    if body.schema != VERDICT_SCHEMA || !body.score.is_finite() || !body.paired_low.is_finite() {
        return Err("verdict_malformed");
    }
    if body.contract_sha256 != contract.sha256 {
        return Err("other_contract");
    }
    if body.comparator_sha256 != contract.comparator.sha256 {
        return Err("other_comparator");
    }
    if candidate != Some(body.candidate_sha256.as_str()) {
        return Err("other_candidate");
    }
    if body.cohort_sha256 == contract.cohort_sha256 {
        Ok(VerdictRead::Sealed(body))
    } else if contract.screens.contains(&body.cohort_sha256) {
        Ok(VerdictRead::Screen(body))
    } else {
        Err("unknown_cohort")
    }
}

/// `self.team.market.verdict`: applies one referee run's output to one
/// submission, relayed by the team's leader or the submitting member.
/// Refused with nothing written: an unknown market or submission, another
/// relay, a market with no contract, a run not ended yet, a closed market, a
/// claim another submission's verdict used, or a second sealed verdict.
///
/// # Errors
///
/// Storage errors and a malformed dispatch payload.
pub(crate) fn relay_verdict(
    vault: &Vault,
    caller: AttemptId,
    input: &TeamMarketVerdictInput,
) -> Result<Answered> {
    let Ok(arm) = EntityId::from_hex(&input.claim.arm) else {
        return Ok(Err("team_market_invalid_input"));
    };
    if !text_ok(&input.claim.unit_key, MAX_TEXT_BYTES) || input.verdict.len() > MAX_VERDICT_BYTES {
        return Ok(Err("team_market_invalid_input"));
    }
    let key = ClaimKey::of(
        arm,
        input.claim.rung,
        &input.claim.unit_key,
        input.claim.attempt,
    );
    let sha256 = sha256_hex(input.verdict.as_bytes());
    vault.with_write_txn_grouped(|txn| {
        let Some(mut market) = MARKET.get(&vault.store, txn, &input.team_ref)? else {
            return Ok(Err("team_market_unbound"));
        };
        let Some(index) = market
            .submissions
            .iter()
            .position(|kept| kept.submission_ref == input.submission_ref)
        else {
            return Ok(Err("team_market_unknown_submission"));
        };
        if !leads_in_txn(vault, txn, caller, &input.team_ref)?
            && participant_in_txn(vault, txn, caller, &input.team_ref)?.as_deref()
                != Some(market.submissions[index].agent.as_str())
        {
            return Ok(Err("team_market_verdict_relay"));
        }
        let Some(contract) = market.contract.clone() else {
            return Ok(Err("team_market_unsealed"));
        };
        let claim = claim_in_txn(vault, txn, &key)?;
        let claim_id = claim.as_ref().map(|claim| claim.id);
        let kept = &market.submissions[index];
        if let Some(evidence) = &kept.evidence {
            return Ok(
                if Some(evidence.claim) == claim_id && evidence.output_sha256 == sha256 {
                    Ok(verdict_answer(input, scored(kept, evidence), true))
                } else {
                    Err("team_market_verdict_final")
                },
            );
        }
        if let Some(screen) = &kept.screen
            && Some(screen.claim) == claim_id
            && screen.output_sha256 == sha256
        {
            let outcome = TeamMarketVerdictOutcome::Screened {
                score: screen.score,
            };
            return Ok(Ok(verdict_answer(input, outcome, true)));
        }
        if market.result.is_some() {
            return Ok(Err("team_market_closed"));
        }
        let now = vault.now_recorded_at();
        let read = match &claim {
            None => Err("no_claim"),
            Some(claim) => {
                let terminal = match &claim.state {
                    ClaimState::Claimed | ClaimState::Started => {
                        return Ok(Err("team_market_verdict_pending"));
                    }
                    ClaimState::Ended(terminal) => terminal,
                };
                let used = market.submissions.iter().enumerate().any(|(at, other)| {
                    at != index
                        && (other.evidence.as_ref().map(|e| e.claim) == Some(claim.id)
                            || other.screen.as_ref().map(|s| s.claim) == Some(claim.id))
                });
                if used {
                    return Ok(Err("team_market_claim_used"));
                }
                read_evidence(
                    &contract,
                    claim,
                    terminal,
                    &input.verdict,
                    &sha256,
                    kept.candidate_sha256.as_deref(),
                )
                .map(|read| (read, claim))
            }
        };
        let submission = &mut market.submissions[index];
        let outcome = match read {
            Ok((VerdictRead::Sealed(body), claim)) => {
                let unknown = body.tasks < contract.bar.min_tasks;
                let passed = !unknown && body.paired_low > -contract.bar.margin;
                submission.score = Some(body.score);
                submission.passed = Some(passed);
                submission.invalid = None;
                submission.evidence = Some(VerdictEvidence {
                    claim: claim.id,
                    workload: claim.workload.clone(),
                    output_sha256: sha256.clone(),
                    tasks: body.tasks,
                    paired_low: body.paired_low,
                    unknown,
                    at: now,
                });
                TeamMarketVerdictOutcome::Scored {
                    score: body.score,
                    passed,
                    unknown,
                }
            }
            Ok((VerdictRead::Screen(body), claim)) => {
                submission.screen = Some(ScreenScore {
                    score: body.score,
                    cohort_sha256: body.cohort_sha256,
                    claim: claim.id,
                    output_sha256: sha256.clone(),
                    at: now,
                });
                TeamMarketVerdictOutcome::Screened { score: body.score }
            }
            Err(reason) => {
                submission.invalid = Some(InvalidVerdict {
                    reason: reason.to_owned(),
                    claim: claim_id,
                    at: now,
                });
                TeamMarketVerdictOutcome::Invalid {
                    reason: reason.to_owned(),
                }
            }
        };
        MARKET.put(&vault.store, txn, &market.team_ref, &market)?;
        Ok(Ok(verdict_answer(input, outcome, false)))
    })
}

/// A sealed verdict's outcome as its submission keeps it: the score and the
/// pass are written with the evidence.
fn scored(submission: &Submission, evidence: &VerdictEvidence) -> TeamMarketVerdictOutcome {
    TeamMarketVerdictOutcome::Scored {
        score: submission.score.unwrap_or_default(),
        passed: submission.passed.unwrap_or(false),
        unknown: evidence.unknown,
    }
}

fn override_view(kept: &MarketOverride) -> TeamOverrideView {
    TeamOverrideView {
        chosen: kept.chosen.clone(),
        reason: kept.reason.clone(),
        by: kept.by.to_hex(),
        at: kept.at,
        ledger_seq: kept.ledger_seq,
    }
}

fn outcome_of(result: &MarketResult, kept: Option<&MarketOverride>) -> TeamMarketOutcome {
    TeamMarketOutcome {
        winner: result.winner.clone(),
        winning_submission: result.winning_submission.clone(),
        bounty: result.bounty,
        closed_at: result.closed_at,
        referee_override: kept.map(override_view),
    }
}

/// A market team's result as it reads now: the referee's, with any CEO
/// override beside it; `None` for a team with no market or an open one.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn market_outcome_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    team_ref: &str,
) -> Result<Option<TeamMarketOutcome>> {
    let Some(market) = MARKET.get(&vault.store, txn, &team_ref.to_owned())? else {
        return Ok(None);
    };
    let Some(result) = &market.result else {
        return Ok(None);
    };
    let kept = OVERRIDE.get(&vault.store, txn, &team_ref.to_owned())?;
    Ok(Some(outcome_of(result, kept.as_ref())))
}

/// [`market_outcome_in_txn`] in its own read.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn market_outcome(vault: &Vault, team_ref: &str) -> Result<Option<TeamMarketOutcome>> {
    let rtxn = vault.store.env.read_txn()?;
    market_outcome_in_txn(vault, &rtxn, team_ref)
}

/// Settles a market team for its receipt, in one writer: closes the market
/// on its referee's verdicts if it is open, then logs the CEO's override, if
/// one is asked, as a ledger line with its own receipt. The award stays the
/// referee's. An override asked again on the same terms keeps the first.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn settle_market(
    vault: &Vault,
    team_ref: &str,
    asked: Option<&TeamOverrideInput>,
    by: EntityId,
) -> Result<std::result::Result<TeamMarketOutcome, &'static str>> {
    if let Some(asked) = asked
        && (!text_ok(&asked.submission_ref, MAX_TEXT_BYTES)
            || !text_ok(&asked.reason, MAX_REASON_BYTES))
    {
        return Ok(Err("team_record_invalid_input"));
    }
    vault.with_write_txn_grouped(|txn| {
        let key = team_ref.to_owned();
        let Some(mut market) = MARKET.get(&vault.store, txn, &key)? else {
            return Ok(Err("team_record_market_unbound"));
        };
        let now = vault.now_recorded_at();
        let result = if let Some(result) = market.result.clone() {
            result
        } else {
            market.close(now)
        };
        let kept = match (asked, OVERRIDE.get(&vault.store, txn, &key)?) {
            (None, kept) => kept,
            (Some(asked), Some(kept)) => {
                if kept.chosen != asked.submission_ref || kept.reason != asked.reason {
                    return Ok(Err("team_record_override_moved"));
                }
                Some(kept)
            }
            (Some(asked), None) => {
                if !market
                    .submissions
                    .iter()
                    .any(|s| s.submission_ref == asked.submission_ref)
                {
                    return Ok(Err("team_record_override_unknown"));
                }
                if result.winning_submission.as_deref() == Some(asked.submission_ref.as_str()) {
                    return Ok(Err("team_record_override_is_referee"));
                }
                let entry = LedgerKind::Override {
                    submission_ref: asked.submission_ref.clone(),
                    by,
                };
                let ledger_seq = market.post(now, None, entry, 0);
                let row = MarketOverride {
                    team_ref: key.clone(),
                    referee_winner: result.winning_submission.clone(),
                    chosen: asked.submission_ref.clone(),
                    reason: asked.reason.clone(),
                    by,
                    at: now,
                    ledger_seq,
                };
                OVERRIDE.put(&vault.store, txn, &key, &row)?;
                Some(row)
            }
        };
        MARKET.put(&vault.store, txn, &key, &market)?;
        Ok(Ok(outcome_of(&result, kept.as_ref())))
    })
}

/// A market's override receipt, if its CEO wrote one.
///
/// # Errors
///
/// Storage errors.
pub fn market_override(vault: &Vault, team_ref: &str) -> Result<Option<MarketOverride>> {
    let rtxn = vault.store.env.read_txn()?;
    OVERRIDE.get(&vault.store, &rtxn, &team_ref.to_owned())
}
