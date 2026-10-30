//! Judge-swap retest, shadow and re-pin passes.
//! Entry function: `run_judge_swap`.
//! Vocabulary and retained state definitions remain in `super`.

use super::*;

/// One judge-swap pass. Model calls go through `host`, outside any vault
/// transaction; every write opens its own.
pub(crate) fn run_judge_swap(
    vault: &Vault,
    host: &dyn JudgeShadowHost,
    now: u64,
) -> Result<JudgeSwapReport> {
    let cases = host.kept_cases(KEPT_CASES)?;
    let incumbent = match load::<JudgeIncumbent>(vault, INCUMBENT_KEY)? {
        Some(incumbent) => incumbent,
        None => {
            let Some(newest) = cases.first() else {
                return Ok(JudgeSwapReport::Idle);
            };
            let incumbent = JudgeIncumbent {
                judge: newest.judge.clone(),
                since: now,
                previous: None,
                takeover: None,
            };
            save(vault, INCUMBENT_KEY, &incumbent)?;
            incumbent
        }
    };
    if let Some(receipt) = recheck(vault, &incumbent, now)? {
        return Ok(JudgeSwapReport::RePinned(receipt));
    }
    let incumbent = incumbent.judge;
    let own: Vec<&JudgeShadowCase> = cases
        .iter()
        .filter(|case| case.judge == incumbent)
        .collect();
    // Who answers now: the incumbent's newest case, asked again.
    let Some(first) = own.first() else {
        return Ok(JudgeSwapReport::Idle);
    };
    let Some(probe) = host.rescore(first)? else {
        return Ok(JudgeSwapReport::Idle);
    };
    if probe.judge == incumbent {
        retest(vault, host, &incumbent, &own, probe, now)
    } else {
        shadow(vault, host, &incumbent, &own, probe, now)
    }
}

/// Retests the incumbent on its own cases, each once: how often it
/// disagrees with itself is the noise a swap is judged against.
fn retest(
    vault: &Vault,
    host: &dyn JudgeShadowHost,
    incumbent: &str,
    own: &[&JudgeShadowCase],
    probe: JudgeShadowAnswer,
    now: u64,
) -> Result<JudgeSwapReport> {
    // With no live judge head the noise has no subject to be kept under,
    // so nothing is retested or asked of the host (FIX 8079, FIX 9076).
    let scorer = {
        let rtxn = vault.store.env.read_txn()?;
        scorer(vault, &rtxn)?
    };
    let Some(scorer) = scorer else {
        tracing::warn!(
            reason = NOISE_SUBJECT_ABSENT,
            "the judge's retest noise was not recorded: its subject is absent"
        );
        return Ok(JudgeSwapReport::Retested {
            judge: incumbent.to_owned(),
            retests: 0,
        });
    };
    let mut probe = Some(probe);
    let mut retests = 0;
    for case in own {
        if retests >= RETESTS {
            break;
        }
        let answered = probe.take();
        let key = format!("{RETESTED_PREFIX}{}", case.case_ref);
        if vault.sync_state_get(&key)?.is_some() {
            continue;
        }
        let again = match answered {
            Some(answer) => answer,
            None => match host.rescore(case)? {
                Some(answer) => answer,
                None => continue,
            },
        };
        // A judge that changed mid-pass is the next pass's swap.
        if again.judge != incumbent {
            break;
        }
        let agreed = agree(&case.answer, &again.answer);
        record_retest(
            vault,
            &Retest {
                scorer,
                executor: incumbent.to_owned(),
                axis: NOISE_AXIS.to_owned(),
                type_ref: None,
                receipt: format!("judge-retest:{}", case.case_ref),
                first: RetestScore::Pass(true),
                second: RetestScore::Pass(agreed),
                at: now,
            },
            now,
        )?;
        save(
            vault,
            &key,
            &JudgeRetestMark {
                case_ref: case.case_ref.clone(),
                skill: judged_skill(&case.state),
                kept: JudgeShadowAnswer {
                    judge: case.judge.clone(),
                    answer: case.answer.clone(),
                },
                rerun: again,
                agreed,
                at: now,
            },
        )?;
        retests += 1;
    }
    Ok(JudgeSwapReport::Retested {
        judge: incumbent.to_owned(),
        retests: u32::try_from(retests).unwrap_or(u32::MAX),
    })
}

/// Has the new judge score the incumbent's cases and rules on the swap.
fn shadow(
    vault: &Vault,
    host: &dyn JudgeShadowHost,
    incumbent: &str,
    own: &[&JudgeShadowCase],
    probe: JudgeShadowAnswer,
    now: u64,
) -> Result<JudgeSwapReport> {
    let candidate = probe.judge.clone();
    let tag = blake3::hash(candidate.as_bytes()).to_hex();
    let key = |case: &JudgeShadowCase| format!("{SHADOW_PREFIX}{}:{}", &tag[..32], case.case_ref);
    if let Some(first) = own.first()
        && load::<JudgeShadowAnswer>(vault, &key(first))?.is_none()
    {
        save(vault, &key(first), &probe)?;
    }
    let policy = judge_swap_policy(vault)?;
    let pair = pair_tag(incumbent, &candidate);
    let mut divergence = Vec::new();
    let mut pairs = Vec::new();
    let mut disagreements: Vec<(&JudgeShadowCase, JudgeSwapDisagreement)> = Vec::new();
    for case in own.iter().take(SHADOW_CASES) {
        let answer = match load::<JudgeShadowAnswer>(vault, &key(case))? {
            Some(kept) => kept,
            None => {
                let Some(answer) = host.rescore(case)? else {
                    continue;
                };
                save(vault, &key(case), &answer)?;
                answer
            }
        };
        if answer.judge != candidate {
            continue;
        }
        let diverged = !agree(&case.answer, &answer.answer);
        divergence.push(DivergenceCase {
            source_family: case.source_family.clone(),
            diverged,
        });
        if let (DecisionAnswer::Score(old), DecisionAnswer::Score(new)) =
            (&case.answer, &answer.answer)
        {
            pairs.push((*old, *new));
        }
        if diverged {
            disagreements.push((*case, disagreement(vault, incumbent, case, answer)?));
        }
    }
    let noise = {
        let rtxn = vault.store.env.read_txn()?;
        noise_cell(vault, &rtxn, incumbent)?
    };
    let noise = match &noise {
        Some(cell) => learning_estimate(vault, cell)?,
        None => None,
    };
    let noise = noise.as_ref().filter(|noise| noise.runs > 0.0);
    let (mut verdict, threshold_source, threshold) = match policy.pinned_divergence {
        Some(rate) => (
            pinned_verdict(&divergence, rate),
            "owner_pinned",
            Some(rate),
        ),
        None => (
            judge_takeover_verdict(&divergence, noise, MIN_CASES_PER_FAMILY),
            "retest_noise",
            noise.map(crate::learning::Estimate::mean),
        ),
    };
    let mut anchors = Anchors::default();
    for (_, case) in &mut disagreements {
        anchor(vault, &pair, &mut anchors, case)?;
    }
    let mut arbitrated = false;
    match verdict {
        // A takeover the anchors already contradict would re-pin at once.
        TakeoverVerdict::TakeOver => {
            let settled = || disagreements.iter().map(|(_, case)| case);
            if anchored(settled(), incumbent) > anchored(settled(), &candidate) {
                verdict = TakeoverVerdict::Hold;
            }
        }
        // Known and wider than the threshold: only the disagreements count.
        TakeoverVerdict::Hold => {
            arbitrated = true;
            for (kept, case) in &mut disagreements {
                let rule = if case.floor {
                    policy.floor_tie_breaker
                } else {
                    policy.tie_breaker
                };
                if case.settled_by == JudgeSwapSettledBy::Open
                    && rule == JudgeTieBreaker::ThirdFamily
                {
                    tie_break(vault, host, &pair, *kept, &candidate, case)?;
                }
            }
            let settled = || disagreements.iter().map(|(_, case)| case);
            let open = settled().filter(|case| case.sided_with.is_none()).count();
            // An open case holds for the incumbent.
            if sided(settled(), &candidate) > sided(settled(), incumbent) + open {
                verdict = TakeoverVerdict::TakeOver;
            }
        }
        TakeoverVerdict::Unknown => {}
    }
    let id = vault.store.clock.entity_id()?.to_hex();
    let mut converted = false;
    if verdict == TakeoverVerdict::TakeOver {
        // Only scores convert; a judge of choices takes over with no map.
        if pairs.len() >= 2 {
            record_judge_conversion(vault, incumbent, &candidate, &pairs, now)?;
            converted = true;
        }
        save(
            vault,
            INCUMBENT_KEY,
            &JudgeIncumbent {
                judge: candidate.clone(),
                since: now,
                previous: Some(incumbent.to_owned()),
                takeover: Some(id.clone()),
            },
        )?;
    }
    let families: BTreeSet<&str> = divergence
        .iter()
        .map(|case| case.source_family.as_str())
        .collect();
    let receipt = JudgeSwapReceipt {
        id,
        from_judge: incumbent.to_owned(),
        to_judge: candidate,
        verdict: match verdict {
            TakeoverVerdict::TakeOver => "take_over",
            TakeoverVerdict::Hold => "hold",
            TakeoverVerdict::Unknown => "unknown",
        }
        .to_owned(),
        arbitrated,
        cases: count(divergence.len()),
        diverged: count(disagreements.len()),
        families: count(families.len()),
        threshold_source: threshold_source.to_owned(),
        threshold,
        noise_runs: noise.map_or(0.0, |noise| noise.runs),
        converted,
        disagreements: disagreements.into_iter().map(|(_, case)| case).collect(),
        at: now,
    };
    save(vault, &format!("{RECEIPT_PREFIX}{}", receipt.id), &receipt)?;
    if verdict == TakeoverVerdict::TakeOver {
        notify_owners(vault, &receipt.id, policy.hands_on, now)?;
    }
    Ok(JudgeSwapReport::Shadowed(receipt))
}

/// Re-reads the last takeover's disagreements against the picks and settled
/// outcomes since. When more of them side with the judge it replaced than
/// with the incumbent, the swap re-pins back: that judge is the incumbent
/// again, the conversion onto the new scale is withdrawn, and the owners
/// hear of it.
fn recheck(
    vault: &Vault,
    incumbent: &JudgeIncumbent,
    now: u64,
) -> Result<Option<JudgeSwapReceipt>> {
    let (Some(previous), Some(takeover)) = (&incumbent.previous, &incumbent.takeover) else {
        return Ok(None);
    };
    let Some(swap) = load::<JudgeSwapReceipt>(vault, &format!("{RECEIPT_PREFIX}{takeover}"))?
    else {
        return Ok(None);
    };
    let pair = pair_tag(previous, &incumbent.judge);
    let mut anchors = Anchors::default();
    let mut disagreements = swap.disagreements.clone();
    for case in &mut disagreements {
        anchor(vault, &pair, &mut anchors, case)?;
    }
    if anchored(disagreements.iter(), previous) <= anchored(disagreements.iter(), &incumbent.judge)
    {
        return Ok(None);
    }
    save(
        vault,
        INCUMBENT_KEY,
        &JudgeIncumbent {
            judge: previous.clone(),
            since: now,
            previous: None,
            takeover: None,
        },
    )?;
    let converted = withdraw_judge_conversion(vault, previous, now)?;
    let receipt = JudgeSwapReceipt {
        id: vault.store.clock.entity_id()?.to_hex(),
        from_judge: incumbent.judge.clone(),
        to_judge: previous.clone(),
        verdict: "re_pin".to_owned(),
        arbitrated: true,
        converted,
        disagreements,
        at: now,
        ..swap
    };
    save(vault, &format!("{RECEIPT_PREFIX}{}", receipt.id), &receipt)?;
    notify_owners(vault, &receipt.id, false, now)?;
    Ok(Some(receipt))
}
