//! Judge rubric pins, label rechecks and human regrades.
//! Entry function: `recheck_judge_labels`.
//! The labels parent owns the anchor rows and rubric pin definitions.

use super::*;

/// The judge's rubric: from the bootstrap `judge` skill, through admitted
/// succession (`Supersedes`, new to old) to its newest revision, when that
/// revision is live, shared, active and approved. The text is its stored
/// package's SKILL.md, or a native revision's own instructions. `None` when no
/// such revision or text exists.
pub(crate) fn judge_rubric_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<JudgeRubric>> {
    let mut head = EntityId::derive(
        crate::entity_id::derived_domains::BOOTSTRAP_SKILL,
        &[JUDGE_SKILL_ID.as_bytes()],
    )?;
    let mut seen = BTreeSet::from([head]);
    loop {
        let newer = vault.filtered_edge_peers(
            txn,
            crate::ports::EdgeDirection::In,
            &head,
            EdgeKind::Supersedes,
            Some(crate::registry::ENTITY_TYPE_SKILL),
        )?;
        // Admitted succession is linear; the least id settles a fork in it.
        let Some(next) = newer.into_iter().filter(|id| !seen.contains(id)).min() else {
            break;
        };
        seen.insert(next);
        head = next;
    }
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &head)?.is_live() {
        return Ok(None);
    }
    let record = match vault.read_skill_record_in_txn(txn, &head) {
        Ok(record) => record,
        Err(Error::EntityNotFound | Error::InvalidClaimBody(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    if record.skill_id != JUDGE_SKILL_ID
        || crate::skill::resident_of(&record)?.is_some()
        || !crate::skill::skill_loadable(&record)
    {
        return Ok(None);
    }
    let text = match vault.runtime_skill_package_in_txn(txn, &head, &record)? {
        Some(package) => package
            .files
            .into_iter()
            .find(|file| file.path == SKILL_FILE)
            .and_then(|file| String::from_utf8(file.content).ok()),
        None if record.source != crate::claim::ClaimSource::Imported
            && record.forked_from.is_none() =>
        {
            Some(record.desc.clone())
        }
        None => None,
    };
    Ok(text.map(|text| JudgeRubric {
        skill: head,
        version: record.version,
        digest: *blake3::hash(text.as_bytes()).as_bytes(),
        text,
    }))
}

/// [`judge_rubric_in_txn`] in a read transaction of its own: the rubric the
/// replay judge reads beside every case.
pub fn judge_rubric(vault: &Vault) -> Result<Option<JudgeRubric>> {
    let txn = vault.store.env.read_txn()?;
    judge_rubric_in_txn(vault, &txn)
}

/// Re-pin the judge on `rubric`. The first pin is only recorded. A moved
/// digest stamps every label in the anchor as pending under the new rubric,
/// a pending one included; a label waiting on its person's re-grade keeps
/// waiting. Returns how many labels it stamped.
fn repin_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    rubric: &JudgeRubric,
    at: u64,
) -> Result<usize> {
    let pinned = RUBRIC_PIN.get(&vault.store, &*txn, &())?;
    if pinned
        .as_ref()
        .is_some_and(|pin| pin.digest == rubric.digest)
    {
        return Ok(0);
    }
    RUBRIC_PIN.put(
        &vault.store,
        txn,
        &(),
        &JudgeRubricPin {
            digest: rubric.digest,
            skill: rubric.skill,
            version: rubric.version.clone(),
            pinned_at: at,
        },
    )?;
    if pinned.is_none() {
        return Ok(0);
    }
    let mut stamped = Vec::new();
    for row in LABELS.iter_from(&vault.store, &*txn, &[])? {
        let (key, mut label) = row?;
        if key != label.ask.id {
            return Err(Error::CorruptedIndex("judge label identity"));
        }
        if label.in_anchor() {
            label.recheck = Some(JudgeLabelRecheck::Pending {
                rubric: rubric.digest,
            });
            stamped.push(label);
        }
    }
    for label in &stamped {
        LABELS.put(&vault.store, txn, &label.ask.id, label)?;
    }
    Ok(stamped.len())
}

/// [`repin_in_txn`] on the rubric as it reads now, before a pick. An
/// unreadable rubric leaves the pin as it was: the pick still stands, and the
/// Coach's next pass re-pins.
pub(super) fn repin_before_pick_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    at: u64,
) -> Result<()> {
    match judge_rubric_in_txn(vault, &*txn) {
        Ok(Some(rubric)) => {
            repin_in_txn(vault, txn, &rubric, at)?;
        }
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(%error, "the judge rubric is unreadable; a pick left the pin as it was");
        }
    }
    Ok(())
}

/// What the host's checker made of one pending pick against the new rubric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JudgeLabelFit {
    /// The pick still fits the rubric.
    Fits,
    /// The pick conflicts with the rubric.
    Conflicts,
    /// A model was asked and gave no answer to stand on.
    Unknown,
    /// No model was asked: the pick stays pending for a later pass.
    Unavailable,
}

/// One pending pick as the host's checker reads it: the label (its question,
/// its two options and the person's pick) and the rubric to check it against.
#[derive(Debug, Clone, Copy)]
pub struct JudgeLabelRecheckRequest<'a> {
    pub label: &'a JudgeLabel,
    pub rubric: &'a JudgeRubric,
}

/// The host's side of a re-check: one model call per pending pick, made
/// outside any vault transaction.
pub trait JudgeLabelChecker {
    fn check(&self, request: &JudgeLabelRecheckRequest<'_>) -> Result<JudgeLabelFit>;
}

/// What one re-check pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JudgeLabelRecheckReport {
    /// Labels the pass's re-pin stamped pending.
    pub stamped: u32,
    /// Pending picks found still fitting: their stamp cleared.
    pub fits: u32,
    /// Picks found conflicting, or not judged: out of the anchor, waiting on
    /// their person's re-grade.
    pub waiting: u32,
    /// Picks left pending: past the pass's limit, unasked, or moved meanwhile.
    pub pending: u32,
}

/// The Coach's re-check pass: re-pin the judge on its rubric's current text,
/// then put at most `limit` pending picks to `checker`, each settled in its own
/// transaction.
pub(crate) fn recheck_judge_labels(
    vault: &Vault,
    checker: &dyn JudgeLabelChecker,
    limit: usize,
    at: u64,
) -> Result<JudgeLabelRecheckReport> {
    let Some((rubric, stamped)) = vault.with_write_txn_grouped(|txn| {
        let Some(rubric) = judge_rubric_in_txn(vault, &*txn)? else {
            return Ok(None);
        };
        let stamped = repin_in_txn(vault, txn, &rubric, at)?;
        Ok(Some((rubric, stamped)))
    })?
    else {
        return Ok(JudgeLabelRecheckReport::default());
    };
    let mut report = JudgeLabelRecheckReport {
        stamped: u32::try_from(stamped).unwrap_or(u32::MAX),
        ..JudgeLabelRecheckReport::default()
    };
    let due = {
        let txn = vault.store.env.read_txn()?;
        let mut due = Vec::new();
        for row in LABELS.iter_from(&vault.store, &txn, &[])? {
            let (key, label) = row?;
            if key != label.ask.id {
                return Err(Error::CorruptedIndex("judge label identity"));
            }
            if label.recheck_due(rubric.digest) {
                due.push(label);
            }
        }
        due
    };
    let mut asked = 0_usize;
    for label in due {
        if asked >= limit {
            report.pending += 1;
            continue;
        }
        let fit = checker.check(&JudgeLabelRecheckRequest {
            label: &label,
            rubric: &rubric,
        })?;
        if fit == JudgeLabelFit::Unavailable {
            report.pending += 1;
            continue;
        }
        asked += 1;
        match vault
            .with_write_txn_grouped(|txn| settle_recheck_in_txn(vault, txn, &label, &rubric, fit))?
        {
            Some(true) => report.fits += 1,
            Some(false) => report.waiting += 1,
            None => report.pending += 1,
        }
    }
    Ok(report)
}

/// One checker answer on `label` against `rubric`, while neither moved since
/// the pass read them. A fit clears the stamp and keeps the pick time. A
/// conflict or an unknown answer takes the pick out of the anchor and asks its
/// person to re-grade it. `Some(fits)`, or `None` when either moved.
fn settle_recheck_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    label: &JudgeLabel,
    rubric: &JudgeRubric,
    fit: JudgeLabelFit,
) -> Result<Option<bool>> {
    let pinned = RUBRIC_PIN.get(&vault.store, &*txn, &())?;
    let current = LABELS.get(&vault.store, &*txn, &label.ask.id)?;
    if current.as_ref() != Some(label) || pinned.is_none_or(|pin| pin.digest != rubric.digest) {
        return Ok(None);
    }
    let fits = fit == JudgeLabelFit::Fits;
    let mut settled = label.clone();
    settled.recheck = if fits {
        None
    } else {
        Some(JudgeLabelRecheck::Waiting {
            rubric: rubric.digest,
            ask: regrade_ask_in_txn(vault, txn, label, rubric.digest)?,
        })
    };
    LABELS.put(&vault.store, txn, &label.ask.id, &settled)?;
    Ok(Some(fits))
}

/// Put `label`'s re-grade ask to its person: does the pick still fit the
/// rubric `rubric`? `None` when it cannot be put (the person is no longer
/// active, the skill is gone, or the words pass the context bound); the pick
/// then waits with no ask.
fn regrade_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    label: &JudgeLabel,
    rubric: [u8; 32],
) -> Result<Option<[u8; 32]>> {
    let keep = format!("{REGRADE_KEEP}{}", label.chosen);
    let question = ask_identity(
        label.ask.skill,
        label.ask.responsible,
        &label.ask.campaign,
        &label.ask.evidence,
        JudgeAskReason::RubricRecheck,
        [keep.as_str(), REGRADE_ASK_AGAIN],
        Some(JudgeRegrade {
            label: label.ask.id,
            rubric,
        }),
    )?;
    match propose_in_txn(vault, txn, question) {
        Ok(ask) => Ok(Some(ask.id)),
        Err(Error::InvalidConfig(_) | Error::EntityNotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

/// What a re-grade did: the label as it now stands and, when its person said
/// the pick no longer fits, the fresh ask of its case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JudgeLabelRegrade {
    pub label: JudgeLabel,
    pub fresh: Option<JudgeAsk>,
}

/// The responsible person's answer to a delivered re-grade ask. `still_fits`
/// puts the pick back in the anchor, its pick time unchanged. Otherwise the
/// pick leaves the anchor for good and its case is asked again: a fresh A/B
/// ask under the pinned rubric, which the digest delivers like any other. The
/// same answer again returns the same outcome; the other one fails.
pub fn record_judge_label_regrade(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    ask_id: [u8; 32],
    still_fits: bool,
) -> Result<JudgeLabelRegrade> {
    vault.with_write_txn_grouped(|txn| {
        let actor =
            crate::dreamer_runner::maintenance::validate_person_in_txn(vault, &*txn, owner)?;
        let ask = ASKS
            .get(&vault.store, &*txn, &ask_id)?
            .ok_or(Error::EntityNotFound)?;
        let Some(of) = ask.regrade.filter(|_| {
            ask.id == ask_id
                && ask.responsible == actor
                && ask.delivered_at.is_some()
                && ask.reason == JudgeAskReason::RubricRecheck
        }) else {
            return Err(invalid());
        };
        let mut label = LABELS
            .get(&vault.store, &*txn, &of.label)?
            .ok_or(Error::EntityNotFound)?;
        if label.ask.id != of.label {
            return Err(Error::CorruptedIndex("judge label identity"));
        }
        let state = label.recheck;
        match state {
            Some(JudgeLabelRecheck::Waiting {
                rubric,
                ask: Some(waiting),
            }) if waiting == ask_id && rubric == of.rubric => {}
            Some(JudgeLabelRecheck::Kept { ask: kept, .. }) if kept == ask_id && still_fits => {
                return Ok(JudgeLabelRegrade { label, fresh: None });
            }
            Some(JudgeLabelRecheck::Replaced {
                ask: replaced,
                fresh,
                ..
            }) if replaced == ask_id && !still_fits => {
                let fresh = ASKS.get(&vault.store, &*txn, &fresh)?;
                return Ok(JudgeLabelRegrade { label, fresh });
            }
            _ => return Err(invalid()),
        }
        let fresh = if still_fits {
            label.recheck = Some(JudgeLabelRecheck::Kept {
                rubric: of.rubric,
                ask: ask_id,
            });
            None
        } else {
            let pinned = RUBRIC_PIN
                .get(&vault.store, &*txn, &())?
                .map_or(of.rubric, |pin| pin.digest);
            let fresh = propose_in_txn(
                vault,
                txn,
                ask_identity(
                    label.ask.skill,
                    label.ask.responsible,
                    &label.ask.campaign,
                    &label.ask.evidence,
                    JudgeAskReason::RubricRegrade,
                    [label.ask.option_a.as_str(), label.ask.option_b.as_str()],
                    Some(JudgeRegrade {
                        label: of.label,
                        rubric: pinned,
                    }),
                )?,
            )?;
            label.recheck = Some(JudgeLabelRecheck::Replaced {
                rubric: of.rubric,
                ask: ask_id,
                fresh: fresh.id,
            });
            Some(fresh)
        };
        LABELS.put(&vault.store, txn, &of.label, &label)?;
        Ok(JudgeLabelRegrade { label, fresh })
    })
}
