//! `library.draft` on a browser session (CUA E7): the session's own history
//! (`trail`) as draft steps, its open page, and the caller's checks put in
//! the form a program keeps, through the one pure draft
//! (`crate::library::draft`). It needs no library, runs no model and
//! replays nothing.
//!
//! A check's live handle goes back to its row's locator, as a proposal's
//! does; one the session no longer knows is left out and named. A check's
//! secret keeps its run-bound handle, of the kind the session holds for it;
//! a plain value the check's field, or the value itself, shows to be a
//! secret goes into the run's custody as that exact value and is checked by
//! handle, never kept as text. A check that cannot be kept so is left out
//! and named.

use super::BrowserSession;
use super::trail::{Event, Marker, origin_of, value_secret, withheld};
use crate::secret::bare_handle;
use crate::{
    BrowserDriver, BrowserError, DraftGap, DraftGapKind, DraftInput, DraftOutcome, DraftOutput,
    DraftPage, DraftStep, EffectReceipt, ExpectInput, OperandGap, ReplayAction, SecretKind,
    draft_from_steps, is_live_handle,
};
use std::collections::BTreeMap;

/// An effect's receipt as a draft step: its act, or why it has none, and
/// whether its act proved it changed nothing.
fn effect_step(receipt: &EffectReceipt) -> DraftStep {
    let requested_origin = match &receipt.action {
        Some(ReplayAction::Open { url }) => origin_of(url),
        _ => None,
    };
    let outcome = if receipt.fact.is_some() {
        DraftOutcome::NoEffect
    } else {
        DraftOutcome::Ok
    };
    DraftStep {
        seq: receipt.seq,
        verb: receipt.verb.clone(),
        tab: receipt.tab.clone(),
        result_tab: receipt.result_tab.clone(),
        source_url: receipt.source_url.clone(),
        source_origin: receipt.source_origin.clone(),
        result_url: receipt.url.clone(),
        result_origin: origin_of(&receipt.url),
        requested_origin,
        target_name: receipt.target_name.clone(),
        effect_class: receipt.effect_class.clone(),
        action: receipt.action.clone().ok_or(DraftGapKind::NoAction),
        outcome,
    }
}

/// A stop as a draft step: no act, failed, or marking the effect it
/// followed failed; a refused press keeps its class.
fn stop_step(marker: &Marker) -> DraftStep {
    let cause = marker.stop.cause.clone();
    let outcome = match marker.stop.receipt {
        Some(seq) => DraftOutcome::Marked { seq, cause },
        None => DraftOutcome::Failed { cause },
    };
    DraftStep {
        seq: marker.seq,
        verb: marker.stop.step.clone(),
        tab: marker.tab.clone(),
        result_tab: marker.tab.clone(),
        source_url: marker.url.clone(),
        source_origin: marker.origin.clone(),
        result_url: marker.url.clone().unwrap_or_default(),
        result_origin: marker.origin.clone(),
        requested_origin: None,
        target_name: None,
        effect_class: marker.stop.effect_class.clone(),
        action: Err(DraftGapKind::NoAction),
        outcome,
    }
}

impl BrowserSession {
    /// `library.draft`: the session's history drafted for its open page.
    pub(super) fn draft(&mut self, mut input: DraftInput) -> Result<DraftOutput, BrowserError> {
        let url = self.live()?.url()?;
        let origin = origin_of(&url);
        let mut secrets = BTreeMap::new();
        let mut gaps = Vec::new();
        let checks = std::mem::take(&mut input.postcondition);
        for (index, check) in checks.into_iter().enumerate() {
            match self.drafted_check(check, origin.as_deref(), &mut secrets) {
                Ok(check) => input.postcondition.push(check),
                Err(cause) => {
                    let gap = match cause {
                        Some(cause) => DraftGapKind::CheckSecretWithheld {
                            check: index,
                            cause,
                        },
                        None => DraftGapKind::CheckUnknownRef { check: index },
                    };
                    gaps.push(DraftGap {
                        seq: None,
                        verb: None,
                        gap,
                    });
                }
            }
        }
        let steps = self.draft_steps();
        let page = DraftPage {
            url,
            origin,
            secrets,
        };
        let mut output = draft_from_steps(&input, &steps, &page)?;
        output.complete &= gaps.is_empty();
        output.gaps.extend(gaps);
        Ok(output)
    }

    /// The history as draft steps, in order: a stop after an effect marks
    /// that effect failed.
    fn draft_steps(&self) -> Vec<DraftStep> {
        let mut steps: Vec<DraftStep> = self
            .trail
            .iter()
            .map(|event| match event {
                Event::Effect(receipt) => effect_step(receipt),
                Event::Stop(marker) => stop_step(marker),
            })
            .collect();
        for event in &self.trail {
            if let Event::Stop(marker) = event
                && let Some(seq) = marker.stop.receipt
                && let Some(step) = steps.iter_mut().find(|step| step.seq == seq)
            {
                step.outcome = DraftOutcome::Failed {
                    cause: marker.stop.cause.clone(),
                };
            }
        }
        steps
    }

    /// `check` as a program keeps it, a secret by its handle, the kind of
    /// each handle in `secrets`; or why it cannot be kept: a live handle
    /// the session does not know (none), or a secret not held as a handle.
    fn drafted_check(
        &self,
        mut check: ExpectInput,
        origin: Option<&str>,
        secrets: &mut BTreeMap<String, SecretKind>,
    ) -> Result<ExpectInput, Option<OperandGap>> {
        let mut field = None;
        if let Some(target) = check.target.as_mut()
            && is_live_handle(target)
        {
            let info = self.driver.handle_info(target).ok_or(None)?;
            field = info.secret;
            *target = info.locator;
        }
        if let Some(named) = check.secret.take() {
            let handle = bare_handle(&named).to_owned();
            let kind = self.secrets.kind_of(&handle);
            let kind = kind.ok_or(Some(OperandGap::UnknownKind))?;
            secrets.insert(handle.clone(), kind);
            check.secret = Some(handle);
        } else if let Some(value) = check.value.take() {
            match field.or_else(|| value_secret(&value)) {
                None => check.value = Some(value),
                Some(kind) => {
                    let held = self
                        .secrets
                        .acquire(kind, &value, origin.unwrap_or_default());
                    let handle = held.map_err(|note| Some(withheld(note)))?;
                    secrets.insert(handle.clone(), kind);
                    check.secret = Some(handle);
                }
            }
        }
        Ok(check)
    }
}
