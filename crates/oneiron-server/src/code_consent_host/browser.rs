//! The served host's answered pass over a held browser act (FIX 10423).
//!
//! The engine admits the act once: the answer's approve-once marker is
//! spent beside the wait's admission, so a retried pass never runs it
//! again. This host then runs that act on the run's own live browser, the
//! seat its run's doors share, under one press armed for exactly it: the
//! same act and input, resolved to the same row on the same page of the
//! same guest. The press is a person's, per send, and pays no reviewed
//! batch. A row, page or guest that changed runs nothing: the press never
//! moves to another target. What the act came to settles the wait, and its
//! reply wakes the run with the act's own answer.

use std::sync::PoisonError;

use oneiron::code_run::{AdmittedBrowserAct, CodeConsentBrowserAction, CodeConsentBrowserOutcome};
use oneiron::task_verb::sdk::AgentVerb;
use oneiron::{EntityId, Vault};
use oneiron_browser::{BrowserDriver, BrowserError, HeldPress, PressNeed};
use serde_json::Value;

use crate::server::SyncServer;

/// Why a held browser act ran nothing: its run's browser is gone, or is
/// another guest than the one the act was held in.
const CODE_WAIT_BROWSER_GONE: &str = "code_wait_browser_gone";

/// Why a held browser act ran nothing: the act met another row, page or
/// input than the one its press was given for.
const CODE_WAIT_TARGET_CHANGED: &str = "code_wait_target_changed";

/// Why a held browser act ran nothing: its kept act does not read as a
/// browser act.
const CODE_WAIT_ACT_UNREADABLE: &str = "code_wait_act_unreadable";

/// Drives wait `wait_id`'s held browser act once and settles the wait with
/// what it came to. A wait with nothing to run (unanswered, denied, settled
/// or admitted by an earlier pass) runs nothing here.
pub(super) fn resume_answered_browser(
    server: &SyncServer,
    vault: &Vault,
    wait_id: EntityId,
) -> oneiron::Result<()> {
    let Some(admitted) = vault.admit_browser_code_consent_wait(wait_id)? else {
        return Ok(());
    };
    let outcome = run_held_act(server, &admitted);
    vault.settle_browser_code_consent_wait(wait_id, outcome)?;
    Ok(())
}

/// Runs the admitted act on its run's live browser under the one press
/// armed for it, and what it came to: its answer; a refusal for a browser
/// that is gone or a target that changed; or, for an act whose input was
/// sent and whose page did not read after, an unknown delivery with its
/// receipt.
fn run_held_act(server: &SyncServer, admitted: &AdmittedBrowserAct) -> CodeConsentBrowserOutcome {
    let refused = |reasons: &[&str]| {
        CodeConsentBrowserOutcome::Refused(reasons.iter().map(|code| (*code).to_owned()).collect())
    };
    let action = &admitted.action;
    let (Some(verb), Ok(input), Some(held)) = (
        AgentVerb::from_name(&action.act),
        serde_json::from_str::<Value>(&action.operands),
        held_press(action),
    ) else {
        return refused(&[CODE_WAIT_ACT_UNREADABLE]);
    };
    let Some(seat) = server.browser_seats.get(admitted.run_id) else {
        return refused(&[CODE_WAIT_BROWSER_GONE]);
    };
    let mut session = seat.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(driver) = session.as_mut() else {
        return refused(&[CODE_WAIT_BROWSER_GONE]);
    };
    if driver.manifest().generation != action.session || !driver.arm_press(held) {
        return refused(&[CODE_WAIT_BROWSER_GONE]);
    }
    let acted = oneiron::task_verb::sdk::invoke_browser(driver, verb.as_str(), input);
    // The press covered this act alone; nothing it left stands.
    driver.disarm_press();
    drop(driver.take_held_press());
    match acted {
        Ok(mut answer) => {
            if let Some(object) = answer.as_object_mut() {
                if let Ok(manifest) = serde_json::to_value(driver.manifest()) {
                    object.insert("session_manifest".into(), manifest);
                }
                object.insert("engine".into(), Value::from(driver.engine().as_str()));
            }
            CodeConsentBrowserOutcome::Delivered(answer)
        }
        Err(error @ BrowserError::NeedsPress(_)) => {
            refused(&[CODE_WAIT_TARGET_CHANGED, error.code()])
        }
        Err(error) => match driver.sent_receipt() {
            Some(receipt) => CodeConsentBrowserOutcome::DeliveryUnknown {
                reasons: vec![error.code().to_owned()],
                receipt: serde_json::to_value(receipt).ok(),
            },
            None => refused(&[error.code()]),
        },
    }
}

/// The press the session armed for `action`, as the session held it.
fn held_press(action: &CodeConsentBrowserAction) -> Option<HeldPress> {
    Some(HeldPress {
        act: action.act.strip_prefix("self.browser.")?.to_owned(),
        operands: serde_json::from_str(&action.operands).ok()?,
        class: action.class.clone(),
        role: action.role.clone(),
        name: action.name.clone(),
        locator: action.locator.clone(),
        page: action.page.clone(),
        generation: action.session.clone(),
        need: match action.need.as_str() {
            "batch_spent" => PressNeed::BatchSpent,
            _ => PressNeed::PerSend,
        },
    })
}
