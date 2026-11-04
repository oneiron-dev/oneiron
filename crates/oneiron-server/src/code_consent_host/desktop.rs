//! The served host's answered pass over a held desktop act (FIX 11499):
//! [`browser`]'s twin for the desktop guest, beside it, never folded into
//! it (L13 09:01).
//!
//! The vault's own admission of a desktop verb is met again first, as
//! every desktop call meets it. The engine then admits the act once, as
//! it admits a browser act (a desktop wait keeps the same pending
//! effect), and this host runs that act on the run's own live desktop,
//! under one press armed for exactly it: the same act and input, resolved
//! to the same row in the same window of the same guest. A row, window or
//! guest that changed runs nothing: the press never moves to another
//! target. What the act came to settles the wait, and its reply wakes the
//! run with the act's own answer, through the post hooks the first pass
//! never reached when the wait kept its pre (FIX 11497).

use std::sync::PoisonError;

use oneiron::code_run::{AdmittedBrowserAct, CodeConsentBrowserAction, CodeConsentBrowserOutcome};
use oneiron::task_verb::sdk::AgentVerb;
use oneiron::{EntityId, Vault};
use oneiron_browser::{BrowserDriver, BrowserError, HeldPress, PressNeed};
use serde_json::Value;

use crate::server::SyncServer;

/// Why a held desktop act ran nothing: its run's desktop is gone, or is
/// another guest than the one the act was held in.
const CODE_WAIT_DESKTOP_GONE: &str = "code_wait_desktop_gone";

/// Why a held desktop act ran nothing: the act met another row, window or
/// input than the one its press was given for.
const CODE_WAIT_TARGET_CHANGED: &str = "code_wait_target_changed";

/// Why a held desktop act ran nothing: its kept act does not read as a
/// desktop act.
const CODE_WAIT_ACT_UNREADABLE: &str = "code_wait_act_unreadable";

/// Drives wait `wait_id`'s held desktop act once and settles the wait with
/// what it came to. A wait with nothing to run (unanswered, denied, settled
/// or admitted by an earlier pass) runs nothing here.
pub(super) fn resume_answered_desktop(
    server: &SyncServer,
    vault: &Vault,
    wait_id: EntityId,
) -> oneiron::Result<()> {
    if let Err(refused) = crate::api::RunGuests::guest_admits(vault, true) {
        let outcome = CodeConsentBrowserOutcome::Refused(vec![refused.code]);
        vault.settle_browser_code_consent_wait(wait_id, outcome)?;
        return Ok(());
    }
    let Some(admitted) = vault.admit_browser_code_consent_wait(wait_id)? else {
        return Ok(());
    };
    let outcome = run_held_act(server, vault, &admitted);
    vault.settle_browser_code_consent_wait(wait_id, outcome)?;
    Ok(())
}

/// Runs the admitted act on its run's live desktop under the one press
/// armed for it, and what it came to: its answer; a refusal for a desktop
/// that is gone or a target that changed; or, for an act whose input was
/// sent and whose window did not read after, an unknown delivery with its
/// receipt (FIX 12134).
fn run_held_act(
    server: &SyncServer,
    vault: &Vault,
    admitted: &AdmittedBrowserAct,
) -> CodeConsentBrowserOutcome {
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
    let Some(seat) = server.desktop_seats.get(admitted.run_id) else {
        return refused(&[CODE_WAIT_DESKTOP_GONE]);
    };
    let mut session = seat.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(driver) = session.as_mut() else {
        return refused(&[CODE_WAIT_DESKTOP_GONE]);
    };
    if driver.manifest().generation != action.session || !driver.arm_press(held) {
        return refused(&[CODE_WAIT_DESKTOP_GONE]);
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
            }
            // The post hooks the first pass never reached (FIX 11497), as
            // on the browser pass in `browser.rs`.
            let answer = match action.hook_pre.clone() {
                Some(snapshot) => oneiron::task_verb::verb_hook_boundary::row_post(
                    vault,
                    snapshot.into_post_pre(),
                    answer.clone(),
                )
                .unwrap_or(answer),
                None => answer,
            };
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
        act: action.act.strip_prefix("self.desktop.")?.to_owned(),
        operands: serde_json::from_str(&action.operands).ok()?,
        class: action.class.clone(),
        role: action.role.clone(),
        name: action.name.clone(),
        locator: action.locator.clone(),
        page: action.page.clone(),
        audience: action.audience.clone(),
        tab: action.tab.clone(),
        document: action.document.clone(),
        generation: action.session.clone(),
        need: match action.need.as_str() {
            "batch_spent" => PressNeed::BatchSpent,
            _ => PressNeed::PerSend,
        },
    })
}
