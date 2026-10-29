//! The replay library (OF-598; EIRI-ARCH-0002 "The replay library"): a
//! solved browser run, kept as a parameterised program for its site.
//!
//! A program joins the library only after two checks. First the host checks
//! that the run succeeded: the program's postcondition, read on the page
//! itself, never the program's own "done". Then the program replays once
//! with no model (a routine step takes only a rule's answer), on a fresh
//! guest the host starts for it and never on the solved run's page, and the
//! replay meets the postcondition again on that guest's page. A proposal
//! that gives held-out values (`replay_args`) replays with them, so the
//! program is shown to work past its solved run's values (`held_out`).
//! Repeated work on a site tries the library first: opening a page lists
//! the site's programs, each card with its lineage's recent outcomes. A
//! library run is live: every effect in it still crosses its gated door,
//! and a run that misses its postcondition goes back to the planner with
//! the checks it missed and the page it left. A run is strict, where only a
//! rule answers its routine steps, or assisted (CUA E2); a program whose
//! strict runs miss three times in a row retires `drift`. A program that
//! stops working leaves by retire, and a later solved run that passes both
//! checks files it afresh, or files its repair as its successor
//! (`supersedes`), which retires it in the same write.
//!
//! A program's `{{name}}` slots take the run's arguments as data, in the
//! batch's own fields; nothing is spliced into code. A secret takes a typed
//! slot (FIX 8028, `secret_slots`): neither the program nor its proof holds
//! a secret, or the handle a run found it as.
//!
//! A program names elements by locator only, never by a live handle (a
//! handle names one node of one session's page). A proposal's handles the
//! session minted are put back to their rows' locators before the program
//! is checked; each step resolves its locators on the page as it runs.

mod admission;
mod cards;
mod draft;
#[cfg(feature = "driver")]
mod durable;
mod live_run;
mod program;
mod propose;
mod secret_slots;
mod targets;

pub(crate) use secret_slots::handle_form;

#[cfg(feature = "driver")]
pub(crate) use draft::draft_with_secrets;
#[cfg(feature = "driver")]
pub(crate) use durable::durable_draft;

pub use admission::{
    AdmissionRefusal, Admitted, RecentCounts, ReplayGuest, SupersedeOutcome, SupersedeRefusal,
    WorkflowSeed, validate_replay_args,
};
pub use cards::{
    LibraryCard, LibraryFindInput, LibraryFindOutput, LibraryRetireInput, LibraryRetireOutput,
    LibraryRetiredInput, LibraryRetiredOutput, RetiredCard,
};
pub use draft::{
    DraftGap, DraftGapKind, DraftInput, DraftOutcome, DraftOutput, DraftPage, DraftStep,
    PressedThrough, SlotCandidate, SlotField, draft_from_steps,
};
#[cfg(feature = "driver")]
pub use live_run::filled_checks;
#[cfg(feature = "driver")]
pub(crate) use live_run::run;
pub use live_run::{
    FiledWorkflow, LibraryRunInput, LibraryRunMode, LibraryRunOutput, RunOutcome, SecretArg,
    default_mode, effective_mode, model_free,
};
#[cfg(feature = "driver")]
pub use program::program_origin;
pub use program::{WorkflowLibrary, WorkflowProgram, site_of};
pub use propose::{ProposeInput, ProposeOutput, WorkflowCheck, WorkflowProof};
#[cfg(feature = "driver")]
pub(crate) use propose::{check_solved, no_fresh_guest, replay_and_file, supersedes_refused};
pub use secret_slots::SecretParam;

use crate::{BatchStep, BrowserError, ExpectInput};
#[cfg(feature = "driver")]
use crate::{BrowserDriver, CheckReceipt};
use std::collections::BTreeMap;

/// Fills every `{{name}}` slot in `value`'s strings from `args`.
fn fill_slots(
    value: &mut serde_json::Value,
    args: &BTreeMap<String, String>,
) -> Result<(), BrowserError> {
    match value {
        serde_json::Value::String(text) if text.contains("{{") => {
            *text = fill_text(text, args).map_err(|gap| match gap {
                SlotGap::Unclosed => BrowserError::Input("a {{ slot is never closed".to_owned()),
                SlotGap::Missing(name) => {
                    BrowserError::Input(format!("slot {{{{{name}}}}} is no parameter"))
                }
            })?;
        }
        serde_json::Value::Array(items) => {
            for item in items {
                fill_slots(item, args)?;
            }
        }
        serde_json::Value::Object(fields) => {
            for field in fields.values_mut() {
                fill_slots(field, args)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// A slot [`fill_text`] could not fill: one `args` holds no value for, by
/// its name, or one never closed.
pub(crate) enum SlotGap {
    Missing(String),
    Unclosed,
}

/// `text` with every `{{name}}` slot filled from `args`: the one slot
/// filler a program's fields and a Fill's template share (CUA E6).
pub(crate) fn fill_text(text: &str, args: &BTreeMap<String, String>) -> Result<String, SlotGap> {
    let mut filled = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        filled.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let close = after.find("}}").ok_or(SlotGap::Unclosed)?;
        let name = after[..close].trim();
        let arg = args
            .get(name)
            .ok_or_else(|| SlotGap::Missing(name.to_owned()))?;
        filled.push_str(arg);
        rest = &after[close + 2..];
    }
    filled.push_str(rest);
    Ok(filled)
}

#[cfg(feature = "driver")]
/// The checks the page as it is now misses, by index, each with what its
/// read found.
fn missed<D: BrowserDriver + ?Sized>(
    driver: &mut D,
    checks: &[ExpectInput],
) -> Result<Vec<(usize, CheckReceipt)>, BrowserError> {
    let mut missed = Vec::new();
    for (index, check) in checks.iter().enumerate() {
        let observed = driver.expect(check.clone())?;
        if !observed.met {
            let expect = check.clone();
            missed.push((index, CheckReceipt { expect, observed }));
        }
    }
    Ok(missed)
}

#[cfg(feature = "driver")]
/// Puts every live handle `driver` minted among `steps` and `checks` back to
/// its row's locator.
fn by_locator<D: BrowserDriver + ?Sized>(
    driver: &D,
    steps: &mut [BatchStep],
    checks: &mut [ExpectInput],
) {
    let targets = steps
        .iter_mut()
        .flat_map(BatchStep::targets_mut)
        .chain(checks.iter_mut().filter_map(|check| check.target.as_mut()));
    for target in targets {
        if let Some(info) = driver.handle_info(target.as_str()) {
            *target = info.locator;
        }
    }
}
