//! What an admission checks past the two pages, and what the library keeps
//! of it (CUA E1): the held-out values a replay may run with, the fresh
//! guest it runs on, a program's lineage (`supersedes`) and provenance
//! (`seed`), and the recent outcomes a card counts.

use crate::{BrowserEngine, SwitchCarried, SwitchNotCarried, SwitchStage, WorkflowProgram};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Where a hub pack's seed program came from: the pack, the ref it was
/// pinned at, the file's path in it, the file's digest and its licence.
/// Provenance only: it grants nothing, and a hub import supplies the
/// verified values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowSeed {
    pub pack: String,
    pub pinned_ref: String,
    pub path: String,
    pub digest: String,
    pub license: String,
}

/// The fresh guest an admission's replay ran on: its engine, and what it
/// took of the proposing session's sign-ins (its cookies, and the stores of
/// the origins its tab visited), listed as an engine switch's record lists
/// them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReplayGuest {
    pub engine: BrowserEngine,
    pub carried: Vec<SwitchCarried>,
    pub not_carried: Vec<SwitchNotCarried>,
}

/// Why the library refused a `supersedes` link. Nothing was filed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SupersedeRefusal {
    /// It is no program's ref.
    Malformed,
    /// No program of this one's site, live or retired, is filed under it.
    NotOnSite,
    /// It names the program this one refiles: the same bytes repair nothing.
    SameRecord,
    /// The program it names is live, and only the caller whose run filed it
    /// retires it (`RETIRE_FILER_ONLY`, as `library.retire`).
    NotFiler,
}

/// What an admission did with the program its `supersedes` named.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SupersedeOutcome {
    /// It was live: it retired `superseded:<the new ref>` as its successor
    /// was filed.
    Retired,
    /// It was retired already: the successor links it, and it is not
    /// retired again.
    Linked,
    /// The proposed program's bytes equal a filed one's, so the admission
    /// refiled that one: no repair, and no link.
    Dropped,
}

/// What a refusing check found, where its `unmet` checks do not say it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "cause", rename_all = "snake_case")]
pub enum AdmissionRefusal {
    /// The `replay_args` given hold nothing out: `used` names the slots the
    /// steps and the postcondition use, `missing` the names of `args` they
    /// lack, `unknown` the names they hold that `args` does not, and `same`
    /// each used slot they give the solved run's value.
    HeldOut {
        used: Vec<String>,
        missing: Vec<String>,
        unknown: Vec<String>,
        same: Vec<String>,
    },
    /// No fresh guest ran the replay: the host gives none, or one did not
    /// start (`start`), or did not take the carried cookies (`cookies`).
    /// `code` is the browser's refusal code there, and `detail` its words.
    FreshGuest {
        stage: SwitchStage,
        code: String,
        detail: String,
    },
    /// The library refused the `supersedes` link to `workflow`.
    Supersedes {
        workflow: String,
        why: SupersedeRefusal,
    },
}

/// What the library did with a program both checks passed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admitted {
    /// Filed under `workflow`, and what became of the program its
    /// `supersedes` named, when it named one.
    Filed {
        workflow: String,
        superseded: Option<SupersedeOutcome>,
    },
    /// The `supersedes` link was refused; nothing was filed.
    Refused(SupersedeRefusal),
}

/// A program's recent outcomes, as its card counts them: among the newest
/// `of` outcomes of its lineage (its own, and those of the programs it
/// supersedes), the library runs that met the postcondition (`pass`) or
/// did not (`miss`), and the repairs that filed a successor (`repair`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RecentCounts {
    pub pass: u32,
    pub miss: u32,
    pub repair: u32,
    pub of: u32,
}

/// Whether `replay_args` hold values out from `args` for `program`'s
/// replay (CUA E1 held-out values, CALLS row; Engine 10-21 23:4x). None
/// given, absent or empty, replays with `args` and holds nothing out. Given,
/// they name exactly the names `args` does, and at least one slot the steps
/// or the postcondition use takes another value.
///
/// # Errors
///
/// [`AdmissionRefusal::HeldOut`] when the values given hold nothing out,
/// naming what is missing, unknown or the same.
pub fn validate_replay_args(
    program: &WorkflowProgram,
    args: &BTreeMap<String, String>,
    replay_args: &BTreeMap<String, String>,
) -> Result<bool, AdmissionRefusal> {
    if replay_args.is_empty() {
        return Ok(false);
    }
    let lacking = |of: &BTreeMap<String, String>, other: &BTreeMap<String, String>| {
        of.keys()
            .filter(|name| !other.contains_key(*name))
            .cloned()
            .collect::<Vec<_>>()
    };
    let (missing, unknown) = (lacking(args, replay_args), lacking(replay_args, args));
    let used = used_slots(program);
    let same: Vec<String> = used
        .iter()
        .filter(|slot| args.get(*slot) == replay_args.get(*slot))
        .cloned()
        .collect();
    if missing.is_empty() && unknown.is_empty() && same.len() < used.len() {
        return Ok(true);
    }
    Err(AdmissionRefusal::HeldOut {
        used: used.into_iter().collect(),
        missing,
        unknown,
        same,
    })
}

/// The `{{name}}` slots `program`'s steps and postcondition use.
fn used_slots(program: &WorkflowProgram) -> BTreeSet<String> {
    let mut used = BTreeSet::new();
    let values = [
        serde_json::to_value(&program.steps),
        serde_json::to_value(&program.postcondition),
    ];
    for value in values.into_iter().flatten() {
        slots_in(&value, &mut used);
    }
    used
}

/// Adds every `{{name}}` slot in `value`'s strings to `used`, as
/// `fill_slots` reads them.
fn slots_in(value: &serde_json::Value, used: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::String(text) => {
            let mut rest = text.as_str();
            while let Some(open) = rest.find("{{") {
                let after = &rest[open + 2..];
                let Some(close) = after.find("}}") else {
                    break;
                };
                used.insert(after[..close].trim().to_owned());
                rest = &after[close + 2..];
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                slots_in(item, used);
            }
        }
        serde_json::Value::Object(fields) => {
            for field in fields.values() {
                slots_in(field, used);
            }
        }
        _ => {}
    }
}
