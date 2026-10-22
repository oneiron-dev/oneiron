//! The library's cards (OF-598): a program as a planner reads it, and the
//! inputs and answers of `find`, `retire` and `retired`, moved out of
//! `library` whole.

use super::{RecentCounts, SecretParam, WorkflowSeed};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Lists the library's programs for a site: `site` (a host, as
/// `www.example.com`), or the open page's.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LibraryFindInput {
    #[serde(default)]
    pub site: Option<String>,
    /// Words the program's subgoal holds, ignoring case.
    #[serde(default)]
    pub subgoal: Option<String>,
    /// The task type the program was filed under, as `node_id@tree_version`
    /// (a card's `type_ref`): that node at that tree version only, never a
    /// descendant or another version's node (CUA E4). A filter in another
    /// form is refused.
    #[serde(default)]
    pub type_ref: Option<String>,
}

/// One library program as a planner reads it: its lifetime runs and
/// failures, its lineage's recent outcomes, how its admission proved it,
/// and where it came from.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LibraryCard {
    pub workflow: String,
    pub site: String,
    pub subgoal: String,
    /// The task type its subgoal placed at when it was filed, as
    /// `node_id@tree_version`: the form `find`'s `type_ref` takes.
    pub type_ref: String,
    pub params: Vec<String>,
    /// Those of `params` that take a secret: a run names a handle it holds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_params: Vec<SecretParam>,
    pub runs: u32,
    pub failures: u32,
    /// The newest outcomes of its lineage: its own, and those of the
    /// programs it supersedes.
    pub recent: RecentCounts,
    /// Whether its admission replayed with values held out from the solved
    /// run's; one that held none out was shown on those values only.
    pub held_out: bool,
    /// The program this one repaired, by its `workflow` ref.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<WorkflowSeed>,
    /// When it was filed, or last refiled, as the vault records time.
    pub filed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run_at: Option<u64>,
    /// Its strict runs in a row that missed their postcondition or a
    /// locator: the third retires it `drift`, and a strict run that met it
    /// starts the count again.
    pub strict_misses: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LibraryFindOutput {
    pub site: String,
    pub workflows: Vec<LibraryCard>,
}

/// Takes a program out of the library: no later `open` or `find` lists it,
/// and no run can start it.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LibraryRetireInput {
    pub workflow: String,
    /// Why it leaves; the library keeps it with the retire.
    #[serde(default)]
    pub reason: Option<String>,
}

/// The program a retire took out, as its card read then.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LibraryRetireOutput {
    pub retired: LibraryCard,
}

/// Lists the programs retires took out of the library for a site: `site`
/// (a host, as `www.example.com`), or the open page's.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LibraryRetiredInput {
    #[serde(default)]
    pub site: Option<String>,
}

/// One retired program: the card it had when a retire took it out, when,
/// and why.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RetiredCard {
    pub card: LibraryCard,
    pub retired_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A site's retired programs, the newest retire first.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LibraryRetiredOutput {
    pub site: String,
    pub retired: Vec<RetiredCard>,
}
