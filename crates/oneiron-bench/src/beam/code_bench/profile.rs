//! Each CODE-BENCH arm is a fixed tool profile plus the pieces it needs.
//! Canon (ARCH-0042 #code-bench): "A missing piece marks that arm not
//! ready; nothing is faked."

use serde::{Deserialize, Serialize};

/// One arm of ARCH-0042's table. The same model, harness and cap hold in
/// every arm; only the tools differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Arm {
    /// File reads, edits, the shell and the codemap; no Oneiron memory.
    NoMemory,
    /// `no_memory` plus one dev vault's memory tools.
    VaultMemory,
    /// File reads, edits and the shell, grep included; no MCP tools.
    GrepOnly,
    /// File reads, edits and the shell plus symbol and graph reads over a
    /// code snapshot; grep is off.
    SymbolGraph,
    /// Three writers on one shared Oneiron work: fork, proposal, merge queue.
    OneironWriters,
    /// Three writers, each in a Git worktree, merged by plain Git.
    GitWorktrees,
}

/// The check an arm belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Check {
    Memory,
    Navigation,
    Collaboration,
}

/// A piece an arm needs before it can run, supplied by the run plan or
/// found in the task's world.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Piece {
    /// `docs/codemap/` in the task's world.
    Codemap,
    /// The MCP server of one dev vault seeded through the cut.
    MemoryVault,
    /// The MCP server holding a code snapshot of the task's base.
    CodeSnapshot,
    /// The MCP server of an Oneiron that serves the shared work path.
    OneironCodePath,
}

/// MCP server names, as `mcp.json` names them and a transcript's tool names
/// carry them (`mcp__<server>__<tool>`).
pub(super) const MEMORY_SERVER: &str = "oneiron-memory";
pub(super) const CODE_SERVER: &str = "oneiron-code";
pub(super) const WORK_SERVER: &str = "oneiron-work";

/// The Claude Code tools every arm has: file reads, edits and the shell.
const BASE_TOOLS: [&str; 5] = ["Read", "Edit", "Write", "Bash", "Glob"];
/// Denied in every arm: the merged PR and its tests are on the network.
const NETWORK_DENIED: [&str; 8] = [
    "WebFetch",
    "WebSearch",
    "Bash(gh:*)",
    "Bash(curl:*)",
    "Bash(wget:*)",
    "Bash(git fetch:*)",
    "Bash(git pull:*)",
    "Bash(git clone:*)",
];
/// Denied in `symbol_graph`: the arm reads by symbol and graph, not by text.
const GREP_DENIED: [&str; 4] = ["Grep", "Bash(grep:*)", "Bash(rg:*)", "Bash(git grep:*)"];

/// The code snapshot's reads (`scripts/sdk/verbs/<name>.json`).
const SYMBOL_GRAPH_VERBS: [&str; 11] = [
    "self.code.symbols.definitions",
    "self.code.symbols.neighbors",
    "graph_fs.cat",
    "graph_fs.find",
    "graph_fs.grep",
    "graph_fs.head",
    "graph_fs.ls",
    "graph_fs.read_file",
    "graph_fs.read_link",
    "graph_fs.readdir",
    "graph_fs.wc",
];
/// The shared work path and the checkout rows it leads to.
const ONEIRON_WRITER_VERBS: [&str; 13] = [
    "self.code.work.open",
    "self.code.proposal_submit",
    "self.code.merge_queue.enqueue",
    "vault.code.checkout.bind",
    "vault.code.checkout.claim",
    "vault.code.checkout.get",
    "vault.code.checkout.holder.bind",
    "vault.code.checkout.publish",
    "vault.code.checkout.reclaim",
    "vault.code.checkout.renew",
    "vault.code.checkout.settle",
    "vault.code.checkout.takeover",
    "vault.code.checkout.teardown",
];
/// The memory server's tools: the native read table's `memory.` methods and
/// the `self.memory.` rows.
const MEMORY_TOOL_PREFIXES: [&str; 2] = ["memory.", "self.memory."];

impl Arm {
    pub(super) const ALL: [Self; 6] = [
        Self::NoMemory,
        Self::VaultMemory,
        Self::GrepOnly,
        Self::SymbolGraph,
        Self::OneironWriters,
        Self::GitWorktrees,
    ];

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::NoMemory => "no_memory",
            Self::VaultMemory => "vault_memory",
            Self::GrepOnly => "grep_only",
            Self::SymbolGraph => "symbol_graph",
            Self::OneironWriters => "oneiron_writers",
            Self::GitWorktrees => "git_worktrees",
        }
    }

    /// The check whose table row names this arm. `no_memory` is also the
    /// navigation check's third arm, run once and shared.
    pub(super) const fn check(self) -> Check {
        match self {
            Self::NoMemory | Self::VaultMemory => Check::Memory,
            Self::GrepOnly | Self::SymbolGraph => Check::Navigation,
            Self::OneironWriters | Self::GitWorktrees => Check::Collaboration,
        }
    }

    pub(super) const fn pieces(self) -> &'static [Piece] {
        match self {
            Self::NoMemory => &[Piece::Codemap],
            Self::VaultMemory => &[Piece::Codemap, Piece::MemoryVault],
            Self::GrepOnly | Self::GitWorktrees => &[],
            Self::SymbolGraph => &[Piece::CodeSnapshot],
            Self::OneironWriters => &[Piece::OneironCodePath],
        }
    }

    /// The verb rows the arm calls, each checked at the serving engine's
    /// commit before the arm is ready.
    pub(super) const fn verbs(self) -> &'static [&'static str] {
        match self {
            Self::SymbolGraph => &SYMBOL_GRAPH_VERBS,
            Self::OneironWriters => &ONEIRON_WRITER_VERBS,
            Self::NoMemory | Self::VaultMemory | Self::GrepOnly | Self::GitWorktrees => &[],
        }
    }

    /// Tool-name prefixes the arm may call on its MCP server, beside its
    /// exact verbs.
    pub(super) const fn tool_prefixes(self) -> &'static [&'static str] {
        match self {
            Self::VaultMemory => &MEMORY_TOOL_PREFIXES,
            _ => &[],
        }
    }

    /// The MCP server the arm talks to, if any.
    pub(super) const fn server(self) -> Option<&'static str> {
        match self {
            Self::VaultMemory => Some(MEMORY_SERVER),
            Self::SymbolGraph => Some(CODE_SERVER),
            Self::OneironWriters => Some(WORK_SERVER),
            Self::NoMemory | Self::GrepOnly | Self::GitWorktrees => None,
        }
    }

    /// Claude Code's `permissions.allow` for the arm.
    pub(super) fn allowed_tools(self) -> Vec<String> {
        let mut tools = Vec::from(BASE_TOOLS.map(String::from));
        if self != Self::SymbolGraph {
            tools.push("Grep".to_owned());
        }
        if let Some(server) = self.server() {
            tools.push(format!("mcp__{server}"));
        }
        tools
    }

    /// Claude Code's `permissions.deny` for the arm.
    pub(super) fn denied_tools(self) -> Vec<String> {
        let mut tools = Vec::from(NETWORK_DENIED.map(String::from));
        if self == Self::SymbolGraph {
            tools.extend(GREP_DENIED.map(String::from));
        }
        tools
    }

    /// The arm's rules, as the writer's prompt states them.
    pub(super) fn rules(self) -> String {
        let verbs = self.verbs().join(", ");
        match self {
            Self::NoMemory => "Tools: file reads, edits and the shell. The codemap is in \
                               `docs/codemap/` of your tree. There is no Oneiron memory."
                .to_owned(),
            Self::VaultMemory => format!(
                "Tools: file reads, edits and the shell, plus the memory tools of the \
                 `{MEMORY_SERVER}` MCP server (tool names starting `memory.` or \
                 `self.memory.`): it holds our engine work records up to the cut. The \
                 codemap is in `docs/codemap/` of your tree."
            ),
            Self::GrepOnly => "Tools: file reads, edits and the shell, grep and rg included. \
                               There are no MCP tools."
                .to_owned(),
            Self::SymbolGraph => format!(
                "Tools: file reads, edits and the shell, plus these reads of the \
                 `{CODE_SERVER}` MCP server over a snapshot of your tree: {verbs}. The Grep \
                 tool and shell grep, rg and git grep are off."
            ),
            Self::OneironWriters => format!(
                "Tools: file reads, edits and the shell, plus the `{WORK_SERVER}` MCP server: \
                 {verbs}. Open the shared work with self.code.work.open, submit your part \
                 with self.code.proposal_submit and queue it with \
                 self.code.merge_queue.enqueue. Do not merge with plain Git."
            ),
            Self::GitWorktrees => "Tools: file reads, edits and the shell. Your tree is a Git \
                                   worktree on your own branch. Commit your part there, then \
                                   merge it into the shared branch `integration` with plain \
                                   Git, resolving any conflict with the other writers' parts."
                .to_owned(),
        }
    }
}

impl Check {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Navigation => "navigation",
            Self::Collaboration => "collaboration",
        }
    }
}

impl Piece {
    /// The name a not-ready reason and the run plan use.
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Codemap => "codemap",
            Self::MemoryVault => "memory_vault",
            Self::CodeSnapshot => "code_snapshot",
            Self::OneironCodePath => "oneiron_code_path",
        }
    }
}
