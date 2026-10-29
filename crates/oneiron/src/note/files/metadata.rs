//! What a Files source knows of each file besides its text (FIX 6942): the
//! formats it takes text from, why a file is held by its name only, and the
//! facts of the revision the ledger took.

use serde::{Deserialize, Serialize};

use super::super::folder_source::OriginalBytes;

/// The extensions, any case, whose files are UTF-8 text a Files source
/// takes whole: plain text, markup, data and code. Markdown (`md`) and PDF
/// (its text layer) are read as an attached folder reads them. Every other
/// file is held by its name only. Code is text here and never runs.
pub const FILES_TEXT_EXTENSIONS: &[&str] = &[
    "txt",
    "text",
    "markdown",
    "mdx",
    "rst",
    "adoc",
    "org",
    "tex",
    "csv",
    "tsv",
    "json",
    "jsonl",
    "yaml",
    "yml",
    "toml",
    "ini",
    "cfg",
    "conf",
    "xml",
    "html",
    "htm",
    "css",
    "scss",
    "sass",
    "less",
    "svg",
    "log",
    "rs",
    "py",
    "js",
    "mjs",
    "cjs",
    "ts",
    "tsx",
    "jsx",
    "go",
    "java",
    "kt",
    "kts",
    "swift",
    "c",
    "h",
    "cc",
    "cpp",
    "cxx",
    "hpp",
    "hh",
    "m",
    "mm",
    "cs",
    "rb",
    "php",
    "pl",
    "pm",
    "lua",
    "r",
    "jl",
    "scala",
    "sh",
    "bash",
    "zsh",
    "fish",
    "ps1",
    "sql",
    "graphql",
    "gql",
    "proto",
    "vue",
    "svelte",
    "dart",
    "ex",
    "exs",
    "erl",
    "hs",
    "ml",
    "mli",
    "clj",
    "cljs",
    "el",
    "vim",
    "nix",
    "zig",
    "gradle",
    "cmake",
    "mk",
    "tf",
    "dockerfile",
];

/// Why a file has no text in the vault: it is held by its name, and
/// never as text it does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NameOnlyReason {
    /// A format the source takes no text from.
    Unsupported,
    /// Named as text, but its bytes are not UTF-8 text.
    NotText,
    /// Its bytes could not be read, or a PDF that is encrypted or does not
    /// parse.
    Unreadable,
    /// No text: blank, or a PDF with no text layer.
    Empty,
    /// It has another name (a hard link), which may be outside the folder:
    /// its bytes are not read.
    Linked,
}

/// Whether the vault holds a file's text, or its name only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileReadiness {
    /// Its text landed as a NOTE (or as its parts).
    Text,
    /// Held by its name only.
    NameOnly { why: NameOnlyReason },
}

/// What the host read of a file, beside its text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileFacts {
    pub bytes: u64,
    /// When the file was last written (seconds).
    pub modified_at: u64,
}

/// What the ledger keeps of a Files source's file: the facts of the
/// revision it took, when it first saw the file and when it last took the
/// file's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMeta {
    pub bytes: u64,
    pub modified_at: u64,
    pub first_seen_at: u64,
    /// When the vault last took the file's text; none while it holds the
    /// file by name only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub indexed_at: Option<u64>,
}

impl FileMeta {
    /// The meta of a file first seen `at`, whose text the vault took at
    /// `indexed_at`.
    pub(crate) fn first(facts: FileFacts, at: u64, indexed_at: Option<u64>) -> Self {
        Self {
            bytes: facts.bytes,
            modified_at: facts.modified_at,
            first_seen_at: at,
            indexed_at,
        }
    }

    /// This meta on the revision `facts` names, whose text the vault took
    /// at `indexed_at`.
    pub(crate) fn moved(self, facts: FileFacts, indexed_at: Option<u64>) -> Self {
        Self {
            bytes: facts.bytes,
            modified_at: facts.modified_at,
            first_seen_at: self.first_seen_at,
            indexed_at,
        }
    }
}

/// One file the host holds by name only: its path under the folder,
/// why, and its facts. A file whose bytes the walk read carries them, kept
/// as its original once its ledger row lands (FIX 11276); one whose bytes
/// were never read carries none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameOnlyFile {
    pub path: String,
    pub why: NameOnlyReason,
    pub facts: FileFacts,
    pub original: Option<OriginalBytes>,
}
