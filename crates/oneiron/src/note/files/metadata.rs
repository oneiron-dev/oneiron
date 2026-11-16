//! What a Files source knows of each file besides its text (FIX 6942): the
//! formats it takes text from, why a file is held by its name only, and the
//! facts of the revision the ledger took.

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

#[doc(hidden)]
pub use oneiron_verb_wire::note::files::metadata::{FileReadiness, NameOnlyReason};

#[doc(hidden)]
pub use oneiron_records::note::files::metadata::{FileFacts, FileMeta};

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
