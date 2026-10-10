//! The whole vault as a read-only file tree (OF-355, ARCH-0051), read as its
//! owner. A path is a lazy query: `/worlds`, `/entities`, `/claims` and
//! `/backlinks` cost nothing until walked. Reads go through the owner's
//! scoped read, so owner-excluded scopes are absent; every listing and
//! search is bounded and pages by cursor, so no call dumps the vault. Nothing
//! here writes.

use oneiron::Vault;
use oneiron::claim::ScopedReadActorKey;
use oneiron::graph_fs::{GraphFsCommandOutput, GraphFsCoreutilsDecision, GraphFsOptions};
use serde::{Deserialize, Serialize};

use super::{OwnerError, OwnerResult};

/// Lines `head` prints when the request names none.
const HEAD_LINES: usize = 10;

/// One command over the tree.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Command {
    #[default]
    Ls,
    Cat,
    Head,
    Wc,
    Find,
    Grep,
    Readlink,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GraphFsQuery {
    /// An absolute path, such as `/entities` or `/claims/by-time`.
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) op: Command,
    /// The `next_cursor` of the previous page.
    #[serde(default)]
    pub(crate) cursor: Option<String>,
    /// `grep`: the text to find.
    #[serde(default)]
    pub(crate) pattern: Option<String>,
    /// `grep`: search below `path` too.
    #[serde(default)]
    pub(crate) recursive: bool,
    /// `ls`: newest first.
    #[serde(default)]
    pub(crate) by_time: bool,
    /// `find`: only what changed after this Unix second.
    #[serde(default)]
    pub(crate) newer_than: Option<u64>,
    /// `head`: how many lines.
    #[serde(default)]
    pub(crate) lines: Option<usize>,
}

/// What a command printed.
#[derive(Debug, Serialize)]
pub(crate) struct GraphFsReply {
    pub(crate) path: String,
    /// The command's output, as a shell would print it, in `encoding`.
    pub(crate) output: String,
    /// `utf8` when the output is text, as it is; `base64` (standard, padded)
    /// when it holds bytes that are not, such as a MessagePack body. Decoding
    /// each page by its own encoding and joining them gives the stored bytes.
    pub(crate) encoding: &'static str,
    /// Send this back as `cursor` for the next page; absent on the last.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) next_cursor: Option<String>,
    /// `pushdown` when an index answered, `walk` when the tree was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) plan: Option<&'static str>,
}

pub(crate) fn run(
    vault: &Vault,
    reader: ScopedReadActorKey,
    query: &GraphFsQuery,
) -> OwnerResult<GraphFsReply> {
    let scoped = vault.scoped_read(reader);
    let tree = scoped.graph_fs(GraphFsOptions::default());
    let path = query.path.as_str();
    let cursor = query.cursor.as_deref();
    let output = match query.op {
        Command::Ls => tree.ls(path, query.by_time, cursor)?,
        Command::Cat => tree.cat(path, cursor)?,
        Command::Head => tree.head(path, query.lines.unwrap_or(HEAD_LINES), cursor)?,
        Command::Wc => tree.wc(path)?,
        Command::Find => tree.find(path, query.newer_than, cursor)?,
        Command::Grep => {
            let pattern = query
                .pattern
                .as_deref()
                .filter(|pattern| !pattern.is_empty())
                .ok_or_else(|| OwnerError::Invalid("grep needs a `pattern`".to_owned()))?;
            tree.grep(pattern, path, query.recursive, cursor)?
        }
        Command::Readlink => {
            let target = tree
                .read_link(path)?
                .ok_or_else(|| OwnerError::NotFound("link", path.to_owned()))?;
            return Ok(GraphFsReply {
                path: path.to_owned(),
                output: target,
                encoding: "utf8",
                next_cursor: None,
                plan: None,
            });
        }
    };
    Ok(reply(path, output))
}

fn reply(path: &str, output: GraphFsCommandOutput) -> GraphFsReply {
    let plan = match output.decision() {
        GraphFsCoreutilsDecision::Pushdown => "pushdown",
        GraphFsCoreutilsDecision::Walk => "walk",
    };
    let next_cursor = output.next_cursor().map(str::to_owned);
    let (output, encoding) = match String::from_utf8(output.into_bytes()) {
        Ok(text) => (text, "utf8"),
        Err(bytes) => {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD.encode(bytes.into_bytes());
            (encoded, "base64")
        }
    };
    GraphFsReply {
        path: path.to_owned(),
        output,
        encoding,
        next_cursor,
        plan: Some(plan),
    }
}
