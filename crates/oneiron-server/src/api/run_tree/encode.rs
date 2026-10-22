//! The run tree's JSON, written on a heap stack (FIX 10067). Each node is
//! projected flat and serialized alone through its derived encoding, and its
//! children are written into its own `children` array, so a deep tree never
//! deepens the call stack. The bytes are the ones the derived nested
//! encoding writes; no depth or count limits the tree.

use axum::http::header;
use axum::response::{IntoResponse, Response};
use serde::ser::Error as _;

use super::CoreRunTreeInterventionResponse;
use super::projection::{core_run_tree_node, core_run_tree_shell};

/// The response's opening with no roots, as its derived encoding writes it.
const EMPTY_ROOTS: &str = "{\"roots\":[]";
/// A flat node's closing: its `children` field, last, empty.
const EMPTY_CHILDREN_CLOSE: &str = "[]}";
/// An intervention response's closing with no snapshot: `tree`, last, null.
const NO_TREE_CLOSE: &str = "null}";

/// A JSON body already written, served as `application/json`.
pub(super) fn raw_json(body: String) -> Response {
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// The core run-tree response for `tree`: `{"roots":[...],"repairs":[...]}`.
pub(super) fn run_tree_json(tree: oneiron::RunTree) -> serde_json::Result<String> {
    let oneiron::RunTree { roots, repairs } = tree;
    let shell = serde_json::to_string(&core_run_tree_shell(repairs))?;
    let rest = shell
        .strip_prefix(EMPTY_ROOTS)
        .ok_or_else(|| shape_error("response"))?;
    let mut out = String::from("{\"roots\":[");
    write_nodes(&mut out, roots)?;
    out.push(']');
    out.push_str(rest);
    Ok(out)
}

/// An intervention response with `tree`, its fresh snapshot, when it has
/// one, written into its `tree` field.
pub(super) fn intervention_json(
    mut response: CoreRunTreeInterventionResponse,
    tree: Option<oneiron::RunTree>,
) -> serde_json::Result<String> {
    response.tree = None;
    let shell = serde_json::to_string(&response)?;
    let Some(tree) = tree else {
        return Ok(shell);
    };
    let open = shell
        .strip_suffix(NO_TREE_CLOSE)
        .ok_or_else(|| shape_error("intervention response"))?;
    let mut out = open.to_owned();
    out.push_str(&run_tree_json(tree)?);
    out.push('}');
    Ok(out)
}

/// Writes `roots` and their subtrees, comma-separated, in order: each node's
/// own fields, then its children inside its `children` array.
fn write_nodes(out: &mut String, roots: Vec<oneiron::RunTreeNode>) -> serde_json::Result<()> {
    // One level per open node, the outermost the roots: the siblings left to
    // write and whether none has been written yet.
    let mut levels = vec![(roots.into_iter(), true)];
    while let Some((siblings, first)) = levels.last_mut() {
        let Some(mut node) = siblings.next() else {
            levels.pop();
            if !levels.is_empty() {
                // Closes the open node's `children` array and the node.
                out.push_str("]}");
            }
            continue;
        };
        if !std::mem::replace(first, false) {
            out.push(',');
        }
        let children = std::mem::take(&mut node.children);
        let flat = serde_json::to_string(&core_run_tree_node(&mut node))?;
        let open = flat
            .strip_suffix(EMPTY_CHILDREN_CLOSE)
            .ok_or_else(|| shape_error("node"))?;
        out.push_str(open);
        out.push('[');
        levels.push((children.into_iter(), true));
    }
    Ok(())
}

/// A projection whose derived encoding no longer ends or starts where the
/// splice expects: a code fault, never a property of the tree.
fn shape_error(what: &str) -> serde_json::Error {
    serde_json::Error::custom(format!(
        "the run tree {what} did not encode in its derived shape"
    ))
}
