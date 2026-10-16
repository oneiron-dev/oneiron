//! The animation and connector index. It reports which timing, build and
//! connector entries name a shape; it never cascades or rewrites them.
use super::graph::{A, P, child, descendants, path};
use super::{RetainedNode, ShapeKind, ShapeView};
use crate::ooxml::XmlTree;

/// Build elements that name a shape by `spid`.
const BUILDS: [&str; 4] = ["bldP", "bldGraphic", "bldDgm", "bldOleChart"];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnimationIndex {
    pub targets: Vec<AnimationTarget>,
    /// Every `p:cTn/@id` in the slide's timing tree.
    pub timing_ids: Vec<u32>,
    /// `(cNvPr id, name)` of shapes whose name starts with `!!` (Morph).
    pub morph_names: Vec<(Option<u32>, String)>,
    pub connections: Vec<Connection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnimationTarget {
    /// The `spid` named.
    pub shape: u32,
    pub role: TargetRole,
    /// `p:txEl` paragraph or character range, when the target is text.
    pub text: Option<TextRange>,
    /// The nearest enclosing `p:cTn/@id`.
    pub timing_id: Option<u32>,
    pub node: RetainedNode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetRole {
    /// `p:spTgt` an effect acts on.
    Effect,
    /// `p:spTgt` inside a trigger condition.
    Condition,
    /// A build list entry (`p:bldP` and kin).
    Build,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextRange {
    Paragraphs { start: u32, end: u32 },
    Characters { start: u32, end: u32 },
}

/// A connector's `a:stCxn`/`a:endCxn` shape ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub connector: Option<u32>,
    pub start: Option<u32>,
    pub end: Option<u32>,
}

impl AnimationIndex {
    /// Every timing, condition and build entry naming `shape`.
    pub fn targets_of(&self, shape: u32) -> impl Iterator<Item = &AnimationTarget> {
        self.targets
            .iter()
            .filter(move |target| target.shape == shape)
    }

    /// Connectors glued to `shape` at either end.
    pub fn connections_to(&self, shape: u32) -> impl Iterator<Item = &Connection> {
        self.connections
            .iter()
            .filter(move |cxn| cxn.start == Some(shape) || cxn.end == Some(shape))
    }
}

pub(super) fn index(part: &str, tree: &XmlTree, shapes: &[ShapeView]) -> AnimationIndex {
    let mut index = AnimationIndex::default();
    for shape in shapes {
        if let Some(name) = shape.name.as_deref().filter(|name| name.starts_with("!!")) {
            index.morph_names.push((shape.id, name.to_owned()));
        }
        if shape.kind == ShapeKind::Connector {
            let ends = path(
                tree,
                shape.node.index,
                &[(P, "nvCxnSpPr"), (P, "cNvCxnSpPr")],
            );
            let end = |name| {
                ends.and_then(|at| child(tree, at, A, name))
                    .and_then(|at| tree.nodes[at].attr("id"))
                    .and_then(|id| id.parse().ok())
            };
            index.connections.push(Connection {
                connector: shape.id,
                start: end("stCxn"),
                end: end("endCxn"),
            });
        }
    }
    let Some(timing) = child(tree, 0, P, "timing") else {
        return index;
    };
    for at in descendants(tree, timing) {
        let node = &tree.nodes[at];
        if node.namespace != P {
            continue;
        }
        if node.name == "cTn"
            && let Some(id) = node.attr("id").and_then(|id| id.parse().ok())
        {
            index.timing_ids.push(id);
        }
        let role = if node.name == "spTgt" {
            if ancestors(tree, at).any(|up| tree.nodes[up].is(P, "cond")) {
                TargetRole::Condition
            } else {
                TargetRole::Effect
            }
        } else if BUILDS.contains(&node.name.as_str()) {
            TargetRole::Build
        } else {
            continue;
        };
        let Some(shape) = node.attr("spid").and_then(|id| id.parse().ok()) else {
            continue;
        };
        index.targets.push(AnimationTarget {
            shape,
            role,
            text: text_range(tree, at),
            timing_id: ancestors(tree, at)
                .find(|&up| tree.nodes[up].is(P, "cTn"))
                .and_then(|up| tree.nodes[up].attr("id"))
                .and_then(|id| id.parse().ok()),
            node: RetainedNode {
                part: part.to_owned(),
                index: at,
            },
        });
    }
    index
}

fn ancestors(tree: &XmlTree, at: usize) -> impl Iterator<Item = usize> + '_ {
    std::iter::successors(tree.nodes[at].parent, |&up| tree.nodes[up].parent)
}

fn text_range(tree: &XmlTree, target: usize) -> Option<TextRange> {
    let element = child(tree, target, P, "txEl")?;
    let (at, paragraphs) = match child(tree, element, P, "pRg") {
        Some(at) => (at, true),
        None => (child(tree, element, P, "charRg")?, false),
    };
    let read = |name| tree.nodes[at].attr(name).and_then(|v| v.parse().ok());
    let (start, end) = (read("st")?, read("end")?);
    Some(if paragraphs {
        TextRange::Paragraphs { start, end }
    } else {
        TextRange::Characters { start, end }
    })
}
