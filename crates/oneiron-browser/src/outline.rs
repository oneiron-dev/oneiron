//! The accessibility tree as rows a program reads: a closed set of roles,
//! closed menus collapsed, layout and text-run noise left out, and each row
//! named by a locator built from its role, its name and its named
//! ancestors. Its live handle is minted once the rows are read
//! (`driver::handles`); here the row's `ref` stays empty.
//!
//! A link row's destination (`url`) and a heading row's level (`level`),
//! as the tree names them, ride beside the row, never in it or its locator:
//! the capture joins them to its DOM read (`driver::row_metadata`, FIX
//! 6851), and a settle poll's fingerprint hashes the row's fields as before.
//!
//! A read's secrets (FIX 8028) are found on its rows as the tree names
//! them, then the rows are read again through the read's [`Masks`]: a
//! secret field's value shows its handle, and a name or value that echoes
//! a secret shows the same in its place, before any locator is built. A
//! locator or scope key holds `[secret]` there, never the handle, so it
//! stays as it was however the handle changes.

use crate::secret_fields::{SECRET_MARK, secret_echo_policy};
use crate::{Row, RowSecret};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// Roles a program acts on.
pub(crate) const CONTROLS: &[&str] = &[
    "button",
    "link",
    "textbox",
    "searchbox",
    "combobox",
    "listbox",
    "option",
    "checkbox",
    "radio",
    "switch",
    "slider",
    "spinbutton",
    "menuitem",
    "menuitemcheckbox",
    "menuitemradio",
    "tab",
    "treeitem",
];

/// Roles a program reads but does not act on.
const READS: &[&str] = &[
    "heading",
    "dialog",
    "alertdialog",
    "alert",
    "status",
    "img",
    "StaticText",
];

/// Roles whose name, when they have one, joins the ref of every row inside.
const SCOPES: &[&str] = &[
    "dialog",
    "alertdialog",
    "form",
    "region",
    "navigation",
    "main",
    "banner",
    "contentinfo",
    "complementary",
    "search",
    "list",
    "listitem",
    "row",
    "table",
    "grid",
    "group",
    "radiogroup",
    "menu",
    "menubar",
    "tablist",
    "toolbar",
    "article",
    "tree",
];

const STATES: &[&str] = &[
    "focused", "disabled", "checked", "expanded", "selected", "required", "invalid", "pressed",
];

/// The longest name or text a row carries.
const NAME_CHARS: usize = 200;

/// A row, the DOM node it was read from, and the frame whose document
/// holds it, when the tree names one; with a link row's destination and a
/// heading row's level as the tree names them.
pub(crate) struct Line {
    pub(crate) row: Row,
    pub(crate) backend_node: Option<u64>,
    pub(crate) frame: Option<String>,
    pub(crate) ax_url: Option<String>,
    pub(crate) ax_level: Option<u32>,
    /// The accessibility node the row was read from.
    pub(crate) ax_id: Option<String>,
    /// The row shows a secret in place, its own or one it echoes: a
    /// screenshot masks it.
    pub(crate) masked: bool,
    /// What the page holds where the row shows a secret in place, whole:
    /// never in the row, only for the read's own comparisons.
    pub(crate) original: Option<String>,
}

/// What a read's secrets make of its rows (FIX 8028). Empty, the rows are
/// as the tree names them: a settle poll's, which only a hash reads.
#[derive(Default)]
pub(crate) struct Masks {
    /// Each secret row's own secret, by its accessibility node.
    pub(crate) fields: HashMap<String, Masked>,
    /// Each secret the read found, as its page holds it, with what shows in
    /// its place wherever a name or a value echoes it.
    pub(crate) echoes: Vec<(String, String)>,
}

/// One secret row's secret: what its value shows, none when the secret is
/// the row's own text (its name), and the secret it carries.
pub(crate) struct Masked {
    pub(crate) shown: Option<String>,
    pub(crate) secret: RowSecret,
}

impl Masks {
    pub(crate) fn is_empty(&self) -> bool {
        self.fields.is_empty() && self.echoes.is_empty()
    }
}

/// Whether a row of `role` is a control, whose text the outline folds into
/// its name.
pub(crate) fn is_control(role: &str) -> bool {
    CONTROLS.contains(&role)
}

struct Node<'a> {
    raw: &'a Value,
    role: &'a str,
    /// The name the row shows.
    name: String,
    /// The name its locator and scope key hold, where a secret it echoes
    /// makes it differ from `name`.
    label: Option<String>,
}

impl Node<'_> {
    /// The name the row's locator and its scope's key are built from.
    fn key(&self) -> &str {
        self.label.as_deref().unwrap_or(&self.name)
    }
}

/// Reads `Accessibility.getFullAXTree`'s `nodes` into rows, in page order,
/// each secret in them as `masks` has it.
/// Whether any node of a tree read has a role a row is read from: a tree
/// with none reads as no row.
pub(crate) fn has_rows(nodes: &[Value]) -> bool {
    nodes.iter().any(|node| {
        let role = field(node, "role").unwrap_or("");
        CONTROLS.contains(&role) || READS.contains(&role)
    })
}

/// A loaded page's visible text as a tree of its own (FIX 7717): a root,
/// and each nonblank line of `text` a read-only text node under it, which
/// no DOM node backs, so no act reaches it. Every line is kept; the rows
/// read from it go through the same secret classification as any read.
pub(crate) fn text_nodes(text: &str) -> Vec<Value> {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let ids: Vec<String> = (0..lines.len()).map(|at| format!("text:{at}")).collect();
    let root = serde_json::json!({
        "nodeId": "text:root",
        "role": {"value": "RootWebArea"},
        "childIds": ids,
    });
    std::iter::once(root)
        .chain(lines.iter().zip(&ids).map(|(line, id)| {
            serde_json::json!({
                "nodeId": id,
                "parentId": "text:root",
                "role": {"value": "StaticText"},
                "name": {"value": line},
            })
        }))
        .collect()
}

pub(crate) fn lines(nodes: &[Value], masks: &Masks) -> Vec<Line> {
    let by_id: HashMap<&str, &Value> = nodes
        .iter()
        .filter_map(|n| Some((n.get("nodeId")?.as_str()?, n)))
        .collect();
    let Some(root) = nodes.iter().find(|n| n.get("parentId").is_none()) else {
        return Vec::new();
    };
    let mut walk = Walk {
        by_id: &by_id,
        scope: Vec::new(),
        seen: HashMap::new(),
        out: Vec::new(),
        visited: HashSet::new(),
        masks,
        shown: masks
            .echoes
            .iter()
            .map(|(secret, shown)| (secret.as_str(), shown.as_str()))
            .collect(),
        marks: masks
            .echoes
            .iter()
            .map(|(secret, _)| (secret.as_str(), SECRET_MARK))
            .collect(),
    };
    walk.visit(root, false, None);
    walk.out
}

struct Walk<'a> {
    by_id: &'a HashMap<&'a str, &'a Value>,
    scope: Vec<String>,
    seen: HashMap<String, u32>,
    out: Vec<Line>,
    visited: HashSet<&'a str>,
    masks: &'a Masks,
    /// Each secret with what a row shows in its place, and with what a
    /// locator holds there.
    shown: Vec<(&'a str, &'a str)>,
    marks: Vec<(&'a str, &'a str)>,
}

impl<'a> Walk<'a> {
    /// Visits `raw` and the rows under it. `frame` is the frame of the
    /// nearest node above that named one: a document's nodes are its frame's.
    fn visit(&mut self, raw: &'a Value, in_control: bool, frame: Option<&'a str>) {
        if let Some(id) = raw.get("nodeId").and_then(Value::as_str)
            && !self.visited.insert(id)
        {
            return;
        }
        let frame = raw.get("frameId").and_then(Value::as_str).or(frame);
        let ignored = raw.get("ignored").and_then(Value::as_bool).unwrap_or(false);
        let (name, label) = self.names(field(raw, "name").unwrap_or(""));
        let node = Node {
            raw,
            role: field(raw, "role").unwrap_or(""),
            name,
            label,
        };
        let control = CONTROLS.contains(&node.role);
        let mut scoped = false;
        if !ignored {
            // A control's own text is already its name.
            let read = READS.contains(&node.role)
                && !node.name.is_empty()
                && !(node.role == "StaticText" && in_control);
            if control || read {
                self.emit(&node, frame);
            }
            if SCOPES.contains(&node.role) && !node.name.is_empty() {
                self.scope.push(format!("{} \"{}\"", node.role, node.key()));
                scoped = true;
            }
        }
        // A closed menu, list or tree shows its own row and none of its items.
        if state(raw, "expanded").as_deref() != Some("false") {
            for child in raw
                .get("childIds")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(child) = child.as_str().and_then(|id| self.by_id.get(id)) {
                    self.visit(child, in_control || control, frame);
                }
            }
        }
        if scoped {
            self.scope.pop();
        }
    }

    /// A node's name as its row shows it, and, where a secret it echoes
    /// shows in its place, as its locator holds it.
    fn names(&self, raw: &str) -> (String, Option<String>) {
        match secret_echo_policy(raw, &self.shown) {
            Some(shown) => {
                let label = secret_echo_policy(raw, &self.marks).unwrap_or_default();
                (clip(&shown), Some(clip(&label)))
            }
            None => (clip(raw), None),
        }
    }

    fn emit(&mut self, node: &Node<'_>, frame: Option<&str>) {
        let mut key = self.scope.join(" > ");
        key.push_str(&format!(" > {} \"{}\"", node.role, node.key()));
        // Identical twins (same role, name and named ancestors) are told apart
        // by their order among themselves alone.
        let twin = self.seen.entry(key.clone()).or_insert(0);
        *twin += 1;
        if *twin > 1 {
            key.push_str(&format!(" ~{twin}"));
        }
        let hash = blake3::hash(key.as_bytes()).to_hex();
        let states = STATES
            .iter()
            .filter_map(|&name| match state(node.raw, name).as_deref() {
                None | Some("false") => None,
                Some("true") => Some(name.to_owned()),
                Some(other) => Some(format!("{name}={other}")),
            })
            .collect();
        let ax_id = node.raw.get("nodeId").and_then(Value::as_str);
        let raw_value = field(node.raw, "value").filter(|v| !v.is_empty());
        let own = ax_id.and_then(|id| self.masks.fields.get(id));
        let (value, secret, echoed) = match own {
            Some(masked) => (masked.shown.clone(), Some(masked.secret.clone()), false),
            None => match raw_value.and_then(|raw| secret_echo_policy(raw, &self.shown)) {
                Some(shown) => (Some(clip(&shown)), None, true),
                None => (raw_value.map(clip), None, false),
            },
        };
        let masked = secret.is_some() || echoed || node.label.is_some();
        // A secret that is the row's own text is its name, as the page
        // holds it.
        let original = match own {
            _ if !masked => None,
            Some(own) if own.shown.is_none() => field(node.raw, "name").map(str::to_owned),
            _ => raw_value.map(str::to_owned),
        };
        let row = Row {
            target: String::new(),
            locator: format!("e{}", &hash[..12]),
            role: node.role.to_owned(),
            name: node.name.clone(),
            value,
            states,
            depth: u16::try_from(self.scope.len()).unwrap_or(u16::MAX),
            href: None,
            level: None,
            datetimes: Vec::new(),
            unavailable: Vec::new(),
            secret,
        };
        let backend_node = node.raw.get("backendDOMNodeId").and_then(Value::as_u64);
        // Only a link's `url` is its destination and only a heading's
        // `level` its rank: a document, an image or a list item names
        // its own. Chromium writes the level as a number, Lightpanda as a
        // decimal string.
        let ax_url = (node.role == "link")
            .then(|| state(node.raw, "url"))
            .flatten()
            .filter(|url| !url.is_empty());
        let ax_level = (node.role == "heading")
            .then(|| state(node.raw, "level"))
            .flatten()
            .and_then(|level| level.trim().parse::<u32>().ok())
            .filter(|level| *level > 0);
        self.out.push(Line {
            row,
            backend_node,
            frame: frame.map(str::to_owned),
            ax_url,
            ax_level,
            ax_id: ax_id.map(str::to_owned),
            masked,
            original,
        });
    }
}

/// An accessibility node's `name`, `value`, `description` or `role` text,
/// as the tree names it.
pub(crate) fn field<'v>(node: &'v Value, name: &str) -> Option<&'v str> {
    node.get(name)?.get("value")?.as_str()
}

/// Whether the tree marks the node `protected`, as it marks a concealed
/// field's.
pub(crate) fn protected(node: &Value) -> bool {
    state(node, "protected").as_deref() == Some("true")
}

/// Whether a row of `role` reads text, whose text is its name.
pub(crate) fn is_read(role: &str) -> bool {
    READS.contains(&role)
}

fn state(node: &Value, name: &str) -> Option<String> {
    let property = node
        .get("properties")?
        .as_array()?
        .iter()
        .find(|p| p.get("name").and_then(Value::as_str) == Some(name))?;
    match property.get("value")?.get("value")? {
        Value::String(text) => Some(text.clone()),
        other => Some(other.to_string()),
    }
}

pub(crate) fn clip(text: &str) -> String {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    match text.char_indices().nth(NAME_CHARS) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text,
    }
}
