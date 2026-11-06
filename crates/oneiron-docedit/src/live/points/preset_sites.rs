//! Source-defined preset sites retained when Edit Points makes a freeform.
use crate::edit::xml::{self, A};
use crate::ooxml::XmlTree;
use std::collections::BTreeSet;

mod data;

struct Preset {
    name: &'static str,
    adjustments: &'static [(&'static str, &'static str)],
    guides: &'static str,
    connections: &'static str,
    names: &'static [&'static str],
}

pub(super) struct Kept {
    pub(super) adjustments: String,
    pub(super) guides: &'static str,
    pub(super) connections: &'static str,
    pub(super) names: BTreeSet<String>,
}

/// Defaults and instance adjustments share their names; the first instance
/// entry wins, as it did while the shape still used the preset.
pub(super) fn kept(tree: &XmlTree, preset: usize) -> Option<Kept> {
    let name = tree.nodes[preset].attr("prst")?;
    let definition = data::PRESETS.iter().find(|entry| entry.name == name)?;
    if definition.connections.is_empty() {
        return None;
    }
    let overrides: Vec<(&str, &str)> = xml::child(tree, preset, A, "avLst")
        .into_iter()
        .flat_map(|list| tree.nodes[list].children.iter().copied())
        .filter(|&at| tree.nodes[at].is(A, "gd"))
        .filter_map(|at| Some((tree.nodes[at].attr("name")?, tree.nodes[at].attr("fmla")?)))
        .collect();
    let mut emitted = BTreeSet::new();
    let mut adjustments = String::new();
    for &(name, default) in definition.adjustments {
        let formula = overrides
            .iter()
            .find_map(|&(held, formula)| (held == name).then_some(formula))
            .unwrap_or(default);
        adjustments.push_str(&guide(name, formula));
        emitted.insert(name);
    }
    for &(name, formula) in &overrides {
        if emitted.insert(name) {
            adjustments.push_str(&guide(name, formula));
        }
    }
    let mut names: BTreeSet<String> = definition
        .names
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    names.extend(overrides.iter().map(|&(name, _)| name.to_owned()));
    Some(Kept {
        adjustments,
        guides: definition.guides,
        connections: definition.connections,
        names,
    })
}

fn guide(name: &str, formula: &str) -> String {
    format!(
        r#"<a:gd name="{}" fmla="{}"/>"#,
        xml::escape_attribute(name),
        xml::escape_attribute(formula),
    )
}
