//! `set_preset` and `set_glue`: a shape's or connector's preset geometry,
//! and a connector's glue. Adjust values belong to the preset they were
//! written for, so a preset change writes an empty `a:avLst`; custom
//! geometry takes no preset.
use super::check::Declared;
use super::xml::{self, A, P};
use super::{ConnectorPreset, EditRefusal, FitUnverified, Preset, Written};
use crate::deck::{ShapeKind, ShapeView, SlideView};
use crate::retained_opc::Package;

/// The path from a shape or connector element to its preset geometry.
pub(super) const PRESET: &[(&str, &str)] = &[(P, "spPr"), (A, "prstGeom")];
/// The path from a connector element to the element holding its glue.
pub(super) const GLUE: &[(&str, &str)] = &[(P, "nvCxnSpPr"), (P, "cNvCxnSpPr")];

fn written(slide: &SlideView, id: u32, path: super::check::Path) -> Written {
    Written {
        allowed: vec![slide.part.clone()],
        declared: vec![Declared::element(&slide.part, Some(id), path)],
        relationships: Vec::new(),
        created: Vec::new(),
        effects: Vec::new(),
        fit: None,
    }
}

pub(super) fn set_preset(
    next: &mut Package,
    slide: &SlideView,
    shape: &ShapeView,
    preset: &str,
) -> Result<Written, EditRefusal> {
    let id = shape.id.ok_or(EditRefusal::Missing("shape id"))?;
    let known = match shape.kind {
        ShapeKind::Shape => Preset::from_name(preset).is_some(),
        ShapeKind::Connector => ConnectorPreset::from_name(preset).is_some(),
        _ => {
            return Err(EditRefusal::Invalid(
                "only a shape or a connector takes a preset",
            ));
        }
    };
    if !known {
        return Err(EditRefusal::Invalid(
            "the preset is outside the written set",
        ));
    }
    let (bytes, tree) = xml::read(next, &slide.part)?;
    let at = xml::path(&tree, shape.node.index, PRESET)
        .ok_or(EditRefusal::Invalid("custom geometry takes no preset"))?;
    let node = &tree.nodes[at];
    let prefix = xml::prefix(node);
    let element = format!(
        r#"<{geom} prst="{preset}"><{list}/></{geom}>"#,
        geom = xml::qualify(prefix, "prstGeom"),
        list = xml::qualify(prefix, "avLst"),
    );
    next.replace_xml_part(
        &slide.part,
        xml::splice(&bytes, vec![(node.span.clone(), element.into_bytes())])?,
    )?;
    let mut out = written(slide, id, PRESET);
    // The preset's text rectangle is the text's frame.
    out.fit = shape.text.is_some().then(|| FitUnverified {
        part: slide.part.clone(),
        shape: id,
    });
    Ok(out)
}

/// Each end the native id of a shape on the slide and its connection site,
/// or free.
pub(super) fn set_glue(
    next: &mut Package,
    slide: &SlideView,
    shape: &ShapeView,
    start: Option<(u32, u32)>,
    end: Option<(u32, u32)>,
) -> Result<Written, EditRefusal> {
    let id = shape.id.ok_or(EditRefusal::Missing("shape id"))?;
    if shape.kind != ShapeKind::Connector {
        return Err(EditRefusal::Invalid("only a connector is glued"));
    }
    for (glued, _) in start.iter().chain(end.iter()) {
        if !slide
            .shapes
            .iter()
            .any(|held| held.id == Some(*glued) && held.kind != ShapeKind::Group)
        {
            return Err(EditRefusal::Missing("connector end shape"));
        }
    }
    let (bytes, tree) = xml::read(next, &slide.part)?;
    let at = xml::path(&tree, shape.node.index, GLUE)
        .ok_or(EditRefusal::Missing("connector properties"))?;
    let node = &tree.nodes[at];
    let kept = |name: &str| {
        xml::child(&tree, at, A, name).map(|child| bytes[tree.nodes[child].span.clone()].to_vec())
    };
    // CT_NonVisualConnectorProperties: locks, start, end, extensions.
    let mut element = xml::open_tag(&bytes, node);
    element.extend(kept("cxnSpLocks").unwrap_or_default());
    for (local, glue) in [("stCxn", start), ("endCxn", end)] {
        if let Some((glued, site)) = glue {
            element.extend(
                format!(r#"<a:{local} xmlns:a="{A}" id="{glued}" idx="{site}"/>"#).into_bytes(),
            );
        }
    }
    element.extend(kept("extLst").unwrap_or_default());
    element.extend(format!("</{}>", node.qualified).into_bytes());
    next.replace_xml_part(
        &slide.part,
        xml::splice(&bytes, vec![(node.span.clone(), element)])?,
    )?;
    Ok(written(slide, id, GLUE))
}

/// A connector's glue as written: each end's shape id and site.
pub(crate) fn glue_of(
    tree: &crate::ooxml::XmlTree,
    connector: usize,
) -> (Option<(u32, u32)>, Option<(u32, u32)>) {
    let end = |local: &str| {
        let holder = xml::path(tree, connector, GLUE)?;
        let at = xml::child(tree, holder, A, local)?;
        let node = &tree.nodes[at];
        Some((
            node.attr("id")?.parse().ok()?,
            node.attr("idx")?.parse().ok()?,
        ))
    };
    (end("stCxn"), end("endCxn"))
}

/// A shape's or connector's preset geometry name as written.
pub(crate) fn preset_of(tree: &crate::ooxml::XmlTree, shape: usize) -> Option<&str> {
    tree.nodes[xml::path(tree, shape, PRESET)?].attr("prst")
}
