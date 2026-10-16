//! `set_xfrm` and `move_in_slide_space`: a shape's own transform, attribute
//! by attribute. An inherited transform is never materialised: owning one
//! takes a declared offset and extent.
use super::check::Declared;
use super::xml::{self, A, P, Splice};
use super::{EditRefusal, Effect, FitUnverified, Written, Xfrm};
use crate::deck::{Refusal, ShapeKind, ShapeView, SlideView, State};
use crate::ooxml::XmlTree;
use crate::retained_opc::Package;
use std::ops::RangeInclusive;

/// `ST_Coordinate` and `ST_PositiveCoordinate` (ECMA-376 Part 1, 20.1.10).
const COORDINATE: RangeInclusive<i64> = -27_273_042_329_600..=27_273_042_316_900;
const POSITIVE: RangeInclusive<i64> = 0..=27_273_042_316_900;
/// 360° in `ST_Angle` units.
pub(super) const TURN: i64 = 21_600_000;

/// The path from a shape element to its own transform.
pub(crate) fn own_path(kind: ShapeKind) -> &'static [(&'static str, &'static str)] {
    match kind {
        ShapeKind::Group => &[(P, "grpSpPr"), (A, "xfrm")],
        ShapeKind::GraphicFrame => &[(P, "xfrm")],
        _ => &[(P, "spPr"), (A, "xfrm")],
    }
}

pub(super) fn set_xfrm(
    next: &mut Package,
    slide: &SlideView,
    shape: &ShapeView,
    declared: &Xfrm,
) -> Result<Written, EditRefusal> {
    let id = shape.id.ok_or(EditRefusal::Missing("shape id"))?;
    check_ranges(declared)?;
    // Owning an inherited transform drops the rest of it (it is inherited
    // whole), so an inherited rotation or flip must be declared too.
    let geometry = &shape.geometry;
    if geometry.offset.inherited
        && (declared.rotation.is_none() && geometry.rotation.value.is_some_and(|rot| rot != 0)
            || declared.flip_h.is_none() && geometry.flip_h.value == Some(true)
            || declared.flip_v.is_none() && geometry.flip_v.value == Some(true))
    {
        return Err(EditRefusal::InheritedTransform);
    }
    let (bytes, tree) = xml::read(next, &slide.part)?;
    let edits = write(&bytes, &tree, shape.node.index, shape.kind, declared)?;
    if !edits.is_empty() {
        next.replace_xml_part(&slide.part, xml::splice(&bytes, edits)?)?;
    }
    let resized = declared
        .extent
        .is_some_and(|extent| shape.geometry.extent.value != Some(extent));
    Ok(Written {
        allowed: vec![slide.part.clone()],
        declared: vec![Declared::element(
            &slide.part,
            Some(id),
            own_path(shape.kind),
        )],
        relationships: Vec::new(),
        created: Vec::new(),
        effects: glued(slide, id),
        fit: (resized && shape.text.is_some()).then(|| FitUnverified {
            part: slide.part.clone(),
            shape: id,
        }),
    })
}

/// Move through the inverse of the composed parent transform; the new local
/// offset is rounded to the EMU, so the slide-space move is exact to within
/// half an EMU scaled by the parents.
pub(super) fn move_in_slide_space(
    next: &mut Package,
    slide: &SlideView,
    shape: &ShapeView,
    (dx, dy): (i64, i64),
) -> Result<Written, EditRefusal> {
    let offset = &shape.geometry.offset;
    let own = match (offset.state, offset.value) {
        (State::Explicit, Some(value)) if !offset.inherited => value,
        _ => return Err(EditRefusal::InheritedTransform),
    };
    let parent = &shape.geometry.parent_transform;
    let matrix = match (parent.state, parent.value) {
        (State::Unresolved(Refusal::NonInvertibleGroupTransform), _) => {
            return Err(EditRefusal::NonInvertibleGroupTransform);
        }
        (State::Unresolved(_), _) | (_, None) => {
            return Err(EditRefusal::UnrepresentableTransform(
                "the parent transform is unresolved",
            ));
        }
        (_, Some(matrix)) => matrix,
    };
    let det = matrix.a * matrix.d - matrix.b * matrix.c;
    if !det.is_finite() || det.abs() < f64::EPSILON {
        return Err(EditRefusal::NonInvertibleGroupTransform);
    }
    let (dx, dy) = (dx as f64, dy as f64);
    let local = (
        (matrix.d * dx - matrix.c * dy) / det,
        (matrix.a * dy - matrix.b * dx) / det,
    );
    let moved = (
        own.0 as f64 + local.0.round(),
        own.1 as f64 + local.1.round(),
    );
    if !moved.0.is_finite() || !moved.1.is_finite() {
        return Err(EditRefusal::UnrepresentableTransform(
            "the move leaves the coordinate space",
        ));
    }
    let xfrm = Xfrm {
        offset: Some((moved.0 as i64, moved.1 as i64)),
        ..Xfrm::default()
    };
    let mut written = set_xfrm(next, slide, shape, &xfrm)?;
    written.fit = None;
    Ok(written)
}

pub(super) fn check_ranges(xfrm: &Xfrm) -> Result<(), EditRefusal> {
    if let Some((x, y)) = xfrm.offset
        && !(COORDINATE.contains(&x) && COORDINATE.contains(&y))
    {
        return Err(EditRefusal::UnrepresentableTransform(
            "offset outside ST_Coordinate",
        ));
    }
    if let Some((cx, cy)) = xfrm.extent
        && !(POSITIVE.contains(&cx) && POSITIVE.contains(&cy))
    {
        return Err(EditRefusal::UnrepresentableTransform(
            "extent outside ST_PositiveCoordinate",
        ));
    }
    if xfrm.rotation.is_some_and(|rot| !(0..TURN).contains(&rot)) {
        return Err(EditRefusal::UnrepresentableTransform(
            "rotation outside [0°, 360°)",
        ));
    }
    Ok(())
}

fn flag(value: bool) -> &'static str {
    if value { "1" } else { "0" }
}

/// Splices that write the declared properties into the shape's own
/// transform; an unchanged or schema-default value adds nothing.
pub(super) fn write(
    bytes: &[u8],
    tree: &XmlTree,
    shape: usize,
    kind: ShapeKind,
    declared: &Xfrm,
) -> Result<Vec<Splice>, EditRefusal> {
    let path = own_path(kind);
    let (holder_path, [(ns, name)]) = path.split_at(path.len() - 1) else {
        unreachable!("a transform path ends in the transform");
    };
    let holder =
        xml::path(tree, shape, holder_path).ok_or(EditRefusal::Missing("shape properties"))?;
    let Some(own) = xml::child(tree, holder, ns, name) else {
        let (Some((x, y)), Some((cx, cy))) = (declared.offset, declared.extent) else {
            return Err(EditRefusal::InheritedTransform);
        };
        if kind != ShapeKind::Shape && kind != ShapeKind::Picture && kind != ShapeKind::Connector {
            return Err(EditRefusal::Invalid(
                "a group or frame without its own transform",
            ));
        }
        let mut attributes = String::new();
        if let Some(rot) = declared.rotation.filter(|&rot| rot != 0) {
            attributes.push_str(&format!(r#" rot="{rot}""#));
        }
        for (attribute, value) in [("flipH", declared.flip_h), ("flipV", declared.flip_v)] {
            if value == Some(true) {
                attributes.push_str(&format!(r#" {attribute}="1""#));
            }
        }
        let element = format!(
            r#"<a:xfrm xmlns:a="{A}"{attributes}><a:off x="{x}" y="{y}"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm>"#
        );
        return Ok(vec![xml::insert_first(
            bytes,
            &tree.nodes[holder],
            &element,
        )]);
    };
    let node = &tree.nodes[own];
    let mut edits = Vec::new();
    let mut attribute = |node: &crate::ooxml::Node, name: &str, value: String, default: &str| {
        let unchanged = match node.attr(name) {
            Some(current) => current == value,
            None => value == default,
        };
        if !unchanged {
            edits.push(xml::set_attribute(bytes, node, name, &value));
        }
    };
    if let Some(rot) = declared.rotation {
        attribute(node, "rot", rot.to_string(), "0");
    }
    if let Some(flip) = declared.flip_h {
        attribute(node, "flipH", flag(flip).to_owned(), "0");
    }
    if let Some(flip) = declared.flip_v {
        attribute(node, "flipV", flag(flip).to_owned(), "0");
    }
    let pairs = [
        ("off", declared.offset.map(|(x, y)| [("x", x), ("y", y)])),
        (
            "ext",
            declared.extent.map(|(cx, cy)| [("cx", cx), ("cy", cy)]),
        ),
    ];
    let mut inserted = Vec::new();
    for (element, values) in pairs {
        let Some(values) = values else { continue };
        match xml::child(tree, own, A, element) {
            Some(at) => {
                for (name, value) in values {
                    attribute(&tree.nodes[at], name, value.to_string(), "");
                }
            }
            None => {
                let [(n1, v1), (n2, v2)] = values;
                inserted.push(format!(
                    r#"<a:{element} xmlns:a="{A}" {n1}="{v1}" {n2}="{v2}"/>"#
                ));
            }
        }
    }
    if !inserted.is_empty() {
        if node.empty {
            return Err(EditRefusal::UnrepresentableTransform(
                "a transform without its offset and extent",
            ));
        }
        let at =
            xml::child(tree, own, A, "off").map_or(node.open_end, |off| tree.nodes[off].span.end);
        edits.push((at..at, inserted.concat().into_bytes()));
    }
    Ok(edits)
}

fn glued(slide: &SlideView, id: u32) -> Vec<Effect> {
    slide
        .animation
        .connections_to(id)
        .map(|cxn| Effect::GluedConnector {
            connector: cxn.connector,
        })
        .collect()
}
