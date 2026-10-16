//! A compiled drawing as DrawingML: one `p:grpSp` whose child space is the
//! viewBox, for a slide's `p:spTree`. The fragment uses the `p:` and `a:`
//! prefixes the slide part declares.

use super::{Cap, Drawing, Frame, Geometry, Join, NativeShape, PathSpec, Preset, Segment, Solid};
use crate::ooxml::escape_text;

impl Drawing {
    /// The group and its shapes, with shape ids from `first_id`; returns the
    /// fragment and the next free id. `name` and `description` are the
    /// group's `cNvPr` name and alternative text.
    pub fn drawingml(&self, first_id: u32, name: &str, description: &str) -> (String, u32) {
        let (placed, child) = (self.placed, self.child);
        let mut out = format!(
            r#"<p:grpSp><p:nvGrpSpPr><p:cNvPr id="{first_id}" name="{}" descr="{}"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="{}" y="{}"/><a:ext cx="{}" cy="{}"/><a:chOff x="{}" y="{}"/><a:chExt cx="{}" cy="{}"/></a:xfrm></p:grpSpPr>"#,
            attr(name),
            attr(description),
            placed.x,
            placed.y,
            placed.cx,
            placed.cy,
            child.x,
            child.y,
            child.cx,
            child.cy,
        );
        let mut id = first_id;
        for shape in &self.shapes {
            id += 1;
            write_shape(&mut out, id, shape);
        }
        out.push_str("</p:grpSp>");
        (out, id + 1)
    }
}

fn write_shape(out: &mut String, id: u32, shape: &NativeShape) {
    out.push_str(&format!(
        r#"<p:sp><p:nvSpPr><p:cNvPr id="{id}" name="{}"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:spPr>"#,
        attr(&shape.name)
    ));
    xfrm(out, &shape.frame);
    match &shape.geometry {
        Geometry::Preset(preset) => {
            let (name, adjust) = match preset {
                Preset::Rect => ("rect", None),
                Preset::RoundRect { adj } => ("roundRect", Some(adj)),
                Preset::Ellipse => ("ellipse", None),
                Preset::Line => ("line", None),
            };
            out.push_str(&format!(r#"<a:prstGeom prst="{name}">"#));
            match adjust {
                Some(adj) => {
                    out.push_str(&format!(
                        r#"<a:avLst><a:gd name="adj" fmla="val {adj}"/></a:avLst>"#
                    ));
                }
                None => out.push_str("<a:avLst/>"),
            }
            out.push_str("</a:prstGeom>");
        }
        Geometry::Custom(paths) => {
            out.push_str(r#"<a:custGeom><a:avLst/><a:gdLst/><a:ahLst/><a:cxnLst/><a:rect l="l" t="t" r="r" b="b"/><a:pathLst>"#);
            for path in paths {
                write_path(out, path);
            }
            out.push_str("</a:pathLst></a:custGeom>");
        }
    }
    match shape.fill {
        Some(fill) => solid(out, fill),
        None => out.push_str("<a:noFill/>"),
    }
    match shape.stroke {
        Some(stroke) => {
            let cap = match stroke.cap {
                Cap::Flat => "flat",
                Cap::Round => "rnd",
                Cap::Square => "sq",
            };
            out.push_str(&format!(r#"<a:ln w="{}" cap="{cap}">"#, stroke.width));
            solid(out, stroke.paint);
            match stroke.join {
                Join::Miter { limit } => out.push_str(&format!(r#"<a:miter lim="{limit}"/>"#)),
                Join::Round => out.push_str("<a:round/>"),
                Join::Bevel => out.push_str("<a:bevel/>"),
            }
            out.push_str("</a:ln>");
        }
        None => out.push_str("<a:ln><a:noFill/></a:ln>"),
    }
    out.push_str("</p:spPr></p:sp>");
}

fn xfrm(out: &mut String, frame: &Frame) {
    out.push_str("<a:xfrm");
    if frame.rot != 0 {
        out.push_str(&format!(r#" rot="{}""#, frame.rot));
    }
    if frame.flip_v {
        out.push_str(r#" flipV="1""#);
    }
    let r = frame.rect;
    out.push_str(&format!(
        r#"><a:off x="{}" y="{}"/><a:ext cx="{}" cy="{}"/></a:xfrm>"#,
        r.x, r.y, r.cx, r.cy
    ));
}

fn write_path(out: &mut String, path: &PathSpec) {
    out.push_str(&format!(r#"<a:path w="{}" h="{}""#, path.w, path.h));
    if !path.fill {
        out.push_str(r#" fill="none""#);
    }
    if !path.stroke {
        out.push_str(r#" stroke="0""#);
    }
    out.push('>');
    for segment in &path.segments {
        let (tag, points) = match *segment {
            Segment::MoveTo(p) => ("moveTo", vec![p]),
            Segment::LineTo(p) => ("lnTo", vec![p]),
            Segment::CubicTo(a, b, c) => ("cubicBezTo", vec![a, b, c]),
            Segment::QuadTo(a, b) => ("quadBezTo", vec![a, b]),
            Segment::Close => {
                out.push_str("<a:close/>");
                continue;
            }
        };
        out.push_str(&format!("<a:{tag}>"));
        for p in points {
            out.push_str(&format!(r#"<a:pt x="{}" y="{}"/>"#, p.x, p.y));
        }
        out.push_str(&format!("</a:{tag}>"));
    }
    out.push_str("</a:path>");
}

fn solid(out: &mut String, paint: Solid) {
    let [r, g, b] = paint.rgb;
    out.push_str(&format!(
        r#"<a:solidFill><a:srgbClr val="{r:02X}{g:02X}{b:02X}""#
    ));
    if paint.alpha < 100_000 {
        out.push_str(&format!(r#"><a:alpha val="{}"/></a:srgbClr>"#, paint.alpha));
    } else {
        out.push_str("/>");
    }
    out.push_str("</a:solidFill>");
}

/// Attribute text: escaped, with line breaks kept as references.
fn attr(text: &str) -> String {
    escape_text(text)
        .replace('\n', "&#10;")
        .replace('\t', "&#9;")
}
