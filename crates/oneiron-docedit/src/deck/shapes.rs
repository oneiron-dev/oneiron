//! The shape walk: every shape in document order with its identity evidence,
//! placeholder, resolved geometry and text, and the composed transform of the
//! groups around it. Opaque content (`mc:AlternateContent`, content parts) is
//! carried by the package and not entered.
use super::graph::{A, A16, P, child, descendants, path};
use super::resolve::{self, Layer, SlideContext, attr};
use super::{
    Affine, ParagraphView, Placeholder, Refusal, RetainedNode, RunView, ShapeKind, ShapeView,
    State, TextView, Value, fingerprint,
};
use crate::ooxml::XmlTree;

pub(super) fn walk(context: &SlideContext<'_>, sp_tree: usize) -> Vec<ShapeView> {
    let mut shapes = Vec::new();
    if let Some(tree) = context.tree(context.slide) {
        let top = Value::schema_default(Affine::IDENTITY);
        visit(context, tree, sp_tree, &[], &top, &mut shapes);
    }
    shapes
}

fn visit(
    context: &SlideContext<'_>,
    tree: &XmlTree,
    container: usize,
    groups: &[usize],
    parent: &Value<Affine>,
    shapes: &mut Vec<ShapeView>,
) {
    for &at in &tree.nodes[container].children {
        let node = &tree.nodes[at];
        if node.namespace != P {
            continue;
        }
        let (kind, nv) = match node.name.as_str() {
            "sp" => (ShapeKind::Shape, "nvSpPr"),
            "pic" => (ShapeKind::Picture, "nvPicPr"),
            "graphicFrame" => (ShapeKind::GraphicFrame, "nvGraphicFramePr"),
            "cxnSp" => (ShapeKind::Connector, "nvCxnSpPr"),
            "grpSp" => (ShapeKind::Group, "nvGrpSpPr"),
            _ => continue,
        };
        let nv = child(tree, at, P, nv);
        let c_nv_pr = nv.and_then(|nv| child(tree, nv, P, "cNvPr"));
        let read = |name| c_nv_pr.and_then(|id| tree.nodes[id].attr(name));
        let placeholder = nv
            .and_then(|nv| path(tree, nv, &[(P, "nvPr"), (P, "ph")]))
            .map(|ph| Placeholder {
                kind: tree.nodes[ph].attr("type").unwrap_or("obj").to_owned(),
                // An unreadable index matches no layout placeholder.
                idx: tree.nodes[ph]
                    .attr("idx")
                    .map_or(Some(0), |idx| idx.parse().ok())
                    .unwrap_or(u32::MAX),
            });
        let layers = context.shape_layers(at, placeholder.as_ref());
        let geometry = context.geometry(&layers, parent.clone());
        let text = text(context, tree, at, &layers, placeholder.as_ref());
        let index = shapes.len();
        shapes.push(ShapeView {
            node: RetainedNode {
                part: context.slide.to_owned(),
                index: at,
            },
            kind,
            id: read("id").and_then(|id| id.parse().ok()),
            creation_id: c_nv_pr
                .and_then(|id| descendants(tree, id).find(|&d| tree.nodes[d].is(A16, "creationId")))
                .and_then(|d| tree.nodes[d].attr("id"))
                .map(guid),
            name: read("name").map(str::to_owned),
            group_path: groups.to_vec(),
            placeholder,
            geometry,
            text,
            content_fingerprint: fingerprint::content(tree, at),
        });
        if kind == ShapeKind::Group {
            let transform = group_transform(context, tree, at, parent);
            let mut inner = groups.to_vec();
            inner.push(index);
            visit(context, tree, at, &inner, &transform, shapes);
        }
    }
}

/// Canonical GUID evidence: uppercase and braced.
pub(crate) fn guid(id: &str) -> String {
    format!("{{{}}}", id.trim_matches(['{', '}']).to_ascii_uppercase())
}

/// Compose the group's child-to-parent matrix with its parent's. A missing
/// or degenerate transform is refused, not approximated.
fn group_transform(
    context: &SlideContext<'_>,
    tree: &XmlTree,
    group: usize,
    parent: &Value<Affine>,
) -> Value<Affine> {
    let Some(outer) = parent.value else {
        return parent.clone();
    };
    let source = path(tree, group, &[(P, "grpSpPr"), (A, "xfrm")])
        .map(|xfrm| resolve::source(context.slide, tree, xfrm, None));
    match group_matrix(tree, group) {
        Ok(inner) => Value {
            value: Some(Affine::then_outer(inner, outer)),
            state: State::Explicit,
            source,
            inherited: false,
        },
        Err(why) => Value::unresolved(why, source),
    }
}

/// The group's own child-to-parent matrix: scale `chOff`/`chExt` onto
/// `off`/`ext`, then flip and rotate about the group's centre.
pub(crate) fn group_matrix(tree: &XmlTree, group: usize) -> Result<Affine, Refusal> {
    let xfrm = path(tree, group, &[(P, "grpSpPr"), (A, "xfrm")])
        .ok_or(Refusal::UnrepresentableTransform)?;
    let pair = |name, x, y| {
        let at = &tree.nodes[child(tree, xfrm, A, name)?];
        Some((
            at.attr(x)?.parse::<f64>().ok()?,
            at.attr(y)?.parse::<f64>().ok()?,
        ))
    };
    let element = &tree.nodes[xfrm];
    let flag = |name| element.attr(name).map_or(Some(false), super::boolean);
    let (Some(off), Some(ext), Some(ch_off), Some(ch_ext), Some(rot), Some(flip_h), Some(flip_v)) = (
        pair("off", "x", "y"),
        pair("ext", "cx", "cy"),
        pair("chOff", "x", "y"),
        pair("chExt", "cx", "cy"),
        element
            .attr("rot")
            .map_or(Some(0.0), |rot| rot.parse::<f64>().ok()),
        flag("flipH"),
        flag("flipV"),
    ) else {
        return Err(Refusal::UnrepresentableTransform);
    };
    if [ext.0, ext.1, ch_ext.0, ch_ext.1].contains(&0.0) {
        return Err(Refusal::NonInvertibleGroupTransform);
    }
    let (sx, sy) = (ext.0 / ch_ext.0, ext.1 / ch_ext.1);
    let scale = Affine {
        a: sx,
        b: 0.0,
        c: 0.0,
        d: sy,
        e: off.0 - ch_off.0 * sx,
        f: off.1 - ch_off.1 * sy,
    };
    let (sin, cos) = (rot / 60_000.0).to_radians().sin_cos();
    let (fx, fy) = (
        if flip_h { -1.0 } else { 1.0 },
        if flip_v { -1.0 } else { 1.0 },
    );
    let (cx, cy) = (off.0 + ext.0 / 2.0, off.1 + ext.1 / 2.0);
    let (a, b, c, d) = (cos * fx, sin * fx, -sin * fy, cos * fy);
    let turn = Affine {
        a,
        b,
        c,
        d,
        e: cx - (a * cx + c * cy),
        f: cy - (b * cx + d * cy),
    };
    Ok(Affine::then_outer(scale, turn))
}

fn text(
    context: &SlideContext<'_>,
    tree: &XmlTree,
    shape: usize,
    layers: &[Layer<'_>],
    ph: Option<&Placeholder>,
) -> Option<TextView> {
    let body = child(tree, shape, P, "txBody")?;
    let paragraphs = tree.nodes[body]
        .children
        .iter()
        .copied()
        .filter(|&at| tree.nodes[at].is(A, "p"))
        .map(|at| paragraph(context, tree, at, layers, ph))
        .collect();
    Some(TextView {
        body: context.body(layers, child(tree, body, A, "bodyPr")),
        paragraphs,
    })
}

fn paragraph(
    context: &SlideContext<'_>,
    tree: &XmlTree,
    at: usize,
    layers: &[Layer<'_>],
    ph: Option<&Placeholder>,
) -> ParagraphView {
    let own = child(tree, at, A, "pPr");
    let own_layer = own.map_or(Layer::Missing, |p_pr| Layer::At(context.slide, p_pr));
    let level = context.lookup(
        &[own_layer],
        attr("lvl", |v| v.parse::<u8>().ok().filter(|level| *level <= 8)),
        Some(0),
    );
    let style = context.paragraph_layers(layers, ph, level.value.map_or(1, |level| level + 1));
    let chain: Vec<Layer<'_>> = std::iter::once(own_layer)
        .chain(style.iter().copied())
        .collect();
    // Runs read their own a:rPr, then this paragraph's a:defRPr, then the
    // style chain's a:defRPr.
    let paragraph_default = own
        .and_then(|p_pr| child(tree, p_pr, A, "defRPr"))
        .map_or(Layer::Missing, |at| Layer::At(context.slide, at));
    let defaults: Vec<Layer<'_>> = std::iter::once(paragraph_default)
        .chain(context.map_layers(&style, |tree, node| child(tree, node, A, "defRPr")))
        .collect();
    let runs = tree.nodes[at]
        .children
        .iter()
        .copied()
        .filter(|&run| tree.nodes[run].is(A, "r") || tree.nodes[run].is(A, "fld"))
        .map(|run| run_view(context, tree, run, &defaults))
        .collect();
    ParagraphView {
        node: RetainedNode {
            part: context.slide.to_owned(),
            index: at,
        },
        align: context.lookup(
            &chain,
            attr("algn", |v| Some(v.to_owned())),
            Some("l".into()),
        ),
        bullet: context.bullet(&chain),
        level,
        runs,
    }
}

/// The soft breaks (`a:br`) of the paragraph element at `at`, each as the
/// number of its runs and fields (the runs `paragraph` reads, which leave
/// breaks out) before it. The text mapping counts each break as one U+000B
/// in the paragraph's text; a reader that carries breaks places them by
/// this.
pub(crate) fn soft_breaks(tree: &XmlTree, at: usize) -> Vec<usize> {
    let mut runs = 0;
    let mut breaks = Vec::new();
    for &child in &tree.nodes[at].children {
        let node = &tree.nodes[child];
        if node.is(A, "r") || node.is(A, "fld") {
            runs += 1;
        } else if node.is(A, "br") {
            breaks.push(runs);
        }
    }
    breaks
}

fn run_view(
    context: &SlideContext<'_>,
    tree: &XmlTree,
    at: usize,
    defaults: &[Layer<'_>],
) -> RunView {
    let own =
        child(tree, at, A, "rPr").map_or(Layer::Missing, |r_pr| Layer::At(context.slide, r_pr));
    let chain: Vec<Layer<'_>> = std::iter::once(own)
        .chain(defaults.iter().copied())
        .collect();
    RunView {
        node: RetainedNode {
            part: context.slide.to_owned(),
            index: at,
        },
        text: child(tree, at, A, "t").map_or_else(String::new, |t| tree.nodes[t].text.clone()),
        size: context.lookup(&chain, attr("sz", |v| v.parse().ok()), None),
        bold: context.lookup(&chain, attr("b", super::boolean), Some(false)),
        italic: context.lookup(&chain, attr("i", super::boolean), Some(false)),
        latin: context.latin(&chain),
        colour: context.colour(&chain),
    }
}
