//! The template reader: masters and their layouts, each placeholder with its
//! resolved geometry and the first-level text style new text in it would
//! take. Template import keeps masters, layouts and themes opaque (ARCH-0077,
//! "Creation operation"); this view only reads them.
use super::graph::{A, Graph, P, child, path};
use super::resolve::{Layer, SlideContext, attr};
use super::{DeckError, Placeholder, ShapeView, Value, shapes};
use crate::ooxml::DOCUMENT_RELATIONSHIPS;
use crate::retained_opc::Package;

/// Every master in presentation order and the layouts each one lists.
#[derive(Debug, Clone)]
pub struct TemplateView {
    /// The presentation part (`ppt/presentation.xml`).
    pub presentation: String,
    /// `p:sldSz`, in EMU.
    pub slide_size: Option<(i64, i64)>,
    pub masters: Vec<MasterView>,
}

#[derive(Debug, Clone)]
pub struct MasterView {
    pub part: String,
    pub theme: Option<String>,
    /// The theme's major and minor latin typefaces.
    pub major_font: Option<String>,
    pub minor_font: Option<String>,
    pub shapes: Vec<ShapeView>,
    /// The style of new text in an ordinary text box: `p:otherStyle`, then
    /// the presentation default.
    pub ordinary_text: TextStyle,
    /// In `p:sldLayoutIdLst` order.
    pub layouts: Vec<LayoutView>,
}

#[derive(Debug, Clone)]
pub struct LayoutView {
    pub part: String,
    /// `p:cSld/@name`, for display only: selection never reads it.
    pub name: Option<String>,
    pub shapes: Vec<ShapeView>,
    /// For each of `shapes`, the style new first-level text in it takes.
    pub text: Vec<TextStyle>,
}

/// The first-level paragraph style new text takes.
#[derive(Debug, Clone, PartialEq)]
pub struct TextStyle {
    /// Hundredths of a point.
    pub size: Value<u32>,
    /// `marL`, in EMU.
    pub indent: Value<i64>,
}

impl TemplateView {
    /// Read the template without mutating `package`.
    pub fn read(package: &Package) -> Result<Self, DeckError> {
        let graph = Graph::load(package)?;
        let presentation = graph.part(&graph.presentation)?;
        let tree = &presentation.tree;
        tree.root(P, "presentation")?;
        let slide_size = child(tree, 0, P, "sldSz").and_then(|size| {
            let read = |name| tree.nodes[size].attr(name)?.parse::<i64>().ok();
            read("cx").zip(read("cy"))
        });
        let mut masters = Vec::new();
        for master in listed(&graph, &graph.presentation, "sldMasterIdLst", "slideMaster")? {
            masters.push(read_master(&graph, master)?);
        }
        Ok(Self {
            presentation: graph.presentation.clone(),
            slide_size,
            masters,
        })
    }
}

/// The parts an id list (`p:sldMasterIdLst`, `p:sldLayoutIdLst`) names
/// through its owner's relationships, in list order.
fn listed<'g>(
    graph: &'g Graph,
    owner: &str,
    list: &str,
    kind: &str,
) -> Result<Vec<&'g str>, DeckError> {
    let part = graph.part(owner)?;
    let Some(list) = child(&part.tree, 0, P, list) else {
        return Ok(Vec::new());
    };
    let mut found = Vec::new();
    for (_, entry) in part.tree.children(list) {
        let target = entry
            .attr_ns(DOCUMENT_RELATIONSHIPS, "id")
            .and_then(|id| part.rels.iter().find(|rel| rel.id == id))
            .filter(|rel| rel.kind == kind)
            .and_then(|rel| rel.target.as_deref())
            .ok_or(DeckError::Invalid("template list relationship"))?;
        found.push(target);
    }
    Ok(found)
}

fn read_master(graph: &Graph, part: &str) -> Result<MasterView, DeckError> {
    graph.part(part)?.tree.root(P, "sldMaster")?;
    let theme = graph.related(part, "theme")?;
    let context = SlideContext {
        graph,
        slide: part,
        layout: None,
        master: Some(part),
        theme,
    };
    let font = |scheme| {
        let tree = context.tree(theme?)?;
        let at = path(
            tree,
            0,
            &[
                (A, "themeElements"),
                (A, "fontScheme"),
                (A, scheme),
                (A, "latin"),
            ],
        )?;
        tree.nodes[at].attr("typeface").map(str::to_owned)
    };
    let mut layouts = Vec::new();
    for layout in listed(graph, part, "sldLayoutIdLst", "slideLayout")? {
        layouts.push(read_layout(graph, layout, part, theme)?);
    }
    Ok(MasterView {
        part: part.to_owned(),
        theme: theme.map(str::to_owned),
        major_font: font("majorFont"),
        minor_font: font("minorFont"),
        // The master's own shapes: no master layer above them.
        shapes: walk(&SlideContext {
            master: None,
            ..context
        }),
        ordinary_text: style(&context, &[], None),
        layouts,
    })
}

fn read_layout(
    graph: &Graph,
    part: &str,
    master: &str,
    theme: Option<&str>,
) -> Result<LayoutView, DeckError> {
    let tree = &graph.part(part)?.tree;
    tree.root(P, "sldLayout")?;
    let context = SlideContext {
        graph,
        slide: part,
        layout: None,
        master: Some(master),
        theme,
    };
    let shapes = walk(&context);
    let text = shapes
        .iter()
        .map(|shape| {
            let layers = context.shape_layers(shape.node.index, shape.placeholder.as_ref());
            style(&context, &layers, shape.placeholder.as_ref())
        })
        .collect();
    Ok(LayoutView {
        part: part.to_owned(),
        name: child(tree, 0, P, "cSld")
            .and_then(|c_sld| tree.nodes[c_sld].attr("name"))
            .map(str::to_owned),
        shapes,
        text,
    })
}

fn walk(context: &SlideContext<'_>) -> Vec<ShapeView> {
    context
        .tree(context.slide)
        .and_then(|tree| path(tree, 0, &[(P, "cSld"), (P, "spTree")]))
        .map_or_else(Vec::new, |sp_tree| shapes::walk(context, sp_tree))
}

/// The paragraph resolver's chain at level one, read for its run size and
/// left margin.
fn style(context: &SlideContext<'_>, layers: &[Layer<'_>], ph: Option<&Placeholder>) -> TextStyle {
    let chain = context.paragraph_layers(layers, ph, 1);
    let defaults = context.map_layers(&chain, |tree, node| child(tree, node, A, "defRPr"));
    TextStyle {
        size: context.lookup(&defaults, attr("sz", |v| v.parse().ok()), None),
        indent: context.lookup(&chain, attr("marL", |v| v.parse().ok()), None),
    }
}
