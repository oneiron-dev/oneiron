//! The four property-specific resolvers (geometry, text body, paragraph,
//! run). Each walks its own chain of retained elements and stops at the first
//! layer that states the property; an ambiguous placeholder ends the chain
//! as unresolved instead of guessing which layout shape was meant.
use super::graph::{A, Graph, P, child, path};
use super::{
    Autofit, BodyView, Bullet, Colour, Font, Geometry, Placeholder, Refusal, RetainedNode, Source,
    State, Value,
};
use crate::ooxml::XmlTree;

pub(super) struct SlideContext<'a> {
    pub(super) graph: &'a Graph,
    pub(super) slide: &'a str,
    pub(super) layout: Option<&'a str>,
    pub(super) master: Option<&'a str>,
    pub(super) theme: Option<&'a str>,
}

/// One element a lookup consults, a layer that lacks the element (kept so
/// depth still tells own from inherited), or the end of a chain.
#[derive(Debug, Clone, Copy)]
pub(super) enum Layer<'a> {
    At(&'a str, usize),
    Missing,
    Stop(Refusal),
}

/// What a layer states: the element and attribute, and the parsed value
/// (`None` when present but unreadable).
pub(super) struct Found<T> {
    pub(super) node: usize,
    pub(super) attribute: Option<&'static str>,
    pub(super) value: Option<T>,
}

impl SlideContext<'_> {
    pub(super) fn tree(&self, part: &str) -> Option<&XmlTree> {
        self.graph.parts.get(part).map(|part| &part.tree)
    }

    /// The shape itself, then its layout and master placeholders.
    pub(super) fn shape_layers(&self, shape: usize, ph: Option<&Placeholder>) -> Vec<Layer<'_>> {
        let mut layers = vec![Layer::At(self.slide, shape)];
        let Some(ph) = ph else {
            return layers;
        };
        let mut class_of = ph.kind.as_str();
        if let Some(layout) = self.layout {
            match placeholder_match(self.tree(layout), ph, true) {
                Match::One(node, kind) => {
                    layers.push(Layer::At(layout, node));
                    class_of = kind;
                }
                Match::Many => {
                    layers.push(Layer::Stop(Refusal::AmbiguousPlaceholder));
                    return layers;
                }
                Match::None => {}
            }
        }
        if let Some(master) = self.master {
            let wanted = Placeholder {
                kind: class_of.to_owned(),
                idx: ph.idx,
            };
            match placeholder_match(self.tree(master), &wanted, false) {
                Match::One(node, _) => layers.push(Layer::At(master, node)),
                Match::Many => layers.push(Layer::Stop(Refusal::AmbiguousPlaceholder)),
                Match::None => {}
            }
        }
        layers
    }

    /// Replace each layer by the element `select` finds in it.
    pub(super) fn map_layers<'a>(
        &self,
        layers: &[Layer<'a>],
        select: impl Fn(&XmlTree, usize) -> Option<usize>,
    ) -> Vec<Layer<'a>> {
        layers
            .iter()
            .map(|layer| match *layer {
                Layer::At(part, node) => self
                    .tree(part)
                    .and_then(|tree| select(tree, node))
                    .map_or(Layer::Missing, |found| Layer::At(part, found)),
                other => other,
            })
            .collect()
    }

    /// The first layer stating the property wins; none yields the schema
    /// default when there is one, else absent.
    pub(super) fn lookup<T>(
        &self,
        layers: &[Layer<'_>],
        read: impl Fn(&XmlTree, usize) -> Option<Found<T>>,
        default: Option<T>,
    ) -> Value<T> {
        for (depth, layer) in layers.iter().enumerate() {
            let (part, node) = match *layer {
                Layer::At(part, node) => (part, node),
                Layer::Missing => continue,
                Layer::Stop(why) => return Value::unresolved(why, None),
            };
            let Some(tree) = self.tree(part) else {
                return Value::unresolved(Refusal::UnresolvedEffectiveStyle, None);
            };
            let Some(found) = read(tree, node) else {
                continue;
            };
            let source = Some(source(part, tree, found.node, found.attribute));
            return match found.value {
                Some(value) => Value {
                    value: Some(value),
                    state: State::Explicit,
                    source,
                    inherited: depth > 0,
                },
                None => Value::unresolved(Refusal::UnresolvedEffectiveStyle, source),
            };
        }
        default.map_or_else(Value::absent, Value::schema_default)
    }

    pub(super) fn geometry(&self, layers: &[Layer<'_>], parent: Value<super::Affine>) -> Geometry {
        let holders = self.map_layers(layers, xfrm);
        let found = self.lookup(
            &holders,
            |_, node| {
                Some(Found {
                    node,
                    attribute: None,
                    value: Some(()),
                })
            },
            None,
        );
        let (State::Explicit, Some(at)) = (found.state, found.source) else {
            let why = match found.state {
                State::Unresolved(why) => Some(why),
                _ => None,
            };
            return Geometry {
                offset: blank(why),
                extent: blank(why),
                rotation: blank(why),
                flip_h: blank(why),
                flip_v: blank(why),
                parent_transform: parent,
            };
        };
        let part = at.node.part.as_str();
        let one = [Layer::At(part, at.node.index)];
        let from = found.inherited;
        Geometry {
            offset: layer_of(self.lookup(&one, pair(A, "off", "x", "y"), None), from),
            extent: layer_of(self.lookup(&one, pair(A, "ext", "cx", "cy"), None), from),
            rotation: layer_of(
                self.lookup(&one, attr("rot", |v| v.parse().ok()), Some(0)),
                from,
            ),
            flip_h: layer_of(
                self.lookup(&one, attr("flipH", super::boolean), Some(false)),
                from,
            ),
            flip_v: layer_of(
                self.lookup(&one, attr("flipV", super::boolean), Some(false)),
                from,
            ),
            parent_transform: parent,
        }
    }

    pub(super) fn body(&self, layers: &[Layer<'_>], own: Option<usize>) -> BodyView {
        let bodies = self.map_layers(layers, |tree, node| {
            path(tree, node, &[(P, "txBody"), (A, "bodyPr")])
        });
        let inset = |name: &'static str, default: i64| {
            self.lookup(&bodies, attr(name, |v| v.parse().ok()), Some(default))
        };
        BodyView {
            node: own.map(|index| RetainedNode {
                part: self.slide.to_owned(),
                index,
            }),
            insets: [
                inset("lIns", 91_440),
                inset("tIns", 45_720),
                inset("rIns", 91_440),
                inset("bIns", 45_720),
            ],
            anchor: self.lookup(
                &bodies,
                attr("anchor", |v| Some(v.to_owned())),
                Some("t".into()),
            ),
            wrap: self.lookup(
                &bodies,
                attr("wrap", |v| Some(v.to_owned())),
                Some("square".into()),
            ),
            autofit: self.lookup(&bodies, autofit, None),
        }
    }

    /// The shape's style layers at `level` (1-based), after its own `a:pPr`:
    /// `a:lstStyle` of the shape and its placeholders, then the master text
    /// style for the placeholder class, then the presentation default.
    pub(super) fn paragraph_layers<'a>(
        &'a self,
        shape_layers: &[Layer<'a>],
        ph: Option<&Placeholder>,
        level: u8,
    ) -> Vec<Layer<'a>> {
        let name = format!("lvl{level}pPr");
        let mut layers = self.map_layers(shape_layers, |tree, node| {
            path(
                tree,
                node,
                &[(P, "txBody"), (A, "lstStyle"), (A, name.as_str())],
            )
        });
        if matches!(layers.last(), Some(Layer::Stop(_))) {
            return layers;
        }
        let style = match ph.map(|ph| class(&ph.kind)) {
            Some("title") => "titleStyle",
            Some("body") => "bodyStyle",
            _ => "otherStyle",
        };
        if let Some(master) = self.master
            && let Some(at) = self
                .tree(master)
                .and_then(|tree| path(tree, 0, &[(P, "txStyles"), (P, style), (A, name.as_str())]))
        {
            layers.push(Layer::At(master, at));
        }
        let presentation = self.graph.presentation.as_str();
        if let Some(at) = self
            .tree(presentation)
            .and_then(|tree| path(tree, 0, &[(P, "defaultTextStyle"), (A, name.as_str())]))
        {
            layers.push(Layer::At(presentation, at));
        }
        layers
    }

    pub(super) fn bullet(&self, layers: &[Layer<'_>]) -> Value<Bullet> {
        self.lookup(
            layers,
            |tree, node| {
                tree.nodes[node].children.iter().find_map(|&at| {
                    let found = &tree.nodes[at];
                    let value = if found.is(A, "buNone") {
                        Some(Bullet::None)
                    } else if found.is(A, "buChar") {
                        found.attr("char").map(|c| Bullet::Char(c.to_owned()))
                    } else if found.is(A, "buAutoNum") {
                        found.attr("type").map(|t| Bullet::AutoNumber(t.to_owned()))
                    } else {
                        return None;
                    };
                    Some(Found {
                        node: at,
                        attribute: None,
                        value,
                    })
                })
            },
            None,
        )
    }

    /// `a:latin`, with a `+mj-`/`+mn-` reference resolved through the theme.
    pub(super) fn latin(&self, layers: &[Layer<'_>]) -> Value<Font> {
        let mut value = self.lookup(
            layers,
            |tree, node| {
                child(tree, node, A, "latin").map(|at| Found {
                    node: at,
                    attribute: Some("typeface"),
                    value: tree.nodes[at].attr("typeface").map(str::to_owned),
                })
            },
            None,
        );
        let Some(typeface) = value.value.take() else {
            return Value {
                value: None,
                state: value.state,
                source: value.source,
                inherited: value.inherited,
            };
        };
        match self.theme_font(&typeface) {
            Some(resolved) => Value {
                value: Some(Font { typeface, resolved }),
                state: value.state,
                source: value.source,
                inherited: value.inherited,
            },
            None => Value::unresolved(Refusal::UnresolvedEffectiveStyle, value.source),
        }
    }

    fn theme_font(&self, typeface: &str) -> Option<String> {
        let Some(reference) = typeface.strip_prefix('+') else {
            return Some(typeface.to_owned());
        };
        let (scheme, script) = reference.split_once('-')?;
        let scheme = match scheme {
            "mj" => "majorFont",
            "mn" => "minorFont",
            _ => return None,
        };
        let script = match script {
            "lt" => "latin",
            "ea" => "ea",
            "cs" => "cs",
            _ => return None,
        };
        let tree = self.tree(self.theme?)?;
        let at = path(
            tree,
            0,
            &[
                (A, "themeElements"),
                (A, "fontScheme"),
                (A, scheme),
                (A, script),
            ],
        )?;
        tree.nodes[at]
            .attr("typeface")
            .filter(|face| !face.is_empty())
            .map(str::to_owned)
    }

    pub(super) fn colour(&self, layers: &[Layer<'_>]) -> Value<Colour> {
        self.lookup(
            layers,
            |tree, node| {
                child(tree, node, A, "solidFill").map(|fill| Found {
                    node: fill,
                    attribute: None,
                    value: super::colour::read(self, tree, fill),
                })
            },
            None,
        )
    }
}

/// Every geometry value when no `a:xfrm` was reached.
fn blank<T>(why: Option<Refusal>) -> Value<T> {
    why.map_or_else(Value::absent, |why| Value::unresolved(why, None))
}

/// A value read inside an inherited `a:xfrm` is inherited too.
fn layer_of<T>(mut value: Value<T>, inherited: bool) -> Value<T> {
    if value.state == State::Explicit {
        value.inherited = inherited;
    }
    value
}

pub(super) fn attr<T>(
    name: &'static str,
    parse: impl Fn(&str) -> Option<T>,
) -> impl Fn(&XmlTree, usize) -> Option<Found<T>> {
    move |tree, node| {
        tree.nodes[node].attr(name).map(|value| Found {
            node,
            attribute: Some(name),
            value: parse(value),
        })
    }
}

fn pair(
    ns: &'static str,
    element: &'static str,
    x: &'static str,
    y: &'static str,
) -> impl Fn(&XmlTree, usize) -> Option<Found<(i64, i64)>> {
    move |tree, node| {
        child(tree, node, ns, element).map(|at| {
            let read = |name| {
                tree.nodes[at]
                    .attr(name)
                    .and_then(|v| v.parse::<i64>().ok())
            };
            Found {
                node: at,
                attribute: None,
                value: read(x).zip(read(y)),
            }
        })
    }
}

fn autofit(tree: &XmlTree, node: usize) -> Option<Found<Autofit>> {
    tree.nodes[node].children.iter().find_map(|&at| {
        let element = &tree.nodes[at];
        let percent = |name| element.attr(name).map(|v| v.parse::<u32>().ok());
        let value = if element.is(A, "noAutofit") {
            Some(Autofit::None)
        } else if element.is(A, "spAutoFit") {
            Some(Autofit::Shape)
        } else if element.is(A, "normAutofit") {
            match (percent("fontScale"), percent("lnSpcReduction")) {
                (Some(None), _) | (_, Some(None)) => None,
                (font_scale, line_reduction) => Some(Autofit::Normal {
                    font_scale: font_scale.flatten(),
                    line_reduction: line_reduction.flatten(),
                }),
            }
        } else {
            return None;
        };
        Some(Found {
            node: at,
            attribute: None,
            value,
        })
    })
}

/// The element holding a shape's own transform.
fn xfrm(tree: &XmlTree, shape: usize) -> Option<usize> {
    let node = &tree.nodes[shape];
    if node.is(P, "graphicFrame") {
        child(tree, shape, P, "xfrm")
    } else if node.is(P, "grpSp") {
        path(tree, shape, &[(P, "grpSpPr"), (A, "xfrm")])
    } else {
        path(tree, shape, &[(P, "spPr"), (A, "xfrm")])
    }
}

pub(super) fn source(part: &str, tree: &XmlTree, node: usize, attribute: Option<&str>) -> Source {
    Source {
        node: RetainedNode {
            part: part.to_owned(),
            index: node,
        },
        element: tree.nodes[node].qualified.clone(),
        attribute: attribute.map(str::to_owned),
    }
}

/// Placeholder class: `title`/`ctrTitle` are titles; `body`, `subTitle` and
/// the implied `obj` are body text; every other type is its own class.
fn class(kind: &str) -> &str {
    match kind {
        "title" | "ctrTitle" => "title",
        "body" | "subTitle" | "obj" => "body",
        other => other,
    }
}

enum Match<'t> {
    None,
    One(usize, &'t str),
    Many,
}

/// Layout placeholders match on index and class together; master
/// placeholders match on class alone.
fn placeholder_match<'t>(tree: Option<&'t XmlTree>, ph: &Placeholder, by_idx: bool) -> Match<'t> {
    let Some(tree) = tree else {
        return Match::None;
    };
    let Some(sp_tree) = path(tree, 0, &[(P, "cSld"), (P, "spTree")]) else {
        return Match::None;
    };
    let mut found = Match::None;
    for at in super::graph::descendants(tree, sp_tree) {
        if !tree.nodes[at].is(P, "ph") {
            continue;
        }
        let kind = tree.nodes[at].attr("type").unwrap_or("obj");
        let idx = tree.nodes[at]
            .attr("idx")
            .map_or(Some(0), |idx| idx.parse::<u32>().ok());
        if class(kind) != class(&ph.kind) || (by_idx && idx != Some(ph.idx)) {
            continue;
        }
        // p:ph sits at shape/nv*Pr/p:nvPr/p:ph.
        let shape = tree.nodes[at]
            .parent
            .and_then(|nv_pr| tree.nodes[nv_pr].parent)
            .and_then(|nv| tree.nodes[nv].parent);
        let Some(shape) = shape else {
            continue;
        };
        found = match found {
            Match::None => Match::One(shape, kind),
            _ => return Match::Many,
        };
    }
    found
}
