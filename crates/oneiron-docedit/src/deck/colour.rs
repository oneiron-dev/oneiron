//! Colours stay symbolic: a scheme slot and its ordered transforms are kept as
//! written, and the computed colour is derived through the slide's colour map
//! and theme, or refused. Equal RGB never implies a shared scheme slot.
use super::Refusal;
use super::graph::{A, P, child, path};
use super::resolve::SlideContext;
use crate::ooxml::XmlTree;

/// Theme slots a colour map maps onto; `dk1`..`lt2` are never remapped.
const DIRECT: [&str; 4] = ["dk1", "lt1", "dk2", "lt2"];

/// One colour transform child (`a:lumMod val="75000"`), in document order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColourTransform {
    pub name: String,
    pub value: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColourSpec {
    Scheme {
        slot: String,
        transforms: Vec<ColourTransform>,
    },
    Srgb {
        rgb: [u8; 3],
        transforms: Vec<ColourTransform>,
    },
    System {
        name: String,
        last: Option<[u8; 3]>,
        transforms: Vec<ColourTransform>,
    },
    /// A colour model this view keeps but does not compute (`a:prstClr`).
    Other {
        element: String,
        transforms: Vec<ColourTransform>,
    },
}

/// Alpha is in 1/100,000; 100,000 is opaque.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgba {
    pub rgb: [u8; 3],
    pub alpha: u32,
}

/// The symbolic expression and the colour it computes to in this slide's
/// context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Colour {
    pub spec: ColourSpec,
    pub computed: Result<Rgba, Refusal>,
}

/// Read the colour inside a fill element; `None` when it holds none.
pub(super) fn read(context: &SlideContext<'_>, tree: &XmlTree, fill: usize) -> Option<Colour> {
    let element = *tree.nodes[fill].children.first()?;
    let spec = spec(tree, element)?;
    let computed = compute(context, &spec);
    Some(Colour { spec, computed })
}

fn spec(tree: &XmlTree, at: usize) -> Option<ColourSpec> {
    let node = &tree.nodes[at];
    if node.namespace != A {
        return None;
    }
    let transforms = node
        .children
        .iter()
        .map(|&index| ColourTransform {
            name: tree.nodes[index].name.clone(),
            value: tree.nodes[index]
                .attr("val")
                .and_then(|value| value.parse().ok()),
        })
        .collect();
    Some(match node.name.as_str() {
        "schemeClr" => ColourSpec::Scheme {
            slot: node.attr("val")?.to_owned(),
            transforms,
        },
        "srgbClr" => ColourSpec::Srgb {
            rgb: hex(node.attr("val")?)?,
            transforms,
        },
        "sysClr" => ColourSpec::System {
            name: node.attr("val")?.to_owned(),
            last: node.attr("lastClr").and_then(hex),
            transforms,
        },
        other => ColourSpec::Other {
            element: other.to_owned(),
            transforms,
        },
    })
}

fn compute(context: &SlideContext<'_>, spec: &ColourSpec) -> Result<Rgba, Refusal> {
    let (base, transforms) = match spec {
        ColourSpec::Srgb { rgb, transforms }
        | ColourSpec::System {
            last: Some(rgb),
            transforms,
            ..
        } => (*rgb, transforms),
        ColourSpec::Scheme { slot, transforms } => (scheme(context, slot)?, transforms),
        ColourSpec::System { last: None, .. } => return Err(Refusal::UnresolvedColourContext),
        ColourSpec::Other { .. } => return Err(Refusal::UnsupportedColourTransform),
    };
    let (hue, saturation, mut lightness) = to_hsl(base);
    let mut alpha = 100_000;
    for transform in transforms {
        let value = transform.value.ok_or(Refusal::UnsupportedColourTransform)?;
        match transform.name.as_str() {
            "alpha" => alpha = u32::try_from(value.clamp(0, 100_000)).unwrap_or(0),
            "lumMod" => lightness *= value as f64 / 100_000.0,
            "lumOff" => lightness += value as f64 / 100_000.0,
            _ => return Err(Refusal::UnsupportedColourTransform),
        }
        lightness = lightness.clamp(0.0, 1.0);
    }
    Ok(Rgba {
        rgb: from_hsl(hue, saturation, lightness),
        alpha,
    })
}

/// Theme → colour map → slot: the slide's `p:clrMapOvr`, then the layout's,
/// then the master's `p:clrMap`.
fn scheme(context: &SlideContext<'_>, slot: &str) -> Result<[u8; 3], Refusal> {
    let theme_slot = if DIRECT.contains(&slot) {
        slot.to_owned()
    } else {
        colour_map(context)
            .and_then(|(tree, map)| tree.nodes[map].attr(slot))
            .ok_or(Refusal::UnresolvedColourContext)?
            .to_owned()
    };
    let tree = context
        .theme
        .and_then(|theme| context.tree(theme))
        .ok_or(Refusal::UnresolvedColourContext)?;
    let at = path(
        tree,
        0,
        &[
            (A, "themeElements"),
            (A, "clrScheme"),
            (A, theme_slot.as_str()),
        ],
    )
    .and_then(|slot| tree.nodes[slot].children.first().copied())
    .ok_or(Refusal::UnresolvedColourContext)?;
    let node = &tree.nodes[at];
    let value = if node.is(A, "srgbClr") {
        node.attr("val")
    } else if node.is(A, "sysClr") {
        node.attr("lastClr")
    } else {
        None
    };
    value.and_then(hex).ok_or(Refusal::UnresolvedColourContext)
}

fn colour_map<'a>(context: &'a SlideContext<'_>) -> Option<(&'a XmlTree, usize)> {
    for part in [Some(context.slide), context.layout].into_iter().flatten() {
        let tree = context.tree(part)?;
        let Some(over) = child(tree, 0, P, "clrMapOvr") else {
            continue;
        };
        if let Some(map) = child(tree, over, A, "overrideClrMapping") {
            return Some((tree, map));
        }
        // An explicit `a:masterClrMapping` asks for the master's map: a
        // layout override below it does not apply (FIX 8575).
        if child(tree, over, A, "masterClrMapping").is_some() {
            return master_map(context);
        }
    }
    master_map(context)
}

/// The master's `p:clrMap`.
fn master_map<'a>(context: &'a SlideContext<'_>) -> Option<(&'a XmlTree, usize)> {
    let tree = context.tree(context.master?)?;
    child(tree, 0, P, "clrMap").map(|map| (tree, map))
}

fn hex(value: &str) -> Option<[u8; 3]> {
    if value.len() != 6 || !value.is_ascii() {
        return None;
    }
    let byte = |at: usize| u8::from_str_radix(&value[at..at + 2], 16).ok();
    Some([byte(0)?, byte(2)?, byte(4)?])
}

fn to_hsl(rgb: [u8; 3]) -> (f64, f64, f64) {
    let [r, g, b] = rgb.map(|c| f64::from(c) / 255.0);
    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    let lightness = (max + min) / 2.0;
    let delta = max - min;
    if delta == 0.0 {
        return (0.0, 0.0, lightness);
    }
    let saturation = if lightness > 0.5 {
        delta / (2.0 - max - min)
    } else {
        delta / (max + min)
    };
    let hue = if max == r {
        (g - b) / delta + if g < b { 6.0 } else { 0.0 }
    } else if max == g {
        (b - r) / delta + 2.0
    } else {
        (r - g) / delta + 4.0
    };
    (hue / 6.0, saturation, lightness)
}

fn from_hsl(hue: f64, saturation: f64, lightness: f64) -> [u8; 3] {
    let channel = |value: f64| (value.clamp(0.0, 1.0) * 255.0).round() as u8;
    if saturation == 0.0 {
        return [channel(lightness); 3];
    }
    let q = if lightness < 0.5 {
        lightness * (1.0 + saturation)
    } else {
        lightness + saturation - lightness * saturation
    };
    let p = 2.0 * lightness - q;
    let part = |mut t: f64| {
        if t < 0.0 {
            t += 1.0;
        }
        if t > 1.0 {
            t -= 1.0;
        }
        if t < 1.0 / 6.0 {
            p + (q - p) * 6.0 * t
        } else if t < 0.5 {
            q
        } else if t < 2.0 / 3.0 {
            p + (q - p) * (2.0 / 3.0 - t) * 6.0
        } else {
            p
        }
    };
    [
        channel(part(hue + 1.0 / 3.0)),
        channel(part(hue)),
        channel(part(hue - 1.0 / 3.0)),
    ]
}
