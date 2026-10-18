//! The app properties (`docProps/app.xml`) a slide's addition, copy or
//! removal would leave stale (FIX 2377, FIX 2748): the slide, hidden-slide
//! and notes counts, the slide's title among the document's part titles, and
//! the words and paragraphs of the slides' text. Those titles are listed by
//! heading-pair groups. The slide titles are the group counting the deck's
//! slides (the last such group, as PowerPoint writes them after the fonts
//! and themes), and a slide's title sits at its list index there: a copy
//! lists its source's title, a blank slide [`UNTITLED`]. Words and paragraphs
//! are recounted over every slide's text ([`Text`]). Properties that do not
//! read so are left as they are: no reader opens a deck by them.
use super::super::super::media::related;
use super::super::super::xml::{self, Splice};
use crate::deck::{DeckView, SlideView};
use crate::edit::EditRefusal;
use crate::ooxml::{Node, XmlTree};
use crate::retained_opc::Package;

const EP: &str = "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties";
const VT: &str = "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes";

/// The title a slide with none is listed under, as English PowerPoint lists
/// it (CALLS "OF-510 deck app properties").
const UNTITLED: &str = "PowerPoint Presentation";

/// The words and paragraphs of slide text (CALLS "OF-510 deck app
/// properties"): every shape's text body, group members included; tables,
/// charts and notes are not counted. A paragraph counts when it holds a
/// character that is not white space, and its words are its runs' text
/// split on white space.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Text {
    words: u64,
    paragraphs: u64,
}

impl Text {
    /// One slide's text.
    pub(super) fn of_slide(slide: &SlideView) -> Self {
        let mut text = Self::default();
        for paragraph in slide
            .shapes
            .iter()
            .filter_map(|shape| shape.text.as_ref())
            .flat_map(|body| &body.paragraphs)
        {
            let words = paragraph
                .runs
                .iter()
                .map(|run| run.text.as_str())
                .collect::<String>()
                .split_whitespace()
                .count();
            if words > 0 {
                text.paragraphs = text.paragraphs.saturating_add(1);
                text.words = text
                    .words
                    .saturating_add(u64::try_from(words).unwrap_or(u64::MAX));
            }
        }
        text
    }

    /// Every slide's text in `view`.
    pub(super) fn of_deck(view: &DeckView) -> Self {
        view.slides
            .iter()
            .map(Self::of_slide)
            .fold(Self::default(), Self::plus)
    }

    pub(super) fn plus(self, other: Self) -> Self {
        Self {
            words: self.words.saturating_add(other.words),
            paragraphs: self.paragraphs.saturating_add(other.paragraphs),
        }
    }

    pub(super) fn less(self, other: Self) -> Self {
        Self {
            words: self.words.saturating_sub(other.words),
            paragraphs: self.paragraphs.saturating_sub(other.paragraphs),
        }
    }
}

/// The app properties after the removal of the slide at `index` of the
/// `count` the presentation listed, `hidden` or shown, with `notes` or none,
/// the deck holding `text` after it.
pub(super) fn slide_removed(
    next: &mut Package,
    index: usize,
    count: usize,
    (hidden, notes): (bool, bool),
    text: Text,
) -> Result<(), EditRefusal> {
    rewrite(next, |tree, _| {
        let mut edits = counts(tree, false, hidden, notes);
        edits.extend(title_removed(tree, index, count));
        edits.extend(text_edits(tree, text));
        edits
    })?;
    Ok(())
}

/// The app properties after a slide joined the `count` the presentation
/// listed, at `index` of the list after it, `hidden` or shown, with `notes`
/// or none, the deck holding `text` after it. A copy names its `source`'s
/// index, whose title it lists; a blank slide lists [`UNTITLED`].
pub(super) fn slide_added(
    next: &mut Package,
    (index, count): (usize, usize),
    (hidden, notes): (bool, bool),
    source: Option<usize>,
    text: Text,
) -> Result<(), EditRefusal> {
    rewrite(next, |tree, bytes| {
        let mut edits = counts(tree, true, hidden, notes);
        edits.extend(title_added(tree, bytes, (index, count), source));
        edits.extend(text_edits(tree, text));
        edits
    })?;
    Ok(())
}

/// The words and paragraphs of `view`, the deck `next` holds, written over
/// the app properties' counts: the live export's last write, after its text
/// edits. The part, when it changed.
pub(crate) fn recount_slide_text(
    next: &mut Package,
    view: &DeckView,
) -> Result<Option<String>, EditRefusal> {
    let text = Text::of_deck(view);
    rewrite(next, |tree, _| text_edits(tree, text))
}

/// The `Slides` count `package`'s app properties state, when they state one.
pub(in super::super) fn slide_count(package: &Package) -> Result<Option<u64>, EditRefusal> {
    let Some(part) = related(package, "", "extended-properties")? else {
        return Ok(None);
    };
    let Some(bytes) = package.part(&part)? else {
        return Ok(None);
    };
    let Ok(tree) = XmlTree::parse(&bytes, package.limits().xml) else {
        return Ok(None);
    };
    Ok(tree
        .child(0, EP, "Slides")
        .ok()
        .flatten()
        .and_then(|(_, node)| node.text.trim().parse().ok()))
}

/// Apply `edits` to the app properties, when the package has a part that
/// reads as them. The part, when it changed.
fn rewrite(
    next: &mut Package,
    edits: impl FnOnce(&XmlTree, &[u8]) -> Vec<Splice>,
) -> Result<Option<String>, EditRefusal> {
    let Some(part) = related(next, "", "extended-properties")? else {
        return Ok(None);
    };
    let Some(bytes) = next.part(&part)? else {
        return Ok(None);
    };
    let Ok(tree) = XmlTree::parse(&bytes, next.limits().xml) else {
        return Ok(None);
    };
    if tree.root(EP, "Properties").is_err() {
        return Ok(None);
    }
    let edits = edits(&tree, &bytes);
    if edits.is_empty() {
        return Ok(None);
    }
    next.replace_xml_part(&part, xml::splice(&bytes, edits)?)?;
    Ok(Some(part))
}

/// The count element `name` set to `value` of what it states, when it
/// states a number and that changes it.
fn count_edit(tree: &XmlTree, name: &str, value: impl FnOnce(u64) -> u64) -> Option<Splice> {
    let (_, node) = tree.child(0, EP, name).ok().flatten()?;
    let was = node.text.trim().parse::<u64>().ok()?;
    let now = value(was);
    (now != was).then(|| (node.content.clone(), now.to_string().into_bytes()))
}

/// The slide, hidden-slide and notes counts one more (`added`) or one less.
fn counts(tree: &XmlTree, added: bool, hidden: bool, notes: bool) -> Vec<Splice> {
    [("Slides", true), ("HiddenSlides", hidden), ("Notes", notes)]
        .into_iter()
        .filter(|&(_, moved)| moved)
        .filter_map(|(name, _)| {
            count_edit(tree, name, |was| {
                if added {
                    was.saturating_add(1)
                } else {
                    was.saturating_sub(1)
                }
            })
        })
        .collect()
}

/// The word and paragraph counts set to `text`.
fn text_edits(tree: &XmlTree, text: Text) -> Vec<Splice> {
    [("Words", text.words), ("Paragraphs", text.paragraphs)]
        .into_iter()
        .filter_map(|(name, now)| count_edit(tree, name, |_| now))
        .collect()
}

/// The slide titles' group in `TitlesOfParts`, read over `count` slides.
struct Titles<'t> {
    /// The group's count element.
    group: &'t Node,
    /// The group's first title among `names`.
    first: usize,
    names: Vec<&'t Node>,
    /// The `TitlesOfParts` vector.
    vector: &'t Node,
}

impl Titles<'_> {
    /// The group's `count` and the vector's size, one more (`added`) or one
    /// less.
    fn resized(&self, count: usize, added: bool) -> Vec<Splice> {
        let move_by = |n: usize| {
            if added {
                n.saturating_add(1)
            } else {
                n.saturating_sub(1)
            }
        };
        let mut edits = vec![(
            self.group.content.clone(),
            move_by(count).to_string().into_bytes(),
        )];
        if let Some(size) = self.vector.attr_spans.get("size") {
            edits.push((
                size.clone(),
                format!("size=\"{}\"", move_by(self.names.len())).into_bytes(),
            ));
        }
        edits
    }
}

/// The group listing the deck's `count` slide titles; none when the lists do
/// not read as groups over the titles.
fn titles(tree: &XmlTree, count: usize) -> Option<Titles<'_>> {
    let list = |name: &str| {
        tree.child(0, EP, name)
            .ok()
            .flatten()
            .and_then(|(at, _)| tree.child(at, VT, "vector").ok().flatten())
    };
    let ((pairs, _), (listed, vector)) = (list("HeadingPairs")?, list("TitlesOfParts")?);
    // Each group is a name variant then a count variant.
    let groups = tree
        .children(pairs)
        .filter_map(|(at, _)| tree.child(at, VT, "i4").ok().flatten())
        .map(|(_, node)| Some((node, node.text.trim().parse::<usize>().ok()?)))
        .collect::<Option<Vec<(&Node, usize)>>>()?;
    let names: Vec<&Node> = tree
        .children(listed)
        .map(|(_, node)| node)
        .filter(|node| node.is(VT, "lpstr"))
        .collect();
    if groups.iter().map(|&(_, n)| n).sum::<usize>() != names.len() {
        return None;
    }
    let group = groups.iter().rposition(|&(_, n)| n == count)?;
    Some(Titles {
        group: groups[group].0,
        first: groups[..group].iter().map(|&(_, n)| n).sum::<usize>(),
        names,
        vector,
    })
}

/// The removed slide's title out of `TitlesOfParts`, and its group's count
/// one less.
fn title_removed(tree: &XmlTree, index: usize, count: usize) -> Vec<Splice> {
    let Some(titles) = titles(tree, count) else {
        return Vec::new();
    };
    let Some(title) = titles.names.get(titles.first + index) else {
        return Vec::new();
    };
    let mut edits = vec![(title.span.clone(), Vec::new())];
    edits.extend(titles.resized(count, false));
    edits
}

/// The new slide's title into `TitlesOfParts` at `index`, and its group's
/// count one more: a copy of its `source`'s title, or [`UNTITLED`] written
/// as its neighbour's element is.
fn title_added(
    tree: &XmlTree,
    bytes: &[u8],
    (index, count): (usize, usize),
    source: Option<usize>,
) -> Vec<Splice> {
    if count == 0 || index > count {
        return Vec::new();
    }
    let Some(titles) = titles(tree, count) else {
        return Vec::new();
    };
    let model = source.unwrap_or_else(|| index.min(count - 1));
    let (Some(model), Some(last)) = (
        titles.names.get(titles.first + model),
        titles.names.get(titles.first + count - 1),
    ) else {
        return Vec::new();
    };
    let title = match source {
        Some(_) => bytes[model.span.clone()].to_vec(),
        None => {
            let mut title = xml::open_tag(bytes, model);
            title.extend(UNTITLED.as_bytes());
            title.extend(format!("</{}>", model.qualified).into_bytes());
            title
        }
    };
    let point = match titles.names.get(titles.first + index) {
        Some(next) if index < count => next.span.start,
        _ => last.span.end,
    };
    let mut edits = vec![(point..point, title)];
    edits.extend(titles.resized(count, true));
    edits
}
