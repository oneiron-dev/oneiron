//! One page through the ladder (ARCH-0077, "Layout selection"): a layout
//! chosen by capability; then a compatible layout with ordinary shapes under
//! the same theme; then a split where the page allows it; then a supported
//! composition; then a typed decision. Only blocks marked optional may be
//! left out, and only after the whole ladder failed with them.
use super::brief::{BlockContent, Brief, Division, Page, Priority};
use super::capability::{Carry, GUTTER, Need, Profile, Room, Template, fit};
use super::{Composition, Destination, Fallback, Rect, Shortfall, ShortfallReason};
use std::cmp::Reverse;

/// One planned slide before part names are allocated.
#[derive(Debug, Clone)]
pub(super) struct Draft {
    pub(super) layout: String,
    pub(super) fallback: Option<Fallback>,
    pub(super) split: Option<(usize, usize)>,
    pub(super) placements: Vec<Placed>,
}

/// A block (by index in its page) in a room, with the estimate behind it.
#[derive(Debug, Clone)]
pub(super) struct Placed {
    pub(super) block: usize,
    pub(super) carry: Carry,
    pub(super) destination: Destination,
    pub(super) need: i64,
    pub(super) room: i64,
}

pub(super) enum PageOutcome {
    /// The slides, and the indices of optional blocks left out.
    Slides(Vec<Draft>, Vec<usize>),
    Ask(Vec<Shortfall>),
}

/// Unused content placeholders, then room (more first), then template order.
type Rank = (usize, Reverse<i128>, usize);

#[derive(Debug, Clone, Copy)]
enum Arrangement {
    Columns,
    Rows,
}

struct Ladder<'a> {
    page: &'a Page,
    template: &'a Template,
    needs: Vec<Need<'a>>,
}

pub(super) fn plan_page(brief: &Brief, page: &Page, template: &Template) -> PageOutcome {
    let ladder = Ladder {
        page,
        template,
        needs: page
            .blocks
            .iter()
            .map(|block| Need::of(brief, block))
            .collect(),
    };
    let all: Vec<usize> = (0..page.blocks.len()).collect();
    if let Some(slides) = ladder.climb(&all) {
        return PageOutcome::Slides(slides, Vec::new());
    }
    let required: Vec<usize> = all
        .iter()
        .copied()
        .filter(|&block| page.blocks[block].priority == Priority::Required)
        .collect();
    if !required.is_empty()
        && required.len() < all.len()
        && let Some(slides) = ladder.climb(&required)
    {
        let omitted = all
            .into_iter()
            .filter(|block| !required.contains(block))
            .collect();
        return PageOutcome::Slides(slides, omitted);
    }
    PageOutcome::Ask(ladder.shortfalls())
}

impl Ladder<'_> {
    fn climb(&self, blocks: &[usize]) -> Option<Vec<Draft>> {
        let title = blocks
            .iter()
            .copied()
            .find(|&block| matches!(self.page.blocks[block].content, BlockContent::Title { .. }));
        let content: Vec<usize> = blocks
            .iter()
            .copied()
            .filter(|&block| Some(block) != title)
            .collect();
        if let Some(draft) = self.by_capability(title, &content) {
            return Some(vec![draft]);
        }
        if let Some(mut draft) = self.arranged(title, &content, Arrangement::Columns) {
            draft.fallback = Some(Fallback::OrdinaryShapes);
            return Some(vec![draft]);
        }
        if self.page.division == Division::Split
            && content.len() > 1
            && let Some(drafts) = self.split(title, &content)
        {
            return Some(drafts);
        }
        let mut draft = self.arranged(title, &content, Arrangement::Rows)?;
        draft.fallback = Some(Fallback::Composition(Composition::Rows));
        Some(vec![draft])
    }

    /// Every block fills a placeholder that suits it. Among the layouts that
    /// hold the page, the fewest unused placeholders win, then the most
    /// room, then template order.
    fn by_capability(&self, title: Option<usize>, content: &[usize]) -> Option<Draft> {
        let mut best: Option<(Rank, Draft)> = None;
        for (order, profile) in self.template.profiles.iter().enumerate() {
            let mut placements = Vec::new();
            if let Some(title) = title {
                let Some(placed) = self.title_in(title, profile) else {
                    continue;
                };
                placements.push(placed);
            }
            let fits: Vec<Vec<Option<(Carry, i64)>>> = content
                .iter()
                .map(|&block| {
                    profile
                        .content
                        .iter()
                        .map(|slot| fit(&self.needs[block], &self.template.slot(slot)))
                        .collect()
                })
                .collect();
            let Some(assigned) = assign(content.len(), profile.content.len(), |block, room| {
                fits[block][room].is_some()
            }) else {
                continue;
            };
            let mut area = 0i128;
            for (index, (&block, &room)) in content.iter().zip(&assigned).enumerate() {
                let slot = &profile.content[room];
                area += i128::from(slot.bounds.cx) * i128::from(slot.bounds.cy);
                let Some((carry, need)) = fits[index][room] else {
                    continue;
                };
                placements.push(Placed {
                    block,
                    carry,
                    destination: Destination::Placeholder {
                        placeholder: slot.placeholder.clone(),
                        shape: slot.shape.clone(),
                        bounds: slot.bounds,
                    },
                    need,
                    room: slot.bounds.cy,
                });
            }
            let key = (profile.content.len() - content.len(), Reverse(area), order);
            if best.as_ref().is_none_or(|(held, _)| key < *held) {
                best = Some((
                    key,
                    Draft {
                        layout: profile.layout.clone(),
                        fallback: None,
                        split: None,
                        placements,
                    },
                ));
            }
        }
        best.map(|(_, draft)| draft)
    }

    /// The title in the layout's first title placeholder it fits.
    fn title_in(&self, title: usize, profile: &Profile) -> Option<Placed> {
        profile.titles.iter().find_map(|slot| {
            let (carry, need) = fit(&self.needs[title], &self.template.slot(slot))?;
            Some(Placed {
                block: title,
                carry,
                destination: Destination::Placeholder {
                    placeholder: slot.placeholder.clone(),
                    shape: slot.shape.clone(),
                    bounds: slot.bounds,
                },
                need,
                room: slot.bounds.cy,
            })
        })
    }

    /// The title by role, every other block an ordinary shape in the
    /// layout's region, divided evenly. Layouts with the fewest content
    /// placeholders are tried first.
    fn arranged(
        &self,
        title: Option<usize>,
        content: &[usize],
        arrangement: Arrangement,
    ) -> Option<Draft> {
        if content.is_empty() {
            return None;
        }
        let mut profiles: Vec<_> = self.template.profiles.iter().enumerate().collect();
        profiles.sort_by_key(|(order, profile)| (profile.content.len(), *order));
        profiles.into_iter().find_map(|(_, profile)| {
            let mut placements = Vec::new();
            if let Some(title) = title {
                placements.push(self.title_in(title, profile)?);
            }
            let cells = divide(profile.region?, content.len(), arrangement)?;
            for (&block, cell) in content.iter().zip(cells) {
                let (carry, need) = fit(&self.needs[block], &self.template.area(cell))?;
                placements.push(Placed {
                    block,
                    carry,
                    destination: Destination::Shape { bounds: cell },
                    need,
                    room: cell.cy,
                });
            }
            Some(Draft {
                layout: profile.layout.clone(),
                fallback: None,
                split: None,
                placements,
            })
        })
    }

    /// Consecutive runs of content, each as long as one slide holds by
    /// capability or with ordinary shapes; the title repeats on each.
    fn split(&self, title: Option<usize>, content: &[usize]) -> Option<Vec<Draft>> {
        let mut drafts = Vec::new();
        let mut start = 0;
        while start < content.len() {
            let (end, draft) = (start + 1..=content.len()).rev().find_map(|end| {
                let run = &content[start..end];
                self.by_capability(title, run)
                    .or_else(|| self.arranged(title, run, Arrangement::Columns))
                    .map(|draft| (end, draft))
            })?;
            drafts.push(draft);
            start = end;
        }
        if drafts.len() < 2 {
            return None;
        }
        let count = drafts.len();
        for (index, draft) in drafts.iter_mut().enumerate() {
            draft.fallback = Some(Fallback::Split);
            draft.split = Some((index, count));
        }
        Some(drafts)
    }

    /// Why the page holds no plan: blocks no room suits or that overflow
    /// every room alone; failing those, every content block is crowded.
    fn shortfalls(&self) -> Vec<Shortfall> {
        let template = self.template;
        let mut rooms: Vec<Room<'_>> = Vec::new();
        for profile in &template.profiles {
            rooms.extend(profile.titles.iter().map(|slot| template.slot(slot)));
            rooms.extend(profile.content.iter().map(|slot| template.slot(slot)));
            rooms.extend(profile.region.map(|region| template.area(region)));
        }
        let mut found = Vec::new();
        for (block, need) in self.page.blocks.iter().zip(&self.needs) {
            let reason = if !rooms.iter().any(|room| need.suited(room.suits)) {
                ShortfallReason::NoSuitableSlot
            } else if !rooms.iter().any(|room| fit(need, room).is_some()) {
                ShortfallReason::Overflow
            } else {
                continue;
            };
            found.push(Shortfall {
                block: block.id.clone(),
                reason,
            });
        }
        if found.is_empty() {
            found = self
                .page
                .blocks
                .iter()
                .filter(|block| !matches!(block.content, BlockContent::Title { .. }))
                .map(|block| Shortfall {
                    block: block.id.clone(),
                    reason: ShortfallReason::Crowded,
                })
                .collect();
        }
        found
    }
}

/// `count` equal cells across (columns) or down (rows) `region`, a gutter
/// apart.
fn divide(region: Rect, count: usize, arrangement: Arrangement) -> Option<Vec<Rect>> {
    let n = i64::try_from(count).ok()?;
    let along = match arrangement {
        Arrangement::Columns => region.cx,
        Arrangement::Rows => region.cy,
    };
    let size = (along - (n - 1) * GUTTER) / n;
    if size <= 0 {
        return None;
    }
    Some(
        (0..n)
            .map(|index| {
                let start = index * (size + GUTTER);
                match arrangement {
                    Arrangement::Columns => Rect {
                        x: region.x + start,
                        cx: size,
                        ..region
                    },
                    Arrangement::Rows => Rect {
                        y: region.y + start,
                        cy: size,
                        ..region
                    },
                }
            })
            .collect(),
    )
}

/// A distinct room for every block (augmenting paths), trying blocks in
/// argument order and rooms in reading order. A free room is taken before an
/// earlier block is moved, so blocks keep reading order when they can.
fn assign(blocks: usize, rooms: usize, fits: impl Fn(usize, usize) -> bool) -> Option<Vec<usize>> {
    let edges: Vec<Vec<usize>> = (0..blocks)
        .map(|block| (0..rooms).filter(|&room| fits(block, room)).collect())
        .collect();
    let mut owner: Vec<Option<usize>> = vec![None; rooms];
    for block in 0..blocks {
        let mut seen = vec![false; rooms];
        if !augment(block, &edges, &mut owner, &mut seen) {
            return None;
        }
    }
    let mut assigned = vec![0; blocks];
    for (room, held) in owner.iter().enumerate() {
        if let Some(block) = held {
            assigned[*block] = room;
        }
    }
    Some(assigned)
}

fn augment(
    block: usize,
    edges: &[Vec<usize>],
    owner: &mut [Option<usize>],
    seen: &mut [bool],
) -> bool {
    if let Some(&room) = edges[block]
        .iter()
        .find(|&&room| !seen[room] && owner[room].is_none())
    {
        seen[room] = true;
        owner[room] = Some(block);
        return true;
    }
    for &room in &edges[block] {
        if seen[room] {
            continue;
        }
        seen[room] = true;
        let held = owner[room];
        if held.is_none_or(|held| augment(held, edges, owner, seen)) {
            owner[room] = Some(block);
            return true;
        }
    }
    false
}
