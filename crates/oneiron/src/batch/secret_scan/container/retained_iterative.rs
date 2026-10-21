//! The retained repository read's walk and rebuild with their frames on the
//! heap (FIX 8031): the same readers, the same order and the same stops as
//! the recursive `walk` and `rebuild` beside them, each container's frame
//! held here rather than on the thread's stack, so a blob of distinct nested
//! containers is read whole at any depth without running that stack out. No
//! depth, count or byte bound is added (rule 5); only the retained read
//! comes here, and the bounded read keeps its recursion, which its own depth
//! bound holds.
//!
//! A container's members are read one level at a time through its reader,
//! then walked in order, each handed to the visitor before anything under
//! it. A member ahead of every container at its level is handed over as its
//! reader yields it, so an archive of plain files is still held one member
//! at a time. A reader that stops partway leaves the members it read before
//! its stop to be walked first, so the keys they hold are still seen; then
//! its stop is the walk's. Each container is entered before its members are
//! read and left after them, so the cycle guard knows exactly the containers
//! the walk is inside, and a walk that stops leaves each it entered.
//!
//! The rebuild reads, the same way, the members a place lies under, builds
//! each from the bottom up, then has the container's reader read it again
//! and encode it around those members, handed back at their steps in order.

use super::{Budget, Kind, Stop, Walked, archive, gzip, kind, pdf};
use crate::error::Error;
use crate::secret_custody::{KeyPlaces, MemberStep, filled};

/// What the walk does next, the last frame first.
enum Frame {
    /// A member to hand to the visitor, then to walk when it is a container.
    Member(MemberStep, Vec<u8>),
    /// The stop a container's reader met after the members framed above it.
    Stopped(Stop),
    /// A container whose members are walked: the walk leaves it, and its
    /// step leaves the path (the file's own container has none).
    Leave,
}

/// `walk` over a retained repository read: every member under `bytes`,
/// depth first in each container's order, handed to `visit` with its path.
pub(super) fn walk(
    bytes: &[u8],
    budget: &mut Budget,
    visit: &mut dyn FnMut(&[MemberStep], &[u8]) -> Walked<()>,
) -> Walked<()> {
    let mut frames = Vec::new();
    let walked = walk_frames(bytes, budget, visit, &mut frames);
    // A stop ends the walk inside each container still framed to leave.
    for frame in &frames {
        if matches!(frame, Frame::Leave) {
            budget.leave_container();
        }
    }
    walked
}

fn walk_frames(
    bytes: &[u8],
    budget: &mut Budget,
    visit: &mut dyn FnMut(&[MemberStep], &[u8]) -> Walked<()>,
    frames: &mut Vec<Frame>,
) -> Walked<()> {
    let mut path = Vec::new();
    enter(bytes, &mut path, budget, visit, frames)?;
    while let Some(frame) = frames.pop() {
        match frame {
            Frame::Member(step, member) => {
                path.push(step);
                visit(path.as_slice(), member.as_slice())?;
                if !enter(&member, &mut path, budget, visit, frames)? {
                    path.pop();
                }
            }
            Frame::Stopped(stop) => return Err(stop),
            Frame::Leave => {
                budget.leave_container();
                path.pop();
            }
        }
    }
    Ok(())
}

/// Enters `bytes`, at `path`, when it is a container, and says whether it
/// was. Its members are read one level down: each ahead of every container
/// at that level is handed to `visit` as it is read, and the rest are
/// framed in order above the container's [`Frame::Leave`] and any stop its
/// reader met.
fn enter(
    bytes: &[u8],
    path: &mut Vec<MemberStep>,
    budget: &mut Budget,
    visit: &mut dyn FnMut(&[MemberStep], &[u8]) -> Walked<()>,
    frames: &mut Vec<Frame>,
) -> Walked<bool> {
    let Some(container) = kind(bytes) else {
        return Ok(false);
    };
    budget.enter_container(bytes)?;
    frames.push(Frame::Leave);
    let mut held: Vec<Frame> = Vec::new();
    let mut visitor_stopped = false;
    let mut each = |step: MemberStep, member: &[u8], _: &mut Budget| -> Walked<()> {
        if !held.is_empty() || kind(member).is_some() {
            held.push(Frame::Member(step, member.to_vec()));
            return Ok(());
        }
        path.push(step);
        let seen = visit(path.as_slice(), member);
        path.pop();
        visitor_stopped = seen.is_err();
        seen
    };
    let read = members(container, bytes, budget, &mut each);
    match read {
        Ok(()) => {}
        // The visitor's own stop, in order: no member was held before it.
        Err(stop) if visitor_stopped => return Err(stop),
        Err(stop) => frames.push(Frame::Stopped(stop)),
    }
    frames.extend(held.into_iter().rev());
    Ok(true)
}

/// A container the rebuild is inside: its bytes with their own spans
/// filled, which its reader reads again once its marked members are built;
/// the members still to build, the next one last; those built, in order;
/// and the stop its reader met after them.
struct Open {
    copy: Vec<u8>,
    container: Kind,
    pending: Vec<(MemberStep, Vec<u8>)>,
    built: Vec<(MemberStep, Vec<u8>)>,
    stop: Option<Stop>,
}

/// One place once its own spans are filled.
enum Opened {
    /// Nothing is marked under it: the filled bytes are its copy.
    Built(Vec<u8>),
    /// A container with marked members to build first.
    Open(Open),
}

/// `rebuild` over a retained repository read: `bytes` with each key
/// `places` names overwritten, every container on the way rebuilt by its
/// own reader. `met` counts the places met.
pub(super) fn rebuild(
    bytes: &[u8],
    places: &KeyPlaces,
    budget: &mut Budget,
    met: &mut usize,
) -> Walked<Vec<u8>> {
    let mut open = Vec::new();
    let rebuilt = rebuild_open(bytes, places, budget, met, &mut open);
    // A stop ends the rebuild inside each container still open.
    for _ in &open {
        budget.leave_container();
    }
    rebuilt
}

fn rebuild_open(
    bytes: &[u8],
    places: &KeyPlaces,
    budget: &mut Budget,
    met: &mut usize,
    open: &mut Vec<Open>,
) -> Walked<Vec<u8>> {
    let mut path = Vec::new();
    match start(bytes, &mut path, places, budget, met)? {
        Opened::Built(copy) => return Ok(copy),
        Opened::Open(file) => open.push(file),
    }
    while let Some(top) = open.last_mut() {
        if let Some((step, member)) = top.pending.pop() {
            path.push(step);
            match start(&member, &mut path, places, budget, met)? {
                Opened::Built(copy) => {
                    path.pop();
                    top.built.push((step, copy));
                }
                Opened::Open(container) => open.push(container),
            }
        } else if let Some(stop) = top.stop.take() {
            return Err(stop);
        } else if let Some(done) = open.pop() {
            // Its members are built: its reader's second read goes no
            // further down, so the walk is out of it.
            budget.leave_container();
            let copy = done.rebuilt(budget)?;
            let Some(step) = path.pop() else {
                // The file's own container.
                return Ok(copy);
            };
            if let Some(parent) = open.last_mut() {
                parent.built.push((step, copy));
            }
        }
    }
    Err(Stop::Fail(Error::InvariantViolation(
        "a masked container copy was left unbuilt",
    )))
}

/// The place at `path`: `bytes` with its own spans filled, built as it is
/// when no place lies under it, or else entered, with each member a place
/// lies under read one level down to build first.
fn start(
    bytes: &[u8],
    path: &mut Vec<MemberStep>,
    places: &KeyPlaces,
    budget: &mut Budget,
    met: &mut usize,
) -> Walked<Opened> {
    let mut copy = bytes.to_vec();
    for (_, spans) in places
        .iter()
        .filter(|(at, _)| at.as_slice() == path.as_slice())
    {
        copy = filled(&copy, spans.iter().copied())?;
        *met += 1;
    }
    if !places
        .iter()
        .any(|(at, _)| at.len() > path.len() && at.starts_with(path.as_slice()))
    {
        return Ok(Opened::Built(copy));
    }
    let container =
        kind(bytes).ok_or(Stop::Fail(Error::CorruptedIndex("masked file member path")))?;
    budget.enter_container(bytes)?;
    let mut pending: Vec<(MemberStep, Vec<u8>)> = Vec::new();
    let mut each = |step: MemberStep, member: &[u8], _: &mut Budget| -> Walked<()> {
        path.push(step);
        if places.iter().any(|(at, _)| at.starts_with(path.as_slice())) {
            pending.push((step, member.to_vec()));
        }
        path.pop();
        Ok(())
    };
    let read = members(container, &copy, budget, &mut each);
    pending.reverse();
    Ok(Opened::Open(Open {
        copy,
        container,
        pending,
        built: Vec::new(),
        stop: read.err(),
    }))
}

impl Open {
    /// The container its reader reads again and encodes around its built
    /// members, each handed back at its own step, in the order read.
    fn rebuilt(self, budget: &mut Budget) -> Walked<Vec<u8>> {
        let mut built = self.built.into_iter().peekable();
        let mut each = |step: MemberStep, _: &[u8], _: &mut Budget| -> Walked<Option<Vec<u8>>> {
            Ok(built.next_if(|(at, _)| *at == step).map(|(_, copy)| copy))
        };
        let copy = match self.container {
            Kind::Zip => archive::rebuilt(&self.copy, budget, &mut each),
            Kind::Gzip => gzip::rebuilt(&self.copy, budget, &mut each),
            Kind::Pdf => pdf::rebuilt(&self.copy, budget, &mut each),
        }?;
        if built.next().is_some() {
            return Err(Stop::Fail(Error::InvariantViolation(
                "a container's second read passed a built member by",
            )));
        }
        Ok(copy)
    }
}

/// Hands each member `container`'s reader reads in `bytes` to `each`.
fn members(
    container: Kind,
    bytes: &[u8],
    budget: &mut Budget,
    each: &mut dyn FnMut(MemberStep, &[u8], &mut Budget) -> Walked<()>,
) -> Walked<()> {
    match container {
        Kind::Zip => archive::members(bytes, budget, each),
        Kind::Gzip => gzip::members(bytes, budget, each),
        Kind::Pdf => pdf::members(bytes, budget, each),
    }
}
