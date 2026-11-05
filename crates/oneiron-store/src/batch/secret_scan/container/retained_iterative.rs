//! The container walk and rebuild with their frames on the heap (FIX 8031,
//! 7943): each container's frame held here rather than on the thread's
//! stack, so a file of distinct nested containers is read whole at any depth
//! without running that stack out. No depth or count bound holds (rule 5);
//! a container met inside itself is a cycle, and the bounded read's byte
//! floor is its budget's. Every read comes here: the write door's, the
//! release and serving doors' and the retained repository read.
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
//! What it does at each place is its leaf transform's
//! ([`RetainedLeafTransform`]): masking fills the place's spans, a serving
//! copy's text member taking each key's handle text (FIX 7944), and a
//! projection edit replays a member's edit onto its original (FIX 7608
//! 2b-ii), over this one traversal and these readers.

use crate::batch::secret_scan::container::Budget;
use crate::batch::secret_scan::container::Kind;
use crate::batch::secret_scan::container::Stop;
use crate::batch::secret_scan::container::Walked;
use crate::batch::secret_scan::container::archive;
use crate::batch::secret_scan::container::classify;
use crate::batch::secret_scan::container::gzip;
use crate::batch::secret_scan::container::over_budget;
use crate::batch::secret_scan::container::pdf;
use crate::batch::secret_scan::container::tar;
use crate::batch::secret_scan::container::writes_handles;
use crate::batch::secret_scan::container::xz;
use crate::file_secret_marks::KeyPlaces;
use crate::file_secret_marks::MemberStep;
use crate::file_secret_marks::PlaceHandles;
use crate::file_secret_marks::filled;
use crate::file_secret_marks::filled_with;
use oneiron_base::error::Error;

/// What the walk does next, the last frame first.
pub enum Frame {
    /// A member to hand to the visitor, then to walk when it is a container.
    Member(MemberStep, Vec<u8>),
    /// The stop a container's reader met after the members framed above it.
    Stopped(Stop),
    /// A container whose members are walked: the walk leaves it, and its
    /// step leaves the path (the file's own container has none).
    Leave,
}

/// What the retained rebuild does at each place it builds: the place's own
/// transform, and which members it goes down into.
pub trait RetainedLeafTransform {
    /// `bytes`, the place at `path`, once transformed.
    fn transform(&mut self, path: &[MemberStep], bytes: Vec<u8>) -> Walked<Vec<u8>>;
    /// Whether a place lies strictly under `path`.
    fn descends(&self, path: &[MemberStep]) -> bool;
    /// Whether `path` is a place or lies on the way to one.
    fn reaches(&self, path: &[MemberStep]) -> bool;
}

/// Masking's transform: each place's spans filled, or in a text member
/// replaced by the handle text `handles` gives a key (FIX 7944), `met`
/// counting the places met.
pub struct FillPlaces<'p> {
    pub places: &'p KeyPlaces,
    pub handles: Option<&'p PlaceHandles>,
    pub met: usize,
}

impl RetainedLeafTransform for FillPlaces<'_> {
    fn transform(&mut self, path: &[MemberStep], bytes: Vec<u8>) -> Walked<Vec<u8>> {
        let mut spans: Vec<((u64, u64), Option<&str>)> = Vec::new();
        for (index, (at, at_spans)) in self.places.iter().enumerate() {
            if at.as_slice() != path {
                continue;
            }
            let texts = self.handles.and_then(|handles| handles.get(index));
            spans.extend(at_spans.iter().enumerate().map(|(key, span)| {
                let text = texts
                    .and_then(|texts| texts.get(key))
                    .and_then(Option::as_deref);
                (*span, text)
            }));
            self.met += 1;
        }
        if spans.is_empty() {
            return Ok(bytes);
        }
        spans.sort_unstable_by_key(|(span, _)| *span);
        if self.handles.is_some() && writes_handles(path, &bytes) {
            return filled_with(&bytes, &spans).map_err(Stop::Fail);
        }
        filled(&bytes, spans.into_iter().map(|(span, _)| span)).map_err(Stop::Fail)
    }

    fn descends(&self, path: &[MemberStep]) -> bool {
        self.places
            .iter()
            .any(|(at, _)| at.len() > path.len() && at.starts_with(path))
    }

    fn reaches(&self, path: &[MemberStep]) -> bool {
        self.places.iter().any(|(at, _)| at.starts_with(path))
    }
}

/// The serving rebuild's transform (FIX 12279): transform nothing, enter
/// every container. `transform` sees each place's bytes before `descends`
/// is asked, so it records the paths that read as containers; every live
/// member is then built (a container rebuilt by its own reader, anything
/// else kept whole), so the bytes no reader shows are left out at every
/// level, not the root alone. A member inside hidden bytes is never read
/// as a live member, so it is dropped with them, never rebuilt.
#[derive(Default)]
pub struct RebuildAll {
    pub containers: Vec<Vec<MemberStep>>,
}

impl RetainedLeafTransform for RebuildAll {
    fn transform(&mut self, path: &[MemberStep], bytes: Vec<u8>) -> Walked<Vec<u8>> {
        if classify(&bytes).is_some() {
            self.containers.push(path.to_vec());
        }
        Ok(bytes)
    }

    fn descends(&self, path: &[MemberStep]) -> bool {
        self.containers.iter().any(|at| at.as_slice() == path)
    }

    fn reaches(&self, _path: &[MemberStep]) -> bool {
        true
    }
}
