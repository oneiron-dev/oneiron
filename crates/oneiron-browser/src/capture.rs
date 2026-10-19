//! Repeat screenshots (AB-004). Every screenshot an agent's verb takes is a
//! capture with an id of its own, `c<token>:<n>`: `token` is the session's
//! and `n` comes from one counter for the whole session, never reset or
//! reused, so an id from another session never names one of this session's.
//!
//! A screenshot that names an earlier capture (`since_capture`) is still
//! taken, masked, held and answered whole. It also names that capture as
//! `unchanged_from` when its masked PNG is byte for byte the earlier one's
//! (the two content refs are equal) and both were taken in one scope: the
//! same documents and URL (or the same window), the same viewport (or
//! window rectangle), scroll, dimensions and scale, and the same masking.
//! That says the two images are the same PNG, nothing more: not that the
//! page did nothing. Equal pixels encoded otherwise read as changed; nothing
//! compares decoded pixels or how alike two images look. Only a screenshot
//! is a capture, so a crop or zoom never compares with one. A capture no
//! longer held, of another scope, or one this session never took answers as
//! any screenshot does, never a refusal. A receipt's screenshot never
//! compares: each receipt's is a capture of its own, kept as its evidence
//! even when its pixels repeat an earlier one's.

use crate::{ScreenshotInput, ScreenshotTrigger};

/// What every screenshot an agent's verb takes masks: each secret field the
/// page or window shows is blacked out before the image is held. The
/// owner's unmasked screen is never a capture.
pub(crate) const MASKING: &str = "secret_fields";

/// Where a capture was taken, as a later one must match to compare.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Scope {
    /// What it shows: a page's documents and its URL, or a session's
    /// window.
    pub(crate) shows: String,
    /// The rectangle it shows, in CSS or screen pixels: left, top, width
    /// and height.
    pub(crate) rect: [f64; 4],
    /// The page's scroll offset; none for a window, whose scroll is in its
    /// pixels.
    pub(crate) scroll: Option<(f64, f64)>,
    /// The image's width and height in pixels.
    pub(crate) size: (u32, u32),
    /// The image's pixels per CSS or screen pixel.
    pub(crate) scale: f64,
    pub(crate) masking: &'static str,
}

/// A held screenshot's capture: its id, and the scope it was taken in; none
/// when the page's documents moved while it was taken, so it never
/// compares.
#[derive(Clone, Debug)]
pub(crate) struct Capture {
    pub(crate) id: String,
    scope: Option<Scope>,
}

/// One session's capture ids.
pub(crate) struct Captures {
    token: String,
    /// The last capture's number.
    last: u64,
}

impl Captures {
    pub(crate) fn new(token: &str) -> Self {
        Self {
            token: token.to_owned(),
            last: 0,
        }
    }

    /// A new capture taken in `scope`, under the session's next id.
    pub(crate) fn next(&mut self, scope: Option<Scope>) -> Capture {
        self.last = self.last.saturating_add(1);
        Capture {
            id: format!("c{}:{}", self.token, self.last),
            scope,
        }
    }
}

/// The capture a screenshot taken for `input` compares with: the one it
/// names, unless it is a receipt's.
pub(crate) fn compared(input: &ScreenshotInput) -> Option<&str> {
    input
        .since_capture
        .as_deref()
        .filter(|_| input.trigger != ScreenshotTrigger::EffectReceipt)
}

/// What capture `now`, whose masked PNG's content ref is `image`, says of
/// `base`, the held capture its screenshot named, with that one's content
/// ref: `base`'s id when the two are the same PNG, taken in one scope.
pub(crate) fn unchanged_from(
    base: Option<(String, Capture)>,
    image: &str,
    now: &Capture,
) -> Option<String> {
    let (held, base) = base?;
    (held == image && base.scope.is_some() && base.scope == now.scope).then_some(base.id)
}
