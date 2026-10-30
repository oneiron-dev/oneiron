//! A click at a point of a held screenshot (OF-523; FIX 5740, FIX 5741).
//!
//! The row under the point judges the press (Rule 5). A read still cut
//! walks the window on, longer each time, while the smallest row covering
//! the point is missing or the read ends inside its subtree: a container
//! (a menu, a list, a page tab) may hold the control at the point past the
//! cut. The walk ends on a resolved row, a read of the whole tree, or the
//! longest walk there is; at that last stop an unresolved row, or none,
//! takes the gate's floor, a person's press, never the container's class.
//! A resolved control still takes its own grant, and a whole read's rows
//! judge as before.
//!
//! Every walk reads the window's pixels too, and only the final read is
//! checked against the held image (its window, its place, its scale and
//! the masked square under the point), once, after the walk and before the
//! press is judged or any input goes: a changed target never takes input
//! the old image authorized. A mismatch is `stale_image`, with no click.

use super::{
    Base, DesktopSession, Snapshot, WALK_ON_MS_MOST, effect_class, floor_press, looks_as_it_did,
    mask, receipt_class, walk_on_ms,
};
use crate::{BrowserError, Observation, PointInput};
use serde_json::json;
use std::time::Instant;

impl DesktopSession {
    /// Clicks screen point `input` names on its held image, judged by the
    /// row under it on the final read, which the image's check reads too.
    pub(super) fn click_point(&mut self, input: PointInput) -> Result<Observation, BrowserError> {
        let started = Instant::now();
        self.live()?;
        let (_, frame) = self.held(&input.image)?;
        if !(0.0..=1.0).contains(&input.x) || !(0.0..=1.0).contains(&input.y) {
            return Err(BrowserError::Input(
                "a point is two fractions of its image, each from 0 to 1".to_owned(),
            ));
        }
        let x = frame.left + input.x * frame.width;
        let y = frame.top + input.y * frame.height;
        // The driver's window pixels are its screenshot's, from the
        // window's corner.
        let bounds = frame.bounds;
        let across =
            ((x - bounds.x) * frame.scale).clamp(0.0, (bounds.w * frame.scale - 1.0).max(0.0));
        let down =
            ((y - bounds.y) * frame.scale).clamp(0.0, (bounds.h * frame.scale - 1.0).max(0.0));
        let first = self.snapshot(true)?;
        let mut read = self.reach_point(first, x, y)?;
        // The image must still show the window as it stands on the final
        // read: the same window, in the same place. A walk that gave way to
        // another window leaves the image stale.
        if read.key != frame.window || !read.bounds.is_some_and(|now| now.same(frame.bounds)) {
            return Err(BrowserError::StaleImage(input.image));
        }
        // And the spot must still look as it did: a scroll or a redraw in
        // place leaves the window where it was but moves what is under the
        // point. The read is masked as the image was, so secret fields match.
        let (now, scale) = read.shot.take().ok_or_else(|| {
            BrowserError::Protocol("get_window_state sent no screenshot".to_owned())
        })?;
        let now = mask(now, bounds, scale, &read.secrets)?;
        if (scale - frame.scale).abs() > f64::EPSILON
            || !looks_as_it_did(&frame.source, &now, across, down)?
        {
            return Err(BrowserError::StaleImage(input.image));
        }
        let line = read.line_at(x, y);
        // A read still cut at its longest walk, with no row under the
        // point or one it ends inside, takes the floor.
        if read.partial.is_some() && !line.is_some_and(|line| line.closed) {
            return Err(floor_press(x, y));
        }
        let row = line.map(|line| line.row.clone());
        let class = row.as_ref().and_then(|row| effect_class(&row.name));
        let press = self.press_or_hold("click_at", &input, class, row.as_ref(), &read)?;
        let key = read.key;
        let acted = self.act(&read, &Base::of(input.base), |session| {
            session
                .input(
                    "click",
                    json!({"pid": key.pid, "window_id": key.id, "x": across.round(), "y": down.round()}),
                )
                .map_err(BrowserError::from)
        });
        let class = receipt_class(class, row.as_ref());
        self.sent(
            "click_at",
            &read,
            row.as_ref(),
            class,
            press,
            started,
            acted,
        )
    }

    /// `snapshot`, walked on while it is cut and the point's row is not
    /// resolved (FIX 5740): the smallest row covering screen point (`x`,
    /// `y`) missing, or its subtree not closed. Never a larger closed row
    /// in a smaller unresolved one's place. Every walk reads the window's
    /// pixels (FIX 5741). Ends on a resolved row, a whole read, or the
    /// walk on at its longest, as an act's search does.
    fn reach_point(
        &mut self,
        mut snapshot: Snapshot,
        x: f64,
        y: f64,
    ) -> Result<Snapshot, BrowserError> {
        // Whether the last walk on asked for the longest walk there is.
        let mut longest = false;
        loop {
            let Some(cut) = snapshot.partial.clone() else {
                return Ok(snapshot);
            };
            let resolved = snapshot.line_at(x, y).is_some_and(|line| line.closed);
            if resolved || longest || cut.walk_ms >= WALK_ON_MS_MOST {
                return Ok(snapshot);
            }
            longest = walk_on_ms(&cut) >= WALK_ON_MS_MOST;
            snapshot = if self.window == Some(snapshot.key) {
                self.snapshot_on(true, Some(&cut), None)?
            } else {
                self.walk(snapshot.key, true, Some(&cut), None)?
            };
        }
    }
}
