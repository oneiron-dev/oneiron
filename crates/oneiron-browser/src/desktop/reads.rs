use super::*;

impl DesktopSession {
    /// The window the session reads, or else the one in front.
    fn window_key(&mut self) -> Result<WindowKey, BrowserError> {
        if let Some(key) = self.window {
            return Ok(key);
        }
        let key = front(&self.listed()?, |_| true).ok_or_else(no_window)?;
        self.window = Some(key);
        Ok(key)
    }

    /// Reads the session's window: its rows, and its screenshot with
    /// `shot`. A window gone since (a dialog closed) gives way to the window
    /// in front now, and the move is kept for the agent's next answer.
    pub(super) fn snapshot(&mut self, shot: bool) -> Result<Snapshot, BrowserError> {
        self.snapshot_on(shot, None, None)
    }

    /// Reads the session's window as [`Self::snapshot`] does, or, with
    /// `on`, walks on from a walk of it cut there, as [`Self::walk`] does,
    /// within `until`. A window gone since gives way to the window in front,
    /// read from the start, and the move is kept as [`Self::switch`] keeps
    /// it.
    pub(super) fn snapshot_on(
        &mut self,
        shot: bool,
        on: Option<&PartialTree>,
        until: Option<Instant>,
    ) -> Result<Snapshot, BrowserError> {
        let key = self.window_key()?;
        match self.walk(key, shot, on, until) {
            Ok(snapshot) => Ok(snapshot),
            Err(error) => {
                let listed = self.listed()?;
                if listed.iter().any(|window| window.key == key) {
                    return Err(error);
                }
                let front = front(&listed, |_| true).ok_or_else(no_window)?;
                self.switch(key, front, &listed, WindowSwitchCause::Closed);
                self.walk(front, shot, None, until)
            }
        }
    }

    /// The session moves from window `from` to window `to` (CUA-001), for
    /// `why`: `from` is gone, or an act opened `to` in front of it. The move
    /// is kept for the agent's next answer, joined with one it was not told
    /// of yet, from the window it was last told of.
    pub(super) fn switch(
        &mut self,
        from: WindowKey,
        to: WindowKey,
        listed: &[Listed],
        why: WindowSwitchCause,
    ) {
        self.window = Some(to);
        let from = self
            .switched
            .take()
            .map_or_else(|| from.name(), |earlier| earlier.from);
        let window = to.name();
        if from == window {
            return;
        }
        let (app, title) = listed
            .iter()
            .find(|listed| listed.key == to)
            .map(|listed| (listed.app.clone(), listed.title.clone()))
            .unwrap_or_default();
        self.switched = Some(WindowSwitch {
            window,
            app,
            title,
            from,
            why,
        });
    }

    /// Reads window `key` whole: a walk cua-driver cut at its node budget
    /// reads again with a larger budget, and one cut at its time budget with
    /// a longer one, up to [`WALK_MS_MOST`]. A walk still cut answers what
    /// it reached, with where it stopped as its `partial`. With `on`, it
    /// walks on from a walk cut there: one walk of four times its time, at
    /// least [`WALK_MS_MOST`] and at most [`WALK_ON_MS_MOST`], with a node
    /// budget past every node it saw, and no longer one after it. With
    /// `until`, a walk asks for no more time than is left before it (at
    /// least the driver's own second), and none follows once it passed.
    pub(super) fn walk(
        &self,
        key: WindowKey,
        shot: bool,
        on: Option<&PartialTree>,
        until: Option<Instant>,
    ) -> Result<Snapshot, BrowserError> {
        let (mut budget, mut walk_ms, most) = match on {
            None => (FIRST_BUDGET, None, WALK_MS_MOST),
            Some(cut) => {
                let ms = walk_on_ms(cut);
                let seen = cut.visited.saturating_add(cut.pending);
                (FIRST_BUDGET.max(seen.saturating_mul(2)), Some(ms), ms)
            }
        };
        let (reply, asked) = loop {
            let mut arguments = json!({
                "pid": key.pid,
                "window_id": key.id,
                "tree_format": "elements",
                "max_elements": budget,
            });
            let asked =
                walk_ms.map(|ms| until.map_or(ms, |until| ms.min(ms_left(until).max(1000))));
            if let Some(ms) = asked {
                arguments["timeout_ms"] = Value::from(ms);
            }
            if !shot {
                arguments["include_screenshot"] = Value::Bool(false);
            }
            // The call's bound leaves the walk its whole time.
            let bound = CALL + Duration::from_millis(asked.unwrap_or(0));
            let reply = self
                .mcp
                .tool("get_window_state", arguments, Instant::now() + bound)
                .map_err(BrowserError::from)?;
            let state = &reply.output;
            let count = |name: &str| state.get(name).and_then(Value::as_u64).unwrap_or(0);
            let cut = (state.get("truncated").and_then(Value::as_bool) == Some(true))
                .then(|| state.get("truncation_reason").and_then(Value::as_str))
                .flatten();
            let seen = count("nodes_visited").saturating_add(count("nodes_pending"));
            let spent = count("timeout_ms").max(asked.unwrap_or(1000));
            let late = until.is_some_and(|until| Instant::now() >= until);
            match cut {
                Some("node_budget") if !late => {
                    budget = budget.saturating_mul(2).max(seen.saturating_add(1));
                }
                Some("timeout") if spent < most && !late => {
                    walk_ms = Some(spent.saturating_mul(4).min(most));
                }
                _ => break (reply, asked),
            }
        };
        let state = &reply.output;
        let count = |name: &str| state.get(name).and_then(Value::as_u64).unwrap_or(0);
        let partial =
            (state.get("truncated").and_then(Value::as_bool) == Some(true)).then(|| PartialTree {
                reason: state
                    .get("truncation_reason")
                    .and_then(Value::as_str)
                    .unwrap_or("truncated")
                    .to_owned(),
                visited: count("nodes_visited"),
                pending: count("nodes_pending"),
                // At least the time the walk asked for, so each walk on
                // asks longer than the last.
                walk_ms: count("timeout_ms").max(asked.unwrap_or(1000)),
            });
        let elements = state
            .get("elements")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        let app = text_of(state, "app_name");
        let origin = url_of(&app, key);
        let view = SecretView {
            secrets: (!self.polling).then_some(&self.secrets),
            typed: &self.typed,
            origin: &origin,
        };
        let (lines, secrets) = lines(elements, &view);
        let shot = if shot {
            let png = reply.images.into_iter().next().ok_or_else(|| {
                BrowserError::Protocol("get_window_state sent no screenshot".to_owned())
            })?;
            // The driver names the ratio only when it shrank the image.
            let scale = state
                .get("frame_scale")
                .and_then(Value::as_f64)
                .filter(|scale| scale.is_finite() && *scale > 0.0)
                .unwrap_or(1.0);
            Some((png, scale))
        } else {
            None
        };
        Ok(Snapshot {
            key,
            app,
            title: text_of(state, "window_title"),
            bounds: state
                .get("window_bounds")
                .and_then(|bounds| Rect::read(bounds, "width", "height")),
            no_tree: lines.is_empty()
                || state.get("degraded").and_then(Value::as_bool) == Some(true),
            lines,
            secrets,
            partial,
            shot,
        })
    }

    pub(super) fn fingerprint(&mut self) -> Result<blake3::Hash, BrowserError> {
        self.polling = true;
        let read = self.snapshot(false);
        self.polling = false;
        print_of(&read?)
    }

    /// Waits for the window to settle after an action that began at `start`.
    pub(super) fn settle(
        &mut self,
        before: blake3::Hash,
        start: Instant,
    ) -> Result<(), BrowserError> {
        let mut last = before;
        let mut changed_at = None;
        loop {
            std::thread::sleep(POLL);
            let now = Instant::now();
            let print = self.fingerprint()?;
            if print != last {
                last = print;
                changed_at = Some(now);
            }
            let done = match changed_at {
                None => now - start >= REACTION,
                Some(at) => now - at >= QUIET,
            };
            if done || now - start >= SETTLE_CAP {
                return Ok(());
            }
        }
    }

    /// The session's window as it is now, whole or as an edit of `base`.
    pub(super) fn observation(&mut self, base: &Base) -> Result<Observation, BrowserError> {
        let snapshot = self.snapshot(false)?;
        Ok(self.observed(snapshot, base))
    }

    /// `snapshot` as the next observation, whole or as an edit of `base`:
    /// only of an observation of the same window, and only from a walk that
    /// reached the tree's end, since a partial one cannot tell a row gone
    /// from a row past its cut.
    fn observed(&mut self, snapshot: Snapshot, base: &Base) -> Observation {
        self.seq += 1;
        let read = Read {
            seq: self.seq,
            scope: format!(
                "window:{}.{}.{}",
                self.token, snapshot.key.pid, snapshot.key.id
            ),
            url: url_of(&snapshot.app, snapshot.key),
            // A secret the run's reads took shows its handle in the window's
            // title too (FIX 8340).
            title: self
                .secrets
                .mask_known(&snapshot.title)
                .unwrap_or(snapshot.title),
            rows: snapshot.lines.into_iter().map(|line| line.row).collect(),
            no_tree: snapshot.no_tree,
            partial: snapshot.partial,
        };
        self.pages.observe(read, base)
    }

    /// A longer walk of a partial observation's window (Rule 5): `cursor` is
    /// its `walk_next`. The window is walked again at four times the cut's
    /// time, and read as a new whole observation with its own seq, partial
    /// again when still cut. The walk reads the window as it is now.
    pub(super) fn walk_next(&mut self, cursor: &str) -> Result<Observation, BrowserError> {
        let (url, cut) = self.pages.walk_of(cursor)?;
        let key = window_of(&url, cursor)?;
        let snapshot = self.walk(key, false, Some(&cut), None)?;
        Ok(self.observed(snapshot, &Base::Whole))
    }

    /// `snapshot`, searched on for rows `wanted` admits (Rule 5): a read
    /// whose walk stopped before the tree's end and holds none walks its
    /// window on, longer each time, until one holds a wanted row, a walk
    /// reaches the tree's end, a walk on at [`WALK_ON_MS_MOST`] is still
    /// cut, or `until` passes. Only a read with no `partial` shows no row is
    /// wanted. The session's window walks on as [`Self::snapshot_on`] reads
    /// it; another window (a cut answer's) is walked on by its key.
    pub(super) fn search(
        &mut self,
        snapshot: Snapshot,
        until: Option<Instant>,
        wanted: impl Fn(&Row) -> bool,
    ) -> Result<Snapshot, BrowserError> {
        self.search_lines(snapshot, until, |line| wanted(&line.row))
    }

    /// [`Self::search`] for the lines `wanted` admits, where they are on
    /// screen too.
    fn search_lines(
        &mut self,
        mut snapshot: Snapshot,
        until: Option<Instant>,
        wanted: impl Fn(&Line) -> bool,
    ) -> Result<Snapshot, BrowserError> {
        // Whether the last walk on asked for the longest walk there is.
        let mut longest = false;
        loop {
            let Some(cut) = snapshot.partial.clone() else {
                return Ok(snapshot);
            };
            if longest
                || cut.walk_ms >= WALK_ON_MS_MOST
                || snapshot.lines.iter().any(&wanted)
                || until.is_some_and(|until| Instant::now() >= until)
            {
                return Ok(snapshot);
            }
            longest = walk_on_ms(&cut) >= WALK_ON_MS_MOST;
            snapshot = if self.window == Some(snapshot.key) {
                self.snapshot_on(false, Some(&cut), until)?
            } else {
                self.walk(snapshot.key, false, Some(&cut), until)?
            };
        }
    }

    /// The read an act on row `target` runs on (Rule 5): the session's
    /// window, searched on past a cut until a read holds the row. Only a
    /// read that reached the tree's end shows the row gone (`stale_ref`,
    /// from [`Self::token`]); a walk on still cut at its longest answers
    /// `desktop_tree_cut`. The act takes this last read's token with no
    /// read between, since each read retires the last one's tokens.
    pub(super) fn reach(&mut self, target: &str) -> Result<Snapshot, BrowserError> {
        let first = self.snapshot(false)?;
        let snapshot = self.search(first, None, |row| row.target == target)?;
        if snapshot.partial.is_some() && !snapshot.lines.iter().any(|l| l.row.target == target) {
            return Err(BrowserError::TreeCut(target.to_owned()));
        }
        Ok(snapshot)
    }

    /// A cut row answer's longer search (Rule 5): `cursor` is its
    /// `walk_next`. Its window is walked again, longer, and searched on for
    /// the same rows, as a new answer.
    pub(super) fn search_on(&mut self, cursor: &str) -> Result<Found, BrowserError> {
        let search = self.pages.search_of(cursor)?;
        let key = window_of(&search.url, cursor)?;
        let first = self.walk(key, false, Some(&search.cut), None)?;
        let snapshot = self.search(first, None, |row| search.query.matches(row))?;
        Ok(self.rows_of(snapshot, search.query))
    }

    /// The rows of `snapshot` that `query` matches, as a row answer's first
    /// page; a read still cut is held with its search, for its `walk_next`.
    pub(super) fn rows_of(&mut self, snapshot: Snapshot, query: WaitForInput) -> Found {
        let url = url_of(&snapshot.app, snapshot.key);
        let rows = snapshot
            .lines
            .into_iter()
            .map(|line| line.row)
            .filter(|row| query.matches(row))
            .collect();
        let search = snapshot.partial.map(|cut| Search { url, cut, query });
        self.pages.first_found(rows, search)
    }
}
