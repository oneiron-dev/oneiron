//! A rewritten chart's held and new series planned into its own workbook:
//! each sequence at its own cells, a bubble series' sizes beside its values,
//! and a literal or absent slot given the first free cells beside the
//! chart's (FIX 6400).
//! Entry: `Plan::held`, `Plan::gaps`, `Plan::added`.
//! Plan and its private state remain in the parent module.

use super::*;

impl Plan<'_> {
    /// A held series' sequences at its held references, grown or shrunk:
    /// its name in the first cell of its name's, its values, its bubble
    /// sizes, its categories (each level's line) or x values. The category
    /// set it planned and its lines, if it drew one.
    pub(super) fn held(
        &mut self,
        held: &HeldRefs,
        want: &Want<'_>,
        refs: &mut Refs,
    ) -> Result<Option<(usize, Vec<Line>)>, RebuildReason> {
        if let Some(name) = &held.name {
            let line = name.line.head();
            self.take(
                &line,
                &[Cell::Text(want.name.to_owned())],
                false,
                &name.line,
            )?;
            self.names.extend(line.keys());
            refs.name = Some(name.to(&line));
        }
        if let Some(values) = &held.values {
            let down = self.down_of(&values.line, held.name.as_ref().map(|name| &name.line));
            if let Some(line) = self.grown(&values.line, want.values.len(), down)? {
                self.take(&line, want.values, true, &values.line)?;
                refs.values = Some(values.to(&line));
            }
        }
        if let (Some(size), Some(cells)) = (&held.size, want.size) {
            let down = self.down_of(&size.line, None);
            if let Some(line) = self.grown(&size.line, cells.len(), down)? {
                self.take(&line, cells, true, &size.line)?;
                refs.size = Some(size.to(&line));
            }
        }
        let (Some(at), Some(first)) = (&held.first, &want.first) else {
            return Ok(None);
        };
        if at.levels.len() != first.levels.len() {
            return Err(RebuildReason::LevelsChanged);
        }
        let down = at.down.unwrap_or_else(|| self.down_of(&at.line, None));
        let mut grown = Vec::with_capacity(at.levels.len());
        for line in &at.levels {
            match self.grown(line, first.count(), down)? {
                Some(line) => grown.push(line),
                None => return Ok(None),
            }
        }
        let lines = self.place(first, grown, &at.levels, down)?;
        refs.first = at.to_block(&lines);
        Ok(first.set.map(|set| (set, lines)))
    }

    /// A line of `count` cells running `down` from `like`'s first cell,
    /// moved to the first free cells beside it. `None` for no cells.
    fn beside(&self, like: &Line, count: usize, down: bool) -> Result<Option<Line>, RebuildReason> {
        let Some(line) = like.head().fit(count, down)? else {
            return Ok(None);
        };
        Ok(self.room(&[line], down)?.into_iter().next())
    }

    /// The cell a series' name takes beside its values `line`: the one
    /// before its first, when it is free, else the first free one beside.
    fn name_cell(&self, line: &Line, down: bool) -> Result<Option<Line>, RebuildReason> {
        let (col, row) = line.first;
        let before = if down {
            row.checked_sub(1)
                .filter(|row| *row > 0)
                .map(|row| (col, row))
        } else {
            col.checked_sub(1)
                .filter(|col| *col > 0)
                .map(|col| (col, row))
        };
        if let Some(first) = before
            && self.free(&(line.sheet.clone(), first.0, first.1), false)
        {
            return Ok(Some(Line {
                sheet: line.sheet.clone(),
                first,
                last: first,
            }));
        }
        self.beside(line, 1, down)
    }

    /// Plan a series' name into a cell of its own beside its values.
    fn name_beside(
        &mut self,
        values: &Line,
        down: bool,
        name: &str,
        refs: &mut Refs,
    ) -> Result<(), RebuildReason> {
        if let Some(cell) = self.name_cell(values, down)? {
            self.take(&cell, &[Cell::Text(name.to_owned())], false, values)?;
            refs.name = Some(cell.formula());
        }
        Ok(())
    }

    /// A held series' literal or absent slots given cells of their own, as
    /// Edit Data gives them (FIX 6400): its values beside the chart's cells
    /// (`anchor`) when it has none, its name before its values, its x
    /// values, its bubble sizes and a flat category set no series has cells
    /// for beside its values. Each keeps its points; a slot with cells keeps
    /// its reference. The category set it planned and its line, if any.
    pub(super) fn gaps(
        &mut self,
        held: &HeldRefs,
        want: &Want<'_>,
        refs: &mut Refs,
        anchor: Option<&Line>,
    ) -> Result<Option<(usize, Vec<Line>)>, RebuildReason> {
        let own = held.values.as_ref().map(|values| values.line.clone());
        let Some(base) = own.clone().or_else(|| anchor.cloned()) else {
            return Ok(None);
        };
        let down = self.down_of(&base, held.name.as_ref().map(|name| &name.line));
        let mut values = own;
        if refs.values.is_none()
            && let Some(line) = self.beside(&base, want.values.len(), down)?
        {
            self.take(&line, want.values, true, &base)?;
            refs.values = Some(line.formula());
            values = Some(line);
        }
        let Some(values) = values else {
            return Ok(None);
        };
        if refs.name.is_none() && !want.name.is_empty() {
            self.name_beside(&values, down, want.name, refs)?;
        }
        if let (None, Some(size)) = (&refs.size, want.size)
            && let Some(line) = self.beside(&values, size.len(), down)?
        {
            self.take(&line, size, true, &values)?;
            refs.size = Some(line.formula());
        }
        let Some(first) = want.first.as_ref().filter(|first| first.levels.len() == 1) else {
            return Ok(None);
        };
        if refs.first.is_some() {
            return Ok(None);
        }
        let Some(line) = self.beside(&values, first.count(), down)? else {
            return Ok(None);
        };
        let lines = self.place(first, vec![line.clone()], &[line], down)?;
        refs.first = Line::around(&lines).map(|line| line.formula());
        Ok(first.set.map(|set| (set, lines)))
    }

    /// A new series' sequences: its categories the cells its set already
    /// took (else its template's, moved where another set holds them), its
    /// x values the template's where those cells already hold them, and
    /// its values, name, bubble sizes and other x values shifted from the
    /// template's into the first free cells beside them. A slot the
    /// template holds no cells for takes cells beside the new values, and
    /// values whose template has none start from the chart's (`anchor`), as
    /// Edit Data gives them (FIX 6400). The category set it planned and its
    /// lines, when it planned one.
    pub(super) fn added(
        &mut self,
        template: &HeldRefs,
        want: &Want<'_>,
        shared: Option<&[Line]>,
        refs: &mut Refs,
        anchor: Option<&Line>,
    ) -> Result<Option<(usize, Vec<Line>)>, RebuildReason> {
        let mut x = None;
        let mut planned = None;
        match (&want.first, shared, &template.first) {
            (Some(first), Some(lines), _) if first.set.is_some() => {
                self.fill(lines, first)?;
                refs.first = Line::around(lines).map(|line| line.formula());
            }
            (Some(first), _, Some(at)) if first.set.is_some() => {
                if at.levels.len() != first.levels.len() {
                    return Err(RebuildReason::LevelsChanged);
                }
                let down = at.down.unwrap_or_else(|| self.down_of(&at.line, None));
                let mut grown = Vec::with_capacity(at.levels.len());
                for line in &at.levels {
                    grown.extend(self.grown(line, first.count(), down)?);
                }
                if grown.len() == at.levels.len() {
                    let lines = self.place(first, grown, &at.levels, down)?;
                    refs.first = Line::around(&lines).map(|line| line.formula());
                    planned = first.set.map(|set| (set, lines));
                }
            }
            (Some(first), _, Some(at)) => {
                let down = self.down_of(&at.line, None);
                let cells = first.levels.first().map_or(&[][..], Vec::as_slice);
                match at.line.fit(cells.len(), down)? {
                    Some(line) if self.holds(&line, cells) => {
                        self.take(&line, cells, first.numeric, &at.line)?;
                        refs.first = Some(line.formula());
                    }
                    Some(line) => x = Some((line, at.line.clone(), cells)),
                    None => {}
                }
            }
            _ => {}
        }
        let like = template
            .values
            .as_ref()
            .map(|values| values.line.clone())
            .or_else(|| anchor.cloned());
        let Some(like) = like else {
            return Ok(planned);
        };
        let name = template.name.as_ref().map(|name| name.line.head());
        let down = self.down_of(&like, name.as_ref());
        let Some(line) = like.head().fit(want.values.len(), down)? else {
            return Ok(planned);
        };
        let size = match (&template.size, want.size) {
            (Some(held), Some(cells)) => held
                .line
                .fit(cells.len(), down)?
                .map(|line| (line, held.line.clone())),
            _ => None,
        };
        let mut lines = vec![line];
        lines.extend(name.clone());
        lines.extend(x.as_ref().map(|(line, _, _)| line.clone()));
        lines.extend(size.as_ref().map(|(line, _)| line.clone()));
        let mut moved = self.room(&lines, down)?.into_iter();
        let Some(values) = moved.next() else {
            return Ok(planned);
        };
        self.take(&values, want.values, true, &like)?;
        refs.values = Some(values.formula());
        if let (Some(like), Some(line)) = (&name, name.as_ref().and_then(|_| moved.next())) {
            self.take(&line, &[Cell::Text(want.name.to_owned())], false, like)?;
            refs.name = Some(line.formula());
        }
        if let (Some((_, like, cells)), Some(line)) = (&x, moved.next()) {
            self.take(&line, cells, true, like)?;
            refs.first = Some(line.formula());
        }
        if let (Some((_, like)), Some(cells), Some(line)) = (&size, want.size, moved.next()) {
            self.take(&line, cells, true, like)?;
            refs.size = Some(line.formula());
        }
        if refs.name.is_none() && !want.name.is_empty() {
            self.name_beside(&values, down, want.name, refs)?;
        }
        if let (None, Some(cells)) = (&refs.size, want.size)
            && let Some(line) = self.beside(&values, cells.len(), down)?
        {
            self.take(&line, cells, true, &values)?;
            refs.size = Some(line.formula());
        }
        if refs.first.is_none()
            && planned.is_none()
            && let Some(first) = want.first.as_ref().filter(|first| first.levels.len() == 1)
            && let Some(line) = self.beside(&values, first.count(), down)?
        {
            let lines = self.place(first, vec![line.clone()], &[line], down)?;
            refs.first = Line::around(&lines).map(|line| line.formula());
            planned = first.set.map(|set| (set, lines));
        }
        Ok(planned)
    }
}
