//! A rewritten chart's held and new series planned into its own workbook.
//! Entry: `Plan::held`, `Plan::added`.
//! Plan and its private state remain in the parent module.

use super::*;

impl Plan<'_> {
    /// A held series' sequences at its held references, grown or shrunk:
    /// its name in the first cell of its name's, its values, its categories
    /// (each level's line) or x values. The category set it planned and its
    /// lines, if it drew one.
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

    /// A new series' sequences: its categories the cells its set already
    /// took (else its template's, moved where another set holds them), its
    /// x values the template's where those cells already hold them, and
    /// its values, name and other x values shifted from the template's into
    /// the first free cells beside them. The category set it planned and
    /// its lines, when it planned one.
    pub(super) fn added(
        &mut self,
        template: &HeldRefs,
        want: &Want<'_>,
        shared: Option<&[Line]>,
        refs: &mut Refs,
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
        let Some(values) = &template.values else {
            return Ok(planned);
        };
        let name = template.name.as_ref().map(|name| name.line.head());
        let down = self.down_of(&values.line, name.as_ref());
        let Some(line) = values.line.fit(want.values.len(), down)? else {
            return Ok(planned);
        };
        let mut lines = vec![line];
        lines.extend(name.clone());
        lines.extend(x.as_ref().map(|(line, _, _)| line.clone()));
        let mut moved = self.room(&lines, down)?.into_iter();
        if let Some(line) = moved.next() {
            self.take(&line, want.values, true, &values.line)?;
            refs.values = Some(line.formula());
        }
        if let (Some(like), Some(line)) = (&name, name.as_ref().and_then(|_| moved.next())) {
            self.take(&line, &[Cell::Text(want.name.to_owned())], false, like)?;
            refs.name = Some(line.formula());
        }
        if let (Some((_, like, cells)), Some(line)) = (&x, moved.next()) {
            self.take(&line, cells, true, like)?;
            refs.first = Some(line.formula());
        }
        Ok(planned)
    }
}
