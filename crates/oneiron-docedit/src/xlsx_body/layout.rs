//! Worksheet layout and pivot/formula retargeting.
//! Entry: `Book::relayout`.
//! Definitions live here; xlsx_body retains the old API and shared Book state.

use super::*;

impl Book {
    /// Write a sheet layout: rename, reorder, add and delete worksheets in the
    /// sheet list; carry each defined name's scope and the workbook view's
    /// tabs to the new order, dropping names local to a deleted sheet; and
    /// retarget every formula, chart range and hyperlink that names a renamed
    /// or deleted sheet. A deleted sheet's parts leave with it unless another
    /// part still reaches them. A chart or dialog sheet stays after the
    /// worksheet it followed.
    pub(super) fn relayout(&mut self, plan: &[XlsxSheetPlan]) -> Result<()> {
        let mut taken = HashSet::new();
        let mut kept = HashSet::new();
        for slot in plan {
            check_sheet_name(&slot.name)?;
            if !taken.insert(slot.name.to_lowercase()) {
                return Err(refused("two sheets share a name"));
            }
            if let Some(source) = &slot.source
                && (!self.worksheets.contains_key(source) || !kept.insert(source.as_str()))
            {
                return Err(refused(
                    "a sheet layout names an imported worksheet twice or not at all",
                ));
            }
        }
        if plan.is_empty() {
            return Err(refused("a workbook keeps at least one worksheet"));
        }
        if self
            .order
            .iter()
            .any(|name| !self.worksheets.contains_key(name) && taken.contains(&name.to_lowercase()))
        {
            return Err(refused("two sheets share a name"));
        }
        let bytes = self
            .package
            .part(&self.part)?
            .ok_or(refused("the workbook part is missing"))?;
        let tree = XmlTree::parse(&bytes, self.package.limits().xml)?;
        let (list, list_node) = tree
            .child(0, SML, "sheets")?
            .ok_or(refused("the workbook has no sheet list"))?;
        let entries: Vec<_> = tree
            .children(list)
            .filter(|(_, node)| node.is(SML, "sheet"))
            .map(|(_, node)| node)
            .collect();
        // The final order: (index in the old order, name, visibility),
        // `None` for a new worksheet.
        let mut layout: Vec<(Option<usize>, String, XlsxSheetVisibility)> = Vec::new();
        let kept_state = |at: usize| XlsxSheetVisibility::from_state(entries[at].attr("state"));
        {
            let mut followers: HashMap<Option<&str>, Vec<usize>> = HashMap::new();
            let mut anchor = None;
            for (at, name) in self.order.iter().enumerate() {
                if !self.worksheets.contains_key(name) {
                    followers.entry(anchor).or_default().push(at);
                } else if kept.contains(name.as_str()) {
                    anchor = Some(name.as_str());
                }
            }
            for at in followers.remove(&None).unwrap_or_default() {
                layout.push((Some(at), self.order[at].clone(), kept_state(at)));
            }
            for slot in plan {
                let Some(source) = &slot.source else {
                    layout.push((None, slot.name.clone(), slot.visibility));
                    continue;
                };
                let at = self
                    .order
                    .iter()
                    .position(|name| name == source)
                    .ok_or(refused("no such worksheet"))?;
                layout.push((Some(at), slot.name.clone(), slot.visibility));
                for at in followers.remove(&Some(source.as_str())).unwrap_or_default() {
                    layout.push((Some(at), self.order[at].clone(), kept_state(at)));
                }
            }
        }
        // Excel keeps one sheet visible: a layout that hides every one
        // shows its first worksheet.
        let first_visible = match layout
            .iter()
            .position(|(_, _, state)| *state == XlsxSheetVisibility::Visible)
        {
            Some(at) => at,
            None => {
                let at = layout
                    .iter()
                    .position(|(old, ..)| {
                        old.is_none_or(|at| self.worksheets.contains_key(&self.order[at]))
                    })
                    .ok_or(refused("a workbook keeps at least one worksheet"))?;
                layout[at].2 = XlsxSheetVisibility::Visible;
                at
            }
        };
        let mut moved: Vec<Option<usize>> = vec![None; self.order.len()];
        for (new, (old, ..)) in layout.iter().enumerate() {
            if let Some(old) = old {
                moved[*old] = Some(new);
            }
        }
        let mut fates: HashMap<String, SheetFate> = HashMap::new();
        let mut dropped = Vec::new();
        // The tables that go with a deleted worksheet, for the pivot caches
        // that name them.
        let mut gone_tables = HashSet::new();
        for (at, name) in self.order.iter().enumerate() {
            match moved[at] {
                None => {
                    fates.insert(name.to_lowercase(), SheetFate::Delete);
                    dropped.extend(entries[at].attr_ns(REL, "id").map(str::to_owned));
                    if let Some(part) = self.worksheets.get(name) {
                        gone_tables.extend(
                            self.tables(part)?
                                .into_iter()
                                .map(|table| table.name.to_lowercase()),
                        );
                    }
                }
                Some(new) if layout[new].1 != *name => {
                    fates.insert(
                        name.to_lowercase(),
                        SheetFate::Rename(layout[new].1.clone()),
                    );
                }
                Some(_) => {}
            }
        }
        let fate = |name: &str| {
            fates
                .get(&name.to_lowercase())
                .cloned()
                .unwrap_or(SheetFate::Keep)
        };
        // A formula's sheet prefixes follow the layout, and its references
        // to a deleted sheet's tables read `#REF!`.
        let order = self.order.clone();
        let retarget = |text: &str| -> Option<String> {
            let moved = retarget_sheets(text, &order, &fate);
            if gone_tables.is_empty() {
                return moved;
            }
            drop_tables(moved.as_deref().unwrap_or(text), &gone_tables).or(moved)
        };
        // A new `<sheet>` names its part with the prefix the others use.
        let rel_attr = entries.iter().find_map(|node| {
            let id = node.attr_ns(REL, "id")?;
            node.attrs
                .iter()
                .find(|(name, value)| name.ends_with(":id") && value.as_str() == id)
                .map(|(name, _)| name.clone())
        });
        let sheet_element = entries.first().map_or_else(
            || list_node.child_name("sheet"),
            |node| node.qualified.clone(),
        );
        let mut sheet_id = entries
            .iter()
            .filter_map(|node| node.attr("sheetId")?.trim().parse::<u32>().ok())
            .max()
            .unwrap_or(0);
        let dir = self
            .worksheets
            .values()
            .find_map(|part| part.rsplit_once('/').map(|(dir, _)| dir.to_owned()))
            .unwrap_or_else(|| match self.part.rsplit_once('/') {
                Some((dir, _)) => format!("{dir}/worksheets"),
                None => "worksheets".to_owned(),
            });
        let kind = self
            .package
            .relationships(&self.part)?
            .into_iter()
            .find(|rel| !rel.external && rel.kind.ends_with("/worksheet"))
            .map_or_else(|| WORKSHEET_KIND.to_owned(), |rel| rel.kind);
        let mut content = Vec::new();
        let mut worksheets = BTreeMap::new();
        for (old, name, state) in &layout {
            let Some(at) = old else {
                let part = next_part(&self.package, &format!("{dir}/sheet"), ".xml")
                    .map_err(|_| refused("no free worksheet part name"))?;
                let seed = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<worksheet xmlns=\"{SML}\"><sheetData/></worksheet>"
                );
                self.package
                    .add_part(&part, WORKSHEET_TYPE, seed.into_bytes())?;
                let id = self.package.relate(&self.part, &kind, &part)?;
                sheet_id = sheet_id.checked_add(1).ok_or(refused("no free sheet id"))?;
                let link = rel_attr.as_ref().map_or_else(
                    || format!("xmlns:r=\"{REL}\" r:id=\"{id}\""),
                    |attr| format!("{attr}=\"{id}\""),
                );
                let hidden = state
                    .state()
                    .map_or_else(String::new, |state| format!(" state=\"{state}\""));
                content.extend_from_slice(
                    format!(
                        "<{sheet_element} name=\"{}\" sheetId=\"{sheet_id}\"{hidden} {link}/>",
                        escape_text(name)
                    )
                    .as_bytes(),
                );
                worksheets.insert(name.clone(), part);
                continue;
            };
            let node = entries[*at];
            // The retained `<sheet>`, its name and state as laid out.
            let mut sheet_edits = Vec::new();
            if *name != self.order[*at] {
                if !node.attr_spans.contains_key("name") {
                    return Err(refused("a sheet has no name"));
                }
                sheet_edits.push(set_attribute(&bytes, node, "name", name));
            }
            if kept_state(*at) != *state {
                match (state.state(), node.attr_spans.get("state")) {
                    (Some(value), _) => {
                        sheet_edits.push(set_attribute(&bytes, node, "state", value))
                    }
                    (None, Some(span)) => {
                        let start = if bytes[span.start - 1].is_ascii_whitespace() {
                            span.start - 1
                        } else {
                            span.start
                        };
                        sheet_edits.push((start..span.end, Vec::new()));
                    }
                    (None, None) => {}
                }
            }
            let start = node.span.start;
            let rebased = sheet_edits
                .into_iter()
                .map(|(range, value)| (range.start - start..range.end - start, value))
                .collect();
            content.extend(
                splice(&bytes[node.span.clone()], rebased)
                    .map_err(|_| refused("a sheet could not be rewritten"))?,
            );
            if let Some(part) = self.worksheets.get(&self.order[*at]) {
                worksheets.insert(name.clone(), part.clone());
            }
        }
        let mut edits = vec![(list_node.content.clone(), content)];
        if let Some((list, node)) = tree.child(0, SML, "definedNames")? {
            // The list's other markup counts as kept, so it stays with it.
            let mut kept_names = 0;
            let mut name_edits = Vec::new();
            for (_, name) in tree.children(list) {
                if !name.is(SML, "definedName") {
                    kept_names += 1;
                    continue;
                }
                if let Some(old) = name
                    .attr("localSheetId")
                    .and_then(|at| at.trim().parse::<usize>().ok())
                {
                    match moved.get(old).copied().flatten() {
                        None => {
                            name_edits.push((name.span.clone(), Vec::new()));
                            continue;
                        }
                        Some(new) if new != old => name_edits.push(set_attribute(
                            &bytes,
                            name,
                            "localSheetId",
                            &new.to_string(),
                        )),
                        Some(_) => {}
                    }
                }
                kept_names += 1;
                // Only the name's text changes (FIX 8572).
                if !name.empty
                    && let Some(text) = retarget(&name.text)
                {
                    name_edits.extend(
                        replace_text(&bytes, name, &text)
                            .ok_or(refused("the workbook part could not be rewritten"))?,
                    );
                }
            }
            if kept_names == 0 {
                edits.push((node.span.clone(), Vec::new()));
            } else {
                edits.extend(name_edits);
            }
        }
        if let Some((views, _)) = tree.child(0, SML, "bookViews")? {
            for (_, view) in tree
                .children(views)
                .filter(|(_, node)| node.is(SML, "workbookView"))
            {
                for attr in ["activeTab", "firstSheet"] {
                    let Some(old) = view
                        .attr(attr)
                        .and_then(|at| at.trim().parse::<usize>().ok())
                    else {
                        continue;
                    };
                    let mut new = moved.get(old).copied().flatten().unwrap_or(first_visible);
                    // The active tab is a visible one.
                    if attr == "activeTab" && layout[new].2 != XlsxSheetVisibility::Visible {
                        new = first_visible;
                    }
                    if new != old {
                        edits.push(set_attribute(&bytes, view, attr, &new.to_string()));
                    }
                }
            }
        }
        let value = splice(&bytes, edits)
            .map_err(|_| refused("the workbook part could not be rewritten"))?;
        self.package.replace_xml_part(&self.part, value)?;
        if !dropped.is_empty() {
            let before = self.package.reachable("")?;
            for id in &dropped {
                self.package.unrelate(&self.part, id)?;
            }
            let after = self.package.reachable("")?;
            for part in before.difference(&after) {
                if self.package.names().any(|name| name == part.as_str()) {
                    self.package.remove_part(part)?;
                }
            }
            self.package.prune_defaults()?;
        }
        if !fates.is_empty() {
            let parts: Vec<String> = self
                .package
                .names()
                .filter(|name| {
                    let lower = name.to_ascii_lowercase();
                    lower.ends_with(".xml")
                        && ["/worksheets/", "/charts/", "/tables/"]
                            .iter()
                            .any(|dir| lower.contains(dir))
                })
                .map(str::to_owned)
                .collect();
            for part in parts {
                self.rewrite_formulas(&part, &|text: &str, _| retarget(text))?;
            }
            self.move_pivot_sources(&|source: &Node| {
                if let Some(sheet) = source.attr("sheet") {
                    return match fate(sheet) {
                        SheetFate::Keep => SourceFate::Keep,
                        SheetFate::Rename(name) => SourceFate::Sheet(name),
                        SheetFate::Delete => SourceFate::Lost(sheet.to_owned()),
                    };
                }
                match source.attr("name") {
                    Some(table) if gone_tables.contains(&table.to_lowercase()) => {
                        SourceFate::Lost(table.to_owned())
                    }
                    _ => SourceFate::Keep,
                }
            })?;
        }
        if layout.iter().map(|(_, name, _)| name).ne(self.order.iter()) {
            // The worksheets' titles, in the old order and as laid out; a
            // chart or dialog sheet is not one (FIX 3441).
            let old: Vec<String> = self
                .order
                .iter()
                .filter(|name| self.worksheets.contains_key(*name))
                .cloned()
                .collect();
            let new: Vec<String> = layout
                .iter()
                .filter(|(at, ..)| {
                    at.is_none_or(|at| self.worksheets.contains_key(&self.order[at]))
                })
                .map(|(_, name, _)| name.clone())
                .collect();
            self.retitle_parts(&old, &new)?;
        }
        self.visibility = layout
            .iter()
            .map(|(_, name, state)| (name.clone(), *state))
            .collect();
        self.order = layout.into_iter().map(|(_, name, _)| name).collect();
        self.worksheets = worksheets;
        Ok(())
    }

    /// Drop the sheet titles and their heading counts from the extended
    /// properties (`TitlesOfParts` and `HeadingPairs` in docProps/app.xml),
    /// which a sheet layout change leaves naming the old sheets, when their
    /// worksheet titles cannot be told apart to rewrite them. Both are
    /// optional, and the opening application writes them again on save.
    pub(super) fn drop_part_titles(&mut self) -> Result<()> {
        let Some(part) = self
            .package
            .relationships("")?
            .into_iter()
            .find(|rel| !rel.external && rel.kind.ends_with("/extended-properties"))
            .map(|rel| rel.target)
        else {
            return Ok(());
        };
        let Some(bytes) = self.package.part(&part)? else {
            return Ok(());
        };
        let tree = XmlTree::parse(&bytes, self.package.limits().xml)?;
        let edits: Vec<_> = tree
            .children(0)
            .filter(|(_, node)| {
                node.namespace == EXTENDED_PROPERTIES
                    && matches!(node.name.as_str(), "TitlesOfParts" | "HeadingPairs")
            })
            .map(|(_, node)| (node.span.clone(), Vec::new()))
            .collect();
        if edits.is_empty() {
            return Ok(());
        }
        let value = splice(&bytes, edits)
            .map_err(|_| refused("the extended properties could not be rewritten"))?;
        self.package.replace_xml_part(&part, value)?;
        Ok(())
    }

    /// The workbook's pivot cache definitions.
    pub(super) fn pivot_caches(&self) -> Result<Vec<String>> {
        let mut caches: Vec<String> = Vec::new();
        for rel in self.package.relationships(&self.part)? {
            if !rel.external
                && rel.kind.ends_with("/pivotCacheDefinition")
                && !caches.contains(&rel.target)
                && self.package.names().any(|name| name == rel.target)
            {
                caches.push(rel.target);
            }
        }
        Ok(caches)
    }

    /// Point each pivot cache whose source is a range of this workbook
    /// (`worksheetSource` without a link to another file) where `fate`
    /// says. A cache whose source is gone keeps its cached results, as
    /// Excel's does: its source reads `#REF!`, it no longer refreshes on
    /// open, and the effects name it.
    pub(super) fn move_pivot_sources(&mut self, fate: &dyn Fn(&Node) -> SourceFate) -> Result<()> {
        for cache in self.pivot_caches()? {
            let bytes = self
                .package
                .part(&cache)?
                .ok_or(refused("a workbook part is missing"))?;
            let tree = XmlTree::parse(&bytes, self.package.limits().xml)?;
            let mut edits = Vec::new();
            let mut lost = Vec::new();
            for node in &tree.nodes {
                if !node.is(SML, "worksheetSource") || node.attr_ns(REL, "id").is_some() {
                    continue;
                }
                match fate(node) {
                    SourceFate::Keep => {}
                    SourceFate::Sheet(name) => {
                        edits.push(set_attribute(&bytes, node, "sheet", &name))
                    }
                    SourceFate::Range(reference) => {
                        edits.push(set_attribute(&bytes, node, "ref", &reference));
                    }
                    SourceFate::Lost(source) => {
                        edits.extend(drop_attribute(&bytes, node, "sheet"));
                        edits.extend(drop_attribute(&bytes, node, "ref"));
                        edits.push(set_attribute(&bytes, node, "name", "#REF!"));
                        lost.push(source);
                    }
                }
            }
            if !lost.is_empty() {
                let root = &tree.nodes[0];
                if root.attr("refreshOnLoad").is_some_and(truthy) {
                    edits.push(set_attribute(&bytes, root, "refreshOnLoad", "0"));
                }
                for source in lost {
                    self.effects.push(format!(
                        "pivot_source_deleted: {cache}, {source}; its cached results stay and it no longer refreshes on open"
                    ));
                }
            }
            if edits.is_empty() {
                continue;
            }
            let value = splice(&bytes, edits)
                .map_err(|_| refused("a pivot cache could not be rewritten"))?;
            self.package.replace_xml_part(&cache, value)?;
        }
        Ok(())
    }

    /// Rewrite one part's formulas (its defined names, for the workbook) and
    /// hyperlink locations through `rewrite`, which answers `None` for text
    /// it leaves alone. It is also given a worksheet cell formula's cell, as
    /// the part holds it. Only the formula's text changes: its comments and
    /// other markup keep their bytes (FIX 8572).
    pub(super) fn rewrite_formulas(
        &mut self,
        part: &str,
        rewrite: &dyn Fn(&str, Option<(u32, u32)>) -> Option<String>,
    ) -> Result<()> {
        let bytes = self
            .package
            .part(part)?
            .ok_or(refused("a workbook part is missing"))?;
        let tree = XmlTree::parse(&bytes, self.package.limits().xml)?;
        let mut edits = Vec::new();
        for node in &tree.nodes {
            if (FORMULA_ELEMENTS.contains(&node.name.as_str()) || node.is(SML, "definedName"))
                && node.children.is_empty()
                && !node.empty
            {
                let at = node
                    .parent
                    .map(|cell| &tree.nodes[cell])
                    .filter(|cell| node.is(SML, "f") && cell.is(SML, "c"))
                    .and_then(|cell| cell.attr("r"))
                    .and_then(cell_ref);
                if let Some(text) = rewrite(&node.text, at) {
                    edits.extend(
                        replace_text(&bytes, node, &text)
                            .ok_or(refused("a part could not be rewritten"))?,
                    );
                }
            } else if node.is(SML, "hyperlink")
                && let Some(text) = node
                    .attr("location")
                    .and_then(|location| rewrite(location, None))
            {
                edits.push(set_attribute(&bytes, node, "location", &text));
            }
        }
        if edits.is_empty() {
            return Ok(());
        }
        let value = splice(&bytes, edits).map_err(|_| refused("a part could not be rewritten"))?;
        self.package.replace_xml_part(part, value)?;
        Ok(())
    }

    /// Name the pivot cache fields a deleted table column fed. As Excel's
    /// do, they stay in the cache, with the slicers and timelines that
    /// filter them, until it is refreshed from the narrower table.
    pub(super) fn note_pivot_fields(&mut self, lost: &[LostColumns]) -> Result<()> {
        for cache in self.pivot_caches()? {
            let Some(bytes) = self.package.part(&cache)? else {
                continue;
            };
            let tree = XmlTree::parse(&bytes, self.package.limits().xml)?;
            let Some(table) = tree
                .nodes
                .iter()
                .find(|node| node.is(SML, "worksheetSource"))
                .and_then(|node| node.attr("name"))
                .and_then(|name| {
                    lost.iter()
                        .find(|lost| lost.name.to_lowercase() == name.to_lowercase())
                })
            else {
                continue;
            };
            for field in tree.nodes.iter().filter(|node| node.is(SML, "cacheField")) {
                let Some(name) = field.attr("name") else {
                    continue;
                };
                if table
                    .columns
                    .iter()
                    .any(|(_, column)| column.to_lowercase() == name.to_lowercase())
                {
                    self.effects.push(format!(
                        "pivot_field_kept: {cache}, {name}; table {} lost the column, and the cache keeps the field, with the slicers and timelines that filter it, until it is refreshed",
                        table.name
                    ));
                }
            }
        }
        Ok(())
    }
}
