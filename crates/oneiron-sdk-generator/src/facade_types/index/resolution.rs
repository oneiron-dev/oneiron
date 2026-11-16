//! The resolver of `Index`: a file's imports, a path's crate and module, the item a path or a bare name names from
//! a file or in a module, a type a macro defines, and the best candidate by name.

use std::rc::Rc;

use super::super::reader::strip_comments;
use super::super::{EXTERNAL, Ir, STRING, crate_dir, holds, index_error, lib_family};
use super::{Found, Index, ItemRef, Kind, SERIALIZE_STR, USE, Uses, expand_use};
use crate::error::GenerateError;

impl Index {
    // ---- resolution

    /// The file's imports, alias -> path, and its glob paths.
    pub(crate) fn uses(&mut self, crate_name: &str, file: &str) -> Result<Rc<Uses>, GenerateError> {
        self.record_dependency(crate_name, file);
        let key = (crate_name.to_owned(), file.to_owned());
        if let Some(found) = self.use_cache.get(&key) {
            return Ok(Rc::clone(found));
        }
        let mut uses = Uses::default();
        if let Some(text) = self.files.get(&key) {
            for found in USE.captures_iter(text) {
                for (alias, path) in expand_use(&[], &strip_comments(&found[1]), 0)? {
                    if alias == "*" {
                        uses.globs.push(path);
                    } else {
                        uses.names.entry(alias).or_insert(path);
                    }
                }
            }
        }
        let uses = Rc::new(uses);
        self.use_cache.insert(key, Rc::clone(&uses));
        Ok(uses)
    }

    /// A path's crate and module segments, from a file in (crate, module); `None` for an external crate. A path that
    /// names a `CRATES` crate reads it.
    pub(crate) fn absolute(
        &mut self,
        segments: &[String],
        crate_name: &str,
        module: &[String],
    ) -> Result<Option<(String, Vec<String>)>, GenerateError> {
        let head = segments.first().ok_or_else(index_error)?.as_str();
        Ok(Some(match head {
            "crate" => (crate_name.to_owned(), segments[1..].to_vec()),
            "self" => (crate_name.to_owned(), [module, &segments[1..]].concat()),
            "super" => {
                let up = segments
                    .iter()
                    .take_while(|segment| *segment == "super")
                    .count();
                let keep = module.len().saturating_sub(up);
                (
                    crate_name.to_owned(),
                    [&module[..keep], &segments[up..]].concat(),
                )
            }
            _ if crate_dir(head).is_some() => {
                self.load(head)?;
                (head.to_owned(), segments[1..].to_vec())
            }
            _ if holds(EXTERNAL, head) => return Ok(None),
            _ => (crate_name.to_owned(), [module, segments].concat()),
        }))
    }

    /// The item a path names from a file, an external name, or `None`; the search stops past depth 12.
    pub(crate) fn resolve(
        &mut self,
        segments: &[String],
        crate_name: &str,
        file: &str,
        module: &[String],
        depth: usize,
    ) -> Result<Option<Found>, GenerateError> {
        if depth > 12 {
            return Ok(None);
        }
        if segments.len() == 1 {
            return self.resolve_name(&segments[0], crate_name, file, module, depth);
        }
        let head = segments.first().ok_or_else(index_error)?;
        if !matches!(head.as_str(), "crate" | "self" | "super") && crate_dir(head).is_none() {
            let uses = self.uses(crate_name, file)?;
            if let Some(path) = uses.names.get(head) {
                let joined = [path.as_slice(), &segments[1..]].concat();
                return self.resolve(&joined, crate_name, file, module, depth + 1);
            }
        }
        let Some((target, path)) = self.absolute(segments, crate_name, module)? else {
            return Ok(Some(Found::External(segments[segments.len() - 1].clone())));
        };
        let (name, parent) = path.split_last().ok_or_else(index_error)?;
        self.resolve_in(&target, parent, name, depth + 1)
    }

    /// A module path as its file sits, through a parent's `use <module> as <name>;` (FIX 8907: `task_verb::sdk` is
    /// `crate::verbs`).
    pub(crate) fn module_place(
        &mut self,
        crate_name: &str,
        module: &[String],
        depth: usize,
    ) -> Result<(String, Vec<String>), GenerateError> {
        if module.is_empty() || depth > 12 {
            return Ok((crate_name.to_owned(), module.to_vec()));
        }
        // A module with a file of its own sits there: the file found is a dependency (its removal moves the module).
        if let Some(file) = self
            .modules
            .get(&(crate_name.to_owned(), module.to_vec()))
            .cloned()
        {
            self.record_dependency(crate_name, &file);
            return Ok((crate_name.to_owned(), module.to_vec()));
        }
        let (last, head) = module.split_last().ok_or_else(index_error)?;
        let (crate_name, parent) = self.module_place(crate_name, head, depth + 1)?;
        if let Some(file) = self
            .modules
            .get(&(crate_name.clone(), parent.clone()))
            .cloned()
        {
            let uses = self.uses(&crate_name, &file)?;
            if let Some(path) = uses.names.get(last)
                && let Some((target, place)) = self.absolute(path, &crate_name, &parent)?
            {
                return self.module_place(&target, &place, depth + 1);
            }
        }
        let mut place = parent;
        place.push(last.clone());
        Ok((crate_name, place))
    }

    /// The item `name` names in a module: the module file's own item, its import of that name, a glob's item, else
    /// the best candidate by name under the module.
    pub(crate) fn resolve_in(
        &mut self,
        crate_name: &str,
        module: &[String],
        name: &str,
        depth: usize,
    ) -> Result<Option<Found>, GenerateError> {
        if depth > 12 {
            return Ok(None);
        }
        let (crate_name, module) = self.module_place(crate_name, module, 0)?;
        if let Some(file) = self
            .modules
            .get(&(crate_name.clone(), module.clone()))
            .cloned()
        {
            self.record_dependency(&crate_name, &file);
            if let Some(item) = self.local(name, &crate_name, &file) {
                return Ok(Some(Found::Item(item)));
            }
            let uses = self.uses(&crate_name, &file)?;
            if let Some(path) = uses.names.get(name)
                && let Some(found) = self.resolve(path, &crate_name, &file, &module, depth + 1)?
            {
                return Ok(Some(found));
            }
            for glob in &uses.globs {
                let Some((target, place)) = self.absolute(glob, &crate_name, &module)? else {
                    continue;
                };
                if let Some(found) = self.resolve_in(&target, &place, name, depth + 1)? {
                    return Ok(Some(found));
                }
            }
        }
        if self.exact {
            return Ok(None);
        }
        Ok(self
            .by_name(name, &crate_name, &module, Some(&module))
            .map(Found::Item))
    }

    /// The item a bare name names from a file: the file's own item, its import of that name, a glob's item, else the
    /// best candidate by name.
    pub(crate) fn resolve_name(
        &mut self,
        name: &str,
        crate_name: &str,
        file: &str,
        module: &[String],
        depth: usize,
    ) -> Result<Option<Found>, GenerateError> {
        self.record_dependency(crate_name, file);
        if let Some(item) = self.local(name, crate_name, file) {
            return Ok(Some(Found::Item(item)));
        }
        let uses = self.uses(crate_name, file)?;
        if let Some(path) = uses.names.get(name)
            && let Some(found) = self.resolve(path, crate_name, file, module, depth + 1)?
        {
            return Ok(Some(found));
        }
        for glob in &uses.globs {
            let Some((target, place)) = self.absolute(glob, crate_name, module)? else {
                continue;
            };
            // A glob's external name does not count here (`not isinstance(found, tuple)`).
            if let Some(Found::Item(item)) = self.resolve_in(&target, &place, name, depth + 1)? {
                return Ok(Some(Found::Item(item)));
            }
        }
        if self.exact {
            return Ok(None);
        }
        Ok(self
            .by_name(name, crate_name, module, None)
            .map(Found::Item))
    }

    /// `min(local, key=lambda item: not item.top)` over the items of that name in one file: the first top-level
    /// one, else the first.
    fn local(&self, name: &str, crate_name: &str, file: &str) -> Option<ItemRef> {
        let items = self.items.get(name)?;
        let mut local = items
            .iter()
            .filter(|item| item.crate_name == crate_name && item.file == file);
        let first = local.clone().next()?;
        Some(Rc::clone(local.find(|item| item.top).unwrap_or(first)))
    }

    /// A type a macro defines, a string when the macro writes it with `serialize_str`. Each file that calls a macro
    /// to define `name`, and each file that defines a macro so called, is a dependency.
    pub(crate) fn macro_token(&mut self, name: &str) -> Option<Ir> {
        let uses = self.macro_uses.get(name)?;
        for (crate_name, file, macro_name) in uses {
            self.dependencies.insert((crate_name.clone(), file.clone()));
            for definition in self.macro_files.get(macro_name).into_iter().flatten() {
                self.dependencies.insert(definition.clone());
            }
        }
        uses.iter()
            .any(|(_, _, macro_name)| {
                SERIALIZE_STR.is_match(self.macros.get(macro_name).map_or("", String::as_str))
            })
            .then_some(STRING)
    }

    /// The best candidate of that name, same crate, under `within`, nearest module; ties keep the first. Every file
    /// that holds an item of that name is a dependency, a candidate or not (an edit there can make it one).
    /// "Same crate" compares `lib_family`: the crates below `oneiron` that mirror its modules count as `oneiron`.
    pub(crate) fn by_name(
        &mut self,
        name: &str,
        crate_name: &str,
        module: &[String],
        within: Option<&[String]>,
    ) -> Option<ItemRef> {
        let family = lib_family(crate_name);
        let all = self.items.get(name)?;
        self.dependencies.extend(
            all.iter()
                .map(|item| (item.crate_name.clone(), item.file.clone())),
        );
        let mut candidates: Vec<&ItemRef> = all
            .iter()
            .filter(|item| item.kind != Kind::Type || item.top)
            .collect();
        if let Some(within) = within {
            let under: Vec<&ItemRef> = candidates
                .iter()
                .copied()
                .filter(|item| {
                    lib_family(&item.crate_name) == family && item.module.starts_with(within)
                })
                .collect();
            if !under.is_empty() {
                candidates = under;
            }
        }
        let first = candidates.first()?;
        let several_files = candidates
            .iter()
            .any(|item| item.crate_name != first.crate_name || item.file != first.file);
        let rank = |item: &&ItemRef| {
            let common = item
                .module
                .iter()
                .zip(module)
                .take_while(|(a, b)| a == b)
                .count();
            (
                lib_family(&item.crate_name) != family,
                !item.top,
                std::cmp::Reverse(common),
                item.module.len(),
                item.file.clone(),
            )
        };
        let best = Rc::clone(candidates.iter().min_by_key(|item| rank(item))?);
        if several_files {
            self.guesses.insert(name.to_owned());
        }
        Some(best)
    }
}
