//! Syntactic JS/TS entry exports, separate from the retained code-symbol graph.
use super::{invalid, safe_path};
use crate::error::Result;
use oxc_allocator::Allocator;
use oxc_ast::ast::{ImportDeclarationSpecifier, Statement};
use oxc_parser::Parser;
use oxc_semantic::SemanticBuilder;
use oxc_span::SourceType;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

mod commonjs;

/// Names declared by an entry and export sites whose full target is not known.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JsPublicNames {
    pub names: BTreeSet<String>,
    pub unresolved: BTreeSet<String>,
}

#[derive(Clone)]
enum Binding {
    Local(String),
    CommonJsValue,
    DefaultValue,
    From { request: String, name: String },
    Namespace(String),
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Origin {
    Local(String, String),
    Namespace(String),
    External(String, String, String),
    ExternalNamespace(String, String),
    CommonJsValue(String),
    DefaultValue(String),
}

#[derive(Default)]
struct Module {
    bindings: BTreeMap<String, Binding>,
    stars: Vec<String>,
    targets: BTreeMap<String, Option<String>>,
    unresolved: BTreeSet<String>,
}

/// Read a declared public entry from the checked worktree. Names use
/// `js:<entry-name>::<export-name>`; implementation-file moves keep that identity.
/// Relative re-exports follow exact file paths, without package/extension guessing.
pub fn js_public_names(root: &Path, entry_name: &str, entry: &str) -> Result<JsPublicNames> {
    if entry_name.is_empty() {
        return Err(invalid("JavaScript entry name is empty"));
    }
    let mut modules = BTreeMap::new();
    let mut pending = vec![entry.to_owned()];
    while let Some(file) = pending.pop() {
        if modules.contains_key(&file) {
            continue;
        }
        let mut module = read_module(root, &file)?;
        let requests: BTreeSet<_> = module
            .bindings
            .values()
            .filter_map(|binding| match binding {
                Binding::Local(_) | Binding::CommonJsValue | Binding::DefaultValue => None,
                Binding::From { request, .. } | Binding::Namespace(request) => {
                    Some(request.clone())
                }
            })
            .chain(module.stars.iter().cloned())
            .collect();
        for request in requests {
            let target = relative_target(root, &file, &request)?;
            if let Some(target) = &target {
                pending.push(target.clone());
            } else {
                module.unresolved.insert(format!("from:{request}"));
            }
            module.targets.insert(request, target);
        }
        modules.insert(file, module);
    }

    // A fixed point enumerates the finite export-name closure, including cycles.
    // Binding resolution below removes ambiguous star exports, not diamond paths
    // that reach the same original binding.
    let mut surfaces: BTreeMap<_, BTreeSet<_>> = modules
        .iter()
        .map(|(file, module)| (file.clone(), module.bindings.keys().cloned().collect()))
        .collect();
    loop {
        let mut changed = false;
        for (file, module) in &modules {
            let inherited: BTreeSet<_> = module
                .stars
                .iter()
                .filter_map(|request| module.targets.get(request)?.as_ref())
                .filter_map(|target| surfaces.get(target))
                .flat_map(|names| {
                    names
                        .iter()
                        .filter(|name| name.as_str() != "default")
                        .cloned()
                })
                .collect();
            let names = surfaces
                .get_mut(file)
                .expect("every parsed module has a surface");
            let before = names.len();
            names.extend(inherited);
            changed |= names.len() != before;
        }
        if !changed {
            break;
        }
    }
    let mut result = JsPublicNames::default();
    for (file, module) in &modules {
        result
            .unresolved
            .extend(module.unresolved.iter().map(|site| {
                format!(
                    "js:{}::{}#{}",
                    name_segment(entry_name),
                    name_segment(file),
                    name_segment(site)
                )
            }));
    }
    for name in &surfaces[entry] {
        let origins = resolve_binding(&modules, entry, name);
        if origins.is_some_and(|origins| origins.len() == 1) {
            result.names.insert(format!(
                "js:{}::{}",
                name_segment(entry_name),
                name_segment(name)
            ));
        } else {
            result.unresolved.insert(format!(
                "js:{}::{}#export:{}",
                name_segment(entry_name),
                name_segment(entry),
                name_segment(name)
            ));
        }
    }
    Ok(result)
}

fn name_segment(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace(':', "%3A")
        .replace('#', "%23")
}

fn read_module(root: &Path, file: &str) -> Result<Module> {
    let source = std::fs::read_to_string(safe_path(root, file)?)?;
    let source_type = SourceType::from_path(file)
        .map_err(|_| invalid("JavaScript contract source extension is unknown"))?;
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, &source, source_type).parse();
    if parsed.fatal_error || !parsed.diagnostics.is_empty() {
        return Err(invalid("JavaScript contract source contains parse errors"));
    }
    let built = SemanticBuilder::new()
        .with_build_nodes(true)
        .with_check_syntax_error(true)
        .build(&parsed.program);
    if !built.diagnostics.is_empty() {
        return Err(invalid(
            "JavaScript contract source contains binding errors",
        ));
    }
    let record = &parsed.module_record;
    let mut module = Module::default();
    // The parser supplies normalized names, including destructuring, type-only
    // declarations and string-literal export names. Private bindings are absent.
    for name in record.exported_bindings.keys() {
        module
            .bindings
            .insert(name.to_string(), Binding::Local(name.to_string()));
    }
    for export in &record.local_export_entries {
        let exported = if export.export_name.is_default() {
            Some("default".to_owned())
        } else {
            record
                .exported_bindings
                .iter()
                .find(|(_, span)| Some(**span) == export.export_name.span())
                .map(|(name, _)| name.to_string())
        };
        if let Some(exported) = exported {
            let binding = if export.local_name.is_default() {
                // `export default expression` captures a value; it is not the
                // live local binding of `export { local as default }`.
                Binding::DefaultValue
            } else {
                match export.local_name.name() {
                    Some(local) => Binding::Local(local.to_string()),
                    None if export.export_name.is_default() => Binding::DefaultValue,
                    None => {
                        module.unresolved.insert(format!("local:{exported}"));
                        continue;
                    }
                }
            };
            module.bindings.insert(exported, binding);
        }
    }
    let mut imports = BTreeMap::new();
    for statement in &parsed.program.body {
        if let Statement::ImportDeclaration(declaration) = statement {
            for specifier in declaration.specifiers.iter().flatten() {
                let request = declaration.source.value.to_string();
                let (local, binding) = match specifier {
                    ImportDeclarationSpecifier::ImportSpecifier(specifier) => (
                        specifier.local.name.to_string(),
                        Binding::From {
                            request,
                            name: specifier.imported.name().to_string(),
                        },
                    ),
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(specifier) => (
                        specifier.local.name.to_string(),
                        Binding::From {
                            request,
                            name: "default".to_owned(),
                        },
                    ),
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(specifier) => (
                        specifier.local.name.to_string(),
                        Binding::Namespace(request),
                    ),
                };
                imports.insert(local, binding);
            }
        }
    }
    for statement in &parsed.program.body {
        match statement {
            Statement::ExportNamedDeclaration(declaration) => {
                for specifier in &declaration.specifiers {
                    let local = specifier.local.name().to_string();
                    let binding = imports
                        .get(&local)
                        .cloned()
                        .unwrap_or(Binding::Local(local));
                    module
                        .bindings
                        .insert(specifier.exported.name().to_string(), binding);
                }
            }
            Statement::ExportFromDeclaration(declaration) => {
                for specifier in &declaration.specifiers {
                    let binding = Binding::From {
                        request: declaration.source.value.to_string(),
                        name: specifier.local.name().to_string(),
                    };
                    module
                        .bindings
                        .insert(specifier.exported.name().to_string(), binding);
                }
            }
            Statement::TSExportAssignment(_) => {
                module
                    .unresolved
                    .insert("typescript:export-assignment".to_owned());
            }
            Statement::ExportAllDeclaration(declaration) => {
                let request = declaration.source.value.to_string();
                if let Some(exported) = &declaration.exported {
                    module
                        .bindings
                        .insert(exported.name().to_string(), Binding::Namespace(request));
                } else {
                    module.stars.push(request);
                }
            }
            _ => {}
        }
    }
    if !record.has_module_syntax && !parsed.program.source_type.is_module() {
        commonjs::collect(&parsed.program, &built.semantic, file, &mut module);
    }
    Ok(module)
}

// Resolve a name to original bindings without recursion. An explicit export
// shadows stars. Reaching the same binding along two paths is not ambiguity.
fn resolve_binding(
    modules: &BTreeMap<String, Module>,
    entry: &str,
    name: &str,
) -> Option<BTreeSet<Origin>> {
    let mut pending = vec![(entry.to_owned(), name.to_owned())];
    let mut seen = BTreeSet::new();
    let mut origins = BTreeSet::new();
    let mut unknown = false;
    while let Some((file, name)) = pending.pop() {
        if !seen.insert((file.clone(), name.clone())) {
            continue;
        }
        let module = &modules[&file];
        match module.bindings.get(&name) {
            Some(Binding::Local(local)) => {
                origins.insert(Origin::Local(file, local.clone()));
            }
            Some(Binding::CommonJsValue) => {
                origins.insert(Origin::CommonJsValue(file));
            }
            Some(Binding::DefaultValue) => {
                origins.insert(Origin::DefaultValue(file));
            }
            Some(Binding::Namespace(request)) => {
                let origin = if let Some(target) = &module.targets[request] {
                    Origin::Namespace(target.clone())
                } else {
                    Origin::ExternalNamespace(file, request.clone())
                };
                origins.insert(origin);
            }
            Some(Binding::From {
                request,
                name: imported,
            }) => {
                if let Some(target) = &module.targets[request] {
                    pending.push((target.clone(), imported.clone()));
                } else {
                    // The public alias is explicit even when its dependency is
                    // external. The separate unresolved site records that gap.
                    origins.insert(Origin::External(file, request.clone(), imported.clone()));
                }
            }
            None if name != "default" => {
                for request in &module.stars {
                    if let Some(target) = &module.targets[request] {
                        pending.push((target.clone(), name.clone()));
                    } else {
                        // An unknown star may collide with any inherited name.
                        // Never certify that a known sibling star is unambiguous.
                        unknown = true;
                    }
                }
            }
            None => {}
        }
    }
    (!unknown).then_some(origins)
}

fn relative_target(root: &Path, file: &str, request: &str) -> Result<Option<String>> {
    if !request.starts_with("./") && !request.starts_with("../") {
        return Ok(None);
    }
    let mut parts: Vec<_> = Path::new(file)
        .parent()
        .unwrap_or(Path::new(""))
        .components()
        .map(|component| component.as_os_str().to_owned())
        .collect();
    for component in Path::new(request).components() {
        match component {
            Component::Normal(part) => parts.push(part.to_owned()),
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.pop().is_none() {
                    return Ok(None);
                }
            }
            _ => return Ok(None),
        }
    }
    let relative = parts
        .iter()
        .map(|part| part.to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    let path = safe_path(root, &relative)?;
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(Some(relative)),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
