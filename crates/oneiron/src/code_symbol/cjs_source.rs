//! Full-grammar CommonJS parsing and lexical, source-derived symbol relations.

use std::collections::{BTreeMap, HashMap};

use oxc_allocator::Allocator;
use oxc_ast::{AstKind, ast::Expression};
use oxc_parser::Parser;
use oxc_semantic::{NodeId, Semantic, SemanticBuilder, SymbolId};
use oxc_span::{GetSpan, SourceType, Span};

use crate::codebase::{RepoIdentity, RepoRef};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{CodeError, Error, Result};

use super::keys::{code_symbol_entity_id, derive_symbol_fingerprint};
use super::types::{
    CodeChunk, CodeSymbolGraph, CodeSymbolGraphEdge, CodeSymbolManifest, CodeSymbolRevision,
    CodeSymbolSource,
};

pub(super) fn derive_cjs_graph(
    repo: &RepoRef,
    identity: &RepoIdentity,
    commit_hash: Option<String>,
    sources: &[CodeSymbolSource<'_>],
) -> Result<CodeSymbolGraph> {
    let mut output = CjsSymbols::default();
    let mut edges = Vec::new();
    let mut modules = BTreeMap::new();
    let mut imports = Vec::new();
    let session = format!("cjs:{}", identity.as_str());
    for source in sources
        .iter()
        .filter(|source| source.path.ends_with(".cjs"))
    {
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, source.text, SourceType::cjs()).parse();
        // Invalid JavaScript never turns a previously importable repository
        // into a refusal. Its retained blob remains in the snapshot.
        if parsed.fatal_error || !parsed.diagnostics.is_empty() {
            continue;
        }
        let built = SemanticBuilder::new()
            .with_build_nodes(true)
            .with_check_syntax_error(true)
            .build(&parsed.program);
        if !built.diagnostics.is_empty() {
            continue;
        }
        let semantic = built.semantic;
        let module = output.append(
            identity,
            source,
            "<module>",
            "module",
            parsed.program.span,
            0,
            &session,
        )?;
        modules.insert(source.path, module);
        let mut targets = HashMap::<SymbolId, EntityId>::new();
        let mut owners = HashMap::<NodeId, EntityId>::new();
        let mut ordinals = HashMap::<(String, &'static str), u32>::new();
        for symbol in semantic.scoping().symbol_ids() {
            let flags = semantic.scoping().symbol_flags(symbol);
            let kind = if flags.is_function() {
                "function"
            } else if flags.is_class() {
                "class"
            } else if flags.is_variable() || flags.is_catch_variable() {
                "variable"
            } else {
                continue;
            };
            let declaration = semantic.symbol_declaration(symbol);
            let name = semantic.scoping().symbol_name(symbol);
            let ordinal = ordinals.entry((name.to_owned(), kind)).or_default();
            let id = output.append(
                identity,
                source,
                name,
                kind,
                declaration.span(),
                *ordinal,
                &session,
            )?;
            *ordinal = ordinal.saturating_add(1);
            targets.insert(symbol, id);
            match declaration.kind() {
                AstKind::Function(_) | AstKind::Class(_) => {
                    owners.insert(declaration.id(), id);
                }
                AstKind::VariableDeclarator(variable) => {
                    if matches!(&variable.id, oxc_ast::ast::BindingPattern::BindingIdentifier(binding)
                        if binding.symbol_id.get() == Some(symbol))
                        && let Some(initializer) = &variable.init
                    {
                        match initializer.get_inner_expression() {
                            Expression::FunctionExpression(function) => {
                                owners.insert(function.node_id.get(), id);
                            }
                            Expression::ArrowFunctionExpression(function) => {
                                owners.insert(function.node_id.get(), id);
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        // OXC's binding ids distinguish shadowed names, parameters and scopes.
        // A Calls edge identifies the lexical callee, not a runtime execution.
        for (&symbol, &target) in &targets {
            for reference in semantic.symbol_references(symbol) {
                if !reference.is_read() {
                    continue;
                }
                let node = reference.node_id();
                if dynamic_scope(&semantic, node) {
                    continue;
                }
                let owner = reference_owner(&semantic, &owners, node, module);
                let span = semantic.reference_span(reference);
                let is_call =
                    semantic
                        .nodes()
                        .ancestor_kinds(node)
                        .any(|ancestor| match ancestor {
                            AstKind::CallExpression(call) => {
                                call.callee.get_inner_expression().span() == span
                            }
                            AstKind::NewExpression(call) => {
                                call.callee.get_inner_expression().span() == span
                            }
                            _ => false,
                        });
                edges.push(relation(
                    owner,
                    if is_call {
                        EdgeKind::Calls
                    } else {
                        EdgeKind::Refs
                    },
                    target,
                ));
            }
        }
        let require_reassigned = semantic
            .scoping()
            .root_unresolved_references()
            .get("require")
            .is_some_and(|references| {
                references
                    .iter()
                    .any(|&reference| semantic.scoping().get_reference(reference).is_write())
            });
        for node in semantic.nodes().iter() {
            let AstKind::CallExpression(call) = node.kind() else {
                continue;
            };
            let Expression::Identifier(callee) = call.callee.get_inner_expression() else {
                continue;
            };
            if require_reassigned
                || dynamic_scope(&semantic, node.id())
                || callee.name.as_str() != "require"
                || !semantic.is_reference_to_global_variable(callee)
                || call.arguments.len() != 1
            {
                continue;
            }
            let oxc_ast::ast::Argument::StringLiteral(specifier) = &call.arguments[0] else {
                continue;
            };
            if let Some(path) = relative_module_path(source.path, specifier.value.as_str()) {
                imports.push((reference_owner(&semantic, &owners, node.id(), module), path));
            }
        }
    }
    for (source, path) in imports {
        // Resolve only a captured file, never an external package or a guessed
        // export. An extensionless request uses Node's .js/.json/.node search,
        // not an invented .cjs fallback.
        if let Some(&target) = modules.get(path.as_str())
            && source != target
        {
            edges.push(relation(source, EdgeKind::Imports, target));
        }
    }
    CodeSymbolGraph::new(
        CodeSymbolManifest::new(
            repo.clone(),
            identity.clone(),
            commit_hash,
            output.chunks,
            output.symbols,
        )?,
        edges,
    )
}

fn dynamic_scope(semantic: &Semantic<'_>, node: NodeId) -> bool {
    semantic
        .nodes()
        .ancestor_kinds(node)
        .any(|ancestor| matches!(ancestor, AstKind::WithStatement(_)))
}

fn reference_owner(
    semantic: &Semantic<'_>,
    owners: &HashMap<NodeId, EntityId>,
    node: NodeId,
    module: EntityId,
) -> EntityId {
    semantic
        .nodes()
        .ancestor_ids(node)
        .find_map(|parent| owners.get(&parent).copied())
        .unwrap_or(module)
}

fn relation(source: EntityId, kind: EdgeKind, target: EntityId) -> CodeSymbolGraphEdge {
    CodeSymbolGraphEdge::new(
        source,
        kind,
        target,
        kind.default_weight().expect("code relation weight"),
    )
}

#[derive(Default)]
struct CjsSymbols {
    chunks: Vec<CodeChunk>,
    symbols: Vec<CodeSymbolRevision>,
    chunk_indexes: BTreeMap<(String, u32, u32, [u8; 32]), u32>,
}

impl CjsSymbols {
    #[allow(clippy::too_many_arguments)]
    fn append(
        &mut self,
        identity: &RepoIdentity,
        source: &CodeSymbolSource<'_>,
        name: &str,
        kind: &str,
        span: Span,
        ordinal: u32,
        session: &str,
    ) -> Result<EntityId> {
        let range = span.start as usize..span.end as usize;
        let text = source.text.get(range.clone()).ok_or_else(invalid_span)?;
        let start_line = line_at(source.text, range.start)?;
        let end_line = line_at(source.text, range.end)?;
        let chunk = CodeChunk::from_text(source.path, start_line, end_line, text)?;
        let fingerprint =
            derive_symbol_fingerprint(source.path, name, kind, std::slice::from_ref(&chunk))?;
        // Chunks record lines; equal declarations on one line still have
        // different byte spans and must remain separate manifest revisions.
        let fingerprint = super::codec::sha256_bytes(
            &[
                fingerprint.as_slice(),
                &span.start.to_le_bytes(),
                &span.end.to_le_bytes(),
            ]
            .concat(),
        );
        let key = (chunk.path.clone(), start_line, end_line, chunk.content_hash);
        let index = if let Some(&index) = self.chunk_indexes.get(&key) {
            index
        } else {
            let index = u32::try_from(self.chunks.len()).map_err(|_| invalid_span())?;
            self.chunk_indexes.insert(key, index);
            self.chunks.push(chunk);
            index
        };
        let revision = CodeSymbolRevision::new(
            source.path,
            name,
            kind,
            fingerprint,
            vec![index],
            None,
            Some(session.to_owned()),
        )
        .on_document(source.document, ordinal);
        let id = code_symbol_entity_id(identity, &revision)?;
        self.symbols.push(revision);
        Ok(id)
    }
}

fn invalid_span() -> Error {
    Error::Code(CodeError::InvalidCodeSymbolManifestBody(
        "CJS source span exceeds manifest bounds",
    ))
}

fn line_at(source: &str, offset: usize) -> Result<u32> {
    let prefix = source.get(..offset).ok_or_else(invalid_span)?;
    u32::try_from(prefix.bytes().filter(|byte| *byte == b'\n').count() + 1)
        .map_err(|_| invalid_span())
}

fn relative_module_path(source: &str, specifier: &str) -> Option<String> {
    if !(specifier.starts_with("./") || specifier.starts_with("../")) {
        return None;
    }
    let mut parts = source.split('/').collect::<Vec<_>>();
    parts.pop();
    for part in specifier.split('/') {
        match part {
            "." => {}
            ".." => {
                parts.pop()?;
            }
            "" => return None,
            part => parts.push(part),
        }
    }
    Some(parts.join("/"))
}
