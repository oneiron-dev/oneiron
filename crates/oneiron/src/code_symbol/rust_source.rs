//! tree-sitter Rust parsing: definition extraction, identifier references and the derived symbol graph.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ops::Range;

use crate::codebase::RepoRef;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::keys::{code_symbol_entity_id, derive_symbol_fingerprint, repo_identity_key};
use super::text_diff::{changed_line_ranges, source_end_line, subtract_line_range};
use super::types::{
    CODE_SYMBOL_MANIFEST_MAX_SYMBOLS, CODE_SYMBOL_NAME_MAX_BYTES, CodeChunk, CodeEmbeddingInput,
    CodeSymbolGraph, CodeSymbolGraphEdge, CodeSymbolManifest, CodeSymbolRevision, CodeSymbolSource,
};
use super::validate::{compare_chunks, validate_manifest_path, validate_text};

pub(super) const TREE_SITTER_RUST_SOURCE_KIND: &str = "rust";

pub fn derive_code_symbol_graph_from_sources<'a>(
    repo_ref: RepoRef,
    commit_hash: Option<String>,
    sources: impl IntoIterator<Item = CodeSymbolSource<'a>>,
) -> Result<CodeSymbolGraph> {
    let mut sources = sources.into_iter().collect::<Vec<_>>();
    sources.sort_by(|left, right| left.path.cmp(right.path));

    let mut parser = tree_sitter::Parser::new();
    let language = tree_sitter_rust::LANGUAGE.into();
    parser
        .set_language(&language)
        .map_err(|_| Error::InvalidCodeSymbolManifestBody("tree-sitter Rust language rejected"))?;

    let mut chunks = Vec::new();
    let mut extracted = Vec::<ExtractedCodeSymbol>::new();
    let mut parsed_sources = Vec::<ParsedRustSource<'a>>::new();

    for source in sources {
        validate_manifest_path(source.path)?;
        if !is_tree_sitter_rust_source(source.path) {
            continue;
        }
        let tree = parser
            .parse(source.text, None)
            .ok_or(Error::InvalidCodeSymbolManifestBody(
                "tree-sitter Rust parse failed",
            ))?;
        let mut source_symbol_indexes = Vec::new();
        collect_rust_definitions(
            tree.root_node(),
            source.path,
            source.text,
            &mut chunks,
            &mut extracted,
            &mut source_symbol_indexes,
        )?;
        parsed_sources.push(ParsedRustSource {
            text: source.text,
            tree,
            symbol_indexes: source_symbol_indexes,
        });
    }

    if extracted.len() > CODE_SYMBOL_MANIFEST_MAX_SYMBOLS {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "tree-sitter symbol extraction exceeded manifest symbol cap",
        ));
    }

    let mut symbols_by_name = HashMap::<String, Vec<usize>>::new();
    for (index, symbol) in extracted.iter().enumerate() {
        symbols_by_name
            .entry(symbol.revision.name.clone())
            .or_default()
            .push(index);
    }

    let repo_key = repo_identity_key(&repo_ref);
    let symbol_ids = extracted
        .iter()
        .map(|symbol| code_symbol_entity_id(&repo_ref, &symbol.revision))
        .collect::<Result<Vec<_>>>()?;
    let mut edges = Vec::new();
    let mut mention_pairs = BTreeSet::<(EntityId, EntityId)>::new();

    for source in &parsed_sources {
        let root = source.tree.root_node();
        for &source_index in &source.symbol_indexes {
            let symbol = &extracted[source_index];
            let mut refs = Vec::new();
            collect_identifier_refs_in_range(
                root,
                symbol.start_byte,
                symbol.end_byte,
                Some((symbol.name_start_byte, symbol.name_end_byte)),
                source.text.as_bytes(),
                &mut refs,
            )?;
            let mut seen_names = HashSet::new();
            for name in refs {
                if !seen_names.insert(name.clone()) {
                    continue;
                }
                let Some(target_indexes) = symbols_by_name.get(&name) else {
                    continue;
                };
                for &target_index in target_indexes {
                    if target_index == source_index {
                        continue;
                    }
                    let source_id = symbol_ids[source_index];
                    let target_id = symbol_ids[target_index];
                    if mention_pairs.insert((source_id, target_id)) {
                        edges.push(CodeSymbolGraphEdge::new(
                            source_id,
                            EdgeKind::Mentions,
                            target_id,
                            EdgeKind::Mentions.default_weight().unwrap_or(0.6),
                        ));
                    }
                }
            }
        }
    }

    add_same_file_contiguity_edges(&extracted, &symbol_ids, &mut edges);

    let manifest = CodeSymbolManifest::new(
        repo_ref,
        commit_hash,
        chunks,
        extracted
            .into_iter()
            .map(|symbol| {
                let mut revision = symbol.revision;
                revision.source_session =
                    Some(format!("{TREE_SITTER_RUST_SOURCE_KIND}:{repo_key}"));
                revision
            })
            .collect(),
    )?;
    CodeSymbolGraph::new(manifest, edges)
}

#[derive(Debug, Clone)]
struct ExtractedCodeSymbol {
    revision: CodeSymbolRevision,
    start_byte: usize,
    end_byte: usize,
    name_start_byte: usize,
    name_end_byte: usize,
    start_line: u32,
    end_line: u32,
}

struct RustDefinitionChunk<'a> {
    chunk: CodeChunk,
    text: &'a str,
}

struct ParsedRustSource<'a> {
    text: &'a str,
    tree: tree_sitter::Tree,
    symbol_indexes: Vec<usize>,
}

pub(super) fn is_tree_sitter_rust_source(path: &str) -> bool {
    path.ends_with(".rs")
}

fn parse_rust_source(source: &str) -> Result<tree_sitter::Tree> {
    let mut parser = tree_sitter::Parser::new();
    let language = tree_sitter_rust::LANGUAGE.into();
    parser
        .set_language(&language)
        .map_err(|_| Error::InvalidCodeSymbolManifestBody("tree-sitter Rust language rejected"))?;
    parser
        .parse(source, None)
        .ok_or(Error::InvalidCodeSymbolManifestBody(
            "tree-sitter Rust parse failed",
        ))
}

pub(super) fn derive_rust_code_chunks_from_text_diff(
    path: &str,
    old_text: &str,
    new_text: &str,
) -> Result<Vec<CodeChunk>> {
    let changed_ranges = changed_line_ranges(old_text, new_text);
    let tree = parse_rust_source(new_text)?;
    let mut chunks = Vec::new();
    collect_changed_rust_chunks(
        tree.root_node(),
        path,
        new_text,
        &changed_ranges,
        &mut chunks,
    )?;
    chunks.sort_by(compare_chunks);
    chunks.dedup_by(|left, right| {
        left.path == right.path
            && left.start_line == right.start_line
            && left.end_line == right.end_line
            && left.content_hash == right.content_hash
    });
    if chunks.is_empty() && !changed_ranges.is_empty() {
        chunks.push(CodeChunk::from_text(
            path,
            1,
            source_end_line(new_text)?,
            new_text,
        )?);
    }
    Ok(chunks)
}

pub(super) fn rust_code_embedding_inputs(
    repo_ref: &RepoRef,
    path: &str,
    source: &str,
    changed_ranges: &[Range<usize>],
) -> Result<Vec<CodeEmbeddingInput>> {
    let tree = parse_rust_source(source)?;
    let mut inputs = Vec::new();
    collect_changed_rust_embedding_inputs(
        tree.root_node(),
        repo_ref,
        path,
        source,
        changed_ranges,
        &mut inputs,
    )?;
    inputs.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.start_line.cmp(&right.start_line))
            .then_with(|| left.end_line.cmp(&right.end_line))
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.content_hash.cmp(&right.content_hash))
    });
    Ok(inputs)
}

fn collect_changed_rust_chunks(
    node: tree_sitter::Node<'_>,
    path: &str,
    source: &str,
    changed_ranges: &[Range<usize>],
    chunks: &mut Vec<CodeChunk>,
) -> Result<()> {
    if rust_definition_identity(node, source)?.is_some() {
        let definition = rust_definition_chunk(path, source, node)?;
        if definition_has_uncovered_changed_lines(
            node,
            source,
            definition.chunk.start_line,
            definition.chunk.end_line,
            changed_ranges,
        )? {
            chunks.push(definition.chunk);
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_changed_rust_chunks(child, path, source, changed_ranges, chunks)?;
    }
    Ok(())
}

fn collect_changed_rust_embedding_inputs(
    node: tree_sitter::Node<'_>,
    repo_ref: &RepoRef,
    path: &str,
    source: &str,
    changed_ranges: &[Range<usize>],
    inputs: &mut Vec<CodeEmbeddingInput>,
) -> Result<()> {
    if let Some((name, kind)) = rust_definition_identity(node, source)? {
        let definition = rust_definition_chunk(path, source, node)?;
        if definition_has_uncovered_changed_lines(
            node,
            source,
            definition.chunk.start_line,
            definition.chunk.end_line,
            changed_ranges,
        )? {
            let fingerprint = derive_symbol_fingerprint(
                path,
                &name,
                kind,
                std::slice::from_ref(&definition.chunk),
            )?;
            let revision =
                CodeSymbolRevision::new(path, name.clone(), kind, fingerprint, vec![0], None, None);
            let entity_id = code_symbol_entity_id(repo_ref, &revision)?;
            inputs.push(CodeEmbeddingInput::new(
                entity_id,
                path,
                name,
                kind,
                definition.chunk.start_line,
                definition.chunk.end_line,
                definition.chunk.content_hash,
                definition.text,
            ));
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_changed_rust_embedding_inputs(
            child,
            repo_ref,
            path,
            source,
            changed_ranges,
            inputs,
        )?;
    }
    Ok(())
}

fn collect_rust_definitions(
    node: tree_sitter::Node<'_>,
    path: &str,
    source: &str,
    chunks: &mut Vec<CodeChunk>,
    symbols: &mut Vec<ExtractedCodeSymbol>,
    source_symbol_indexes: &mut Vec<usize>,
) -> Result<()> {
    if let Some((name, kind)) = rust_definition_identity(node, source)? {
        validate_text(&name, CODE_SYMBOL_NAME_MAX_BYTES, "symbol name")?;
        let definition = rust_definition_chunk(path, source, node)?;
        let chunk = definition.chunk;
        let chunk_index = u32::try_from(chunks.len()).map_err(|_| {
            Error::InvalidCodeSymbolManifestBody("tree-sitter chunk index exceeds u32")
        })?;
        let fingerprint =
            derive_symbol_fingerprint(path, &name, kind, std::slice::from_ref(&chunk))?;
        let start_line = chunk.start_line;
        let end_line = chunk.end_line;
        chunks.push(chunk);
        let byte_range = node.byte_range();
        let name_range = rust_definition_name_range(node).unwrap_or(byte_range.clone());
        let symbol_index = symbols.len();
        symbols.push(ExtractedCodeSymbol {
            revision: CodeSymbolRevision::new(
                path,
                name,
                kind,
                fingerprint,
                vec![chunk_index],
                None,
                None,
            ),
            start_byte: byte_range.start,
            end_byte: byte_range.end,
            name_start_byte: name_range.start,
            name_end_byte: name_range.end,
            start_line,
            end_line,
        });
        source_symbol_indexes.push(symbol_index);
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_rust_definitions(child, path, source, chunks, symbols, source_symbol_indexes)?;
    }
    Ok(())
}

fn rust_definition_identity(
    node: tree_sitter::Node<'_>,
    source: &str,
) -> Result<Option<(String, &'static str)>> {
    if let Some(kind) = rust_definition_kind(node.kind())
        && let Some(name_node) = node.child_by_field_name("name")
    {
        let name = node_text(name_node, source)?.to_owned();
        return Ok(Some((name, kind)));
    }
    if node.kind() != "impl_item" {
        return Ok(None);
    }
    let trait_text = node
        .child_by_field_name("trait")
        .map(|child| node_text(child, source).map(str::trim).map(str::to_owned))
        .transpose()?;
    let type_text = node
        .child_by_field_name("type")
        .map(|child| node_text(child, source).map(str::trim).map(str::to_owned))
        .transpose()?;
    let name = match (trait_text, type_text) {
        (Some(trait_text), Some(type_text)) if !trait_text.is_empty() && !type_text.is_empty() => {
            format!("impl {trait_text} for {type_text}")
        }
        (_, Some(type_text)) if !type_text.is_empty() => format!("impl {type_text}"),
        _ => format!(
            "impl@{}:{}",
            node.start_position().row + 1,
            node.end_position().row + 1
        ),
    };
    Ok(Some((name, "impl")))
}

fn rust_definition_name_range(node: tree_sitter::Node<'_>) -> Option<Range<usize>> {
    node.child_by_field_name("name")
        .or_else(|| node.child_by_field_name("type"))
        .map(|name_node| name_node.byte_range())
}

fn rust_definition_chunk<'a>(
    path: &str,
    source: &'a str,
    node: tree_sitter::Node<'_>,
) -> Result<RustDefinitionChunk<'a>> {
    let start_byte = rust_doc_context_start_byte(node, source);
    let text =
        source
            .get(start_byte..node.end_byte())
            .ok_or(Error::InvalidCodeSymbolManifestBody(
                "tree-sitter definition byte range is invalid",
            ))?;
    let start_line = source[..start_byte]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let start_line = u32::try_from(start_line)
        .map_err(|_| Error::InvalidCodeSymbolManifestBody("line number exceeds u32"))?;
    let end_line = tree_sitter_line_number(node.end_position().row)?;
    Ok(RustDefinitionChunk {
        chunk: CodeChunk::from_text(path, start_line, end_line, text)?,
        text,
    })
}

fn rust_doc_context_start_byte(node: tree_sitter::Node<'_>, source: &str) -> usize {
    let mut start_byte = node.start_byte();
    let mut previous = node.prev_named_sibling();
    while let Some(candidate) = previous {
        if !is_rust_doc_context_node(candidate.kind()) {
            break;
        }
        let between = source
            .get(candidate.end_byte()..start_byte)
            .unwrap_or_default();
        if between
            .lines()
            .filter(|line| line.trim().is_empty())
            .count()
            > 1
        {
            break;
        }
        start_byte = candidate.start_byte();
        previous = candidate.prev_named_sibling();
    }
    start_byte
}

fn is_rust_doc_context_node(kind: &str) -> bool {
    matches!(
        kind,
        "line_comment" | "block_comment" | "attribute_item" | "inner_attribute_item"
    )
}

fn rust_definition_kind(kind: &str) -> Option<&'static str> {
    match kind {
        "function_item" => Some("function"),
        "struct_item" => Some("struct"),
        "enum_item" => Some("enum"),
        "trait_item" => Some("trait"),
        "mod_item" => Some("module"),
        "const_item" => Some("const"),
        "static_item" => Some("static"),
        "type_item" => Some("type"),
        "macro_definition" => Some("macro"),
        _ => None,
    }
}

fn rust_definition_line_range(source: &str, node: tree_sitter::Node<'_>) -> Result<Range<usize>> {
    let start_byte = rust_doc_context_start_byte(node, source);
    let start_line = source[..start_byte]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count();
    let end_line = usize::try_from(tree_sitter_line_number(node.end_position().row)?)
        .map_err(|_| Error::InvalidCodeSymbolManifestBody("line number exceeds usize"))?;
    Ok(start_line..end_line)
}

fn definition_has_uncovered_changed_lines(
    node: tree_sitter::Node<'_>,
    source: &str,
    start_line: u32,
    end_line: u32,
    changed_ranges: &[Range<usize>],
) -> Result<bool> {
    let start = usize::try_from(start_line.saturating_sub(1)).unwrap_or(usize::MAX);
    let end = usize::try_from(end_line).unwrap_or(usize::MAX);
    let mut uncovered = changed_ranges
        .iter()
        .filter_map(|changed| {
            let range_start = changed.start.max(start);
            let range_end = changed.end.min(end);
            (range_start < range_end).then_some(range_start..range_end)
        })
        .collect::<Vec<_>>();
    if uncovered.is_empty() {
        return Ok(false);
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        subtract_descendant_definition_lines(child, source, &mut uncovered)?;
        if uncovered.is_empty() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn subtract_descendant_definition_lines(
    node: tree_sitter::Node<'_>,
    source: &str,
    uncovered: &mut Vec<Range<usize>>,
) -> Result<()> {
    if rust_definition_identity(node, source)?.is_some() {
        subtract_line_range(uncovered, rust_definition_line_range(source, node)?);
        return Ok(());
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        subtract_descendant_definition_lines(child, source, uncovered)?;
        if uncovered.is_empty() {
            break;
        }
    }
    Ok(())
}

fn collect_identifier_refs_in_range(
    node: tree_sitter::Node<'_>,
    start_byte: usize,
    end_byte: usize,
    skip_range: Option<(usize, usize)>,
    source: &[u8],
    refs: &mut Vec<String>,
) -> Result<()> {
    let range = node.byte_range();
    if range.end <= start_byte || range.start >= end_byte {
        return Ok(());
    }
    if let Some((skip_start, skip_end)) = skip_range
        && range.start == skip_start
        && range.end == skip_end
    {
        return Ok(());
    }
    if node.child_count() == 0 && is_reference_identifier_kind(node.kind()) {
        let bytes = source
            .get(range)
            .ok_or(Error::InvalidCodeSymbolManifestBody(
                "tree-sitter identifier byte range is invalid",
            ))?;
        let text = std::str::from_utf8(bytes).map_err(|_| {
            Error::InvalidCodeSymbolManifestBody("tree-sitter identifier is not UTF-8")
        })?;
        if !text.is_empty() {
            refs.push(text.to_owned());
        }
        return Ok(());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_identifier_refs_in_range(child, start_byte, end_byte, skip_range, source, refs)?;
    }
    Ok(())
}

fn is_reference_identifier_kind(kind: &str) -> bool {
    matches!(kind, "identifier" | "type_identifier" | "field_identifier")
}

fn add_same_file_contiguity_edges(
    symbols: &[ExtractedCodeSymbol],
    symbol_ids: &[EntityId],
    edges: &mut Vec<CodeSymbolGraphEdge>,
) {
    let mut by_path = BTreeMap::<&str, Vec<usize>>::new();
    for (index, symbol) in symbols.iter().enumerate() {
        by_path
            .entry(symbol.revision.path.as_str())
            .or_default()
            .push(index);
    }
    for indexes in by_path.values_mut() {
        indexes.sort_by(|left, right| {
            let left_symbol = &symbols[*left];
            let right_symbol = &symbols[*right];
            left_symbol
                .start_line
                .cmp(&right_symbol.start_line)
                .then_with(|| left_symbol.end_line.cmp(&right_symbol.end_line))
                .then_with(|| left_symbol.revision.name.cmp(&right_symbol.revision.name))
                .then_with(|| left_symbol.revision.kind.cmp(&right_symbol.revision.kind))
        });
        for pair in indexes.windows(2) {
            let left = symbol_ids[pair[0]];
            let right = symbol_ids[pair[1]];
            edges.push(CodeSymbolGraphEdge::new(
                left,
                EdgeKind::Attached,
                right,
                0.2,
            ));
            edges.push(CodeSymbolGraphEdge::new(
                right,
                EdgeKind::Attached,
                left,
                0.2,
            ));
        }
    }
}

fn tree_sitter_line_number(row: usize) -> Result<u32> {
    u32::try_from(row + 1)
        .map_err(|_| Error::InvalidCodeSymbolManifestBody("tree-sitter row exceeds u32"))
}

fn node_text<'a>(node: tree_sitter::Node<'_>, source: &'a str) -> Result<&'a str> {
    source
        .get(node.byte_range())
        .ok_or(Error::InvalidCodeSymbolManifestBody(
            "tree-sitter node byte range is invalid",
        ))
}
