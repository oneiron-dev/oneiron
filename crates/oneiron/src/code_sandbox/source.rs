//! Code-mode source preparation (FIX 8276, owner ruling CODE-MODE-TS = A).
//!
//! An agent may write its program in TypeScript. The host prepares every
//! program before QuickJS runs it, in process: a program Oxc parses as
//! JavaScript, in the same async-function-body grammar the guest evaluates,
//! runs exactly as written, byte for byte, with no reprint. Only a program
//! that fails that parse is parsed as TypeScript and transformed by Oxc; the
//! guest runs the JavaScript Oxc prints, and the original stays the program
//! of record. A program neither parse accepts runs as written, so QuickJS
//! reports its own error, with a typed note. Preparation never refuses a
//! program and adds no bound of its own: what the guest runs keeps every
//! budget it had.

use std::path::{Path, PathBuf};

use oxc_allocator::{Allocator, TakeIn};
use oxc_ast::ast::{ArrowFunctionBody, Expression, Program, Statement};
use oxc_codegen::{Codegen, CodegenOptions};
use oxc_parser::Parser;
use oxc_semantic::SemanticBuilder;
use oxc_span::SourceType;
use oxc_transformer::{
    DecoratorOptions, HelperLoaderMode, HelperLoaderOptions, TransformOptions, Transformer,
};

use crate::{Error, Result};

/// The guest's own envelope around a program (components/code-run-quickjs/guest.c):
/// the program is the body of one async arrow, evaluated as a global script,
/// never as a module. Preparation parses the same text the guest evaluates.
const GUEST_PREFIX: &str = "(async () => {\n";
const GUEST_SUFFIX: &str = "\n})()";

/// The Oxc release that prepares a TypeScript program. The workspace pins
/// every Oxc crate to exactly this version (`=0.152.0`).
pub const OXC_VERSION: &str = "0.152.0";

/// The transform a TypeScript program runs under, by name (CALL, FIX 8276):
/// Oxc's TypeScript transform with its default options (types removed;
/// enums, runtime namespaces and parameter properties lowered), legacy
/// decorators with no emitted metadata, their two helpers defined in the
/// program itself, and no ECMAScript lowering.
pub const TS_TRANSFORM_OPTIONS: &str =
    "typescript-default;decorators-legacy;decorator-metadata-off;helpers-in-program;no-lowering";

/// The two helpers Oxc's legacy decorator lowering calls through
/// `babelHelpers` (its external helper mode), defined on one line in the
/// program itself: QuickJS has no module loader to import them from.
const DECORATOR_HELPERS: &str = concat!(
    "var babelHelpers = { decorate: function (decorators, target, key, desc) { ",
    "var c = arguments.length, r = c < 3 ? target : desc === null ? ",
    "desc = Object.getOwnPropertyDescriptor(target, key) : desc, d; ",
    "if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") ",
    "r = Reflect.decorate(decorators, target, key, desc); ",
    "else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) ",
    "r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r; ",
    "return c > 3 && r && Object.defineProperty(target, key, r), r; }, ",
    "decorateParam: function (index, decorator) { ",
    "return function (target, key) { decorator(target, key, index); }; } };"
);

/// The first line of every error the QuickJS guest reports for a thrown
/// exception: where the throw is in the program it ran, `<line>:<column>`
/// (one-based; the column counts Unicode scalar values, as QuickJS does), or
/// `-` where QuickJS gave none. The host strips it before the text reaches
/// anyone.
const GUEST_ERROR_HEADER: &str = "oneiron-guest-error/1 ";

/// The record a TypeScript program's preparation leaves beside it.
const RECORD_SCHEMA_VERSION: u32 = 1;

/// The domain of a TypeScript preparation's identity digest.
const IDENTITY_DOMAIN: &[u8] = b"oneiron:code-mode:typescript-preparation:v1";

/// The language a program ran as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceLanguage {
    JavaScript,
    TypeScript,
}

impl SourceLanguage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
        }
    }
}

/// Why a program that is not JavaScript Oxc accepts runs as written (CALL,
/// FIX 8276). Each is the host's own fact, never a refusal: the program goes
/// to QuickJS unchanged, and QuickJS stays the authority on what it does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreparationNote {
    /// Neither the JavaScript nor the TypeScript parse accepted the program.
    ParsedAsNeither,
    /// The TypeScript parse accepted the program, but it holds no TypeScript
    /// syntax, so nothing would change it.
    NoTypeScriptSyntax,
    /// Oxc's TypeScript transform could not lower a construct the program
    /// uses; its first message.
    UnsupportedTypeScript(String),
    /// The transform left a program shape the guest's envelope cannot hold.
    UnexpectedTransformShape,
    /// Oxc stopped unexpectedly while preparing the program.
    PreparationStopped,
}

impl PreparationNote {
    /// The note's stable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ParsedAsNeither => "source_parsed_as_neither",
            Self::NoTypeScriptSyntax => "source_has_no_typescript_syntax",
            Self::UnsupportedTypeScript(_) => "unsupported_typescript_syntax",
            Self::UnexpectedTransformShape => "unexpected_typescript_transform_shape",
            Self::PreparationStopped => "source_preparation_stopped",
        }
    }
}

/// One program, prepared for the guest: the original as written, and for a
/// TypeScript program the JavaScript the guest runs in its place.
#[derive(Debug, Clone)]
pub struct PreparedSource<'a> {
    original: &'a str,
    transpiled: Option<TranspiledSource>,
    note: Option<PreparationNote>,
    /// Lines a host prelude put before the authored source (a callable
    /// skill's arguments): a position names the authored line, past them.
    prelude_lines: u32,
}

/// The JavaScript Oxc printed for a TypeScript program, and how its
/// positions go back to the TypeScript source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranspiledSource {
    executed_js: String,
    /// Lines put before the printed program (the decorator helpers).
    helper_lines: u32,
    /// Oxc's source map, `[printed line, printed column, source line,
    /// source column]`, zero-based, columns in UTF-16 units, sorted. A
    /// source line counts the guest envelope's first line, so line `n` is
    /// the program's one-based line `n`.
    mappings: Vec<[u32; 4]>,
}

/// Where a guest's exception was thrown in the program it ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GuestPosition {
    line: u32,
    column: u32,
}

/// The typed per-program record of a TypeScript preparation (CALL, FIX
/// 8276), kept beside the original source: the executed JavaScript's digest,
/// the position map and the Oxc version and options pin.
#[derive(Debug, serde::Serialize)]
struct PreparationRecord<'a> {
    schema_version: u32,
    language: &'static str,
    oxc_version: &'static str,
    transform_options: &'static str,
    original_blake3: String,
    executed_blake3: String,
    helper_lines: u32,
    mappings: &'a [[u32; 4]],
}

/// Prepares `source` for the guest. Never fails and never refuses: a program
/// that is not TypeScript Oxc can lower runs as written, with a note.
#[must_use]
pub fn prepare_source(source: &str) -> PreparedSource<'_> {
    let (transpiled, note) = match std::panic::catch_unwind(|| prepare(source)) {
        Ok(prepared) => prepared,
        Err(_) => (None, Some(PreparationNote::PreparationStopped)),
    };
    PreparedSource {
        original: source,
        transpiled,
        note,
        prelude_lines: 0,
    }
}

impl<'a> PreparedSource<'a> {
    /// The same preparation, for a program whose first `lines` lines are a
    /// host prelude, not the authored source.
    #[must_use]
    pub fn with_prelude_lines(mut self, lines: u32) -> Self {
        self.prelude_lines = lines;
        self
    }

    /// The program as written: the program of record.
    #[must_use]
    pub fn original(&self) -> &'a str {
        self.original
    }

    /// What the guest runs: the original itself, unless it is TypeScript.
    #[must_use]
    pub fn executed(&self) -> &str {
        self.transpiled
            .as_ref()
            .map_or(self.original, |transpiled| transpiled.executed_js.as_str())
    }

    #[must_use]
    pub fn language(&self) -> SourceLanguage {
        if self.transpiled.is_some() {
            SourceLanguage::TypeScript
        } else {
            SourceLanguage::JavaScript
        }
    }

    #[must_use]
    pub fn transpiled(&self) -> Option<&TranspiledSource> {
        self.transpiled.as_ref()
    }

    #[must_use]
    pub fn note(&self) -> Option<&PreparationNote> {
        self.note.as_ref()
    }

    /// Where a failed TypeScript program threw, in its TypeScript source, as
    /// the suffix its error carries. `None` for a JavaScript program, whose
    /// error stays exactly as it was, and for a throw outside the authored
    /// source (the guest envelope, a helper or a prelude line).
    pub(crate) fn failure_position(&self, at: Option<GuestPosition>) -> Option<String> {
        let (line, column) = self.transpiled.as_ref()?.source_position(self.original, at?)?;
        let line = line
            .checked_sub(self.prelude_lines)
            .filter(|line| *line > 0)?;
        Some(format!(
            "; at line {line}, column {column} of the TypeScript source"
        ))
    }
}

impl TranspiledSource {
    #[must_use]
    pub fn executed_js(&self) -> &str {
        &self.executed_js
    }

    /// The preparation's identity: the Oxc pin, the options, the executed
    /// JavaScript and its map. A run's step binds it to its checkpoint.
    #[must_use]
    pub fn identity(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        for part in [
            IDENTITY_DOMAIN,
            OXC_VERSION.as_bytes(),
            TS_TRANSFORM_OPTIONS.as_bytes(),
            self.executed_js.as_bytes(),
        ] {
            hasher.update(&(part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        hasher.update(&self.helper_lines.to_be_bytes());
        hasher.update(&(self.mappings.len() as u64).to_be_bytes());
        for mapping in &self.mappings {
            for value in mapping {
                hasher.update(&value.to_be_bytes());
            }
        }
        *hasher.finalize().as_bytes()
    }

    /// The typed per-program record, as the JSON body the run keeps.
    ///
    /// # Errors
    ///
    /// The record failing to encode.
    pub fn record_json(&self, original: &str) -> Result<Vec<u8>> {
        serde_json::to_vec(&PreparationRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            language: SourceLanguage::TypeScript.as_str(),
            oxc_version: OXC_VERSION,
            transform_options: TS_TRANSFORM_OPTIONS,
            original_blake3: blake3::hash(original.as_bytes()).to_hex().to_string(),
            executed_blake3: blake3::hash(self.executed_js.as_bytes())
                .to_hex()
                .to_string(),
            helper_lines: self.helper_lines,
            mappings: &self.mappings,
        })
        .map_err(|_| Error::InvalidConfig("typescript preparation record encoding".to_owned()))
    }

    /// The one-based line and column in `original` that printed position
    /// `at` came from, when the map names one on that printed line.
    fn source_position(&self, original: &str, at: GuestPosition) -> Option<(u32, u32)> {
        let line = at.line.checked_sub(1)?;
        let text = self.executed_js.split('\n').nth(line as usize)?;
        let column = utf16_units(text, at.column.checked_sub(1)?);
        let printed = line.checked_sub(self.helper_lines)?;
        let before = self
            .mappings
            .partition_point(|mapping| (mapping[0], mapping[1]) <= (printed, column));
        let mapping = self.mappings[..before]
            .last()
            .filter(|mapping| mapping[0] == printed)?;
        let source_line = mapping[2];
        let source = original
            .split('\n')
            .nth(source_line.checked_sub(1)? as usize)?;
        Some((source_line, scalar_count(source, mapping[3]) + 1))
    }
}

/// Splits the guest's error into its text and the position its header
/// names. A message with no header (a fixed guest failure, or a component
/// that writes none) is all text, as it always was.
pub(crate) fn split_guest_error(message: &str) -> (&str, Option<GuestPosition>) {
    let Some((head, text)) = message
        .strip_prefix(GUEST_ERROR_HEADER)
        .and_then(|rest| rest.split_once('\n'))
    else {
        return (message, None);
    };
    if head == "-" {
        return (text, None);
    }
    let position = head.split_once(':').and_then(|(line, column)| {
        Some(GuestPosition {
            line: line.parse().ok()?,
            column: column.parse().ok()?,
        })
    });
    match position {
        Some(position) => (text, Some(position)),
        None => (message, None),
    }
}

/// UTF-16 units in the first `scalars` characters of `text`.
fn utf16_units(text: &str, scalars: u32) -> u32 {
    text.chars()
        .take(scalars as usize)
        .map(|ch| ch.len_utf16() as u32)
        .sum()
}

/// Characters of `text` before UTF-16 offset `units`.
fn scalar_count(text: &str, units: u32) -> u32 {
    let mut seen = 0_u32;
    let mut count = 0_u32;
    for ch in text.chars() {
        if seen >= units {
            break;
        }
        seen += ch.len_utf16() as u32;
        count += 1;
    }
    count
}

fn prepare(source: &str) -> (Option<TranspiledSource>, Option<PreparationNote>) {
    let wrapped = format!("{GUEST_PREFIX}{source}{GUEST_SUFFIX}");
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, &wrapped, SourceType::script()).parse();
    if !parsed.fatal_error && parsed.diagnostics.is_empty() {
        return (None, None);
    }
    match transpile(&wrapped) {
        Ok(transpiled) => (Some(transpiled), None),
        Err(note) => (None, Some(note)),
    }
}

/// Parses `wrapped` as TypeScript in the guest's grammar, transforms it and
/// prints the arrow's body: the program the guest runs in its envelope.
fn transpile(wrapped: &str) -> std::result::Result<TranspiledSource, PreparationNote> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, wrapped, SourceType::ts().with_script(true)).parse();
    // A recovered tree after an error is never run.
    if parsed.fatal_error || !parsed.diagnostics.is_empty() {
        return Err(PreparationNote::ParsedAsNeither);
    }
    let mut program = parsed.program;
    let untouched = Codegen::new().build(&program).code;
    let scoping = SemanticBuilder::new()
        .with_excess_capacity(2.0)
        .with_enum_eval(true)
        .build(&program)
        .semantic
        .into_scoping();
    let transformed = Transformer::new(&allocator, Path::new("program.ts"), &transform_options())
        .build_with_scoping(scoping, &mut program);
    if let Some(first) = transformed.diagnostics.first() {
        return Err(PreparationNote::UnsupportedTypeScript(first.to_string()));
    }
    #[expect(deprecated, reason = "the transform names the helpers it called only here")]
    let helpers = !transformed.helpers_used.is_empty();
    // A program the transform leaves as it was holds no TypeScript: it runs
    // as written, never reprinted.
    if Codegen::new().build(&program).code == untouched {
        return Err(PreparationNote::NoTypeScriptSyntax);
    }
    lift_body(&allocator, &mut program).ok_or(PreparationNote::UnexpectedTransformShape)?;
    Ok(print(&allocator, &mut program, wrapped, helpers))
}

/// The transform options [`TS_TRANSFORM_OPTIONS`] names.
fn transform_options() -> TransformOptions {
    TransformOptions {
        decorator: DecoratorOptions {
            legacy: true,
            emit_decorator_metadata: false,
            ..DecoratorOptions::default()
        },
        helper_loader: HelperLoaderOptions {
            mode: HelperLoaderMode::External,
            ..HelperLoaderOptions::default()
        },
        ..TransformOptions::default()
    }
}

/// Makes the envelope arrow's body the program: its directives and its
/// statements, nothing else. `None` when the transform left anything else.
fn lift_body<'a>(allocator: &'a Allocator, program: &mut Program<'a>) -> Option<()> {
    if program.body.len() != 1 || !program.directives.is_empty() || program.hashbang.is_some() {
        return None;
    }
    let (directives, statements) = {
        let Some(Statement::ExpressionStatement(statement)) = program.body.first_mut() else {
            return None;
        };
        let Expression::CallExpression(call) = &mut statement.expression else {
            return None;
        };
        if !call.arguments.is_empty() {
            return None;
        }
        let Expression::ParenthesizedExpression(envelope) = &mut call.callee else {
            return None;
        };
        let Expression::ArrowFunctionExpression(arrow) = &mut envelope.expression else {
            return None;
        };
        let ArrowFunctionBody::FunctionBody(body) = &mut arrow.body else {
            return None;
        };
        (
            body.directives.take_in(&allocator),
            body.statements.take_in(&allocator),
        )
    };
    program.directives = directives;
    program.body = statements;
    Some(())
}

/// Prints the lifted program with its map. Decorator helpers go on one
/// line of their own, after the directive prologue, so a directive keeps its
/// meaning.
fn print<'a>(
    allocator: &'a Allocator,
    program: &mut Program<'a>,
    wrapped: &str,
    helpers: bool,
) -> TranspiledSource {
    let mut executed_js = String::new();
    if helpers {
        for directive in program.directives.iter() {
            let text = &wrapped[directive.span.start as usize..directive.span.end as usize];
            executed_js.push_str(text);
            if !text.ends_with(';') {
                executed_js.push(';');
            }
            executed_js.push(' ');
        }
        program.directives = oxc_allocator::Vec::new_in(&allocator);
        executed_js.push_str(DECORATOR_HELPERS);
        executed_js.push('\n');
    }
    let printed = Codegen::new()
        .with_options(CodegenOptions {
            source_map_path: Some(PathBuf::from("program.ts")),
            ..CodegenOptions::default()
        })
        .build(program);
    let mut mappings: Vec<[u32; 4]> = printed
        .map
        .map(|map| {
            map.get_tokens()
                .map(|token| {
                    [
                        token.get_dst_line(),
                        token.get_dst_col(),
                        token.get_src_line(),
                        token.get_src_col(),
                    ]
                })
                .collect()
        })
        .unwrap_or_default();
    mappings.sort_unstable();
    executed_js.push_str(&printed.code);
    TranspiledSource {
        executed_js,
        helper_lines: u32::from(helpers),
        mappings,
    }
}
