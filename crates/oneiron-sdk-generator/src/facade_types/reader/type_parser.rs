//! The type parser: a Rust type's text as an `Ast` tree (Python's `parse_type`, and the cursor its nested
//! functions share).

use std::sync::LazyLock;

use regex::Regex;

use super::super::{RECURSION_LIMIT, index_error, recursion_error};
use crate::error::GenerateError;
use crate::py::re::compile;
use crate::py::text::{is_word, strip};

/// A Rust type as a tree (Python's `parse_type` tuples).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Ast {
    /// `("path", segments, args)`
    Path(Vec<String>, Vec<Ast>),
    /// `("tuple", items)`
    Tuple(Vec<Ast>),
    /// `("array", item)`
    Array(Box<Ast>),
    /// `("ref", item)`
    Ref(Box<Ast>),
    /// `("raw", text)`
    Raw(String),
}

/// `TOKEN`: `re.compile(r"\s*(::|->|'[A-Za-z_]\w*|r#\w+|[A-Za-z_]\w*|\d+|.)", re.S)`.
static TOKEN: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?s)\s*(::|->|'[A-Za-z_]\w*|r#\w+|[A-Za-z_]\w*|\d+|.)"));

/// `re.match(r'(r#)?[A-Za-z_]\w*$', name)` on a token (a token holds no newline).
fn is_path_segment(name: &str) -> bool {
    let ident = |text: &str| {
        let mut chars = text.chars();
        chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(is_word)
    };
    name.strip_prefix("r#").is_some_and(ident) || ident(name)
}

/// The Python loop `parse_type` never leaves: a `dyn`, `impl`, `fn`, `*`, `<`, `!` or `_` in a type argument or
/// a tuple, which `typ()` returns as raw without taking it, so the loop appends to its list forever. The port
/// stops there instead (FIX row filed; documented in the PR).
fn no_progress(text: &str, token: &str) -> GenerateError {
    GenerateError::exception(
        "RuntimeError",
        format!(
            "parse_type does not advance at `{token}` in `{text}` (the Python generator looped here without end)"
        ),
    )
}

/// The cursor `parse_type`'s nested functions share.
struct TypeParser<'t> {
    text: &'t str,
    tokens: Vec<&'t str>,
    position: usize,
    /// How many `typ()` and `args()` calls are open (Python's frames for the nested functions): a type nested as
    /// deep as Python's recursion limit is its `RecursionError` here, not an exhausted native stack.
    depth: usize,
}

impl<'t> TypeParser<'t> {
    fn peek(&self, offset: usize) -> Option<&'t str> {
        self.tokens.get(self.position + offset).copied()
    }

    /// `take()`: Python's `tokens[position - 1]` past the end is an `IndexError`.
    fn take(&mut self) -> Result<&'t str, GenerateError> {
        self.position += 1;
        self.tokens
            .get(self.position - 1)
            .copied()
            .ok_or_else(index_error)
    }

    fn raw(&self) -> Ast {
        Ast::Raw(self.text.to_owned())
    }

    fn until_close(&mut self, open: &str, close: &str) -> Result<(), GenerateError> {
        let mut depth: i64 = 1;
        while self.peek(0).is_some() && depth != 0 {
            let token = self.take()?;
            depth += i64::from(token == open);
            depth -= i64::from(token == close);
        }
        Ok(())
    }

    /// Opens one of Python's frames for `typ()` or `args()`.
    fn enter(&mut self) -> Result<(), GenerateError> {
        if self.depth >= RECURSION_LIMIT {
            return Err(recursion_error());
        }
        self.depth += 1;
        Ok(())
    }

    fn args(&mut self) -> Result<Vec<Ast>, GenerateError> {
        self.enter()?;
        let out = self.args_frame();
        self.depth -= 1;
        out
    }

    /// The body of Python's `args()`, inside the frame `args` opens.
    fn args_frame(&mut self) -> Result<Vec<Ast>, GenerateError> {
        let mut out = Vec::new();
        while let Some(token) = self.peek(0).filter(|token| *token != ">") {
            let before = self.position;
            if token.starts_with('\'') {
                self.take()?;
            } else if self.peek(1) == Some("=") && self.peek(2) != Some("=") {
                self.take()?;
                self.take()?;
                self.typ()?;
            } else if token == "{" {
                self.take()?;
                self.until_close("{", "}")?;
            } else {
                out.push(self.typ()?);
            }
            if self.peek(0) == Some(",") {
                self.take()?;
            }
            if self.position == before {
                return Err(no_progress(self.text, token));
            }
        }
        if self.peek(0) == Some(">") {
            self.take()?;
        }
        Ok(out)
    }

    fn typ(&mut self) -> Result<Ast, GenerateError> {
        self.enter()?;
        let node = self.typ_frame();
        self.depth -= 1;
        node
    }

    /// The body of Python's `typ()`, inside the frame `typ` opens.
    fn typ_frame(&mut self) -> Result<Ast, GenerateError> {
        let Some(token) = self.peek(0) else {
            return Ok(self.raw());
        };
        if token == "&" {
            self.take()?;
            if self.peek(0).is_some_and(|next| next.starts_with('\'')) {
                self.take()?;
            }
            if self.peek(0) == Some("mut") {
                self.take()?;
            }
            return Ok(Ast::Ref(Box::new(self.typ()?)));
        }
        if token == "(" {
            self.take()?;
            let mut items = Vec::new();
            while let Some(next) = self.peek(0).filter(|next| *next != ")") {
                let before = self.position;
                items.push(self.typ()?);
                if self.peek(0) == Some(",") {
                    self.take()?;
                }
                if self.position == before {
                    return Err(no_progress(self.text, next));
                }
            }
            self.take()?;
            return Ok(Ast::Tuple(items));
        }
        if token == "[" {
            self.take()?;
            let item = self.typ()?;
            if self.peek(0) == Some(";") {
                self.take()?;
                while self.peek(0).is_some_and(|next| next != "]") {
                    // `take() in '([{'` is a substring test; a token is one bracket or a longer word.
                    if "([{".contains(self.take()?) {
                        self.until_close("[", "]")?;
                    }
                }
            }
            self.take()?;
            return Ok(Ast::Array(Box::new(item)));
        }
        if matches!(token, "dyn" | "impl" | "fn" | "*" | "<" | "!" | "_") {
            return Ok(self.raw());
        }
        let (mut segments, mut generic) = (Vec::new(), Vec::new());
        if token == "::" {
            self.take()?;
        }
        loop {
            let name = self.take()?;
            if !is_path_segment(name) {
                return Ok(self.raw());
            }
            segments.push(name.strip_prefix("r#").unwrap_or(name).to_owned());
            if self.peek(0) == Some("::") && self.peek(1) == Some("<") {
                self.take()?;
            }
            if self.peek(0) == Some("<") {
                self.take()?;
                generic = self.args()?;
            }
            if self.peek(0) == Some("::")
                && self.peek(1).is_some_and(|next| {
                    next.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                })
            {
                self.take()?;
                continue;
            }
            break;
        }
        Ok(Ast::Path(segments, generic))
    }
}

/// A Rust type as a tree; lifetimes, associated assignments and
/// const arguments are dropped, `dyn`/`impl`/`fn`/pointer/unknown syntax is raw, and leftover tokens make the
/// whole type raw.
pub(crate) fn parse_type(text: &str) -> Result<Ast, GenerateError> {
    let tokens = TOKEN
        .captures_iter(text)
        .filter_map(|found| found.get(1))
        .map(|token| token.as_str())
        .filter(|token| !strip(token).is_empty())
        .collect();
    let mut parser = TypeParser {
        text,
        tokens,
        position: 0,
        depth: 0,
    };
    let result = parser.typ()?;
    Ok(if parser.position >= parser.tokens.len() {
        result
    } else {
        parser.raw()
    })
}

// ---------------------------------------------------------------- an alias body (read_item)
