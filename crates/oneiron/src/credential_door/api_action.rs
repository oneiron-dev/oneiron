//! What an API call does, read from the request the door is about to stamp
//! (ARCH-0069 #door-reads-action). The door stays small: one reader per
//! protocol, REST, GraphQL, MCP and JSON-RPC. Knowledge of each service lives
//! in data, the per-API verb-class tables ([`super::api_verb_class`]), and
//! nothing here names a service.
//!
//! Every request reads as its REST action: the method and the path. A body
//! that also reads as GraphQL or JSON-RPC adds those actions, one per
//! operation root field or per batch element. A body that no reader reads
//! adds nothing, and a malformed GraphQL or JSON-RPC body adds no action of
//! that protocol. An unknown shape passes biased-permissive (DEC-0006); it is
//! never a refusal.
//!
//! A GraphQL action is the operation's type and one root field it selects,
//! not the operation's name. The client picks the name, so
//! `mutation harmless { deleteRepository(..) }` must still read as
//! `deleteRepository`. Aliases read as the field they alias. A fragment
//! spread at the root reads as the fragment's own root fields. A spread of a
//! fragment the document does not define reads as an unnamed field, which
//! only a row for any field (`*`) classes.

use std::collections::BTreeSet;

use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The protocol an action was read under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ApiProtocol {
    #[serde(rename = "rest")]
    Rest,
    #[serde(rename = "graphql")]
    GraphQl,
    #[serde(rename = "mcp")]
    Mcp,
    #[serde(rename = "json_rpc")]
    JsonRpc,
}

impl ApiProtocol {
    /// The protocol as a table row spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rest => "rest",
            Self::GraphQl => "graphql",
            Self::Mcp => "mcp",
            Self::JsonRpc => "json_rpc",
        }
    }
}

/// One action a request carries.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ApiAction {
    /// The host the request is addressed to, lower-cased, with its port when
    /// the URL names one other than its scheme's default.
    pub host: String,
    pub protocol: ApiProtocol,
    /// REST: the method, upper-cased. GraphQL: `query`, `mutation` or
    /// `subscription`. MCP: `tools/call`. JSON-RPC: the method.
    pub verb: String,
    /// REST: the path, without its query. GraphQL: one root field the
    /// operation selects, empty when it cannot be named. MCP: the tool's
    /// name. JSON-RPC: empty.
    pub target: String,
}

/// The MCP method whose `params.name` names the tool it calls.
const MCP_TOOLS_CALL: &str = "tools/call";

/// Every action the request to `url` with `method` and `body` carries: its
/// REST action first, then the GraphQL and JSON-RPC actions its JSON body
/// reads as, each once.
#[must_use]
pub fn read_api_actions(url: &Url, method: &str, body: Option<&[u8]>) -> Vec<ApiAction> {
    let host = host_of(url);
    let mut actions = vec![ApiAction {
        host: host.clone(),
        protocol: ApiProtocol::Rest,
        verb: method.trim().to_ascii_uppercase(),
        target: url.path().to_owned(),
    }];
    let Some(Ok(value)) = body.map(serde_json::from_slice::<Value>) else {
        return actions;
    };
    let elements = match &value {
        Value::Array(items) => items.as_slice(),
        other => std::slice::from_ref(other),
    };
    let mut read = BTreeSet::new();
    for element in elements {
        let Value::Object(member) = element else {
            continue;
        };
        if let Some(Value::String(query)) = member.get("query") {
            let operation_name = member.get("operationName").and_then(Value::as_str);
            for (kind, field) in graphql::root_fields(query, operation_name) {
                read.insert((ApiProtocol::GraphQl, kind.to_owned(), field.to_owned()));
            }
        }
        if member.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
            && let Some(rpc_method) = member.get("method").and_then(Value::as_str)
        {
            read.insert(if rpc_method == MCP_TOOLS_CALL {
                let tool = member
                    .get("params")
                    .and_then(|params| params.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                (ApiProtocol::Mcp, MCP_TOOLS_CALL.to_owned(), tool.to_owned())
            } else {
                (ApiProtocol::JsonRpc, rpc_method.to_owned(), String::new())
            });
        }
    }
    actions.extend(read.into_iter().map(|(protocol, verb, target)| ApiAction {
        host: host.clone(),
        protocol,
        verb,
        target,
    }));
    actions
}

/// The host a table names for `url`: lower-cased, with the port when it is
/// not the scheme's default.
fn host_of(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

/// The GraphQL reader: a lexer over the executable document's tokens, and
/// each operation's type and root fields. It reads no schema and checks no
/// validity rule beyond what it needs to find the root fields.
mod graphql {
    use std::collections::{BTreeMap, BTreeSet};

    /// How deep inline fragments at an operation's root are followed. A
    /// deeper one reads as an unnamed field, which only a row for any field
    /// classes, so nesting cannot hide a field.
    const MAX_INLINE_DEPTH: usize = 32;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Token<'a> {
        Name(&'a str),
        Punct(u8),
        Spread,
        /// A string, block string or number.
        Value,
    }

    #[derive(Debug)]
    enum Selection<'a> {
        Field(&'a str),
        Spread(&'a str),
        Inline(Vec<Selection<'a>>),
    }

    #[derive(Debug)]
    struct Operation<'a> {
        kind: &'a str,
        name: Option<&'a str>,
        selections: Vec<Selection<'a>>,
    }

    /// Each (operation type, root field) the document runs: the operation
    /// `operation_name` names when the document holds one by that name, else
    /// every operation. An operation whose root fields cannot be named reads
    /// as one unnamed field. A document that does not lex or parse reads as
    /// nothing.
    pub(super) fn root_fields<'a>(
        document: &'a str,
        operation_name: Option<&str>,
    ) -> BTreeSet<(&'a str, &'a str)> {
        let mut out = BTreeSet::new();
        let Some(tokens) = lex(document) else {
            return out;
        };
        let Some((operations, fragments)) = parse(&tokens) else {
            return out;
        };
        let named =
            operation_name.filter(|wanted| operations.iter().any(|op| op.name == Some(*wanted)));
        for operation in operations
            .iter()
            .filter(|op| named.is_none() || op.name == named)
        {
            let fields = expand(&operation.selections, &fragments);
            if fields.is_empty() {
                out.insert((operation.kind, ""));
            }
            out.extend(fields.into_iter().map(|field| (operation.kind, field)));
        }
        out
    }

    /// The root field names `selections` select, fragments expanded without
    /// recursion. A spread of a fragment the document does not define reads
    /// as an unnamed field.
    fn expand<'a>(selections: &[Selection<'a>], fragments: &Fragments<'a>) -> BTreeSet<&'a str> {
        let mut fields = BTreeSet::new();
        let mut followed = BTreeSet::new();
        let mut pending = vec![selections];
        while let Some(selections) = pending.pop() {
            for selection in selections {
                match selection {
                    Selection::Field(name) => {
                        fields.insert(*name);
                    }
                    Selection::Inline(inner) => pending.push(inner),
                    Selection::Spread(name) => {
                        if followed.insert(*name) {
                            match fragments.get(name) {
                                Some(inner) => pending.push(inner),
                                None => {
                                    fields.insert("");
                                }
                            }
                        }
                    }
                }
            }
        }
        fields
    }

    fn lex(document: &str) -> Option<Vec<Token<'_>>> {
        let bytes = document.as_bytes();
        let mut tokens = Vec::new();
        let mut at = 0;
        while let Some(&byte) = bytes.get(at) {
            match byte {
                b' ' | b'\t' | b'\n' | b'\r' | b',' => at += 1,
                b'#' => {
                    while bytes.get(at).is_some_and(|&b| !matches!(b, b'\n' | b'\r')) {
                        at += 1;
                    }
                }
                b'"' => {
                    at = string_end(bytes, at)?;
                    tokens.push(Token::Value);
                }
                b'.' if bytes.get(at..at + 3) == Some(b"...".as_slice()) => {
                    tokens.push(Token::Spread);
                    at += 3;
                }
                b'!' | b'$' | b'&' | b'(' | b')' | b':' | b'=' | b'@' | b'[' | b']' | b'{'
                | b'|' | b'}' => {
                    tokens.push(Token::Punct(byte));
                    at += 1;
                }
                b'_' | b'A'..=b'Z' | b'a'..=b'z' => {
                    let start = at;
                    while bytes
                        .get(at)
                        .is_some_and(|&b| b.is_ascii_alphanumeric() || b == b'_')
                    {
                        at += 1;
                    }
                    tokens.push(Token::Name(document.get(start..at)?));
                }
                b'-' | b'0'..=b'9' => {
                    at += 1;
                    while bytes.get(at).is_some_and(|&b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-')
                    }) {
                        at += 1;
                    }
                    tokens.push(Token::Value);
                }
                0xEF if bytes.get(at..at + 3) == Some([0xEF_u8, 0xBB, 0xBF].as_slice()) => at += 3,
                _ => return None,
            }
        }
        Some(tokens)
    }

    /// The byte after the string that opens at `start`: a block string
    /// (`"""`, where `\"""` is an escaped quote) or a one-line string.
    fn string_end(bytes: &[u8], start: usize) -> Option<usize> {
        if bytes.get(start..start + 3) == Some(b"\"\"\"".as_slice()) {
            let mut at = start + 3;
            loop {
                if bytes.get(at..at + 4) == Some(b"\\\"\"\"".as_slice()) {
                    at += 4;
                } else if bytes.get(at..at + 3) == Some(b"\"\"\"".as_slice()) {
                    return Some(at + 3);
                } else {
                    bytes.get(at)?;
                    at += 1;
                }
            }
        }
        let mut at = start + 1;
        loop {
            match *bytes.get(at)? {
                b'\\' => at += 2,
                b'"' => return Some(at + 1),
                b'\n' | b'\r' => return None,
                _ => at += 1,
            }
        }
    }

    type Fragments<'a> = BTreeMap<&'a str, Vec<Selection<'a>>>;

    fn parse<'a>(tokens: &[Token<'a>]) -> Option<(Vec<Operation<'a>>, Fragments<'a>)> {
        let mut operations = Vec::new();
        let mut fragments: Fragments<'a> = BTreeMap::new();
        let mut at = 0;
        while let Some(token) = tokens.get(at) {
            match *token {
                Token::Punct(b'{') => operations.push(Operation {
                    kind: "query",
                    name: None,
                    selections: selection_set(tokens, &mut at, 0)?,
                }),
                Token::Name(kind @ ("query" | "mutation" | "subscription")) => {
                    at += 1;
                    let name = match tokens.get(at) {
                        Some(Token::Name(name)) => {
                            at += 1;
                            Some(*name)
                        }
                        _ => None,
                    };
                    skip_to_selection_set(tokens, &mut at)?;
                    operations.push(Operation {
                        kind,
                        name,
                        selections: selection_set(tokens, &mut at, 0)?,
                    });
                }
                Token::Name("fragment") => {
                    let Some(Token::Name(name)) = tokens.get(at + 1) else {
                        return None;
                    };
                    if tokens.get(at + 2) != Some(&Token::Name("on"))
                        || !matches!(tokens.get(at + 3), Some(Token::Name(_)))
                    {
                        return None;
                    }
                    at += 4;
                    skip_to_selection_set(tokens, &mut at)?;
                    let selections = selection_set(tokens, &mut at, 0)?;
                    fragments.entry(*name).or_default().extend(selections);
                }
                _ => return None,
            }
        }
        Some((operations, fragments))
    }

    /// Skips an operation's variable definitions and directives, up to the
    /// `{` that opens its selection set.
    fn skip_to_selection_set(tokens: &[Token<'_>], at: &mut usize) -> Option<()> {
        loop {
            match tokens.get(*at)? {
                Token::Punct(b'{') => return Some(()),
                Token::Punct(b'(') => skip_balanced(tokens, at)?,
                Token::Punct(b'@') => skip_directives(tokens, at)?,
                _ => return None,
            }
        }
    }

    fn skip_directives(tokens: &[Token<'_>], at: &mut usize) -> Option<()> {
        while tokens.get(*at) == Some(&Token::Punct(b'@')) {
            let Some(Token::Name(_)) = tokens.get(*at + 1) else {
                return None;
            };
            *at += 2;
            if tokens.get(*at) == Some(&Token::Punct(b'(')) {
                skip_balanced(tokens, at)?;
            }
        }
        Some(())
    }

    /// Skips the bracketed group that opens at `at`: `(..)`, `[..]` or
    /// `{..}`, with every bracket inside it.
    fn skip_balanced(tokens: &[Token<'_>], at: &mut usize) -> Option<()> {
        let mut depth = 0usize;
        loop {
            match tokens.get(*at)? {
                Token::Punct(b'(' | b'[' | b'{') => depth += 1,
                Token::Punct(b')' | b']' | b'}') => depth = depth.checked_sub(1)?,
                _ => {}
            }
            *at += 1;
            if depth == 0 {
                return Some(());
            }
        }
    }

    /// The selections of the set that opens at `at`. A nested field's own
    /// set is skipped: only the root's fields name what an operation does.
    fn selection_set<'a>(
        tokens: &[Token<'a>],
        at: &mut usize,
        depth: usize,
    ) -> Option<Vec<Selection<'a>>> {
        if tokens.get(*at) != Some(&Token::Punct(b'{')) {
            return None;
        }
        *at += 1;
        let mut selections = Vec::new();
        loop {
            match *tokens.get(*at)? {
                Token::Punct(b'}') => {
                    *at += 1;
                    return Some(selections);
                }
                Token::Spread => {
                    *at += 1;
                    match *tokens.get(*at)? {
                        Token::Name("on") => {
                            let Some(Token::Name(_)) = tokens.get(*at + 1) else {
                                return None;
                            };
                            *at += 2;
                            skip_directives(tokens, at)?;
                            selections.push(inline(tokens, at, depth)?);
                        }
                        Token::Punct(b'@' | b'{') => {
                            skip_directives(tokens, at)?;
                            selections.push(inline(tokens, at, depth)?);
                        }
                        Token::Name(fragment) => {
                            *at += 1;
                            skip_directives(tokens, at)?;
                            selections.push(Selection::Spread(fragment));
                        }
                        _ => return None,
                    }
                }
                Token::Name(first) => {
                    *at += 1;
                    let mut field = first;
                    if tokens.get(*at) == Some(&Token::Punct(b':')) {
                        let Some(Token::Name(aliased)) = tokens.get(*at + 1) else {
                            return None;
                        };
                        field = *aliased;
                        *at += 2;
                    }
                    if tokens.get(*at) == Some(&Token::Punct(b'(')) {
                        skip_balanced(tokens, at)?;
                    }
                    skip_directives(tokens, at)?;
                    if tokens.get(*at) == Some(&Token::Punct(b'{')) {
                        skip_balanced(tokens, at)?;
                    }
                    selections.push(Selection::Field(field));
                }
                _ => return None,
            }
        }
    }

    /// An inline fragment's selections, followed up to
    /// [`MAX_INLINE_DEPTH`]; past it, the set is skipped and reads as one
    /// unnamed field.
    fn inline<'a>(tokens: &[Token<'a>], at: &mut usize, depth: usize) -> Option<Selection<'a>> {
        if depth >= MAX_INLINE_DEPTH {
            if tokens.get(*at) != Some(&Token::Punct(b'{')) {
                return None;
            }
            skip_balanced(tokens, at)?;
            return Some(Selection::Field(""));
        }
        Some(Selection::Inline(selection_set(tokens, at, depth + 1)?))
    }
}
