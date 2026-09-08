//! MCP argument codecs: parsed-value and raw-JSON integer normalization.

use super::tool_catalog::{McpToolName, McpToolValidationError, mcp_tool_schema};
use super::validate::ValidateMcpArgs;
use serde::Deserialize;
use serde::Deserializer;
use serde::de::DeserializeOwned;
use serde::de::Error as DeError;
use serde_json::Value;
use std::ops::Range;

pub(super) fn decode_tool_args<T>(
    tool: McpToolName,
    args: McpToolArguments,
) -> Result<T, McpToolValidationError>
where
    T: DeserializeOwned + ValidateMcpArgs,
{
    // The ADVERTISED schema decides where an integer lives, so the decoder's
    // domain is the advertised domain at every one of those positions —
    // including the ones nested in engine-owned input types this door does not
    // define. Nothing else in the payload is touched.
    let args = schema_normalized_arguments(&mcp_tool_schema(tool).input_schema, args).map_err(
        |message| McpToolValidationError::Decode {
            tool: tool.as_str(),
            message,
        },
    )?;
    let parsed =
        serde_json::from_value::<T>(args).map_err(|error| McpToolValidationError::Decode {
            tool: tool.as_str(),
            message: error.to_string(),
        })?;
    parsed.validate(tool)?;
    Ok(parsed)
}

/// Restates mathematically integral JSON numbers in their integer spelling at
/// every position the ADVERTISED schema types as `integer` (ONE-1704 repair).
///
/// Draft 2020-12 `type: integer` is about the mathematical value, so `1.0` and
/// `1e0` are the integer one. A plain `serde` integer decoder is about the
/// SPELLING and refuses both, which made the advertised domain wider than the
/// runtime's at every legacy numeric field. This closes that gap the same way
/// [`parse_json_unsigned_integer`] does: from the number's own TEXT, with no
/// floating-point arithmetic, and only when the text denotes an exact integer
/// that the JSON integer types can hold. A value that is not integral, or too
/// large to restate, is left exactly as it arrived so both doors still refuse
/// it.
///
/// It is deliberately SCHEMA-DIRECTED rather than a blanket sweep: a free-form
/// caller payload (`value`, `evidence`, `data`, `spec`, …) is typed `{}` and is
/// never rewritten, so a claim that says `1.0` still stores `1.0`.
fn normalize_advertised_integers(schema: &Value, value: &mut Value) {
    if schema.get("type").and_then(Value::as_str) == Some("integer")
        && let Some(integral) = integral_json_number(value)
    {
        *value = integral;
        return;
    }
    if value.is_object() {
        if let Some(properties) = schema.get("properties").and_then(Value::as_object)
            && let Some(entries) = value.as_object_mut()
        {
            for (key, entry) in entries {
                if let Some(property) = properties.get(key) {
                    normalize_advertised_integers(property, entry);
                }
            }
        }
        // A closed tagged union states the same numeric positions in every
        // branch, so applying each is the same value-preserving rewrite.
        for keyword in ["oneOf", "anyOf", "allOf"] {
            if let Some(branches) = schema.get(keyword).and_then(Value::as_array) {
                for branch in branches {
                    normalize_advertised_integers(branch, value);
                }
            }
        }
        if let Some(conditional) = schema.get("then") {
            normalize_advertised_integers(conditional, value);
        }
    } else if let Some(item_schema) = schema.get("items")
        && let Some(items) = value.as_array_mut()
    {
        for item in items {
            normalize_advertised_integers(item_schema, item);
        }
    }
}

/// The integer spelling of one JSON number whose TEXT denotes an exact integer,
/// or `None` when it is already an integer, is fractional, or cannot be
/// restated without loss.
fn integral_json_number(value: &Value) -> Option<Value> {
    let Value::Number(number) = value else {
        return None;
    };
    if number.is_i64() || number.is_u64() {
        return None;
    }
    let text = number.to_string();
    let (negative, magnitude) = match text.strip_prefix('-') {
        Some(magnitude) => (true, magnitude),
        None => (false, text.as_str()),
    };
    let magnitude = parse_json_unsigned_integer(magnitude, u128::from(u64::MAX)).ok()?;
    if negative {
        let magnitude = i128::try_from(magnitude).ok()?;
        i64::try_from(-magnitude).ok().map(Value::from)
    } else {
        u64::try_from(magnitude).ok().map(Value::from)
    }
}

/// One tool call's arguments, still carrying the caller's ORIGINAL JSON number
/// text whenever they arrived as bytes (ONE-1704 repair).
///
/// This build enables `preserve_order`, not `arbitrary_precision`, so parsing
/// straight into [`Value`] rounds every number that is not already an `i64` or
/// `u64` through `f64` BEFORE any schema-directed decision is taken. The
/// schema-valid integer `18446744073709551615.0` is the mathematical
/// `u64::MAX` that Draft 2020-12 `type: integer` admits, but the `f64` it
/// rounds to prints ABOVE that ceiling — so `cache.ttl_ms` and `frame_epoch`
/// refused a value their own advertised schema accepts.
///
/// Holding the RAW text until schema-directed normalization has run closes
/// that gap with no floating-point arithmetic and no lossy round trip. A
/// caller that already holds a parsed [`Value`] keeps the previous behaviour
/// exactly: the spelling is gone by then, and nothing here invents it back.
#[derive(Clone, Debug)]
pub struct McpToolArguments(McpToolArgumentsSource);

#[derive(Clone, Debug)]
enum McpToolArgumentsSource {
    /// The exact JSON source text of the arguments value.
    Raw(String),
    /// An already-parsed value, from an in-process caller.
    Parsed(Value),
}

impl McpToolArguments {
    /// Arguments EXACTLY as the caller spelled them on the wire.
    #[must_use]
    pub fn from_raw_json(text: impl Into<String>) -> Self {
        Self(McpToolArgumentsSource::Raw(text.into()))
    }
}

impl From<Value> for McpToolArguments {
    fn from(value: Value) -> Self {
        Self(McpToolArgumentsSource::Parsed(value))
    }
}

/// Restates every ADVERTISED integer position from the arguments' own number
/// TEXT, and hands typed deserialization the result.
///
/// # Errors
///
/// Returns the `serde_json` message when raw argument text is not JSON at all.
pub(super) fn schema_normalized_arguments(
    schema: &Value,
    arguments: McpToolArguments,
) -> Result<Value, String> {
    match arguments.0 {
        McpToolArgumentsSource::Parsed(mut value) => {
            normalize_advertised_integers(schema, &mut value);
            Ok(value)
        }
        McpToolArgumentsSource::Raw(text) => {
            let Some(node) = McpRawJsonNode::scan(&text) else {
                // Not scannable: fall back to the parsed walk so this path can
                // only ever behave as it did before, never worse.
                let mut value =
                    serde_json::from_str::<Value>(&text).map_err(|error| error.to_string())?;
                normalize_advertised_integers(schema, &mut value);
                return Ok(value);
            };
            let mut rewrites = Vec::new();
            collect_advertised_integer_tokens(schema, &node, &text, &mut rewrites);
            serde_json::from_str::<Value>(&restated_json_text(&text, rewrites))
                .map_err(|error| error.to_string())
        }
    }
}

/// The EXACT source text of `params.arguments` inside one raw JSON-RPC body.
///
/// The gateway parses the envelope into a [`Value`] to route it, and that is
/// precisely where a number's spelling is lost. Arguments are decoded against
/// the ADVERTISED schema instead, so their original text has to survive the
/// envelope parse; this reads it straight back out of the request bytes.
///
/// `None` whenever the body is not a JSON object carrying an object `params`
/// with an `arguments` member. The caller then falls back to the parsed value,
/// which is exactly the previous behaviour.
pub(crate) fn mcp_raw_call_arguments(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let node = McpRawJsonNode::scan(text)?;
    let arguments = node.entry("params")?.entry("arguments")?;
    Some(text[arguments.span.clone()].to_owned())
}

/// The deepest object/array nesting one raw scan descends.
///
/// `serde_json` refuses deeper input at its own parse, so this only bounds the
/// scanner's recursion on text that never reaches a decoder anyway.
const MCP_RAW_JSON_MAX_DEPTH: usize = 128;

/// One node of a raw JSON document: its structure, plus the EXACT source span
/// of every number token inside it.
#[derive(Clone, Debug)]
struct McpRawJsonNode {
    span: Range<usize>,
    kind: McpRawJsonKind,
}

#[derive(Clone, Debug)]
enum McpRawJsonKind {
    /// A number token, whose span is the caller's own spelling.
    Number,
    Array(Vec<McpRawJsonNode>),
    Object(Vec<(String, McpRawJsonNode)>),
    /// A string, `true`, `false`, or `null`: no number token hides in one.
    Opaque,
}

impl McpRawJsonNode {
    /// Scans one complete JSON document, or `None` when the text is not one.
    fn scan(text: &str) -> Option<Self> {
        let mut scanner = McpRawJsonScanner { text, offset: 0 };
        let node = scanner.value(0)?;
        scanner.skip_whitespace();
        (scanner.offset == text.len()).then_some(node)
    }

    /// The entry one object key resolves to, matching `serde_json`'s
    /// last-occurrence rule for a duplicated key so this walk and the parsed
    /// value never disagree about which member is live.
    fn entry(&self, key: &str) -> Option<&Self> {
        let McpRawJsonKind::Object(entries) = &self.kind else {
            return None;
        };
        entries
            .iter()
            .rev()
            .find(|(name, _)| name == key)
            .map(|(_, entry)| entry)
    }
}

struct McpRawJsonScanner<'a> {
    text: &'a str,
    offset: usize,
}

impl McpRawJsonScanner<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.offset).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.offset += 1;
        }
    }

    fn eat(&mut self, byte: u8) -> Option<()> {
        (self.peek() == Some(byte)).then(|| {
            self.offset += 1;
        })
    }

    fn literal(&mut self, literal: &str) -> Option<()> {
        // Only ever reached on an ASCII lead byte, so `offset` is a boundary.
        self.text[self.offset..]
            .starts_with(literal)
            .then(|| self.offset += literal.len())
    }

    fn value(&mut self, depth: usize) -> Option<McpRawJsonNode> {
        if depth > MCP_RAW_JSON_MAX_DEPTH {
            return None;
        }
        self.skip_whitespace();
        let start = self.offset;
        let kind = match self.peek()? {
            b'{' => self.object(depth)?,
            b'[' => self.array(depth)?,
            b'"' => {
                self.string()?;
                McpRawJsonKind::Opaque
            }
            b't' => {
                self.literal("true")?;
                McpRawJsonKind::Opaque
            }
            b'f' => {
                self.literal("false")?;
                McpRawJsonKind::Opaque
            }
            b'n' => {
                self.literal("null")?;
                McpRawJsonKind::Opaque
            }
            b'-' | b'0'..=b'9' => {
                self.number()?;
                McpRawJsonKind::Number
            }
            _ => return None,
        };
        Some(McpRawJsonNode {
            span: start..self.offset,
            kind,
        })
    }

    /// Consumes one number token.
    ///
    /// What matters here is where the token ENDS, and every JSON separator —
    /// `,`, `}`, `]`, and whitespace — is outside this byte set. The token's
    /// own grammar is judged later, from its text, by
    /// [`parse_json_unsigned_integer`], and by `serde_json` on the re-parse.
    fn number(&mut self) -> Option<()> {
        let start = self.offset;
        while matches!(
            self.peek(),
            Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
        ) {
            self.offset += 1;
        }
        (self.offset > start).then_some(())
    }

    /// Consumes one string token, returning the span of its source INCLUDING
    /// both quotes.
    fn string(&mut self) -> Option<Range<usize>> {
        let start = self.offset;
        self.eat(b'"')?;
        loop {
            match self.peek()? {
                b'"' => {
                    self.offset += 1;
                    return Some(start..self.offset);
                }
                // A two-byte escape never straddles the closing quote, and a
                // multi-byte character's continuation bytes are all above the
                // ASCII range this match tests.
                b'\\' => self.offset += 2,
                _ => self.offset += 1,
            }
        }
    }

    fn object(&mut self, depth: usize) -> Option<McpRawJsonKind> {
        self.eat(b'{')?;
        let mut entries = Vec::new();
        self.skip_whitespace();
        if self.eat(b'}').is_some() {
            return Some(McpRawJsonKind::Object(entries));
        }
        loop {
            self.skip_whitespace();
            let key = self.string()?;
            // Decoded by `serde_json` itself, so an escaped spelling resolves
            // to the same schema property the parsed value resolved to.
            let key = serde_json::from_str::<String>(&self.text[key]).ok()?;
            self.skip_whitespace();
            self.eat(b':')?;
            let value = self.value(depth + 1)?;
            entries.push((key, value));
            self.skip_whitespace();
            if self.eat(b',').is_some() {
                continue;
            }
            self.eat(b'}')?;
            return Some(McpRawJsonKind::Object(entries));
        }
    }

    fn array(&mut self, depth: usize) -> Option<McpRawJsonKind> {
        self.eat(b'[')?;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.eat(b']').is_some() {
            return Some(McpRawJsonKind::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.skip_whitespace();
            if self.eat(b',').is_some() {
                continue;
            }
            self.eat(b']')?;
            return Some(McpRawJsonKind::Array(items));
        }
    }
}

/// Collects every ADVERTISED integer position whose number token can be
/// restated as an exact integer, as `(span, integer spelling)` rewrites.
///
/// It visits exactly the positions [`normalize_advertised_integers`] visits —
/// the same schema-directed discipline, so a free-form `{}` payload such as a
/// caller's `spec` is still never rewritten — but decides from the caller's own
/// token TEXT instead of from a number that already went through `f64`.
fn collect_advertised_integer_tokens(
    schema: &Value,
    node: &McpRawJsonNode,
    text: &str,
    rewrites: &mut Vec<(Range<usize>, String)>,
) {
    if schema.get("type").and_then(Value::as_str) == Some("integer")
        && matches!(node.kind, McpRawJsonKind::Number)
        && let Some(integral) = integral_json_token(&text[node.span.clone()])
    {
        rewrites.push((node.span.clone(), integral));
        return;
    }
    match &node.kind {
        McpRawJsonKind::Object(entries) => {
            if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
                for (key, entry) in entries {
                    if let Some(property) = properties.get(key) {
                        collect_advertised_integer_tokens(property, entry, text, rewrites);
                    }
                }
            }
            // A closed tagged union states the same numeric positions in every
            // branch, so applying each is the same value-preserving rewrite.
            for keyword in ["oneOf", "anyOf", "allOf"] {
                if let Some(branches) = schema.get(keyword).and_then(Value::as_array) {
                    for branch in branches {
                        collect_advertised_integer_tokens(branch, node, text, rewrites);
                    }
                }
            }
            if let Some(conditional) = schema.get("then") {
                collect_advertised_integer_tokens(conditional, node, text, rewrites);
            }
        }
        McpRawJsonKind::Array(items) => {
            if let Some(item_schema) = schema.get("items") {
                for item in items {
                    collect_advertised_integer_tokens(item_schema, item, text, rewrites);
                }
            }
        }
        McpRawJsonKind::Number | McpRawJsonKind::Opaque => {}
    }
}

/// Applies the collected integer rewrites to the arguments' source text.
///
/// Each rewrite replaces ONE number token with that token's own integer
/// spelling, so every other byte the caller sent is carried through untouched.
fn restated_json_text(text: &str, mut rewrites: Vec<(Range<usize>, String)>) -> String {
    if rewrites.is_empty() {
        return text.to_owned();
    }
    // A tagged union restates the same position once per branch; the spelling
    // is identical each time, so the first of a span is the whole story.
    rewrites.sort_by_key(|(span, _)| span.start);
    rewrites.dedup_by_key(|(span, _)| span.start);
    let mut restated = String::with_capacity(text.len());
    let mut cursor = 0;
    for (span, integral) in rewrites {
        if span.start < cursor {
            continue;
        }
        restated.push_str(&text[cursor..span.start]);
        restated.push_str(&integral);
        cursor = span.end;
    }
    restated.push_str(&text[cursor..]);
    restated
}

/// The integer spelling of one JSON number TOKEN whose own text denotes an
/// exact integer, or `None` when it is already spelled as an integer, is
/// fractional, or cannot be restated without loss.
///
/// This is [`integral_json_number`]'s decision taken one step earlier, on the
/// bytes the caller actually sent, so a value at the `u64` ceiling is judged on
/// its mathematical value instead of on the `f64` it would have rounded to.
fn integral_json_token(token: &str) -> Option<String> {
    if !token.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
        // Already an integer spelling: `serde_json` decodes the same
        // mathematical value, so restating it would only move bytes.
        return None;
    }
    let (negative, magnitude) = match token.strip_prefix('-') {
        Some(magnitude) => (true, magnitude),
        None => (false, token),
    };
    let magnitude = parse_json_unsigned_integer(magnitude, u128::from(u64::MAX)).ok()?;
    if negative {
        let magnitude = i128::try_from(magnitude).ok()?;
        i64::try_from(-magnitude)
            .ok()
            .map(|integral| integral.to_string())
    } else {
        u64::try_from(magnitude)
            .ok()
            .map(|integral| integral.to_string())
    }
}

/// Parses a JSON number against an unsigned integer domain without going
/// through `f64`. Draft 2020-12's `integer` type is about the mathematical
/// value, not the lexical spelling, so `1.0` and `1e0` are valid integers while
/// `1.5` is not. Keeping the decimal text also prevents a large value near a
/// machine limit from being rounded into the domain.
pub(super) fn parse_json_unsigned_integer(text: &str, maximum: u128) -> Result<u128, &'static str> {
    let (negative, unsigned) = match text.strip_prefix('-') {
        Some(unsigned) => (true, unsigned),
        None => (false, text),
    };
    let exponent_marker = unsigned.find(['e', 'E']);
    let (mantissa, exponent) = exponent_marker.map_or((unsigned, 0_i64), |index| {
        let (mantissa, exponent) = unsigned.split_at(index);
        (mantissa, exponent[1..].parse::<i64>().unwrap_or(i64::MIN))
    });
    if exponent == i64::MIN && exponent_marker.is_some() {
        // An exponent outside the representable range can only be an integer
        // zero when every mantissa digit is zero. Any nonzero value is either a
        // fraction (negative exponent) or outside this unsigned domain.
        let digits = mantissa.replace('.', "");
        if digits.chars().any(|digit| digit != '0') {
            return Err("number is outside the supported integer range");
        }
        return Ok(0);
    }
    let (whole, fraction) = mantissa
        .split_once('.')
        .map_or((mantissa, ""), |(whole, fraction)| (whole, fraction));
    if whole.is_empty() && fraction.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("number is not a valid JSON integer");
    }
    let digits = format!("{whole}{fraction}");
    let nonzero = digits.bytes().any(|byte| byte != b'0');
    if negative && nonzero {
        return Err("number is negative");
    }
    if !nonzero {
        return Ok(0);
    }
    let decimal_position = (whole.len() as i64)
        .checked_add(exponent)
        .ok_or("number is outside the supported integer range")?;
    if decimal_position <= 0 {
        return Err("number has a fractional value");
    }
    let digits_len = digits.len() as i64;
    if decimal_position < digits_len
        && digits[decimal_position as usize..]
            .bytes()
            .any(|byte| byte != b'0')
    {
        return Err("number has a fractional value");
    }
    let significant_end = decimal_position.min(digits_len) as usize;
    let mut integer = digits[..significant_end].trim_start_matches('0').to_owned();
    let maximum_text = maximum.to_string();
    if decimal_position > digits_len {
        let zeros = usize::try_from(decimal_position - digits_len)
            .map_err(|_| "number is outside the supported integer range")?;
        if zeros > maximum_text.len() {
            return Err("number is outside the supported integer range");
        }
        integer.push_str(&"0".repeat(zeros));
    }
    if integer.is_empty() {
        return Ok(0);
    }
    if integer.len() > maximum_text.len()
        || integer.len() == maximum_text.len() && integer.as_str() > maximum_text.as_str()
    {
        return Err("number is outside the supported integer range");
    }
    integer
        .parse::<u128>()
        .map_err(|_| "number is outside the supported integer range")
}

fn deserialize_optional_unsigned<'de, D>(
    deserializer: D,
    maximum: u128,
) -> Result<Option<u128>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    let Value::Number(number) = value else {
        // `#[serde(default)]` supplies None when the property is absent. If
        // this deserializer runs, the property was present; JSON null is not
        // Draft 2020-12 `type: integer` and must not become an absent Option.
        return Err(D::Error::custom("expected an unsigned JSON integer"));
    };
    parse_json_unsigned_integer(&number.to_string(), maximum)
        .map(Some)
        .map_err(D::Error::custom)
}

pub(super) fn deserialize_optional_u32<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = deserialize_optional_unsigned(deserializer, u128::from(u32::MAX))?;
    value
        .map(|value| u32::try_from(value).map_err(D::Error::custom))
        .transpose()
}

pub(super) fn deserialize_optional_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = deserialize_optional_unsigned(deserializer, u128::from(u64::MAX))?;
    value
        .map(|value| u64::try_from(value).map_err(D::Error::custom))
        .transpose()
}
