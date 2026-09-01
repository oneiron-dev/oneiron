use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

use super::codec::encode_compiled_policy;
use super::record::{
    CONNECTOR_KEY_MAX_BUDGET_ROWS, CalendarPeriod, CompiledConnectorPolicy, ConnectorCharterBlock,
    EffectorBudget, EffectorBudgetDimension, EffectorBudgetOnExhaust, EffectorBudgetWindow,
    normalize_connector_key, validate_budget_row, validate_never_list_entry, validate_spend_unit,
};

// --- Charter compiler (GOV-10, ONE-1417) --------------------------------------

/// Domain tag for the compiled-policy hash.
const CONNECTOR_CHARTER_COMPILED_DOMAIN: &[u8] = b"oneiron.connector_charter.compiled.v1";
/// Domain tag for the human-stamped aggregate binding text + compiled policy.
pub(crate) const CONNECTOR_CHARTER_STAMP_DOMAIN: &[u8] = b"oneiron.connector_charter.stamp.v1";

/// ISO-4217 currencies with exponent 0 (major unit == minor unit); every
/// other currency compiles major → minor with the default exponent 2.
/// Pinned by the M8 / R7 resolution (2026-07-10).
const ISO_4217_ZERO_EXPONENT_CURRENCIES: [&str; 3] = ["JPY", "KRW", "VND"];

/// Output of one deterministic charter compile: same text ⇒ same struct ⇒
/// same hashes. The compiler is a mechanical parser — no model in the loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledCharter {
    pub text_hash: [u8; 32],
    pub compiled: CompiledConnectorPolicy,
    pub compiled_hash: [u8; 32],
}

/// A fail-closed charter compile error: 1-based line number over the
/// CRLF-normalized text. Maps into [`Error::ConnectorCharterCompile`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorCharterCompileIssue {
    pub line_number: u32,
    pub message: String,
}

impl From<ConnectorCharterCompileIssue> for Error {
    fn from(issue: ConnectorCharterCompileIssue) -> Self {
        Error::ConnectorCharterCompile {
            line_number: issue.line_number,
            message: issue.message,
        }
    }
}

fn sha256_bytes(chunks: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hasher.finalize().into()
}

/// Canonical msgpack bytes for a compiled policy (the hash input).
fn encode_compiled_policy_bytes(compiled: &CompiledConnectorPolicy) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &encode_compiled_policy(compiled)).map_err(|_| {
        Error::InvariantViolation("compiled connector policy MessagePack encode failed")
    })?;
    Ok(out)
}

pub(crate) fn compiled_policy_hash(compiled: &CompiledConnectorPolicy) -> Result<[u8; 32]> {
    Ok(sha256_bytes(&[
        CONNECTOR_CHARTER_COMPILED_DOMAIN,
        &encode_compiled_policy_bytes(compiled)?,
    ]))
}

/// The human stamp binds text and compiled policy as ONE aggregate.
pub(crate) fn charter_stamped_aggregate(
    text_hash: &[u8; 32],
    compiled_hash: &[u8; 32],
) -> [u8; 32] {
    sha256_bytes(&[CONNECTOR_CHARTER_STAMP_DOMAIN, text_hash, compiled_hash])
}

/// Recomputes the stamped aggregate from the STORED text and compiled policy
/// and compares it to the stamp. Any mismatch degrades enforcement to
/// proposed-only (`gate.pending.charter_drift`) until a human re-stamps.
pub(crate) fn charter_block_drifted(block: &ConnectorCharterBlock) -> Result<bool> {
    // Hash the SAME canonical form the compiler stamps over: it hashes the
    // CRLF-normalized text (`compile_connector_charter`), so an imported block
    // that carries raw `\r\n` while its stamp was computed over the `\n` form
    // must normalize here too, or it would false-drift into proposed-only.
    let normalized = block.text.replace("\r\n", "\n");
    let text_hash = sha256_bytes(&[normalized.as_bytes()]);
    let compiled_hash = compiled_policy_hash(&block.compiled)?;
    Ok(charter_stamped_aggregate(&text_hash, &compiled_hash) != block.stamped_aggregate)
}

/// Never-list matching: an entry `"{c}:{v}"` matches iff (`c == "*"` or
/// `c ==` the normalized effect channel) and (`v == "*"` or `v ==` the
/// trimmed, lowercased effect verb).
pub(crate) fn charter_never_list_matches(
    block: &ConnectorCharterBlock,
    normalized_channel: &str,
    verb: &str,
) -> bool {
    let verb = verb.trim().to_ascii_lowercase();
    block.compiled.never_list.iter().any(|entry| {
        let Some((channel_part, verb_part)) = entry.split_once(':') else {
            return false;
        };
        (channel_part == "*" || channel_part == normalized_channel)
            && (verb_part == "*" || verb_part == verb)
    })
}

/// Capability-aware never-list matching (ONE-1885): the same first-colon entry
/// grammar, evaluated against ONE exact engine-produced per-grant capability key
/// (`mcp:{server}:grant:{hex}`) instead of a whole channel string.
///
/// `capability_key` carries authority, never a shape claim: the gate passes
/// `Some` only for the key its verified matched scoped-MCP grant produced, and
/// recovery only for a stored connector it classified as that synthetic shape.
/// A `None`, colon-less, or empty-first-segment key therefore has no capability
/// identity at all and delegates to [`charter_never_list_matches`] unchanged —
/// the ordinary full-channel behaviour, including colon-bearing channels like
/// `mcp:calendar`. Delegation is one-way: the legacy matcher never routes here.
///
/// With a capability key the effective channel is its FIRST segment and the
/// capability remainder is everything after that first colon, both compared
/// whole. So a stored `"mcp:acme:grant:ab12"` denies exactly that grant, a
/// neighbour grant on the same server keeps its own outcome, and no prefix or
/// per-segment match exists. A two-part `"mcp:{tool}"` entry still denies that
/// tool on this key: the remainder also compares against the normalized connector-key
/// form of the tool, which is the deny-side widening the re-scoping implies.
pub(crate) fn charter_never_list_matches_capability(
    block: &ConnectorCharterBlock,
    normalized_channel: &str,
    verb: &str,
    capability_key: Option<&str>,
) -> bool {
    let Some((effective_channel, capability_remainder)) =
        capability_key.and_then(|key| key.split_once(':'))
    else {
        return charter_never_list_matches(block, normalized_channel, verb);
    };
    if effective_channel.is_empty() {
        return charter_never_list_matches(block, normalized_channel, verb);
    }
    let verb = normalize_connector_key(verb);
    block.compiled.never_list.iter().any(|entry| {
        let Some((channel_part, remainder_part)) = entry.split_once(':') else {
            return false;
        };
        (channel_part == "*" || channel_part == effective_channel)
            && (remainder_part == "*"
                || remainder_part == capability_remainder
                || (!remainder_part.contains(':') && remainder_part == verb))
    })
}

/// Compiles a natural-language charter (the pinned 6-form constrained-English
/// grammar) into a deterministic policy. Fail-closed: any unrecognized or
/// malformed non-empty line aborts the whole compile with its 1-based line
/// number — no partial output.
pub fn compile_connector_charter(
    text: &str,
) -> std::result::Result<CompiledCharter, ConnectorCharterCompileIssue> {
    let normalized = text.replace("\r\n", "\n");
    let text_hash = sha256_bytes(&[normalized.as_bytes()]);

    let mut never_list: Vec<String> = Vec::new();
    let mut channel_caps: Vec<EffectorBudget> = Vec::new();
    for (index, line) in normalized.lines().enumerate() {
        let line_number = u32::try_from(index).unwrap_or(u32::MAX).saturating_add(1);
        let issue = |message: &str| ConnectorCharterCompileIssue {
            line_number,
            message: message.to_owned(),
        };
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match parse_charter_directive(trimmed).map_err(|message| issue(&message))? {
            CharterDirective::Never(entry) => {
                // The compiler may never emit an entry the record validator
                // would reject: such a line used to compile and only fail later
                // at the propose/approve write, with no line number to fix.
                validate_never_list_entry(&entry).map_err(|error| match error {
                    Error::InvalidConnectorKeyBody(reason) => issue(reason),
                    _ => issue("invalid charter never-list entry"),
                })?;
                never_list.push(entry);
            }
            CharterDirective::Cap(budget) => {
                if channel_caps.len() >= CONNECTOR_KEY_MAX_BUDGET_ROWS {
                    return Err(issue("too many charter channel caps"));
                }
                validate_budget_row(&budget).map_err(|error| match error {
                    Error::InvalidConnectorKeyBody(reason) => issue(reason),
                    _ => issue("invalid charter cap"),
                })?;
                channel_caps.push(budget);
            }
        }
    }

    never_list.sort();
    never_list.dedup();
    let compiled = CompiledConnectorPolicy {
        never_list,
        channel_caps,
    };
    let compiled_hash =
        compiled_policy_hash(&compiled).map_err(|_| ConnectorCharterCompileIssue {
            line_number: 0,
            message: "compiled policy encode failed".to_owned(),
        })?;
    Ok(CompiledCharter {
        text_hash,
        compiled,
        compiled_hash,
    })
}

enum CharterDirective {
    Never(String),
    Cap(EffectorBudget),
}

fn parse_charter_directive(line: &str) -> std::result::Result<CharterDirective, String> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let keyword = tokens[0].to_ascii_lowercase();
    match keyword.as_str() {
        // `never <verb>` | `never <verb> on <channel>` | `never key <channel>:<remainder>`
        "never" => match tokens.len() {
            2 => {
                if tokens[1].eq_ignore_ascii_case("key") {
                    // `never key` alone reads as the capability form with its
                    // operand missing, not as a prohibition on the verb "key".
                    // Fail closed rather than compile the silent `*:key`.
                    return Err("never key requires a <channel>:<remainder> key".to_owned());
                }
                Ok(CharterDirective::Never(format!(
                    "*:{}",
                    parse_charter_verb(tokens[1])?
                )))
            }
            3 if tokens[1].eq_ignore_ascii_case("key") => Ok(CharterDirective::Never(
                parse_charter_never_key(tokens[2]),
            )),
            4 if tokens[2].eq_ignore_ascii_case("on") => {
                let verb = parse_charter_verb(tokens[1])?;
                let channel = parse_charter_never_channel(tokens[3])?;
                Ok(CharterDirective::Never(format!("{channel}:{verb}")))
            }
            _ => Err("unrecognized charter directive".to_owned()),
        },
        // `cap <n> sends per <day|week|month|<m>s> on <channel>`
        // `cap spend <n> <unit> per <day|week|month> on <channel>`
        "cap" => {
            if tokens.len() == 8 && tokens[1].eq_ignore_ascii_case("spend") {
                if !tokens[4].eq_ignore_ascii_case("per") || !tokens[6].eq_ignore_ascii_case("on") {
                    return Err("unrecognized charter directive".to_owned());
                }
                let major_units = parse_charter_number(tokens[2], "invalid spend cap amount")?;
                let unit = tokens[3];
                let limit = charter_spend_limit(major_units, unit)?;
                let period = parse_calendar_period(tokens[5])
                    .ok_or_else(|| "invalid calendar period".to_owned())?;
                let channel = parse_charter_cap_channel(tokens[7])?;
                Ok(CharterDirective::Cap(EffectorBudget {
                    dimension: EffectorBudgetDimension::Spend,
                    channel_class: Some(channel),
                    limit,
                    unit: Some(unit.to_owned()),
                    window: EffectorBudgetWindow::Calendar { period, tz: None },
                    on_exhaust: EffectorBudgetOnExhaust::Suspend,
                    reserve_policy: None,
                }))
            } else if tokens.len() == 7 && tokens[2].eq_ignore_ascii_case("sends") {
                if !tokens[3].eq_ignore_ascii_case("per") || !tokens[5].eq_ignore_ascii_case("on") {
                    return Err("unrecognized charter directive".to_owned());
                }
                let limit = parse_charter_number(tokens[1], "invalid sends cap limit")?;
                let window = parse_charter_window(tokens[4])?;
                let channel = parse_charter_cap_channel(tokens[6])?;
                Ok(CharterDirective::Cap(EffectorBudget {
                    dimension: EffectorBudgetDimension::Sends,
                    channel_class: Some(channel),
                    limit,
                    unit: None,
                    window,
                    on_exhaust: EffectorBudgetOnExhaust::Suspend,
                    reserve_policy: None,
                }))
            } else {
                Err("unrecognized charter directive".to_owned())
            }
        }
        // `rate <n> per <m>s on <channel>`
        "rate" => {
            if tokens.len() != 6
                || !tokens[2].eq_ignore_ascii_case("per")
                || !tokens[4].eq_ignore_ascii_case("on")
            {
                return Err("unrecognized charter directive".to_owned());
            }
            let limit = parse_charter_number(tokens[1], "invalid rate limit")?;
            let duration_s = parse_rolling_duration(tokens[3])?;
            let channel = parse_charter_cap_channel(tokens[5])?;
            Ok(CharterDirective::Cap(EffectorBudget {
                dimension: EffectorBudgetDimension::Rate,
                channel_class: Some(channel),
                limit,
                unit: None,
                window: EffectorBudgetWindow::Rolling { duration_s },
                on_exhaust: EffectorBudgetOnExhaust::Refuse,
                reserve_policy: None,
            }))
        }
        _ => Err("unrecognized charter directive".to_owned()),
    }
}

pub(super) fn parse_charter_verb(token: &str) -> std::result::Result<String, String> {
    if token == "*" {
        return Ok("*".to_owned());
    }
    let verb = token.to_ascii_lowercase();
    if !verb.is_empty()
        && verb
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        Ok(verb)
    } else {
        Err("invalid verb".to_owned())
    }
}

fn parse_charter_channel(token: &str) -> std::result::Result<String, String> {
    let channel = normalize_connector_key(token);
    if channel.is_empty() {
        return Err("invalid channel".to_owned());
    }
    Ok(channel)
}

/// `never <verb> on <channel>` channel narrowing. The compiled entry splits at
/// its FIRST ':', so a colon-bearing token here (`mcp:calendar`) would compile
/// into `"mcp:calendar:{verb}"` — an entry whose channel is `"mcp"` and whose
/// remainder is `"calendar:{verb}"`, which denies nothing on the channel the
/// author named (fail-open). Reject it at compile, with a line number, and point
/// at the form that CAN name a colon-bearing identity. Cap/rate channels keep
/// `parse_charter_channel`: a cap row's `channel_class` is matched whole, so
/// `cap 10 sends per day on mcp:calendar` stays legitimate.
fn parse_charter_never_channel(token: &str) -> std::result::Result<String, String> {
    let channel = parse_charter_channel(token)?;
    if channel.contains(':') {
        return Err("never channel must not contain ':'; use `never key`".to_owned());
    }
    Ok(channel)
}

/// `never key <channel>:<remainder>` (ONE-1885): the operand IS the whole
/// compiled entry, canonicalized into the shared `normalize_connector_key`
/// byte-space the per-grant key producer and the matcher already meet in — so a
/// hyphenated or shouted server spelling compiles to the same bytes the engine
/// stores. Shape is not decided here: the compile loop validates every emitted
/// entry through `validate_never_list_entry`, so a missing colon, an empty part,
/// or a partial wildcard fails closed with this line's number.
fn parse_charter_never_key(token: &str) -> String {
    normalize_connector_key(token)
}

/// Cap/rate channel narrowing. The gate matches a cap row's `channel_class`
/// by EXACT equality (`load_budget_row_states`), so a stored `"*"` would never
/// match a real channel (slack/email) — a `cap 10 sends per day on *` would
/// compile into a row that debits 0 forever (fail-OPEN). Reject the wildcard
/// here. `never <verb> on <channel>` keeps `"*"` as a legitimate wildcard via
/// `parse_charter_channel`, so this narrowing is cap/rate-only.
fn parse_charter_cap_channel(token: &str) -> std::result::Result<String, String> {
    let channel = parse_charter_channel(token)?;
    if channel == "*" {
        return Err("cap channel must not be the wildcard '*'".to_owned());
    }
    Ok(channel)
}

fn parse_charter_number(token: &str, message: &str) -> std::result::Result<u64, String> {
    match token.parse::<u64>() {
        Ok(value) if value >= 1 => Ok(value),
        _ => Err(message.to_owned()),
    }
}

fn parse_calendar_period(token: &str) -> Option<CalendarPeriod> {
    CalendarPeriod::parse(token.to_ascii_lowercase().as_str())
}

fn parse_rolling_duration(token: &str) -> std::result::Result<u64, String> {
    token
        .strip_suffix(['s', 'S'])
        .ok_or_else(|| "invalid window duration".to_owned())
        .and_then(|digits| parse_charter_number(digits, "invalid window duration"))
}

fn parse_charter_window(token: &str) -> std::result::Result<EffectorBudgetWindow, String> {
    if let Some(period) = parse_calendar_period(token) {
        return Ok(EffectorBudgetWindow::Calendar { period, tz: None });
    }
    Ok(EffectorBudgetWindow::Rolling {
        duration_s: parse_rolling_duration(token)?,
    })
}

/// M8 / R7 (2026-07-10): the cap unit MUST equal the connector's declared
/// denomination — no conversion in the gate, ever. ISO-4217 currencies
/// compile MAJOR → minor units via the pinned exponent table (default 2;
/// explicit exponent-0 list JPY/KRW/VND); provider units pass through as
/// opaque integers.
fn charter_spend_limit(major_units: u64, unit: &str) -> std::result::Result<u64, String> {
    validate_spend_unit(unit).map_err(|error| match error {
        Error::InvalidConnectorKeyBody(reason) => reason.to_owned(),
        _ => "invalid spend unit".to_owned(),
    })?;
    let bytes = unit.as_bytes();
    let is_iso_currency = bytes.len() == 3 && bytes.iter().all(u8::is_ascii_uppercase);
    if !is_iso_currency {
        return Ok(major_units);
    }
    let exponent: u32 = if ISO_4217_ZERO_EXPONENT_CURRENCIES.contains(&unit) {
        0
    } else {
        2
    };
    major_units
        .checked_mul(10_u64.pow(exponent))
        .ok_or_else(|| "spend cap overflows minor units".to_owned())
}
