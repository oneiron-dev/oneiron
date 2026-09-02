use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

use super::codec::encode_compiled_policy;
use super::record::{
    CAPABILITY_NEVER_ENTRY_TAG, CONNECTOR_KEY_MAX_BUDGET_ROWS, CalendarPeriod,
    CompiledConnectorPolicy, ConnectorCharterBlock, EffectorBudget, EffectorBudgetDimension,
    EffectorBudgetOnExhaust, EffectorBudgetWindow, ScopedCapabilityProvenance,
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

/// ORDINARY never-list matching: an entry `"{c}:{v}"` matches iff (`c == "*"`
/// or `c ==` the WHOLE normalized effect channel) and (`v == "*"` or `v ==` the
/// trimmed, lowercased effect verb).
///
/// The channel is everything before the entry's LAST ':', so every colon inside
/// an ordinary connector is data: `never send on mcp:calendar` matches the
/// complete `mcp:calendar` string and nothing shorter. Capability-only rules are
/// a different mode and are skipped here — an ordinary connector never acquires
/// capability authority from its spelling.
pub(crate) fn charter_never_list_matches(
    block: &ConnectorCharterBlock,
    normalized_channel: &str,
    verb: &str,
) -> bool {
    let verb = verb.trim().to_ascii_lowercase();
    block.compiled.never_list.iter().any(|entry| {
        if entry.starts_with(CAPABILITY_NEVER_ENTRY_TAG) {
            return false;
        }
        let Some((channel_part, verb_part)) = entry.rsplit_once(':') else {
            return false;
        };
        (channel_part == "*" || channel_part == normalized_channel)
            && (verb_part == "*" || verb_part == verb)
    })
}

/// CAPABILITY-ONLY never-list matching (ONE-1885): a `never key` entry matches
/// iff it names EXACTLY the engine-produced per-grant connector of the typed
/// capability this dispatch was admitted under.
///
/// The argument is a verified [`ScopedCapabilityProvenance`], never a string a
/// caller or a durable row could spell: an ordinary connector — including an
/// exact-shaped `mcp:{server}:grant:{id}` lookalike — has no such value, so no
/// `never key` rule can ever reach it. Matching is whole and exact, so a
/// neighbouring grant on the same server keeps its own outcome and no prefix,
/// suffix, or per-segment lookalike matches.
pub(crate) fn charter_never_list_matches_capability(
    block: &ConnectorCharterBlock,
    capability: &ScopedCapabilityProvenance,
) -> bool {
    block.compiled.never_list.iter().any(|entry| {
        entry
            .strip_prefix(CAPABILITY_NEVER_ENTRY_TAG)
            .is_some_and(|capability_key| capability_key == capability.connector())
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
        // `never <verb>` | `never <verb> on <channel>`
        // | `never key mcp:<server>:grant:<id>`
        "never" => match tokens.len() {
            2 => {
                if tokens[1].eq_ignore_ascii_case("key") {
                    // `never key` alone reads as the capability form with its
                    // operand missing, not as a prohibition on the verb "key".
                    // Fail closed rather than compile the silent `*:key`.
                    return Err(
                        "never key requires an mcp:<server>:grant:<id> capability key".to_owned(),
                    );
                }
                Ok(CharterDirective::Never(format!(
                    "*:{}",
                    parse_charter_verb(tokens[1])?
                )))
            }
            3 if tokens[1].eq_ignore_ascii_case("key") => {
                Ok(CharterDirective::Never(parse_charter_never_key(tokens[2])?))
            }
            4 if tokens[2].eq_ignore_ascii_case("on") => {
                let verb = parse_charter_verb(tokens[1])?;
                // The channel keeps its colons: the entry's verb is its LAST
                // segment, so the whole `mcp:calendar` string is the channel.
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

/// Ordinary `never ... on` channels retain their complete connector bytes.
/// Unlike cap/rate channel classes, this grammar is enforced by whole-string
/// matching, so a scoped server's `-` and `_` are distinct data.
fn parse_charter_never_channel(token: &str) -> std::result::Result<String, String> {
    if token.trim().is_empty() {
        return Err("invalid channel".to_owned());
    }
    Ok(token.to_owned())
}

fn parse_charter_channel(token: &str) -> std::result::Result<String, String> {
    let channel = normalize_connector_key(token);
    if channel.is_empty() {
        return Err("invalid channel".to_owned());
    }
    Ok(channel)
}

/// `never key mcp:<server>:grant:<id>` (ONE-1885): the CAPABILITY-ONLY form.
///
/// The operand must name one identity the engine could actually mint — a safe
/// canonical server segment and a real grant id — so it compiles into the
/// tagged entry the capability matcher compares whole against a typed
/// [`ScopedCapabilityProvenance`]. The key must already use the exact canonical
/// server spelling; the compiler never case-folds it or aliases `'-'` with
/// `'_'`.
/// Anything else (a wildcard, a truncated key, an ordinary channel string, a
/// colon-bearing server) fails closed with this line's number rather than
/// becoming a prohibition nothing can honour.
fn parse_charter_never_key(token: &str) -> std::result::Result<String, String> {
    let capability =
        ScopedCapabilityProvenance::parse_owner_capability_key(token).ok_or_else(|| {
            "never key must name one canonical mcp:<server>:grant:<id> capability key".to_owned()
        })?;
    Ok(format!(
        "{CAPABILITY_NEVER_ENTRY_TAG}{}",
        capability.connector()
    ))
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
