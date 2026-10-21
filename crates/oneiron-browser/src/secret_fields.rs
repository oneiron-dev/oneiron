//! One classifier for the secrets a page or a window shows (FIX 8028,
//! OF-560; ARCH-0069 secret custody): card numbers, card security codes,
//! one-time codes and passwords. A field it names becomes a run-bound
//! secret handle where it is found ([`crate::SecretCustody`]); its row shows
//! the handle, and a card its last four digits too, never the secret, and a
//! screenshot masks the same fields.
//!
//! The rule (`secret_field_policy`, CALLS row): an autocomplete token
//! decides first; then the accessibility tree's `protected` property or an
//! input of type password; then the label phrases a text field's label or
//! description names; then a text field showing only mask glyphs; last, a
//! value that is a card number alone (12 to 19 digits, spaces and hyphens
//! between, passing Luhn). A digit count alone never makes a security code
//! or a one-time code.
//!
//! Without the driver the crate is the verb shapes only: the kinds and the
//! row's secret stand, and nothing classifies.
#![cfg_attr(not(feature = "driver"), allow(dead_code))]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::ops::RangeInclusive;

/// What kind of secret a field holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    /// A payment card number: its row shows its last four digits and its
    /// handle.
    Card,
    /// A card's security code (CVV, CVC): its row shows its handle only.
    Cvv,
    /// A one-time code: its row shows its handle only.
    Otp,
    /// A password, passcode or PIN: its row shows its handle only.
    Password,
}

/// The secret a row's value is: its kind, and the run-bound handle it
/// became where it was found, or why it has none. The row's `value` shows
/// the handle (a card its last four digits too), never the secret; a type
/// or expect names the handle as its `secret`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RowSecret {
    pub kind: SecretKind,
    /// The handle (`scN`) the value became, held for this run alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// Why the field shows `[secret]` with no handle: the value was not
    /// taken into custody. A field with no value carries neither.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<SecretNote>,
}

/// Why a secret field's value became no handle. Its row shows `[secret]`,
/// never the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecretNote {
    /// The page shows the field concealed (mask glyphs): there is no value
    /// to take.
    Concealed,
    /// This browser's host keeps no secret custody.
    NoCustody,
    /// The host's custody refused to take the value.
    Refused,
}

/// What a row shows in place of a secret that became no handle, and what
/// a locator or scope key holds in place of any secret, so it stays the
/// same however the secret's handle changes.
pub(crate) const SECRET_MARK: &str = "[secret]";

/// The digits a card number alone holds (`secret_field_policy`).
const CARD_DIGITS: RangeInclusive<usize> = 12..=19;

/// The roles of rows that hold typed text, any of which may be secret.
pub(crate) const TEXT_ROLES: &[&str] = &["textbox", "searchbox", "combobox", "spinbutton"];

/// What a toolkit shows in place of a concealed field's text.
const MASK_GLYPHS: &[char] = &['•', '●', '∙', '*'];

/// Autocomplete tokens that name a secret field, in the order they decide.
const AUTOCOMPLETE: &[(&str, SecretKind)] = &[
    ("cc-number", SecretKind::Card),
    ("cc-csc", SecretKind::Cvv),
    ("one-time-code", SecretKind::Otp),
    ("current-password", SecretKind::Password),
    ("new-password", SecretKind::Password),
];

/// Words in a text field's label or description that mark it secret, in
/// the order they decide: a "card security code" is a security code.
const SECRET_PHRASES: &[(&[&str], SecretKind)] = &[
    (&["cvv"], SecretKind::Cvv),
    (&["cvc"], SecretKind::Cvv),
    (&["security", "code"], SecretKind::Cvv),
    (&["card", "verification"], SecretKind::Cvv),
    (&["one", "time"], SecretKind::Otp),
    (&["otp"], SecretKind::Otp),
    (&["verification", "code"], SecretKind::Otp),
    (&["card", "number"], SecretKind::Card),
    (&["password"], SecretKind::Password),
    (&["passcode"], SecretKind::Password),
    (&["passphrase"], SecretKind::Password),
    (&["pin"], SecretKind::Password),
];

/// What one field shows the classifier: its row's role, the accessibility
/// tree's `protected` property, its input type and autocomplete tokens
/// (a page's DOM, none on a desktop), its label and description, and its
/// value as the page holds it (a text row's text).
pub(crate) struct FieldFacts<'a> {
    pub(crate) role: &'a str,
    pub(crate) protected: bool,
    pub(crate) input_type: Option<&'a str>,
    pub(crate) autocomplete: Option<&'a str>,
    pub(crate) label: &'a str,
    pub(crate) description: &'a str,
    pub(crate) value: &'a str,
}

/// The kind of secret a field holds, if it holds one
/// (`secret_field_policy`, CALLS row).
pub(crate) fn classify(facts: &FieldFacts<'_>) -> Option<SecretKind> {
    secret_field_policy(facts)
}

fn secret_field_policy(facts: &FieldFacts<'_>) -> Option<SecretKind> {
    if let Some(tokens) = facts.autocomplete {
        let tokens: Vec<String> = tokens
            .split_ascii_whitespace()
            .map(str::to_ascii_lowercase)
            .collect();
        let named = AUTOCOMPLETE
            .iter()
            .find(|(token, _)| tokens.iter().any(|t| t == token));
        if let Some((_, kind)) = named {
            return Some(*kind);
        }
    }
    if facts.protected
        || facts
            .input_type
            .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("password"))
    {
        return Some(SecretKind::Password);
    }
    if TEXT_ROLES.contains(&facts.role) {
        let phrase = SECRET_PHRASES.iter().find(|(phrase, _)| {
            has_phrase(facts.label, phrase) || has_phrase(facts.description, phrase)
        });
        if let Some((_, kind)) = phrase {
            return Some(*kind);
        }
        if masked(facts.label) || masked(facts.value) {
            return Some(SecretKind::Password);
        }
    }
    card_alone(facts.value).then_some(SecretKind::Card)
}

/// Whether `text` is nothing but mask glyphs, as a concealed field shows it.
pub(crate) fn masked(text: &str) -> bool {
    let mut glyphs = text.chars().filter(|c| !c.is_whitespace()).peekable();
    glyphs.peek().is_some() && glyphs.all(|c| MASK_GLYPHS.contains(&c))
}

/// Whether `name` holds the words of `phrase` in a row, ignoring case.
pub(crate) fn has_phrase(name: &str, phrase: &[&str]) -> bool {
    let words: Vec<String> = name
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect();
    words
        .windows(phrase.len())
        .any(|w| w.iter().zip(phrase).all(|(a, b)| a == b))
}

/// Whether `value` is a card number alone: 12 to 19 digits, single spaces
/// or hyphens between them, not all zero, passing Luhn.
fn card_alone(value: &str) -> bool {
    let text = value.trim();
    let edges = text.starts_with(|c: char| c.is_ascii_digit())
        && text.ends_with(|c: char| c.is_ascii_digit());
    if !edges
        || !text
            .chars()
            .all(|c| c.is_ascii_digit() || c == ' ' || c == '-')
        || text.contains("  ")
        || text.contains("--")
    {
        return false;
    }
    let digits: Vec<u32> = text.chars().filter_map(|c| c.to_digit(10)).collect();
    if !CARD_DIGITS.contains(&digits.len()) || digits.iter().all(|d| *d == 0) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(at, digit)| match (at % 2, digit * 2) {
            (0, _) => *digit,
            (_, doubled) if doubled > 9 => doubled - 9,
            (_, doubled) => doubled,
        })
        .sum();
    sum % 10 == 0
}

/// What a secret field's row shows in its value's place
/// (`secret_display_policy`, CALLS row): a card's last four digits and its
/// handle, or its handle only when it holds fewer than four digits; any
/// other secret its handle only; `[secret]` when it became no handle.
pub(crate) fn secret_display_policy(kind: SecretKind, value: &str, handle: Option<&str>) -> String {
    let Some(handle) = handle else {
        return SECRET_MARK.to_owned();
    };
    let digits: Vec<char> = value.chars().filter(char::is_ascii_digit).collect();
    match kind {
        SecretKind::Card if digits.len() >= 4 => {
            let last: String = digits[digits.len() - 4..].iter().collect();
            format!("…{last} [secret {handle}]")
        }
        _ => format!("[secret {handle}]"),
    }
}

/// `text` with every secret of one read that it shows in place replaced
/// (`secret_echo_policy`, CALLS row): each `(secret, shown)` pair's secret,
/// found as a whole token (no letter or digit just before or after it), the
/// longest first where two start at one place, gives way to `shown`. None
/// when the text shows none of them.
pub(crate) fn secret_echo_policy(text: &str, echoes: &[(&str, &str)]) -> Option<String> {
    if echoes.is_empty() || text.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut hit = false;
    let mut at = 0;
    while at < text.len() {
        let rest = &text[at..];
        let before = text[..at].chars().next_back();
        let found = echoes
            .iter()
            .filter(|(secret, _)| !secret.is_empty() && rest.starts_with(secret))
            .filter(|(secret, _)| {
                token_edge(before) && token_edge(text[at + secret.len()..].chars().next())
            })
            .max_by_key(|(secret, _)| secret.len());
        match found {
            Some((secret, shown)) => {
                out.push_str(shown);
                at += secret.len();
                hit = true;
            }
            None => {
                let next = rest.chars().next().map_or(1, char::len_utf8);
                out.push_str(&rest[..next]);
                at += next;
            }
        }
    }
    hit.then_some(out)
}

/// Whether `neighbour` ends a token: the text's edge, or no letter or digit.
fn token_edge(neighbour: Option<char>) -> bool {
    neighbour.is_none_or(|c| !c.is_alphanumeric())
}

/// Whether a held secret of `kind` is what a field shows
/// (`secret_compare_policy`, CALLS row): the same bytes, or for a card
/// the same digits, as a card field groups what was typed into it.
pub(crate) fn secret_compare_policy(kind: Option<SecretKind>, held: &str, shown: &str) -> bool {
    if held == shown {
        return true;
    }
    let digits = |text: &str| -> String { text.chars().filter(char::is_ascii_digit).collect() };
    kind == Some(SecretKind::Card) && !digits(held).is_empty() && digits(held) == digits(shown)
}
