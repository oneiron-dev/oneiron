//! Deterministic keyword tripwire for the hosted legal plane.
//!
//! This is a MECHANISM, not a policy. It ships matchers for three of the
//! hosted plane's public categories and nothing else, and a matcher can only
//! fire when the hosted service's own policy carries a row of that category —
//! so an engine build with no hosted policy in play classifies nothing here.
//! `JurisdictionRule` has no matcher by design: a jurisdiction rule is prose
//! that only the safeguard model can read, which is what
//! [`hosted_policy_needs_model_tier`] reports so a deterministic-only pass is
//! never mistaken for coverage of one.
//!
//! Matching is WHOLE-TOKEN, never substring. A substring matcher fires on
//! `minor` inside `minority`, `kid` inside `kidney`, `sex` inside `unisex` and
//! `teen` inside `canteen` — ordinary prose answered with a hosted block.
//! [`normalize`] therefore folds content to lowercase alphanumeric tokens
//! separated by exactly one space and pads both ends, and every needle is
//! padded the same way, so a needle matches a whole word (or a whole run of
//! words) and nothing else. Collapsing the separator runs is what lets a
//! multi-word needle survive ordinary typography: `revenge, porn` and
//! `steps to make (a bomb)` both normalize to single-spaced tokens and match.
//! The cost is that the word forms a substring matcher caught for free must now
//! be listed, which is why the lists below spell out plurals and derived forms.
//!
//! It never runs for the owner plane, and never for content that does not
//! transit our infrastructure.

use super::planes::HostedLegalPolicy;
use super::planes::HostedLegalRow;
use super::verdict::HostedLegalCategory;

/// Words naming a minor. Forms are spelled out because whole-token matching
/// does not derive them — `minors`, `teenagers` and `kiddie` all rode in on the
/// bare stems while matching was substring-based.
const MINOR_TERMS: &[&str] = &[
    "minor",
    "minors",
    "child",
    "children",
    "underage",
    "underaged",
    "kid",
    "kids",
    "kiddie",
    "kiddies",
    "teen",
    "teens",
    "teenage",
    "teenaged",
    "teenager",
    "teenagers",
    "13 year old",
    "13 year olds",
    "14 year old",
    "14 year olds",
    "15 year old",
    "15 year olds",
];

/// Words naming sexual content.
///
/// `explicit` is deliberately NOT one of them. On its own it is an ordinary
/// English adjective — "make the lifetime explicit" — and paired with
/// `minor`-the-adjective it fired this matcher on routine engineering prose.
/// Its sexual sense lives in fixed collocations, so those are listed instead;
/// `sexually explicit` and `explicit sexual` need no entry because `sexually`
/// and `sexual` already carry them.
const SEXUAL_TERMS: &[&str] = &[
    "sex",
    "sexual",
    "sexually",
    "sexualized",
    "sexualised",
    "sexualization",
    "sexualisation",
    "sexy",
    "sexting",
    "nude",
    "nudes",
    "nudity",
    "erotic",
    "erotica",
    "eroticism",
    "porn",
    "porno",
    "pornography",
    "pornographic",
    "nsfw",
    "explicit image",
    "explicit images",
    "explicit photo",
    "explicit photos",
    "explicit video",
    "explicit videos",
];

/// The one term that needs no second half to be what it says it is.
const CSAM_TERMS: &[&str] = &["csam", "csams"];

const NCII_TERMS: &[&str] = &[
    "non consensual intimate",
    "nonconsensual intimate",
    "revenge porn",
    "revenge porno",
    "revenge pornography",
    "leaked nude",
    "leaked nudes",
    "deepfake nude",
    "deepfake nudes",
];

const SERIOUS_CRIME_TERMS: &[&str] = &[
    "build a bomb",
    "make a bomb",
    "make explosives",
    "mass harm",
    "mass harms",
    "terrorist attack",
    "terrorist attacks",
    "3d print a ghost gun",
];

/// The first hosted row whose category has a matcher that fires on `content`.
/// Row order in the hosted policy decides precedence.
pub(crate) fn hosted_tripwire_hit<'a>(
    content: &str,
    policy: &'a HostedLegalPolicy,
) -> Option<&'a HostedLegalRow> {
    let normalized = normalize(content);
    policy
        .rows
        .iter()
        .find(|row| category_matches(row.category, &normalized))
}

/// Whether `policy` carries a row no deterministic matcher can decide.
///
/// A deterministic-only pass over such a policy returns a clean allow meaning
/// "the rows that HAVE matchers did not fire" — not "the policy found nothing",
/// because the jurisdiction row was never read at all. The hosted plane is
/// fail-closed, so the relay marks that pass degraded rather than let the gap
/// read as coverage.
pub(crate) fn hosted_policy_needs_model_tier(policy: &HostedLegalPolicy) -> bool {
    policy
        .rows
        .iter()
        .any(|row| !category_has_deterministic_matcher(row.category))
}

fn category_matches(category: HostedLegalCategory, normalized: &str) -> bool {
    match category {
        HostedLegalCategory::MinorSexualization => is_minor_sexualization(normalized),
        HostedLegalCategory::Ncii => contains_any(normalized, NCII_TERMS),
        HostedLegalCategory::SeriousCrime => contains_any(normalized, SERIOUS_CRIME_TERMS),
        // Prose rules are model territory; a keyword list would only guess.
        HostedLegalCategory::JurisdictionRule => false,
    }
}

/// Which categories the deterministic tier can decide at all. Exhaustive with
/// no wildcard: a new [`HostedLegalCategory`] has to say whether a matcher
/// covers it, or this stops compiling.
const fn category_has_deterministic_matcher(category: HostedLegalCategory) -> bool {
    match category {
        HostedLegalCategory::MinorSexualization
        | HostedLegalCategory::Ncii
        | HostedLegalCategory::SeriousCrime => true,
        HostedLegalCategory::JurisdictionRule => false,
    }
}

fn is_minor_sexualization(normalized: &str) -> bool {
    contains_any(normalized, CSAM_TERMS)
        || (contains_any(normalized, MINOR_TERMS) && contains_any(normalized, SEXUAL_TERMS))
}

fn contains_any(normalized: &str, needles: &[&str]) -> bool {
    needles
        .iter()
        .any(|needle| contains_token(normalized, needle))
}

/// Whole-token containment. `normalized` is single-spaced and padded at both
/// ends, so padding the needle identically turns a substring test into a token
/// test — and a multi-word needle matches a run of whole words.
fn contains_token(normalized: &str, needle: &str) -> bool {
    let mut padded = String::with_capacity(needle.len() + 2);
    padded.push(' ');
    padded.push_str(needle);
    padded.push(' ');
    normalized.contains(&padded)
}

/// Lowercase alphanumeric tokens, exactly one space between them, one space at
/// each end. The padding and the collapsed runs are what make
/// [`contains_token`] a token test rather than a substring test.
fn normalize(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len() + 2);
    normalized.push(' ');
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
        } else if !normalized.ends_with(' ') {
            normalized.push(' ');
        }
    }
    if !normalized.ends_with(' ') {
        normalized.push(' ');
    }
    normalized
}
