//! Deterministic keyword tripwire for the hosted legal plane.
//!
//! This is a MECHANISM, not a policy. It ships matchers for three of the
//! hosted plane's public categories and nothing else, and a matcher can only
//! fire when the hosted service's own policy carries a row of that category —
//! so an engine build with no hosted policy in play classifies nothing here.
//! `JurisdictionRule` has no matcher by design: a jurisdiction rule is prose
//! that only the safeguard model can read.
//!
//! It never runs for the owner plane, and never for content that does not
//! transit our infrastructure.

use super::planes::HostedLegalPolicy;
use super::planes::HostedLegalRow;
use super::verdict::HostedLegalCategory;

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

fn category_matches(category: HostedLegalCategory, normalized: &str) -> bool {
    match category {
        HostedLegalCategory::MinorSexualization => is_minor_sexualization(normalized),
        HostedLegalCategory::Ncii => contains_any(
            normalized,
            &[
                "non consensual intimate",
                "non-consensual intimate",
                "revenge porn",
                "leaked nude",
                "deepfake nude",
            ],
        ),
        HostedLegalCategory::SeriousCrime => contains_any(
            normalized,
            &[
                "build a bomb",
                "make a bomb",
                "make explosives",
                "mass harm",
                "terrorist attack",
                "3d print a ghost gun",
            ],
        ),
        // Prose rules are model territory; a keyword list would only guess.
        HostedLegalCategory::JurisdictionRule => false,
    }
}

fn is_minor_sexualization(normalized: &str) -> bool {
    normalized.contains("csam")
        || (contains_any(
            normalized,
            &[
                "minor",
                "minors",
                "child",
                "children",
                "underage",
                "kid",
                "kids",
                "teen",
                "13 year old",
                "14 year old",
                "15 year old",
            ],
        ) && contains_any(
            normalized,
            &[
                "sex", "sexual", "nude", "nudes", "explicit", "erotic", "porn", "nsfw",
            ],
        ))
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>()
}
