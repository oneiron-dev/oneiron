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
//! # Three matching modes
//!
//! A pure substring matcher fires `minor` inside `minority`, `kid` inside
//! `kidney`, `sex` inside `unisex` and `teen` inside `canteen` — ordinary prose
//! answered with a hosted block. A pure whole-token matcher cannot see inside a
//! closed compound at all, so `childporn`, `teensex` and a `/childporn/` path
//! segment walk straight through it, and growing the word lists never fixes
//! that: the compounds are unbounded. Neither mode is right alone, so this
//! matcher composes three, and each one is narrow enough to state why it is
//! safe.
//!
//! 1. **Whole token.** The ambiguous common words — [`MINOR_TERMS`],
//!    [`SEXUAL_TERMS`], [`NCII_TERMS`], [`SERIOUS_CRIME_TERMS`]. [`normalize`]
//!    folds content to lowercase alphanumeric tokens separated by exactly one
//!    space and pads both ends; every needle is padded the same way, so a
//!    needle matches a whole word (or a whole run of words) and nothing else.
//!    Collapsing the separator runs is what lets a multi-word needle survive
//!    ordinary typography: `revenge, porn` and `steps to make (a bomb)` both
//!    normalize to single-spaced tokens and match. The cost is that every word
//!    form has to be listed, which is why the lists spell out plurals, verb
//!    forms and both -ise/-ize spellings.
//!
//! 2. **Substring-safe stem.** [`CSAM_STEM`] and [`PORN_STEM`], matched raw
//!    against the normalized text, no token boundary at either end. The
//!    argument for each is a collision argument, not a taste one: over the
//!    235,976 entries of `/usr/share/dict/words`, `csam` appears in none, and
//!    `porn` appears only in `Agapornis` (a lovebird genus), `epornitic` /
//!    `epornitically` (of a bird-flock epidemic) and `philopornist` — no word
//!    of ordinary use, and every one of those already tripped the substring
//!    matcher this file replaced, so they are not new. Two stems bought a great
//!    deal: `porn` covers `pornsite`, `pornhub`, `porns`, `pornographies`,
//!    `pornographer` and every compound anyone invents next, and `csam` gets
//!    back the base substring semantics that whole-token matching had silently
//!    narrowed. A third stem needs the same dictionary argument, written down.
//!
//! 3. **Same-token dual stem.** One token carrying BOTH a [`MINOR_STEMS`]
//!    substring and a [`SEXUAL_STEMS`] substring trips minor sexualization on
//!    its own. This is strictly narrower than a document-level substring AND —
//!    if one token holds both stems then the document holds both — so it can
//!    introduce no false positive the substring matcher did not already have,
//!    and no word in `/usr/share/dict/words` carries a stem from each list.
//!    What it buys is every closed compound at once: `childporn`, `kidporn`,
//!    `teensex`, `underagesex`, `childerotica`, `childnudes`, and the path
//!    segments of a URL, which normalize into tokens like any other word.
//!
//! # What differs from the substring matcher this replaced
//!
//! Two classes are deliberately SHED — content the old matcher blocked and this
//! one allows:
//!
//! * **Identity and orientation terms.** `homosexual`, `bisexual`, `pansexual`,
//!   `intersex`, `transsexual`, `asexual` all carry the `sex` substring, so
//!   `bisexual teen support group` and `intersex youth clinic` were answered
//!   with a hosted block. None of them is listed as a sexual term and none is a
//!   dual-stem token, so none of them fires now. This is the false-positive
//!   class the mode split exists to kill, not recall worth preserving.
//! * **Bare `explicit` outside a collocation.** `explicit` on its own is an
//!   ordinary English adjective, and beside `minor`-the-adjective it blocked
//!   routine engineering prose. Its sexual sense is listed as fixed
//!   collocations instead, so `explicit story` and `explicit content` still
//!   fire while `explicit text`, `explicit writing` and `explicit` with no noun
//!   at all no longer do. Those nouns are engineering vocabulary; the loss is
//!   real, narrow, and taken on purpose.
//!
//! Two classes are KEPT even though they read wide, and the tests say so out
//! loud rather than leave them to be rediscovered:
//!
//! * **`nudity`.** It does not contain the substring `nude`, so this is the one
//!   place the lists reach FURTHER than the matcher they replaced. It stays
//!   because `nudity involving a minor` is how the rule this serves is normally
//!   written and the plane is fail-closed — and the cost is that benign prose
//!   about nudity in a children's book is a hosted hit.
//! * **The document-level AND.** A minor term anywhere and a sexual term
//!   anywhere is a hit, however far apart they sit, so `an explicit description
//!   of the minor version bump` trips. A proximity window would narrow it and
//!   is out of scope here; the residual is exactly the substring matcher's own
//!   residual, minus the two shed classes, so it is strictly smaller than what
//!   this file inherited.
//!
//! It never runs for the owner plane, and never for content that does not
//! transit our infrastructure.

use super::planes::HostedLegalPolicy;
use super::planes::HostedLegalRow;
use super::verdict::HostedLegalCategory;

/// Words naming a minor, matched whole-token. Forms are spelled out because
/// whole-token matching does not derive them — `minors`, `teenagers`,
/// `preteen`, `schoolchildren` and `kiddo` all rode in on the bare stems while
/// matching was substring-based, and each needs a line of its own now.
///
/// Hyphenated and possessive spellings need no line: [`normalize`] turns
/// `pre-teen` into `pre teen` and `children's` into `children s`, and the bare
/// `teen` and `children` needles match the token that leaves behind. The
/// unspaced misspellings (`childrens`, `kidz`) do need one.
pub(super) const MINOR_TERMS: &[&str] = &[
    "minor",
    "minors",
    "child",
    "childs",
    "children",
    "childrens",
    "childhood",
    "childlike",
    "childish",
    "schoolchild",
    "schoolchildren",
    "schoolkid",
    "schoolkids",
    "grandchild",
    "grandchildren",
    "stepchild",
    "stepchildren",
    "underage",
    "underaged",
    "kid",
    "kids",
    "kiddie",
    "kiddies",
    "kiddy",
    "kiddo",
    "kiddos",
    "kidz",
    "teen",
    "teens",
    "teenage",
    "teenaged",
    "teenager",
    "teenagers",
    "preteen",
    "preteens",
    "13 year old",
    "13 year olds",
    "14 year old",
    "14 year olds",
    "15 year old",
    "15 year olds",
];

/// Words naming sexual content, matched whole-token.
///
/// The `porn` family is absent on purpose: [`PORN_STEM`] matches it as a raw
/// substring, which covers every compound and inflection without a list.
///
/// `explicit` is deliberately not a needle. On its own it is an ordinary
/// English adjective — "make the lifetime explicit" — and paired with
/// `minor`-the-adjective it fired this matcher on routine engineering prose.
/// Its sexual sense lives in fixed collocations, so those are listed instead:
/// the media nouns AND the prose nouns, because solicitation of text is the
/// shape a memory engine actually stores ("an explicit story about a 14 year
/// old" must not walk through a hole left by listing only `explicit photo`).
/// `sexually explicit` and `explicit sexual` need no entry because `sexually`
/// and `sexual` already carry them.
///
/// Identity and orientation words are absent for the reason given in the
/// module doc, and their absence is asserted by a test, not left to inference.
/// The derivational forms that ARE here — `eroticizing`, `homoerotic`,
/// `hypersexualized` and their siblings — name the act or the content, not a
/// person's orientation.
pub(super) const SEXUAL_TERMS: &[&str] = &[
    "sex",
    "sexes",
    "sexual",
    "sexually",
    "sexuality",
    "sexualise",
    "sexualises",
    "sexualised",
    "sexualising",
    "sexualize",
    "sexualizes",
    "sexualized",
    "sexualizing",
    "sexualisation",
    "sexualization",
    "hypersexualise",
    "hypersexualises",
    "hypersexualised",
    "hypersexualising",
    "hypersexualize",
    "hypersexualizes",
    "hypersexualized",
    "hypersexualizing",
    "hypersexualisation",
    "hypersexualization",
    "oversexualise",
    "oversexualises",
    "oversexualised",
    "oversexualising",
    "oversexualize",
    "oversexualizes",
    "oversexualized",
    "oversexualizing",
    "oversexualisation",
    "oversexualization",
    "sexy",
    "sexier",
    "sexiest",
    "sext",
    "sexts",
    "sexted",
    "sexting",
    "nude",
    "nudes",
    "nudity",
    "erotic",
    "erotica",
    "erotical",
    "erotically",
    "eroticism",
    "eroticise",
    "eroticises",
    "eroticised",
    "eroticising",
    "eroticisation",
    "eroticize",
    "eroticizes",
    "eroticized",
    "eroticizing",
    "eroticization",
    "homoerotic",
    "homoerotica",
    "homoerotically",
    "autoerotic",
    "autoerotica",
    "autoerotically",
    "nsfw",
    // `explicit` only counts beside a noun that gives it the sexual sense.
    "explicit image",
    "explicit images",
    "explicit photo",
    "explicit photos",
    "explicit picture",
    "explicit pictures",
    "explicit pic",
    "explicit pics",
    "explicit video",
    "explicit videos",
    "explicit media",
    "explicit drawing",
    "explicit drawings",
    "explicit artwork",
    "explicit story",
    "explicit stories",
    "explicit fiction",
    "explicit content",
    "explicit roleplay",
    "explicit role play",
    "explicit scene",
    "explicit scenes",
    "explicit description",
    "explicit descriptions",
    "explicit depiction",
    "explicit depictions",
    "explicit material",
    "explicit materials",
];

/// The one stem that needs no second half to be what it says it is, matched as
/// a raw substring so `csamcollection` and a `/csam/` path segment count.
pub(super) const CSAM_STEM: &str = "csam";

/// A sexual term wherever it appears inside a word, matched as a raw substring
/// so the whole `porn` family — compounds, brand names, inflections — needs no
/// enumeration. Like [`CSAM_STEM`] it is safe only because of the dictionary
/// check recorded in the module doc.
pub(super) const PORN_STEM: &str = "porn";

/// The minor half of the same-token dual-stem rule.
///
/// `preteen` is subsumed by `teen` and kept anyway, so the list reads as the
/// rule is stated rather than as the shortest set that implements it.
pub(super) const MINOR_STEMS: &[&str] = &["child", "kid", "teen", "preteen", "minor", "underage"];

/// The sexual half of the same-token dual-stem rule. `sext` is subsumed by
/// `sex`, and kept for the same reason `preteen` is.
pub(super) const SEXUAL_STEMS: &[&str] = &["sex", PORN_STEM, "nude", "erotic", CSAM_STEM, "sext"];

/// Whole-token NCII needles. The `revenge porn` family is not here: it lives in
/// [`NCII_STEM_TAIL_TERMS`], where one entry covers every tail form.
const NCII_TERMS: &[&str] = &[
    "non consensual intimate",
    "nonconsensual intimate",
    "leaked nude",
    "leaked nudes",
    "deepfake nude",
    "deepfake nudes",
];

/// Phrases whose LAST word is a substring-safe stem, so only the front needs a
/// token boundary. ` revenge porn` matches `revenge porn`, `revenge pornography`
/// and `revenge pornsite` alike, and cannot reach past `revenge` into another
/// word because the leading space is required.
const NCII_STEM_TAIL_TERMS: &[&str] = &["revenge porn"];

/// Verb forms are spelled out for the same reason the noun plurals are: the
/// substring matcher read `build a bomb` out of `build a bomber vest` for
/// free, and reads nothing out of `building a bomb`.
const SERIOUS_CRIME_TERMS: &[&str] = &[
    "build a bomb",
    "builds a bomb",
    "building a bomb",
    "build bombs",
    "building bombs",
    "make a bomb",
    "makes a bomb",
    "making a bomb",
    "make bombs",
    "making bombs",
    "bomber vest",
    "bomber vests",
    "make explosives",
    "makes explosives",
    "making explosives",
    "mass harm",
    "mass harms",
    "terrorist attack",
    "terrorist attacks",
    "3d print a ghost gun",
    "3d print ghost guns",
    "3d printed ghost gun",
    "3d printed ghost guns",
    "3d printing a ghost gun",
    "3d printing ghost guns",
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
        HostedLegalCategory::Ncii => {
            contains_any(normalized, NCII_TERMS)
                || contains_any_stem_tail(normalized, NCII_STEM_TAIL_TERMS)
        }
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

/// All three modes, in the order that decides fastest.
fn is_minor_sexualization(normalized: &str) -> bool {
    normalized.contains(CSAM_STEM)
        || some_token_pairs_both_stems(normalized)
        || (contains_any(normalized, MINOR_TERMS) && contains_sexual_term(normalized))
}

/// Mode 1 for the ambiguous words, mode 2 for the `porn` family.
fn contains_sexual_term(normalized: &str) -> bool {
    contains_any(normalized, SEXUAL_TERMS) || normalized.contains(PORN_STEM)
}

/// Mode 3. One token carrying a stem from each list is a closed compound like
/// `childporn`, and is a hit on its own.
fn some_token_pairs_both_stems(normalized: &str) -> bool {
    normalized.split_ascii_whitespace().any(|token| {
        contains_any_substring(token, MINOR_STEMS) && contains_any_substring(token, SEXUAL_STEMS)
    })
}

fn contains_any(normalized: &str, needles: &[&str]) -> bool {
    needles
        .iter()
        .any(|needle| contains_token(normalized, needle))
}

fn contains_any_substring(text: &str, stems: &[&str]) -> bool {
    stems.iter().any(|stem| text.contains(stem))
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

/// Whole-token at the front, open at the back. Only for needles whose last word
/// is a substring-safe stem, where an open tail cannot reach a benign word.
fn contains_any_stem_tail(normalized: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| {
        let mut padded = String::with_capacity(needle.len() + 1);
        padded.push(' ');
        padded.push_str(needle);
        normalized.contains(&padded)
    })
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
