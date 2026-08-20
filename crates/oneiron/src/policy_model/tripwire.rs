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
//! # Five matching modes
//!
//! A pure substring matcher fires `minor` inside `minority`, `kid` inside
//! `kidney`, `sex` inside `unisex` and `teen` inside `canteen` — ordinary prose
//! answered with a hosted block. A pure whole-token matcher cannot see inside a
//! closed compound at all, so `childporn`, `teensex`, `sextape` and a
//! `/childporn/` path segment walk straight through it, and growing the word
//! lists never fixes that: the compounds are unbounded. Neither mode is right
//! everywhere, so this matcher composes five. Each is narrow enough to state
//! why it is safe, and each is applied only to the lists whose vocabulary earns
//! it — which is the point the first two passes of this file got wrong by
//! picking one mode for everything.
//!
//! 1. **Whole token.** The ambiguous common words — [`MINOR_TERMS`] and
//!    [`SEXUAL_TERMS`]. [`normalize`] folds content to lowercase alphanumeric
//!    tokens separated by exactly one space and pads both ends; every needle is
//!    padded the same way, so a needle matches a whole word (or a whole run of
//!    words) and nothing else. The cost is that every word form has to be
//!    listed, which is why the lists spell out plurals, verb forms and both
//!    -ise/-ize spellings. This mode exists for exactly one reason: these two
//!    lists are the ones whose entries are also fragments of ordinary English,
//!    and token anchoring is what keeps `minority` and `unisex` out.
//!
//! 2. **Substring-safe stem.** [`CSAM_STEM`], [`PORN_STEM`] and [`NSFW_STEM`],
//!    matched raw against the normalized text, no token boundary at either end.
//!    The argument for each is a collision argument, not a taste one: over the
//!    235,976 entries of `/usr/share/dict/words`, `csam` and `nsfw` appear in
//!    none, and `porn` appears in fourteen, ten of which are the `porn-` family
//!    itself. The other four are `Agapornis` (a lovebird genus), `epornitic` /
//!    `epornitically` (of a bird-flock epidemic) and `philopornist` — no word
//!    of ordinary use, and every one already tripped the substring matcher this
//!    file replaced, so they are not new.
//!    Three stems buy a great deal: `porn` covers `pornsite`, `pornhub`,
//!    `porns`, `pornographies`, `pornographer` and every compound anyone
//!    invents next, `nsfw` covers `nsfwcontent` and friends, and `csam` gets
//!    back the base substring semantics that whole-token matching had silently
//!    narrowed. A fourth stem needs the same dictionary argument, written down.
//!
//! 3. **Same-token dual stem.** One token carrying BOTH a [`MINOR_STEMS`]
//!    substring and a [`SEXUAL_STEMS`] substring trips minor sexualization on
//!    its own. This is strictly narrower than a document-level substring AND —
//!    if one token holds both stems then the document holds both — so it can
//!    introduce no false positive the substring matcher did not already have,
//!    and no word in `/usr/share/dict/words` carries a stem from each list.
//!    What it buys is the 6 × 8 cross of those two lists in one token, in
//!    either order and with anything around it: `childporn`, `kidporn`,
//!    `teensex`, `underagesex`, `childerotica`, `childnudes`, `childnsfw`,
//!    `nsfwteen`, `explicitchild`, `kiddiepornocollection`, and the path
//!    segments of a URL, which normalize into tokens like any other word. That
//!    cross is the exact scope. A compound built from a word outside both lists
//!    is outside it, and the shed list below says which ones.
//!
//! 4. **Sexual stem in head position.** A token that BEGINS with a
//!    [`SEXUAL_HEAD_STEMS`] entry and carries more after it counts as a sexual
//!    term for the document-level AND, so `sextape of a 14 year old` and
//!    `child sextape` are hits without either word being listed. Head position
//!    is the whole safety argument, and it is a structural one: the benign
//!    words that carry these stems bury them at the END (`unisex`, `Essex`,
//!    `sclerotic`, `canteen`), the identity and orientation words bury them
//!    behind a modifier (`homosexual`, `bisexual`, `intersex`, `asexual`), and
//!    the compounds this has to catch put the stem FIRST (`sextape`,
//!    `sextortion`, `sexcam`, `sexchat`, `nudephotos`, `eroticist`). There is
//!    deliberately no minor-side twin of this rule: `kidney` and `minority`
//!    head-match `kid` and `minor`, and both are benign-corpus strings.
//!
//! 5. **Raw substring.** [`NCII_TERMS`] and [`SERIOUS_CRIME_TERMS`], matched
//!    against the normalized text with no token anchoring at either end —
//!    exactly what the matcher this replaced did with them, and the typography
//!    fix from mode 1 kept. Every entry in these two lists is a multi-word
//!    high-signal phrase (`terrorist attack`, `make a bomb`, `leaked nude`,
//!    `revenge porn`, `non consensual intimate`), so no single dictionary token
//!    can carry one and the whole `minority`/`unisex` failure mode that
//!    justifies mode 1 cannot arise here.
//!
//!    It does NOT follow that substring matching is collision-free on these
//!    lists, and an earlier draft of this paragraph claimed it was. It is not:
//!    `mass harm` sits inside `they amass harmful chemicals` and inside
//!    `mass harmony`, and `build a bomb` sits inside
//!    `build a bombproof shelter`. The rationale is narrower and checkable —
//!    every one of those collisions is IDENTICAL to the matcher this replaced,
//!    because mode 5 IS that matcher's semantics on these two lists. Token
//!    anchoring did not fix them either way; what it did was drop
//!    `the terrorist attacked the embassy`, `counterterrorist attack drill`,
//!    `mass harming of civilians`, `he wants to rebuild a bomb`,
//!    `remake a bomb from the parts`, `unleaked nude photos of her` and
//!    `nonrevenge porn`, every one of which the old matcher blocked. Paying a
//!    real recall loss for no false-positive gain is the trade this mode
//!    reverses.
//!
//!    The one place mode 5 reaches past the old matcher is the eighteen
//!    enumerated verb and plural forms, which are a named widening class below:
//!    `shipbuilding a bomber for the museum` trips `building a bomb`, and the
//!    old matcher let it through. Inflection is otherwise free under this mode,
//!    which is why the lists can spell out the forms that are not prefixes of
//!    each other and still reach the ones nobody spelled out.
//!
//! # What differs from the substring matcher this replaced
//!
//! Measured, not argued. A differential harness runs the matcher this replaced
//! and this one over a probe corpus of tens of millions of strings, built
//! from `/usr/share/dict/words` and from a list of modern compound heads
//! written without reference to either matcher's needles — dictionary words
//! alone, dictionary words crossed with an anchor of the opposite kind, and
//! synthesized compounds in both orders. A corpus generated FROM the needle
//! lists cannot find a loss on a word nobody listed, which is how two earlier
//! passes shipped recall claims that were not true; this one is generated
//! independently of them.
//!
//! Probe-population figures are given as orders of magnitude on purpose. The
//! harness is not in the tree — it depends on a dictionary file that is not
//! ours and whose contents differ between platforms — so an exact count
//! printed here would be a number no reader could check. The facts that ARE
//! stated exactly below are the ones a reader can reproduce with one command
//! against the named dictionary. Any figure of the form "N labels in the
//! sweep" from an earlier revision of this doc was of the unauditable kind and
//! has been withdrawn rather than restated.
//!
//! The acceptance bar is CLASS-level, not lemma-level: every string the old
//! matcher blocked and this one allows must sit inside one of the named
//! classes below, and a novel lemma inside a named class is in scope. A loss
//! outside every named class is a defect, and the differential sweep is what
//! decides which it is.
//!
//! Five classes are SHED — content the old matcher blocked and this one allows.
//!
//! * **1 — Identity and orientation: a stem buried behind a modifier.**
//!   `homosexual`, `bisexual`, `pansexual`, `intersex`, `transsexual`,
//!   `asexual`, `heterosexual`, `demisexual`, `metrosexual`, `psychosexual`,
//!   and the negation `nonsexual`. Each carries `sex`, so `bisexual teen
//!   support group` and `intersex youth clinic` were answered with a hosted
//!   block. None is a listed word, none heads a token with the stem, and none
//!   is a dual-stem token, so none fires now. This is the false-positive class
//!   the mode split exists to kill. The forms that name an ACT rather than an
//!   orientation are listed instead and do fire — `hypersexual`,
//!   `hypersexuality`, `oversexual`, `oversexuality`, `homoerotic`,
//!   `autoerotic` and their families.
//! * **2 — Bare `explicit` outside a collocation.** `explicit` on its own is an
//!   ordinary English adjective, and beside `minor`-the-adjective it blocked
//!   routine engineering prose. Its sexual sense is listed as fixed
//!   collocations instead, so `explicit story` and `explicit content` still
//!   fire while `explicit text`, `explicit writing`, bare `explicit`, and
//!   `explicit`-headed compounds like `explicitcontent` no longer do. Those
//!   nouns are engineering vocabulary; the loss is real, narrow, and taken on
//!   purpose. `explicitchild` still fires, because that is mode 3, not mode 4.
//! * **3 — NOVEL, NON-ENUMERATED sexual compounds with the stem in tail
//!   position and no minor stem in the same token.** The common ones are
//!   enumerated in [`SEXUAL_TERMS`] and do fire — `camsex`, `groupsex`,
//!   `webcamsex`, `cybersex`, `phonesex`, `livenude`. What stays shed is
//!   whatever nobody has listed yet: `freesex`, `animesex`, `hardnude`,
//!   `amateurerotic`. Closing the class outright needs tail-position substring
//!   matching, and the benign corpus prices that exactly: tail matching on
//!   `sex` resurrects `unisex` and `Essex`, and on `erotic` it resurrects
//!   `sclerotic` — all three are strings this matcher is required to leave
//!   alone. Enumeration is therefore the only instrument available, and an
//!   enumeration is by construction one lemma behind. The spaced spellings all
//!   still hit.
//! * **4 — NOVEL, NON-ENUMERATED minor-side compounds carrying no sexual stem,
//!   with the sexual term in another token.** The common ones are enumerated in
//!   [`MINOR_TERMS`] and do fire — `childmodel`, `childstar`, `teenstar`,
//!   `kidcam`. What stays shed is the rest: `childactor nudes`, `teenidol
//!   nudes`. A minor-side head rule would close the class and resurrect
//!   `kidney`, `minority` and `kidnap` with it; the benign corpus forbids that
//!   trade outright, so this side gets enumeration and the same one-lemma lag.
//! * **5 — The `desexualize` family.** `desexualize`, `desexualise`,
//!   `desexualized`, `desexualised` are deliberately NOT listed. They are
//!   removing-sexual-nature vocabulary — `desexualizing children's clothing` is
//!   the ordinary use — so the old matcher's hit on them was a false positive
//!   leaning, not recall. The class is separated from class 1 because the
//!   reason differs: class 1 names an identity, this one names the removal of
//!   the thing the category is about. Both are shed, neither is a regression.
//!
//! Three classes are KEPT even though they read WIDER than the matcher this
//! replaced:
//!
//! * **`nudity`.** It does not contain the substring `nude` and does not head
//!   it either, so the whole-token list is the only thing that reaches it. It
//!   stays because `nudity involving a minor` is how the rule this serves is
//!   normally written and the plane is fail-closed — and the cost is that
//!   benign prose about nudity in a children's book is a hosted hit. It is the
//!   only widening the dictionary sweep finds on the minor-sexualization side.
//! * **Verb and plural forms of the crime and NCII needles.** Seventeen
//!   [`SERIOUS_CRIME_TERMS`] entries (`building a bomb`, `makes a bomb`,
//!   `bomber vest`, `3d printed ghost guns`, …) and the unspaced
//!   `nonconsensual intimate` have no substring inside the old needles, so each
//!   is content the old matcher let through. Spelling them out is the point of
//!   the list; they are widenings all the same, and
//!   `every_needle_stays_inside_the_substring_matchers_reach` enumerates all
//!   eighteen rather than leaving them to be rediscovered.
//! * **The separator-run collapse.** The old [`normalize`] mapped every
//!   non-alphanumeric to its own space, so `revenge, porn` became
//!   `revenge␣␣porn` and missed. Collapsing runs makes both of those hit — an
//!   unbounded class in principle, and the reason mode 5 is "the old semantics
//!   plus the typography fix" rather than "the old semantics".
//!
//! Three residuals are KEPT and none is new:
//!
//! * **The document-level AND.** A minor term anywhere and a sexual term
//!   anywhere is a hit, however far apart they sit, so `an explicit description
//!   of the minor version bump` trips. A proximity window would narrow it and
//!   is explicitly out of scope here.
//! * **Benign `sex*`, `nude*` and `erotic*` dictionary words inherited by mode
//!   4.** Of the distinct normalized tokens in `/usr/share/dict/words`, 106
//!   begin with `sex` and are longer than it, 3 with `nude` and 6 with
//!   `erotic`; the bare stems are mode-1 hits instead, which is why the counts
//!   are one short of the starts-with counts. Beside a minor term every one of
//!   them is a hosted hit — `sexton`, `sextant` and `sexagesimal` are the ones
//!   that turn up in real prose, and `sexagesimal` is live engineering
//!   vocabulary rather than an antique, so `convert to sexagesimal for the
//!   minor axis` trips. All of them tripped the old matcher too, so mode 4
//!   widens nothing; it inherits.
//! * **Benign token runs inherited by mode 5.** `they amass harmful chemicals`
//!   and `mass harmony in the choral arrangement` both carry `mass harm`, and
//!   `build a bombproof shelter` carries `build a bomb`. These are the price of
//!   restoring the old semantics on these two lists, they are exactly the old
//!   matcher's own false positives, and mode 5 adds none of its own outside the
//!   eighteen named forms.
//!
//! The residual is not a subset of the old matcher's — it is differently
//! shaped: smaller on the five shed classes, larger on the three kept-wide
//! ones.
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
///
/// There is no minor-side counterpart to [`SEXUAL_HEAD_STEMS`]: a head rule on
/// `kid` and `minor` resurrects `kidney`, `kidnap` and `minority`, which the
/// benign corpus forbids. So a minor stem welded to a word that is not itself
/// sexual is reachable only by enumeration, and the frequent ones are
/// enumerated at the end of this list. Shed class 4 in the module doc is the
/// remainder, and it is a remainder by construction rather than by oversight.
///
/// The spelled-out ages are here because `thirteen` through `seventeen` each
/// contain `teen`, which the matcher this replaced matched as a raw substring.
/// Listing them costs nothing against that baseline and buys back
/// `thirteen year old nudes` and its five siblings, which whole-token matching
/// on `teen` alone could not see.
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
    // Spelled-out ages. Every one contains `teen`, so none reaches past the
    // substring matcher this replaced.
    "thirteen",
    "fourteen",
    "fifteen",
    "sixteen",
    "seventeen",
    // Minor-side compounds with no sexual stem of their own, so mode 3 cannot
    // see them and no head rule is allowed to. Each contains `child`, `teen` or
    // `kid`, so each was a substring hit before; none is a word in
    // `/usr/share/dict/words`, so none carries a benign sense to lose.
    "childmodel",
    "childstar",
    "teenstar",
    "kidcam",
];

/// Words naming sexual content, matched whole-token.
///
/// The `porn` and `nsfw` families are absent on purpose: [`PORN_STEM`] and
/// [`NSFW_STEM`] match them as raw substrings, which covers every compound and
/// inflection without a list.
///
/// Mode 4 already reaches most of the `sex`-, `nude`- and `erotic`-headed
/// entries below. They stay listed anyway: the list is the readable statement
/// of what this matcher is for, a test walks every entry, and a future
/// narrowing of the head rule must not silently drop them. What only this list
/// reaches is the rest — `nudity`, which heads nothing; the modifier-first
/// forms `homoerotic`, `autoerotic`, `hypersexual`, `hypersexuality`,
/// `oversexual` and `oversexuality`, which name an act rather than an
/// orientation; the tail-position compounds, whose stem sits where no rule of
/// this matcher may reach; and the `explicit` collocations.
///
/// `explicit` is deliberately not a needle on its own. Bare, it is an ordinary
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
    "hypersexual",
    "hypersexuality",
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
    "oversexual",
    "oversexuality",
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
    // Tail-position compounds: the sexual stem is at the END, where mode 4
    // cannot reach it and a tail rule would drag `unisex`, `Essex` and
    // `sclerotic` back in. Enumerated instead. None appears in
    // `/usr/share/dict/words`, as a word or inside one, so none has a benign
    // sense; each contains `sex` or `nude`, so none reaches past the substring
    // matcher this replaced. Shed class 3 is what enumeration cannot cover.
    "camsex",
    "groupsex",
    "webcamsex",
    "cybersex",
    "phonesex",
    "livenude",
    // Agent nouns. Mode 4 already heads all three; they are listed for the same
    // reason the other head-reachable entries are, so a future narrowing of the
    // head rule cannot drop them silently.
    "sexualiser",
    "sexualizer",
    "eroticist",
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

/// The same treatment for `nsfw`, which has zero occurrences anywhere in
/// `/usr/share/dict/words` — the cleanest collision argument of the three. It
/// is what makes `nsfwcontent` and `childnsfw` reachable; whole-token matching
/// on `nsfw` alone left both to walk through.
pub(super) const NSFW_STEM: &str = "nsfw";

/// Mode 2 on the sexual side of the document-level AND. [`CSAM_STEM`] is not
/// here because it does not need a minor term beside it: it trips alone.
pub(super) const SUBSTRING_SAFE_SEXUAL_STEMS: &[&str] = &[PORN_STEM, NSFW_STEM];

/// The minor half of the same-token dual-stem rule.
///
/// `preteen` is subsumed by `teen` and kept anyway, so the list reads as the
/// rule is stated rather than as the shortest set that implements it.
pub(super) const MINOR_STEMS: &[&str] = &["child", "kid", "teen", "preteen", "minor", "underage"];

/// The sexual half of the same-token dual-stem rule. `sext` is subsumed by
/// `sex`, and kept for the same reason `preteen` is.
///
/// `nsfw` and `explicit` are what make `childnsfw`, `nsfwchild`, `teennsfw`,
/// `nsfwteen`, `kiddiensfw`, `minornsfw`, `underagensfw`, the `/childnsfw/` URL
/// segment, `explicitchild` and `explicitteen` reachable; whole-token matching
/// on either word left all ten to walk through. Both carry a dictionary check
/// of their own, and both come back clean: across the 235,976 entries of
/// `/usr/share/dict/words`, ZERO tokens contain `nsfw` anywhere, and ZERO
/// tokens contain `explicit` together with any [`MINOR_STEMS`] entry — the ten
/// dictionary words that contain `explicit` at all are `explicit`,
/// `explicitly`, `explicitness`, `inexplicit`, `inexplicitly`,
/// `inexplicitness`, `superexplicit`, `unexplicit`, `unexplicitly` and
/// `unexplicitness`, none of which carries a minor stem. The same sweep finds
/// ZERO dictionary tokens carrying a stem from BOTH lists, which is the
/// safety argument for mode 3 as a whole.
///
/// `explicit` is here and NOT in [`SEXUAL_HEAD_STEMS`]. In this list it can
/// only fire beside a minor stem in the same token — `explicitchild` — which no
/// dictionary word is; as a head stem it would put `explicitly` back into the
/// sexual side of the AND and undo the shed that this whole split exists for.
pub(super) const SEXUAL_STEMS: &[&str] = &[
    "sex", "sext", PORN_STEM, "nude", "erotic", CSAM_STEM, NSFW_STEM, "explicit",
];

/// Mode 4. A token that BEGINS with one of these and carries more after it is a
/// sexual term on its own.
///
/// Head position is the safety argument, and it is structural rather than a
/// matter of taste: benign words bury these stems at the END (`unisex`,
/// `Essex`, `sclerotic`), orientation words bury them behind a modifier
/// (`homosexual`, `intersex`), and sexual compounds put them FIRST (`sextape`,
/// `sextortion`, `sexcam`, `nudephotos`, `eroticist`). Every hit is therefore
/// also a hit of the substring matcher this replaced, so the rule can widen
/// nothing.
///
/// `sext` is subsumed by `sex`. `porn`, `nsfw` and `csam` need no entry: they
/// match raw in any position.
pub(super) const SEXUAL_HEAD_STEMS: &[&str] = &["sex", "nude", "erotic"];

/// NCII needles, matched as raw substrings of the normalized text (mode 5).
///
/// A previous revision anchored these to token boundaries and lost
/// `unleaked nude photos of her` and `nonrevenge porn` — both blocked by the
/// matcher this replaced. Nothing was bought for that. Every entry is a
/// multi-word phrase, so no single dictionary token can carry one, and the only
/// dictionary continuations of these particular tails are `nudely`, `nudeness`,
/// `nudens`, `intimately`, `intimateness`, `intimater` and the `porn-` family
/// itself — nothing that turns a benign sentence into a hit. The crime list
/// does have real collisions of this shape; the module doc's mode-5 section
/// names them, and they are inherited from the old matcher rather than
/// introduced here.
///
/// The `revenge porn` family needs no separate tail-open list any more, because
/// under mode 5 every needle is open at both ends and `revenge pornography`
/// falls out for free.
pub(super) const NCII_TERMS: &[&str] = &[
    "non consensual intimate",
    "nonconsensual intimate",
    "leaked nude",
    "leaked nudes",
    "deepfake nude",
    "deepfake nudes",
    "revenge porn",
];

/// Serious-crime needles, matched as raw substrings of the normalized text
/// (mode 5), for the reason [`NCII_TERMS`] gives.
///
/// Inflection is free under mode 5 — `terrorist attack` reaches
/// `the terrorist attacked the embassy` and `mass harm` reaches
/// `mass harming of civilians`, both of which token anchoring dropped. The verb
/// and plural forms are spelled out anyway, because substring reach only helps
/// where the shorter form is a prefix: `make a bomb` is not inside
/// `making a bomb`, and no amount of open-endedness makes it so. Seventeen of
/// these entries are content the old matcher let through; the module doc counts
/// them and a test enumerates them.
pub(super) const SERIOUS_CRIME_TERMS: &[&str] = &[
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
        // Mode 5 for both: raw substring, no token anchoring at either end.
        HostedLegalCategory::Ncii => contains_any_substring(normalized, NCII_TERMS),
        HostedLegalCategory::SeriousCrime => {
            contains_any_substring(normalized, SERIOUS_CRIME_TERMS)
        }
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

/// All four modes, in the order that decides fastest.
fn is_minor_sexualization(normalized: &str) -> bool {
    normalized.contains(CSAM_STEM)
        || some_token_pairs_both_stems(normalized)
        || (contains_any(normalized, MINOR_TERMS) && contains_sexual_term(normalized))
}

/// Mode 1 for the ambiguous words, mode 2 for the `porn` and `nsfw` families,
/// mode 4 for a compound that leads with a sexual stem.
fn contains_sexual_term(normalized: &str) -> bool {
    contains_any(normalized, SEXUAL_TERMS)
        || contains_any_substring(normalized, SUBSTRING_SAFE_SEXUAL_STEMS)
        || some_token_heads_a_sexual_stem(normalized)
}

/// Mode 3. One token carrying a stem from each list is a closed compound like
/// `childporn`, and is a hit on its own.
fn some_token_pairs_both_stems(normalized: &str) -> bool {
    normalized.split_ascii_whitespace().any(|token| {
        contains_any_substring(token, MINOR_STEMS) && contains_any_substring(token, SEXUAL_STEMS)
    })
}

/// Mode 4. A token that leads with a sexual stem and carries more after it —
/// `sextape`, `sextortion`, `nudephotos`, `eroticist`. Equal-length tokens are
/// excluded because the bare stem is already a listed word.
fn some_token_heads_a_sexual_stem(normalized: &str) -> bool {
    normalized.split_ascii_whitespace().any(|token| {
        SEXUAL_HEAD_STEMS
            .iter()
            .any(|stem| token.len() > stem.len() && token.starts_with(stem))
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
