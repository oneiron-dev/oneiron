//! The calendar safeguard's pattern head (FIX 12099): a deterministic
//! [`LabelClassifier`] that scores the screen's two labels from plain text
//! patterns, with no model behind it. Each class of signal it finds in a
//! text (an instruction override or a chat-template marker, words addressed
//! to an AI assistant, a tool or URL call, a credential ask, hidden text)
//! adds its weight, and the classes combine as independent evidence. Its
//! pin names it [`PATTERN_HEAD_MODEL`], so every screen record it feeds says
//! a pattern head, not a model, produced the verdict.

use std::ops::RangeInclusive;

use oneiron::llm::decision::{DecisionRung, LabelClassifier, ProviderPin};

use super::safeguard::{SCREEN_LABELS, SCREEN_QUESTION};

/// The model id the head's pin carries, and with it every screen record the
/// head feeds.
const PATTERN_HEAD_MODEL: &str = "heuristic-v1";

/// The weight one class of signal adds when found: alone, the probability
/// that the text addresses an assistant with instructions. Classes combine
/// as `1 - Π(1 - weight)`, so against the default decision band
/// (0.35..0.65) one class alone reads as uncertain and two as instructions.
const SIGNAL_WEIGHT: f64 = 0.45;

/// The weight of an instruction override, a concealment ask or a
/// chat-template marker, which alone reads as instructions.
const OVERRIDE_WEIGHT: f64 = 0.9;

/// Verbs that set an assistant's instructions aside.
const OVERRIDE_VERBS: &[&str] = &["ignore", "disregard", "forget", "override", "bypass"];

/// What an override verb sets aside.
const OVERRIDE_OBJECTS: &[&str] = &[
    "instructions",
    "instruction",
    "prompt",
    "prompts",
    "directives",
    "system message",
    "guardrails",
];

/// How many words after an override verb its object may start: "ignore all
/// of the previous instructions".
const OVERRIDE_WINDOW: usize = 5;

/// Phrases that ask to keep an act from the person an assistant serves.
const CONCEALMENT_LEADS: &[&str] = &[
    "do not tell",
    "don't tell",
    "never tell",
    "do not inform",
    "don't inform",
    "do not let",
    "don't let",
    "do not mention",
    "don't mention",
    "never mention",
    "without telling",
    "without informing",
    "hide this from",
    "keep this from",
];

/// Who a concealment ask keeps the act from.
const CONCEALMENT_OBJECTS: &[&str] = &["user", "human"];

/// How many words after a concealment lead its object may start: "do not
/// tell the user".
const CONCEALMENT_WINDOW: usize = 4;

/// Chat-template and role markers, matched with whitespace removed.
const TEMPLATE_MARKERS: &[&str] = &[
    "<|im_start|>",
    "<|im_end|>",
    "<|system|>",
    "<|user|>",
    "<|assistant|>",
    "[inst]",
    "[/inst]",
    "<<sys>>",
    "###instruction",
    "###system",
    "<system>",
    "</system>",
];

/// Phrases that address an AI assistant or speak of its prompt.
const ASSISTANT_PHRASES: &[&str] = &[
    "ai assistant",
    "ai agent",
    "language model",
    "llm",
    "chatgpt",
    "dear assistant",
    "hey assistant",
    "hello assistant",
    "hi assistant",
    "dear ai",
    "hey ai",
    "attention ai",
    "note to ai",
    "note to the ai",
    "note to the assistant",
    "you are an ai",
    "as an ai",
    "if you are an ai",
    "system prompt",
    "developer mode",
    "jailbreak",
];

/// Phrases that ask for a tool call, a command or a bulk send.
const TOOL_CALL_PHRASES: &[&str] = &[
    "call the tool",
    "use the tool",
    "use your tools",
    "invoke the tool",
    "tool call",
    "function call",
    "run the command",
    "run this command",
    "run the following",
    "execute the command",
    "execute this command",
    "execute the following",
    "send a request to",
    "make a request to",
    "send the contents",
    "forward all emails",
    "forward all messages",
    "forward all files",
    "forward every email",
    "exfiltrate",
];

/// Verbs that call a URL rather than mention it.
const URL_CALL_VERBS: &[&str] = &["fetch", "curl", "wget", "navigate"];

/// The words a URL's scheme reads as.
const URL_SCHEMES: &[&str] = &["http", "https"];

/// How many words after a URL-call verb the URL may start: "curl -s
/// https://".
const URL_CALL_WINDOW: usize = 3;

/// Verbs that ask for something to be handed over.
const CREDENTIAL_ASK_VERBS: &[&str] = &[
    "send", "share", "provide", "give", "reply", "forward", "paste", "enter", "type", "tell",
    "include", "reveal", "disclose", "submit", "email", "post",
];

/// Credentials an ask may name.
const CREDENTIAL_PHRASES: &[&str] = &[
    "password",
    "passwords",
    "api key",
    "api keys",
    "access token",
    "auth token",
    "bearer token",
    "session token",
    "session cookie",
    "secret key",
    "private key",
    "ssh key",
    "seed phrase",
    "recovery phrase",
    "recovery code",
    "recovery codes",
    "backup codes",
    "2fa code",
    "one time code",
    "verification code",
    "otp",
    "credentials",
    "login details",
];

/// How many words after an ask verb the credential may start: "send me
/// your api key".
const CREDENTIAL_WINDOW: usize = 5;

/// Markup that hides text from a reader, matched with whitespace removed.
const HIDDEN_MARKUP: &[&str] = &[
    "<!--",
    "display:none",
    "visibility:hidden",
    "font-size:0;",
    "font-size:0px",
    "font-size:0\"",
    "font-size:0'",
    "opacity:0;",
    "opacity:0\"",
    "color:transparent",
    "mso-hide:all",
];

/// Characters that render as nothing or reorder what renders: the
/// zero-width space, the word joiner and invisible operators, a zero-width
/// no-break space past the text's start, and bidirectional embeddings,
/// overrides and isolates.
const HIDDEN_CHARACTERS: &[RangeInclusive<char>] = &[
    '\u{200B}'..='\u{200B}',
    '\u{2060}'..='\u{2064}',
    '\u{FEFF}'..='\u{FEFF}',
    '\u{202A}'..='\u{202E}',
    '\u{2066}'..='\u{2069}',
];

/// Unicode tag characters: invisible, and able to spell out text.
const TAG_CHARACTERS: RangeInclusive<char> = '\u{E0000}'..='\u{E007F}';

/// The black flag a subdivision flag's tag sequence follows.
const FLAG_BASE: char = '\u{1F3F4}';

/// The longest tag run a subdivision flag carries ("gbsct" and its cancel
/// tag, with room to spare); a longer run spells hidden text.
const FLAG_TAG_RUN_MAX: usize = 7;

/// A deterministic pattern head for the calendar safeguard's question and
/// labels. It answers no other question and scores no other label.
pub(crate) struct PatternLabelHead;

impl LabelClassifier for PatternLabelHead {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Local,
            model: PATTERN_HEAD_MODEL.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    /// The flagged label scores the text's combined signal weight and the
    /// ordinary label its complement.
    fn scores(&self, question: &str, unit: &str, labels: &[String]) -> oneiron::Result<Vec<f64>> {
        if question != SCREEN_QUESTION {
            return Err(oneiron::Error::InvalidConfig(
                "the calendar pattern head answers only the calendar screen question".into(),
            ));
        }
        let instructions = instructions_score(unit);
        labels
            .iter()
            .map(|label| {
                if label.as_str() == SCREEN_LABELS[0] {
                    Ok(instructions)
                } else if label.as_str() == SCREEN_LABELS[1] {
                    Ok(1.0 - instructions)
                } else {
                    Err(oneiron::Error::InvalidConfig(format!(
                        "the calendar pattern head scores no label {label:?}"
                    )))
                }
            })
            .collect()
    }
}

/// The probability, from the text's patterns, that it addresses an AI
/// assistant with instructions.
fn instructions_score(text: &str) -> f64 {
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    let lower = text.to_lowercase().replace('\u{2019}', "'");
    let words: Vec<&str> = lower
        .split(|c: char| !(c.is_alphanumeric() || c == '\''))
        .filter(|word| !word.is_empty())
        .collect();
    let compact: String = lower.chars().filter(|c| !c.is_whitespace()).collect();
    let signals = [
        (
            has_phrase_pair(&words, OVERRIDE_VERBS, OVERRIDE_OBJECTS, OVERRIDE_WINDOW)
                || has_phrase_pair(
                    &words,
                    CONCEALMENT_LEADS,
                    CONCEALMENT_OBJECTS,
                    CONCEALMENT_WINDOW,
                )
                || TEMPLATE_MARKERS
                    .iter()
                    .any(|marker| compact.contains(marker)),
            OVERRIDE_WEIGHT,
        ),
        (has_phrase(&words, ASSISTANT_PHRASES), SIGNAL_WEIGHT),
        (
            has_phrase(&words, TOOL_CALL_PHRASES)
                || has_phrase_pair(&words, URL_CALL_VERBS, URL_SCHEMES, URL_CALL_WINDOW),
            SIGNAL_WEIGHT,
        ),
        (
            has_phrase_pair(
                &words,
                CREDENTIAL_ASK_VERBS,
                CREDENTIAL_PHRASES,
                CREDENTIAL_WINDOW,
            ),
            SIGNAL_WEIGHT,
        ),
        (
            has_hidden_characters(text)
                || HIDDEN_MARKUP.iter().any(|marker| compact.contains(marker)),
            SIGNAL_WEIGHT,
        ),
    ];
    1.0 - signals
        .iter()
        .filter(|(found, _)| *found)
        .map(|(_, weight)| 1.0 - weight)
        .product::<f64>()
}

/// Whether `phrase`'s words occur in `words` in order, starting at `at`.
fn phrase_at(words: &[&str], at: usize, phrase: &str) -> bool {
    phrase
        .split_whitespace()
        .enumerate()
        .all(|(offset, part)| words.get(at + offset) == Some(&part))
}

/// Whether any of `phrases` occurs in `words`.
fn has_phrase(words: &[&str], phrases: &[&str]) -> bool {
    (0..words.len()).any(|at| phrases.iter().any(|phrase| phrase_at(words, at, phrase)))
}

/// Whether a phrase of `leads` is followed, starting within `window` words
/// of its end, by a phrase of `objects`.
fn has_phrase_pair(words: &[&str], leads: &[&str], objects: &[&str], window: usize) -> bool {
    (0..words.len()).any(|at| {
        leads.iter().any(|lead| {
            let end = at + lead.split_whitespace().count();
            phrase_at(words, at, lead)
                && (end..end + window)
                    .any(|start| objects.iter().any(|object| phrase_at(words, start, object)))
        })
    })
}

/// Whether `text` carries a hidden character, or a run of tag characters
/// that is not a subdivision flag's.
fn has_hidden_characters(text: &str) -> bool {
    let mut previous = None;
    let mut tag_run = 0;
    let mut run_follows_flag = false;
    for c in text.chars() {
        if TAG_CHARACTERS.contains(&c) {
            if tag_run == 0 {
                run_follows_flag = previous == Some(FLAG_BASE);
            }
            tag_run += 1;
            if !run_follows_flag || tag_run > FLAG_TAG_RUN_MAX {
                return true;
            }
        } else {
            tag_run = 0;
            if HIDDEN_CHARACTERS.iter().any(|range| range.contains(&c)) {
                return true;
            }
        }
        previous = Some(c);
    }
    false
}
