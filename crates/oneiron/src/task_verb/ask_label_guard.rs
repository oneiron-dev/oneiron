//! The ask door's secret-kind guard on caller-written ask text (FIX-LIST
//! ASK-LABEL-SOLICITS-SECRET; RULING ASK-LABEL-SOLICITS-SECRET = A, scope A2).
//!
//! Canon ARCH-0028 #mcp-tasks (owner ruling ONEIRON-MCP-TASKS = AB): "Forms
//! never ask for secrets. No form asks for a key, password, token or payment
//! credential. Secrets go through custody." An answer is a choice among
//! option ids, so an ask whose text names a secret value kind can still
//! collect one: "Select digit 1 of your payment PIN" with options `d0`..`d9`.
//! This guard refuses such an ask at admission, on every surface it reaches
//! (inbox, `tasks.answer`, an option link, an MCP task form).
//!
//! It runs on the asks a caller writes: [`Memory::tasks_ask`] (the `tasks.ask`
//! verb and a code run's `tasks.ask` self-call) and the `can(ask)` preflight
//! [`Memory::tasks_can_ask`]. Asks the engine composes keep their labels.
//!
//! A word check stops the plain and the injected solicitation. It does not
//! stop a deliberate paraphrase. It refuses an ask *about* a credential too
//! ("Rotate the API key?"), and one that uses a listed word in another sense
//! ("Pin this message?"): such an ask names the credential by its custody
//! name, or says it in other words.
//!
//! [`Memory::tasks_ask`]: crate::memory::Memory::tasks_ask
//! [`Memory::tasks_can_ask`]: crate::memory::Memory::tasks_can_ask

use super::ask_types::TaskAskSpec;
use crate::memory::{MemoryError, MemoryResult};

/// One secret value kind an ask may not name: the name a refusal gives it,
/// and the word runs that name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AskSecretValueKind {
    /// The kind as a refusal names it.
    name: &'static str,
    /// Each run of words that names the kind.
    phrases: &'static [&'static [&'static str]],
}

/// Every secret value kind the guard refuses, in one list. The test
/// `crates/oneiron/tests/ask_label_secret_kind.rs` asks with every phrase.
///
/// A phrase matches its words in order in the text, each compared without
/// case. Words are split at every character that is not a letter or a digit,
/// so `one-time code`, `api_key` and `API key` are all two or three words, and
/// `pinned` or `opinion` never matches `pin`; the lone `s` a possessive leaves
/// (`card's`) is dropped. Up to [`MAX_QUALIFIER_WORDS`] other words may stand
/// between two words of a phrase (`private SSH key`, `one-time login code`),
/// unless one of them is in [`FUNCTION_WORDS`]: "Run verification on the
/// code?" names no one-time code. The last word of a phrase also matches its
/// plural in `s` (`API keys`, `PINs`).
const ASK_SECRET_VALUE_KINDS: &[AskSecretValueKind] = &[
    AskSecretValueKind {
        name: "password",
        phrases: &[&["password"]],
    },
    AskSecretValueKind {
        name: "passcode",
        phrases: &[&["passcode"]],
    },
    AskSecretValueKind {
        name: "passphrase",
        phrases: &[&["passphrase"]],
    },
    AskSecretValueKind {
        name: "PIN",
        phrases: &[&["pin"]],
    },
    AskSecretValueKind {
        name: "one-time code",
        phrases: &[
            &["one", "time", "code"],
            &["otp"],
            &["verification", "code"],
            &["2fa", "code"],
            &["mfa", "code"],
        ],
    },
    AskSecretValueKind {
        name: "card security code",
        phrases: &[&["cvv"], &["cvc"], &["card", "security", "code"]],
    },
    AskSecretValueKind {
        name: "card number",
        phrases: &[&["card", "number"]],
    },
    AskSecretValueKind {
        name: "seed or recovery phrase",
        phrases: &[&["seed", "phrase"], &["recovery", "phrase"]],
    },
    AskSecretValueKind {
        name: "private key",
        phrases: &[&["private", "key"]],
    },
    AskSecretValueKind {
        name: "API key",
        phrases: &[&["api", "key"], &["apikey"]],
    },
    AskSecretValueKind {
        name: "access token",
        phrases: &[&["access", "token"]],
    },
    AskSecretValueKind {
        name: "secret key",
        phrases: &[&["secret", "key"]],
    },
];

/// How many qualifier words may stand between two words of a phrase.
const MAX_QUALIFIER_WORDS: usize = 2;

/// Words that end a phrase's run when they stand between two of its words:
/// a qualifier is a name or an adjective, never one of these.
const FUNCTION_WORDS: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "can", "do", "does", "for", "from",
    "has", "have", "he", "her", "his", "i", "if", "in", "into", "is", "it", "its", "me", "my",
    "no", "not", "of", "on", "or", "our", "she", "so", "than", "that", "the", "their", "them",
    "then", "they", "this", "to", "us", "was", "we", "were", "what", "when", "which", "who",
    "will", "with", "you", "your",
];

/// The suggestion every refusal carries: the way a secret is asked for.
const CUSTODY_WAY: &str = "Ask for this through custody (vault secrets), not in a question.";

/// The first secret value kind `text` names, if any.
fn named_secret_kind(text: &str) -> Option<&'static AskSecretValueKind> {
    let words: Vec<&str> = text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty() && !word.eq_ignore_ascii_case("s"))
        .collect();
    ASK_SECRET_VALUE_KINDS.iter().find(|kind| {
        kind.phrases
            .iter()
            .any(|phrase| (0..words.len()).any(|start| phrase_starts(phrase, &words[start..])))
    })
}

/// `phrase` starts at the first of `words` and goes on in order, each later
/// phrase word after at most [`MAX_QUALIFIER_WORDS`] qualifier words.
fn phrase_starts(phrase: &[&str], words: &[&str]) -> bool {
    let (Some((want, rest)), Some((word, after))) = (phrase.split_first(), words.split_first())
    else {
        return false;
    };
    if !word_names(want, word, rest.is_empty()) {
        return false;
    }
    rest.is_empty()
        || (0..=MAX_QUALIFIER_WORDS.min(after.len())).any(|skip| {
            after[..skip].iter().all(|word| !is_function_word(word))
                && phrase_starts(rest, &after[skip..])
        })
}

/// `word` is the list word `want`, without case; the last word of a phrase
/// may also stand as its plural in `s`.
fn word_names(want: &str, word: &str, last: bool) -> bool {
    want.eq_ignore_ascii_case(word)
        || (last
            && word
                .strip_suffix(['s', 'S'])
                .is_some_and(|stem| want.eq_ignore_ascii_case(stem)))
}

/// `word` is one of [`FUNCTION_WORDS`], without case.
fn is_function_word(word: &str) -> bool {
    FUNCTION_WORDS
        .iter()
        .any(|function| function.eq_ignore_ascii_case(word))
}

/// Refuses `text` (the ask's `field`) when it names a secret value kind.
fn check_text(field: &str, text: &str) -> MemoryResult<()> {
    match named_secret_kind(text) {
        Some(kind) => Err(MemoryError::bad_request_with(
            format!(
                "ask {field} names a secret value ({}); an ask never asks for a secret",
                kind.name
            ),
            &[CUSTODY_WAY],
        )),
        None => Ok(()),
    }
}

impl TaskAskSpec {
    /// Refuses a caller-written ask whose question label, option labels,
    /// option consequences (`then`) or recommendation reason names a secret
    /// value kind ([`ASK_SECRET_VALUE_KINDS`]). Each of these texts reaches
    /// the person asked. Kept and replicated asks are not re-checked.
    pub(in crate::task_verb) fn check_secret_kinds(&self) -> MemoryResult<()> {
        if let Some(label) = &self.what.label {
            check_text("question label", label)?;
        }
        for (id, option) in &self.what.options {
            check_text(&format!("option `{}` label", id.as_str()), &option.label)?;
            if let Some(then) = &option.then {
                check_text(&format!("option `{}` then", id.as_str()), then)?;
            }
        }
        if let Some(rec) = &self.rec {
            check_text("recommendation reason", &rec.why)?;
        }
        Ok(())
    }
}
