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
//! stop a deliberate paraphrase, and it refuses an ask *about* a credential
//! too ("Rotate the API key?"): such an ask names the credential by its
//! custody name instead.
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
/// A phrase matches a run of whole words in the text. Words are split at
/// every character that is not a letter or a digit, so `one-time code`,
/// `api_key` and `API key` are all two or three words, and `pinned` or
/// `opinion` never matches `pin`. A phrase word compares without case, except
/// a word written here with a capital letter, which matches only as written:
/// `PIN` is the acronym, and the verb in "Pin this message?" passes. The last
/// word of a phrase also matches its plural in `s` (`API keys`, `PINs`).
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
        phrases: &[&["PIN"], &["pin", "code"], &["pin", "number"]],
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

/// The suggestion every refusal carries: the way a secret is asked for.
const CUSTODY_WAY: &str = "Ask for this through custody (vault secrets), not in a question.";

/// The first secret value kind `text` names, if any.
fn named_secret_kind(text: &str) -> Option<&'static AskSecretValueKind> {
    let words: Vec<&str> = text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .collect();
    ASK_SECRET_VALUE_KINDS.iter().find(|kind| {
        kind.phrases.iter().any(|phrase| {
            words
                .windows(phrase.len())
                .any(|run| phrase_matches(phrase, run))
        })
    })
}

/// `run` is `phrase`, word for word; its last word may be a plural in `s`.
fn phrase_matches(phrase: &[&str], run: &[&str]) -> bool {
    let last = phrase.len() - 1;
    phrase
        .iter()
        .zip(run)
        .enumerate()
        .all(|(at, (want, word))| {
            word_matches(want, word)
                || (at == last
                    && word
                        .strip_suffix(['s', 'S'])
                        .is_some_and(|stem| word_matches(want, stem)))
        })
}

/// A capitalised list word matches only as written; any other without case.
fn word_matches(want: &str, word: &str) -> bool {
    if want.chars().any(char::is_uppercase) {
        want == word
    } else {
        want.eq_ignore_ascii_case(word)
    }
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
