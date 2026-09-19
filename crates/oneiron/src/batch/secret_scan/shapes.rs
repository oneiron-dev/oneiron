//! Credential-shape detection shared by write, serve, and export.

use super::wordlist::WORDS;
const BLOCKLIST: &str = include_str!("blocklist.txt");

pub(super) fn blocklisted(text: &str) -> bool {
    BLOCKLIST
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .any(|entry| text.contains(entry))
}

pub(super) fn mnemonic(text: &str) -> bool {
    // BIP39 phrases have an exact word count. Do not treat an arbitrarily long
    // repetition of a dictionary word as a wallet. Seed-labelled fields are
    // separately refused even when incomplete or misspelled.
    let shaped = |count| matches!(count, 12 | 15 | 18 | 21 | 24);
    let mut run = 0;
    for word in text.split(|c: char| !c.is_ascii_alphabetic()) {
        if word.is_empty() {
            continue;
        }
        let lower = word.to_ascii_lowercase();
        if WORDS.binary_search(&lower.as_str()).is_ok() {
            run += 1;
        } else {
            if shaped(run) {
                return true;
            }
            run = 0;
        }
    }
    shaped(run)
}

pub(super) fn sensitive_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace(['-', '.'], "_");
    matches!(
        normalized.as_str(),
        "password"
            | "passwd"
            | "pwd"
            | "secret"
            | "token"
            | "api_key"
            | "apikey"
            | "private_key"
            | "client_secret"
            | "access_token"
            | "refresh_token"
            | "authorization"
            | "mnemonic"
            | "seed_phrase"
    ) || [
        "_password",
        "_passwd",
        "_secret",
        "_token",
        "_api_key",
        "_private_key",
        "_access_key",
    ]
    .iter()
    .any(|suffix| normalized.ends_with(suffix))
}

pub(super) fn placeholder(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "[redacted]" | "[secret redacted]" | "<redacted>" | "null"
    )
}

pub(super) fn sensitive_assignment(text: &str) -> bool {
    // Assignment syntax covers dotenv, shell, JSON and YAML. Structural
    // MessagePack fields are checked separately at the payload door.
    text.split(['\n', '\r', ',', ';', '{', '}']).any(|line| {
        let Some((key, value)) = line.split_once(['=', ':']) else {
            return false;
        };
        let key = key
            .trim()
            .trim_start_matches("export ")
            .trim()
            .trim_matches(['\"', '\'']);
        let value = value.trim().trim_matches(['\"', '\'']);
        sensitive_key(key) && !placeholder(value)
    })
}
