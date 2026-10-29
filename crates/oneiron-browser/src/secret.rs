//! The host's secret custody, as a browser or desktop session holds it
//! (FIX 8028, OF-560; ARCH-0069). A secret field a read finds becomes a
//! handle where it is found: the session hands its original bytes to the
//! host's [`SecretCustody`] before any row is built, and the row shows the
//! handle. A type or expect that names a handle as its `secret` asks the
//! host for the bytes at the send or the comparison itself, and never
//! holds them past it. A session whose host gave no custody, or whose host
//! refused a value, shows `[secret]` with a typed note, never the value.

use crate::{BrowserError, SecretKind};

/// The host's custody of the secrets a run's browser finds: it takes each
/// one where it is found, bound to that run, and lends its bytes back only
/// to that run's own type and expect.
pub trait SecretCustody: Send + Sync {
    /// Takes `value`, a secret of `kind` the run's page or window at
    /// `origin` shows, into custody bound to the run: the handle (`scN`)
    /// its row shows. The same value of the same kind in the same run
    /// answers the same handle.
    fn acquire(&self, kind: SecretKind, value: &str, origin: &str) -> Result<String, BrowserError>;

    /// Lends the bytes `handle` holds to `use_`, the session's own send or
    /// comparison, once: a handle this run does not hold is refused.
    fn with_value(
        &self,
        handle: &str,
        use_: &mut dyn FnMut(&str) -> Result<(), BrowserError>,
    ) -> Result<(), BrowserError>;

    /// Lends the bytes `handle` holds to `use_` for `operation`, the
    /// session's own type or expect, once (FIX 8342): the host's use record
    /// names which. The default lends them as [`Self::with_value`] does.
    fn with_value_as(
        &self,
        handle: &str,
        operation: SecretUse,
        use_: &mut dyn FnMut(&str) -> Result<(), BrowserError>,
    ) -> Result<(), BrowserError> {
        let _ = operation;
        self.with_value(handle, use_)
    }
}

/// What a session asks a secret's bytes for (FIX 8342): a type sends them
/// into a field; an expect compares them with what the page holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretUse {
    Type,
    Expect,
}

impl SecretUse {
    /// The operation's word in a use record.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Type => "type",
            Self::Expect => "expect",
        }
    }
}

/// What a type enters: its literal text, or the bytes a secret handle
/// holds, asked for at the send.
#[cfg(feature = "driver")]
#[derive(Clone, Copy, Debug)]
pub(crate) enum Entry<'a> {
    Text(&'a str),
    Secret(&'a str),
}

/// The handle a type or expect names, as a row shows it (`[secret scN]`,
/// a card's `…1234 [secret scN]`) or bare (`scN`): bare.
#[cfg(feature = "driver")]
pub(crate) fn bare_handle(named: &str) -> &str {
    let named = named.trim();
    match named.split_once("[secret ") {
        Some((_, rest)) => rest
            .split_once(']')
            .map_or(rest, |(handle, _)| handle)
            .trim(),
        None => named,
    }
}

/// The entry exactly one of `text` and `secret` names.
#[cfg(feature = "driver")]
pub(crate) fn entry<'a>(
    text: Option<&'a str>,
    secret: Option<&'a str>,
) -> Result<Entry<'a>, BrowserError> {
    match (text, secret) {
        (Some(text), None) => Ok(Entry::Text(text)),
        (None, Some(secret)) => Ok(Entry::Secret(secret)),
        _ => Err(BrowserError::Input(
            "a type names exactly one of text and secret".to_owned(),
        )),
    }
}

#[cfg(feature = "driver")]
pub(crate) use held::Secrets;

#[cfg(feature = "driver")]
mod held {
    use super::{SecretCustody, SecretUse, bare_handle};
    use crate::secret_fields::{secret_compare_policy, secret_display_policy, secret_echo_policy};
    use crate::{BrowserError, SecretKind, SecretNote};
    use std::collections::{HashMap, HashSet};

    /// Every kind a session's reads take a value as.
    const KINDS: [SecretKind; 4] = [
        SecretKind::Card,
        SecretKind::Cvv,
        SecretKind::Otp,
        SecretKind::Password,
    ];
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

    /// A session's hold on its host's custody, shared with every driver
    /// it attaches (an engine switch's target among them), and the kind of
    /// each handle a read of the session's took.
    #[derive(Clone, Default)]
    pub(crate) struct Secrets(Arc<Mutex<Held>>);

    #[derive(Default)]
    struct Held {
        custody: Option<Arc<dyn SecretCustody>>,
        kinds: HashMap<String, SecretKind>,
        /// Each value the session's reads took, by its kind and a keyed
        /// hash of it, never the value: the handle it became, so a value a
        /// later read (a poll, a delta, the next call) shows again takes no
        /// second record (`secret_custody_reuse_policy`, CALLS row).
        taken: HashMap<(SecretKind, [u8; 32]), String>,
        /// The session's own key for those hashes, made at its first take.
        key: Option<[u8; 32]>,
    }

    /// A key no other session holds, for the hashes of what one session
    /// took: the process's random hasher keys, spread over 32 bytes.
    fn memo_key() -> [u8; 32] {
        use std::hash::BuildHasher;
        let state = std::collections::hash_map::RandomState::new();
        let mut key = [0u8; 32];
        for (at, chunk) in key.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&state.hash_one(at).to_le_bytes());
        }
        key
    }

    impl Secrets {
        fn held(&self) -> MutexGuard<'_, Held> {
            self.0.lock().unwrap_or_else(PoisonError::into_inner)
        }

        fn custody(&self) -> Option<Arc<dyn SecretCustody>> {
            self.held().custody.clone()
        }

        /// Gives the session its host's custody.
        pub(crate) fn install(&self, custody: Arc<dyn SecretCustody>) {
            self.held().custody = Some(custody);
        }

        /// A fresh guest's hold takes the proposing session's custody,
        /// where its host gave it none, the kinds of its handles, and, while
        /// it took none of its own, what the proposing session took: the
        /// replay is the same run, so a value both pages show is one handle.
        pub(crate) fn adopt(&self, from: &Self) {
            if Arc::ptr_eq(&self.0, &from.0) {
                return;
            }
            let (custody, kinds, key, taken) = {
                let from = from.held();
                (
                    from.custody.clone(),
                    from.kinds.clone(),
                    from.key,
                    from.taken.clone(),
                )
            };
            let mut held = self.held();
            if held.custody.is_none() {
                held.custody = custody;
            }
            for (handle, kind) in kinds {
                held.kinds.entry(handle).or_insert(kind);
            }
            if held.taken.is_empty() {
                held.key = key;
                held.taken = taken;
            }
        }

        /// Takes `value` into custody: its handle, or why there is none. A
        /// value of the same kind the session took before answers the
        /// handle it took then. A card number is filed by its digits, without
        /// single spaces or dashes (FIX 10333), so one printed either way
        /// takes one handle.
        pub(crate) fn acquire(
            &self,
            kind: SecretKind,
            value: &str,
            origin: &str,
        ) -> Result<String, SecretNote> {
            let (custody, print) = {
                let mut held = self.held();
                let key = *held.key.get_or_insert_with(memo_key);
                let print = if kind == SecretKind::Card {
                    let collapsed: String = value.chars().filter(char::is_ascii_digit).collect();
                    *blake3::keyed_hash(&key, collapsed.as_bytes()).as_bytes()
                } else {
                    *blake3::keyed_hash(&key, value.as_bytes()).as_bytes()
                };
                if let Some(handle) = held.taken.get(&(kind, print)) {
                    return Ok(handle.clone());
                }
                (held.custody.clone(), print)
            };
            let custody = custody.ok_or(SecretNote::NoCustody)?;
            let handle = custody
                .acquire(kind, value, origin)
                .map_err(|_| SecretNote::Refused)?;
            let mut held = self.held();
            held.kinds.insert(handle.clone(), kind);
            held.taken.insert((kind, print), handle.clone());
            Ok(handle)
        }

        /// Lends the bytes `named` (a handle, bare or as a row shows it)
        /// holds to `use_` for `operation`, through the host's custody.
        pub(crate) fn with_value(
            &self,
            named: &str,
            operation: SecretUse,
            use_: &mut dyn FnMut(&str) -> Result<(), BrowserError>,
        ) -> Result<(), BrowserError> {
            let handle = bare_handle(named);
            let custody = self.custody().ok_or_else(|| {
                BrowserError::SecretRefused(format!(
                    "this browser's host keeps no secrets, so {handle} names none"
                ))
            })?;
            custody.with_value_as(handle, operation, use_)
        }

        /// The secrets earlier reads of this session took that `text` shows
        /// again (FIX 8337, FIX 8338, FIX 8340), each with what shows in its
        /// place: the run-scoped matcher. Each whole token of `text` is
        /// hashed with the session's own key and looked up among the hashes
        /// the session already keeps of what it took; a card number printed
        /// with single spaces or dashes is collapsed to its digits first and
        /// matched among cards only (FIX 10333). No value is kept for it,
        /// and nothing this run's reads did not take is matched.
        pub(crate) fn known_in(&self, text: &str) -> Vec<(String, String)> {
            let held = self.held();
            let Some(key) = held.key.filter(|_| !held.taken.is_empty()) else {
                return Vec::new();
            };
            let mut found = Vec::new();
            for token in tokens(text) {
                let print = *blake3::keyed_hash(&key, token.as_bytes()).as_bytes();
                let named = KINDS
                    .iter()
                    .find_map(|kind| Some((*kind, held.taken.get(&(*kind, print))?)));
                if let Some((kind, handle)) = named {
                    let shown = secret_display_policy(kind, token, Some(handle.as_str()));
                    found.push((token.to_owned(), shown));
                }
            }
            for (original, collapsed) in card_spans(text) {
                let print = *blake3::keyed_hash(&key, collapsed.as_bytes()).as_bytes();
                if let Some(handle) = held.taken.get(&(SecretKind::Card, print)) {
                    let shown =
                        secret_display_policy(SecretKind::Card, original, Some(handle.as_str()));
                    found.push((original.to_owned(), shown));
                }
            }
            found
        }

        /// `text` with each secret an earlier read of this session took
        /// shown as its handle, or none where it shows none.
        pub(crate) fn mask_known(&self, text: &str) -> Option<String> {
            let known = self.known_in(text);
            let pairs: Vec<(&str, &str)> = known
                .iter()
                .map(|(secret, shown)| (secret.as_str(), shown.as_str()))
                .collect();
            secret_echo_policy(text, &pairs)
        }

        /// The kind of secret `handle` holds, when a read of this session
        /// took it.
        pub(crate) fn kind_of(&self, handle: &str) -> Option<SecretKind> {
            self.held().kinds.get(bare_handle(handle)).copied()
        }

        /// Whether a row holds what a check names: its `value`, matched
        /// against what the row shows (`shown`) or, where it shows a
        /// secret in place, what its page holds (`page`); or the secret a
        /// handle names (`secret`), compared with what the page holds
        /// through the host's custody, never answered. A check naming
        /// neither is met by the row alone.
        pub(crate) fn holds(
            &self,
            shown: Option<&str>,
            page: Option<&str>,
            value: Option<&str>,
            secret: Option<&str>,
        ) -> Result<bool, BrowserError> {
            match (value, secret) {
                (None, None) => Ok(true),
                (Some(want), _) => Ok(shown == Some(want) || page == Some(want)),
                (None, Some(named)) => {
                    let Some(page) = page.or(shown) else {
                        return Ok(false);
                    };
                    let kind = self.kind_of(named);
                    let mut met = false;
                    self.with_value(named, SecretUse::Expect, &mut |held: &str| {
                        met = secret_compare_policy(kind, held, page);
                        Ok(())
                    })?;
                    Ok(met)
                }
            }
        }
    }

    /// The whole tokens of `text` a secret may be: each run between blanks,
    /// that run without the punctuation prose puts around it, and each run
    /// of letters, digits and hyphens in it; each once.
    fn tokens(text: &str) -> Vec<&str> {
        let mut seen = HashSet::new();
        let mut tokens = Vec::new();
        for run in text.split_whitespace() {
            let bare = run.trim_matches(|c: char| ".,;:!?\"'()[]{}<>".contains(c));
            let parts = run
                .split(|c: char| !(c.is_alphanumeric() || c == '-'))
                .map(|part| part.trim_matches('-'));
            for token in [run, bare].into_iter().chain(parts) {
                if !token.is_empty() && seen.insert(token) {
                    tokens.push(token);
                }
            }
        }
        tokens
    }

    /// The card numbers `text` prints with single spaces or dashes, as each
    /// stands and collapsed to its digits (FIX 10333): each run of digit
    /// groups joined by single separators, each once. Only runs with a
    /// separator print here; whole tokens stay with [`tokens`].
    fn card_spans(text: &str) -> Vec<(&str, String)> {
        let bytes = text.as_bytes();
        let mut spans = Vec::new();
        let mut seen = HashSet::new();
        let mut i = 0;
        while i < bytes.len() {
            if !bytes[i].is_ascii_digit() {
                i += 1;
                continue;
            }
            let mut groups = Vec::new();
            let mut k = i;
            loop {
                let start = k;
                while k < bytes.len() && bytes[k].is_ascii_digit() {
                    k += 1;
                }
                groups.push((start, k));
                if k + 1 < bytes.len()
                    && (bytes[k] == b' ' || bytes[k] == b'-')
                    && bytes[k + 1].is_ascii_digit()
                {
                    k += 1;
                    continue;
                }
                break;
            }
            let end = groups.last().map_or(i, |(_, end)| *end);
            if groups.len() >= 2 {
                let before = text[..i].chars().next_back();
                let after = text[end..].chars().next();
                let edge = |side: Option<char>| side.is_none_or(|c| !c.is_alphanumeric());
                let before_ok = edge(before);
                let after_ok = edge(after);
                for a in 0..groups.len() {
                    let mut digits = 0;
                    for b in a..groups.len() {
                        digits += groups[b].1 - groups[b].0;
                        if b > a {
                            if (12..=19).contains(&digits) {
                                let ok_before = a > 0 || before_ok;
                                let ok_after = b + 1 < groups.len() || after_ok;
                                if ok_before && ok_after {
                                    let original = &text[groups[a].0..groups[b].1];
                                    if seen.insert(original) {
                                        let mut collapsed = String::with_capacity(digits);
                                        for group in &groups[a..=b] {
                                            collapsed.push_str(&text[group.0..group.1]);
                                        }
                                        spans.push((original, collapsed));
                                    }
                                }
                            }
                            if digits > 19 {
                                break;
                            }
                        }
                    }
                }
            }
            i = end.max(i + 1);
        }
        spans
    }
}
