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
    use super::{SecretCustody, bare_handle};
    use crate::secret_fields::secret_compare_policy;
    use crate::{BrowserError, SecretKind, SecretNote};
    use std::collections::HashMap;
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
        /// handle it took then.
        pub(crate) fn acquire(
            &self,
            kind: SecretKind,
            value: &str,
            origin: &str,
        ) -> Result<String, SecretNote> {
            let (custody, print) = {
                let mut held = self.held();
                let key = *held.key.get_or_insert_with(memo_key);
                let print = *blake3::keyed_hash(&key, value.as_bytes()).as_bytes();
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
        /// holds to `use_`, through the host's custody.
        pub(crate) fn with_value(
            &self,
            named: &str,
            use_: &mut dyn FnMut(&str) -> Result<(), BrowserError>,
        ) -> Result<(), BrowserError> {
            let handle = bare_handle(named);
            let custody = self.custody().ok_or_else(|| {
                BrowserError::SecretRefused(format!(
                    "this browser's host keeps no secrets, so {handle} names none"
                ))
            })?;
            custody.with_value(handle, use_)
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
                    self.with_value(named, &mut |held: &str| {
                        met = secret_compare_policy(kind, held, page);
                        Ok(())
                    })?;
                    Ok(met)
                }
            }
        }
    }
}
