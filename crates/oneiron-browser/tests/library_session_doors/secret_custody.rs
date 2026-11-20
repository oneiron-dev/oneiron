//! Records custody calls over fabricated fixture values.

use oneiron_browser::{BrowserError, SecretCustody, SecretKind};
use std::sync::{Arc, Mutex};

/// A custody call and its arguments, in the order the session made it.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum CustodyCall {
    Acquire {
        kind: SecretKind,
        value: String,
        origin: String,
    },
    WithValue(String),
}

/// Returns one fabricated binding and never lends its bytes back.
#[derive(Clone)]
pub(crate) struct CountingSecretCustody {
    binding: String,
    calls: Arc<Mutex<Vec<CustodyCall>>>,
}

impl CountingSecretCustody {
    /// Creates an empty call log and sets the binding to return on acquisition.
    pub(crate) fn new(binding: &str) -> Self {
        Self {
            binding: binding.to_owned(),
            calls: Arc::default(),
        }
    }

    /// Returns the whole custody call log.
    pub(crate) fn calls(&self) -> Vec<CustodyCall> {
        self.calls.lock().expect("custody log locks").clone()
    }
}

impl SecretCustody for CountingSecretCustody {
    fn acquire(&self, kind: SecretKind, value: &str, origin: &str) -> Result<String, BrowserError> {
        self.calls
            .lock()
            .expect("custody log locks")
            .push(CustodyCall::Acquire {
                kind,
                value: value.to_owned(),
                origin: origin.to_owned(),
            });
        Ok(self.binding.clone())
    }

    fn with_value(
        &self,
        handle: &str,
        _use_value: &mut dyn FnMut(&str) -> Result<(), BrowserError>,
    ) -> Result<(), BrowserError> {
        self.calls
            .lock()
            .expect("custody log locks")
            .push(CustodyCall::WithValue(handle.to_owned()));
        Err(BrowserError::SecretRefused(
            "fixture custody does not lend values".to_owned(),
        ))
    }
}
