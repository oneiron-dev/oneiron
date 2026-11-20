//! Records custody calls over fabricated fixture values.

use oneiron_browser::{BrowserError, SecretCustody, SecretKind};
use serde::Serialize;
use std::sync::{Arc, Mutex};

/// A custody call and its arguments, in the order the session made it.
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub(crate) enum CustodyCall {
    Acquire {
        kind: SecretKind,
        value: String,
        origin: String,
    },
    CheckedAcquire {
        kind: SecretKind,
        matches_expected: bool,
        origin: String,
    },
    WithValue(String),
}

/// Returns one fabricated binding and never lends its bytes back.
#[derive(Clone)]
pub(crate) struct RecordingSecretCustody {
    binding: String,
    expected_value: Option<String>,
    calls: Arc<Mutex<Vec<CustodyCall>>>,
}

impl RecordingSecretCustody {
    /// Creates an empty call log and sets the binding to return on acquisition.
    pub(crate) fn new(binding: &str) -> Self {
        Self {
            binding: binding.to_owned(),
            expected_value: None,
            calls: Arc::default(),
        }
    }

    /// Records whether an acquisition received this value, instead of copying the bytes.
    pub(crate) fn checking_value(mut self, expected_value: &str) -> Self {
        self.expected_value = Some(expected_value.to_owned());
        self
    }

    /// Returns the whole custody call log.
    pub(crate) fn calls(&self) -> Vec<CustodyCall> {
        self.calls.lock().expect("custody log locks").clone()
    }
}

impl SecretCustody for RecordingSecretCustody {
    fn acquire(&self, kind: SecretKind, value: &str, origin: &str) -> Result<String, BrowserError> {
        let origin = origin.to_owned();
        let call = match &self.expected_value {
            Some(expected) => CustodyCall::CheckedAcquire {
                kind,
                matches_expected: value == expected,
                origin,
            },
            None => CustodyCall::Acquire {
                kind,
                value: value.to_owned(),
                origin,
            },
        };
        self.calls.lock().expect("custody log locks").push(call);
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
