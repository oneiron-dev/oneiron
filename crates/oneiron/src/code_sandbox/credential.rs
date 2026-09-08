//! Opaque credential handles and the read-only credential call ABI.

use std::fmt;

use super::paths::SandboxVirtualPath;
use rmpv::Value;

use crate::{Error, Result};

const ABI_KEY_OPERATION: &str = "operation";

const ABI_KEY_CREDENTIAL_HANDLE: &str = "credentialHandle";

const ABI_KEY_ARGS: &str = "args";

/// Opaque credential reference passed through guest ABI instead of secret bytes.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SandboxCredentialHandle(String);

impl SandboxCredentialHandle {
    /// Creates an opaque credential handle.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidClaimBody`] when the handle is blank or contains
    /// control characters.
    pub fn new(handle: impl Into<String>) -> Result<Self> {
        let handle = handle.into();
        let trimmed = handle.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidClaimBody(
                "sandbox credential handle must not be blank",
            ));
        }
        if trimmed.chars().any(char::is_control) {
            return Err(Error::InvalidClaimBody(
                "sandbox credential handle contains control character",
            ));
        }
        Ok(Self(trimmed.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SandboxCredentialHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SandboxCredentialHandle")
            .field(&self.0)
            .finish()
    }
}

/// Effect class for credential-backed host operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxCredentialEffect {
    ReadOnly,
}

impl SandboxCredentialEffect {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
        }
    }
}

/// Typed operation name for a credential-backed, read-only host call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxCredentialOperation {
    name: String,
    effect: SandboxCredentialEffect,
}

impl SandboxCredentialOperation {
    /// Creates a read-only credential-backed operation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidClaimBody`] when the operation name is blank or
    /// contains control characters.
    pub fn read_only(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidClaimBody(
                "sandbox credential operation must not be blank",
            ));
        }
        if trimmed.chars().any(char::is_control) {
            return Err(Error::InvalidClaimBody(
                "sandbox credential operation contains control character",
            ));
        }
        Ok(Self {
            name: trimmed.to_owned(),
            effect: SandboxCredentialEffect::ReadOnly,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn effect(&self) -> SandboxCredentialEffect {
        self.effect
    }
}

/// Credential-backed host call from guest code.
#[derive(Debug, Clone, PartialEq)]
pub struct SandboxCredentialCall {
    pub(super) operation: SandboxCredentialOperation,
    pub(super) credential: SandboxCredentialHandle,
    args: Value,
}

impl SandboxCredentialCall {
    /// Creates a handle-only credential call for a read-only host operation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidClaimBody`] when the operation name is invalid.
    pub fn read_only(
        operation: impl Into<String>,
        credential: SandboxCredentialHandle,
        args: Value,
    ) -> Result<Self> {
        Ok(Self {
            operation: SandboxCredentialOperation::read_only(operation)?,
            credential,
            args,
        })
    }

    #[must_use]
    pub fn operation(&self) -> &SandboxCredentialOperation {
        &self.operation
    }

    #[must_use]
    pub fn credential(&self) -> &SandboxCredentialHandle {
        &self.credential
    }

    #[must_use]
    pub fn args(&self) -> &Value {
        &self.args
    }

    /// Guest ABI serialization for the call. It carries a credential handle,
    /// never credential material.
    #[must_use]
    pub fn guest_abi_value(&self) -> Value {
        Value::Map(vec![
            (
                Value::from(ABI_KEY_OPERATION),
                Value::from(self.operation.as_str().to_owned()),
            ),
            (
                Value::from(ABI_KEY_CREDENTIAL_HANDLE),
                Value::from(self.credential.as_str().to_owned()),
            ),
            (Value::from(ABI_KEY_ARGS), self.args.clone()),
        ])
    }
}

/// Host receipt for a credential-backed call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxCredentialOutcome {
    pub(super) operation: SandboxCredentialOperation,
    pub(super) credential: SandboxCredentialHandle,
}

impl SandboxCredentialOutcome {
    #[must_use]
    pub fn operation(&self) -> &SandboxCredentialOperation {
        &self.operation
    }

    #[must_use]
    pub fn credential(&self) -> &SandboxCredentialHandle {
        &self.credential
    }
}

/// Read-only file request from guest code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxReadFile {
    pub path: SandboxVirtualPath,
}

impl SandboxReadFile {
    #[must_use]
    pub const fn new(path: SandboxVirtualPath) -> Self {
        Self { path }
    }
}

/// Guest-visible file read result. The host path is intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxFileRead {
    pub path: SandboxVirtualPath,
    pub bytes: Vec<u8>,
}
