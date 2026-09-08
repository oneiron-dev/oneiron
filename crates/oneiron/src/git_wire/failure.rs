//! Failure taxonomy and redaction: classified git failures plus the two error-constructor helpers.

use super::record::hex_lower;
use super::{GitWireOperation, GitWireProcessOutput};
use crate::error::{Error, Result};

/// Result alias of every GitWire operation.
pub type GitWireResult<T> = Result<T>;

pub(super) fn invalid(message: &'static str) -> Error {
    Error::InvalidRepoMutationRecord(message)
}

pub(super) fn uncertain(message: String) -> Error {
    Error::RepoMutationFailed(message)
}

/// The classified cause of a git failure.
///
/// A class is the *only* thing a git child's diagnostics contribute to a
/// durable row or a propagated error: the raw text, which can carry a remote
/// URL, a credential, or an absolute path, never leaves this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitWireFailureClass {
    /// A ref could not be locked, or its lock file already existed.
    RefLocked,
    /// A compare-and-set saw a value other than the expected one.
    RefMismatch,
    /// A named object, ref, or revision does not exist.
    Missing,
    /// The object store or a ref store is damaged.
    Corrupt,
    /// The filesystem refused the operation.
    Permission,
    /// The working root is not a repository GitWire may drive.
    NotARepository,
    /// The child exceeded its runtime bound and was killed.
    Timeout,
    /// The child exceeded its output bound.
    OutputOverflow,
    /// The child was terminated by a signal.
    Signalled,
    /// Anything else. Always treated as uncertainty, never as absence.
    Unknown,
}

impl GitWireFailureClass {
    /// Stable wire name recorded on durable rows.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RefLocked => "ref_locked",
            Self::RefMismatch => "ref_mismatch",
            Self::Missing => "missing",
            Self::Corrupt => "corrupt",
            Self::Permission => "permission",
            Self::NotARepository => "not_a_repository",
            Self::Timeout => "timeout",
            Self::OutputOverflow => "output_overflow",
            Self::Signalled => "signalled",
            Self::Unknown => "unknown",
        }
    }

    pub(super) fn parse(value: &str) -> Result<Self> {
        const ALL: [GitWireFailureClass; 10] = [
            GitWireFailureClass::RefLocked,
            GitWireFailureClass::RefMismatch,
            GitWireFailureClass::Missing,
            GitWireFailureClass::Corrupt,
            GitWireFailureClass::Permission,
            GitWireFailureClass::NotARepository,
            GitWireFailureClass::Timeout,
            GitWireFailureClass::OutputOverflow,
            GitWireFailureClass::Signalled,
            GitWireFailureClass::Unknown,
        ];
        ALL.into_iter()
            .find(|class| class.as_str() == value)
            .ok_or_else(|| invalid("unknown git wire failure class"))
    }
}

/// Needle table used to classify a child's diagnostics. Matching happens on a
/// lowercased copy that is dropped immediately afterwards.
const GIT_WIRE_FAILURE_NEEDLES: [(&str, GitWireFailureClass); 16] = [
    ("but expected", GitWireFailureClass::RefMismatch),
    ("reference already exists", GitWireFailureClass::RefMismatch),
    ("unable to create", GitWireFailureClass::RefLocked),
    ("cannot lock ref", GitWireFailureClass::RefLocked),
    ("cannot lock the ref", GitWireFailureClass::RefLocked),
    ("unable to lock", GitWireFailureClass::RefLocked),
    ("permission denied", GitWireFailureClass::Permission),
    ("operation not permitted", GitWireFailureClass::Permission),
    ("read-only file system", GitWireFailureClass::Permission),
    ("not a git repository", GitWireFailureClass::NotARepository),
    ("object file is empty", GitWireFailureClass::Corrupt),
    ("loose object", GitWireFailureClass::Corrupt),
    ("corrupt", GitWireFailureClass::Corrupt),
    ("bad object", GitWireFailureClass::Corrupt),
    ("does not exist", GitWireFailureClass::Missing),
    ("unknown revision", GitWireFailureClass::Missing),
];

/// A git failure reduced to the facts that may safely be stored or propagated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GitWireFailure {
    class: GitWireFailureClass,
    exit_code: Option<i32>,
    diagnostics_digest: [u8; 32],
    diagnostics_len: usize,
}

impl GitWireFailure {
    /// The classified cause.
    pub const fn class(&self) -> GitWireFailureClass {
        self.class
    }

    /// Whether the failure leaves the repository in an unknown state, so the
    /// caller's recovery intent must be preserved rather than discarded.
    pub const fn is_uncertain(&self) -> bool {
        !matches!(self.class, GitWireFailureClass::RefMismatch)
    }

    /// The redacted description. It carries the operation, the class, the exit
    /// code, and a digest of the child's diagnostics — never their content.
    pub fn message(&self, operation: GitWireOperation) -> String {
        let digest = hex_lower(&self.diagnostics_digest);
        let short = &digest[..16];
        let class = self.class.as_str();
        let code = self.exit_code;
        let len = self.diagnostics_len;
        let name = operation.as_str();
        format!("git {name} failed: class={class} exit={code:?} diag=blake3:{short} bytes={len}")
    }

    pub(super) fn error(&self, operation: GitWireOperation) -> Error {
        uncertain(self.message(operation))
    }
}

pub(super) fn classify_failure(output: &GitWireProcessOutput) -> GitWireFailure {
    let class = if output.timed_out {
        GitWireFailureClass::Timeout
    } else if output.truncated {
        GitWireFailureClass::OutputOverflow
    } else if output.exit_code.is_none() {
        GitWireFailureClass::Signalled
    } else {
        classify_diagnostics(&output.stderr)
    };
    GitWireFailure {
        class,
        exit_code: output.exit_code,
        diagnostics_digest: *blake3::hash(&output.stderr).as_bytes(),
        diagnostics_len: output.stderr.len(),
    }
}

pub(super) fn classify_diagnostics(stderr: &[u8]) -> GitWireFailureClass {
    let text = String::from_utf8_lossy(stderr).to_lowercase();
    for (needle, class) in GIT_WIRE_FAILURE_NEEDLES {
        if text.contains(needle) {
            return class;
        }
    }
    GitWireFailureClass::Unknown
}
