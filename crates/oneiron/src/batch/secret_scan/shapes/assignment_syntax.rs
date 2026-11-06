//! The literals of the credential-assignment rule (FIX 7200, FIX 5392 Rule
//! 5): its segment edges, separators, trims, credential names and release
//! placeholders. [`super::sensitive_assignment`] reads them over a whole
//! text. The release reader's recognizer reads the same ones as the text
//! streams.

/// The edges the assignment rule splits a text into segments at. None is a
/// token byte, so no provider token crosses one either.
pub(in crate::batch::secret_scan) const SEGMENT_BREAKS: [char; 6] =
    ['\n', '\r', ',', ';', '{', '}'];

/// The characters a segment's key ends at: the first one in the segment.
pub(in crate::batch::secret_scan) const ASSIGNMENT_SEPARATORS: [char; 2] = ['=', ':'];

/// The shell prefix a key reading strips, as often as it leads. Its only
/// blank is its last character.
pub(in crate::batch::secret_scan) const EXPORT_PREFIX: &str = "export ";

/// The quotes a key or value reading trims from both ends.
pub(in crate::batch::secret_scan) const ASSIGNMENT_QUOTES: [char; 2] = ['"', '\''];

/// The quotes a custody-handle reading trims from both ends.
pub(in crate::batch::secret_scan) const HANDLE_QUOTES: [char; 3] = ['"', '\'', '`'];

/// What a bare custody handle starts with, before its digits: `sc12`.
pub(in crate::batch::secret_scan) const HANDLE_TAG: &str = "sc";

/// The normalized keys that are a credential name whole.
pub(in crate::batch::secret_scan) const CREDENTIAL_NAMES: [&str; 14] = [
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "client_secret",
    "access_token",
    "refresh_token",
    "authorization",
    "mnemonic",
    "seed_phrase",
];

/// The endings that make any normalized key a credential name.
pub(in crate::batch::secret_scan) const CREDENTIAL_NAME_ENDINGS: [&str; 7] = [
    "_password",
    "_passwd",
    "_secret",
    "_token",
    "_api_key",
    "_private_key",
    "_access_key",
];

/// The values serve and export have always read as no secret at all, once
/// trimmed and in ASCII lower case.
pub(in crate::batch::secret_scan) const RELEASE_PLACEHOLDERS: [&str; 5] =
    ["", "[redacted]", "[secret redacted]", "<redacted>", "null"];

/// A key byte as a key reading compares it: ASCII lower case, with `-` and
/// `.` read as `_`. Every other byte, a non-ASCII one too, reads as itself.
pub(in crate::batch::secret_scan) const fn normalized_key_byte(byte: u8) -> u8 {
    match byte.to_ascii_lowercase() {
        b'-' | b'.' => b'_',
        lower => lower,
    }
}
