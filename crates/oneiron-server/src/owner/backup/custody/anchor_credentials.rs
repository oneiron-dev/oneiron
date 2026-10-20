//! The owner credential a custody anchor door admits (FIX 5788), handed to
//! the process that calls the door on a pipe of its own,
//! `--custody-anchor-credentials-fd`: managed serve, plain serve,
//! `oneiron backup` and a restore where no vault is yet. Never argv, the
//! environment, a file or the config. The pipe carries exactly one UTF-8
//! JSON object, then EOF: `{"bearer": "<token>", "binding_seed": null}`, or
//! with the capability slip's 32-byte binding seed, as an array of 32
//! numbers, in place of `null`. Its bytes are read into a buffer wiped on
//! drop and decoded from it in place; a refusal says what was wrong, never a
//! byte of what was read.

use std::fmt;
use std::io::Read as _;
use std::os::fd::{FromRawFd as _, RawFd};
use std::os::unix::fs::FileTypeExt as _;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::error::Category;
use serde_json::value::RawValue;
use zeroize::{Zeroize as _, Zeroizing};

/// How many bytes one read off the pipe takes.
const READ_CHUNK: usize = 1024;

/// A custody anchor door's owner credential: the bearer, and the binding
/// seed that signs each call's holder proof when the bearer is a capability
/// slip. Kept in memory only, shared with the door's client for as long as
/// that lives, and wiped on drop. It is never cloned, serialized or printed.
pub(crate) struct CustodyAnchorCredentials {
    bearer: Zeroizing<String>,
    binding_seed: Option<Zeroizing<[u8; 32]>>,
}

impl fmt::Debug for CustodyAnchorCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustodyAnchorCredentials")
            .field("bearer", &"<redacted>")
            .field(
                "binding_seed",
                &self.binding_seed.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// The pipe's one object. The bearer is borrowed raw from the read buffer,
/// so the parser never copies or unescapes it into a scratch buffer of its
/// own; the seed is wiped when this drops. Both keys are required.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire<'a> {
    #[serde(borrow)]
    bearer: &'a RawValue,
    #[serde(deserialize_with = "Option::deserialize")]
    binding_seed: Option<[u8; 32]>,
}

impl Drop for Wire<'_> {
    fn drop(&mut self) {
        self.binding_seed.zeroize();
    }
}

impl CustodyAnchorCredentials {
    /// The credentials a command was handed on `fd`
    /// (`--custody-anchor-credentials-fd`), read before it opens anything
    /// and shared with the door's client; `None` without the flag.
    pub(crate) fn handed(fd: Option<RawFd>) -> anyhow::Result<Option<Arc<Self>>> {
        fd.map(|fd| {
            Self::read_fd(fd).map(Arc::new).map_err(|reason| {
                anyhow::anyhow!("--custody-anchor-credentials-fd {fd} refused: {reason}")
            })
        })
        .transpose()
    }

    /// Takes `fd` over, the read end of a pipe, reads it to EOF and decodes
    /// the one credentials object it carries. The descriptor is closed
    /// either way.
    pub(crate) fn read_fd(fd: RawFd) -> Result<Self, String> {
        if fd < 0 {
            return Err(format!("{fd} is not a file descriptor"));
        }
        // SAFETY: `fd` arrives on argv (`--custody-anchor-credentials-fd`)
        // from whoever started this process, and is this process's to own:
        // it is read once, here. The `File` takes it over exactly once and
        // closes it on drop, which is also what lets the writer's EOF end
        // the read.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        if !file
            .metadata()
            .is_ok_and(|metadata| metadata.file_type().is_fifo())
        {
            return Err("it is not a pipe: the credentials ride a pipe, never a file".into());
        }
        let held = read_to_end(file).map_err(|error| format!("it did not read: {error}"))?;
        Self::decode(&held)
    }

    /// The one credentials object in `bytes`, with nothing after it.
    fn decode(bytes: &[u8]) -> Result<Self, String> {
        // The parser's own message can quote what it read: only its kind is
        // said.
        let wire: Wire<'_> = serde_json::from_slice(bytes).map_err(|error| {
            String::from(match error.classify() {
                Category::Eof => "it ended before its one JSON object did",
                Category::Syntax | Category::Io => {
                    "it is not one UTF-8 JSON object with nothing after it"
                }
                Category::Data => {
                    "its object is not a bearer string and a binding seed (null or 32 bytes) with no other key"
                }
            })
        })?;
        // A bearer is a token of visible ASCII: one that needs a JSON escape,
        // or is no string at all, is refused rather than unescaped.
        let bearer = wire
            .bearer
            .get()
            .strip_prefix('"')
            .and_then(|raw| raw.strip_suffix('"'))
            .filter(|token| {
                !token.is_empty()
                    && token
                        .bytes()
                        .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
            })
            .ok_or("its bearer is not a token of visible ASCII characters")?;
        Ok(Self {
            bearer: Zeroizing::new(bearer.to_owned()),
            binding_seed: wire.binding_seed.map(Zeroizing::new),
        })
    }

    /// The bearer the door is called with.
    pub(super) fn bearer(&self) -> &str {
        &self.bearer
    }

    /// The slip's binding seed, when the bearer is a capability slip.
    pub(super) fn binding_seed(&self) -> Option<&[u8; 32]> {
        self.binding_seed.as_deref()
    }
}

/// Reads `file` to its EOF into a buffer wiped on drop. It grows by moving
/// into a larger wiped buffer, never by reallocating in place, so no copy of
/// what was read is left behind unwiped.
fn read_to_end(mut file: std::fs::File) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut held = Zeroizing::new(Vec::with_capacity(READ_CHUNK));
    let mut chunk = Zeroizing::new([0_u8; READ_CHUNK]);
    loop {
        let read = match file.read(&mut chunk[..]) {
            Ok(0) => return Ok(held),
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if held.capacity() - held.len() < read {
            let mut grown = Zeroizing::new(Vec::with_capacity(held.capacity() * 2 + read));
            grown.extend_from_slice(&held);
            held = grown;
        }
        held.extend_from_slice(&chunk[..read]);
    }
}
