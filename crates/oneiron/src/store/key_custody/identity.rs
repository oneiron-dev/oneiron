//! Typed custody identities and their codecs: who a custody entry belongs to
//! (vault, kind, item, generation), the binding namespace it lives in, and the
//! opaque secret it holds. No codec here takes a value's bytes as a name.

use std::path::{Path, PathBuf};

use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::side_table::{CodecError, RawValue, SideKey};

/// A structural fault in custody itself, not in one kind's entry: a binding
/// that does not decode, a directory that is not the engine's.
pub(crate) fn custody_corrupt() -> Error {
    Error::CorruptedIndex("key custody")
}

/// One independent fork and retirement domain. A restore in a vault's place
/// keeps it; a side restore or an activation forks into a new one, so from
/// then on neither vault's erase reaches the other's entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CustodyNamespace([u8; 16]);

impl CustodyNamespace {
    /// The namespace a custody head, log frame or anchor record names.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// The vault whose subjects a custody holds: the store's own identity
/// (`vault_identity:local:v1`) when the binding was minted, else 32 random
/// bytes. Never a path hash. A fork keeps it: the entries it copies are still
/// that vault's subjects, in another namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CustodyVaultId([u8; 32]);

impl CustodyVaultId {
    /// The vault a custody head, log frame or anchor record names.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// What a custody entry keys. Each kind has a stable one-byte tag, used by
/// its directory name and its intent key; a tag is never reused or renumbered.
///
/// | tag    | kind                | client                                   |
/// |--------|---------------------|------------------------------------------|
/// | `0x01` | `ClaimDecision`     | claim-bound Gate decision rows (ORCB)    |
/// | `0x02` | `BodyInstance`      | reserved: KS-2 body instances            |
/// | `0x03` | `KnownValueIndex`   | reserved: KS-3 known-value index key     |
/// | `0x04` | `KnownValueEntry`   | reserved: KS-3 known-value holder entries |
/// | `0x05` | `WorldPad`          | reserved: KS-5 world pads                |
/// | `0x06` | `CredentialValue`   | reserved: KS-6 credential values         |
/// | `0x07` | `CheckpointPayload` | reserved: KS-7 checkpoint payloads       |
/// | `0x08` | `TrainingLink`      | the vault's training link key K (TRAINING-LINK = C) |
///
/// A later client adds its variant with its reserved tag, its item width and
/// secret width, and its corruption label; custody itself stays the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum CustodyKind {
    /// The per-claim key of claim-bound Gate decision rows: item = claim id
    /// (16 bytes), secret = AES-256-GCM key (32 bytes).
    ClaimDecision,
    /// The vault's training link key K (TRAINING-LINK = C, TL-2): one per
    /// vault, so its item is empty and it lives at one fixed generation;
    /// secret = the 32-byte HMAC-SHA256 key its publisher training codes are
    /// made under.
    TrainingLink,
}

impl CustodyKind {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::ClaimDecision => 0x01,
            Self::TrainingLink => 0x08,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x01 => Some(Self::ClaimDecision),
            0x08 => Some(Self::TrainingLink),
            _ => None,
        }
    }

    /// The width of this kind's canonical item id.
    pub(crate) const fn item_len(self) -> usize {
        match self {
            Self::ClaimDecision => 16,
            Self::TrainingLink => 0,
        }
    }

    /// The width of this kind's secret: a stored entry of any other length
    /// is damaged, never replaced.
    pub(crate) const fn secret_len(self) -> usize {
        match self {
            Self::ClaimDecision | Self::TrainingLink => 32,
        }
    }

    /// What a damaged or retired entry of this kind reads as: the error its
    /// client's readers already match on.
    pub(crate) fn corrupt(self) -> Error {
        match self {
            Self::ClaimDecision => Error::CorruptedIndex("gate decision ORCB"),
            Self::TrainingLink => Error::CorruptedIndex("training link key"),
        }
    }
}

/// One item within its kind, in that client's canonical id codec: an id the
/// client already holds (a claim id), never value bytes and never a name
/// derived from a value. Its directory name is its lowercase hex.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CustodyItemId(Vec<u8>);

/// Who a custody entry belongs to, every generation of it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CustodySubject {
    vault: CustodyVaultId,
    kind: CustodyKind,
    item: CustodyItemId,
}

impl CustodySubject {
    /// Refuses an item that is not `kind`'s width.
    pub(crate) fn new(vault: CustodyVaultId, kind: CustodyKind, item: &[u8]) -> Result<Self> {
        if item.len() != kind.item_len() {
            return Err(kind.corrupt());
        }
        Ok(Self {
            vault,
            kind,
            item: CustodyItemId(item.to_vec()),
        })
    }

    pub(crate) fn vault(&self) -> CustodyVaultId {
        self.vault
    }

    pub(crate) fn kind(&self) -> CustodyKind {
        self.kind
    }

    pub(crate) fn item(&self) -> &[u8] {
        &self.item.0
    }

    pub(crate) fn at(&self, generation: u64) -> CustodyId {
        CustodyId {
            subject: self.clone(),
            generation,
        }
    }

    /// `<tag hex>.<item hex>`: the subject's directory in its compartment.
    pub(super) fn dir_name(&self) -> String {
        format!(
            "{:02x}.{}",
            self.kind.tag(),
            crate::entity_id::bytes_to_hex_lower(&self.item.0)
        )
    }

    /// The subject a directory name in `vault`'s compartment names. A name
    /// the engine would not write names none.
    pub(super) fn from_dir_name(vault: CustodyVaultId, name: &str) -> Option<Self> {
        let (tag, item) = name.split_once('.')?;
        let kind = CustodyKind::from_tag(u8::from_str_radix(tag, 16).ok()?)?;
        let subject = Self::new(vault, kind, &hex_decode(item)?).ok()?;
        (subject.dir_name() == name).then_some(subject)
    }
}

/// `vault (32) | kind tag (1) | item`, after the intent table's prefix.
impl SideKey for CustodySubject {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.vault.0);
        out.push(self.kind.tag());
        out.extend_from_slice(&self.item.0);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let vault = CustodyVaultId(bytes.get(..32)?.try_into().ok()?);
        let kind = CustodyKind::from_tag(*bytes.get(32)?)?;
        Self::new(vault, kind, bytes.get(33..)?).ok()
    }
}

/// One generation of one subject: the unit custody stores, retires and
/// forks. Generations of a subject are counted from zero; a retired one is
/// never reused.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CustodyId {
    subject: CustodySubject,
    generation: u64,
}

impl CustodyId {
    pub(crate) fn subject(&self) -> &CustodySubject {
        &self.subject
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn kind(&self) -> CustodyKind {
        self.subject.kind
    }
}

/// Where a vault's custody is and whose it is: non-secret, checkpointed with
/// the vault (`key_custody:binding:v1`). A restore in the vault's place binds
/// the same live custody, so replacing an image never brings back an entry
/// already destroyed there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CustodyBinding {
    namespace: CustodyNamespace,
    vault: CustodyVaultId,
    root: PathBuf,
}

const BINDING_VERSION: u8 = 1;

impl CustodyBinding {
    /// A new custody beside the vault at `root`, in a fresh namespace, for
    /// the vault `vault` names, or a random vault id when it names none.
    pub(crate) fn mint(root: PathBuf, vault: Option<[u8; 32]>) -> Self {
        let vault = vault.unwrap_or_else(|| {
            let mut id = [0; 32];
            rand::rngs::OsRng.fill_bytes(&mut id);
            id
        });
        Self {
            namespace: fresh_namespace(),
            vault: CustodyVaultId(vault),
            root,
        }
    }

    /// The binding a fork of this custody takes beside the vault at `root`:
    /// a fresh namespace, the same vault.
    pub(crate) fn fork_to(&self, root: PathBuf) -> Self {
        Self {
            namespace: fresh_namespace(),
            vault: self.vault,
            root,
        }
    }

    pub(crate) fn vault(&self) -> CustodyVaultId {
        self.vault
    }

    /// The fork and retirement domain this custody's entries live in.
    pub(crate) fn namespace(&self) -> CustodyNamespace {
        self.namespace
    }

    /// The same custody, its namespace and vault kept, beside the vault at
    /// `root`: a disaster recovery's destination, which takes over the
    /// source's lineage (KS-4) rather than forking it.
    pub(crate) fn rebind_to(&self, root: PathBuf) -> Self {
        Self {
            namespace: self.namespace,
            vault: self.vault,
            root,
        }
    }

    /// The vault root this custody sits beside.
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// One subject of this binding's vault.
    pub(crate) fn subject(&self, kind: CustodyKind, item: &[u8]) -> Result<CustodySubject> {
        CustodySubject::new(self.vault, kind, item)
    }

    /// `<namespace hex>.<vault hex>`: this binding's compartment.
    pub(super) fn compartment_name(&self) -> String {
        format!(
            "{}.{}",
            crate::entity_id::bytes_to_hex_lower(&self.namespace.0),
            crate::entity_id::bytes_to_hex_lower(&self.vault.0)
        )
    }
}

fn fresh_namespace() -> CustodyNamespace {
    let mut namespace = [0; 16];
    rand::rngs::OsRng.fill_bytes(&mut namespace);
    CustodyNamespace(namespace)
}

/// `1 | namespace (16) | vault (32) | native absolute root path`.
impl RawValue for CustodyBinding {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut out = vec![BINDING_VERSION];
        out.extend_from_slice(&self.namespace.0);
        out.extend_from_slice(&self.vault.0);
        out.extend(encode_native_path(&self.root).ok_or_else(custody_corrupt)?);
        Ok(out)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let decoded = (|| {
            let (&BINDING_VERSION, rest) = bytes.split_first()? else {
                return None;
            };
            Some(Self {
                namespace: CustodyNamespace(rest.get(..16)?.try_into().ok()?),
                vault: CustodyVaultId(rest.get(16..48)?.try_into().ok()?),
                root: decode_native_path(rest.get(48..)?)?,
            })
        })();
        decoded.ok_or_else(|| custody_corrupt().into())
    }
}

/// A native absolute path's bytes; `None` for a relative one, or off unix.
pub(in crate::store) fn encode_native_path(path: &Path) -> Option<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.is_absolute()
            .then(|| path.as_os_str().as_bytes().to_vec())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// The absolute path `raw` spells: at most 4096 bytes; `None` otherwise, or
/// off unix.
pub(in crate::store) fn decode_native_path(raw: &[u8]) -> Option<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(raw));
        (!raw.is_empty() && raw.len() <= 4096 && path.is_absolute()).then(|| path.to_path_buf())
    }
    #[cfg(not(unix))]
    {
        let _ = raw;
        None
    }
}

/// Lowercase hex only, so one item has one name.
pub(super) fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    (crate::entity_id::bytes_to_hex_lower(&bytes) == text).then_some(bytes)
}

/// Opaque custody bytes: zeroized on drop, redacted in `Debug`, never named
/// in a log, error, receipt, notice or digest.
pub(crate) struct CustodySecret(Zeroizing<Vec<u8>>);

impl CustodySecret {
    /// `len` fresh random bytes.
    pub(crate) fn random(len: usize) -> Self {
        let mut bytes = Zeroizing::new(vec![0; len]);
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub(super) fn from_bytes(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for CustodySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CustodySecret(<redacted>)")
    }
}
