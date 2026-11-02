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
/// | `0x02` | `BodyInstance`      | body instances (KS-2A)                   |
/// | `0x03` | `KnownValueIndex`   | the known-value index's master key (KS-3) |
/// | `0x04` | `KnownValueEntry`   | known-value history entries, by holder (KS-3) |
/// | `0x05` | `WorldPad`          | world key pads (KS-5, FIX 346)           |
/// | `0x06` | `CredentialValue`   | KS-6 credential values, per generation   |
/// | `0x07` | `CheckpointPayload` | KS-7 checkpoint payload compartments     |
/// | `0x08` | `TrainingLink`      | the vault's training link key K (TRAINING-LINK = C) |
/// | `0x09` | `CustodyTransition` | KS-6 custody transition instances        |
/// | `0x0a` | `CustodyRequestInput` | KS-6 custody request inputs, whole     |
/// | `0x0b` | `ConnectorResume` | a connector call's resume state (FIX 9157) |
/// | `0x0c` | `InferenceSnapshot` | an inference snapshot's wrapped data key |
/// | `0x0d` | `ErasableKey` | erasable keys: a home handoff's actor content, a grant's scope opening (FIX 8875) |
/// | `0x0e` | `HostIssuerSeed` | the vault's host issuer seed, escrowed (FIX-LIST 10770) |
///
/// A later client adds its variant with its reserved tag, its item width and
/// secret width, and its corruption label; custody itself stays the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum CustodyKind {
    /// The per-claim key of claim-bound Gate decision rows: item = claim id
    /// (16 bytes), secret = AES-256-GCM key (32 bytes).
    ClaimDecision,
    /// One body instance's key (KS-2A): item = the instance's random id (16
    /// bytes) then its scope byte, never the body's digest, so a later body
    /// of the same bytes never shares a retired instance's lifetime; secret =
    /// the body file's data key (32 bytes).
    BodyInstance,
    /// The known-value index's master key (KS-3): one per vault, so its item
    /// is empty and it lives at generation 0; secret = the 32 random bytes
    /// the index's fingerprint and tag keys derive from.
    KnownValueIndex,
    /// One known-value history entry (KS-3): item = the holding custody
    /// record's id (16 bytes), never a name derived from a value; generation
    /// = the holder's entry slot; secret = the index's 46-byte entry, `len
    /// (u32be) | tag (8) | rolling (u16be) | fingerprint (32)` (FIX 12209).
    KnownValueEntry,
    /// One world key's pad (KS-5, FIX 346): item = the key's full id (40
    /// bytes: the world's id (16), the key generation (8, big-endian), the
    /// key's random mint id (16); CALLS `FIX 5686 pad custody item codec`),
    /// so a world erase finds every pad of the world by its directory names;
    /// generation 0; secret = the pad (32 bytes).
    WorldPad,
    /// One owner's compartment of a checkpoint's ordinary payload (KS-7):
    /// item = subtype (1) | canonical owner (32) | incarnation (16), secret
    /// = the compartment's sealing key (32 bytes).
    CheckpointPayload,
    /// The vault's training link key K (TRAINING-LINK = C, TL-2): one per
    /// vault, so its item is empty and it lives at one fixed generation;
    /// secret = the 32-byte key its publisher training codes are derived
    /// from (keyed BLAKE3).
    TrainingLink,
    /// One generation of one credential's value (KS-6): item = the custody
    /// record's id (16 bytes), generation = the record's rotation
    /// generation; secret = the value's sealing key (32 bytes). CALLS
    /// `KS-6 leaf ids`.
    CredentialValue,
    /// One custody transition instance (KS-6): item = the credential's id
    /// (16) then the instance's random id (16), minted before any byte it
    /// seals, so a credential's carriers are found by its id alone; slot 0;
    /// secret = the carrier's sealing key (32 bytes).
    CustodyTransition,
    /// One custody request's whole protected input (KS-6), every numbered
    /// part of it under one key: item and secret as a transition's.
    CustodyRequestInput,
    /// One generation of one connector call's resume state (FIX 9157): item
    /// = the call ref (16 bytes), generation = the caller's round
    /// generation; secret = the resume state's sealing key (32 bytes).
    ConnectorResume,
    /// One inference snapshot's wrapped data key: item = the snapshot
    /// catalog's id (16 bytes), at generation 0; secret = the serialized
    /// wrapped key (61 bytes), kept here alone.
    InferenceSnapshot,
    /// One erasable key (FIX 8875): item = purpose (1) | parent (16: the
    /// actor a home handoff key seals for, or a grant) | incarnation (32) |
    /// the key's random ref (32), so every key of one parent is found by its
    /// directory names, orphans included; generation 0; secret = the
    /// content key (32 bytes).
    ErasableKey,
    /// The vault's host issuer seed, escrowed (FIX-LIST 10770): one subject
    /// per vault, so its item is empty; one generation per seed its root
    /// signs with; secret = the 32-byte seed, the same bytes an install's
    /// `HostIssuerSeed` keystore slot holds (`store::host_issuer_custody`).
    HostIssuerSeed,
}

impl CustodyKind {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::ClaimDecision => 0x01,
            Self::BodyInstance => 0x02,
            Self::KnownValueIndex => 0x03,
            Self::KnownValueEntry => 0x04,
            Self::WorldPad => 0x05,
            Self::CredentialValue => 0x06,
            Self::CheckpointPayload => 0x07,
            Self::TrainingLink => 0x08,
            Self::CustodyTransition => 0x09,
            Self::CustodyRequestInput => 0x0a,
            Self::ConnectorResume => 0x0b,
            Self::InferenceSnapshot => 0x0c,
            Self::ErasableKey => 0x0d,
            Self::HostIssuerSeed => 0x0e,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x01 => Some(Self::ClaimDecision),
            0x02 => Some(Self::BodyInstance),
            0x03 => Some(Self::KnownValueIndex),
            0x04 => Some(Self::KnownValueEntry),
            0x05 => Some(Self::WorldPad),
            0x06 => Some(Self::CredentialValue),
            0x07 => Some(Self::CheckpointPayload),
            0x08 => Some(Self::TrainingLink),
            0x09 => Some(Self::CustodyTransition),
            0x0a => Some(Self::CustodyRequestInput),
            0x0b => Some(Self::ConnectorResume),
            0x0c => Some(Self::InferenceSnapshot),
            0x0d => Some(Self::ErasableKey),
            0x0e => Some(Self::HostIssuerSeed),
            _ => None,
        }
    }

    /// The width of this kind's canonical item id.
    pub(crate) const fn item_len(self) -> usize {
        match self {
            Self::ClaimDecision => 16,
            Self::BodyInstance => 17,
            Self::KnownValueEntry
            | Self::CredentialValue
            | Self::ConnectorResume
            | Self::InferenceSnapshot => 16,
            Self::CustodyTransition | Self::CustodyRequestInput => 32,
            Self::WorldPad => 40,
            Self::CheckpointPayload => 49,
            Self::ErasableKey => 81,
            Self::KnownValueIndex | Self::TrainingLink | Self::HostIssuerSeed => 0,
        }
    }

    /// The width of this kind's secret: a stored entry of any other length
    /// is damaged, never replaced.
    pub(crate) const fn secret_len(self) -> usize {
        match self {
            Self::ClaimDecision
            | Self::BodyInstance
            | Self::KnownValueIndex
            | Self::WorldPad
            | Self::CheckpointPayload
            | Self::TrainingLink
            | Self::CredentialValue
            | Self::CustodyTransition
            | Self::CustodyRequestInput
            | Self::ConnectorResume
            | Self::ErasableKey
            | Self::HostIssuerSeed => 32,
            Self::KnownValueEntry => 46,
            Self::InferenceSnapshot => 61,
        }
    }

    /// What a damaged or retired entry of this kind reads as: the error its
    /// client's readers already match on.
    pub(crate) fn corrupt(self) -> Error {
        match self {
            Self::ClaimDecision => Error::CorruptedIndex("gate decision ORCB"),
            Self::BodyInstance => Error::CorruptedIndex("body file key custody"),
            Self::KnownValueIndex => Error::CorruptedIndex("known-value index key custody"),
            Self::KnownValueEntry => Error::CorruptedIndex("known-value history custody"),
            Self::WorldPad => Error::CorruptedIndex("world key pad custody"),
            Self::CheckpointPayload => Error::CorruptedIndex("checkpoint payload custody"),
            Self::TrainingLink => Error::CorruptedIndex("training link key"),
            Self::CredentialValue => Error::CorruptedIndex("credential value custody"),
            Self::CustodyTransition => Error::CorruptedIndex("custody transition custody"),
            Self::CustodyRequestInput => Error::CorruptedIndex("custody request input custody"),
            Self::ConnectorResume => Error::CorruptedIndex("connector resume custody"),
            Self::InferenceSnapshot => Error::CorruptedIndex("inference snapshot custody"),
            Self::ErasableKey => Error::CorruptedIndex("erasable key custody"),
            Self::HostIssuerSeed => Error::CorruptedIndex("host issuer seed custody"),
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

/// A binding's first byte names the platform its root path is spelled for:
/// Unix bytes, or Windows UTF-16LE. Both are this build's formats; a binding
/// of the other platform's still parses, its root naming nothing here.
const BINDING_UNIX: u8 = 1;
const BINDING_WINDOWS: u8 = 2;
#[cfg(unix)]
const BINDING_NATIVE: u8 = BINDING_UNIX;
#[cfg(not(unix))]
const BINDING_NATIVE: u8 = BINDING_WINDOWS;

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

/// `platform (1 Unix, 2 Windows) | namespace (16) | vault (32) | absolute
/// root path in that platform's spelling`. A binding written on the other
/// platform keeps its namespace and vault and names no root here (an empty
/// path): a restore rebinds it beside its destination before any host path
/// is used, and nothing finds custody at it.
impl RawValue for CustodyBinding {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut out = vec![BINDING_NATIVE];
        out.extend_from_slice(&self.namespace.0);
        out.extend_from_slice(&self.vault.0);
        out.extend(encode_native_path(&self.root).ok_or_else(custody_corrupt)?);
        Ok(out)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let decoded = (|| {
            let (&platform, rest) = bytes.split_first()?;
            let path = rest.get(48..)?;
            let root = if platform == BINDING_NATIVE {
                decode_native_path(path)?
            } else if platform == BINDING_UNIX || platform == BINDING_WINDOWS {
                (!path.is_empty()).then(PathBuf::new)?
            } else {
                return None;
            };
            Some(Self {
                namespace: CustodyNamespace(rest.get(..16)?.try_into().ok()?),
                vault: CustodyVaultId(rest.get(16..48)?.try_into().ok()?),
                root,
            })
        })();
        decoded.ok_or_else(|| custody_corrupt().into())
    }
}

/// A native absolute path, losslessly: its bytes on Unix, its UTF-16 code
/// units little-endian on Windows; `None` for a relative one.
pub(in crate::store) fn encode_native_path(path: &Path) -> Option<Vec<u8>> {
    if !path.is_absolute() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Some(path.as_os_str().as_bytes().to_vec())
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        Some(
            path.as_os_str()
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect(),
        )
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

/// The absolute path `raw` spells in this platform's encoding
/// ([`encode_native_path`]); `None` for an empty, relative or ill-formed
/// one. On Unix at most 4096 bytes, its path bound; Windows takes any
/// length.
pub(in crate::store) fn decode_native_path(raw: &[u8]) -> Option<PathBuf> {
    if raw.is_empty() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(raw));
        (raw.len() <= 4096 && path.is_absolute()).then(|| path.to_path_buf())
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        if !raw.len().is_multiple_of(2) {
            return None;
        }
        let wide: Vec<u16> = raw
            .chunks_exact(2)
            .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
            .collect();
        let path = PathBuf::from(std::ffi::OsString::from_wide(&wide));
        path.is_absolute().then_some(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
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

    /// Bytes its client computed (a known-value entry, KS-3): published as
    /// they are, never minted.
    pub(crate) fn from_bytes(bytes: Zeroizing<Vec<u8>>) -> Self {
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
