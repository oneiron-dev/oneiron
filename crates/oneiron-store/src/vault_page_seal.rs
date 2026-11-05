//! The page seal a vault's config holds (OF-570): the page key every LMDB
//! page of the vault is sealed under, the vault it belongs to and the vault
//! data key it derives from. Minting, unlocking, the mirror beside the vault
//! and the open stay in the engine (`world_keys::page_seal`).

use std::sync::Arc;

use oneiron_contracts::error::Result;
use zeroize::Zeroizing;

use crate::key_material::{derive_guarded, os_fill};

/// The derive-key context of a vault's page key.
pub const PAGE_KEY_CONTEXT: &str = "oneiron/vault-page-key/v1";
const COMMITMENT_CONTEXT: &str = "oneiron/vault-key-commitment/v1";

/// What opens a sealed vault's pages: the page key, the vault it belongs to,
/// and the vault data key it derives from. No `Serialize`, a `Debug` that
/// prints nothing, and the keys are wiped when the last clone drops.
#[derive(Clone)]
pub struct VaultPageSeal {
    vault_id: [u8; 32],
    incarnation: [u8; 32],
    page_key: Arc<Zeroizing<[u8; 32]>>,
    data_key: Arc<VaultDataKey>,
    origin: SealOrigin,
}

/// Where a seal came from: minted for a new vault, the one seal that creates
/// a vault, unlocked from a mirror by the carried wraps it opened or by the
/// data-key kit's pieces (FIX 5614), which open no wrap, or made from the
/// data key a managed node's supervisor delivered (`new` for a new vault's).
/// `Beside` is a fresh incarnation of an open vault's seal: it creates the
/// vault restored beside it or in its place, whose restore stages it, so no
/// creation record is kept for it (FIX 1942).
#[derive(Clone)]
pub enum SealOrigin {
    New,
    Beside,
    Unlocked(Vec<WrapDigest>),
    Kit,
    Delivered { new: bool },
}

impl std::fmt::Debug for VaultPageSeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultPageSeal(..)")
    }
}

impl PartialEq for VaultPageSeal {
    fn eq(&self, other: &Self) -> bool {
        let diff = self
            .page_key
            .iter()
            .zip(other.page_key.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        self.vault_id == other.vault_id && self.incarnation == other.incarnation && diff == 0
    }
}

impl VaultPageSeal {
    /// A seal for `incarnation` of the vault `vault_id` under `data_key`:
    /// engine-internal, for the seal minting and unlocking in
    /// `world_keys::page_seal`.
    #[doc(hidden)]
    pub fn derive(
        vault_id: [u8; 32],
        incarnation: [u8; 32],
        data_key: VaultDataKey,
        origin: SealOrigin,
    ) -> Self {
        Self::derive_shared(vault_id, incarnation, Arc::new(data_key), origin)
    }

    /// [`Self::derive`] under a data key another seal or a restore holds:
    /// engine-internal.
    #[doc(hidden)]
    pub fn derive_shared(
        vault_id: [u8; 32],
        incarnation: [u8; 32],
        data_key: Arc<VaultDataKey>,
        origin: SealOrigin,
    ) -> Self {
        let page_key = Arc::new(data_key.derive(PAGE_KEY_CONTEXT, &incarnation));
        Self {
            vault_id,
            incarnation,
            page_key,
            data_key,
            origin,
        }
    }

    /// A seal for a vault restored in this one's place or beside it: this
    /// seal's vault and data key under a fresh incarnation. It creates the
    /// restored vault, as a new vault's seal does; the restored rows carry the
    /// key's wraps, and its mirror follows them.
    pub fn fresh_incarnation(&self) -> Result<Self> {
        let mut incarnation = [0u8; 32];
        os_fill(&mut incarnation)?;
        Ok(Self::derive_shared(
            self.vault_id,
            incarnation,
            Arc::clone(&self.data_key),
            SealOrigin::Beside,
        ))
    }

    /// The vault this seal belongs to. A new vault takes it as its own id.
    #[must_use]
    pub fn vault_id(&self) -> [u8; 32] {
        self.vault_id
    }

    /// The incarnation this seal opened, as the mirror names it (FIX 2706):
    /// a public fact beside the vault id, since the mirror carries it in
    /// plain and the page key still takes the data key. It names WHICH of a
    /// mirror's candidates this seal is, so a reader holding two
    /// environments of one vault can tell the live one from its replacement
    /// without opening either.
    #[must_use]
    pub fn incarnation(&self) -> [u8; 32] {
        self.incarnation
    }

    /// The page key, for the environment builders: engine-internal.
    #[doc(hidden)]
    pub fn page_key(&self) -> &[u8; 32] {
        &self.page_key
    }

    /// The page key as the seal holds it, for the opened-vault registry:
    /// engine-internal.
    #[doc(hidden)]
    pub fn shared_page_key(&self) -> &Arc<Zeroizing<[u8; 32]>> {
        &self.page_key
    }

    /// The vault data key the page key derives from: engine-internal.
    #[doc(hidden)]
    pub fn data_key(&self) -> &Arc<VaultDataKey> {
        &self.data_key
    }

    /// Where this seal came from: engine-internal.
    #[doc(hidden)]
    pub fn origin(&self) -> &SealOrigin {
        &self.origin
    }
}

/// The unlocked vault data key. No `Clone`, no `Serialize`, a `Debug` that
/// prints nothing, and its bytes are wiped on drop.
pub struct VaultDataKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for VaultDataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultDataKey(..)")
    }
}

impl VaultDataKey {
    pub fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        os_fill(&mut bytes[..])?;
        Ok(Self(bytes))
    }

    /// The key a managed node's supervisor delivered, copied into a handle
    /// that wipes it on drop: zero-filled first, then filled, so no plain
    /// copy is made on the way (FIX 6048).
    pub fn delivered(bytes: &[u8; 32]) -> Self {
        let mut guarded = Zeroizing::new([0u8; 32]);
        guarded.copy_from_slice(bytes);
        Self(guarded)
    }

    /// `BLAKE3-derive_key("oneiron/vault-key-commitment/v1", vault id ‖ key)`: it
    /// pins which bytes are this vault's key and reveals nothing about them.
    pub fn commitment(&self, vault_id: &[u8; 32]) -> [u8; 32] {
        // Public: the guard's copy is wiped as it drops.
        *self.derive(COMMITMENT_CONTEXT, vault_id)
    }

    /// A key of its own for one use, `BLAKE3-derive_key(context, vault id ‖ key)`,
    /// derived straight into its guard (FIX 6334).
    pub fn derive(&self, context: &str, vault_id: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        derive_guarded(context, &[&vault_id[..], &self.0[..]])
    }

    /// The key held in `bytes`, a guard a wrap or a kit opened to:
    /// engine-internal.
    #[doc(hidden)]
    pub fn from_guarded(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// The key's bytes in their guard, for sealing them into a wrap or a
    /// kit: engine-internal.
    #[doc(hidden)]
    pub fn guarded_bytes(&self) -> &Zeroizing<[u8; 32]> {
        &self.0
    }
}

/// One wrap as a page-seal mirror carries it (OF-570): its id, which names
/// its kind and label, and the BLAKE3 digest of its sealed envelope. A
/// sealed vault admits an unlock from its mirror only while it holds the
/// wrap that opened, envelope for envelope.
#[derive(Clone, PartialEq, Eq)]
pub struct WrapDigest {
    id: String,
    envelope: [u8; 32],
}

impl WrapDigest {
    /// The digest of the wrap filed under `id` whose sealed envelope hashes
    /// to `envelope`.
    pub fn new(id: String, envelope: [u8; 32]) -> Self {
        Self { id, envelope }
    }

    /// The wrap's id.
    pub fn id(&self) -> &String {
        &self.id
    }
}
