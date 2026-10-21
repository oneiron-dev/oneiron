//! The sealed custody head (KS-4, FIX 5685): the latest live entries of one
//! lineage and every retirement fact it holds, sealed at one log position.
//!
//! A head is bound to its vault, namespace, writer epoch, sequence number and
//! log tip, and names each entry by its typed id and generation. Its entries
//! go in compartments, one per scope: each is sealed under a fresh random
//! compartment key, and that key is wrapped to each recipient its scope
//! admits: the owner's recovery root (hybrid, so the kit, which keeps only
//! its seed, opens every compartment), and for a host-readable scope the
//! vault data key's custody subkey as well. An owner-only compartment is
//! never wrapped to the host-readable data key. Compartment 0 is the control
//! compartment: the lineage's control secret, which opens its log frames and
//! authenticates its anchor records, and the digest of every other
//! compartment in order, so no compartment is dropped, added, moved or
//! transplanted from another head. A head holds no frozen requirement: a
//! restore asks it for what its image needs.

use std::collections::{BTreeMap, BTreeSet};

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, HybridPublicKey, HybridSecretKey, Kek, OpenKey, OpenPolicy, Purpose,
    SealKey, SealParams, SuiteId, WrapType, seal,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

use super::identity::{CustodyId, CustodyKind, CustodySecret, CustodySubject};
use super::log::{
    AEAD, CRYPTO_EPOCH, Control, CustodyPosition, POSITION_LEN, open_sym, seal_refused, seal_sym,
};
use super::recipients::RecipientRetirement;

const HEAD_MAGIC: &[u8; 4] = b"OCHD";
const HEAD_VERSION: u16 = 1;
const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;
const DATA_KEY_RECIPIENT: &[u8] = b"oneiron/custody-head/data-key/v1";
const COMPARTMENT_RECIPIENT: &[u8] = b"oneiron/custody-head/compartment/v1";
/// The derive-key context of a compartment's envelope key id ([`key_id`]).
const KEY_ID_CONTEXT: &str = "oneiron/custody-head/compartment-key-id/v1";
const TO_ROOT: u8 = 1;
const TO_DATA_KEY: u8 = 2;
/// The most entries, live or retired, one compartment holds: a codec bound
/// that keeps each compartment's plaintext far inside one E0 envelope; a
/// scope with more takes more compartments.
const COMPARTMENT_ENTRIES: usize = 32 * 1024;

/// The context of the vault data key's subkey a host-readable compartment
/// is also wrapped under.
pub(crate) const CUSTODY_HEAD_WRAP_CONTEXT: &str = "oneiron/custody-head/v1";

pub(super) fn head_corrupt() -> Error {
    Error::CorruptedIndex("key custody head")
}

/// Who may read one kind's entries, which fixes the recipients of the
/// compartment they are sealed in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CompartmentScope {
    /// Kinds the host engine reads in its own process (claim keys, the
    /// training link key): their compartment opens with the vault data key
    /// as well, so a restore that unlocked a backup opens it without the kit.
    HostReadable,
    /// Kinds only the owner's own machines may read (a later client's):
    /// wrapped to the recovery root alone, never to the host-readable data
    /// key.
    OwnerOnly,
}

impl CompartmentScope {
    /// Each kind's scope; a later kind names its own.
    pub(crate) fn of(kind: CustodyKind) -> Self {
        match kind {
            // A body instance's key is one the host engine reads in its own
            // process, as a claim key is (KS-2A); so are the known-value
            // index's master and its history entries (KS-3), which no kit
            // need open.
            //
            // A world pad too (KS-5, CALLS WORLD_PAD_HEAD_SCOPE): a backup
            // the data key unlocks restores its worlds' pads, as it did
            // when the pads rode its rows. A pad alone opens nothing; its
            // world's key wraps open only to a machine or root secret.
            CustodyKind::ClaimDecision
            | CustodyKind::BodyInstance
            | CustodyKind::KnownValueIndex
            | CustodyKind::KnownValueEntry
            | CustodyKind::WorldPad
            | CustodyKind::CheckpointPayload
            | CustodyKind::TrainingLink => Self::HostReadable,
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::HostReadable => 1,
            Self::OwnerOnly => 2,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::HostReadable),
            2 => Some(Self::OwnerOnly),
            _ => None,
        }
    }
}

/// Who a head's compartment keys are wrapped to. Domain policy picks them:
/// the stored root's public facts and the held data key, never a seed.
pub(crate) struct CustodyRecipients {
    /// The owner's recovery root, by id and hybrid public key: every
    /// compartment. `None` while no root is pinned; the kit is never
    /// enrolled by a publication.
    pub(crate) root: Option<([u8; 32], HybridPublicKey)>,
    /// The vault data key's [`CUSTODY_HEAD_WRAP_CONTEXT`] subkey: the
    /// control compartment and host-readable ones.
    pub(crate) data_key: Option<Zeroizing<[u8; 32]>>,
    /// The worlds (16-byte ids) whose pads the head leaves out: their
    /// settings keep their pads off where the head goes (KS-5 pad head
    /// eligibility). They stay in this machine's custody.
    pub(crate) pad_worlds_kept_local: BTreeSet<[u8; 16]>,
}

impl CustodyRecipients {
    /// Whether the head leaves the live entry `id` out: a world pad of a
    /// world [`Self::pad_worlds_kept_local`] names.
    pub(crate) fn keeps_local(&self, id: &CustodyId) -> bool {
        id.kind() == CustodyKind::WorldPad
            && id
                .subject()
                .item()
                .get(..16)
                .and_then(|world| <[u8; 16]>::try_from(world).ok())
                .is_some_and(|world| self.pad_worlds_kept_local.contains(&world))
    }
}

/// What a restore opens a head with. The kit's root opens every
/// compartment; the data key, unlocked from a backup, opens the control
/// compartment and host-readable ones.
pub(crate) struct CustodyOpener<'a> {
    pub(crate) root: Option<&'a HybridSecretKey>,
    pub(crate) data_key: Option<Zeroizing<[u8; 32]>>,
}

/// One live entry a head carries.
pub(super) struct HeadEntry {
    pub(super) id: CustodyId,
    pub(super) secret: CustodySecret,
}

/// A head opened by one opener: its position, the control secret, every
/// live entry of the compartments the opener opened, the retirement facts
/// they hold, and the scopes it could not open.
pub(crate) struct OpenedHead {
    pub(super) position: CustodyPosition,
    pub(super) control: Zeroizing<[u8; 32]>,
    pub(super) live: BTreeMap<CustodyId, CustodySecret>,
    pub(super) retired: BTreeSet<CustodyId>,
    pub(super) unopened: BTreeSet<CompartmentScope>,
    /// The released escrow recipients the lineage retired (LC FIX
    /// 5384/5385), from the control compartment.
    pub(super) recipients: Vec<RecipientRetirement>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadWire {
    version: u16,
    #[serde(with = "serde_bytes_vec")]
    position: Vec<u8>,
    compartments: Vec<CompartmentWire>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompartmentWire {
    scope: u8,
    #[serde(with = "serde_bytes_vec")]
    sealed: Vec<u8>,
    wraps: Vec<WrapWire>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WrapWire {
    to: u8,
    root: Option<[u8; 32]>,
    #[serde(with = "serde_bytes_vec")]
    envelope: Vec<u8>,
}

/// One compartment's plaintext. The control compartment holds the control
/// secret and the other compartments' digests; the rest hold entries.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyWire {
    control: Option<[u8; 32]>,
    digests: Vec<[u8; 32]>,
    live: Vec<EntryWire>,
    retired: Vec<FactWire>,
    /// The control compartment's: every released escrow recipient the
    /// lineage retired, public facts only (LC FIX 5384/5385).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    recipients: Vec<RecipientRetirement>,
}

impl Drop for BodyWire {
    fn drop(&mut self) {
        if let Some(control) = &mut self.control {
            control.zeroize();
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryWire {
    kind: u8,
    #[serde(with = "serde_bytes_vec")]
    item: Vec<u8>,
    generation: u64,
    #[serde(with = "serde_bytes_vec")]
    secret: Vec<u8>,
}

impl Drop for EntryWire {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FactWire {
    kind: u8,
    #[serde(with = "serde_bytes_vec")]
    item: Vec<u8>,
    generation: u64,
}

/// Byte strings as msgpack bin, not arrays of numbers.
pub(super) mod serde_bytes_vec {
    use serde::{Deserializer, Serializer};

    pub(in crate::store::key_custody) fn serialize<S: Serializer>(
        bytes: &[u8],
        out: S,
    ) -> Result<S::Ok, S::Error> {
        out.serialize_bytes(bytes)
    }

    pub(in crate::store::key_custody) fn deserialize<'de, D: Deserializer<'de>>(
        input: D,
    ) -> Result<Vec<u8>, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Vec<u8>, E> {
                Ok(bytes.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, bytes: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(bytes)
            }
        }
        input.deserialize_bytes(Visitor)
    }
}

/// What binds a compartment and its key's wraps to their place in exactly
/// this head: a 32-byte commitment to the whole of `position | u32be index |
/// scope`, which fits an envelope's key id (FIX 6769).
fn key_id(position: &[u8; POSITION_LEN], index: u32, scope: Option<CompartmentScope>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(KEY_ID_CONTEXT);
    hasher.update(position);
    hasher.update(&index.to_be_bytes());
    hasher.update(&[scope.map_or(0, CompartmentScope::code)]);
    *hasher.finalize().as_bytes()
}

fn wrap_policy<'a>(
    purpose: Purpose,
    vault: &'a [u8],
    recipient: &'a [u8],
    key_id: &'a [u8],
    wraps: &'a [WrapType],
    kems: &'a [SuiteId],
) -> OpenPolicy<'a> {
    OpenPolicy {
        purpose,
        vault_id: vault,
        recipient,
        key_id,
        wraps,
        aead_suites: &[AEAD],
        kem_suites: kems,
        min_epoch: CRYPTO_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    }
}

/// Seals one compartment holding `body` under a fresh key, wrapped to each
/// recipient `scope` admits (`None`: the control compartment).
fn seal_compartment(
    position: &CustodyPosition,
    index: u32,
    scope: Option<CompartmentScope>,
    body: &BodyWire,
    recipients: &CustodyRecipients,
) -> Result<CompartmentWire> {
    let pos = position.to_bytes();
    let id = key_id(&pos, index, scope);
    let mut key = Zeroizing::new([0u8; 32]);
    crate::world_keys::os_fill(&mut key[..])?;
    let plain = Zeroizing::new(rmp_serde::to_vec_named(body).map_err(|_| head_corrupt())?);
    let sealed = seal_sym(
        Purpose::CustodyCompartment,
        position.vault,
        &id,
        COMPARTMENT_RECIPIENT,
        &Kek::from_bytes_ref(&key),
        &plain,
    )?;
    let mut wraps = Vec::new();
    if let Some((root, public)) = &recipients.root {
        let params = SealParams {
            suite: AEAD,
            purpose: Purpose::CustodyCompartmentKey,
            epoch: CRYPTO_EPOCH,
            key_id: &id,
            recipient: root,
            vault_id: position.vault.as_bytes(),
        };
        let envelope = seal(
            &params,
            SealKey::Hybrid {
                recipient: public,
                kem_suite: KEM,
            },
            &key[..],
            &mut SysRng,
        )
        .map_err(|error| seal_refused(&error))?;
        wraps.push(WrapWire {
            to: TO_ROOT,
            root: Some(*root),
            envelope: envelope.to_bytes(),
        });
    }
    // An owner-only compartment never opens with the host-readable data key.
    if scope != Some(CompartmentScope::OwnerOnly)
        && let Some(data_key) = &recipients.data_key
    {
        wraps.push(WrapWire {
            to: TO_DATA_KEY,
            root: None,
            envelope: seal_sym(
                Purpose::CustodyCompartmentKey,
                position.vault,
                &id,
                DATA_KEY_RECIPIENT,
                &Kek::from_bytes_ref(data_key),
                &key[..],
            )?,
        });
    }
    if wraps.is_empty() {
        return Err(Error::InvalidConfig(
            "a custody head needs a recipient: the vault key is locked and no recovery root is \
             pinned"
                .into(),
        ));
    }
    Ok(CompartmentWire {
        scope: scope.map_or(0, CompartmentScope::code),
        sealed,
        wraps,
    })
}

/// Seals a head at `position` holding `entries`, the retirement facts
/// `retired` and the released escrow recipients `released` retired, wrapped
/// to `recipients`. The bytes are key-bearing: they go only to a custody
/// target, never to a log, error or receipt.
pub(super) fn seal_head(
    position: &CustodyPosition,
    control: &Control,
    entries: Vec<HeadEntry>,
    retired: Vec<CustodyId>,
    released: Vec<RecipientRetirement>,
    recipients: &CustodyRecipients,
) -> Result<Zeroizing<Vec<u8>>> {
    // Each scope's entries go in as many compartments as they fill, each
    // at most COMPARTMENT_ENTRIES of them: a head grows with its custody,
    // never past one envelope's bound and never capped (Rule 5).
    let mut scopes: BTreeMap<CompartmentScope, Vec<BodyWire>> = BTreeMap::new();
    let chunk_of = |scopes: &mut BTreeMap<CompartmentScope, Vec<BodyWire>>, scope| {
        let chunks = scopes.entry(scope).or_default();
        if chunks
            .last()
            .is_none_or(|body| body.live.len() + body.retired.len() >= COMPARTMENT_ENTRIES)
        {
            chunks.push(BodyWire::default());
        }
        chunks.len() - 1
    };
    for entry in entries {
        let scope = CompartmentScope::of(entry.id.kind());
        let at = chunk_of(&mut scopes, scope);
        scopes.get_mut(&scope).ok_or_else(head_corrupt)?[at]
            .live
            .push(EntryWire {
                kind: entry.id.kind().tag(),
                item: entry.id.subject().item().to_vec(),
                generation: entry.id.generation(),
                secret: entry.secret.expose().to_vec(),
            });
    }
    for id in retired {
        let scope = CompartmentScope::of(id.kind());
        let at = chunk_of(&mut scopes, scope);
        scopes.get_mut(&scope).ok_or_else(head_corrupt)?[at]
            .retired
            .push(FactWire {
                kind: id.kind().tag(),
                item: id.subject().item().to_vec(),
                generation: id.generation(),
            });
    }
    let mut compartments = Vec::with_capacity(scopes.len() + 1);
    let mut digests = Vec::with_capacity(scopes.len());
    let chunks = scopes
        .into_iter()
        .flat_map(|(scope, bodies)| bodies.into_iter().map(move |body| (scope, body)));
    for (index, (scope, body)) in chunks.enumerate() {
        let index = u32::try_from(index + 1).map_err(|_| head_corrupt())?;
        let sealed = seal_compartment(position, index, Some(scope), &body, recipients)?;
        digests.push(*blake3::hash(&sealed.sealed).as_bytes());
        compartments.push(sealed);
    }
    let control_body = BodyWire {
        control: Some(*control.secret()),
        digests,
        live: Vec::new(),
        retired: Vec::new(),
        recipients: released,
    };
    compartments.insert(
        0,
        seal_compartment(position, 0, None, &control_body, recipients)?,
    );
    let wire = HeadWire {
        version: HEAD_VERSION,
        position: position.to_bytes().to_vec(),
        compartments,
    };
    let mut out = Zeroizing::new(HEAD_MAGIC.to_vec());
    out.extend_from_slice(&rmp_serde::to_vec_named(&wire).map_err(|_| head_corrupt())?);
    Ok(out)
}

fn parse(head: &[u8]) -> Result<HeadWire> {
    let body = head.strip_prefix(HEAD_MAGIC).ok_or_else(head_corrupt)?;
    let wire: HeadWire = rmp_serde::from_slice(body).map_err(|_| head_corrupt())?;
    if wire.version != HEAD_VERSION || wire.compartments.is_empty() {
        return Err(head_corrupt());
    }
    Ok(wire)
}

/// The position a head claims, read without opening it: what a target lists
/// and a status reports. Nothing here is authenticated until it opens.
pub(super) fn head_position(head: &[u8]) -> Result<CustodyPosition> {
    CustodyPosition::from_bytes(&parse(head)?.position).ok_or_else(head_corrupt)
}

/// The position the first bytes of a head claim, before the rest of it has
/// arrived: a residence stage an upload is still writing (FIX 6415). The
/// wire is a map whose first two entries are [`HeadWire`]'s version and
/// position, read alone here. `None` when they are not there yet, or are
/// not this engine's. Unauthenticated, as [`head_position`] is.
pub(super) fn staged_position(lead: &[u8]) -> Option<CustodyPosition> {
    use rmpv::Value;
    let body = lead.strip_prefix(HEAD_MAGIC)?;
    let shape = rmp_serde::to_vec_named(&HeadWire {
        version: HEAD_VERSION,
        position: Vec::new(),
        compartments: Vec::new(),
    })
    .ok()?;
    let (map, entries) = body.split_first()?;
    if shape.first() != Some(map) {
        return None;
    }
    let mut cursor = std::io::Cursor::new(entries);
    let version_key = rmpv::decode::read_value(&mut cursor).ok()?;
    let version = rmpv::decode::read_value(&mut cursor).ok()?;
    let position_key = rmpv::decode::read_value(&mut cursor).ok()?;
    let position = rmpv::decode::read_value(&mut cursor).ok()?;
    match (version_key, version, position_key, position) {
        (
            Value::String(version_key),
            Value::Integer(version),
            Value::String(position_key),
            Value::Binary(position),
        ) if version_key.as_str() == Some("version")
            && version.as_u64() == Some(u64::from(HEAD_VERSION))
            && position_key.as_str() == Some("position") =>
        {
            CustodyPosition::from_bytes(&position)
        }
        _ => None,
    }
}

/// The compartment key one of `wraps` gives `opener`, if any does.
fn unwrap_key(
    position: &CustodyPosition,
    id: &[u8],
    scope: Option<CompartmentScope>,
    wraps: &[WrapWire],
    opener: &CustodyOpener<'_>,
) -> Option<Zeroizing<[u8; 32]>> {
    let vault = position.vault.as_bytes();
    let opened = wraps.iter().find_map(|wrap| match (wrap.to, wrap.root) {
        (TO_ROOT, Some(root)) => {
            let secret = opener.root?;
            let policy = wrap_policy(
                Purpose::CustodyCompartmentKey,
                vault,
                &root,
                id,
                &[WrapType::HybridCapsule],
                &[KEM],
            );
            Envelope::parse(&wrap.envelope)
                .ok()?
                .open(OpenKey::Hybrid(secret), &policy)
                .ok()
        }
        (TO_DATA_KEY, None) if scope != Some(CompartmentScope::OwnerOnly) => {
            let data_key = opener.data_key.as_ref()?;
            open_sym(
                Purpose::CustodyCompartmentKey,
                position.vault,
                id,
                DATA_KEY_RECIPIENT,
                &Kek::from_bytes_ref(data_key),
                &wrap.envelope,
            )
            .ok()
        }
        _ => None,
    })?;
    if opened.len() != 32 {
        return None;
    }
    // Straight into guarded storage, never through a plain array (FIX 6048).
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&opened);
    Some(key)
}

fn open_body(
    position: &CustodyPosition,
    id: &[u8],
    key: &Zeroizing<[u8; 32]>,
    sealed: &[u8],
) -> Result<BodyWire> {
    let plain = open_sym(
        Purpose::CustodyCompartment,
        position.vault,
        id,
        COMPARTMENT_RECIPIENT,
        &Kek::from_bytes_ref(key),
        sealed,
    )?;
    rmp_serde::from_slice(&plain).map_err(|_| head_corrupt())
}

/// Opens `head` with `opener`. The control compartment must open, and it
/// must name every other compartment, in order; a compartment whose key the
/// opener holds no wrap for is listed as unopened, never skipped silently.
pub(crate) fn open_head(head: &[u8], opener: &CustodyOpener<'_>) -> Result<OpenedHead> {
    let wire = parse(head)?;
    let position = CustodyPosition::from_bytes(&wire.position).ok_or_else(head_corrupt)?;
    let pos = position.to_bytes();
    let (first, rest) = wire.compartments.split_first().ok_or_else(head_corrupt)?;
    if first.scope != 0 {
        return Err(head_corrupt());
    }
    let control_id = key_id(&pos, 0, None);
    let key = unwrap_key(&position, &control_id, None, &first.wraps, opener).ok_or_else(|| {
        crate::world_keys::refused("the custody head does not open with this key or kit")
    })?;
    let mut control = open_body(&position, &control_id, &key, &first.sealed)?;
    let secret = Zeroizing::new(control.control.ok_or_else(head_corrupt)?);
    if control.digests.len() != rest.len()
        || rest
            .iter()
            .zip(&control.digests)
            .any(|(compartment, digest)| blake3::hash(&compartment.sealed).as_bytes() != digest)
    {
        return Err(head_corrupt());
    }
    let mut opened = OpenedHead {
        position,
        control: secret,
        live: BTreeMap::new(),
        retired: BTreeSet::new(),
        unopened: BTreeSet::new(),
        recipients: std::mem::take(&mut control.recipients),
    };
    // A scope's compartments follow one another, scopes in order: one
    // canonical layout, which the control compartment's digests fix.
    let mut last: Option<CompartmentScope> = None;
    for (index, compartment) in rest.iter().enumerate() {
        let scope = CompartmentScope::from_code(compartment.scope).ok_or_else(head_corrupt)?;
        if last.is_some_and(|last| last > scope) {
            return Err(head_corrupt());
        }
        last = Some(scope);
        let index = u32::try_from(index + 1).map_err(|_| head_corrupt())?;
        let id = key_id(&pos, index, Some(scope));
        let Some(key) = unwrap_key(&position, &id, Some(scope), &compartment.wraps, opener) else {
            opened.unopened.insert(scope);
            continue;
        };
        let mut body = open_body(&position, &id, &key, &compartment.sealed)?;
        if !body.recipients.is_empty() {
            return Err(head_corrupt());
        }
        for mut entry in std::mem::take(&mut body.live) {
            let id = typed(&position, entry.kind, &entry.item, entry.generation, scope)?;
            let secret = std::mem::take(&mut entry.secret);
            if secret.len() != id.kind().secret_len() {
                return Err(head_corrupt());
            }
            opened
                .live
                .insert(id, CustodySecret::from_bytes(Zeroizing::new(secret)));
        }
        for fact in &body.retired {
            opened.retired.insert(typed(
                &position,
                fact.kind,
                &fact.item,
                fact.generation,
                scope,
            )?);
        }
    }
    Ok(opened)
}

/// The typed id a compartment names, refused in a compartment not of its
/// kind's scope.
fn typed(
    position: &CustodyPosition,
    tag: u8,
    item: &[u8],
    generation: u64,
    scope: CompartmentScope,
) -> Result<CustodyId> {
    let kind = CustodyKind::from_tag(tag).ok_or_else(head_corrupt)?;
    if CompartmentScope::of(kind) != scope {
        return Err(head_corrupt());
    }
    Ok(CustodySubject::new(position.vault, kind, item)
        .map_err(|_| head_corrupt())?
        .at(generation))
}
