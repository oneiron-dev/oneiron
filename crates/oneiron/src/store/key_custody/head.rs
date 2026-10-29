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
//! authenticates its anchor records, and one fixed-size root over every
//! other compartment's digest in order, with their count, so no compartment
//! is dropped, added, moved or transplanted from another head (FIX 5800).
//! A head holds no frozen requirement: a restore asks it for what its image
//! needs. A world's pads may go in a
//! compartment of their own, wrapped to the world's admitted machines and
//! roots alone (`pad_scope`, FIX 6706); that is off for now. A world
//! compartment holds one pad, and the control compartment commits to each
//! compartment's whole wire, so a restore that does not open one carries it
//! on as it is (`carried_pads`, PAD-3, FIX 11133).

use std::collections::{BTreeMap, BTreeSet};

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, Kek, OpenKey, OpenPolicy, Purpose, SealKey, SealParams, SuiteId,
    WrapType, seal,
};
use zeroize::Zeroizing;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::body_history::HistoryRows;
use super::erase_evidence::{CredentialFenceFact, FenceFact, fold_fact};
use super::identity::{CustodyId, CustodyKind, CustodySecret, CustodySubject};
use super::log::{AEAD, CRYPTO_EPOCH, Control, CustodyPosition, open_sym, seal_refused, seal_sym};
use super::recipients::RecipientRetirement;

mod carried_pads;
mod pad_scope;
mod scope;
mod wire;

pub(super) use self::carried_pads::{CARRIED_PREFIX, CarriedWorldPad, carried_set_digest};

#[allow(
    unused_imports,
    reason = "L03 02A's pad hydration (FIX 6706) reaches these through crate::store"
)]
pub(crate) use self::pad_scope::{
    OpenedWorldPads, PadRecipients, SealedWorldPads, WorldPadScope, open_world_pad_compartment,
    seal_world_pad_compartment,
};
pub(crate) use self::scope::{CompartmentScope, CustodyOpener, CustodyRecipients};
use self::wire::{
    Bodies, BodyWire, CompartmentWire, DigestRoot, EntryWire, EvidenceWire, FactWire, HEAD_MAGIC,
    HEAD_VERSION, HeadWire, HistoryJoin, WrapWire, key_id, parse,
};
pub(super) use self::wire::{head_position, serde_bytes_vec, staged_position};

const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;
const DATA_KEY_RECIPIENT: &[u8] = b"oneiron/custody-head/data-key/v1";
const COMPARTMENT_RECIPIENT: &[u8] = b"oneiron/custody-head/compartment/v1";
const TO_ROOT: u8 = 1;
const TO_DATA_KEY: u8 = 2;

/// The context of the vault data key's subkey a host-readable compartment
/// is also wrapped under.
pub(crate) const CUSTODY_HEAD_WRAP_CONTEXT: &str = "oneiron/custody-head/v1";

pub(super) fn head_corrupt() -> Error {
    Error::CorruptedIndex("key custody head")
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
    /// The lineage's body history at the head's position (FIX 6229), from
    /// the host-readable compartments the opener opened.
    pub(super) history: HistoryRows,
    /// Each erased credential's fact at the head's position (FIX 10584 item
    /// 3), from the host-readable compartments the opener opened.
    pub(super) evidence: BTreeMap<EntityId, FenceFact>,
    /// The world pad compartments the opener did not open, the head's own
    /// and those it carried, each at its origin coordinates (PAD-3).
    pub(super) carried: Vec<CarriedWorldPad>,
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
    let world = scope.and_then(CompartmentScope::world);
    // A world's pads: its admitted machines and roots alone, never the data
    // key or the generic root wrap (FIX 6706).
    if let Some(world) = world {
        let admitted = recipients.pad_worlds.get(&world);
        let wraps = pad_scope::wrap_to_world(position, &id, &key, admitted)?;
        return Ok(CompartmentWire {
            scope: scope.map_or(0, CompartmentScope::code),
            world: Some(*world.as_bytes()),
            pad: Some(carried_pads::PadCompartmentIdentity::of(body)?),
            sealed,
            wraps,
        });
    }
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
            machine: None,
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
            machine: None,
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
        world: None,
        pad: None,
        sealed,
        wraps,
    })
}

/// Seals a head at `position` holding `entries`, the retirement facts
/// `retired`, the released escrow recipients `released` retired, the body
/// history `history`, the erased credentials' facts `evidence` and each of
/// the `carried` world compartments `recipients` admit (PAD-3), wrapped to
/// `recipients`. The bytes are key-bearing: they go only to a custody
/// target, never to a log, error or receipt.
#[allow(
    clippy::too_many_arguments,
    reason = "one head's whole content, each part its own kind"
)]
pub(super) fn seal_head(
    position: &CustodyPosition,
    control: &Control,
    entries: Vec<HeadEntry>,
    retired: Vec<CustodyId>,
    released: Vec<RecipientRetirement>,
    history: &HistoryRows,
    evidence: &BTreeMap<EntityId, FenceFact>,
    carried: &[CarriedWorldPad],
    recipients: &CustodyRecipients,
) -> Result<Zeroizing<Vec<u8>>> {
    // Each scope's rows go in as many compartments as they fill, each at
    // most a pacing bound of plaintext bytes and a world's one pad (PAD-3):
    // a head grows with its custody, never past one envelope's bound and
    // never capped (Rule 5, FIX 5800).
    let mut bodies = Bodies::default();
    for entry in entries {
        let scope = CompartmentScope::of(entry.id.subject())?;
        let item = entry.id.subject().item();
        let secret = entry.secret.expose();
        bodies
            .body(scope, item.len() + secret.len())
            .live
            .push(EntryWire {
                kind: entry.id.kind().tag(),
                item: item.to_vec(),
                generation: entry.id.generation(),
                secret: secret.to_vec(),
            });
    }
    for id in retired {
        let scope = recipients.fact_scope(&id)?;
        let item = id.subject().item();
        bodies.body(scope, item.len()).retired.push(FactWire {
            kind: id.kind().tag(),
            item: item.to_vec(),
            generation: id.generation(),
        });
    }
    // The body history rides with the host-readable keys it retires, a
    // large row in fragments.
    for (key, value) in history {
        bodies.push_history(key, value)?;
    }
    // Every erased credential's fact rides the host-readable compartments,
    // whatever key eligibility keeps local (FIX 10584 item 3).
    for (credential, fact) in evidence {
        bodies
            .body(CompartmentScope::HostReadable, 16)
            .evidence
            .push(EvidenceWire {
                credential: *credential.as_bytes(),
                fact: fact.code(),
            });
    }
    // The released escrow recipients are paged with them, public facts only
    // (FIX 5800), so the control compartment stays one size.
    for retirement in released {
        let bytes = rmp_serde::to_vec_named(&retirement)
            .map_err(|_| head_corrupt())?
            .len();
        bodies
            .body(CompartmentScope::HostReadable, bytes)
            .recipients
            .push(retirement);
    }
    let mut compartments = Vec::new();
    let mut digests = Vec::new();
    for (index, (scope, body)) in bodies.into_bodies().enumerate() {
        let index = u32::try_from(index + 1).map_err(|_| head_corrupt())?;
        let sealed = seal_compartment(position, index, Some(scope), &body, recipients)?;
        digests.push(carried_pads::wire_digest(&sealed)?);
        compartments.push(sealed);
    }
    let (carried_world_pads, carried_digests) = carried_pads::eligible(carried, recipients)?;
    let control_body = BodyWire {
        control: Some(*control.secret()),
        root: Some(carried_pads::digest_root(&digests, &carried_digests)?),
        live: Vec::new(),
        retired: Vec::new(),
        recipients: Vec::new(),
        history: Vec::new(),
        evidence: Vec::new(),
    };
    compartments.insert(
        0,
        seal_compartment(position, 0, None, &control_body, recipients)?,
    );
    let wire = HeadWire {
        version: HEAD_VERSION,
        position: position.to_bytes().to_vec(),
        compartments,
        carried_world_pads,
    };
    let mut out = Zeroizing::new(HEAD_MAGIC.to_vec());
    out.extend_from_slice(&rmp_serde::to_vec_named(&wire).map_err(|_| head_corrupt())?);
    Ok(out)
}

/// The compartment key one of `wraps` gives `opener`, if any does.
fn unwrap_key(
    position: &CustodyPosition,
    id: &[u8],
    scope: Option<CompartmentScope>,
    wraps: &[WrapWire],
    opener: &CustodyOpener<'_>,
) -> Option<Zeroizing<[u8; 32]>> {
    // A world's pads open only with an admitted machine's or root's own
    // wrap, never the data key's or the generic root wrap (FIX 6706).
    if scope.and_then(CompartmentScope::world).is_some() {
        return pad_scope::unwrap_world(position, id, wraps, opener.machine, opener.root);
    }
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
    guarded_key(&opened)
}

/// A 32-byte key straight into guarded storage, never through a plain
/// array (FIX 6048); `None` for any other length.
fn guarded_key(opened: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    if opened.len() != 32 {
        return None;
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(opened);
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
/// must name every other compartment and every carried one, whole and in
/// order; a compartment whose key the opener holds no wrap for is listed as
/// unopened, never skipped silently, and a world's is carried (PAD-3).
pub(crate) fn open_head(head: &[u8], opener: &CustodyOpener<'_>) -> Result<OpenedHead> {
    let mut wire = parse(head)?;
    let carried = std::mem::take(&mut wire.carried_world_pads);
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
    let control = open_body(&position, &control_id, &key, &first.sealed)?;
    let secret = Zeroizing::new(control.control.ok_or_else(head_corrupt)?);
    let root: DigestRoot = control.root.ok_or_else(head_corrupt)?;
    if !control.history.is_empty()
        || !control.evidence.is_empty()
        || !control.recipients.is_empty()
        || !carried_pads::committed(rest, &carried, &root)?
    {
        return Err(head_corrupt());
    }
    let provenance = carried_pads::provenance(head, &first.sealed);
    let mut opened = OpenedHead {
        position,
        control: secret,
        live: BTreeMap::new(),
        retired: BTreeSet::new(),
        unopened: BTreeSet::new(),
        recipients: Vec::new(),
        history: BTreeMap::new(),
        evidence: BTreeMap::new(),
        carried: Vec::new(),
    };
    // A scope's compartments follow one another, scopes in order: one
    // canonical layout, which the control compartment's digests fix.
    let mut last: Option<CompartmentScope> = None;
    let mut history = HistoryJoin::default();
    for (index, compartment) in rest.iter().enumerate() {
        let scope = CompartmentScope::from_wire(compartment.scope, compartment.world)
            .ok_or_else(head_corrupt)?;
        if last.is_some_and(|last| last > scope)
            || compartment.pad.is_some() != scope.world().is_some()
        {
            return Err(head_corrupt());
        }
        last = Some(scope);
        let index = u32::try_from(index + 1).map_err(|_| head_corrupt())?;
        let id = key_id(&pos, index, Some(scope));
        let Some(key) = unwrap_key(&position, &id, Some(scope), &compartment.wraps, opener) else {
            opened.unopened.insert(scope);
            carried_pads::left_unopened(&mut opened, index, scope, compartment, provenance)?;
            continue;
        };
        let mut body = open_body(&position, &id, &key, &compartment.sealed)?;
        if body.root.is_some()
            || ((!body.history.is_empty()
                || !body.evidence.is_empty()
                || !body.recipients.is_empty())
                && scope != CompartmentScope::HostReadable)
        {
            return Err(head_corrupt());
        }
        opened.recipients.append(&mut body.recipients);
        carried_pads::check_pad(compartment.pad.as_ref(), &body)?;
        for wire in &body.evidence {
            let fact = CredentialFenceFact {
                credential: EntityId::from_bytes(wire.credential).map_err(|_| head_corrupt())?,
                fact: FenceFact::from_code(wire.fact).ok_or_else(head_corrupt)?,
            };
            fold_fact(&mut opened.evidence, fact);
        }
        for row in std::mem::take(&mut body.history) {
            if !super::body_history::admits(&row.key) {
                return Err(head_corrupt());
            }
            history.push(row, &mut opened.history)?;
        }
        // A world's compartment names each of its pads once, live or
        // retired, never both (FIX 6706).
        let world = scope.world().is_some();
        for mut entry in std::mem::take(&mut body.live) {
            let id = typed(
                &position,
                entry.kind,
                &entry.item,
                entry.generation,
                scope,
                false,
            )?;
            let secret = std::mem::take(&mut entry.secret);
            if secret.len() != id.kind().secret_len() {
                return Err(head_corrupt());
            }
            let secret = CustodySecret::from_bytes(Zeroizing::new(secret));
            // A pad an unopened compartment names retired is not live too.
            if world && opened.retired.contains(&id) {
                return Err(head_corrupt());
            }
            if opened.live.insert(id, secret).is_some() && world {
                return Err(head_corrupt());
            }
        }
        for fact in &body.retired {
            let id = typed(
                &position,
                fact.kind,
                &fact.item,
                fact.generation,
                scope,
                true,
            )?;
            if world && (opened.live.contains_key(&id) || opened.retired.contains(&id)) {
                return Err(head_corrupt());
            }
            opened.retired.insert(id);
        }
    }
    history.finish()?;
    carried_pads::open_carried(&mut opened, carried, opener)?;
    Ok(opened)
}

/// The typed id a compartment names, refused in a compartment not of its
/// subject's scope; a world's pad is custody generation 0. A world pad's
/// retirement `fact` may ride the host-readable compartment as well
/// ([`CustodyRecipients::fact_scope`], FIX 9178); its live pad never does.
fn typed(
    position: &CustodyPosition,
    tag: u8,
    item: &[u8],
    generation: u64,
    scope: CompartmentScope,
    fact: bool,
) -> Result<CustodyId> {
    let kind = CustodyKind::from_tag(tag).ok_or_else(head_corrupt)?;
    let subject = CustodySubject::new(position.vault, kind, item).map_err(|_| head_corrupt())?;
    let own = CompartmentScope::of(&subject).map_err(|_| head_corrupt())?;
    let host_fact = fact && own.world().is_some() && scope == CompartmentScope::HostReadable;
    if (own != scope && !host_fact) || (own.world().is_some() && generation != 0) {
        return Err(head_corrupt());
    }
    Ok(subject.at(generation))
}
