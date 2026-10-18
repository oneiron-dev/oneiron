//! Bounded, canonical, signed transfer of one scoped machine-claim history,
//! one delta at a time.
//!
//! This is an untrusted wire packet, not an authority roster or an import door.
//! Packets form a chain: each names the exact previous packet by its content
//! hash and carries only the transitions new since that packet. Every packet
//! repeats the claim's one birth anchor, which is a DAG root only in the
//! genesis packet; a later packet's roots are the previous packet's heads,
//! which the host pins from that verified packet, never from the incoming one.
//! The bounds below bound one packet, so a claim's lifecycle has no cap and
//! storage grows with its transitions, not their square.
//! The host must pin genesis, signer, scope, predecessor, its heads and
//! challenge, and independently prove the signer was a live owner at the named
//! authority frontier and that the chain carries *all* scoped births and
//! transitions.

use std::collections::BTreeSet;

use crate::EntityId;
use crate::authority::{AuthorityKey, AuthoritySignature, verify_authority_signature};

/// Signature domain, distinct from authority-log and machine-claim signatures.
pub const CLAIM_HISTORY_HANDOFF_DOMAIN: &[u8] = b"oneiron/claim-history-handoff/v1";
pub const CLAIM_HISTORY_HANDOFF_VERSION: u8 = 1;
/// The leading byte of a re-root carry: the handoff layout, so the byte is in
/// both the transcript and the content hash.
pub const CLAIM_HISTORY_CARRY_VERSION: u8 = 2;
// Per-packet codec bounds: they bound one delta, never a claim's history.
const MAX_SCOPE: usize = 4096;
const MAX_BIRTHS: usize = 1024;
const MAX_TRANSITIONS: usize = 4096;
const MAX_PARENTS: usize = 64;
const MAX_WIRE: usize = 1_048_576;

/// One exact machine CLAIM birth and the digest of its canonical signed row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimBirth {
    pub id: EntityId,
    pub digest: [u8; 32],
}

/// One exact transition and its complete predecessor set. Predecessors name
/// the packet's roots (the birth digests at genesis, the previous packet's
/// heads after it) or transitions of the same delta, not floating entity IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimTransition {
    pub hash: [u8; 32],
    pub predecessors: Vec<[u8; 32]>,
}

/// What a packet's signer vouches for. Every root write (a birth, a lifecycle
/// transition, an explicit carry-forward) signs a `Handoff`. Only a host
/// re-root signs a `ReRootCarry`, at its own ReRoot, for each history it
/// carries across the move. That packet travels in the history's chain, so a
/// replica can tell a carried history from one the move left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffKind {
    Handoff,
    ReRootCarry,
}

/// Signed packet. `scope` is an opaque, host-defined *canonical* byte string:
/// producer and trusted pin must use the same codec. It is never interpreted,
/// narrowed or widened by this layer. Equality is byte-exact, not a scope guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimHistoryHandoff {
    pub kind: HandoffKind,
    pub vault_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub scope: Vec<u8>,
    /// The claim's birth anchor, repeated unchanged in every packet of the
    /// chain. A DAG root only in the genesis packet; after it, identity only.
    pub births: Vec<ClaimBirth>,
    /// Only the transitions new in this packet: its delta on the previous
    /// packet. A carry's delta is empty.
    pub transitions: Vec<ClaimTransition>,
    /// Exact maximal hashes of the whole history after this delta: each root
    /// the delta does not consume, and each of its own unconsumed transitions.
    pub heads: Vec<[u8; 32]>,
    pub authority_head: [u8; 32],
    /// Content hash of the exact previous packet; `None` only at genesis.
    pub previous_handoff_hash: Option<[u8; 32]>,
    pub nonce: [u8; 32],
    pub challenge: [u8; 32],
    /// Must be the trusted pinned host key; no received signer set is trusted.
    pub signer: AuthorityKey,
    pub signature: [u8; 64],
}

/// Wire failures refuse the packet. Missing predecessor records are separately
/// reported as `MissingParents` by the verification door.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffCodecError {
    InvalidEncoding,
    NonCanonical,
    LimitExceeded,
}

type CodecResult<T> = std::result::Result<T, HandoffCodecError>;

/// The only trusted inputs are supplied out of band by the receiving host.
#[derive(Debug, Clone, Copy)]
pub struct ClaimHistoryHandoffPin<'a> {
    pub vault_id: &'a [u8; 32],
    pub genesis_hash: &'a [u8; 32],
    pub expected_signer: &'a AuthorityKey,
    pub scope: &'a [u8],
    pub previous_handoff_hash: Option<[u8; 32]>,
    /// Heads of the exact previous packet, the delta's roots: empty at
    /// genesis. The host reads them from that verified packet or from its own
    /// stored pin, never from the packet under test.
    pub previous_heads: &'a [[u8; 32]],
    pub challenge: &'a [u8; 32],
}

/// Host callback verdict. `OwnerAndComplete` requires independently checked
/// causal owner standing at `authority_head` AND completeness of scoped births,
/// signed rows, transitions and parent closure across the whole chain. A
/// copied roster is not proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffStanding {
    OwnerAndComplete,
    MissingParents,
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffRefusal {
    InvalidPacket,
    PinMismatch,
    BadSignature,
    InvalidClosure,
    OwnerOrHistoryNotProved,
}

/// A verified digest is still not permission to mutate storage. The host can
/// use it to bind an import operation after its independent callback proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedClaimHistoryHandoff {
    pub content_hash: [u8; 32],
    pub authority_head: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffVerification {
    Verified(VerifiedClaimHistoryHandoff),
    MissingParents,
    Refused(HandoffRefusal),
}

fn sorted_unique<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|pair| pair[0] < pair[1])
}

impl ClaimHistoryHandoff {
    fn check_shape(&self) -> CodecResult<()> {
        if self.scope.is_empty()
            || self.scope.len() > MAX_SCOPE
            || self.births.is_empty()
            || self.births.len() > MAX_BIRTHS
            || self.transitions.len() > MAX_TRANSITIONS
            || self.heads.is_empty()
            || self.heads.len() > MAX_BIRTHS + MAX_TRANSITIONS
            || self
                .transitions
                .iter()
                .any(|t| t.predecessors.is_empty() || t.predecessors.len() > MAX_PARENTS)
        {
            return Err(HandoffCodecError::LimitExceeded);
        }
        if !sorted_unique_by(&self.births, |b| b.id)
            || !sorted_unique_by(&self.transitions, |t| t.hash)
            || !sorted_unique(&self.heads)
            || self
                .transitions
                .iter()
                .any(|t| !sorted_unique(&t.predecessors))
        {
            return Err(HandoffCodecError::NonCanonical);
        }
        match &self.signer {
            AuthorityKey::Ed25519(_) => {}
            AuthorityKey::P256(bytes) if bytes.len() == 33 && (bytes[0] == 2 || bytes[0] == 3) => {}
            AuthorityKey::P256(_) => return Err(HandoffCodecError::NonCanonical),
        }
        Ok(())
    }

    fn body(&self) -> CodecResult<Vec<u8>> {
        self.check_shape()?;
        let mut out = Vec::new();
        out.push(match self.kind {
            HandoffKind::Handoff => CLAIM_HISTORY_HANDOFF_VERSION,
            HandoffKind::ReRootCarry => CLAIM_HISTORY_CARRY_VERSION,
        });
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.genesis_hash);
        put_bytes(&mut out, &self.scope);
        put_count(&mut out, self.births.len());
        for birth in &self.births {
            out.extend_from_slice(birth.id.as_bytes());
            out.extend_from_slice(&birth.digest);
        }
        put_count(&mut out, self.transitions.len());
        for transition in &self.transitions {
            out.extend_from_slice(&transition.hash);
            put_count(&mut out, transition.predecessors.len());
            for parent in &transition.predecessors {
                out.extend_from_slice(parent);
            }
        }
        put_count(&mut out, self.heads.len());
        for head in &self.heads {
            out.extend_from_slice(head);
        }
        out.extend_from_slice(&self.authority_head);
        match self.previous_handoff_hash {
            Some(hash) => {
                out.push(1);
                out.extend_from_slice(&hash);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.challenge);
        match &self.signer {
            AuthorityKey::Ed25519(bytes) => {
                out.push(1);
                out.extend_from_slice(bytes);
            }
            AuthorityKey::P256(bytes) => {
                out.push(2);
                out.extend_from_slice(bytes);
            }
        }
        if out.len() + 64 > MAX_WIRE {
            return Err(HandoffCodecError::LimitExceeded);
        }
        Ok(out)
    }

    /// Exact bytes to sign. Signature is excluded; every other field is bound.
    pub fn transcript(&self) -> CodecResult<Vec<u8>> {
        let body = self.body()?;
        let mut out = Vec::with_capacity(CLAIM_HISTORY_HANDOFF_DOMAIN.len() + 4 + body.len());
        out.extend_from_slice(CLAIM_HISTORY_HANDOFF_DOMAIN);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Deterministic versioned wire encoding, including the fixed-width signature.
    pub fn encode(&self) -> CodecResult<Vec<u8>> {
        let mut out = self.body()?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Hash of the entire canonical signed packet, including the signature.
    pub fn content_hash(&self) -> CodecResult<[u8; 32]> {
        let bytes = self.encode()?;
        let mut hasher = blake3::Hasher::new_derive_key("oneiron/claim-history-handoff-content/v1");
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }

    /// Strict bounded decoder: no omitted fields, trailing bytes or alternate
    /// ordering; unknown versions fail closed rather than aliasing a known kind.
    pub fn decode(bytes: &[u8]) -> CodecResult<Self> {
        if bytes.len() > MAX_WIRE {
            return Err(HandoffCodecError::LimitExceeded);
        }
        let mut cursor = Cursor { bytes, at: 0 };
        let kind = match cursor.take::<1>()?[0] {
            CLAIM_HISTORY_HANDOFF_VERSION => HandoffKind::Handoff,
            CLAIM_HISTORY_CARRY_VERSION => HandoffKind::ReRootCarry,
            _ => return Err(HandoffCodecError::InvalidEncoding),
        };
        let vault_id = cursor.take()?;
        let genesis_hash = cursor.take()?;
        let scope = cursor.variable(MAX_SCOPE)?;
        let births_len = cursor.count(MAX_BIRTHS)?;
        let mut births = Vec::with_capacity(births_len);
        for _ in 0..births_len {
            let id = EntityId::from_bytes(cursor.take()?)
                .map_err(|_| HandoffCodecError::InvalidEncoding)?;
            births.push(ClaimBirth {
                id,
                digest: cursor.take()?,
            });
        }
        let transitions_len = cursor.count(MAX_TRANSITIONS)?;
        let mut transitions = Vec::with_capacity(transitions_len);
        for _ in 0..transitions_len {
            let hash = cursor.take()?;
            let parents_len = cursor.count(MAX_PARENTS)?;
            let mut predecessors = Vec::with_capacity(parents_len);
            for _ in 0..parents_len {
                predecessors.push(cursor.take()?);
            }
            transitions.push(ClaimTransition { hash, predecessors });
        }
        let heads_len = cursor.count(MAX_BIRTHS + MAX_TRANSITIONS)?;
        let mut heads = Vec::with_capacity(heads_len);
        for _ in 0..heads_len {
            heads.push(cursor.take()?);
        }
        let authority_head = cursor.take()?;
        let previous_handoff_hash = match cursor.take::<1>()?[0] {
            0 => None,
            1 => Some(cursor.take()?),
            _ => return Err(HandoffCodecError::InvalidEncoding),
        };
        let nonce = cursor.take()?;
        let challenge = cursor.take()?;
        let signer = match cursor.take::<1>()?[0] {
            1 => AuthorityKey::Ed25519(cursor.take()?),
            2 => AuthorityKey::P256(cursor.take::<33>()?.to_vec()),
            _ => return Err(HandoffCodecError::InvalidEncoding),
        };
        let signature = cursor.take()?;
        if cursor.at != bytes.len() {
            return Err(HandoffCodecError::InvalidEncoding);
        }
        let result = Self {
            kind,
            vault_id,
            genesis_hash,
            scope,
            births,
            transitions,
            heads,
            authority_head,
            previous_handoff_hash,
            nonce,
            challenge,
            signer,
            signature,
        };
        result.check_shape()?;
        Ok(result)
    }
}

fn sorted_unique_by<T, K: Ord>(items: &[T], key: impl Fn(&T) -> K) -> bool {
    items.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}
fn put_count(out: &mut Vec<u8>, count: usize) {
    out.extend_from_slice(&(count as u16).to_be_bytes());
}
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_count(out, bytes.len());
    out.extend_from_slice(bytes);
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl Cursor<'_> {
    fn slice(&mut self, len: usize) -> CodecResult<&[u8]> {
        let end = self
            .at
            .checked_add(len)
            .ok_or(HandoffCodecError::InvalidEncoding)?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or(HandoffCodecError::InvalidEncoding)?;
        self.at = end;
        Ok(slice)
    }
    fn take<const N: usize>(&mut self) -> CodecResult<[u8; N]> {
        self.slice(N)?
            .try_into()
            .map_err(|_| HandoffCodecError::InvalidEncoding)
    }
    fn count(&mut self, max: usize) -> CodecResult<usize> {
        let count = usize::from(u16::from_be_bytes(self.take()?));
        if count > max {
            return Err(HandoffCodecError::LimitExceeded);
        }
        Ok(count)
    }
    fn variable(&mut self, max: usize) -> CodecResult<Vec<u8>> {
        let len = self.count(max)?;
        Ok(self.slice(len)?.to_vec())
    }
}

/// How one packet's delta closes over its roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeltaClosure {
    /// Every transition reduces from the roots and the heads are exact.
    Closed,
    /// A predecessor is neither a root nor a transition of this delta.
    MissingParents,
    /// A duplicate, a transition that repeats a root, a cycle or wrong heads.
    Invalid,
}

/// The closure of `packet`'s delta over its roots R: the birth digests at
/// genesis (`previous_heads` must then be empty), else `previous_heads`, the
/// heads of the exact previous packet. With D the delta's transition hashes,
/// P their predecessors and U = R ∪ D: D is duplicate-free and disjoint from
/// R, every predecessor set is nonempty and canonical, P ⊆ U, D reduces
/// topologically from R, and the heads are exactly U \ P, so a previous head
/// the delta does not consume stays a head. Pure: it reads this packet only.
pub(crate) fn handoff_delta_closure(
    packet: &ClaimHistoryHandoff,
    previous_heads: &[[u8; 32]],
) -> DeltaClosure {
    let (roots, listed): (BTreeSet<[u8; 32]>, usize) = match packet.previous_handoff_hash {
        None if previous_heads.is_empty() => (
            packet.births.iter().map(|b| b.digest).collect(),
            packet.births.len(),
        ),
        None => return DeltaClosure::Invalid,
        // After genesis the birth anchor is identity, not a node: it never
        // comes back as a head.
        Some(_) => (
            previous_heads.iter().copied().collect(),
            previous_heads.len(),
        ),
    };
    let delta: BTreeSet<[u8; 32]> = packet.transitions.iter().map(|t| t.hash).collect();
    if roots.is_empty()
        || roots.len() != listed
        || delta.len() != packet.transitions.len()
        || !delta.is_disjoint(&roots)
        || packet
            .transitions
            .iter()
            .any(|t| t.predecessors.is_empty() || !sorted_unique(&t.predecessors))
    {
        return DeltaClosure::Invalid;
    }
    let all: BTreeSet<[u8; 32]> = roots.union(&delta).copied().collect();
    let predecessor_set: BTreeSet<[u8; 32]> = packet
        .transitions
        .iter()
        .flat_map(|t| t.predecessors.iter().copied())
        .collect();
    if !predecessor_set.is_subset(&all) {
        return DeltaClosure::MissingParents;
    }
    // An edge must not point to itself or to a cycle. Every node must reach
    // some declared head. A topological reduction from the roots proves
    // acyclicity.
    let mut seen = roots;
    let mut remaining = delta;
    loop {
        let ready: Vec<_> = packet
            .transitions
            .iter()
            .filter(|t| {
                remaining.contains(&t.hash) && t.predecessors.iter().all(|p| seen.contains(p))
            })
            .map(|t| t.hash)
            .collect();
        if ready.is_empty() {
            break;
        }
        for hash in ready {
            remaining.remove(&hash);
            seen.insert(hash);
        }
    }
    if !remaining.is_empty()
        || all
            .difference(&predecessor_set)
            .copied()
            .collect::<Vec<_>>()
            != packet.heads
    {
        return DeltaClosure::Invalid;
    }
    DeltaClosure::Closed
}

/// Pure, fail-closed verifier of one packet of a chain. The callback MUST
/// independently establish: (1) causal host-owner standing at
/// `authority_head` from local signed log parents (not a packet roster);
/// (2) exact, complete scoped birth IDs and canonical row digests; (3) that
/// the chain behind this packet is present and closed, so the pinned previous
/// heads and this delta together name the whole history.
/// It can return `MissingParents` if its local authority/claim history is not
/// yet complete. No timestamp, network identity, or packet-asserted roster
/// grants authority here. This method never mutates a store.
pub fn verify_claim_history_handoff(
    packet: &ClaimHistoryHandoff,
    pin: &ClaimHistoryHandoffPin<'_>,
    standing: impl FnOnce(&ClaimHistoryHandoff) -> HandoffStanding,
) -> HandoffVerification {
    if packet.check_shape().is_err() {
        return HandoffVerification::Refused(HandoffRefusal::InvalidPacket);
    }
    if packet.vault_id != *pin.vault_id
        || packet.genesis_hash != *pin.genesis_hash
        || packet.signer != *pin.expected_signer
        || packet.scope.as_slice() != pin.scope
        || packet.previous_handoff_hash != pin.previous_handoff_hash
        || pin.previous_handoff_hash.is_none() != pin.previous_heads.is_empty()
        || !sorted_unique(pin.previous_heads)
        || packet.challenge != *pin.challenge
    {
        return HandoffVerification::Refused(HandoffRefusal::PinMismatch);
    }
    let Ok(transcript) = packet.transcript() else {
        return HandoffVerification::Refused(HandoffRefusal::InvalidPacket);
    };
    let signature = AuthoritySignature {
        suite: packet.signer.suite(),
        public_key: packet.signer.clone(),
        signature: packet.signature.to_vec(),
    };
    if !verify_authority_signature(&signature, &transcript) {
        return HandoffVerification::Refused(HandoffRefusal::BadSignature);
    }
    match handoff_delta_closure(packet, pin.previous_heads) {
        DeltaClosure::Closed => {}
        DeltaClosure::MissingParents => return HandoffVerification::MissingParents,
        DeltaClosure::Invalid => {
            return HandoffVerification::Refused(HandoffRefusal::InvalidClosure);
        }
    }
    match standing(packet) {
        HandoffStanding::OwnerAndComplete => match packet.content_hash() {
            Ok(content_hash) => HandoffVerification::Verified(VerifiedClaimHistoryHandoff {
                content_hash,
                authority_head: packet.authority_head,
            }),
            Err(_) => HandoffVerification::Refused(HandoffRefusal::InvalidPacket),
        },
        HandoffStanding::MissingParents => HandoffVerification::MissingParents,
        HandoffStanding::Refused => {
            HandoffVerification::Refused(HandoffRefusal::OwnerOrHistoryNotProved)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn packet(signing: &SigningKey) -> ClaimHistoryHandoff {
        let id = EntityId::from_bytes([1; 16]).expect("claim id");
        ClaimHistoryHandoff {
            kind: HandoffKind::Handoff,
            vault_id: [2; 32],
            genesis_hash: [3; 32],
            scope: b"canonical-scope-v1".to_vec(),
            births: vec![ClaimBirth {
                id,
                digest: [4; 32],
            }],
            transitions: vec![ClaimTransition {
                hash: [5; 32],
                predecessors: vec![[4; 32]],
            }],
            heads: vec![[5; 32]],
            authority_head: [6; 32],
            previous_handoff_hash: Some([7; 32]),
            nonce: [8; 32],
            challenge: [9; 32],
            signer: AuthorityKey::Ed25519(signing.verifying_key().to_bytes()),
            signature: [0; 64],
        }
    }
    fn sign(packet: &mut ClaimHistoryHandoff, key: &SigningKey) {
        packet.signature = key
            .sign(&packet.transcript().expect("transcript"))
            .to_bytes();
    }
    fn pin<'a>(p: &'a ClaimHistoryHandoff) -> ClaimHistoryHandoffPin<'a> {
        ClaimHistoryHandoffPin {
            vault_id: &p.vault_id,
            genesis_hash: &p.genesis_hash,
            expected_signer: &p.signer,
            scope: &p.scope,
            previous_handoff_hash: p.previous_handoff_hash,
            challenge: &p.challenge,
        }
    }
    fn good(_: &ClaimHistoryHandoff) -> HandoffStanding {
        HandoffStanding::OwnerAndComplete
    }

    #[test]
    fn roundtrip_hash_and_exact_verified_packet() {
        let signer = SigningKey::from_bytes(&[11; 32]);
        let mut p = packet(&signer);
        sign(&mut p, &signer);
        let bytes = p.encode().unwrap();
        let decoded = ClaimHistoryHandoff::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
        assert_eq!(decoded.encode().unwrap(), bytes);
        assert!(
            matches!(verify_claim_history_handoff(&decoded, &pin(&p), good),
            HandoffVerification::Verified(v) if v.content_hash == p.content_hash().unwrap())
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            ClaimHistoryHandoff::decode(&trailing),
            Err(HandoffCodecError::InvalidEncoding)
        );
    }

    #[test]
    fn genesis_previous_challenge_and_scope_are_trusted_pins() {
        let signer = SigningKey::from_bytes(&[11; 32]);
        let mut p = packet(&signer);
        sign(&mut p, &signer);
        let wrong_genesis = [0; 32];
        let wrong = ClaimHistoryHandoffPin {
            genesis_hash: &wrong_genesis,
            ..pin(&p)
        };
        assert_eq!(
            verify_claim_history_handoff(&p, &wrong, good),
            HandoffVerification::Refused(HandoffRefusal::PinMismatch)
        );
        let wrong = ClaimHistoryHandoffPin {
            previous_handoff_hash: None,
            ..pin(&p)
        };
        assert_eq!(
            verify_claim_history_handoff(&p, &wrong, good),
            HandoffVerification::Refused(HandoffRefusal::PinMismatch)
        );
        let wrong_challenge = [0; 32];
        let wrong = ClaimHistoryHandoffPin {
            challenge: &wrong_challenge,
            ..pin(&p)
        };
        assert_eq!(
            verify_claim_history_handoff(&p, &wrong, good),
            HandoffVerification::Refused(HandoffRefusal::PinMismatch)
        );
        let wrong = ClaimHistoryHandoffPin {
            scope: b"other-scope",
            ..pin(&p)
        };
        assert_eq!(
            verify_claim_history_handoff(&p, &wrong, good),
            HandoffVerification::Refused(HandoffRefusal::PinMismatch)
        );
        let trusted = ClaimHistoryHandoff::decode(&p.encode().unwrap()).unwrap();
        p.scope[0] ^= 1;
        let tampered_pin = pin(&p);
        assert_eq!(
            verify_claim_history_handoff(&trusted, &tampered_pin, good),
            HandoffVerification::Refused(HandoffRefusal::PinMismatch)
        );
    }

    #[test]
    fn absent_predecessor_requires_parents_even_when_signed() {
        let signer = SigningKey::from_bytes(&[11; 32]);
        let mut p = packet(&signer);
        p.transitions[0].predecessors = vec![[10; 32]];
        sign(&mut p, &signer);
        assert_eq!(
            verify_claim_history_handoff(&p, &pin(&p), good),
            HandoffVerification::MissingParents
        );
    }

    #[test]
    fn retired_signer_and_incomplete_authority_frontier_never_pass() {
        let signer = SigningKey::from_bytes(&[11; 32]);
        let mut p = packet(&signer);
        sign(&mut p, &signer);
        assert_eq!(
            verify_claim_history_handoff(&p, &pin(&p), |_| HandoffStanding::Refused),
            HandoffVerification::Refused(HandoffRefusal::OwnerOrHistoryNotProved)
        );
        assert_eq!(
            verify_claim_history_handoff(&p, &pin(&p), |_| HandoffStanding::MissingParents),
            HandoffVerification::MissingParents
        );
        let other_signer =
            AuthorityKey::Ed25519(SigningKey::from_bytes(&[12; 32]).verifying_key().to_bytes());
        let wrong = ClaimHistoryHandoffPin {
            expected_signer: &other_signer,
            ..pin(&p)
        };
        assert_eq!(
            verify_claim_history_handoff(&p, &wrong, good),
            HandoffVerification::Refused(HandoffRefusal::PinMismatch)
        );
    }

    #[test]
    fn tampered_body_fails_signature_and_cycles_fail_closure() {
        let signer = SigningKey::from_bytes(&[11; 32]);
        let mut p = packet(&signer);
        sign(&mut p, &signer);
        p.births[0].digest = [12; 32];
        assert_eq!(
            verify_claim_history_handoff(&p, &pin(&p), good),
            HandoffVerification::Refused(HandoffRefusal::BadSignature)
        );
        p.transitions[0].predecessors = vec![[5; 32]];
        sign(&mut p, &signer);
        assert_eq!(
            verify_claim_history_handoff(&p, &pin(&p), good),
            HandoffVerification::Refused(HandoffRefusal::InvalidClosure)
        );
    }
}
