use super::{
    MAX_INPUT_BYTES, MAX_PARTS, PART_LABEL, input_digest, part_digest, part_key, parts_digest,
};
#[cfg(feature = "sync")]
use super::{PART_BYTES, refused, splits};
use crate::authority::AuthorityEntryHash;
#[cfg(feature = "sync")]
use crate::authority::{
    AuthorityEntryRead, AuthorityFold, AuthorityFoldIssue, AuthorityKey, AuthorityOp,
    OwnerWorkBody, OwnerWorkRequest, authority_entry_hash, read_authority_log_entry_body,
};
#[cfg(feature = "sync")]
use crate::error::Result;

/// A relayed input's frame: the second it was sealed at, the request, then
/// its witness's length. The witness and the row's body follow, each at most
/// [`MAX_INPUT_BYTES`]: the whole input, or one part of it.
const FRAME_BYTES: usize = 8 + 32 + 4;

/// Where one row's bytes sit in a split input: the part's index, and every
/// part's digest in order, which the digest the request names is over.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct InputPart {
    pub(super) index: u32,
    pub(super) digests: Vec<[u8; 32]>,
}

/// One input as it is kept and relayed: the second it was sealed at, whose
/// month's base window carries it, the request it is for, that request's
/// witness and its envelope, whole or one part of it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RelayedInput {
    pub(crate) sealed_at: u64,
    pub(crate) request: AuthorityEntryHash,
    /// The request's signed authority entry, canonical (FIX 4996). It rides
    /// outside the envelope's digest, which the request names.
    pub(crate) witness: Vec<u8>,
    /// Where `envelope` sits in the input the request names; `None` while
    /// it is the whole.
    pub(crate) part: Option<InputPart>,
    /// The whole input, or this part's bytes.
    pub(crate) envelope: Vec<u8>,
}

/// What an input's witness proves: the request, and the install key that
/// signed it, when it is one.
#[cfg(feature = "sync")]
pub(crate) struct Witnessed {
    key: Option<[u8; 32]>,
    request: OwnerWorkRequest,
}

#[cfg(feature = "sync")]
impl Witnessed {
    /// Whether `fold` judged the request entry `hash` invalid with its
    /// signer folded (FIX 4996): a chain of its carrier this install reads
    /// (never another anchor's: FIX
    /// FOREIGN-ANCHOR-CHAIN-COUNTS-IN-EVERY-CHAIN-PREDICATES) names the key
    /// that signed it, and the fold holds an issue for exactly this entry,
    /// other than one that waits on a parent not here yet.
    pub(crate) fn folded_invalid(&self, fold: &AuthorityFold, hash: &AuthorityEntryHash) -> bool {
        let Some(key) = &self.key else {
            return false;
        };
        fold.machine(self.request.carrier)
            .is_some_and(|machine| machine.names_key_under(key, fold.pinned_root.as_ref()))
            && fold.issues.iter().any(|issue| match issue {
                AuthorityFoldIssue::InvalidEntry(entry)
                | AuthorityFoldIssue::RetiredSigner(entry)
                | AuthorityFoldIssue::SignerNotInAncestry(entry)
                | AuthorityFoldIssue::NonMonotonicSeq(entry)
                | AuthorityFoldIssue::WrongVault(entry) => entry == hash,
                _ => false,
            })
    }
}

// Never print the ciphertext.
impl std::fmt::Debug for RelayedInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayedInput")
            .field("sealed_at", &self.sealed_at)
            .field(
                "part",
                &self
                    .part
                    .as_ref()
                    .map(|part| (part.index, part.digests.len())),
            )
            .field("bytes", &self.envelope.len())
            .finish_non_exhaustive()
    }
}

impl RelayedInput {
    /// The frame, the witness, then the body: the envelope, or for a part
    /// its label, index, part count and part digests, then its bytes. A
    /// witness longer than a `u32` is never framed: [`Self::decode`] refuses
    /// one past [`MAX_INPUT_BYTES`].
    pub(crate) fn encode(&self) -> Vec<u8> {
        let witness_len = u32::try_from(self.witness.len()).unwrap_or(u32::MAX);
        let listed = self.part.as_ref().map_or(0, |part| part.digests.len());
        let mut out = Vec::with_capacity(
            FRAME_BYTES
                + self.witness.len()
                + PART_LABEL.len()
                + 8
                + 32 * listed
                + self.envelope.len(),
        );
        out.extend_from_slice(&self.sealed_at.to_be_bytes());
        out.extend_from_slice(&self.request);
        out.extend_from_slice(&witness_len.to_be_bytes());
        out.extend_from_slice(&self.witness);
        if let Some(part) = &self.part {
            out.extend_from_slice(PART_LABEL);
            out.extend_from_slice(&part.index.to_be_bytes());
            out.extend_from_slice(&u32::try_from(listed).unwrap_or(u32::MAX).to_be_bytes());
            for digest in &part.digests {
                out.extend_from_slice(digest);
            }
        }
        out.extend_from_slice(&self.envelope);
        out
    }

    /// Decodes a kept or relayed input strictly; `None` for a short frame,
    /// a zero request, an empty or oversized witness or envelope, or a part
    /// whose index is outside its list, whose list is empty or past
    /// [`MAX_PARTS`], or whose bytes are not the digest its list names for
    /// it. The witness is read, not judged: [`Self::witnessed`] judges it.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let (sealed_at, rest) = bytes.split_first_chunk::<8>()?;
        let (request, rest) = rest.split_first_chunk::<32>()?;
        let (witness_len, rest) = rest.split_first_chunk::<4>()?;
        let (witness, body) =
            rest.split_at_checked(usize::try_from(u32::from_be_bytes(*witness_len)).ok()?)?;
        let (part, envelope) = match body.strip_prefix(PART_LABEL) {
            None => (None, body),
            Some(rest) => {
                let (part, bytes) = InputPart::decode(rest)?;
                (Some(part), bytes)
            }
        };
        if *request == [0; 32]
            || witness.is_empty()
            || witness.len() > MAX_INPUT_BYTES
            || envelope.is_empty()
            || envelope.len() > MAX_INPUT_BYTES
        {
            return None;
        }
        Some(Self {
            sealed_at: u64::from_be_bytes(*sealed_at),
            request: *request,
            witness: witness.to_vec(),
            part,
            envelope: envelope.to_vec(),
        })
    }

    /// The key this row is kept and relayed under: the digest the request
    /// names for a whole input, else this part's own key under it.
    pub(crate) fn row_key(&self) -> [u8; 32] {
        match &self.part {
            Some(part) => part_key(&self.digest(), part.index),
            None => self.digest(),
        }
    }

    /// The rows that carry this whole input when it travels in parts: each
    /// numbered part, in order, every one with the witness and the part
    /// list. `None` when it fits one row, or is a part already. Refused only
    /// past the part list's own bound. A door's own input is kept as it is
    /// read instead (`stream`, FIX 11140).
    #[cfg(feature = "sync")]
    pub(super) fn parts(&self) -> Result<Option<Vec<Self>>> {
        if self.part.is_some() || !splits(&self.envelope) {
            return Ok(None);
        }
        let digests: Vec<[u8; 32]> = self.envelope.chunks(PART_BYTES).map(part_digest).collect();
        if digests.len() > MAX_PARTS {
            return Err(refused(
                "the custody input splits into more parts than one part list names",
            ));
        }
        Ok(Some(
            self.envelope
                .chunks(PART_BYTES)
                .zip(0_u32..)
                .map(|(bytes, index)| Self {
                    sealed_at: self.sealed_at,
                    request: self.request,
                    witness: self.witness.clone(),
                    part: Some(InputPart {
                        index,
                        digests: digests.clone(),
                    }),
                    envelope: bytes.to_vec(),
                })
                .collect(),
        ))
    }

    /// The request this input's witness proves (FIX 4996): the witness is a
    /// canonical authority entry whose signature verifies, it hashes to
    /// `request`, and it is a custody request naming this input's digest.
    /// `None` otherwise. It proves the row self-consistent, not its signer
    /// one of this vault's machines: a row a key no machine here ever holds
    /// signed is kept until its window retires, so an input that arrives
    /// before its request still reaches its holder (CALLS
    /// CUSTODY_INPUT_PRUNE, FIX 5405).
    #[cfg(feature = "sync")]
    pub(crate) fn witnessed(&self) -> Option<Witnessed> {
        let AuthorityEntryRead::Open(entry) = read_authority_log_entry_body(&self.witness).ok()?
        else {
            return None;
        };
        if authority_entry_hash(&entry).ok()? != self.request {
            return None;
        }
        let key = match entry.signer_key() {
            AuthorityKey::Ed25519(key) => Some(*key),
            _ => None,
        };
        let AuthorityOp::OwnerWorkRequest(request) = entry.op else {
            return None;
        };
        let digest = self.digest();
        matches!(
            &request.work,
            OwnerWorkBody::Custody { input: Some(named), .. } if *named == digest
        )
        .then_some(Witnessed { key, request })
    }

    /// The digest the request names: of the whole input, or for a part,
    /// over its list of part digests.
    pub(crate) fn digest(&self) -> [u8; 32] {
        match &self.part {
            Some(part) => parts_digest(&part.digests),
            None => input_digest(&self.envelope),
        }
    }
}

impl InputPart {
    /// A part's index, part count and part digests, then its bytes, which
    /// must be the digest its list names for it.
    fn decode(body: &[u8]) -> Option<(Self, &[u8])> {
        let (index, rest) = body.split_first_chunk::<4>()?;
        let (count, rest) = rest.split_first_chunk::<4>()?;
        let count = usize::try_from(u32::from_be_bytes(*count)).ok()?;
        if count == 0 || count > MAX_PARTS {
            return None;
        }
        let (listed, bytes) = rest.split_at_checked(count.checked_mul(32)?)?;
        let digests = listed
            .chunks_exact(32)
            .map(|digest| <[u8; 32]>::try_from(digest).ok())
            .collect::<Option<Vec<_>>>()?;
        let index = u32::from_be_bytes(*index);
        let named = digests.get(usize::try_from(index).ok()?)?;
        (part_digest(bytes) == *named).then_some((Self { index, digests }, bytes))
    }
}
