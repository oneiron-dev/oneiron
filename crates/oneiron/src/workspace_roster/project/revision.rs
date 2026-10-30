//! Immutable, content-addressed project revisions (decision 8). Every signed
//! authority state a PROJECT row ever carried, and every resolution or seal
//! envelope, is kept as a companion entity whose id derives from the hash of
//! its canonical body, so a later row can never erase an earlier one and every
//! replica that holds the same revisions folds the same history.
use super::resolution::{ProjectResolution, ProjectSeal};
use super::*;
use crate::authority::{AuthorityFold, CapabilitySlip};
use crate::entity_id::derived_domains::PROJECT_REVISION;
use crate::side_table::{FixedSideKey, SideKey};
use crate::store::Store;
use std::collections::BTreeMap;

/// The short-id prefix the revision kind is registered under at run time,
/// beside PROJECT in PROJECT's pack.
pub(crate) const PROJECT_REVISION_SHORT_ID_PREFIX: &str = "pv";

/// Domain of a revision's logical hash; distinct from every authority-log,
/// slip, challenge, resolution and seal domain.
const REVISION_HASH_DOMAIN: &[u8] = b"oneiron/project-revision/v1/";

/// blake3(REVISION_HASH_DOMAIN || canonical body). Serde: a MessagePack bin of
/// exactly 32 bytes, or the array of exactly 32 numbers serde_json writes for
/// it; another length is refused.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectRevisionHash(pub [u8; 32]);

impl std::fmt::Debug for ProjectRevisionHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", crate::entity_id::bytes_to_hex_lower(&self.0))
    }
}

impl Serialize for ProjectRevisionHash {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for ProjectRevisionHash {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Bytes32;
        impl<'de> serde::de::Visitor<'de> for Bytes32 {
            type Value = ProjectRevisionHash;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("32 bytes")
            }
            fn visit_bytes<E: serde::de::Error>(
                self,
                bytes: &[u8],
            ) -> std::result::Result<Self::Value, E> {
                bytes
                    .try_into()
                    .map(ProjectRevisionHash)
                    .map_err(|_| E::invalid_length(bytes.len(), &self))
            }
            // serde_json writes the bytes as an array of numbers; exactly 32
            // of them read back (FIX 3296).
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut bytes = Vec::with_capacity(32);
                while let Some(byte) = seq.next_element::<u8>()? {
                    bytes.push(byte);
                }
                self.visit_bytes(&bytes)
            }
        }
        deserializer.deserialize_bytes(Bytes32)
    }
}

impl SideKey for ProjectRevisionHash {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(Self)
    }
}

impl FixedSideKey for ProjectRevisionHash {
    const WIDTH: usize = 32;
}

/// The signed fields of a v2/v3 proof, without its anchor: what a held
/// signed revision and an anchor link carry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRevisionProof {
    pub slip_wire: String,
    pub holder_signature: Vec<u8>,
    pub signed_at: u64,
    pub version: ProjectProofVersion,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum ProjectRevision {
    /// An unsigned owner-door state a signed chain bottoms out on (v2 form, no roster).
    Boundary {
        project: EntityId,
        authority: ProjectAuthority,
    },
    /// One v2/v3 signed state; `parent` is its proof's last anchor link, by hash.
    Signed {
        project: EntityId,
        authority: ProjectAuthority,
        proof: ProjectRevisionProof,
        parent: Option<ProjectRevisionHash>,
    },
    Resolution {
        project: EntityId,
        resolution: ProjectResolution,
    },
    Seal {
        project: EntityId,
        seal: ProjectSeal,
    },
}

impl ProjectRevision {
    /// `rmp_serde::to_vec_named`, the PROJECT body codec.
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        encode(self)
    }
    pub fn hash(&self) -> Result<ProjectRevisionHash> {
        Ok(hash_of(&self.canonical_bytes()?))
    }
    pub fn parent(&self) -> Option<ProjectRevisionHash> {
        match self {
            Self::Signed { parent, .. } => *parent,
            _ => None,
        }
    }
    pub fn project(&self) -> EntityId {
        match self {
            Self::Boundary { project, .. }
            | Self::Signed { project, .. }
            | Self::Resolution { project, .. }
            | Self::Seal { project, .. } => *project,
        }
    }
    /// The slip a signed row or envelope carries.
    pub(crate) fn slip_wire(&self) -> Option<&str> {
        match self {
            Self::Boundary { .. } => None,
            Self::Signed { proof, .. } => Some(&proof.slip_wire),
            Self::Resolution { resolution, .. } => Some(&resolution.slip_wire),
            Self::Seal { seal, .. } => Some(&seal.slip_wire),
        }
    }
    pub(crate) fn authority(&self) -> Option<&ProjectAuthority> {
        match self {
            Self::Boundary { authority, .. } | Self::Signed { authority, .. } => Some(authority),
            _ => None,
        }
    }
}

fn hash_of(canonical: &[u8]) -> ProjectRevisionHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REVISION_HASH_DOMAIN);
    hasher.update(canonical);
    ProjectRevisionHash(*hasher.finalize().as_bytes())
}

pub(crate) fn revision_entity_id(hash: ProjectRevisionHash) -> Result<EntityId> {
    EntityId::derive(PROJECT_REVISION, &[&hash.0])
}

/// Pure: refuses a body that is not its own canonical re-encoding, whose hash
/// does not derive `id`, or whose envelope lists are not sorted and unique.
/// No vault context. No size cap of its own: the projection admits a PROJECT
/// state of any slice size, so a cap here would refuse capturing one; an
/// untrusted carrier is bounded by its transport, as any row is.
pub(crate) fn decode_revision(
    id: EntityId,
    body: &[u8],
) -> Result<(ProjectRevisionHash, ProjectRevision)> {
    let refused = || Error::from(RecordError::InvalidProjectBody("invalid project revision"));
    let revision: ProjectRevision = decode(body).map_err(|_| refused())?;
    if revision.canonical_bytes()? != body {
        return Err(refused());
    }
    let hash = hash_of(body);
    if revision_entity_id(hash)? != id {
        return Err(refused());
    }
    let sorted = |hashes: &[ProjectRevisionHash]| hashes.windows(2).all(|pair| pair[0] < pair[1]);
    match &revision {
        ProjectRevision::Resolution { resolution, .. }
            if resolution.contenders.len() < 2
                || !sorted(&resolution.contenders)
                || !sorted(&resolution.prior) =>
        {
            return Err(refused());
        }
        ProjectRevision::Seal { seal, .. } if !sorted(&seal.supersedes) => return Err(refused()),
        ProjectRevision::Boundary { authority, .. } if authority.roster.is_some() => {
            return Err(refused());
        }
        _ => {}
    }
    Ok((hash, revision))
}

/// The revisions a v2/v3 anchor chain holds, bottom first as the chain is,
/// however long it is (rule 5, FIX 9436): `chain` as
/// [`ProjectRecord::anchor`] builds it.
pub(crate) fn revisions_of(
    project: EntityId,
    chain: &[ProjectAnchorLink],
) -> Result<Vec<(ProjectRevisionHash, ProjectRevision)>> {
    let mut out: Vec<(ProjectRevisionHash, ProjectRevision)> = Vec::with_capacity(chain.len());
    let mut parent = None;
    for link in chain {
        let revision = match &link.proof {
            None => ProjectRevision::Boundary {
                project,
                authority: link.authority.clone(),
            },
            Some(proof) => ProjectRevision::Signed {
                project,
                authority: link.authority.clone(),
                proof: proof.clone(),
                parent,
            },
        };
        let hash = revision.hash()?;
        parent = Some(hash);
        out.push((hash, revision));
    }
    Ok(out)
}

/// The chain of a stored PROJECT row: none for an unsigned row, which a
/// signed chain only ever meets as its bottom boundary.
pub(crate) fn revisions_of_row(
    project: EntityId,
    record: &ProjectRecord,
) -> Result<Vec<(ProjectRevisionHash, ProjectRevision)>> {
    if record.write_proof.is_none() {
        return Ok(Vec::new());
    }
    revisions_of(project, &record.anchor()?)
}

/// How far a held revision's origin is established. Authentication checks
/// only what its bytes fix for good; standing is judged at every fold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RevisionOrigin {
    /// Its immutable slip chain verified: the mint's claims equal the slip's,
    /// the host's signature over them, every caveat transfer signature, and
    /// the last binding signer's signature over the rebuilt challenge.
    /// Boundary rows carry no signature and need none.
    Authenticated,
    /// A Signed row whose parent chain is not held: its challenge cannot be built.
    AwaitingParent,
    /// Its slip's mint is not known: the host signature cannot be checked.
    AwaitingMint,
    /// A check above failed. Kept so a re-sent carrier is recognized; never
    /// folded, counted, recorded as evidence or exported.
    Forged,
}

/// Rebuildable from the companions: (project, hash) -> (companion id, origin).
pub(super) const REVISIONS: SideTable<
    (EntityId, ProjectRevisionHash),
    (EntityId, RevisionOrigin),
    Named,
> = SideTable::new(&side_table::PROJECT_REVISIONS);
/// Rebuildable: (slip id, (project, hash)) -> (). Rows whose slip's mint is
/// not held yet; a mint's arrival touches their projects.
pub(super) const REVISION_AWAITING_MINT: SideTable<
    ([u8; 32], (EntityId, ProjectRevisionHash)),
    (),
    Raw,
> = SideTable::new(&side_table::PROJECT_REVISION_AWAITING_MINT);
/// Marker of the one-time capture at writable open.
pub(super) const PROJECT_REVISION_BACKFILL: SideTable<(), u64, Raw> =
    SideTable::new(&side_table::PROJECT_REVISION_BACKFILL);

pub(crate) fn is_project_revision_type(store: &Store, kind: u8) -> bool {
    store.structural_kind_registration(kind).is_some_and(|row| {
        row.pack == PACK && row.short_id_prefix == PROJECT_REVISION_SHORT_ID_PREFIX
    })
}

pub(crate) fn project_revision_type(store: &Store) -> Option<u8> {
    store
        .structural_kind_registrations()
        .into_iter()
        .find(|row| row.pack == PACK && row.short_id_prefix == PROJECT_REVISION_SHORT_ID_PREFIX)
        .map(|row| row.type_byte)
}

/// A companion body this vault would admit at `id`: canonical, hash-derived
/// and bound to this vault.
pub(crate) fn admissible_revision(
    fold: Option<&AuthorityFold>,
    id: EntityId,
    body: &[u8],
) -> Result<(ProjectRevisionHash, ProjectRevision)> {
    let (hash, revision) = decode_revision(id, body)?;
    if let (Some(fold), Some(wire)) = (fold, revision.slip_wire()) {
        let slip = CapabilitySlip::from_token(wire)
            .map_err(|_| RecordError::InvalidProjectBody("invalid project revision slip"))?;
        if fold
            .vault_id
            .is_some_and(|vault| vault != slip.claims.vault_id)
        {
            return Err(
                RecordError::InvalidProjectBody("project revision of another vault").into(),
            );
        }
    }
    Ok((hash, revision))
}

/// One held revision with its established origin.
#[derive(Clone, Debug)]
pub(crate) struct HeldRevision {
    pub(crate) revision: ProjectRevision,
    pub(crate) origin: RevisionOrigin,
}

/// The held set of one project: indexed companions plus the stored row's
/// chain, read on the fly. Forged rows are excluded.
#[derive(Clone, Debug, Default)]
pub(crate) struct HeldRevisions {
    pub(crate) rows: BTreeMap<ProjectRevisionHash, HeldRevision>,
    /// Signed children by parent hash.
    pub(crate) children: BTreeMap<ProjectRevisionHash, BTreeSet<ProjectRevisionHash>>,
    /// Resolutions by the anchor they settle.
    pub(crate) resolutions: BTreeMap<ProjectRevisionHash, BTreeSet<ProjectRevisionHash>>,
    pub(crate) seals: BTreeSet<ProjectRevisionHash>,
}

impl HeldRevisions {
    pub(crate) fn get(&self, hash: &ProjectRevisionHash) -> Option<&HeldRevision> {
        self.rows.get(hash)
    }
    pub(crate) fn insert(
        &mut self,
        hash: ProjectRevisionHash,
        revision: ProjectRevision,
        origin: RevisionOrigin,
    ) {
        if origin == RevisionOrigin::Forged || self.rows.contains_key(&hash) {
            return;
        }
        match &revision {
            ProjectRevision::Signed {
                parent: Some(parent),
                ..
            } => {
                self.children.entry(*parent).or_default().insert(hash);
            }
            ProjectRevision::Resolution { resolution, .. } => {
                self.resolutions
                    .entry(resolution.anchor)
                    .or_default()
                    .insert(hash);
            }
            ProjectRevision::Seal { .. } => {
                self.seals.insert(hash);
            }
            _ => {}
        }
        self.rows.insert(hash, HeldRevision { revision, origin });
    }
    pub(crate) fn resolutions_at(
        &self,
        anchor: &ProjectRevisionHash,
    ) -> impl Iterator<Item = &ProjectRevisionHash> {
        self.resolutions.get(anchor).into_iter().flatten()
    }
    pub(crate) fn children_of(
        &self,
        hash: &ProjectRevisionHash,
    ) -> impl Iterator<Item = &ProjectRevisionHash> {
        self.children.get(hash).into_iter().flatten()
    }
}

/// Reads a held companion by its index row.
fn companion(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<ProjectRevision>> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? else {
        return Ok(None);
    };
    if raw.len() <= ENTITY_METADATA_HEADER_LEN {
        return Ok(None);
    }
    Ok(decode_revision(id, &raw[ENTITY_METADATA_HEADER_LEN..])
        .ok()
        .map(|(_, revision)| revision))
}

/// The held set of `project`, with `extra` (a candidate's chain) folded in
/// unchecked.
pub(crate) fn held_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    project: EntityId,
    kind: u8,
) -> Result<HeldRevisions> {
    let mut held = HeldRevisions::default();
    // A forged row is final: no fold reads it, so its body is never loaded.
    let mut forged = BTreeSet::new();
    for row in REVISIONS.iter_from(store, txn, project.as_bytes())? {
        let ((owner, hash), (id, origin)) = row?;
        if owner != project {
            break;
        }
        if origin == RevisionOrigin::Forged {
            forged.insert(hash);
        } else if let Some(revision) = companion(store, txn, id)? {
            held.insert(hash, revision, origin);
        }
    }
    if let Some(stored) = read::stored(store, txn, project, kind)? {
        for (hash, revision) in revisions_of_row(project, &stored)? {
            if !held.rows.contains_key(&hash) && !forged.contains(&hash) {
                // Unindexed (a vault from before the capture): the fold
                // authenticates it on the fly.
                held.insert(hash, revision, RevisionOrigin::AwaitingParent);
            }
        }
    }
    Ok(held)
}

/// Rebuilds the exact anchor chain of a held revision, root first and the
/// revision last, the value its children's `write_challenge` signs over,
/// however long its lineage is (rule 5, FIX 9436). `None` when a link is
/// missing, or met twice, which only a malformed set can hold.
pub(crate) fn anchor_of(
    held: &HeldRevisions,
    hash: ProjectRevisionHash,
) -> Option<Vec<ProjectAnchorLink>> {
    let mut chain = Vec::new();
    let mut seen = BTreeSet::new();
    let mut next = Some(hash);
    while let Some(at) = next {
        if !seen.insert(at) {
            return None;
        }
        let row = &held.get(&at)?.revision;
        chain.push(match row {
            ProjectRevision::Boundary { authority, .. } => ProjectAnchorLink {
                authority: authority.clone(),
                proof: None,
            },
            ProjectRevision::Signed {
                authority, proof, ..
            } => ProjectAnchorLink {
                authority: authority.clone(),
                proof: Some(proof.clone()),
            },
            _ => return None,
        });
        next = row.parent();
    }
    chain.reverse();
    Some(chain)
}

/// What one held revision's origin check reads: the slip wire, the challenge
/// its signature covers and the holder signature.
type SignedChallenge = (String, Vec<u8>, Vec<u8>);

/// The challenge a held revision's signature covers, when its chain is held.
fn challenge_of(
    held: &HeldRevisions,
    hash: ProjectRevisionHash,
) -> Option<Result<SignedChallenge>> {
    let row = &held.get(&hash)?.revision;
    Some(match row {
        ProjectRevision::Boundary { .. } => return None,
        ProjectRevision::Signed {
            project,
            authority,
            proof,
            parent,
        } => {
            let anchor = match parent {
                Some(parent) => anchor_of(held, *parent)?,
                None => Vec::new(),
            };
            authority
                .write_challenge(*project, proof.version, proof.signed_at, &anchor)
                .map(|challenge| {
                    (
                        proof.slip_wire.clone(),
                        challenge,
                        proof.holder_signature.clone(),
                    )
                })
        }
        ProjectRevision::Resolution {
            project,
            resolution,
        } => resolution.challenge(*project).map(|challenge| {
            (
                resolution.slip_wire.clone(),
                challenge,
                resolution.holder_signature.clone(),
            )
        }),
        ProjectRevision::Seal { project, seal } => seal.challenge(*project).map(|challenge| {
            (
                seal.slip_wire.clone(),
                challenge,
                seal.holder_signature.clone(),
            )
        }),
    })
}

/// The origin a held revision earns now: Authenticated or Forged once its
/// chain and mint are held, else what it waits for.
pub(crate) fn authenticate(
    held: &HeldRevisions,
    fold: &AuthorityFold,
    hash: ProjectRevisionHash,
) -> RevisionOrigin {
    let Some(row) = held.get(&hash) else {
        return RevisionOrigin::AwaitingParent;
    };
    if matches!(row.revision, ProjectRevision::Boundary { .. }) {
        return RevisionOrigin::Authenticated;
    }
    let Some(wire) = row.revision.slip_wire() else {
        return RevisionOrigin::Forged;
    };
    let Ok(slip) = CapabilitySlip::from_token(wire) else {
        return RevisionOrigin::Forged;
    };
    if !fold.slips.mints.contains_key(&slip.claims.slip_id) {
        return RevisionOrigin::AwaitingMint;
    }
    let Some(parts) = challenge_of(held, hash) else {
        return RevisionOrigin::AwaitingParent;
    };
    match parts {
        Ok((_, challenge, signature))
            if slip.verify_origin(fold, &challenge, &signature).is_ok() =>
        {
            RevisionOrigin::Authenticated
        }
        _ => RevisionOrigin::Forged,
    }
}

/// The slip id a waiting row's mint carries.
pub(crate) fn slip_id_of(revision: &ProjectRevision) -> Option<[u8; 32]> {
    let slip = CapabilitySlip::from_token(revision.slip_wire()?).ok()?;
    Some(slip.claims.slip_id)
}
