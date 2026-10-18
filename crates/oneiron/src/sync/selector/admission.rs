//! Federated import admission: window admit, claim revalidation, entity copy, authority-log door, and tombstone rejection.

use std::collections::{BTreeMap, BTreeSet};

use loro::{CommitOptions, ExportMode, LoroDoc};
#[cfg(feature = "sync")]
use xxhash_rust::xxh3::xxh3_64;

use crate::Vault;
use crate::authority::{
    AuthorityOp, authority_entry_hash, authority_log_entity_id, decode_authority_log_entry_body,
    genesis_vault_id, validate_authority_log_entry_body_bytes,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimSubject, restamp_federated_claim_source, validate_claim_body_and_decode};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncEngineContext, SyncProtocolValidation};
use crate::federation::{MembershipStanding, PactDelivery};
#[cfg(feature = "test-hooks")]
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::registry::{
    ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN,
    ENTITY_TYPE_WORLD,
};
use crate::sync::loro_support::{
    map_for_each_tombstone_value, map_for_each_value_bytes, map_get_bytes, map_insert_bytes,
};
use crate::sync::schema::create_window_doc;
use crate::sync::types::WindowKey;

#[cfg(feature = "sync")]
use super::edge::{
    EarlyStamps, HeldStamp, ReleasedStamps, copy_admitted_edges, hold_stamps, pending_births,
    refuse_admitted_stamps, refuse_non_binary_edges, release_born_stamps,
};
use crate::error::{RecordError, SyncError};

/// Role carried by a member/guest federation import path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FederationAdmissionRole {
    Member,
    Guest,
}

impl FederationAdmissionRole {
    const fn origin(self) -> &'static str {
        match self {
            Self::Member => "federation_admission.member",
            Self::Guest => "federation_admission.guest",
        }
    }
}

/// How admission grades a federated CLAIM, TURN or CONVERSATION (FIX 360).
#[cfg(feature = "sync")]
#[derive(Debug, Clone, Copy)]
enum ImportGrading {
    /// Imported evidence: a claim is restamped `src=imported` and its
    /// confidence scaled by `scale`; a transcript takes the federation import
    /// stamp.
    Imported { scale: f32 },
    /// A verified member's write in this shared vault, first-party to it
    /// (ARCH-0043): a claim keeps its source and confidence, and a transcript
    /// takes no import stamp.
    FirstParty,
}

/// Produces locally admitted window update bytes for a member/guest federation
/// import.
///
/// The incoming CRDT update is decoded into an unobserved scratch doc. Claim
/// entities are re-stamped to `src=imported` and evaluated against the local
/// source-trust floor before any bytes are copied into the returned update.
/// The returned doc is freshly authored with a federation admission origin,
/// so callers can import it through the ordinary replay/materialization path
/// without giving the original remote op ids trust-blind write authority.
///
/// No facet stamp a peer sends onto a row this vault lacks is in the
/// returned update. With no sender named here, nothing can bind such a stamp
/// to its row's birth, so it is dropped (`copy_admitted_edges`).
#[cfg(feature = "sync")]
pub fn admit_federated_window_update(
    vault: &Vault,
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
) -> Result<Vec<u8>> {
    Ok(admit_window_update(
        vault,
        key,
        update,
        role,
        None,
        ImportGrading::Imported {
            scale: super::DEFAULT_FEDERATED_CONFIDENCE_SCALE,
        },
        None,
    )?
    .bytes)
}

/// [`admit_federated_window_update`] for an update the federation peer
/// `peer` sent. Its facet stamps onto rows this vault lacks wait out of the
/// update ([`AdmittedUpdate`]) until the peer's birth of each row applies.
/// Its claims are graded as imported evidence, and no pact source remaps
/// them: the door the federation import calls is
/// [`admit_peer_window_update_as`].
#[cfg(feature = "sync")]
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::sync) fn admit_peer_window_update(
    vault: &Vault,
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
    peer: EntityId,
) -> Result<AdmittedUpdate> {
    admit_guest_window_update(vault, key, update, role, peer, None)
}

/// [`admit_peer_window_update`] for a guest whose pact names `guest`, its
/// source vault: each of its CLAIMs lands in its foreign WORLD copy
/// ([`Routes`], FIX 3497).
#[cfg(feature = "sync")]
fn admit_guest_window_update(
    vault: &Vault,
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
    peer: EntityId,
    guest: Option<&[u8; 32]>,
) -> Result<AdmittedUpdate> {
    let lane = crate::federation::facet_read::HeldLane::Peer(peer).key();
    // The owner's scale for this peer, read once for the whole update.
    let scale = vault.federation_peer_confidence(&peer)?;
    admit_window_update(
        vault,
        key,
        update,
        role,
        Some(lane),
        ImportGrading::Imported { scale },
        guest,
    )
}

/// [`admit_peer_window_update`] at the `standing` the peer's own grant gives
/// it here (`FederationPeer::membership`, FIX 360). A member's update, sent
/// as one, is first-party to this shared vault: its claims are neither
/// restamped `src=imported` nor downweighted, and the claim gate still judges
/// them; its TURN and CONVERSATION rows take no federation import stamp. A
/// scoped guest's update, or one sent as a guest's, keeps guest grading, and
/// its CLAIMs land in the foreign WORLD copies the source vault `delivery`
/// names derives (FIX 3497). A guest's update with no unambiguous active pact
/// (`delivery` is `None`) has no such source and is refused, never landed as
/// this vault's own.
#[cfg(feature = "sync")]
pub(in crate::sync) fn admit_peer_window_update_as(
    vault: &Vault,
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
    (peer, standing): (EntityId, MembershipStanding),
    delivery: Option<&PactDelivery>,
) -> Result<AdmittedUpdate> {
    let first_party = role == FederationAdmissionRole::Member
        && matches!(standing, MembershipStanding::Member { .. });
    if !first_party {
        let delivery = delivery.ok_or_else(|| {
            super::codec::selector_err(crate::error::SyncSelectorValidation::GrantInactive)
        })?;
        return admit_guest_window_update(
            vault,
            key,
            update,
            role,
            peer,
            Some(&delivery.source_vault),
        );
    }
    let lane = crate::federation::facet_read::HeldLane::Peer(peer).key();
    admit_window_update(
        vault,
        key,
        update,
        role,
        Some(lane),
        ImportGrading::FirstParty,
        None,
    )
}

/// [`admit_federated_window_update`] for a foreign artifact staged under
/// `receipt_id`. Its facet stamps onto rows this vault lacks wait under the
/// receipt until the confirmation's import births the rows
/// ([`staged_births`]).
#[cfg(feature = "sync")]
pub(crate) fn admit_staged_window_update(
    vault: &Vault,
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
    receipt_id: &[u8; 32],
) -> Result<AdmittedUpdate> {
    admit_window_update(
        vault,
        key,
        update,
        role,
        Some(staged_lane(receipt_id)),
        ImportGrading::Imported {
            scale: super::DEFAULT_FEDERATED_CONFIDENCE_SCALE,
        },
        None,
    )
}

#[cfg(feature = "sync")]
fn staged_lane(receipt_id: &[u8; 32]) -> String {
    crate::federation::facet_read::HeldLane::Staged(*receipt_id).key()
}

/// An update the federation door admitted, and the facet stamps it sent onto
/// rows this vault lacks, which wait out of its bytes: the ones whose rows it
/// brings until those births apply here, the rest held under its sender.
///
/// A guest's update can land in more than one window ([`Routes`], FIX 3497):
/// this part imports first, then each part in [`Self::parts`] after it.
#[cfg(feature = "sync")]
pub(crate) struct AdmittedUpdate {
    key: WindowKey,
    bytes: Vec<u8>,
    rows: u64,
    early: EarlyStamps,
    births: Vec<(EntityId, Vec<u8>)>,
    peer_rows: Vec<(EntityId, [u8; 32])>,
    delivered: BTreeMap<EntityId, [u8; 32]>,
    born_with: Vec<super::born_with::CarriedText>,
    lane: Option<String>,
    routed: Vec<AdmittedUpdate>,
}

#[cfg(feature = "sync")]
impl AdmittedUpdate {
    /// The window these bytes import into: the update's own, or for a
    /// guest's update in one of its WORLD windows, that world's foreign copy
    /// (FIX 3497).
    pub(crate) const fn key(&self) -> &WindowKey {
        &self.key
    }

    /// This part, then each part a guest's update routed into a foreign
    /// WORLD window (FIX 3497), in the order they import.
    pub(crate) fn parts(&self) -> impl Iterator<Item = &Self> {
        std::iter::once(self).chain(&self.routed)
    }

    /// The admitted bytes to import.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The writes the update asks of this vault: its rows and edges, and the
    /// stamps that wait out of it (Astra-b F2 on #1432).
    pub(crate) fn writes(&self) -> u64 {
        self.parts()
            .map(|part| {
                let early = part.early.held.len() + part.early.with_birth.len();
                part.rows.saturating_add(early as u64)
            })
            .fold(0, u64::saturating_add)
            .max(1)
    }

    /// Holds the stamps ahead of their rows under the peer that sent the
    /// update and the `grant` it sent them under, within the peer's caps.
    pub(crate) fn hold_from_peer(
        &self,
        vault: &Vault,
        key: &WindowKey,
        grant: EntityId,
    ) -> Result<()> {
        match &self.lane {
            Some(lane) => hold_stamps(vault, key, (lane, Some(grant)), &self.early.held, true),
            None => Ok(()),
        }
    }

    /// Holds every stamp of a staged artifact under its receipt, the ones
    /// whose rows it brings too: those births apply only at its confirmation.
    pub(crate) fn hold_staged(&self, vault: &Vault, key: &WindowKey) -> Result<()> {
        let Some(lane) = &self.lane else {
            return Ok(());
        };
        hold_stamps(vault, key, (lane, None), &self.early.held, false)?;
        hold_stamps(vault, key, (lane, None), &self.early.with_birth, false)
    }

    /// The record of every stamp [`Self::hold_staged`] holds, which the
    /// receipt keeps while it is Pending.
    pub(crate) fn staged_stamps(&self) -> Vec<u8> {
        HeldStamp::record(&[&self.early.held, &self.early.with_birth])
    }

    /// The rows the update brings whose births its import must watch, each
    /// with the bytes it brings.
    pub(crate) fn births(&self) -> &[(EntityId, Vec<u8>)] {
        &self.births
    }

    /// The rows whose door judges a peer's row apart from this vault's own,
    /// each with the digest of the bytes the update brings.
    pub(crate) fn peer_rows(&self) -> &[(EntityId, [u8; 32])] {
        &self.peer_rows
    }

    /// Every row the update brings, with the digest of its bytes: what a
    /// pact delivers when the update's import writes it (FIX 321).
    pub(crate) const fn delivered(&self) -> &BTreeMap<EntityId, [u8; 32]> {
        &self.delivered
    }

    /// After the update's import, keeps the born-with text the sender let
    /// travel beside each row that landed (OF-491).
    pub(crate) fn keep_born_with(&self, vault: &Vault) -> Result<()> {
        super::born_with::keep_carried(vault, &self.born_with)
    }

    /// After the update's import, the stamps on the rows that import birthed
    /// (`born`, [`release_born_stamps`]).
    pub(crate) fn release(
        &self,
        vault: &Vault,
        key: &WindowKey,
        born: &BTreeSet<EntityId>,
    ) -> Result<Option<ReleasedStamps>> {
        match &self.lane {
            Some(lane) => {
                release_born_stamps(vault, key, lane, &self.births, born, &self.early.with_birth)
            }
            None => Ok(None),
        }
    }
}

/// The rows a staged artifact's admitted bytes bring that this vault lacks
/// and that its receipt holds stamps on, read before the confirmation imports
/// them.
#[cfg(feature = "sync")]
pub(crate) struct StagedBirths {
    lane: String,
    births: Vec<(EntityId, Vec<u8>)>,
}

#[cfg(feature = "sync")]
impl StagedBirths {
    /// The rows the confirmation's import must watch, each with the bytes
    /// the artifact brings.
    pub(crate) fn births(&self) -> &[(EntityId, Vec<u8>)] {
        &self.births
    }

    /// After the confirmation's import, the stamps on the rows that import
    /// birthed (`born`).
    pub(crate) fn release(
        &self,
        vault: &Vault,
        key: &WindowKey,
        born: &BTreeSet<EntityId>,
    ) -> Result<Option<ReleasedStamps>> {
        release_born_stamps(vault, key, &self.lane, &self.births, born, &[])
    }
}

/// [`StagedBirths`] of the artifact staged under `receipt_id`.
#[cfg(feature = "sync")]
pub(in crate::sync) fn staged_births(
    vault: &Vault,
    key: &WindowKey,
    (receipt_id, stamps_digest): (&[u8; 32], Option<[u8; 32]>),
    admitted_update: &[u8],
) -> Result<StagedBirths> {
    let admitted = create_window_doc("federation-staged", key);
    admitted.import(admitted_update).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "import admitted update",
            source,
        })
    })?;
    let lane = staged_lane(receipt_id);
    // The held table restores live and maintenance sweeps it, so a hold can
    // be gone while its receipt is Pending. The receipt's own record holds
    // every staged stamp again before its birth is judged: an owner's import
    // never lands a row without the facets it staged (Astra-c F1 on #1432).
    let record = crate::batch::export::vault_import_staged_stamps(vault, receipt_id)?;
    let stamps = HeldStamp::from_receipt_record(&record.unwrap_or_default(), stamps_digest)?;
    hold_stamps(vault, key, (&lane, None), &stamps, false)?;
    let births = pending_births(vault, &lane, &admitted.get_map("entities"), &[])?;
    Ok(StagedBirths { lane, births })
}

/// `guest` is the source vault a guest's pact names: with one, the update's
/// CLAIMs land in their foreign WORLD copies ([`Routes`], FIX 3497), and the
/// admitted update holds one part per window it lands in.
#[cfg(feature = "sync")]
fn admit_window_update(
    vault: &Vault,
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
    lane: Option<String>,
    grading: ImportGrading,
    guest: Option<&[u8; 32]>,
) -> Result<AdmittedUpdate> {
    let remote = create_window_doc("federation-remote", key);
    remote.import(update).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "import federated update",
            source,
        })
    })?;

    refuse_non_binary_edges(&remote.get_map("edges"))?;
    let policy = vault
        .with_write_txn_grouped(|wtxn| crate::gate::resolve_policy_manifest(&vault.store, wtxn))?;

    reject_federated_tombstones(&remote)?;
    // The withheld CLAIMs and the contained cross-world edges (FIX 3660).
    let mut terminal = crate::sync::quarantine::TerminalRejectionBatch::new(key.as_str());
    let routes = match guest {
        Some(source) => Routes::plan(vault, key, &remote, source, &mut terminal)?,
        None => Routes::unrouted(key),
    };
    // Every part's rows and edges are copied before any birth is: a ref to a
    // row another part carries is not one admission dropped.
    let mut copied = Vec::with_capacity(routes.keys.len());
    for (part, part_key) in routes.keys.iter().enumerate() {
        let admitted = create_admission_doc(part_key, update, role, guest)?;
        copy_admitted_entities(vault, &policy, &remote, &admitted, grading, &routes, part)?;
        let edges = routes.edges_of(&remote, part)?;
        let early = copy_admitted_edges(
            vault,
            part_key,
            &remote.get_map("entities"),
            &admitted.get_map("entities"),
            &edges
                .as_ref()
                .map_or_else(|| remote.get_map("edges"), |edges| edges.get_map("edges")),
            &admitted.get_map("edges"),
        )?;
        if part == 0 {
            crate::sync::note::copy_judged(vault, &remote, &admitted)?;
        }
        copied.push((admitted, early));
    }
    terminal.commit(vault)?;

    // The sender is another vault, as far as its rows' births go: a ref to a
    // row admission dropped is masked, under that lane's key.
    let withheld = match &lane {
        Some(lane) => crate::provenance::birth::WithheldKey::for_destination(
            vault,
            format!("admit:{lane}").as_bytes(),
        )?,
        None => crate::provenance::birth::WithheldKey::fresh(),
    };
    // A row the copy lands under another id than the sender's, a guest's
    // WORLD (FIX 3657), keeps the birth the sender carried for it.
    let renamed = routes
        .worlds
        .iter()
        .map(|(sender, here)| (*here, *sender))
        .collect::<BTreeMap<_, _>>();
    let carried = (copied.len() > 1 || !renamed.is_empty()).then(|| {
        copied
            .iter()
            .flat_map(|(admitted, _)| {
                admitted
                    .get_map("entities")
                    .keys()
                    .filter_map(|key| EntityId::from_hex(&key).ok())
                    .collect::<Vec<_>>()
            })
            .collect::<BTreeSet<_>>()
    });
    let mut parts = Vec::with_capacity(copied.len());
    for ((admitted, early), part_key) in copied.into_iter().zip(&routes.keys) {
        match &carried {
            Some(carried) => crate::sync::row_birth::copy_births_carried_to_other_vault(
                &remote, &admitted, &withheld, carried, &renamed,
            )?,
            None => crate::sync::row_birth::copy_births_within(
                &remote,
                &admitted,
                crate::sync::row_birth::BirthReach::OtherVault(&withheld),
            )?,
        }
        // Its born-with text never enters the admitted bytes: the import keeps
        // it beside the rows that land.
        let born_with = super::born_with::admitted_born_with(&remote, &admitted);
        let births = match &lane {
            Some(lane) => pending_births(
                vault,
                lane,
                &admitted.get_map("entities"),
                &early.with_birth,
            )?,
            None => Vec::new(),
        };
        let peer_rows = crate::sync::ingest::peer_rows(&admitted.get_map("entities"));
        let delivered = crate::sync::ingest::delivered_rows(&admitted.get_map("entities"));
        admitted.commit_with(CommitOptions::new().origin(role.origin()));
        let rows = admitted.get_map("entities").len() + admitted.get_map("edges").len();
        let bytes = admitted
            .export(ExportMode::all_updates())
            .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportAllUpdates, e))?;
        parts.push(AdmittedUpdate {
            key: part_key.clone(),
            bytes,
            rows: rows as u64,
            early,
            births,
            peer_rows,
            delivered,
            born_with,
            lane: lane.clone(),
            routed: Vec::new(),
        });
    }
    let mut parts = parts.into_iter();
    let mut admitted = parts.next().ok_or(Error::InvariantViolation(
        "an admitted update lands in its own window first",
    ))?;
    admitted.routed = parts.collect();
    Ok(admitted)
}

/// Where each row of an update the federation door admits lands (FIX 3497).
///
/// A guest's CLAIM lands in a foreign WORLD copy, never in the sender's world
/// or base here (ARCH-0043): its world is rewritten to the foreign id its
/// source vault and the sender's world derive, and window residence keeps a
/// CLAIM in its world's window. An update in one of the sender's WORLD
/// windows therefore lands whole in that world's foreign window. In a base
/// window only its base CLAIMs move, each to its month's window of the
/// sender's base copy, with each edge whose world endpoint is such a CLAIM
/// or a foreign-world CLAIM this vault stores; every other row stays in the
/// update's own window, part 0, which imports first. A guest CLAIM a MACHINE
/// proof binds is withheld whole with every edge naming it
/// ([`crate::federation::guest_claim_withheld`]). An admission with no guest
/// source, member content among them, routes nothing.
///
/// A WORLD row the guest sends lands under its foreign id, the one its CLAIMs
/// in that world now name, in the window it came in (FIX 3657). Each InWorld
/// or SetIn edge endpoint naming such a WORLD names that id, and so does a
/// CLAIM about such an edge. An edge whose two endpoints are proven to sit in
/// two different foreign WORLDs is quarantined alone
/// ([`contains_cross_world_edge`], FIX 3660).
#[cfg(feature = "sync")]
struct Routes<'a> {
    /// The window each part imports into, part 0 first.
    keys: Vec<WindowKey>,
    /// The source vault a guest's pact names.
    guest: Option<&'a [u8; 32]>,
    /// The part each moved CLAIM lands in.
    claims: BTreeMap<EntityId, usize>,
    /// The guest CLAIMs withheld whole.
    withheld: BTreeSet<EntityId>,
    /// The part each moved edge lands in, by its key; `None` drops it.
    edges: BTreeMap<String, Option<usize>>,
    /// The guest's WORLDs that land under foreign ids here, by the sender's
    /// id (FIX 3657).
    worlds: BTreeMap<EntityId, EntityId>,
    /// The key each edge naming one of those WORLDs lands under, by its own.
    rekeyed: BTreeMap<String, String>,
}

/// A guest's update as its rows are copied: the source vault its pact names
/// and the WORLDs that land under foreign ids here ([`Routes::worlds`]).
#[cfg(feature = "sync")]
#[derive(Clone, Copy)]
struct GuestCopy<'a> {
    source: &'a [u8; 32],
    worlds: &'a BTreeMap<EntityId, EntityId>,
}

#[cfg(feature = "sync")]
impl<'a> Routes<'a> {
    /// One part, in the update's own window, that rewrites nothing.
    fn unrouted(key: &WindowKey) -> Self {
        Self {
            keys: vec![key.clone()],
            guest: None,
            claims: BTreeMap::new(),
            withheld: BTreeSet::new(),
            edges: BTreeMap::new(),
            worlds: BTreeMap::new(),
            rekeyed: BTreeMap::new(),
        }
    }

    /// The routes of a guest's update from the source vault `guest`. Each
    /// withheld CLAIM and each contained cross-world edge is recorded in
    /// `terminal`. A row or edge whose bytes do not read routes to part 0,
    /// where admission refuses it.
    fn plan(
        vault: &Vault,
        key: &WindowKey,
        remote: &LoroDoc,
        guest: &'a [u8; 32],
        terminal: &mut crate::sync::quarantine::TerminalRejectionBatch,
    ) -> Result<Self> {
        let own = match key.world() {
            Some(world) => WindowKey::for_month_world(
                key,
                crate::federation::foreign_world_for(guest, world)?.entity_id(),
            ),
            None => key.clone(),
        };
        let mut routes = Self {
            keys: vec![own],
            guest: Some(guest),
            ..Self::unrouted(key)
        };
        let mut placed = Placement::new(guest);
        let mut moved = Vec::new();
        // The WORLD rows the update carries, and the ids an InWorld or SetIn
        // edge, or a CLAIM about one, names: those that may be WORLDs.
        let mut carried_worlds = Vec::new();
        let mut named = BTreeSet::new();
        map_for_each_value_bytes(&remote.get_map("entities"), |raw, blob| {
            let (Some(blob), Ok(id)) = (blob, EntityId::from_hex(raw)) else {
                return;
            };
            let Some(header) = EntityMetadataHeader::parse(blob) else {
                return;
            };
            if id.to_hex() != raw {
                return;
            }
            if header.entity_type == ENTITY_TYPE_WORLD {
                carried_worlds.push(id);
                return;
            }
            if header.entity_type != ENTITY_TYPE_CLAIM {
                return;
            }
            let Ok(body) =
                validate_claim_body_and_decode(&blob[ENTITY_METADATA_HEADER_LEN..], true)
            else {
                return;
            };
            if crate::federation::guest_claim_withheld(&body) {
                terminal.push(
                    crate::sync::quarantine::QuarantineContainer::Entities,
                    raw,
                    &Error::Claim(crate::error::ClaimError::InvalidMachineClaimProof),
                    blob,
                );
                routes.withheld.insert(id);
                return;
            }
            named.extend(world_edge_subject(&body.subject).into_iter().flatten());
            placed.claims.insert(id, body.world);
            if key.world().is_none() && body.world.is_none() {
                moved.push((id, header.learned_at));
            }
        });
        if !moved.is_empty() {
            let base = placed.foreign_of(None)?;
            for (id, learned_at) in moved {
                let part = routes.part(WindowKey::for_world(learned_at, base));
                routes.claims.insert(id, part);
            }
        }
        let remote_edges = remote.get_map("edges");
        let mut edges = Vec::new();
        map_for_each_value_bytes(&remote_edges, |raw, _| {
            if let Some((src, kind, tgt)) = super::bridge::parse_edge_key(raw) {
                if is_world_edge(kind) {
                    named.extend([src, tgt]);
                }
                edges.push((raw.to_owned(), (src, kind, tgt)));
            }
        });
        routes.rename_worlds(vault, guest, carried_worlds, named)?;
        for (raw, (src, kind, tgt)) in edges {
            if routes.withheld.contains(&src) || routes.withheld.contains(&tgt) {
                routes.edges.insert(raw, None);
                continue;
            }
            let src_world = placed.foreign_world(vault, src)?;
            let tgt_world = match src_world {
                Some(_) => placed.foreign_world(vault, tgt)?,
                None => None,
            };
            if contains_cross_world_edge(src_world, tgt_world) {
                terminal.push(
                    crate::sync::quarantine::QuarantineContainer::Edges,
                    &raw,
                    &cross_world_edge_refusal(),
                    &map_get_bytes(&remote_edges, &raw).unwrap_or_default(),
                );
                routes.edges.insert(raw, None);
                continue;
            }
            routes.rekey(&raw, (src, kind, tgt));
            if key.world().is_some() {
                continue;
            }
            // A world edge rides its world endpoint's window, the source's
            // first (`edge_belongs_to_window`).
            for end in [src, tgt] {
                let moved = routes.claims.get(&end).copied();
                let part = match moved {
                    Some(part) => Some(part),
                    None => placed
                        .stored_window(vault, end)?
                        .map(|window| routes.part(window)),
                };
                if let Some(part) = part {
                    routes.edges.insert(raw, Some(part));
                    break;
                }
            }
        }
        Ok(routes)
    }

    /// Names the guest's WORLDs that land under foreign ids here (FIX 3657):
    /// each `carried` WORLD row, and each `named` id whose foreign copy this
    /// vault already stores as a WORLD row, which only that WORLD's earlier
    /// copy from `guest` puts there. Any other id keeps its own, PERSON and
    /// CLAIM ids among them, and so does a WORLD whose row has not arrived.
    fn rename_worlds(
        &mut self,
        vault: &Vault,
        guest: &[u8; 32],
        carried: Vec<EntityId>,
        named: BTreeSet<EntityId>,
    ) -> Result<()> {
        for id in carried {
            let here = crate::federation::foreign_world_for(guest, id)?.entity_id();
            self.worlds.insert(id, here);
        }
        for id in named {
            if self.worlds.contains_key(&id) {
                continue;
            }
            let here = crate::federation::foreign_world_for(guest, id)?.entity_id();
            let stored = vault.get_raw_unsealed(&here)?;
            if stored
                .as_deref()
                .and_then(EntityMetadataHeader::parse)
                .is_some_and(|header| header.entity_type == ENTITY_TYPE_WORLD)
            {
                self.worlds.insert(id, here);
            }
        }
        Ok(())
    }

    /// Lands the edge keyed `raw` under the key its renamed WORLD endpoints
    /// name, when it is an InWorld or SetIn edge naming one (FIX 3657).
    fn rekey(&mut self, raw: &str, (src, kind, tgt): (EntityId, EdgeKind, EntityId)) {
        if !is_world_edge(kind) {
            return;
        }
        let here = |id: EntityId| self.worlds.get(&id).copied().unwrap_or(id);
        let (to_src, to_tgt) = (here(src), here(tgt));
        if (to_src, to_tgt) != (src, tgt) {
            let key = super::bridge::format_edge_key(&to_src, kind, &to_tgt);
            self.rekeyed.insert(raw.to_owned(), key);
        }
    }

    /// The guest's update as its rows are copied; `None` with no guest
    /// source.
    fn guest_copy(&self) -> Option<GuestCopy<'_>> {
        self.guest.map(|source| GuestCopy {
            source,
            worlds: &self.worlds,
        })
    }

    /// The part landing in `window`, a new one when none does yet.
    fn part(&mut self, window: WindowKey) -> usize {
        match self.keys.iter().position(|key| *key == window) {
            Some(part) => part,
            None => {
                self.keys.push(window);
                self.keys.len() - 1
            }
        }
    }

    /// The part the entity keyed `raw` lands in; `None` withholds it.
    fn entity_part(&self, raw: &str) -> Option<usize> {
        match EntityId::from_hex(raw) {
            Ok(id) if id.to_hex() == raw => {
                (!self.withheld.contains(&id)).then(|| self.claims.get(&id).copied().unwrap_or(0))
            }
            _ => Some(0),
        }
    }

    /// The edges `part` copies, when they are not the whole update's, each
    /// under the key it lands under.
    fn edges_of(&self, remote: &LoroDoc, part: usize) -> Result<Option<LoroDoc>> {
        if self.withheld.is_empty()
            && self.edges.is_empty()
            && self.rekeyed.is_empty()
            && self.keys.len() == 1
        {
            return Ok(None);
        }
        let routed = LoroDoc::new();
        let edges = routed.get_map("edges");
        let mut result = Ok(());
        map_for_each_value_bytes(&remote.get_map("edges"), |raw, value| {
            if result.is_ok()
                && self.edges.get(raw).copied().unwrap_or(Some(0)) == Some(part)
                && let Some(value) = value
            {
                let key = self.rekeyed.get(raw).map_or(raw, String::as_str);
                result = map_insert_bytes(&edges, key, value);
            }
        });
        result.map(|()| Some(routed))
    }
}

/// Where the endpoints of a guest's edges sit here once its CLAIMs land in
/// their foreign WORLDs (FIX 3660): a carried CLAIM in the foreign WORLD its
/// sender's world maps to, any other in the foreign WORLD this vault stores
/// it in. Each is read once.
#[cfg(feature = "sync")]
struct Placement<'a> {
    guest: &'a [u8; 32],
    /// Each carried CLAIM the update does not withhold, with its world as
    /// the sender names it.
    claims: BTreeMap<EntityId, Option<EntityId>>,
    /// Each sender world's foreign WORLD, once derived.
    foreign: BTreeMap<Option<EntityId>, EntityId>,
    /// Each stored row's foreign window, once read.
    stored: BTreeMap<EntityId, Option<WindowKey>>,
}

#[cfg(feature = "sync")]
impl<'a> Placement<'a> {
    const fn new(guest: &'a [u8; 32]) -> Self {
        Self {
            guest,
            claims: BTreeMap::new(),
            foreign: BTreeMap::new(),
            stored: BTreeMap::new(),
        }
    }

    /// The foreign WORLD the guest CLAIM in the sender's `world` lands in.
    fn foreign_of(&mut self, world: Option<EntityId>) -> Result<EntityId> {
        if let Some(here) = self.foreign.get(&world) {
            return Ok(*here);
        }
        let here = crate::federation::guest_claim_world(self.guest, world)?.entity_id();
        self.foreign.insert(world, here);
        Ok(here)
    }

    /// The foreign WORLD `id` is proven to sit in here; `None` when it sits in
    /// none, or nothing here proves where it sits.
    fn foreign_world(&mut self, vault: &Vault, id: EntityId) -> Result<Option<EntityId>> {
        if let Some(world) = self.claims.get(&id).copied() {
            return self.foreign_of(world).map(Some);
        }
        Ok(self
            .stored_window(vault, id)?
            .and_then(|window| window.world()))
    }

    /// The window a CLAIM this vault stores in a foreign WORLD resides in.
    fn stored_window(&mut self, vault: &Vault, id: EntityId) -> Result<Option<WindowKey>> {
        if let Some(window) = self.stored.get(&id) {
            return Ok(window.clone());
        }
        let window = stored_foreign_window(vault, &id)?;
        self.stored.insert(id, window.clone());
        Ok(window)
    }
}

/// Whether an edge of `kind` places its endpoints in a world, one of them a
/// WORLD.
#[cfg(feature = "sync")]
const fn is_world_edge(kind: EdgeKind) -> bool {
    matches!(kind, EdgeKind::InWorld | EdgeKind::SetIn)
}

/// The endpoints of the InWorld or SetIn edge a CLAIM is about.
#[cfg(feature = "sync")]
const fn world_edge_subject(subject: &ClaimSubject) -> Option<[EntityId; 2]> {
    match *subject {
        ClaimSubject::Edge {
            source,
            kind,
            target,
        } if is_world_edge(kind) => Some([source, target]),
        _ => None,
    }
}

/// A guest CLAIM about an InWorld or SetIn edge names the edge by the ids
/// its copy lands under (FIX 3657).
#[cfg(feature = "sync")]
fn rename_world_edge_subject(subject: &mut ClaimSubject, worlds: &BTreeMap<EntityId, EntityId>) {
    if let ClaimSubject::Edge {
        source,
        kind,
        target,
    } = subject
        && is_world_edge(*kind)
    {
        for end in [source, target] {
            if let Some(here) = worlds.get(&*end) {
                *end = *here;
            }
        }
    }
}

/// The policy hook for a guest's edge whose endpoints sit in two different
/// foreign WORLDs here (FIX 3660, CALLS "FIX 3660 cross-world edge
/// containment"). Such an edge fits no window (`edge_worlds_match`), and the
/// Engine keeps it refused (CALLS "FIX 3497 base-window guest split"). Given
/// the foreign WORLD each endpoint is proven to sit in, this says whether the
/// refusal stops at the edge: it is quarantined terminally before it enters
/// the copied doc, so the rows and edges beside it still land, rather than
/// left in its part for window residence to refuse the part whole. An
/// endpoint nothing proves (`None`) is never taken as base or as any world.
#[cfg(feature = "sync")]
fn contains_cross_world_edge(src: Option<EntityId>, tgt: Option<EntityId>) -> bool {
    matches!((src, tgt), (Some(src), Some(tgt)) if src != tgt)
}

/// The refusal a contained cross-world edge is quarantined under: the one
/// window residence gives it (`check_edge_residence`).
#[cfg(feature = "sync")]
fn cross_world_edge_refusal() -> Error {
    Error::InvalidConfig("edge outside window residence".into())
}

/// The window a CLAIM this vault stores in a foreign WORLD resides in.
#[cfg(feature = "sync")]
fn stored_foreign_window(vault: &Vault, id: &EntityId) -> Result<Option<WindowKey>> {
    let Some(raw) = vault.get_raw_unsealed(id)? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    Ok(crate::sync::types::entity_world(&raw)
        .ok()
        .flatten()
        .filter(|world| crate::entity_id::is_foreign_world_id_range(*world))
        .map(|world| WindowKey::for_world(header.learned_at, world)))
}

/// Re-runs federated claim admission over ALREADY-ADMITTED window bytes using
/// the policy resolved RIGHT NOW.
///
/// `admit_federated_window_update` evaluates claims against the policy that was
/// resolved at ADMISSION time. A staged vault import parks those bytes behind a
/// durable Pending receipt, and the human confirmation that releases them can
/// land arbitrarily later — so the policy the operator actually consented under
/// is the one in force at CONFIRM time, not the one that happened to be loaded
/// when the artifact was first staged. This door re-resolves the manifest with
/// the same resolver the stage leg uses and re-applies the same claim gate.
///
/// It deliberately re-checks the admitted bytes AS THEY ARE rather than
/// re-deriving a fresh admitted doc: the receipt pins their digest, so a
/// re-admission would produce different bytes and break the digest bind. The
/// claims inside are already restamped to `src=imported`, which is exactly the
/// source the gate must judge on the import path, so no restamp is repeated.
///
/// Non-claim rows were admitted by identity/kind rules that do not depend on
/// resolved policy, so they are left alone here, except an agent definition:
/// it is judged again against the definition stored now, so one turned off
/// since the stage does not come back on through the confirmation.
#[cfg(feature = "sync")]
pub(in crate::sync) fn revalidate_admitted_federated_claims(
    vault: &Vault,
    key: &WindowKey,
    admitted_update: &[u8],
    role: FederationAdmissionRole,
) -> Result<()> {
    let admitted = create_window_doc(role.origin(), key);
    admitted.import(admitted_update).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "import admitted update",
            source,
        })
    })?;

    let policy = vault
        .with_write_txn_grouped(|wtxn| crate::gate::resolve_policy_manifest(&vault.store, wtxn))?;

    let rtxn = vault.store.env.read_txn()?;
    let mut result = Ok(());
    map_for_each_value_bytes(&admitted.get_map("entities"), |key, value| {
        if result.is_err() {
            return;
        }
        result = recheck_admitted_claim_blob(&vault.store, &policy, value).and_then(|()| {
            let id = EntityId::from_hex(key).map_err(|_| Error::InvalidKey)?;
            let blob = value.ok_or(Error::InvalidKey)?;
            refuse_peer_agent_definition_widening(&vault.store, &rtxn, &id, blob)
        });
    });
    result
}

/// Refuses ALREADY-ADMITTED window bytes that carry a facet stamp
/// ([`refuse_admitted_stamps`]), so a staged artifact an older door admitted
/// with its stamps in its bytes is not confirmed (non-terminal, as a claim
/// refusal is).
#[cfg(feature = "sync")]
pub(in crate::sync) fn revalidate_admitted_facet_stamps(
    key: &WindowKey,
    admitted_update: &[u8],
) -> Result<()> {
    let admitted = create_window_doc("federation-staged", key);
    admitted.import(admitted_update).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "import admitted update",
            source,
        })
    })?;
    refuse_admitted_stamps(&admitted.get_map("edges"))
}

#[cfg(feature = "sync")]
fn recheck_admitted_claim_blob(
    store: &crate::store::Store,
    policy: &crate::gate::PolicyManifestResolution,
    value: Option<&[u8]>,
) -> Result<()> {
    let blob = value.ok_or(Error::InvalidKey)?;
    let header =
        EntityMetadataHeader::parse(blob).ok_or(Error::CorruptedIndex("entity metadata"))?;
    if crate::sync::pack_sync::is_pack_handle(header.entity_type) {
        return validate_federated_pack(store, blob);
    }
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(());
    }
    let body = validate_claim_body_and_decode(&blob[ENTITY_METADATA_HEADER_LEN..], true)?;
    crate::gate::check_federated_claim_admission(store, &body, policy)
}

/// The doc one part of an admission is authored in. Its op ids derive from
/// the window it lands in, the update, the role and, for a guest's update, the
/// source vault its CLAIMs are remapped under (FIX 3497), so one op id never
/// carries two payloads.
#[cfg(feature = "sync")]
fn create_admission_doc(
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
    guest: Option<&[u8; 32]>,
) -> Result<LoroDoc> {
    let doc = LoroDoc::new();
    doc.set_peer_id(federated_admission_peer_id(key, update, role, guest))
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroSetPeerId, e))?;
    let _entities = doc.get_map("entities");
    let _edges = doc.get_map("edges");
    let _tombstones = doc.get_map("tombstones");
    doc.commit();
    Ok(doc)
}

#[cfg(feature = "sync")]
fn federated_admission_peer_id(
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
    guest: Option<&[u8; 32]>,
) -> u64 {
    let mut material = Vec::with_capacity(
        b"oneiron.federation.admission.peer.v0".len()
            + role.origin().len()
            + key.as_str().len()
            + std::mem::size_of::<u64>()
            + update.len(),
    );
    material.extend_from_slice(b"oneiron.federation.admission.peer.v0");
    material.extend_from_slice(&(role.origin().len() as u64).to_le_bytes());
    material.extend_from_slice(role.origin().as_bytes());
    material.extend_from_slice(&(key.as_str().len() as u64).to_le_bytes());
    material.extend_from_slice(key.as_str().as_bytes());
    material.extend_from_slice(&(update.len() as u64).to_le_bytes());
    material.extend_from_slice(update);
    if let Some(source) = guest {
        material.extend_from_slice(&(source.len() as u64).to_le_bytes());
        material.extend_from_slice(source);
    }

    match xxh3_64(&material) {
        0 => 1,
        u64::MAX => u64::MAX - 1,
        peer_id => peer_id,
    }
}

/// Test-only helper for downstream crates that need to seed a grant-backed
/// selector without opening the public maintenance-band write gate.
#[cfg(feature = "test-hooks")]
pub fn put_selector_test_federation_grant(
    vault: &Vault,
    grant_id: &EntityId,
    grant: &crate::federation::FederationGrant,
    learned_at: u64,
) -> Result<()> {
    let body = crate::federation::encode_federation_grant_body(grant)?;
    vault
        .batch()
        .put_replicated(
            grant_id,
            ENTITY_TYPE_FEDERATION_GRANT,
            crate::temporal::TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        )
        .commit()
}

/// Copies the rows `routes` lands in `part` from `source` into `target`, each
/// under the id it lands under.
#[cfg(feature = "sync")]
fn copy_admitted_entities(
    vault: &Vault,
    policy: &crate::gate::PolicyManifestResolution,
    source: &LoroDoc,
    target: &LoroDoc,
    grading: ImportGrading,
    routes: &Routes<'_>,
    part: usize,
) -> Result<()> {
    let source_entities = source.get_map("entities");
    let target_entities = target.get_map("entities");
    let rtxn = vault.store.env.read_txn()?;
    let mut result = Ok(());
    map_for_each_value_bytes(&source_entities, |key, value| {
        if result.is_err() || routes.entity_part(key) != Some(part) {
            return;
        }
        result = admit_federated_entity_blob_graded(
            vault,
            policy,
            &rtxn,
            key,
            value,
            grading,
            routes.guest_copy(),
        )
        .and_then(|(here, blob)| map_insert_bytes(&target_entities, &here.to_hex(), &blob));
    });
    result
}

#[cfg(feature = "sync")]
pub(crate) fn admit_federated_entity_blob(
    vault: &Vault,
    policy: &crate::gate::PolicyManifestResolution,
    txn: &heed::RoTxn<'_>,
    key: &str,
    value: Option<&[u8]>,
) -> Result<Vec<u8>> {
    admit_federated_entity_blob_graded(
        vault,
        policy,
        txn,
        key,
        value,
        ImportGrading::Imported {
            scale: super::DEFAULT_FEDERATED_CONFIDENCE_SCALE,
        },
        None,
    )
    .map(|(_, blob)| blob)
}

/// [`admit_federated_entity_blob`] with the sending peer's `grading` for a
/// CLAIM, TURN or CONVERSATION, and the id the row lands under: the key it
/// came under, but for a guest's WORLD. A guest's CLAIM lands in its foreign
/// WORLD copy (FIX 3497), and a guest's WORLD row under that copy's id, its
/// bytes as they came (FIX 3657).
#[cfg(feature = "sync")]
fn admit_federated_entity_blob_graded(
    vault: &Vault,
    policy: &crate::gate::PolicyManifestResolution,
    txn: &heed::RoTxn<'_>,
    key: &str,
    value: Option<&[u8]>,
    grading: ImportGrading,
    guest: Option<GuestCopy<'_>>,
) -> Result<(EntityId, Vec<u8>)> {
    let blob = value.ok_or(Error::InvalidKey)?;
    let id = EntityId::from_hex(key).map_err(|_| Error::InvalidKey)?;
    if key != id.to_hex() {
        return Err(Error::InvalidKey);
    }

    let header =
        EntityMetadataHeader::parse(blob).ok_or(Error::CorruptedIndex("entity metadata"))?;
    if crate::sync::pack_sync::is_pack_handle(header.entity_type) {
        validate_federated_pack(&vault.store, blob)?;
        return Ok((id, blob.to_vec()));
    }
    if header.entity_type != ENTITY_TYPE_CLAIM {
        if header.entity_type == ENTITY_TYPE_AUTHORITY_LOG {
            admit_federated_authority_log(vault, &id, &blob[ENTITY_METADATA_HEADER_LEN..])?;
            return Ok((id, blob.to_vec()));
        }
        // A guest's WORLD row lands under the foreign id its CLAIMs in that
        // world name here, in the window it came in: WORLD is no window's
        // world carrier (`entity_world`). Its body is unsigned and kept as
        // it came. No leaf in it is authority here: a world's privacy and
        // owner come only from a signed `AuthorityOp::WorldPrivacy`, and none
        // of the sender's names this id. The key was judged as it came; the
        // checks bound to a row's id judge the id it lands under.
        let here = match guest {
            Some(guest) if header.entity_type == ENTITY_TYPE_WORLD => {
                crate::federation::foreign_world_for(guest.source, id)?.entity_id()
            }
            _ => id,
        };
        // The same registry classification decides writability and admission.
        // Unknown bytes cannot become peer-writable because they lie in a range.
        vault
            .store
            .validate_public_entity_type(header.entity_type)?;
        if crate::federation::selector_range_of(header.entity_type).is_none()
            && vault
                .structural_kind_registration(header.entity_type)
                .is_none_or(|registration| registration.family.is_none())
        {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        validate_admitted_replicated_body(
            &here,
            header.entity_type,
            &blob[ENTITY_METADATA_HEADER_LEN..],
        )?;
        refuse_peer_agent_definition_widening(&vault.store, txn, &here, blob)?;
        if matches!(grading, ImportGrading::Imported { .. })
            && matches!(
                header.entity_type,
                ENTITY_TYPE_TURN | ENTITY_TYPE_CONVERSATION
            )
        {
            return restamp_federated_transcript(blob).map(|blob| (here, blob));
        }
        return Ok((here, blob.to_vec()));
    }

    let body = validate_claim_body_and_decode(&blob[ENTITY_METADATA_HEADER_LEN..], true)?;
    let mut body = match grading {
        ImportGrading::Imported { scale } => {
            downweight_federated_claim(restamp_federated_claim_source(body), scale)?
        }
        ImportGrading::FirstParty => body,
    };
    if let Some(guest) = guest {
        // Its world is the recipient's before the gate judges it, so the copy
        // the gate passes is the copy every later step sees.
        body.world =
            Some(crate::federation::guest_claim_world(guest.source, body.world)?.entity_id());
        rename_world_edge_subject(&mut body.subject, guest.worlds);
    }
    crate::gate::check_federated_claim_admission(&vault.store, &body, policy)?;
    let encoded = crate::claim::encode_claim_body(&body)?;

    let mut admitted = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + encoded.len());
    admitted.extend_from_slice(&blob[..ENTITY_METADATA_HEADER_LEN]);
    admitted.extend_from_slice(&encoded);
    Ok((id, admitted))
}

/// Refuses a peer's agent definition that turns the one stored at `id` back
/// on, read in `txn`. Turning a definition back on is the owner's, and a peer
/// is not the owner. Typed as the peer's bytes, so the frame quarantines.
#[cfg(feature = "sync")]
fn refuse_peer_agent_definition_widening(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    blob: &[u8],
) -> Result<()> {
    let header =
        EntityMetadataHeader::parse(blob).ok_or(Error::CorruptedIndex("entity metadata"))?;
    if header.entity_type == crate::registry::ENTITY_TYPE_AGENT_DEF
        && crate::agent_def::agent_definition_put_widens_in_txn(
            store,
            txn,
            id,
            &blob[ENTITY_METADATA_HEADER_LEN..],
        )?
    {
        return Err(Error::Artifact(
            crate::error::ArtifactError::InvalidAgentDefBody(
                "a federation peer cannot turn an agent definition back on",
            ),
        ));
    }
    Ok(())
}

/// The source a foreign TURN or CONVERSATION is stamped with (OF-149).
pub(crate) const FEDERATION_IMPORT_SOURCE: &str = "federation";

/// A peer's TURN or CONVERSATION is imported evidence, never the owner's live
/// words, unless the peer is a verified member ([`ImportGrading::FirstParty`]):
/// its body is stamped with the federation import source unless the peer
/// already named one. The stamp is a birth fact, so a peer row landing
/// on an unstamped local one is refused by the put door, never relabelled.
/// An empty body (a deleted shell) carries no words and passes unchanged.
#[cfg(feature = "sync")]
fn restamp_federated_transcript(blob: &[u8]) -> Result<Vec<u8>> {
    let body = &blob[ENTITY_METADATA_HEADER_LEN..];
    if body.is_empty() {
        return Ok(blob.to_vec());
    }
    let refused = || -> Error {
        RecordError::InvalidConversationBody("a federated transcript body must be a map").into()
    };
    let mut cursor = std::io::Cursor::new(body);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| refused())?;
    if cursor.position() != body.len() as u64 {
        return Err(refused());
    }
    let rmpv::Value::Map(mut entries) = value else {
        return Err(refused());
    };
    let key = crate::memory::IMPORTED_SOURCE_KEY;
    match entries
        .iter()
        .filter(|(name, _)| name.as_str() == Some(key))
        .count()
    {
        0 => entries.push((
            rmpv::Value::from(key),
            rmpv::Value::from(FEDERATION_IMPORT_SOURCE),
        )),
        1 => return Ok(blob.to_vec()),
        _ => return Err(refused()),
    }
    let mut encoded = Vec::with_capacity(blob.len() + 32);
    encoded.extend_from_slice(&blob[..ENTITY_METADATA_HEADER_LEN]);
    rmpv::encode::write_value(&mut encoded, &rmpv::Value::Map(entries)).map_err(|_| refused())?;
    Ok(encoded)
}

/// ARCH-0043 requires a down-weight but does not prescribe a factor. The
/// sending peer's owner-set scale applies, by default
/// [`super::DEFAULT_FEDERATED_CONFIDENCE_SCALE`] for every federated role. A
/// verified member's claims take none ([`ImportGrading::FirstParty`]).
fn downweight_federated_claim(
    mut body: crate::claim::ClaimBody,
    scale: f32,
) -> Result<crate::claim::ClaimBody> {
    const AUDIT_KEY: &str = "federated_original_confidence";
    let original = body.confidence;
    body.confidence *= scale;
    if body.predicate == crate::provenance::PREDICATE_EDGE_PROVENANCE {
        // The wrapper and value record carry the same confidence. Keep both
        // graded values equal so admission cannot create an invalid replay row.
        let mut record = crate::provenance::decode_edge_provenance_body(&body.value)?;
        record.confidence = body.confidence;
        body.value = crate::provenance::encode_edge_provenance_value(&record);
    }
    let mut entries = match body.scope.take() {
        Some(rmpv::Value::Map(entries)) => entries,
        Some(scope) => vec![(rmpv::Value::from("pre_federated_confidence_scope"), scope)],
        None => Vec::new(),
    };
    entries.retain(|(key, _)| key.as_str() != Some(AUDIT_KEY));
    entries.push((rmpv::Value::from(AUDIT_KEY), rmpv::Value::F32(original)));
    body.scope = Some(rmpv::Value::Map(entries));
    Ok(body)
}

/// Per-kind body validation for the non-CLAIM federation admission arm.
///
/// FED-1093: kind WRITABILITY is not admission. This arm previously checked
/// only that the metadata header parsed and that the type byte was not
/// engine-authored, then copied the peer's bytes verbatim — so a body that
/// `apply_put` is guaranteed to refuse (a TASK carrying no role, an undecodable
/// SKILL) entered the ADMITTED doc. The staged foreign import then pinned that
/// doc's digest, the confirmation marked the receipt `Confirmed`
/// unconditionally, and replay quarantined the offending row and continued —
/// so the operator consented to an import that silently dropped it. The
/// confirm GCs the staged content in the same txn, and the artifact's
/// `receipt_id` is re-derived from its own bytes, so the drop cannot be undone
/// by re-presenting it. CLAIM and AUTHORITY_LOG already refuse their invalid
/// bodies at this door; every other kind whose body schema is PINNED refuses
/// here too, before any receipt exists.
///
/// Only the STATELESS half of `apply_put`'s per-kind chain is mirrored, and it
/// delegates to the very same validators, so this door cannot judge a body
/// materialization would accept. Store-reading rules (authority-log store-key
/// binding and gate policy) stay where they can
/// read a transaction — this is a fail-closed prefilter, never the authority:
/// materialization still re-validates every row it is handed. Kinds with no
/// pinned body schema stay opaque here exactly as they are at the storage
/// layer, and the maintenance kinds are unreachable — the writability test
/// above has already rejected them.
///
/// A FACET is a scenario mask, never a store for PERSON identity: an
/// identity-shaped FACET body takes the shared sync identity refusal before an
/// import receipt can be staged, so a peer cannot confirm bytes that
/// materialization must discard.
#[cfg(feature = "sync")]
fn validate_admitted_replicated_body(id: &EntityId, entity_type: u8, body: &[u8]) -> Result<()> {
    if entity_type != crate::registry::ENTITY_TYPE_AGENT_DEF {
        crate::agent_def::validate_put_at_seeded_id(id, entity_type, None)?;
    }
    validate_sync_identity_body(entity_type, body)?;
    match entity_type {
        crate::registry::ENTITY_TYPE_RECEIPT_RECORD => {
            crate::receipt::validate_receipt_record_body(id, body)?;
        }
        crate::registry::ENTITY_TYPE_TASK => {
            crate::habit::task_role_from_body_bytes(body)?;
        }
        crate::registry::ENTITY_TYPE_CODE_ARTIFACT => {
            crate::code_artifact::validate_code_artifact_body_bytes(body)?;
        }
        crate::registry::ENTITY_TYPE_BLOB_ARTIFACT => {
            crate::blob_artifact::validate_blob_artifact_body_bytes(body)?;
        }
        crate::registry::ENTITY_TYPE_SKILL => {
            crate::skill::decode_skill_record(body)?;
        }
        crate::registry::ENTITY_TYPE_AGENT_DEF => {
            let definition = crate::agent_def::decode_agent_definition(body)?;
            crate::agent_def::validate_reserved_logical_id(id, &definition)?;
            crate::agent_def::validate_put_at_seeded_id(id, entity_type, Some(&definition))?;
        }
        _ => {}
    }
    Ok(())
}

/// The one sync identity-body refusal. PERSON holds identity and a FACET is a
/// scenario mask, so a FACET body shaped as a persona or relationship is
/// refused. Federated body admission and raw full-window admission both call
/// this; neither copies the predicate.
#[cfg(feature = "sync")]
pub(in crate::sync) fn validate_sync_identity_body(entity_type: u8, body: &[u8]) -> Result<()> {
    if entity_type == crate::registry::ENTITY_TYPE_FACET
        && crate::companion::is_identity_facet_body(body)
    {
        return Err(Error::InvalidClaimBody(
            "FACET cannot carry PERSON identity",
        ));
    }
    Ok(())
}

/// Federation admission door for a AUTHORITY_LOG carrier.
///
/// ONE-1604-D1 (fix-leg 4): the CRDT row's KEY is bound to the id derived
/// from the decoded body, exactly as `check_authority_log_store_key` binds it
/// at the write door. Without the bind, admission validated the body and the
/// vault root but never checked that the body belonged at `id` — so a
/// wrong-key authority row entered the ADMITTED doc and only failed later at
/// materialize. That is strictly worse than rejecting here: the admitted doc
/// is what the ordinary replay path imports, so the mismatch surfaced after
/// the row had already been copied into locally authored bytes, and anything
/// this door scopes off the same key operated on a row that could never be
/// admitted under it.
///
/// The bind is a REMOTE rejection, not a local failure:
/// `AuthorityLogStoreKeyMismatch` is already classified in
/// `quarantine::remote_rejection_reason`, so the replay sites quarantine the
/// row and continue rather than aborting the window (H2). Deriving the id
/// costs one hash over bytes this function has already decoded.
#[cfg(feature = "sync")]
fn admit_federated_authority_log(vault: &Vault, id: &EntityId, body: &[u8]) -> Result<()> {
    validate_authority_log_entry_body_bytes(body)?;
    let entry = decode_authority_log_entry_body(body)?;
    if authority_log_entity_id(&entry)? != *id {
        return Err(Error::Record(RecordError::AuthorityLogStoreKeyMismatch {
            id: *id,
        }));
    }
    let entry_vault_id = match &entry.op {
        AuthorityOp::Genesis { .. } => genesis_vault_id(&entry)?,
        _ => entry
            .vault_id
            .ok_or(Error::Record(RecordError::InvalidAuthorityLogBody(
                "missing authority vault id",
            )))?,
    };
    let local = vault.authority_fold()?;
    let local_vault_id =
        local
            .vault_id
            .ok_or(Error::Record(RecordError::InvalidAuthorityLogBody(
                "missing local authority root",
            )))?;
    if entry_vault_id != local_vault_id {
        return Err(Error::Record(RecordError::InvalidAuthorityLogBody(
            "foreign authority log vault id",
        )));
    }
    let rtxn = vault.store.env.read_txn()?;
    let evidence = crate::authority::adopted_evidence_in_txn(&vault.store, &rtxn)?;
    if !crate::authority::authority_row_resident(&vault.store, &rtxn, &entry)?
        && crate::authority::door_refuses_retired_standing(
            &vault.store,
            &local,
            &authority_entry_hash(&entry)?,
            &entry,
            &mut |hash| {
                crate::authority::door_ancestor_row(&vault.store, &rtxn, evidence.as_deref(), hash)
            },
        )?
    {
        return Err(Error::Record(RecordError::InvalidAuthorityLogBody(
            "authority row signed by a key a handoff retired",
        )));
    }
    Ok(())
}

#[cfg(feature = "sync")]
fn reject_federated_tombstones(source: &LoroDoc) -> Result<()> {
    let mut has_tombstone = false;
    map_for_each_tombstone_value(&source.get_map("tombstones"), |_, _| {
        has_tombstone = true;
    });
    if has_tombstone {
        return Err(Error::sync_protocol(
            SyncProtocolValidation::FederatedTombstoneAdmission,
        ));
    }
    Ok(())
}

#[cfg(feature = "sync")]
fn validate_federated_pack(store: &crate::store::Store, blob: &[u8]) -> Result<()> {
    let source = crate::registry::pack_byte_map::PackInstanceEnvelope::from_bytes(
        &blob[ENTITY_METADATA_HEADER_LEN..],
    )?;
    let txn = store.env.read_txn()?;
    let (handle, local) = store.remap_pack_instance_in_txn(&txn, &source)?;
    store.validate_pack_instance_in_txn(&txn, handle, &local.to_bytes()?)
}

#[cfg(all(test, feature = "sync"))]
mod retired_facet_tests {
    use super::*;

    #[test]
    fn valid_legacy_facet_refused_before_sync_admission_but_scenario_is_allowed() {
        let person = crate::test_util::entity(0x71);
        let id = crate::test_util::entity(0x72);
        let legacy = crate::companion::tests::support::retired_persona_facet_body(person);
        assert!(matches!(
            validate_admitted_replicated_body(&id, crate::registry::ENTITY_TYPE_FACET, &legacy),
            Err(Error::Record(RecordError::InvalidCompanionRecordBody(_)))
        ));
        let scenario = rmp_serde::to_vec_named(&serde_json::json!({
            "kind": "scenario", "person_ref": person.to_hex()
        }))
        .expect("scenario fixture");
        assert!(
            validate_admitted_replicated_body(&id, crate::registry::ENTITY_TYPE_FACET, &scenario,)
                .is_ok()
        );
    }
}

#[cfg(all(test, feature = "sync"))]
mod suppression_carrier_tests {
    use super::*;
    use crate::receipt::{ReceiptKind, ReceiptRecord};
    use serde::Serialize;

    #[derive(Serialize)]
    struct ForgedCarrier {
        intent_id: [u8; 32],
        receipt: ReceiptRecord,
    }

    #[test]
    fn replicated_admission_refuses_truncated_and_wrong_id_suppression_assets() {
        let id = EntityId::from_bytes([0x87; 16]).expect("fixture id");
        let malformed = b"invalid receipt";
        assert!(
            validate_admitted_replicated_body(
                &id,
                crate::registry::ENTITY_TYPE_RECEIPT_RECORD,
                malformed
            )
            .is_err()
        );
        let receipt = ReceiptRecord {
            receipt_id: format!(
                "outbound:suppression:{}",
                crate::entity_id::bytes_to_hex_lower(&[0x88; 32])
            ),
            receipt_kind: ReceiptKind::Outbound,
            occurred_at: 1,
            actor: None,
            on_behalf_of: None,
            outcome: "suppressed".to_owned(),
            job_ref: None,
            trigger_ref: None,
            policy_trace: Vec::new(),
            fields: [
                ("suppression".to_owned(), "dedupe".to_owned()),
                ("dedupe_key".to_owned(), "same".to_owned()),
            ]
            .into(),
        };
        let body = rmp_serde::to_vec_named(&ForgedCarrier {
            intent_id: [0x88; 32],
            receipt,
        })
        .expect("encode forged carrier");
        assert!(
            validate_admitted_replicated_body(
                &id,
                crate::registry::ENTITY_TYPE_RECEIPT_RECORD,
                &body
            )
            .is_err()
        );
    }
}
