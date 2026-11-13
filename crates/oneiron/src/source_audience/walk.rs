//! The source-audience conjunct every audience read meets: a row reads to
//! its viewers only while each of them reads under the policy it was born
//! under, and under the policies of what its words came from.
//!
//! What a row's words came from, as this walk reads it:
//! - a MESSAGE's TURN (`PartOf`);
//! - a TURN's MESSAGE rows (`PartOf` into it): its text is projected from
//!   them, so a row written from a TURN reads under its MESSAGEs' sources;
//! - every record a row is `DerivedFrom` (an attachment's text, an EVENT a
//!   message proposed, an epoch summary);
//! - the records and MESSAGEs a summary, a merge header or a copied reply
//!   carries words from ([`crate::scope_summary::word_sources_in`]), and a
//!   scope summary's covers;
//! - a CLAIM's entity subject.
//!
//! Each of those must read: a summary of a private thread is as private as
//! the thread. A CLAIM is the one union: its supporting sources (`Supports`
//! into it) are the evidence it was learned from, and a claim learned from
//! a personal mailbox alone reads only to that mailbox's readers, while one
//! any reader could also have learned from a source they read stays theirs
//! too. A claim with no support restricts nothing by this rule.
//!
//! A row nothing binds and whose words came from nothing bound reads as
//! before. A policy that does not resolve denies, and a read that
//! authenticates no one reads no bound row, as a private thread is read
//! (FIX 2951). A cycle adds no restriction of its own.
//!
//! A row a source landed carries the source-audience obligation in its own
//! bytes (fix list row 16256): the engine's landing stamps it on every row it
//! binds, a MESSAGE as much as its TURN, so a MESSAGE whose TURN or `PartOf`
//! edge has not arrived is still known. A stamp in any shape, valid or not,
//! marks the row, whatever its kind. Such a row read where its binding is
//! absent reads to no one. Bindings and policies travel with their rows on
//! the owner's full-window lane only ([`super::replica`]): a row bound to a
//! policy that resolves here leaves by it, its binding beside it; a row
//! whose words came from a row bound otherwise, and every bound row on any
//! other lane, does not leave this vault ([`withheld_from_replication_in`]).
//! A row held back here ([`super::HeldBack`]: its carried binding waits for
//! its policy, or the vault it came from withheld it after it travelled)
//! reads to no one, and neither does a row whose words came from it.
//!
//! An Owner's whole-vault export asks the same walk which source each row
//! came from ([`ExportJudge`], fix list row 15416): a row whose lineage
//! reaches a source the export leaves out stays home, and so does a row a
//! source landed with no binding here. A source no connection here names
//! goes as the exporter reads it. The export reuses each verdict across its
//! whole pass, so a verdict reached through a row still being judged stands
//! only until that row settles: a denial takes it back.

use std::collections::{BTreeMap, BTreeSet};

use crate::EdgeKind;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::{EntityId, Vault};

/// Whether the row bytes `raw` are one a source audience landed: its OWN
/// body states the source-audience obligation, valid or malformed, whatever
/// its kind (fix list row 16256). No parent, edge or import label is read.
fn source_marked(raw: &[u8]) -> bool {
    super::obligation::row_obligation(raw).is_present()
}

/// What the words of the row `id` (bytes `bytes`) came from, as the walk
/// reads it: the rows each of which must read, and a CLAIM's supports, one
/// of which must.
fn word_sources(
    vault: &Vault,
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    bytes: &[u8],
) -> Result<(Vec<EntityId>, Vec<EntityId>)> {
    let header = EntityMetadataHeader::parse(bytes)
        .ok_or(Error::CorruptedIndex("source audience row header"))?;
    let body = bytes.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
    let mut every = Vec::new();
    if header.entity_type == ENTITY_TYPE_MESSAGE {
        every.extend(crate::conversation_dag::counted_edge_ids(
            dbs,
            txn,
            &id,
            EdgeKind::PartOf,
            false,
        )?);
    }
    // A TURN's words are its MESSAGE rows' (FIX SOURCE-AUDIENCE-TURN-MESSAGE-LINEAGE):
    // each row `PartOf` it must read. The cycle back through a MESSAGE's own
    // `PartOf` adds nothing.
    if header.entity_type == ENTITY_TYPE_TURN {
        every.extend(crate::conversation_dag::counted_edge_ids(
            dbs,
            txn,
            &id,
            EdgeKind::PartOf,
            true,
        )?);
    }
    every.extend(crate::conversation_dag::counted_edge_ids(
        dbs,
        txn,
        &id,
        EdgeKind::DerivedFrom,
        false,
    )?);
    // A summary whose sources no longer resolve, or do not read, is refused
    // by the derived-source conjunct; here it names nothing more.
    if let Ok(crate::scope_summary::WordSources::From(sources)) =
        crate::scope_summary::word_sources_in(vault, txn, &id, bytes)
    {
        every.extend(sources);
    }
    if let Ok(Some(covers)) =
        crate::scope_summary::body_covers_in_txn(vault, txn, &id, header.entity_type, body)
    {
        every.extend(covers);
    }
    let mut supports = Vec::new();
    if header.entity_type == ENTITY_TYPE_CLAIM {
        if let Ok(claim) = crate::claim::decode_claim_body(body, true)
            && let crate::claim::ClaimSubject::Entity(subject) = claim.subject
        {
            every.push(subject);
        }
        supports =
            crate::conversation_dag::counted_edge_ids(dbs, txn, &id, EdgeKind::Supports, true)?;
    }
    Ok((every, supports))
}

/// The lane a row would leave this vault on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplicationScope {
    /// The owner-grade full-window lane, which carries a row's binding and
    /// policy beside it (Engine A, 6 Nov 03:46).
    FullOwnerWindow,
    /// Any lane that carries no audience: a selector, a federation.
    Restricted,
}

/// Whether the row `id` stays out of replication on `scope`: it, or a row
/// its words came from, is held back here, or [`withheld_by_lineage_in`]
/// keeps it.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn withheld_from_replication_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    scope: ReplicationScope,
) -> Result<bool> {
    LineagePass::new(vault, txn)?.withheld_from_replication(id, scope)
}

/// Whether the row `id`, or any row its words came from (every support of a
/// CLAIM included), is held back here. A vault that holds no row back
/// answers at once.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn lineage_held_in(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    if !super::any_held_in(vault, txn)? {
        return Ok(false);
    }
    let dbs = vault.store.read();
    let mut seen = BTreeSet::from([*id]);
    let mut pending = vec![*id];
    while let Some(row) = pending.pop() {
        if super::held_back_in(vault, txn, &row)?.is_some() {
            return Ok(true);
        }
        let Some(bytes) = crate::ports::EntityStoreRead::port_entity_raw(&dbs, txn, &row)? else {
            continue;
        };
        let (every, supports) = word_sources(vault, &dbs, txn, row, &bytes)?;
        for source in every.into_iter().chain(supports) {
            if seen.insert(source) {
                pending.push(source);
            }
        }
    }
    Ok(false)
}

/// Whether the row `id` stays out of replication on `scope` by its own
/// binding and lineage, as this vault holds them. On a restricted
/// lane: when it is bound to a source audience, a source landed it, or its
/// words came from such a row. On the full owner window: when it is bound
/// to anything but a policy whose closure publishes here, a source landed it
/// with no binding, or its words came from a row bound otherwise or landed
/// unbound; such a row travels with its binding and policy. There its words
/// come from rows as a read takes them: every row it was written from, and,
/// for a CLAIM, one of its supports, so a claim one free support carries
/// travels as it reads (FIX 12559 follow-up); a restricted lane counts every
/// support. Where the vault holds no policy and no row a source landed was
/// ever written here, only a row whose own bytes carry the source-audience
/// obligation is withheld, by that stamp; where one was, the walk runs as
/// everywhere, so a row whose words came from a landed row whose policy
/// does not resolve here stays too (fix list row 16255).
///
/// # Errors
///
/// Storage failures.
pub(crate) fn withheld_by_lineage_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    scope: ReplicationScope,
) -> Result<bool> {
    LineagePass::new(vault, txn)?.withheld_by_lineage(id, scope)
}

/// One replication pass (FIX 16254, FIX 17212): a window packing or an
/// export asks of many rows, and each verdict on a row's ancestry holds for
/// every later row of the pass that reaches it. The verdicts are kept by
/// what the judge asks (the policy the asking row travels under, and
/// whether every support counts), and only those that hold whatever row
/// asks: each settled verdict (see [`Judge::row_readable`]). No verdict
/// outlives the committed state it was read in.
///
/// A pass reads in its caller's snapshot ([`Self::new`]), or in a snapshot
/// of its own for each ask ([`Self::per_ask`]). A pass whose caller opens
/// read transactions between its asks needs the second: the vendored heed
/// has no NOTLS, so a second read transaction on one thread fails with
/// MDB_BAD_RSLOT (FIX 6992, WINDOW-LINEAGE-RSLOT).
pub(crate) struct LineagePass<'a, 't> {
    vault: &'a Vault,
    snapshot: PassSnapshot<'a, 't>,
    needs_lineage: bool,
    /// [`lineage_held_in`] by row.
    held: BTreeMap<EntityId, bool>,
    /// The judge's verdicts by ask, then by row.
    verdicts: BTreeMap<(Option<EntityId>, bool), BTreeMap<EntityId, bool>>,
}

/// Where a [`LineagePass`] reads.
#[derive(Clone, Copy)]
enum PassSnapshot<'a, 't> {
    /// The caller's snapshot, for the whole pass.
    Held(&'a heed::RoTxn<'t>),
    /// A snapshot opened and dropped inside each ask. `read_at` is the last
    /// committed write the kept verdicts were read after
    /// ([`heed::RoTxn::id`]); an ask that sees a later write drops them
    /// first, so the kept verdicts always read as one snapshot would.
    PerAsk { read_at: Option<usize> },
}

/// Whether a row here can be held by its lineage at all: a policy is
/// stored, or a source landed a row.
fn needs_lineage_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(super::any_policy_in(vault, txn)? || super::any_landed_in(vault, txn)?)
}

impl<'a, 't> LineagePass<'a, 't> {
    /// A pass over the caller's snapshot `txn`.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn new(vault: &'a Vault, txn: &'a heed::RoTxn<'t>) -> Result<Self> {
        Ok(Self {
            vault,
            snapshot: PassSnapshot::Held(txn),
            needs_lineage: needs_lineage_in(vault, txn)?,
            held: BTreeMap::new(),
            verdicts: BTreeMap::new(),
        })
    }

    /// A pass that reads each ask in a snapshot of its own, so its caller
    /// may open read transactions between the asks. The verdicts are kept
    /// while no write commits between the asks.
    pub(crate) const fn per_ask(vault: &'a Vault) -> Self {
        Self {
            vault,
            snapshot: PassSnapshot::PerAsk { read_at: None },
            needs_lineage: true,
            held: BTreeMap::new(),
            verdicts: BTreeMap::new(),
        }
    }

    /// `read` in the pass's snapshot: the caller's, or one of its own for
    /// this ask, after the verdicts read before a later committed write are
    /// dropped.
    fn in_snapshot<T>(
        &mut self,
        read: impl FnOnce(&mut Self, &heed::RoTxn<'_>) -> Result<T>,
    ) -> Result<T> {
        match self.snapshot {
            PassSnapshot::Held(txn) => read(self, txn),
            PassSnapshot::PerAsk { read_at } => {
                let vault = self.vault;
                let txn = vault.store.env.read_txn()?;
                let at = txn.id();
                if read_at != Some(at) {
                    self.held.clear();
                    self.verdicts.clear();
                    self.needs_lineage = needs_lineage_in(vault, &txn)?;
                    self.snapshot = PassSnapshot::PerAsk { read_at: Some(at) };
                }
                read(self, &txn)
            }
        }
    }

    /// [`withheld_from_replication_in`], in this pass.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn withheld_from_replication(
        &mut self,
        id: &EntityId,
        scope: ReplicationScope,
    ) -> Result<bool> {
        self.in_snapshot(|pass, txn| pass.withheld_from_replication_at(txn, id, scope))
    }

    /// Whether `other`, read in the pass's snapshot, holds, or else
    /// [`Self::withheld_from_replication`] in the same snapshot.
    ///
    /// # Errors
    ///
    /// Storage failures, and `other`'s.
    pub(crate) fn withheld_from_replication_or(
        &mut self,
        id: &EntityId,
        scope: ReplicationScope,
        other: impl FnOnce(&heed::RoTxn<'_>) -> Result<bool>,
    ) -> Result<bool> {
        self.in_snapshot(|pass, txn| {
            Ok(other(txn)? || pass.withheld_from_replication_at(txn, id, scope)?)
        })
    }

    /// [`lineage_held_in`], in this pass.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn lineage_held(&mut self, id: &EntityId) -> Result<bool> {
        self.in_snapshot(|pass, txn| pass.lineage_held_at(txn, id))
    }

    /// [`withheld_by_lineage_in`], in this pass.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn withheld_by_lineage(
        &mut self,
        id: &EntityId,
        scope: ReplicationScope,
    ) -> Result<bool> {
        self.in_snapshot(|pass, txn| pass.withheld_by_lineage_at(txn, id, scope))
    }

    fn withheld_from_replication_at(
        &mut self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        scope: ReplicationScope,
    ) -> Result<bool> {
        Ok(self.lineage_held_at(txn, id)? || self.withheld_by_lineage_at(txn, id, scope)?)
    }

    fn lineage_held_at(&mut self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
        if let Some(known) = self.held.get(id) {
            return Ok(*known);
        }
        let held = lineage_held_in(self.vault, txn, id)?;
        self.held.insert(*id, held);
        Ok(held)
    }

    fn withheld_by_lineage_at(
        &mut self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        scope: ReplicationScope,
    ) -> Result<bool> {
        let vault = self.vault;
        let dbs = vault.store.read();
        if !self.needs_lineage {
            // No row here came from a landed one: only the row's own stamp
            // can hold it.
            return Ok(
                crate::ports::EntityStoreRead::port_entity_raw(&dbs, txn, id)?
                    .is_some_and(|raw| source_marked(&raw)),
            );
        }
        // The policy the row travels under, when the lane carries one.
        let travels_under = match scope {
            ReplicationScope::Restricted => None,
            ReplicationScope::FullOwnerWindow => match super::binding_in(vault, txn, id)? {
                Some(policy) if super::replica::publishable_in(vault, txn, &policy)? => {
                    Some(policy)
                }
                _ => None,
            },
        };
        let every_support = scope == ReplicationScope::Restricted;
        let ask = (travels_under, every_support);
        // The read's own judge, on heap frames, asking each row's binding to
        // be the one the row travels under, with this pass's verdicts for
        // that ask.
        let mut judge = Judge::new(
            vault,
            &dbs,
            txn,
            Ask::Travel {
                under: travels_under,
                every_support,
            },
        );
        judge.rows = self.verdicts.remove(&ask).unwrap_or_default();
        let readable = judge.row_readable(*id, None);
        self.verdicts.insert(ask, judge.rows);
        let withheld = !readable?;
        // On the owner's full window a row its lineage would keep home
        // travels with the policies that lineage reaches, when they publish
        // (fix list row 17207).
        if withheld && scope == ReplicationScope::FullOwnerWindow {
            return Ok(derived_closure_in(vault, txn, id)?.is_none());
        }
        Ok(withheld)
    }
}

/// The policies the row `id` travels under on the owner's full window
/// beside its own binding, when its lineage would keep it home there (fix
/// list row 17207): what [`travel_closure_in`] finds, when the full-window
/// judge withholds the row and the set is not empty. `None` for a row that
/// travels as it is, or stays home.
///
/// # Errors
///
/// Storage failures.
#[cfg(feature = "sync")]
pub(crate) fn derived_travel_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<BTreeSet<EntityId>>> {
    if !super::any_policy_in(vault, txn)? || lineage_held_in(vault, txn, id)? {
        return Ok(None);
    }
    let dbs = vault.store.read();
    let travels_under = match super::binding_in(vault, txn, id)? {
        Some(policy) if super::replica::publishable_in(vault, txn, &policy)? => Some(policy),
        _ => None,
    };
    let mut judge = Judge::new(
        vault,
        &dbs,
        txn,
        Ask::Travel {
            under: travels_under,
            every_support: false,
        },
    );
    if judge.row_readable(*id, None)? {
        return Ok(None);
    }
    derived_closure_in(vault, txn, id)
}

/// [`travel_closure_in`], when it names at least one policy.
fn derived_closure_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<BTreeSet<EntityId>>> {
    Ok(travel_closure_in(vault, txn, id)?.filter(|policies| !policies.is_empty()))
}

/// Every policy the lineage of the row `id` reaches, the row itself
/// included (fix list row 17207): the binding of each row its words came
/// from and of every support of a CLAIM (a support alternative counts as
/// required, so the set reads never wider than the row does), and every
/// policy a full-window carrier brought for one of them. A row gone from
/// this view adds its own binding and carried policies and nothing more.
/// `None` when the lineage cannot travel: a row held back here, a row a
/// source landed with no binding, or a policy that does not publish.
fn travel_closure_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<BTreeSet<EntityId>>> {
    let dbs = vault.store.read();
    let mut policies = BTreeSet::new();
    let mut seen = BTreeSet::from([*id]);
    let mut pending = vec![*id];
    while let Some(row) = pending.pop() {
        if super::held_back_in(vault, txn, &row)?.is_some() {
            return Ok(None);
        }
        if let Some(carried) = super::derived_policies_in(vault, txn, &row)? {
            policies.extend(carried);
        }
        let binding = super::binding_in(vault, txn, &row)?;
        if let Some(policy) = binding {
            policies.insert(policy);
        }
        let Some(bytes) = crate::ports::EntityStoreRead::port_entity_raw(&dbs, txn, &row)? else {
            continue;
        };
        if binding.is_none() && source_marked(&bytes) {
            return Ok(None);
        }
        let (every, supports) = word_sources(vault, &dbs, txn, row, &bytes)?;
        for source in every.into_iter().chain(supports) {
            if seen.insert(source) {
                pending.push(source);
            }
        }
    }
    for policy in &policies {
        if !super::replica::publishable_in(vault, txn, policy)? {
            return Ok(None);
        }
    }
    Ok(Some(policies))
}

/// Whether every one of `viewers` reads the revision `raw` of `id` under
/// the source audience: its own binding, and those of everything its words
/// came from. `dbs` is the view the read walks (a session's composed view
/// included); bindings and policies read base. A vault that holds no
/// policy, holds no row back and never had a row a source landed answers at
/// once (fix list row 16255).
pub(crate) fn readable_with_read_in(
    vault: &Vault,
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
    viewers: &[EntityId],
) -> Result<bool> {
    if !super::any_policy_in(vault, txn)?
        && !super::any_held_in(vault, txn)?
        && !super::any_landed_in(vault, txn)?
    {
        // No row here came from a landed one: only the row's own stamp can
        // deny it.
        return Ok(!source_marked(raw));
    }
    let mut judge = Judge::new(vault, dbs, txn, Ask::Read(viewers));
    judge.row_readable(id, Some(raw))
}

/// The source-audience policies a read of the rows `roots` by every one of
/// `viewers` meets, as [`readable_with_read_in`] judges each of them (slice
/// 6.4e, `vault.policy.preflight`): those carried to each row and the one
/// binding it, and those of every row its words came from, along the same
/// lineage the judge walks. Of a CLAIM's supports, one of which the read
/// needs, only those of each support that reads to `viewers` count, so no
/// policy is named that the read did not meet. A row gone from `dbs` adds
/// its own binding and carried policies and nothing more. A vault that
/// holds no policy answers none.
///
/// The caller names every row its read met: a witnessed TURN and each
/// MESSAGE row its projected text was read from (review of #6985, round 2);
/// the TURN's own lineage reaches the rows `PartOf` it as well. It names the
/// policies of rows a read admitted; it judges nothing of the rows
/// themselves.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn read_audience_in(
    vault: &Vault,
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    roots: &[EntityId],
    viewers: &[EntityId],
) -> Result<BTreeSet<EntityId>> {
    let mut policies = BTreeSet::new();
    if !super::any_policy_in(vault, txn)? {
        return Ok(policies);
    }
    let mut judge = Judge::new(vault, dbs, txn, Ask::Read(viewers));
    let mut seen: BTreeSet<EntityId> = roots.iter().copied().collect();
    let mut pending: Vec<EntityId> = seen.iter().copied().collect();
    while let Some(row) = pending.pop() {
        if let Some(carried) = super::derived_policies_in(vault, txn, &row)? {
            policies.extend(carried);
        }
        if let Some(policy) = super::binding_in(vault, txn, &row)? {
            policies.insert(policy);
        }
        let Some(bytes) = crate::ports::EntityStoreRead::port_entity_raw(dbs, txn, &row)? else {
            continue;
        };
        let (every, supports) = word_sources(vault, dbs, txn, row, &bytes)?;
        for source in every {
            if seen.insert(source) {
                pending.push(source);
            }
        }
        for support in supports {
            if !seen.contains(&support) && judge.row_readable(support, None)? {
                seen.insert(support);
                pending.push(support);
            }
        }
    }
    Ok(policies)
}

/// What a judge asks of each row's own binding.
#[derive(Clone, Copy)]
enum Ask<'a> {
    /// A read by every one of these viewers: the binding's policy reads to
    /// them.
    Read(&'a [EntityId]),
    /// Replication: the binding is the policy the row travels under, which
    /// a restricted lane has none of. A restricted lane counts every support
    /// of a CLAIM as a row it was written from (L02, 6 Nov 06:24).
    Travel {
        under: Option<EntityId>,
        every_support: bool,
    },
    /// An Owner's whole-vault export (fix list row 15416): the binding's
    /// source is one the export carries ([`ExportAudience`]).
    Export(&'a ExportAudience),
}

/// What an Owner's whole-vault export carries, by the source each row was
/// landed from (fix list row 15416): a row goes when its own binding's
/// source and the sources of everything its words came from go, a CLAIM
/// when one of its supports does, as a read judges a row.
pub(crate) struct ExportAudience {
    /// The person the copy is for.
    pub(crate) exporter: EntityId,
    /// Each source policy a source this vault holds was born under, and
    /// whether the copy carries its rows. The rows of a source policy no
    /// source here was born under go as the exporter reads them
    /// ([`super::actor_reads_in`]: the source's readers, a thread shared
    /// with the exporter, a source that stands open); a policy that does not
    /// resolve carries nothing.
    pub(crate) sources: BTreeMap<EntityId, bool>,
    /// The source policies of [`Self::sources`] that are other members'
    /// personal mailboxes the copy carries.
    pub(crate) carried_members: BTreeSet<EntityId>,
}

/// What an export's judge met while it judged a pass (fix list row 15416).
#[derive(Debug, Default)]
pub(crate) struct ExportMet {
    /// Each source policy of [`ExportAudience::sources`] some row it judged
    /// was bound under, its own or through a thread of it.
    pub(crate) sources: BTreeSet<EntityId>,
    /// Each of [`ExportAudience::carried_members`] the admitted lineage of a
    /// row the copy ships reached ([`ExportJudge::ships`]).
    pub(crate) carried: BTreeSet<EntityId>,
    /// Whether it left out a row whose source this vault cannot name: a row
    /// a source landed with no binding here, a row held back here, a row
    /// bound under a policy that does not resolve, or a row of a source no
    /// connection here names that the exporter does not read.
    pub(crate) unidentified: bool,
}

/// One Owner's whole-vault export pass over the source audiences (fix list
/// row 15416): each row's settled verdict and each policy's, memoised across
/// the whole pass, so the rows a lineage shares are judged once.
pub(crate) struct ExportJudge<'a, 's, 't> {
    judge: Judge<'a, 's, 't>,
    /// No policy and no held row here: a row's own stamp alone decides, as
    /// [`readable_with_read_in`] reads it.
    quiet: bool,
}

impl<'a, 's, 't> ExportJudge<'a, 's, 't> {
    /// The judge of a pass reading `dbs` in `txn` for `audience`.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn new(
        vault: &'a Vault,
        dbs: &'a crate::store::StoreRead<'s>,
        txn: &'a heed::RoTxn<'t>,
        audience: &'a ExportAudience,
    ) -> Result<Self> {
        let quiet = !super::any_policy_in(vault, txn)? && !super::any_held_in(vault, txn)?;
        Ok(Self {
            judge: Judge::new(vault, dbs, txn, Ask::Export(audience)),
            quiet,
        })
    }

    /// Whether the copy carries the row `id`: its bytes `raw`, else as the
    /// pass's view holds them.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn carries(&mut self, id: EntityId, raw: Option<&[u8]>) -> Result<bool> {
        if !self.quiet {
            return self.judge.row_readable(id, raw);
        }
        let marked = match raw {
            Some(raw) => source_marked(raw),
            None => {
                crate::ports::EntityStoreRead::port_entity_raw(self.judge.dbs, self.judge.txn, &id)?
                    .is_some_and(|raw| source_marked(&raw))
            }
        };
        self.judge.met.unidentified |= marked;
        Ok(!marked)
    }

    /// The row `id`, which [`Self::carries`], goes into the copy: each other
    /// member's mailbox the copy carries that the row's admitted lineage
    /// reached is carried ([`ExportMet::carried`]).
    pub(crate) fn ships(&mut self, id: EntityId) {
        if let Some(reached) = self
            .judge
            .export
            .as_ref()
            .and_then(|export| export.reached.get(&id))
        {
            self.judge.met.carried.extend(reached.iter().copied());
        }
    }

    /// What the pass met.
    pub(crate) fn met(self) -> ExportMet {
        self.judge.met
    }
}

/// One read's or one replication's verdicts, memoised by row and by policy.
struct Judge<'a, 's, 't> {
    vault: &'a Vault,
    dbs: &'a crate::store::StoreRead<'s>,
    txn: &'a heed::RoTxn<'t>,
    ask: Ask<'a>,
    policies: BTreeMap<EntityId, bool>,
    /// The settled verdicts that hold whatever row asks. A [`LineagePass`]
    /// keeps them across its rows (see [`Judge::row_readable`]).
    rows: BTreeMap<EntityId, bool>,
    /// What an export's judge met; nothing for any other ask.
    met: ExportMet,
    /// What an export's judge keeps beside its verdicts ([`ExportReach`]);
    /// `None` for a read's or a replication's judge.
    export: Option<ExportReach>,
}

/// What an export's judge, whose verdicts its whole pass reuses, keeps
/// beside them (fix list row 15416): what each admitted row's lineage
/// reached. A `true` reached through a row still being judged keeps what it
/// reached only while it stands ([`Judge::row_readable`]); a row that heads
/// its cycle settles each of them, and each reaches what the head reaches.
#[derive(Default)]
struct ExportReach {
    /// The carried members' mailboxes ([`ExportAudience::carried_members`])
    /// each admitted row's lineage reached: only rows that reached one.
    reached: BTreeMap<EntityId, BTreeSet<EntityId>>,
    /// Each policy whose rows are a carried member's mailbox's, and that
    /// mailbox's source policy.
    members: BTreeMap<EntityId, EntityId>,
}

impl<'a, 's, 't> Judge<'a, 's, 't> {
    fn new(
        vault: &'a Vault,
        dbs: &'a crate::store::StoreRead<'s>,
        txn: &'a heed::RoTxn<'t>,
        ask: Ask<'a>,
    ) -> Self {
        Self {
            vault,
            dbs,
            txn,
            ask,
            policies: BTreeMap::new(),
            rows: BTreeMap::new(),
            met: ExportMet::default(),
            export: matches!(ask, Ask::Export(_)).then(ExportReach::default),
        }
    }
}

/// A row the judge has opened: decided at once, or waiting on what its
/// words came from.
enum Opened {
    Decided(bool),
    Waiting(Frame),
}

/// One row being judged on the heap: every row of `every` must read, and,
/// when `supports` names any, one of them must.
struct Frame {
    id: EntityId,
    every: Vec<EntityId>,
    supports: Vec<EntityId>,
    next_every: usize,
    next_support: usize,
    /// Whether the row last visited was a support.
    visiting_support: bool,
    decided: Option<bool>,
    /// The lowest stack depth of a row still being judged that a verdict
    /// this frame took read as `true` (fix list row 16255 review): its own
    /// depth when none did.
    low: usize,
    /// How many frames this judgement had pushed when it pushed this one.
    pushed_at: usize,
    /// An export's judge alone: the carried members' mailboxes the
    /// row's own policies are of, then those its admitted lineage reached.
    reached: BTreeSet<EntityId>,
}

/// What a frame asks next.
enum Step {
    Visit(EntityId),
    Done(bool),
}

impl Frame {
    const fn new(
        id: EntityId,
        every: Vec<EntityId>,
        supports: Vec<EntityId>,
        reached: BTreeSet<EntityId>,
    ) -> Self {
        Self {
            id,
            every,
            supports,
            next_every: 0,
            next_support: 0,
            visiting_support: false,
            decided: None,
            low: usize::MAX,
            pushed_at: 0,
            reached,
        }
    }

    /// Takes the verdict on the row last visited: one of `every` that does
    /// not read decides no; one support that reads decides yes. `low` is the
    /// lowest depth of a row still being judged that the verdict read.
    fn take(&mut self, readable: bool, low: usize) {
        self.low = self.low.min(low);
        if self.visiting_support {
            if readable {
                self.decided = Some(true);
            }
        } else if !readable {
            self.decided = Some(false);
        }
    }

    fn next(&mut self) -> Step {
        if let Some(verdict) = self.decided {
            return Step::Done(verdict);
        }
        while let Some(source) = self.every.get(self.next_every).copied() {
            self.next_every += 1;
            if source != self.id {
                self.visiting_support = false;
                return Step::Visit(source);
            }
        }
        if self.supports.is_empty() {
            return Step::Done(true);
        }
        match self.supports.get(self.next_support).copied() {
            // A row that supports itself reads as it does.
            Some(source) if source == self.id => Step::Done(true),
            Some(source) => {
                self.next_support += 1;
                self.visiting_support = true;
                Step::Visit(source)
            }
            None => Step::Done(false),
        }
    }
}

impl Judge<'_, '_, '_> {
    /// The verdict on `id`, its ancestry judged on a heap stack of frames, so
    /// a chain of any length is read without growing the call stack (FIX
    /// 12559 follow-up). A row in progress reads as `true` to a cycle back
    /// to it: a cycle adds no restriction.
    ///
    /// Only a settled verdict is memoised. A `false` is settled at once: a
    /// row in progress read as `true` can only have made it more readable.
    /// A `true` that read a row still in progress waits, conditional, until
    /// every row it read has settled, and stands only if none of them was
    /// denied: a denied row drops every conditional `true` reached while it
    /// was being judged, which is judged again when next asked (fix list row
    /// 16255 review). So a cycle never lends a row a `true` its other words
    /// deny. An export's judge keeps what each `true` reached the same way
    /// ([`ExportReach`]): a dropped `true` forgets it, and a row that heads
    /// its cycle lends what it reached to each `true` that settles with it.
    fn row_readable(&mut self, id: EntityId, raw: Option<&[u8]>) -> Result<bool> {
        if let Some(known) = self.rows.get(&id) {
            return Ok(*known);
        }
        let mut root = match self.open(id, raw)? {
            Opened::Decided(verdict) => {
                self.rows.insert(id, verdict);
                return Ok(verdict);
            }
            Opened::Waiting(frame) => frame,
        };
        root.low = 0;
        let mut stack = vec![root];
        // The rows in progress, by their depth on the stack.
        let mut in_progress = BTreeMap::from([(id, 0_usize)]);
        // Each `true` not settled yet: the lowest depth it read, and how
        // many frames had been pushed when it was reached.
        let mut conditional: BTreeMap<EntityId, (usize, usize)> = BTreeMap::new();
        let mut pushes = 0_usize;
        // The verdict the frame on top takes next, the lowest depth it read,
        // and the row it was taken on, when that row's reach is kept.
        let mut finished: Option<(bool, usize, Option<EntityId>)> = None;
        let mut verdict_of_root = true;
        while let Some(frame) = stack.last_mut() {
            if let Some((readable, low, visited)) = finished.take() {
                frame.take(readable, low);
                if readable && let Some(visited) = visited {
                    self.reach_through(frame, visited);
                }
            }
            match frame.next() {
                Step::Done(verdict) => {
                    let Some(done) = stack.pop() else {
                        break;
                    };
                    let depth = stack.len();
                    in_progress.remove(&done.id);
                    if done.low < depth && verdict {
                        // It read a row below it still in progress: so does
                        // every `true` that read it.
                        for (low, _) in conditional.values_mut() {
                            if *low >= depth {
                                *low = done.low;
                            }
                        }
                        conditional.insert(done.id, (done.low, pushes));
                        self.keep_reached(done.id, &done.reached);
                        finished = Some((true, done.low, Some(done.id)));
                        continue;
                    }
                    self.rows.insert(done.id, verdict);
                    if !verdict {
                        // Every `true` reached while it was being judged may
                        // have read it in progress: each is judged again
                        // when it is next asked.
                        let dropped: Vec<EntityId> = conditional
                            .iter()
                            .filter(|&(_, &(_, pushed))| pushed >= done.pushed_at)
                            .map(|(row, _)| *row)
                            .collect();
                        for row in dropped {
                            conditional.remove(&row);
                            self.forget_reached(row);
                        }
                    } else if done.low >= depth {
                        // Every row it read has settled, none denied: so
                        // does each `true` that read it.
                        let settled: Vec<EntityId> = conditional
                            .iter()
                            .filter(|&(_, (low, _))| *low >= depth)
                            .map(|(row, _)| *row)
                            .collect();
                        for row in settled {
                            conditional.remove(&row);
                            self.rows.insert(row, true);
                            self.keep_reached(row, &done.reached);
                        }
                    }
                    if verdict {
                        self.keep_reached(done.id, &done.reached);
                    }
                    finished = Some((verdict, usize::MAX, Some(done.id)));
                    if stack.is_empty() {
                        verdict_of_root = verdict;
                    }
                }
                Step::Visit(source) => {
                    if let Some(known) = self.rows.get(&source) {
                        finished = Some((*known, usize::MAX, Some(source)));
                        continue;
                    }
                    if let Some(&depth) = in_progress.get(&source) {
                        // What a row in progress reaches is lent to this
                        // one when the row heading its cycle settles.
                        finished = Some((true, depth, None));
                        continue;
                    }
                    if let Some(&(low, _)) = conditional.get(&source) {
                        finished = Some((true, low, Some(source)));
                        continue;
                    }
                    match self.open(source, None)? {
                        Opened::Decided(verdict) => {
                            self.rows.insert(source, verdict);
                            finished = Some((verdict, usize::MAX, Some(source)));
                        }
                        Opened::Waiting(mut frame) => {
                            let depth = stack.len();
                            pushes += 1;
                            frame.low = depth;
                            frame.pushed_at = pushes;
                            in_progress.insert(source, depth);
                            stack.push(frame);
                        }
                    }
                }
            }
        }
        Ok(verdict_of_root)
    }

    /// What an export's judge's `frame` takes beside a `true` it read on the
    /// row `visited`: the carried members' mailboxes that row's lineage
    /// reached.
    fn reach_through(&self, frame: &mut Frame, visited: EntityId) {
        if let Some(reached) = self
            .export
            .as_ref()
            .and_then(|export| export.reached.get(&visited))
        {
            frame.reached.extend(reached.iter().copied());
        }
    }

    /// Keeps, on an export's judge, `reached` beside what the row `id`,
    /// judged `true`, reached already.
    fn keep_reached(&mut self, id: EntityId, reached: &BTreeSet<EntityId>) {
        if let Some(export) = self.export.as_mut()
            && !reached.is_empty()
        {
            export
                .reached
                .entry(id)
                .or_default()
                .extend(reached.iter().copied());
        }
    }

    /// Forgets what a dropped conditional `true` on `id` reached: the row is
    /// judged again when next asked.
    fn forget_reached(&mut self, id: EntityId) {
        if let Some(export) = self.export.as_mut() {
            export.reached.remove(&id);
        }
    }

    /// What the row `id` needs: its own binding's verdict, its own bytes
    /// (`raw`, else as this view holds them), and the rows its words came
    /// from. A row held back here reads to no one; a replication judges it
    /// by its own binding and lineage alone.
    fn open(&mut self, id: EntityId, raw: Option<&[u8]>) -> Result<Opened> {
        if matches!(self.ask, Ask::Read(_) | Ask::Export(_))
            && super::held_back_in(self.vault, self.txn, &id)?.is_some()
        {
            self.met.unidentified |= matches!(self.ask, Ask::Export(_));
            return Ok(Opened::Decided(false));
        }
        // The carried members' mailboxes the row's own policies are of, for
        // an export's judge.
        let mut reached = BTreeSet::new();
        // The policies a full-window carrier brought for a derived row (fix
        // list row 17207): every one of them reads, whatever the row's own
        // lineage here says, before anything else; an unknown one reads to
        // no one. A replication walk ships such a row only with its carried
        // policies, as its own sets them (`travel_closure_in`).
        if let Some(policies) = super::derived_policies_in(self.vault, self.txn, &id)? {
            match self.ask {
                Ask::Read(viewers) => {
                    for policy in policies {
                        if !self.policy_readable(policy, viewers)? {
                            return Ok(Opened::Decided(false));
                        }
                    }
                }
                Ask::Export(audience) => {
                    for policy in policies {
                        if !self.export_carries(policy, audience)? {
                            return Ok(Opened::Decided(false));
                        }
                        reached.extend(self.member_mailbox_of(policy));
                    }
                }
                Ask::Travel { .. } => return Ok(Opened::Decided(false)),
            }
        }
        let binding = super::binding_in(self.vault, self.txn, &id)?;
        if let Some(policy) = binding {
            let admitted = match self.ask {
                Ask::Read(viewers) => self.policy_readable(policy, viewers)?,
                Ask::Export(audience) => self.export_carries(policy, audience)?,
                Ask::Travel { under, .. } => under == Some(policy),
            };
            if !admitted {
                return Ok(Opened::Decided(false));
            }
            reached.extend(self.member_mailbox_of(policy));
        }
        let bytes = match raw {
            Some(raw) => raw.to_vec(),
            None => {
                match crate::ports::EntityStoreRead::port_entity_raw(self.dbs, self.txn, &id)? {
                    Some(bytes) => bytes,
                    // A row gone from this view carries no words to judge; its
                    // own binding, read above, still stands, and so does the
                    // mailbox it is of.
                    None if reached.is_empty() => return Ok(Opened::Decided(true)),
                    None => {
                        return Ok(Opened::Waiting(Frame::new(
                            id,
                            Vec::new(),
                            Vec::new(),
                            reached,
                        )));
                    }
                }
            }
        };
        // A row a source landed whose binding is absent here reads to no one.
        if binding.is_none() && source_marked(&bytes) {
            self.met.unidentified |= matches!(self.ask, Ask::Export(_));
            return Ok(Opened::Decided(false));
        }
        let (mut every, mut supports) = word_sources(self.vault, self.dbs, self.txn, id, &bytes)?;
        if matches!(
            self.ask,
            Ask::Travel {
                every_support: true,
                ..
            }
        ) {
            every.append(&mut supports);
        }
        Ok(Opened::Waiting(Frame::new(id, every, supports, reached)))
    }

    /// The carried member's mailbox the rows bound under `policy` are of,
    /// as an export's judge found it.
    fn member_mailbox_of(&self, policy: EntityId) -> Option<EntityId> {
        self.export.as_ref()?.members.get(&policy).copied()
    }

    fn policy_readable(&mut self, policy: EntityId, viewers: &[EntityId]) -> Result<bool> {
        if let Some(known) = self.policies.get(&policy) {
            return Ok(*known);
        }
        let verdict = match super::readers_in(self.vault, self.txn, &policy)? {
            None => false,
            Some(None) => true,
            Some(Some(readers)) => {
                let mut every = !viewers.is_empty();
                for viewer in viewers {
                    if !every {
                        break;
                    }
                    every = super::names_reader_in(self.vault, self.txn, &readers, *viewer)?;
                }
                every
            }
        };
        self.policies.insert(policy, verdict);
        Ok(verdict)
    }

    /// Whether an export for `audience` carries the rows bound under
    /// `policy`: a thread's by its source, a source by the audience's map.
    /// A source no connection here names (a replica's group address, whose
    /// connection never travels) is not known to be another person's
    /// mailbox: its rows go as the exporter reads them, by the source's
    /// readers, a share of the thread or a source that stands open
    /// ([`super::actor_reads_in`]). A policy that does not resolve carries
    /// nothing.
    fn export_carries(&mut self, policy: EntityId, audience: &ExportAudience) -> Result<bool> {
        if let Some(known) = self.policies.get(&policy) {
            return Ok(*known);
        }
        let source = match super::policy_in(self.vault, self.txn, &policy)?.map(|row| row.kind) {
            Some(super::SourceAudienceKind::Source { .. }) => Some(policy),
            Some(super::SourceAudienceKind::Thread { source, .. }) => Some(source),
            None => None,
        };
        let verdict = match source {
            Some(source) => match audience.sources.get(&source).copied() {
                Some(carried) => {
                    self.met.sources.insert(source);
                    if carried
                        && audience.carried_members.contains(&source)
                        && let Some(export) = self.export.as_mut()
                    {
                        export.members.insert(policy, source);
                    }
                    carried
                }
                None => {
                    let carried =
                        super::actor_reads_in(self.vault, self.txn, &policy, audience.exporter)?;
                    self.met.unidentified |= !carried;
                    carried
                }
            },
            None => {
                self.met.unidentified = true;
                false
            }
        };
        self.policies.insert(policy, verdict);
        Ok(verdict)
    }
}
