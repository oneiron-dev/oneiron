//! The source-audience conjunct every audience read meets: a row reads to
//! its viewers only while each of them reads under the policy it was born
//! under, and under the policies of what its words came from.
//!
//! What a row's words came from, as this walk reads it:
//! - a MESSAGE's TURN (`PartOf`);
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
//! source landed whose source this vault cannot name.

use std::collections::{BTreeMap, BTreeSet};

use crate::EdgeKind;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE};
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
    Ok(lineage_held_in(vault, txn, id)? || withheld_by_lineage_in(vault, txn, id, scope)?)
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
/// support. Where the vault holds no policy only a row a source landed is
/// withheld, by its own stamp.
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
    let dbs = vault.store.read();
    if !super::any_policy_in(vault, txn)? {
        return Ok(
            crate::ports::EntityStoreRead::port_entity_raw(&dbs, txn, id)?
                .is_some_and(|raw| source_marked(&raw)),
        );
    }
    // The policy the row travels under, when the lane carries one.
    let travels_under = match scope {
        ReplicationScope::Restricted => None,
        ReplicationScope::FullOwnerWindow => match super::binding_in(vault, txn, id)? {
            Some(policy) if super::replica::publishable_in(vault, txn, &policy)? => Some(policy),
            _ => None,
        },
    };
    // The read's own judge, on heap frames, asking each row's binding to be
    // the one the row travels under.
    let mut judge = Judge::new(
        vault,
        &dbs,
        txn,
        Ask::Travel {
            under: travels_under,
            every_support: scope == ReplicationScope::Restricted,
        },
    );
    let withheld = !judge.row_readable(*id, None)?;
    // On the owner's full window a row its lineage would keep home travels
    // with the policies that lineage reaches, when they publish (fix list
    // row 17207).
    if withheld && scope == ReplicationScope::FullOwnerWindow {
        return Ok(derived_closure_in(vault, txn, id)?.is_none());
    }
    Ok(withheld)
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
/// included); bindings and policies read base. A vault that holds no policy
/// and holds no row back answers at once.
pub(crate) fn readable_with_read_in(
    vault: &Vault,
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
    viewers: &[EntityId],
) -> Result<bool> {
    if !super::any_policy_in(vault, txn)? && !super::any_held_in(vault, txn)? {
        // No policy here, as on a replica the audience never reached: a row
        // a source landed still reads to no one.
        return Ok(!source_marked(raw));
    }
    let mut judge = Judge::new(vault, dbs, txn, Ask::Read(viewers));
    judge.row_readable(id, Some(raw))
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
    /// whether the copy carries its rows. A source policy no source here was
    /// born under is carried when it stands open or its own readers name the
    /// exporter ([`super::names_reader_in`]); a policy that does not resolve
    /// to a source is not.
    pub(crate) sources: BTreeMap<EntityId, bool>,
}

/// What an export's judge met while it judged a pass (fix list row 15416).
#[derive(Debug, Default)]
pub(crate) struct ExportMet {
    /// Each source policy of [`ExportAudience::sources`] some row it judged
    /// was bound under, its own or through a thread of it.
    pub(crate) sources: BTreeSet<EntityId>,
    /// Whether it left out a row whose source this vault cannot name: a row
    /// a source landed with no binding here, a row held back here, or a row
    /// bound under a policy that resolves to no source the copy carries.
    pub(crate) unidentified: bool,
}

/// One Owner's whole-vault export pass over the source audiences (fix list
/// row 15416): each row's verdict and each policy's, memoised across the
/// whole pass, so the rows a lineage shares are judged once.
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
    rows: BTreeMap<EntityId, bool>,
    /// What an export's judge met; nothing for any other ask.
    met: ExportMet,
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
}

/// What a frame asks next.
enum Step {
    Visit(EntityId),
    Done(bool),
}

impl Frame {
    const fn new(id: EntityId, every: Vec<EntityId>, supports: Vec<EntityId>) -> Self {
        Self {
            id,
            every,
            supports,
            next_every: 0,
            next_support: 0,
            visiting_support: false,
            decided: None,
        }
    }

    /// Takes the verdict on the row last visited: one of `every` that does
    /// not read decides no; one support that reads decides yes.
    fn take(&mut self, readable: bool) {
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
    fn row_readable(&mut self, id: EntityId, raw: Option<&[u8]>) -> Result<bool> {
        if let Some(known) = self.rows.get(&id) {
            return Ok(*known);
        }
        let mut stack = match self.open(id, raw)? {
            Opened::Decided(verdict) => {
                self.rows.insert(id, verdict);
                return Ok(verdict);
            }
            Opened::Waiting(frame) => {
                self.rows.insert(id, true);
                vec![frame]
            }
        };
        let mut finished: Option<bool> = None;
        while let Some(frame) = stack.last_mut() {
            if let Some(readable) = finished.take() {
                frame.take(readable);
            }
            match frame.next() {
                Step::Done(verdict) => {
                    let done = frame.id;
                    stack.pop();
                    self.rows.insert(done, verdict);
                    finished = Some(verdict);
                }
                Step::Visit(source) => {
                    if let Some(known) = self.rows.get(&source) {
                        finished = Some(*known);
                        continue;
                    }
                    match self.open(source, None)? {
                        Opened::Decided(verdict) => {
                            self.rows.insert(source, verdict);
                            finished = Some(verdict);
                        }
                        Opened::Waiting(frame) => {
                            self.rows.insert(source, true);
                            stack.push(frame);
                        }
                    }
                }
            }
        }
        Ok(finished.unwrap_or(true))
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
        }
        let bytes = match raw {
            Some(raw) => raw.to_vec(),
            None => {
                match crate::ports::EntityStoreRead::port_entity_raw(self.dbs, self.txn, &id)? {
                    Some(bytes) => bytes,
                    // A row gone from this view carries no words to judge; its
                    // own binding, read above, still stands.
                    None => return Ok(Opened::Decided(true)),
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
        Ok(Opened::Waiting(Frame::new(id, every, supports)))
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
    /// `policy`: a thread's by its source, a source by the audience's map, a
    /// source no source here was born under when it stands open or its own
    /// readers name the exporter. A policy that does not resolve carries
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
            Some(source) => match audience.sources.get(&source) {
                Some(carried) => {
                    self.met.sources.insert(source);
                    *carried
                }
                None => {
                    let carried = self.unnamed_source_carried(source, audience.exporter)?;
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

    /// Whether an export for `exporter` carries the rows of the source
    /// policy `source`, which no source this vault holds was born under:
    /// when it stands open, or its own readers name the exporter.
    fn unnamed_source_carried(&self, source: EntityId, exporter: EntityId) -> Result<bool> {
        Ok(
            match super::policy_in(self.vault, self.txn, &source)?.map(|row| row.kind) {
                Some(super::SourceAudienceKind::Source { open: true, .. }) => true,
                Some(super::SourceAudienceKind::Source { readers, .. }) => {
                    super::names_reader_in(self.vault, self.txn, &readers, exporter)?
                }
                _ => false,
            },
        )
    }
}
