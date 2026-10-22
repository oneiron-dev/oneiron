//! The vault's own retrieval probes, which a space version move runs paired on its incumbent
//! and its candidate (OF-370; ARCH-0004 `#swap-check-not-worse`).
//!
//! A probe is one query written from one stored document, which is its source family, and the
//! documents that answer it: that document and those derived from it or it from them. Its query
//! is text another model wrote, or a stored image or audio document itself (a media query,
//! FIX 1637). The design note's recipe, not a ruling: about twenty probes per kind, written at
//! sleep by a model other than the spaces' own, for example by describing a photo, so a probe
//! cannot just copy a caption. [`Vault::author_space_probes`] hands such a model the documents
//! of a kind that no probe comes from yet, drawn across date-cut cohorts, newest first, rather
//! than in id order (ARCH-0053 `#eval-exposure`).

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use super::media::{
    MediaEgressGate, MediaEmbedReport, MediaEmbeddingInput, PendingMedia, asset_document_in,
    is_text_document_type, text_document_of,
};
use super::space::InputKind;
use super::{EgressDecision, EgressPredicate, EmbedderLocality};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::side_table::{self, Named, SideTable, SideTableDbs};

mod ledger;
pub(super) use ledger::ProbeCohortLedger;

/// Probes the authoring pass keeps per kind.
pub const SPACE_PROBES_PER_KIND: usize = 20;
/// Longest probe query, in bytes.
pub const SPACE_PROBE_QUERY_MAX_LEN: usize = 2048;
/// Width of a probe cohort's date cut, in vault seconds: the authoring pass groups a kind's
/// documents by the window the vault learned each in, and draws its probes' families across
/// those windows, the window holding fewest probes first and the newest on a tie.
pub const SPACE_PROBE_COHORT_SECS: u64 = 30 * 24 * 60 * 60;

/// Stored probes. Key: probe id16.
const EMBEDDING_PROBE: SideTable<[u8; 16], SpaceProbe, Named> =
    SideTable::new(&side_table::EMBEDDING_PROBE);

/// One retrieval probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceProbe {
    /// The kind of the documents it finds; a move's check runs it for that kind's slot.
    pub kind: InputKind,
    /// A text query, through each space's text tower; beside a media query, what it asks in
    /// words, which may be empty.
    pub query: String,
    /// A stored image or audio ASSET whose bytes are the query, through each space's tower of
    /// that media kind; `None` for a text query. Never one of its targets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_media: Option<EntityId>,
    /// The document it was written from, its source family; one of its targets.
    pub family: EntityId,
    /// Every document that answers the query.
    pub targets: BTreeSet<EntityId>,
    /// The model that wrote it.
    pub author: String,
    /// Vault seconds.
    pub written_at: u64,
    /// Its family's date cut: the start, in vault seconds, of the [`SPACE_PROBE_COHORT_SECS`]
    /// window the vault learned its source document in; `None` for a probe put by hand.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cohort: Option<u64>,
}

impl SpaceProbe {
    /// The probe's id: its kind, family and query, and its media query when it has one.
    #[must_use]
    pub fn id(&self) -> [u8; 16] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron/space_probe/v1");
        hasher.update(&[self.kind as u8]);
        hasher.update(self.family.as_bytes());
        hasher.update(self.query.as_bytes());
        if let Some(media) = &self.query_media {
            hasher.update(b"\0query_media");
            hasher.update(media.as_bytes());
        }
        let mut id = [0_u8; 16];
        id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        id
    }

    fn validate(&self) -> Result<()> {
        let query = self.query.trim();
        if (query.is_empty() && self.query_media.is_none())
            || self.query.len() > SPACE_PROBE_QUERY_MAX_LEN
        {
            return Err(Error::InvalidConfig(format!(
                "a space probe's query must hold 1..={SPACE_PROBE_QUERY_MAX_LEN} bytes of text"
            )));
        }
        if self
            .query_media
            .is_some_and(|media| self.targets.contains(&media))
        {
            return Err(Error::InvalidConfig(
                "a space probe's media query is none of its targets".into(),
            ));
        }
        // Every target it names is kept and run (FIX 8199): no count of them is refused.
        if self.targets.is_empty() {
            return Err(Error::InvalidConfig(
                "a space probe names at least one target document".into(),
            ));
        }
        if !self.targets.contains(&self.family) {
            return Err(Error::InvalidConfig(
                "a space probe's source document is one of its targets".into(),
            ));
        }
        if self.author.trim().is_empty() {
            return Err(Error::InvalidConfig(
                "a space probe names the model that wrote it".into(),
            ));
        }
        Ok(())
    }
}

/// A host model that writes probes: a model other than the spaces' own.
pub trait SpaceProbeAuthor: Send + Sync {
    /// The model id a probe records as its author.
    fn author_id(&self) -> &str;
    /// Where the model runs. Stored image and audio bytes leave for a third party only
    /// through the host's media egress gate ([`Vault::author_space_probes_admitted`]); a text
    /// document goes where the host's admitted call (the vault's inference policy) lets it.
    fn locality(&self) -> EmbedderLocality;
    /// One search query a person might type to find `document`, in other words than its own;
    /// `None` when the model writes none.
    fn write_probe(&self, document: &MediaEmbeddingInput<'_>) -> Result<Option<String>>;
}

/// What one authoring pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpaceProbeReport {
    /// Probes stored this pass.
    pub written: usize,
    /// Documents the model wrote no usable query for.
    pub declined: usize,
    /// Documents deleted, or texts moved, before their probe landed.
    pub vanished: usize,
    /// Probes of the kind already held, before this pass.
    pub held: usize,
    /// Documents the host's media egress gate kept from a third-party author, unsent.
    pub withheld: usize,
}

pub(crate) fn space_probes_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
) -> Result<Vec<([u8; 16], SpaceProbe)>> {
    EMBEDDING_PROBE.scan(store, txn)
}

impl Vault {
    /// Stores one probe; every target must be a stored record, and a media query a stored ASSET
    /// holding inline image or audio. The write checks the owner's proof again (FIX 8200).
    pub fn put_space_probe(
        &self,
        owner: &AuthenticatedOwner,
        probe: SpaceProbe,
    ) -> Result<[u8; 16]> {
        probe.validate()?;
        let id = probe.id();
        let mut wtxn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &wtxn)?;
        for target in &probe.targets {
            if self.store.port_entity_record(&wtxn, target)?.is_none() {
                return Err(Error::EntityNotFound);
            }
        }
        if let Some(media) = probe.query_media
            && media_query_in(&self.store, &wtxn, media)?.is_none()
        {
            return Err(Error::InvalidConfig(
                "a space probe's media query is a stored ASSET holding inline image or audio"
                    .into(),
            ));
        }
        EMBEDDING_PROBE.put(&self.store, &mut wtxn, &id, &probe)?;
        wtxn.commit()?;
        Ok(id)
    }

    /// Every stored probe, in id order.
    pub fn space_probes(&self) -> Result<Vec<([u8; 16], SpaceProbe)>> {
        let rtxn = self.store.env.read_txn()?;
        space_probes_in_txn(&self.store, &rtxn)
    }

    /// Deletes one probe; `false` when none had that id. The write checks the owner's proof
    /// again (FIX 8200).
    pub fn delete_space_probe(&self, owner: &AuthenticatedOwner, id: &[u8; 16]) -> Result<bool> {
        let mut wtxn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &wtxn)?;
        let existed = EMBEDDING_PROBE.contains(&self.store, &wtxn, id)?;
        EMBEDDING_PROBE.delete(&self.store, &mut wtxn, id)?;
        wtxn.commit()?;
        Ok(existed)
    }

    /// Tops `kind` up toward [`SPACE_PROBES_PER_KIND`] probes, at most `max_items` this pass:
    /// `author` reads documents of that kind no probe comes from yet, outside any transaction,
    /// drawn across date-cut cohorts ([`SPACE_PROBE_COHORT_SECS`]): the cohort holding fewest
    /// probes first, the newest on a tie, and its newest document first. Each query it writes
    /// is stored with that document as its family and cohort, and as its targets that document
    /// and each one a `DerivedFrom` edge away that is a document of `kind`, all of them
    /// (ARCH-0053 `#eval-derivation`).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the author runs at a third party and `kind` is a media
    /// kind; storage and model errors otherwise.
    pub fn author_space_probes(
        &self,
        kind: InputKind,
        author: &dyn SpaceProbeAuthor,
        max_items: usize,
    ) -> Result<SpaceProbeReport> {
        self.author_space_probes_admitted(kind, author, max_items, None)
    }

    /// [`Self::author_space_probes`] with the host's media egress gate (FIX 6743): an author at
    /// a third party writes image and audio probes only from the documents `egress` allows
    /// ([`EgressPredicate::decide_media`]) that no device-local world keeps (DEC-0005), each
    /// asked again right before its bytes go to the author; the rest stay unsent and are
    /// counted [`SpaceProbeReport::withheld`]. A text author, or one on this device or the
    /// owner's server, reads as it does without a gate.
    ///
    /// # Errors
    ///
    /// As [`Self::author_space_probes`]; a third-party media author with no gate is refused as
    /// there.
    pub fn author_space_probes_admitted(
        &self,
        kind: InputKind,
        author: &dyn SpaceProbeAuthor,
        max_items: usize,
        egress: Option<&dyn EgressPredicate>,
    ) -> Result<SpaceProbeReport> {
        let gated = author.locality() == EmbedderLocality::ThirdParty && kind != InputKind::Text;
        let egress = match egress {
            _ if !gated => None,
            Some(egress) => Some(egress),
            None => {
                return Err(Error::InvalidConfig(
                    "a third-party probe author has no egress grant for stored media".into(),
                ));
            }
        };
        let mut report = SpaceProbeReport::default();
        let documents = {
            let rtxn = self.store.env.read_txn()?;
            let gate = egress
                .map(|egress| MediaEgressGate::read(self, &rtxn, egress))
                .transpose()?;
            let probes: Vec<SpaceProbe> = space_probes_in_txn(&self.store, &rtxn)?
                .into_iter()
                .map(|(_, probe)| probe)
                .filter(|probe| probe.kind == kind)
                .collect();
            let families: BTreeSet<EntityId> = probes.iter().map(|probe| probe.family).collect();
            report.held = families.len();
            let want = SPACE_PROBES_PER_KIND
                .saturating_sub(families.len())
                .min(max_items);
            let mut documents = Vec::new();
            if want > 0 {
                let kinds = BTreeSet::from([kind]);
                // Each candidate's date cut, its bytes left unread until it is drawn.
                let mut cohorts: BTreeMap<u64, Vec<(u64, EntityId)>> = BTreeMap::new();
                let mut scan = MediaEmbedReport::default();
                let mut withheld = 0;
                self.scan_documents_in_txn(&rtxn, &kinds, &mut scan, |document| {
                    if families.contains(&document.id) {
                        return Ok(true);
                    }
                    if let Some(gate) = &gate
                        && !gate.admits(&self.store, &rtxn, &document)?
                    {
                        withheld += 1;
                        return Ok(true);
                    }
                    cohorts
                        .entry(cohort_of(document.learned_at))
                        .or_default()
                        .push((document.learned_at, document.id));
                    Ok(true)
                })?;
                report.withheld += withheld;
                let mut held: BTreeMap<u64, usize> = BTreeMap::new();
                for cohort in probes.iter().filter_map(|probe| probe.cohort) {
                    *held.entry(cohort).or_default() += 1;
                }
                for id in draw_across_cohorts(cohorts, held, want) {
                    let mut read = MediaEmbedReport::default();
                    let document = match kind {
                        InputKind::Text => {
                            text_document_of(self, &self.store, &rtxn, id, &mut read)?
                        }
                        InputKind::Image | InputKind::Audio => {
                            super::repo_projection::asset_document_projected_in(
                                self,
                                &self.store,
                                &rtxn,
                                id,
                                &kinds,
                                &mut read,
                            )?
                        }
                    };
                    documents.extend(document);
                }
            }
            documents
        };
        let mut written = Vec::new();
        for document in &documents {
            let input = document.input();
            if let Some(egress) = egress
                && (egress.decide_media(&input) != EgressDecision::Allow
                    || !self.media_rows_may_leave(None, &[document.id])?)
            {
                report.withheld += 1;
                continue;
            }
            let Some(query) = author
                .write_probe(&input)?
                .map(|query| query.trim().to_owned())
                .filter(|query| !query.is_empty() && query.len() <= SPACE_PROBE_QUERY_MAX_LEN)
            else {
                report.declined += 1;
                continue;
            };
            // A probe that only repeats the text it came from tests nothing a model swap moves.
            if document.kind == InputKind::Text
                && std::str::from_utf8(&document.bytes)
                    .is_ok_and(|text| text.trim().eq_ignore_ascii_case(&query))
            {
                report.declined += 1;
                continue;
            }
            written.push((document, query));
        }
        if written.is_empty() {
            return Ok(report);
        }
        let mut wtxn = self.store.env.write_txn()?;
        let written_at = self.store.clock.now_recorded_at();
        for (document, query) in written {
            let moved = match document.text_hash {
                Some(hash) => super::media::text_document_in_txn(self, &wtxn, &document.id)?
                    .is_none_or(|text| super::space::text_hash(&text) != hash),
                None => false,
            };
            if moved
                || self
                    .store
                    .port_entity_record(&wtxn, &document.id)?
                    .is_none()
            {
                report.vanished += 1;
                continue;
            }
            let probe = SpaceProbe {
                kind,
                query,
                query_media: None,
                family: document.id,
                targets: family_targets_in(self, &wtxn, document.id, kind)?,
                author: author.author_id().to_owned(),
                written_at,
                cohort: Some(cohort_of(document.learned_at)),
            };
            probe.validate()?;
            EMBEDDING_PROBE.put(&self.store, &mut wtxn, &probe.id(), &probe)?;
            report.written += 1;
        }
        wtxn.commit()?;
        Ok(report)
    }
}

/// The start of the [`SPACE_PROBE_COHORT_SECS`] window `learned_at` falls in.
fn cohort_of(learned_at: u64) -> u64 {
    learned_at - learned_at % SPACE_PROBE_COHORT_SECS
}

/// Up to `want` of `cohorts`' documents, each `(learned_at, id)`: the cohort that holds the
/// fewest probes, `held` and drawn here together, gives its newest document next, the newest
/// cohort on a tie.
fn draw_across_cohorts(
    mut cohorts: BTreeMap<u64, Vec<(u64, EntityId)>>,
    mut held: BTreeMap<u64, usize>,
    want: usize,
) -> Vec<EntityId> {
    for documents in cohorts.values_mut() {
        documents.sort_unstable();
    }
    let mut drawn = Vec::new();
    while drawn.len() < want {
        let Some(cohort) = cohorts
            .iter()
            .filter(|(_, documents)| !documents.is_empty())
            .map(|(cohort, _)| *cohort)
            .min_by_key(|cohort| {
                let probes = held.get(cohort).copied().unwrap_or(0);
                (probes, std::cmp::Reverse(*cohort))
            })
        else {
            break;
        };
        if let Some((_, document)) = cohorts.get_mut(&cohort).and_then(Vec::pop) {
            drawn.push(document);
            *held.entry(cohort).or_default() += 1;
        }
    }
    drawn
}

/// The documents that answer a probe written from `family`: it, and each record one
/// `DerivedFrom` edge away (a summary written from it, or what it was written from) that is a
/// document of `kind` here, every one of them. Derived rows inherit their source's family
/// (ARCH-0053 `#eval-derivation`).
fn family_targets_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    family: EntityId,
    kind: InputKind,
) -> Result<BTreeSet<EntityId>> {
    let mut targets = BTreeSet::from([family]);
    let peers = vault.store.port_edge_peers(
        txn,
        &family,
        EdgeDirection::Both,
        crate::EdgeKind::DerivedFrom,
    )?;
    let peers: BTreeSet<EntityId> = peers.collect::<Result<_>>()?;
    let kinds = BTreeSet::from([kind]);
    for peer in peers {
        let mut read = MediaEmbedReport::default();
        let answers = match kind {
            InputKind::Text => {
                vault
                    .store
                    .port_entity_record(txn, &peer)?
                    .is_some_and(|row| is_text_document_type(row.entity_type))
                    && text_document_of(vault, &vault.store, txn, peer, &mut read)?.is_some()
            }
            InputKind::Image | InputKind::Audio => {
                super::repo_projection::asset_document_projected_in(vault, &vault.store, txn, peer, &kinds, &mut read)?.is_some()
            }
        };
        if answers {
            targets.insert(peer);
        }
    }
    Ok(targets)
}

/// The image or audio document a media query names, as `store` reads it; `None` when it is
/// gone or holds neither.
pub(super) fn media_query_in(
    store: &impl crate::store::ManifestDbs,
    txn: &RoTxn<'_>,
    id: EntityId,
) -> Result<Option<PendingMedia>> {
    asset_document_in(
        store,
        txn,
        id,
        &BTreeSet::from([InputKind::Image, InputKind::Audio]),
        &mut MediaEmbedReport::default(),
    )
}
