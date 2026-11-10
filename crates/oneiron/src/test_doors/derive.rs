//! Doors to the derivation transaction (untangle 6.7a): commit a batch of
//! items as an actor, read its batch record back, and ask the derive
//! verdict.

use crate::attempt_queue::AttemptId;
use crate::claim::ClaimSource;
use crate::derive::{
    DerivationBatch, DerivationItem, DerivationStamp, DerivedAboutLine, DerivedArchive,
    DerivedClaim, DerivedEvidence, DerivedPersonAbout, DerivedPsychProfile, DerivedSameAs,
    DerivedSettle, DerivedSettlement, DerivedSupersede, DerivedTopology, ItemOutcome, ItemRef,
};
use crate::error::Result;
use crate::gate::{DeriveCapability, DeriveRefusal};
use crate::write_envelope::{SourceLineage, WriteActor};
use crate::{EdgeActorClass, EntityId, Vault};

/// A row a door claim names: a stored one, or an earlier item's.
#[derive(Debug, Clone)]
pub enum Named {
    /// A stored row.
    Stored(EntityId),
    /// The row an earlier item of the batch lands, by its local name.
    Local(&'static str),
}

/// One derived claim for a door batch.
#[derive(Debug, Clone)]
pub struct Claim {
    pub local: &'static str,
    pub predicate: &'static str,
    pub subject: Named,
    pub value: serde_json::Value,
    pub evidence: Vec<Named>,
}

/// Evidence for a door batch: `sources` support the claim `head`.
#[derive(Debug, Clone)]
pub struct Evidence {
    pub local: &'static str,
    pub head: Named,
    pub sources: Vec<Named>,
}

/// A SameAs for a door batch: `source` is the same as `target`.
#[derive(Debug, Clone)]
pub struct SameAs {
    pub local: &'static str,
    pub source: Named,
    pub target: Named,
}

/// A distinct assertion for a door batch: `a` and `b` are different, under
/// the agent's `topology_seal` Grant `grant`; applied when `apply`.
#[derive(Debug, Clone)]
pub struct Distinct {
    pub local: &'static str,
    pub a: EntityId,
    pub b: EntityId,
    pub grant: EntityId,
    pub apply: bool,
}

/// A supersession for a door batch: `new` replaces `old`.
#[derive(Debug, Clone)]
pub struct Supersede {
    pub local: &'static str,
    pub new: Named,
    pub old: Named,
}

/// An answer to one open conflict, for a door batch.
#[derive(Debug, Clone)]
pub enum Settlement {
    /// This member stands.
    Keep(Named),
    /// Every member stays active.
    HoldBoth,
    /// The marker named no real contradiction.
    Dismiss,
}

/// A settlement for a door batch.
#[derive(Debug, Clone)]
pub struct Settle {
    pub local: &'static str,
    pub marker: Named,
    pub settlement: Settlement,
}

/// An archive for a door batch: `claim` at `score`.
#[derive(Debug, Clone)]
pub struct Archive {
    pub local: &'static str,
    pub claim: Named,
    pub score: f64,
}

/// A person's `about` lines for a door batch, written from the facts whose
/// digest `written_from` names.
#[derive(Debug, Clone)]
pub struct About {
    pub local: &'static str,
    pub person: Named,
    pub written_from: [u8; 32],
    /// Each line's band and text, lowest band first.
    pub lines: Vec<(u8, &'static str)>,
}

/// A PsychProfile for a door batch: about `subject`, built from the whole
/// record `document`.
#[derive(Debug, Clone)]
pub struct Profile {
    pub local: &'static str,
    pub subject: EntityId,
    pub document: EntityId,
}

/// One item of a door batch.
#[derive(Debug, Clone)]
pub enum Derived {
    Claim(Claim),
    Evidence(Evidence),
    Supersede(Supersede),
    Settle(Settle),
    SameAs(SameAs),
    Distinct(Distinct),
    About(About),
    Profile(Profile),
    Archive(Archive),
}

/// One item's outcome, as the commit answered it or the batch record keeps
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub local: String,
    pub kind: String,
    pub landed: bool,
    pub rows: Vec<EntityId>,
    /// `auto` or `proposed` for a landed claim.
    pub approval: Option<String>,
    pub reasons: Vec<String>,
}

/// What a door commit did.
#[derive(Debug, Clone)]
pub struct Committed {
    pub batch: EntityId,
    pub items: Vec<Item>,
}

fn named(named: &Named) -> ItemRef {
    match named {
        Named::Stored(id) => ItemRef::Stored(*id),
        Named::Local(name) => ItemRef::Local((*name).to_owned()),
    }
}

/// Writes the shipped policy with a `core:read` grant for `reader`, as an
/// owner's policy lets a member read: the rows `reader` names and cites then
/// read back to it.
///
/// # Errors
///
/// The vault's.
pub fn grant_core_read(vault: &Vault, reader: EntityId) -> Result<()> {
    super::consolidation::shipped_policy_with_reader(vault, &reader.to_hex())
}

/// Writes the shipped policy with a `core:read` grant for `reader` that
/// reaches rows of the kinds `kinds` alone: a row of any other kind is
/// outside its read.
///
/// # Errors
///
/// The vault's.
pub fn grant_core_read_of_kinds(vault: &Vault, reader: EntityId, kinds: &[u8]) -> Result<()> {
    let mut scope = crate::federation::scope_codec::read_preset();
    scope.bands = crate::federation::ScopeAxis::Some(kinds.iter().copied().collect());
    super::consolidation::shipped_policy_with_read_scope(vault, &reader.to_hex(), &scope)
}

/// Commits `claims` as one batch by `actor` of `class`, in run `run`.
///
/// # Errors
///
/// The commit's: a malformed batch or a storage error.
pub fn commit_claims(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
    run: &str,
    claims: &[Claim],
) -> Result<Committed> {
    let items: Vec<Derived> = claims.iter().cloned().map(Derived::Claim).collect();
    commit(vault, actor, class, run, &items)
}

/// Commits `items` as one batch by `actor` of `class`, in run `run`.
///
/// # Errors
///
/// The commit's: a malformed batch or a storage error.
pub fn commit(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
    run: &str,
    items: &[Derived],
) -> Result<Committed> {
    commit_in_attempt(vault, actor, class, run, None, items)
}

/// [`commit`] in the attempt `attempt`.
///
/// # Errors
///
/// The commit's: a malformed batch or a storage error.
pub fn commit_in_attempt(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
    run: &str,
    attempt: Option<AttemptId>,
    items: &[Derived],
) -> Result<Committed> {
    let stamp = DerivationStamp {
        actor: WriteActor::new(actor, class),
        run: Some(run.to_owned()),
        attempt,
        lineage: SourceLineage::of(ClaimSource::Generated),
    };
    let batch = DerivationBatch {
        items: items
            .iter()
            .map(|item| -> Result<DerivationItem> {
                Ok(match item {
                    Derived::Claim(claim) => DerivationItem::Claim(DerivedClaim {
                        local: claim.local.to_owned(),
                        predicate: claim.predicate.to_owned(),
                        subject: named(&claim.subject),
                        value: claim.value.clone(),
                        confidence: 0.9,
                        evidence: claim.evidence.iter().map(named).collect(),
                    }),
                    Derived::Evidence(evidence) => DerivationItem::Evidence(DerivedEvidence {
                        local: evidence.local.to_owned(),
                        head: named(&evidence.head),
                        sources: evidence.sources.iter().map(named).collect(),
                    }),
                    Derived::Supersede(supersede) => DerivationItem::Supersede(DerivedSupersede {
                        local: supersede.local.to_owned(),
                        new: named(&supersede.new),
                        old: named(&supersede.old),
                    }),
                    Derived::Archive(archive) => DerivationItem::Archive(DerivedArchive {
                        local: archive.local.to_owned(),
                        claim: named(&archive.claim),
                        signals: crate::dreamer_consolidation::selection::StrengthSignals {
                            type_prior: 0.1,
                            frequency: 0.1,
                            recency: 0.1,
                            diversity: 0.1,
                        },
                        score: archive.score,
                    }),
                    Derived::Settle(settle) => DerivationItem::Settle(DerivedSettle {
                        local: settle.local.to_owned(),
                        marker: named(&settle.marker),
                        settlement: match &settle.settlement {
                            Settlement::Keep(kept) => DerivedSettlement::Keep(named(kept)),
                            Settlement::HoldBoth => DerivedSettlement::HoldBoth,
                            Settlement::Dismiss => DerivedSettlement::Dismiss,
                        },
                    }),
                    Derived::SameAs(same_as) => DerivationItem::SameAs(DerivedSameAs {
                        local: same_as.local.to_owned(),
                        source: named(&same_as.source),
                        target: named(&same_as.target),
                    }),
                    Derived::Distinct(distinct) => DerivationItem::Topology(DerivedTopology {
                        local: distinct.local.to_owned(),
                        op: crate::identity_topology::IdentityTopologyOp::AssertDistinct(
                            crate::identity_topology::AssertDistinctOp {
                                a: distinct.a,
                                b: distinct.b,
                                reason: "derived".to_owned(),
                            },
                        ),
                        grant: distinct.grant,
                        apply: distinct.apply,
                    }),
                    Derived::About(about) => DerivationItem::PersonAbout(DerivedPersonAbout {
                        local: about.local.to_owned(),
                        person: named(&about.person),
                        written_from: about.written_from,
                        lines: about
                            .lines
                            .iter()
                            .map(|(band, text)| DerivedAboutLine {
                                band: *band,
                                text: (*text).to_owned(),
                            })
                            .collect(),
                    }),
                    Derived::Profile(profile) => {
                        DerivationItem::PsychProfile(DerivedPsychProfile {
                            local: profile.local.to_owned(),
                            facet: None,
                            world: None,
                            profile: whole_record_profile(profile.subject, profile.document)?,
                        })
                    }
                })
            })
            .collect::<Result<Vec<_>>>()?,
    };
    let receipt = vault.derive_commit(&stamp, &batch)?;
    Ok(Committed {
        batch: receipt.batch,
        items: receipt
            .items
            .into_iter()
            .map(|item| match item.outcome {
                ItemOutcome::Landed { rows, approval, .. } => Item {
                    local: item.local,
                    kind: item.kind.to_owned(),
                    landed: true,
                    rows,
                    approval: approval.map(|approval| approval.as_str().to_owned()),
                    reasons: Vec::new(),
                },
                ItemOutcome::Refused { reasons, .. } => Item {
                    local: item.local,
                    kind: item.kind.to_owned(),
                    landed: false,
                    rows: Vec::new(),
                    approval: None,
                    reasons,
                },
            })
            .collect(),
    })
}

/// A PsychProfile about `subject` built from the whole record `document`.
fn whole_record_profile(
    subject: EntityId,
    document: EntityId,
) -> Result<crate::psych_profile::PsychProfile> {
    use crate::psych_profile::{
        PsychProfile, PsychProfileConfidence, PsychProfileSource, PsychProfileSourceWords,
    };
    PsychProfile::new(
        subject,
        "steady and curious",
        "A steady, curious person.",
        "They meet new things steadily and with curiosity.",
        vec![document],
        PsychProfileConfidence::new(0.8, 0.7, 0.6)?,
    )?
    .with_sources(vec![PsychProfileSource {
        revision_ref: document,
        document_ref: document,
        world_ref: None,
        document_revision: crate::vault::RevisionRef([0; 16]),
        words: PsychProfileSourceWords::Record { content: [0; 32] },
    }])
}

/// The digest of the facts about `person` that `actor` of `class` reads,
/// and the bands that take a line: what an `about` item is written from.
///
/// # Errors
///
/// The vault's.
pub fn about_facts(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
    person: EntityId,
) -> Result<([u8; 32], Vec<u8>)> {
    let facts = vault.person_about_facts(WriteActor::new(actor, class), person)?;
    Ok((facts.digest, facts.bands))
}

/// The PEOPLE `about` step at the start of a Dreamer wake pass: it reads
/// every person's facts and records the facts each person's lines are now
/// asked from. A reader sees a person's lines only while they are written
/// from the facts a wake pass last read.
///
/// # Errors
///
/// The vault's.
pub fn wake_reads_about_facts(vault: &Vault) -> Result<()> {
    crate::dreamer_consolidation::enqueue_person_about_on_wake(vault, vault.now_recorded_at())
}

/// The subject of the stored claim `id`, when it is a stored claim about a
/// row.
///
/// # Errors
///
/// The vault's.
pub fn claim_subject(vault: &Vault, id: EntityId) -> Result<Option<EntityId>> {
    let Some(raw) = vault.get(&id)? else {
        return Ok(None);
    };
    Ok(crate::claim::decode_claim_body(&raw, true)
        .ok()
        .and_then(|body| match body.subject {
            crate::claim::ClaimSubject::Entity(subject) => Some(subject),
            _ => None,
        }))
}

/// Whether a PsychProfile about `subject` is stored at the address with no
/// facet and no world.
///
/// # Errors
///
/// The vault's.
pub fn profile_stored(vault: &Vault, subject: EntityId) -> Result<bool> {
    use crate::psych_profile::{PsychProfileKey, psych_profile_entity_id};
    let id = psych_profile_entity_id(&PsychProfileKey {
        person: subject,
        facet: None,
        world: None,
    });
    Ok(vault.get_psych_profile(&id)?.is_some())
}

/// Witnesses one user TURN saying `words`, as a new speaker; its id.
///
/// # Errors
///
/// The vault's.
pub fn witness_turn(vault: &Vault, words: &str) -> Result<EntityId> {
    use crate::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
    let speaker = EntityId::now();
    vault.put_entity(
        &speaker,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"witness",
    )?;
    let turn = EntityId::now();
    vault
        .memory(speaker, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: words.to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: 10,
            assertions: WitnessAssertions::default(),
        })
        .map_err(|error| crate::error::Error::InvalidConfig(format!("witness: {error:?}")))?;
    Ok(turn)
}

/// Whether `source` holds a `supports` edge to `head`.
///
/// # Errors
///
/// The vault's.
pub fn supports(vault: &Vault, source: EntityId, head: EntityId) -> Result<bool> {
    use crate::ports::EdgeStoreRead;
    let txn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .port_edge_get(&txn, &source, crate::edge::EdgeKind::Supports, &head)?
        .is_some())
}

/// Whether `source` holds a `same_as` edge to `target`.
///
/// # Errors
///
/// The vault's.
pub fn same_as_edge(vault: &Vault, source: EntityId, target: EntityId) -> Result<bool> {
    use crate::ports::EdgeStoreRead;
    let txn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .port_edge_get(&txn, &source, crate::edge::EdgeKind::SameAs, &target)?
        .is_some())
}

/// The embedded owner mints the standing grant that lets the Dreamer apply
/// its SameAs links.
///
/// # Errors
///
/// The vault's.
pub fn mint_nightly_links(vault: &Vault) -> Result<()> {
    let owner = super::steward::owner(vault)?;
    crate::dreamer_consolidation::mint_nightly_link_grant(
        vault,
        &owner,
        crate::dreamer_consolidation::NightlyLinkGrantRequest::default(),
    )
    .map_err(|error| {
        crate::error::Error::InvalidConfig(format!("nightly link grant: {error:?}"))
    })?;
    Ok(())
}

/// The lifecycle status of the claim `id` (`active`, `superseded`, ...),
/// when it is a stored claim.
///
/// # Errors
///
/// The vault's.
pub fn claim_lifecycle(vault: &Vault, id: EntityId) -> Result<Option<String>> {
    let Some(raw) = vault.get(&id)? else {
        return Ok(None);
    };
    Ok(crate::claim::decode_claim_body(&raw, true)
        .ok()
        .map(|body| body.lifecycle.as_str().to_owned()))
}

/// Opens a conflict between the stored claims `new` and `old`, as the
/// claim lifecycle's supersession coaching opens one: the Dreamer writes the
/// pair's `core.conflict.open` marker as a proposal. Its id.
///
/// # Errors
///
/// The vault's, and a `new` that is no stored claim.
pub fn open_conflict(vault: &Vault, new: EntityId, old: EntityId) -> Result<EntityId> {
    use crate::claim::{ClaimApprovalStatus, ClaimSource};
    use crate::write_envelope::{WriteEnvelope, WriteProvenance};
    let raw = vault
        .get(&new)?
        .ok_or(crate::error::Error::EntityNotFound)?;
    let body = crate::claim::decode_claim_body(&raw, true)?;
    let envelope = WriteEnvelope::new(
        vault.dreamer_authority()?,
        ClaimSource::Generated,
        WriteProvenance::new(rmpv::Value::Map(vec![(
            rmpv::Value::from("surface"),
            rmpv::Value::from("test.open_conflict"),
        )]))?,
        ClaimApprovalStatus::Proposed,
    );
    let marker = crate::claim::conflict_marker(&new, &old, &body, &envelope)?;
    let now = vault.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        let mut envelope = marker.envelope.clone();
        vault.sign_retained_machine_claim_in_txn(
            txn,
            &marker.id,
            &marker.candidate,
            &mut envelope,
        )?;
        vault
            .batch_in()
            .claim_candidate(
                &marker.id,
                marker.candidate.clone(),
                &envelope,
                crate::TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )
            .apply_recording_gate_decisions(txn)
    })?;
    Ok(marker.id)
}

/// Sets the owner's strength policy: a claim archives only with a score
/// below `archive_below`, once quiet for `quiet_ms`.
///
/// # Errors
///
/// The vault's, and a policy out of bounds.
pub fn set_strength_policy(vault: &Vault, archive_below: f64, quiet_ms: u64) -> Result<()> {
    vault.set_consolidation_strength_policy(
        &crate::dreamer_consolidation::strength::ConsolidationStrengthPolicy {
            archive_below,
            quiet_ms,
        },
    )
}

/// Whether the row `id` is live: an archived claim is not.
///
/// # Errors
///
/// The vault's.
pub fn row_live(vault: &Vault, id: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(crate::vault::live_entity_row_in_txn(&vault.store, &txn, &id)?.is_live())
}

/// The items of the committed batch `batch`, as its record keeps them.
///
/// # Errors
///
/// The vault's.
pub fn batch_items(vault: &Vault, batch: EntityId) -> Result<Option<Vec<Item>>> {
    Ok(vault.derive_batch(batch)?.map(|record| {
        record
            .items
            .into_iter()
            .map(|item| Item {
                local: item.local,
                kind: item.kind,
                landed: item.landed,
                rows: item.rows,
                approval: item.approval,
                reasons: item.reasons,
            })
            .collect()
    }))
}

/// The batches `actor` committed, oldest first.
///
/// # Errors
///
/// The vault's.
pub fn batches_of(vault: &Vault, actor: EntityId) -> Result<Vec<EntityId>> {
    vault.derive_batches_of(actor)
}

/// The reason tokens of the refusal receipt the batch record names for its
/// item `local`; `None` when the item has no refusal receipt.
///
/// # Errors
///
/// The vault's.
pub fn refusal_receipt(vault: &Vault, batch: EntityId, local: &str) -> Result<Option<Vec<String>>> {
    let Some(record) = vault.derive_batch(batch)? else {
        return Ok(None);
    };
    let txn = vault.store.env.read_txn()?;
    let Some(receipt) = record
        .items
        .iter()
        .find(|item| item.local == local)
        .and_then(|item| item.receipt)
    else {
        return Ok(None);
    };
    Ok(vault
        .store
        .gate_decision_in_txn(&txn, crate::store::GateDecisionId::from_bytes(receipt))?
        .filter(|decision| {
            decision.content_kind == crate::derive::DERIVE_ITEM_CONTENT_KIND
                && decision.outcome == "deny"
        })
        .map(|decision| decision.reason_codes))
}

/// The derive verdict for `actor` of `class` doing `capability` (`archive`
/// when `archive`, else `derive`) to `target`: the grant it was judged by,
/// or the refusal's token.
///
/// # Errors
///
/// The vault's.
pub fn derive_verdict(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
    archive: bool,
    target: Option<EntityId>,
) -> Result<std::result::Result<String, &'static str>> {
    let capability = if archive {
        DeriveCapability::Archive
    } else {
        DeriveCapability::Derive
    };
    let txn = vault.store.env.read_txn()?;
    Ok(crate::gate::derive_verdict_in_txn(
        &vault.store,
        &txn,
        WriteActor::new(actor, class),
        capability,
        target,
    )?
    .map(|allowed| allowed.grant_ref)
    .map_err(DeriveRefusal::token))
}

/// Every refusal token of the derive verdict.
#[must_use]
pub fn refusal_tokens() -> Vec<&'static str> {
    [
        DeriveRefusal::NoLandingRows,
        DeriveRefusal::OptedOut,
        DeriveRefusal::GrantGone,
        DeriveRefusal::GrantLacksDerive,
        DeriveRefusal::GrantLacksArchive,
        DeriveRefusal::OutsideGrant,
    ]
    .into_iter()
    .map(DeriveRefusal::token)
    .collect()
}
