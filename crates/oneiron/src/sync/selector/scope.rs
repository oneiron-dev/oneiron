//! Export scope tables: coreference consent context, per-source facet scope mirror, and per-entity decisions.

use std::collections::{BTreeSet, HashMap, HashSet};

use loro::LoroDoc;

use crate::Vault;
use crate::authority::{AuthorityFold, FederationPactStatus};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{COREFERENCE_PACT_ID_LEN, ClaimLifecycleStatus};
use crate::companion::{
    CompanionExportClassification, CompanionScope, ENTITY_TYPE_COMPANION_REGISTER,
    decode_companion_record_body,
};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{FederationGrantScope, selector_range_of};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_WORLD};
use crate::sync::bridge::parse_edge_key;
use crate::sync::loro_support::map_for_each_value_bytes;

use super::codec::{EmptyAxis, SyncSelector, SyncSelectorWorld};

/// Which coreference material this ONE export request may carry (ONE-1414).
///
/// Cross-vault coreference is LOCAL BY DEFAULT: a `same_as` link and every
/// `core.coreference.*` claim stay home unless the owner consented to share
/// THIS link into THIS pact. The context is the whole answer for one request —
/// built once, read on every row — so the edge pass and the claim pass cannot
/// reach different conclusions about the same link.
///
/// `pact_id` absent means the grant is UNPACTED, and an unpacted grant carries
/// no coreference material at all: with no pact there is nothing a consent
/// claim could name, so a consent-SHAPED claim in the window is not consent to
/// anything. That case is not special-cased anywhere — it falls out of
/// `allowed_links` being empty.
#[derive(Debug, Default)]
pub(super) struct CoreferenceExportContext {
    /// The pact this export runs under, when the grant is pact-bound.
    pact_id: Option<[u8; COREFERENCE_PACT_ID_LEN]>,
    /// Links the owner consented to share into exactly `pact_id`, with
    /// endpoint order normalized — consent is a property of the LINK, not of
    /// which endpoint happens to be stored as the source.
    allowed_links: BTreeSet<(EntityId, EntityId)>,
}

impl CoreferenceExportContext {
    pub(super) fn allows(&self, source: EntityId, target: EntityId) -> bool {
        self.allowed_links
            .contains(&normalized_coreference_pair(source, target))
    }

    /// Whether one decoded CLAIM body may travel.
    ///
    /// Claims outside the `core.coreference.*` namespace are none of this
    /// context's business and pass untouched. Inside it:
    ///
    /// * the claim must hang off a `same_as` EdgeRef whose link is allowed —
    ///   a coreference-namespace claim on any other subject describes no link
    ///   this context can vouch for, so it is withheld;
    /// * a STATUS claim then travels with its link, because the status is what
    ///   makes the shared link mean anything;
    /// * a SHARE-CONSENT claim travels only when it names THIS export's pact.
    ///   Pact Q's consent is not a weaker statement about pact P, it is a
    ///   statement about a relationship P's peer is not party to — shipping it
    ///   would disclose the existence of another federation.
    fn claim_travels(&self, body: &crate::claim::ClaimBody) -> bool {
        if !body
            .predicate
            .starts_with(crate::claim::PREDICATE_COREFERENCE_PREFIX)
        {
            return true;
        }
        let crate::claim::ClaimSubject::Edge {
            source,
            kind: EdgeKind::SameAs,
            target,
        } = body.subject
        else {
            return false;
        };
        if !self.allows(source, target) {
            return false;
        }
        if body.predicate != crate::claim::PREDICATE_COREFERENCE_SHARE_CONSENT {
            return true;
        }
        matches!(
            (
                self.pact_id,
                crate::claim::coreference_share_consent_pact_id(body),
            ),
            (Some(pact), Ok(claimed)) if claimed == pact
        )
    }
}

/// Endpoint pair in a stable order, so one link has one identity regardless of
/// which orientation it was stored in.
fn normalized_coreference_pair(source: EntityId, target: EntityId) -> (EntityId, EntityId) {
    if source <= target {
        (source, target)
    } else {
        (target, source)
    }
}

/// Resolves what coreference material this request may carry.
///
/// The `same_as` pairs come from the SOURCE DOC — that is what could be
/// exported — while CONSENT is read from the VAULT. That split is the same
/// stored-first discipline [`mirrored_endpoint_type`] applies to endpoint
/// types, and for the same reason: LMDB holds the owner's actual decision,
/// whereas a document row is whatever last won the map. Reading consent from
/// the doc would let a row decide its own disclosure.
///
/// The doc scan runs FIRST and returns early when the window carries no
/// `same_as` edge at all, which is the overwhelming majority of exports: the
/// authority fold is not recomputed for a window that has no link to share.
/// The early return is not a bypass — the default context allows nothing, so a
/// stray coreference claim whose link is absent from the window is still
/// withheld.
pub(super) fn coreference_export_context(
    vault: &Vault,
    source: &LoroDoc,
    selector: &SyncSelector,
) -> Result<CoreferenceExportContext> {
    let mut pairs = BTreeSet::<(EntityId, EntityId)>::new();
    map_for_each_value_bytes(&source.get_map("edges"), |raw_key, maybe_value| {
        if maybe_value.is_none() {
            return;
        }
        if let Some((src, EdgeKind::SameAs, tgt)) = parse_edge_key(raw_key) {
            pairs.insert(normalized_coreference_pair(src, tgt));
        }
    });
    if pairs.is_empty() {
        return Ok(CoreferenceExportContext::default());
    }

    let fold = vault.authority_fold()?;
    let Some(pact_id) = active_export_pact(&fold, &selector.grant_id) else {
        return Ok(CoreferenceExportContext::default());
    };

    let mut allowed_links = BTreeSet::new();
    for (a, b) in pairs {
        if crate::federation::coreference_shared_for_pact(vault, a, b, &pact_id)? {
            allowed_links.insert((a, b));
        }
    }
    Ok(CoreferenceExportContext {
        pact_id: Some(pact_id),
        allowed_links,
    })
}

/// The id of the ACTIVE pact governing `grant_id`, or `None` when the grant is
/// unpacted or its governing pact is not Active.
///
/// Which pact governs is [`AuthorityFold::pact_for_grant`]'s decision and stays
/// there; this only recovers the id, which the fold keys the map by rather than
/// storing in the state. The identity comparison is by reference into that same
/// map, so it can never match a different pact that merely compares equal.
fn active_export_pact(
    fold: &AuthorityFold,
    grant_id: &EntityId,
) -> Option<[u8; COREFERENCE_PACT_ID_LEN]> {
    let pact = fold.pact_for_grant(grant_id)?;
    if pact.status != FederationPactStatus::Active {
        return None;
    }
    fold.federation_pacts
        .iter()
        .find_map(|(id, candidate)| std::ptr::eq(candidate, pact).then_some(*id))
}

/// One source entity's `FacetOf` scope, as read by [`facet_scope_by_source`].
///
/// A source with NO entry is Unfaceted — either it carries no `FacetOf` rows
/// at all, or every row it carries was SCOPE-INERT (the source is not typed
/// into the admitted set, or the row's target does not resolve to a FACET).
/// The two are deliberately the same state: an inert stamp is not a withhold,
/// it is a non-statement.
#[derive(Debug, Default)]
pub(super) struct FacetScope {
    any: bool,
    selected: bool,
    unselected: bool,
    malformed: bool,
}

#[derive(Debug)]
pub(super) struct EntitySelectorDecision {
    pub(super) facet_visible: bool,
    pub(super) facet_seed: bool,
}

/// Builds the per-source facet scope a facet-limited peer's export is filtered
/// against, honoring a `FacetOf` row's scope ONLY when BOTH endpoints resolve
/// onto the ONE-1645 table: the source into the admitted set
/// (`CLAIM | TURN | EVENT`) and the target to a FACET.
///
/// READ MIRROR OF THE WRITE TABLE — the why. This door reads the RAW Loro map,
/// never LMDB, so it sees rows no write door would have accepted: the local
/// batch door aborts an off-table stamp, the remat chokepoint quarantines one,
/// and [`copy_admitted_edges`] drops a PROVABLY off-table one at the
/// federation trust boundary — but the H2 defer deliberately lets a row whose
/// deciding endpoint is not knowable YET pass through, and that row is still
/// sitting in the document after its endpoint later arrives typed off-table.
/// Honoring it would let a forged `PERSON -> <selected FACET>` stamp pull the
/// PERSON and its one-hop neighbors across the disclosure boundary, which is
/// an authorization bypass, not a schema violation.
///
/// So the read side runs the SAME table the write side runs, on BOTH endpoints
/// ([`crate::batch::facet_of_endpoint_types_on_table`]): a stamp is honored
/// here exactly when it is a stamp the engine would have let be WRITTEN. A row
/// failing either half is SCOPE-INERT — never a seed, never a withhold — so
/// its source is simply Unfaceted, judged on the selector's other filters like
/// any unstamped entity.
///
/// BOTH HALVES ARE LOAD-BEARING, and the target half is the subtler one. A
/// selector's `facets` list is a set of ids the peer NAMED; membership in it
/// is not evidence the id exists, still less that it is a FACET. A forged
/// `<on-table src> -> <selected id>` row aimed at an ABSENT id would, under a
/// source-only mirror, seed closure from an id the document never typed — and
/// a later frame delivering that id as a PERSON would keep the seed live,
/// because nothing re-examines a resident row. Requiring the target to RESOLVE
/// TO A FACET makes the row inert until such a blob actually exists, at which
/// point the row HEALS into ordinary scoping.
///
/// ENDPOINT TYPES RESOLVE STORED-FIRST, the same two-source order
/// [`admitted_endpoint_type`] uses at the admission boundary:
///
/// 1. the LOCAL vault row — entity type is immutable per id
///    ([`Error::EntityTypeImmutable`]), so a stored type is PERMANENT truth
///    about that id, and the quarantine door that enforces it leaves LMDB
///    holding the first-writer type;
/// 2. else the document blob.
///
/// Reading the document blob FIRST would be LWW-gameable: a peer stores an
/// endpoint as PERSON (the type-conflict quarantine correctly leaves LMDB at
/// PERSON) while a higher-Lamport EVENT blob wins the Loro map, and a
/// blob-first mirror reads the fake.
///
/// WHERE THE TWO DISAGREE the STORED type wins, in BOTH endpoint roles: the
/// conflicting blob is a write the immutability gate rejected, and a rejected
/// write is never consulted for anything. [`mirrored_endpoint_type`] carries
/// the rule and its full argument.
///
/// The asymmetry — inert rather than fail-closed — is deliberate. Making the
/// mirror "helpfully" withhold on an unwritable row would hand a hostile peer
/// a SUPPRESSION primitive: spray `<host's PERSON> -> <any facet>` rows into
/// the window and the host's own entities vanish from a legitimate grant.
/// Refusing to READ an unwritable row is the fix; letting it DENY is the same
/// bug with the sign flipped.
///
/// SCOPE OF THIS MIRROR: it is the read-side twin of THIS lane's write table,
/// nothing wider. The broader exposure-gate design — which disclosure surfaces
/// should consult facet scope at all, and how facet exposure state is
/// consented — is S-DISC2's, and ONE-1646's gate table is derived from door
/// behavior that this function's admitted set now defines on both sides.
/// EVENT is admitted, so EVENT-sourced stamps stay disclosure-effective here
/// (pinned by `tests::selector_denies_event_scoped_to_unselected_facet`).
pub(super) fn facet_scope_by_source(
    vault: &Vault,
    entities: &loro::LoroMap,
    edges: &loro::LoroMap,
    selector: &SyncSelector,
) -> Result<HashMap<EntityId, FacetScope>> {
    let selected: HashSet<EntityId> = selector.facets.iter().copied().collect();
    let mut scopes = HashMap::<EntityId, FacetScope>::new();
    if selected.is_empty() {
        return Ok(scopes);
    }

    let rtxn = vault.store.env.read_txn()?;
    // Endpoint types are read once per id, not once per row: a source may
    // carry many stamps and a facet may be named by many sources. One rule
    // serves both roles, so an id appearing in both still costs one read.
    let mut types = HashMap::<EntityId, Option<u8>>::new();
    let mut result = Ok(());
    map_for_each_value_bytes(edges, |raw_key, maybe_value| {
        if result.is_err() {
            return;
        }
        let Some((src, kind, tgt)) = parse_edge_key(raw_key) else {
            return;
        };
        if kind != EdgeKind::FacetOf {
            return;
        }
        // BOTH endpoints must resolve onto the table. A LOCAL fault reading
        // stored types (corrupted header, heed read error) is our defect, not
        // the peer's: fail the export closed rather than silently drop a scope
        // and over-disclose.
        let (src_type, tgt_type) = match (
            mirrored_endpoint_type(vault, &rtxn, entities, &mut types, &src),
            mirrored_endpoint_type(vault, &rtxn, entities, &mut types, &tgt),
        ) {
            (Ok(src_type), Ok(tgt_type)) => (src_type, tgt_type),
            (Err(local), _) | (_, Err(local)) => {
                result = Err(local);
                return;
            }
        };
        // A row that fails either half is SCOPE-INERT: not a seed, and not a
        // withhold either. The target half is the one a source-only mirror
        // misses — a selector's `facets` list is ids the peer NAMED, which is
        // no evidence any of them exists or is a FACET.
        let on_table = matches!((src_type, tgt_type), (Some(src_type), Some(tgt_type))
            if crate::batch::facet_of_endpoint_types_on_table(src_type, tgt_type));
        if !on_table {
            return;
        }
        let entry = scopes.entry(src).or_default();
        entry.any = true;
        if maybe_value.is_none() {
            entry.malformed = true;
            return;
        }
        if selected.contains(&tgt) {
            entry.selected = true;
        } else {
            entry.unselected = true;
        }
    });
    result.map(|()| scopes)
}

/// One `FacetOf` endpoint's effective type byte for the read mirror, memoized
/// per id. ONE rule, both roles — an endpoint carries the same type whichever
/// end of the row it sits on, so a single memo entry serves both.
///
/// Resolution is [`admitted_endpoint_type`]'s STORED-FIRST order, with the
/// stored row winning OUTRIGHT when the two facts disagree:
///
/// 1. the LOCAL vault row — entity type is immutable per id
///    ([`Error::EntityTypeImmutable`]), so a stored type is PERMANENT truth
///    and the quarantine door that enforces it leaves LMDB holding the
///    first-writer type. When it exists, nothing else is consulted;
/// 2. else the document blob — the not-yet-materialized endpoint of an honest
///    out-of-order delivery (the H2 line), which the ONE-1645 table then
///    judges on its own merits;
/// 3. neither ⇒ `None`: unknowable, hence scope-inert until the endpoint
///    really lands, at which point the row HEALS into ordinary scoping.
///
/// STORED-WINS IS THE WHOLE CONFLICT RULE, and it is one rule rather than a
/// per-role pair because a CONFLICTING blob is a write the immutability gate
/// REJECTED — a rejected write is not evidence about anything, so it is never
/// consulted, in either role, for any purpose. Both attacks die on the same
/// clause:
///
/// * a conflicting blob never CREATES a seed. A stored PERSON with a forged
///   admitted-type blob still reads PERSON, so the stamp stays off the table
///   and seeds nothing — the peer cannot BUY scope with a type the engine
///   refused to write. Symmetrically on the target: a forged FACET blob over
///   a stored PERSON cannot manufacture a facet.
/// * a conflicting blob never ERASES a withhold. A stored EVENT source and a
///   stored FACET target keep scoping through any retype aimed at either end,
///   so an entity withheld from a facet-limited peer stays withheld. Reading a
///   conflict as `None` on EITHER end would make the row inert and delete
///   containment a valid stored row had already established.
///
/// SUPPRESSION STILL CANNOT BE MANUFACTURED, which is the property the
/// inert-not-fail-closed rule protects: the withholds that survive are exactly
/// the ones the STORED types already justified. A forged unselected stamp
/// aimed at a stored-PERSON source is off the table and stays inert, so no new
/// suppression primitive appears — a peer cannot make the host's own rows
/// vanish from a legitimate grant by spraying rejected blobs.
///
/// FAIL DIRECTION: stored truth never loses to a rejected write, in either
/// role. A peer-controlled conflict can therefore never move a row from
/// withheld to exported, nor from contained to seeded.
///
/// Absent, non-binary, and header-unparsable document blobs all read as no
/// document fact. A LOCAL fault reading the stored row (unparsable header) is
/// our defect, not the peer's, and propagates.
fn mirrored_endpoint_type(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    entities: &loro::LoroMap,
    cache: &mut HashMap<EntityId, Option<u8>>,
    id: &EntityId,
) -> Result<Option<u8>> {
    if let Some(cached) = cache.get(id) {
        return Ok(*cached);
    }
    let resolved = match crate::batch::stored_entity_type(&vault.store, rtxn, id)? {
        Some(stored) => Some(stored),
        None => super::loro_support::map_get_bytes(entities, &id.to_hex())
            .as_deref()
            .and_then(EntityMetadataHeader::parse)
            .map(|header| header.entity_type),
    };
    cache.insert(*id, resolved);
    Ok(resolved)
}

pub(super) fn entity_selector_decision(
    id: &EntityId,
    blob: &[u8],
    grant_scope: FederationGrantScope,
    selector: &SyncSelector,
    facet_scope: &HashMap<EntityId, FacetScope>,
    empty: EmptyAxis,
    coreference: &CoreferenceExportContext,
) -> Option<EntitySelectorDecision> {
    let header = EntityMetadataHeader::parse(blob)?;
    if !coreference_claim_passes(header.entity_type, blob, coreference) {
        return None;
    }
    // Interim ONE-1865 guard (SECRET-01, ONE-1919): no SECRET_CUSTODY record
    // replicates at all until ONE-1865's per-credential portable dial replaces
    // this blanket exclusion with `portable ∧ !device_only` respect. Without
    // this the class contract ("device-bound never leaves the device",
    // "cross-vault never replicated") would be false from merge until 1865.
    if header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
        return None;
    }
    if header.entity_type == ENTITY_TYPE_COMPANION_REGISTER
        && !companion_register_passes_selector(blob, grant_scope)
    {
        return None;
    }
    if selector.band_filter_active(empty)
        && !selector
            .bands
            .contains(&selector_range_of(header.entity_type))
    {
        return None;
    }
    if selector.facet_filter_active(empty)
        && header.entity_type == ENTITY_TYPE_FACET
        && !selector.facets.contains(id)
    {
        return None;
    }
    if selector.facet_filter_active(empty)
        && facet_scope.get(id).is_some_and(|scope| {
            scope.malformed || scope.unselected || (scope.any && !scope.selected)
        })
    {
        return None;
    }
    if header.entity_type == ENTITY_TYPE_WORLD {
        match selector.world {
            SyncSelectorWorld::All => {}
            SyncSelectorWorld::Base => return None,
            SyncSelectorWorld::World(world) if *id != world.entity_id() => return None,
            SyncSelectorWorld::World(_) => {}
        }
    }
    if !world_passes(
        header.entity_type,
        &blob[ENTITY_METADATA_HEADER_LEN..],
        selector.world,
    ) {
        return None;
    }
    let facet_visible = selector.facet_filter_active(empty)
        && header.entity_type == ENTITY_TYPE_FACET
        && selector.facets.contains(id);
    let facet_seed = selector.facet_filter_active(empty)
        && facet_scope.get(id).is_some_and(|scope| scope.selected);
    Some(EntitySelectorDecision {
        facet_visible,
        facet_seed,
    })
}

/// ONE-1414 coreference exclusion, applied to ONE candidate entity blob.
///
/// Non-CLAIM blobs are none of this arm's business and pass untouched. A CLAIM
/// blob that does not DECODE is WITHHELD, the same fail-closed reading
/// [`world_passes`] already applies to the same bytes.
///
/// The fail direction is not stylistic. `filtered_window_doc` filters a
/// caller-supplied doc, and in production that doc is the live window carrying
/// peer-pushed rows the bridge itself calls peer-controlled input — quarantine
/// RECORDS a rejected row but does not remove it from the CRDT. Passing an
/// undecodable CLAIM through would therefore hand a peer a bypass with no
/// forgery required: plant a row carrying `core.coreference.share_consent`, a
/// byte-20 EdgeRef, and pact Q, then break one required field so full decode
/// fails. [`CoreferenceExportContext::claim_travels`] is the ONLY place the
/// allowed link and the exact export pact are checked, so skipping it exports
/// the raw claim verbatim — across a pact boundary, or out of an unpacted grant
/// that may carry no coreference material at all. The identical path would also
/// let a structurally impossible status (`confirmed` at `Auto`) travel.
///
/// Nothing legitimate is lost: an undecodable CLAIM is a row no reader can
/// interpret, and withholding it discloses strictly less than shipping it.
fn coreference_claim_passes(
    entity_type: u8,
    blob: &[u8],
    coreference: &CoreferenceExportContext,
) -> bool {
    if entity_type != ENTITY_TYPE_CLAIM {
        return true;
    }
    crate::claim::decode_claim_body(&blob[ENTITY_METADATA_HEADER_LEN..], true)
        .is_ok_and(|body| coreference.claim_travels(&body))
}

fn companion_register_passes_selector(blob: &[u8], grant_scope: FederationGrantScope) -> bool {
    let Ok(record) = decode_companion_record_body(&blob[ENTITY_METADATA_HEADER_LEN..]) else {
        return false;
    };
    if !matches!(
        record.lifecycle,
        ClaimLifecycleStatus::Active | ClaimLifecycleStatus::Retracted
    ) {
        return false;
    }
    match record.export_classification {
        CompanionExportClassification::LocalOnly => false,
        CompanionExportClassification::Portable => {
            !matches!(record.scope, CompanionScope::SharedVault { .. })
        }
        CompanionExportClassification::SharedVault => {
            let FederationGrantScope::Vault {
                vault_id: grant_vault_id,
            } = grant_scope;
            matches!(
                record.scope,
                CompanionScope::SharedVault { vault_id } if vault_id == grant_vault_id
            )
        }
    }
}

fn world_passes(entity_type: u8, body: &[u8], world: SyncSelectorWorld) -> bool {
    let target = match world {
        SyncSelectorWorld::All => return true,
        SyncSelectorWorld::Base => None,
        SyncSelectorWorld::World(id) => Some(id.entity_id()),
    };
    if entity_type != ENTITY_TYPE_CLAIM {
        return true;
    }
    let Ok(body) = crate::claim::decode_claim_body(body, true) else {
        return false;
    };
    match body.world {
        None => true,
        Some(claim_world) => target == Some(claim_world),
    }
}
