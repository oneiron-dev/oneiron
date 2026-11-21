//! FIX [BK-HOME-MOVE-PUBLIC-PAGE-INDEX-NOT-CARRIED] (lead ruling
//! BK-HOME-MOVE-CARRIES-BOOKINGS = A, 21 Nov 06:2x: "a move must never
//! silently strand a visitor's link"): the booking pages' publications a home
//! move carries, as one section on the home handoff carrier
//! (`crate::sync::home_handoff`). A public link resolves its page through the
//! token index first, and the publication claim the index names reaches no
//! other machine by sync: every peer refuses it at the put choke point
//! ([`super::write_index::guard_publication_put`]). So the new home of a move
//! held neither, and every public route of every page, a visitor's cancel and
//! reschedule links among them, answered "booking page" not found.
//!
//! - `booking.public_page.token:` ([`BookingPublicationRows`]): each indexed
//!   page with the publication claim its token names, and each claim id the
//!   deny-only marker protects. Ids only.
//! - Each indexed publication claim as the old home stores it travels apart
//!   ([`CarriedPublication`]), sealed under its publisher, the owner whose
//!   write it is (FIX 8875). An absent or erased claim travels as its facts
//!   alone.
//!
//! The new home lands each carried claim through the replicated put inside
//! the owner write's staging for that one id
//! ([`crate::memory::booking_publication::land_carried_publication_in_txn`]),
//! unchanged: never over a deletion this node holds, and not again when this
//! node holds the same body. Then it indexes each carried page to the carried
//! claim, over a row of its own (the old home's publication is the one the
//! visitors' links were served from), and keeps every marker, its own and the
//! carried ones (deny-only: nothing clears one). It mints no invite grant.
//! Every read-time check of a live publication stands as on the old home, so
//! an unpublished, retracted or erased page stays not public here.
//!
//! The section names no restore key: the two tables keep their restore class
//! (`[restore: refuse "public booking pages"]`).

use std::collections::BTreeMap;

use heed::{RoTxn, RwTxn};
use oneiron_records::booking::lifecycle::{entity_ref_serde, entity_refs_serde};
use serde::{Deserialize, Serialize};

use super::write_index::{
    indexed_pages_in_txn, put_carried_index_in_txn, put_carried_protection_in_txn,
};
use super::{BOOKING_PUBLIC_PAGE_PREDICATE, publication_owner};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimSubject, decode_claim_body};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EntityStoreRead, TombstoneStoreRead};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::side_table::{self, SideTableDecl};
use crate::sync::home_handoff::{
    ActorContent, HomeFence, HomeMove, HomeTable, ImageRows, Partitioned, TableAdopt,
};
use crate::temporal::TimeRange;

fn invalid(detail: &str) -> Error {
    Error::InvalidConfig(detail.to_owned())
}

/// Every indexed page and every protected claim id.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BookingPublicationRows {
    pages: Vec<CarriedPage>,
    #[serde(with = "entity_refs_serde")]
    protected: Vec<EntityId>,
}

/// One token index row: the page, and the publication claim its token names.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CarriedPage {
    #[serde(with = "entity_ref_serde")]
    page: EntityId,
    #[serde(with = "entity_ref_serde")]
    claim: EntityId,
}

/// One indexed publication claim's stored row: its header's clocks and its
/// body, the owner's words, sealed under the publisher.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CarriedPublication {
    #[serde(with = "entity_ref_serde")]
    publisher: EntityId,
    #[serde(with = "entity_ref_serde")]
    claim: EntityId,
    occurred_start: u64,
    occurred_end: u64,
    learned_at: u64,
    row_version: u64,
    body: Vec<u8>,
}

impl ActorContent for CarriedPublication {
    fn actor(&self) -> EntityId {
        self.publisher
    }
}

/// The publisher of `body` when it decodes as a publication claim of `page`.
fn publisher_of(body: &[u8], page: EntityId) -> Option<EntityId> {
    let decoded = decode_claim_body(body, true).ok()?;
    if decoded.predicate != BOOKING_PUBLIC_PAGE_PREDICATE
        || decoded.subject != ClaimSubject::Entity(page)
    {
        return None;
    }
    publication_owner(&decoded)
}

/// `claim` as this node stores it, when it is a publication of `page` with a
/// publisher. `None`: absent, erased, or no publication of the page.
fn stored_publication_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    page: EntityId,
    claim: EntityId,
) -> Result<Option<CarriedPublication>> {
    let Some(raw) = vault.store.port_entity_raw_wiped(txn, &claim)? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CLAIM || raw.len() <= ENTITY_METADATA_HEADER_LEN {
        return Ok(None);
    }
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    Ok(
        publisher_of(body, page).map(|publisher| CarriedPublication {
            publisher,
            claim,
            occurred_start: header.occurred_start,
            occurred_end: header.occurred_end,
            learned_at: header.learned_at,
            row_version: header.row_version,
            body: body.to_vec(),
        }),
    )
}

/// Lands `carried` as the old home stored it, unless this node holds a
/// deletion of the claim (never resurrected) or already holds its body.
fn land_carried_claim_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    carried: &CarriedPublication,
) -> Result<()> {
    let read: &RoTxn<'_> = txn;
    if vault
        .store
        .port_deletion_state(read, &carried.claim)?
        .deleted
    {
        return Ok(());
    }
    if vault
        .store
        .port_entity_raw_wiped(read, &carried.claim)?
        .is_some_and(|raw| raw.get(ENTITY_METADATA_HEADER_LEN..) == Some(&carried.body[..]))
    {
        return Ok(());
    }
    crate::memory::booking_publication::land_carried_publication_in_txn(
        vault,
        txn,
        carried.claim,
        |txn| {
            vault
                .batch_in()
                .put_replicated(
                    &carried.claim,
                    ENTITY_TYPE_CLAIM,
                    TimeRange {
                        start: carried.occurred_start,
                        end: carried.occurred_end,
                    },
                    carried.learned_at,
                    Some(carried.row_version),
                    &carried.body,
                )
                .apply_ingested(txn, None, None)
        },
    )
}

impl HomeTable for BookingPublicationRows {
    type Rows = Self;
    type Actor = CarriedPublication;
    const TABLE: &'static SideTableDecl = &side_table::BOOKING_PUBLIC_PAGE_TOKEN_INDEX;
    const SCHEMA_VERSION: u16 = 1;

    /// The owner's publication write indexes in its own transaction: nothing
    /// is pending.
    fn quiescent(_vault: &Vault, _txn: &RoTxn<'_>, _movement: &HomeMove) -> Result<bool> {
        Ok(true)
    }

    fn export(
        vault: &Vault,
        txn: &RoTxn<'_>,
        _fence: &HomeFence,
    ) -> Result<Partitioned<Self, CarriedPublication>> {
        let (indexed, protected) = indexed_pages_in_txn(vault, txn)?;
        let mut pages = Vec::with_capacity(indexed.len());
        let mut actors = Vec::new();
        for (page, claim) in indexed {
            if let Some(carried) = stored_publication_in_txn(vault, txn, page, claim)? {
                actors.push(carried);
            }
            pages.push(CarriedPage { page, claim });
        }
        Ok(Partitioned {
            facts: Self { pages, protected },
            actors,
        })
    }

    /// Lands the carried claims, then the index rows and the markers, as the
    /// module doc says.
    fn adopt(
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        _fence: &HomeFence,
        rows: Partitioned<Self, CarriedPublication>,
    ) -> Result<TableAdopt> {
        let indexed: BTreeMap<EntityId, EntityId> = rows
            .facts
            .pages
            .iter()
            .map(|carried| (carried.claim, carried.page))
            .collect();
        for carried in &rows.actors {
            let Some(&page) = indexed.get(&carried.claim) else {
                return Err(invalid(
                    "a carried booking publication is not the claim a carried page names",
                ));
            };
            if publisher_of(&carried.body, page) != Some(carried.publisher) {
                return Err(invalid(
                    "a carried booking publication is not its publisher's publication of its page",
                ));
            }
            land_carried_claim_in_txn(vault, txn, carried)?;
        }
        for carried in &rows.facts.pages {
            put_carried_index_in_txn(vault, txn, carried.page, carried.claim)?;
        }
        for claim in &rows.facts.protected {
            put_carried_protection_in_txn(vault, txn, *claim)?;
        }
        Ok(TableAdopt::Applied)
    }

    /// None: the two tables keep their restore class, so a restore over a
    /// live vault still refuses to roll a public page back.
    fn live_keys(_vault: &Vault, _txn: &RoTxn<'_>) -> Result<Vec<Vec<u8>>> {
        Ok(Vec::new())
    }

    /// None, as [`Self::live_keys`].
    fn manages(_vault: &Vault, _txn: &RoTxn<'_>, _image: &ImageRows) -> Result<Vec<Vec<u8>>> {
        Ok(Vec::new())
    }
}
