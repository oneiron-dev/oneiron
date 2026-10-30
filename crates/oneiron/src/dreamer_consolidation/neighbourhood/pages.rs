//! A child's listing in stable pages (Rule 5, FIX 7580). The listing is
//! whole: no entity, head or relationship is left out for room. It is cut
//! into pages in its own order (a nightly child's thing first, then each
//! entity as its passage names it, each with its heads newest first), so the
//! thing's entity always opens the first page and the same listing always
//! pages the same way. A child slice is cut per slice line and mention set
//! (FIX 8724), so each line pages its own whole neighbourhood (FIX 9347).
//! An entity whose heads run past a page opens the next page again with its
//! own line, so every head is read beside its entity.

use super::render::{claim_line_bytes, entity_line_bytes};
use super::{KnownClaim, KnownEntity, Neighbourhood};
use crate::EntityId;

/// A page's room: the byte budget the whole listing had before it was
/// paged, each line measured at its width with full ids. It splits, never
/// caps: every entry lands in some page, and a line wider than a page has a
/// page of its own.
const PAGE_BYTES: usize = 4 * 1024;

/// One page of a listing: entities in listing order, each with the run of
/// its heads this page holds.
#[derive(Debug, Default)]
pub(in crate::dreamer_consolidation) struct ListingPage<'n> {
    entities: Vec<(&'n KnownEntity, Vec<&'n KnownClaim>)>,
}

impl<'n> ListingPage<'n> {
    /// Whether the page shows `claim`.
    pub(in crate::dreamer_consolidation) fn shows(&self, claim: EntityId) -> bool {
        self.claims().any(|known| known.id == claim)
    }

    /// The page's entities, each with the heads it shows of it.
    pub(super) fn entities(&self) -> &[(&'n KnownEntity, Vec<&'n KnownClaim>)] {
        &self.entities
    }

    /// The relationships the page's heads hold within, in page order.
    pub(super) fn relationships(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.claims()
            .flat_map(|claim| claim.rel.iter().flatten().copied())
    }

    fn claims(&self) -> impl Iterator<Item = &'n KnownClaim> + '_ {
        self.entities
            .iter()
            .flat_map(|(_, claims)| claims.iter().copied())
    }

    /// Whether the page holds only its last entity's own line, so a head
    /// that does not fit still belongs on it.
    fn only_an_entity_line(&self) -> bool {
        matches!(self.entities.as_slice(), [(_, claims)] if claims.is_empty())
    }
}

impl Neighbourhood {
    /// The listing in pages, each head only while `admitted` holds it as a
    /// prior head. A listing with nothing in it is one empty page, so its
    /// child still makes its one call.
    pub(in crate::dreamer_consolidation) fn pages(
        &self,
        admitted: impl Fn(&EntityId) -> bool,
    ) -> Vec<ListingPage<'_>> {
        let mut pages = Vec::new();
        let mut page = ListingPage::default();
        let mut bytes = 0;
        for entity in &self.entities {
            let head = entity_line_bytes(entity.id, entity.label.as_deref());
            if !page.entities.is_empty() && bytes + head > PAGE_BYTES {
                pages.push(std::mem::take(&mut page));
                bytes = 0;
            }
            page.entities.push((entity, Vec::new()));
            bytes += head;
            for claim in entity.claims.iter().filter(|claim| admitted(&claim.id)) {
                let line = claim_line_bytes(claim);
                if bytes + line > PAGE_BYTES && !page.only_an_entity_line() {
                    pages.push(std::mem::take(&mut page));
                    page.entities.push((entity, Vec::new()));
                    bytes = head;
                }
                if let Some((_, claims)) = page.entities.last_mut() {
                    claims.push(claim);
                }
                bytes += line;
            }
        }
        if !page.entities.is_empty() || pages.is_empty() {
            pages.push(page);
        }
        pages
    }
}
