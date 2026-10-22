//! ROOM as one ordered stream of rows (FIX 9746, 9747): the room's roster by
//! actor id, then the rules the caller reads in it by claim id.
//!
//! Every read takes the whole room again under the caller's current read:
//! the whole roster gives the terms, every admitted rule folds into the
//! posture, and only then is a page cut, so a later restrictive rule is never
//! hidden behind an earlier page. Scope, posture, host and offers ride every
//! page whole. No count of members or rules refuses a room. The page sizes
//! pace the output and the rule scan, and a caller asking for more gets it by
//! continuing (CALLS "256-row room pages, 1000-row loop pages, continuing to
//! the end").

use super::super::paging::{BoardPageCursor, decode_page_cursor, encode_page_cursor, page_binding};
use super::super::people::PeopleView;
use super::super::room::{RoomBar, RoomMode, RoomPosture, RoomPresence, RoomSection};
use super::super::{BoardFrameError, BoardSection};
use crate::EntityId;
use crate::claim::{
    ClaimLifecycleStatus, ClaimReadStatus, PointRead, RoomTerms, ScopedRead, ScopedReadReceipt,
};
use crate::edge::EdgeKind;
use crate::memory::{ClaimView, Memory, MemoryError, MemoryResult};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CLAIM;

/// Rows one ROOM page emits, roster members and rules together.
const ROOM_PAGE_ROWS: usize = 256;

/// Rule ids one step of a room's rule scan reads; the scan steps on to the
/// end.
const ROOM_SCAN_PAGE: usize = 1000;

/// The page kind a ROOM cursor is bound to.
const ROOM_PAGE_KIND: &str = "context_board.room";

/// The cursor phase of a roster member and of a rule.
const PHASE_ROSTER: u8 = 0;
const PHASE_RULES: u8 = 1;

/// One page of a room's ROOM section.
#[derive(Debug, Clone)]
pub struct RoomSectionPage {
    /// The room's whole scope, posture, host, offers, invitees and receipt,
    /// with this page's roster members and rules.
    pub section: RoomSection,
    /// Members on the room's whole roster.
    pub roster_total: u64,
    /// Rules the caller reads in the room, on every page together.
    pub rules_total: u64,
    /// Continues the stream past this page; `None` once `end`.
    pub next_cursor: Option<String>,
    /// No row of the room is past this page.
    pub end: bool,
    /// The whole roster, which `invite?:` leaves out on every page.
    members: Vec<RoomPresence>,
}

impl RoomSectionPage {
    /// The page's ROOM board section: the room's headers, a `page:` row with
    /// the room's member and rule counts and the cursor that continues it,
    /// then this page's members and rules.
    pub fn board_section(
        &self,
        people: &PeopleView<'_>,
    ) -> std::result::Result<BoardSection, BoardFrameError> {
        let mut page = format!(
            "page: members={} rules={} end={}",
            self.roster_total, self.rules_total, self.end
        );
        if let Some(cursor) = &self.next_cursor {
            page.push_str(" next_cursor=");
            page.push_str(cursor);
        }
        self.section
            .board_section_page(people, &self.members, Some(page))
    }
}

/// Where a page starts: past this roster member, or past this rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoomPageAfter {
    Member(EntityId),
    Rule(EntityId),
}

/// The rules a room's scan admitted, with the posture all of them fold into.
struct RoomRules {
    claims: Vec<ClaimView>,
    posture: RoomPosture,
    receipt: ScopedReadReceipt,
}

impl Memory<'_> {
    /// Roster, scope, posture and rules, all read fresh and whole. No copy of
    /// the board or of posture is stored anywhere.
    pub fn rooms_render(&self, room: EntityId) -> MemoryResult<RoomSection> {
        let roster = self.room_roster(room)?;
        let terms = self.turn_terms_now(room, &roster)?;
        let scope = terms.room_scope();
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let rules = self.scan_room_rules(room, &roster, &terms, &read)?;
        let invitable = self.room_invitable(room, &read)?;
        Ok(RoomSection {
            room,
            roster,
            scope,
            posture: rules.posture,
            claims: rules.claims,
            offers: self.rooms_open_offers(room)?,
            receipt: rules.receipt,
            host: None,
            invitable,
        })
    }

    /// [`Self::rooms_render`] with the room's host read among `session`'s
    /// present participants and the caller ([`Self::rooms_host`]). A session
    /// the vault holds no SESSION row for names no present set, so the
    /// section carries no host, as it does with no session at all.
    pub fn rooms_render_hosted(
        &self,
        room: EntityId,
        session: Option<EntityId>,
    ) -> MemoryResult<RoomSection> {
        let mut section = self.rooms_render(room)?;
        if let Some(session) = session
            && self.vault().session_presence(session).is_ok()
        {
            section.host = Some(self.rooms_host(room, Some(session))?.hosting);
        }
        Ok(section)
    }

    /// One page of [`Self::rooms_render_hosted`]: up to 256 (`ROOM_PAGE_ROWS`)
    /// rows of the room's stream past `cursor`, the roster by actor id and
    /// then the rules by claim id. The whole room is read again for every
    /// page under the caller's read now; the cursor only says where the last
    /// page stopped. A cursor minted for another caller or room, or one that
    /// does not decode, is refused.
    pub fn rooms_render_page_hosted(
        &self,
        room: EntityId,
        session: Option<EntityId>,
        cursor: Option<&str>,
    ) -> MemoryResult<RoomSectionPage> {
        let binding = page_binding(ROOM_PAGE_KIND, &[self.actor().as_bytes(), room.as_bytes()]);
        let after = cursor
            .map(|token| decode_room_cursor(&binding, token).ok_or_else(invalid_room_cursor))
            .transpose()?;
        let mut section = self.rooms_render_hosted(room, session)?;
        let mut members = std::mem::take(&mut section.roster);
        members.sort_by_key(|member| member.actor);
        let mut rules = std::mem::take(&mut section.claims)
            .into_iter()
            .map(|claim| Ok((EntityId::from_hex(&claim.claim_ref)?, claim)))
            .collect::<crate::Result<Vec<_>>>()?;
        rules.sort_by_key(|(id, _)| *id);
        let roster_from = match after {
            None => 0,
            Some(RoomPageAfter::Member(last)) => {
                members.partition_point(|member| member.actor <= last)
            }
            Some(RoomPageAfter::Rule(_)) => members.len(),
        };
        let rules_from = match after {
            Some(RoomPageAfter::Rule(last)) => rules.partition_point(|(id, _)| *id <= last),
            _ => 0,
        };
        let roster_to = roster_from + (members.len() - roster_from).min(ROOM_PAGE_ROWS);
        let left = ROOM_PAGE_ROWS - (roster_to - roster_from);
        let rules_to = rules_from + (rules.len() - rules_from).min(left);
        let end = roster_to == members.len() && rules_to == rules.len();
        let last = if rules_to > rules_from {
            Some(RoomPageAfter::Rule(rules[rules_to - 1].0))
        } else if roster_to > roster_from {
            Some(RoomPageAfter::Member(members[roster_to - 1].actor))
        } else {
            after
        };
        let next_cursor = last
            .filter(|_| !end)
            .map(|last| encode_room_cursor(&binding, last));
        let roster_total = u64::try_from(members.len()).unwrap_or(u64::MAX);
        let rules_total = u64::try_from(rules.len()).unwrap_or(u64::MAX);
        section.roster = members[roster_from..roster_to].to_vec();
        section.claims = rules
            .drain(rules_from..rules_to)
            .map(|(_, claim)| claim)
            .collect();
        Ok(RoomSectionPage {
            section,
            roster_total,
            rules_total,
            next_cursor,
            end,
            members,
        })
    }

    /// Every active rule of `room` the caller reads, in `ROOM_SCAN_PAGE`-id
    /// steps to the end, with the posture they all fold into. A rule is the
    /// caller's when its read admits it, its world is in the room's terms,
    /// every present peer reads it too and the room discloses it; a rule the
    /// caller reads but a peer or the room withholds is counted as withheld.
    fn scan_room_rules(
        &self,
        room: EntityId,
        roster: &[RoomPresence],
        terms: &RoomTerms,
        read: &ScopedRead<'_>,
    ) -> MemoryResult<RoomRules> {
        // Each rule must also pass every present peer's ordinary read.
        let present: Vec<_> = roster
            .iter()
            .filter(|member| member.present)
            .map(|member| member.actor)
            .collect();
        let peers: Vec<_> = self
            .peer_read_keys(&present)?
            .into_iter()
            .map(|key| self.vault().scoped_read(key))
            .collect();
        let listing = self.read_lane(ClaimReadStatus::Recorded)?;
        let mut receipt = None;
        let mut suppressed = 0;
        let mut claims = Vec::new();
        let mut posture = RoomPosture::default();
        let mut has_bar = false;
        let mut after = None;
        loop {
            let page = self.vault().sources_page(
                &room,
                EdgeKind::ClaimOf,
                Some(ENTITY_TYPE_CLAIM),
                after.as_ref(),
                ROOM_SCAN_PAGE,
            )?;
            let listed = self.active_room_rules(&listing, &page.ids, &mut receipt)?;
            let reads = listed
                .iter()
                .map(|claim| EntityId::from_hex(&claim.claim_ref).map(PointRead::id))
                .collect::<crate::Result<Vec<_>>>()?;
            if !reads.is_empty() {
                let own = read.read(&reads, None)?;
                fold_receipt(&mut receipt, own.receipt);
                let peer_rows = peers
                    .iter()
                    .map(|peer| Ok(peer.read(&reads, None)?.value))
                    .collect::<MemoryResult<Vec<_>>>()?;
                for (index, claim) in listed.into_iter().enumerate() {
                    let world = claim
                        .world_ref
                        .as_deref()
                        .map(EntityId::from_hex)
                        .transpose()?
                        .unwrap_or_else(crate::claim::base_world_id);
                    if own.value[index].is_none()
                        || !terms
                            .worlds
                            .worlds
                            .contains(&crate::federation::ScopeId(world))
                    {
                        continue;
                    }
                    // A clearance in the meet holds each rule to P7 as well.
                    if peer_rows.iter().any(|rows| rows[index].is_none())
                        || !self.room_discloses(
                            room,
                            terms,
                            &present,
                            EntityId::from_hex(&claim.claim_ref)?,
                        )?
                    {
                        suppressed += 1;
                        continue;
                    }
                    fold_room_posture(&mut posture, &mut has_bar, &claim)?;
                    claims.push(claim);
                }
            }
            after = page.resume_after;
            if after.is_none() {
                break;
            }
        }
        claims.sort_by(|a, b| a.claim_ref.cmp(&b.claim_ref));
        let mut receipt = match receipt {
            Some(receipt) => receipt,
            None => {
                let mut receipt = listing.read_receipt(None, 0)?;
                receipt.restrict_with(&read.read_receipt(None, 0)?);
                receipt
            }
        };
        if suppressed > 0 {
            receipt.add_suppressed(suppressed);
        }
        Ok(RoomRules {
            claims,
            posture,
            receipt,
        })
    }

    /// The active rules among `ids` that `listing` admits, read from their
    /// admitted bodies, its receipt folded into `receipt`.
    fn active_room_rules(
        &self,
        listing: &ScopedRead<'_>,
        ids: &[EntityId],
        receipt: &mut Option<ScopedReadReceipt>,
    ) -> MemoryResult<Vec<ClaimView>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let reads: Vec<_> = ids.iter().copied().map(PointRead::id).collect();
        let listed = listing.read(&reads, None)?;
        fold_receipt(receipt, listed.receipt);
        let mut rules = Vec::new();
        for row in listed.value.into_iter().flatten() {
            let Some(bytes) = row.body.as_deref() else {
                continue;
            };
            let body = crate::claim::decode_claim_body(bytes, true)?;
            if body.lifecycle != ClaimLifecycleStatus::Active {
                continue;
            }
            rules.push(self.served_claim_view(&row.id, &body)?);
        }
        Ok(rules)
    }

    /// FIX 1163: whom this reader may bring in by a roster write it could
    /// sign, among the PERSONs it reads; in an ordinary room, by the
    /// invitation it may file there (OF-529).
    fn room_invitable(
        &self,
        room: EntityId,
        read: &ScopedRead<'_>,
    ) -> MemoryResult<std::collections::BTreeSet<EntityId>> {
        let mut invitable = std::collections::BTreeSet::new();
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let reader = crate::WriteActor::new(self.actor(), self.actor_class());
        if crate::workspace_roster::files_roster_joins_in_txn(vault, &txn, room, reader)?
            || crate::workspace_roster::invites_into_room_in_txn(vault, &txn, room, reader)?
        {
            let persons = vault
                .store
                .port_entity_ids_by_type(&txn, crate::registry::ENTITY_TYPE_PERSON, None)?
                .collect::<crate::Result<Vec<_>>>()?;
            let readable = read.entities_readable_in_txn(&txn, &persons)?;
            for (person, readable) in persons.into_iter().zip(readable) {
                if readable
                    && crate::workspace_roster::roster_invitee_in_txn(vault, &txn, room, person)?
                {
                    invitable.insert(person);
                }
            }
        }
        Ok(invitable)
    }
}

/// Folds one admitted room rule into `posture`: the strictest mode, and the
/// highest bar of those that set one.
fn fold_room_posture(
    posture: &mut RoomPosture,
    has_bar: &mut bool,
    claim: &ClaimView,
) -> MemoryResult<()> {
    match (claim.predicate.as_str(), claim.value.as_str()) {
        ("room.posture.mode", Some(mode)) => {
            posture.mode = posture.mode.max(match mode {
                "chime" => RoomMode::Chime,
                "asked_only" => RoomMode::AskedOnly,
                "silent" => RoomMode::Silent,
                _ => {
                    return Err(MemoryError::bad_request_with(
                        "invalid room posture mode",
                        &[],
                    ));
                }
            });
        }
        ("room.posture.bar", Some(bar)) => {
            let bar = match bar {
                "low" => RoomBar::Low,
                "med" => RoomBar::Med,
                "high" => RoomBar::High,
                _ => {
                    return Err(MemoryError::bad_request_with(
                        "invalid room posture bar",
                        &[],
                    ));
                }
            };
            posture.bar = if *has_bar { posture.bar.max(bar) } else { bar };
            *has_bar = true;
        }
        _ => {}
    }
    Ok(())
}

/// Folds a later read's receipt into the scan's: the first one taken, each
/// later one restricting it.
fn fold_receipt(receipt: &mut Option<ScopedReadReceipt>, later: ScopedReadReceipt) {
    match receipt {
        Some(receipt) => receipt.restrict_with(&later),
        None => *receipt = Some(later),
    }
}

/// The page a ROOM cursor names, when it was minted under `binding`.
fn decode_room_cursor(binding: &[u8; 32], token: &str) -> Option<RoomPageAfter> {
    let cursor = decode_page_cursor(binding, token)?;
    let (&phase, key) = cursor.after.split_first()?;
    let key = EntityId::from_bytes(<[u8; 16]>::try_from(key).ok()?).ok()?;
    match phase {
        PHASE_ROSTER => Some(RoomPageAfter::Member(key)),
        PHASE_RULES => Some(RoomPageAfter::Rule(key)),
        _ => None,
    }
}

/// The cursor that continues a ROOM stream past `after`.
fn encode_room_cursor(binding: &[u8; 32], after: RoomPageAfter) -> String {
    let (phase, key) = match after {
        RoomPageAfter::Member(key) => (PHASE_ROSTER, key),
        RoomPageAfter::Rule(key) => (PHASE_RULES, key),
    };
    let mut bytes = Vec::with_capacity(17);
    bytes.push(phase);
    bytes.extend_from_slice(key.as_bytes());
    encode_page_cursor(
        binding,
        &BoardPageCursor {
            fence: None,
            after: bytes,
        },
    )
}

/// A ROOM cursor minted for another caller or room, or one that does not
/// decode.
fn invalid_room_cursor() -> MemoryError {
    MemoryError::bad_request_with("invalid room page cursor", &[])
}
