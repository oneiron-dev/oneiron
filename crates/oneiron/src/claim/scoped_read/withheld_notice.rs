//! A live owner's existence read of another person's notice that its
//! sources withhold from him (lead 21 Nov 06:3x on
//! [RECIPIENT-NOTICE-READ-BY-ANY-READER]: "he sees that it exists, not its
//! body"; Engine ANSWER OWNER-NOTICE-EXISTENCE Q1 = A, 21 Nov 11:25).
//!
//! `vault.get` of such a notice by id answers a withheld stub: its id, its
//! kind, its recipient and when it was created, and that its body is
//! withheld. It never carries the notice's source, subjects, actions,
//! origin or marks. The stub stands only where the notice's source floor is
//! the one gate that withholds it: the same read with that floor alone
//! waived admits the row. Every other gate (the read's filter, the
//! recipient and thread-notice rules, deletion, a legal order that keeps
//! the row from use) keeps the notice absent as before.
use super::*;
use crate::inbox::NotificationKind;
use crate::vault::ReadMode;

/// What a live owner learns of another person's notice its sources
/// withhold from him: that it exists, never its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WithheldNotice {
    /// The notice's id, the one the read named.
    pub(crate) id: EntityId,
    /// What happened, as the notice's kind names it.
    pub(crate) kind: NotificationKind,
    /// The person it is addressed to, as the notice stores them (32 hex).
    pub(crate) recipient: String,
    /// When the event happened (Unix seconds); it never moves on a mark.
    pub(crate) created_at: u64,
}

impl WithheldNotice {
    /// The stub's body as `vault.get` answers it: `id`, `kind`,
    /// `recipient`, `created_at` and `body_withheld: true`, nothing else.
    pub(crate) fn stub_body(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id.to_hex(),
            "kind": self.kind,
            "recipient": self.recipient,
            "created_at": self.created_at,
            "body_withheld": true,
        })
    }
}

impl<'v> ScopedRead<'v> {
    /// The withheld stub of the live notice `id` in `txn`, for this read's
    /// live owner, where the notice is addressed to another person and its
    /// source floor alone withholds it from him.
    ///
    /// `None` for every other read and row: a reader that is not a live
    /// owner, a row that is not a live NOTIFICATION, a notice addressed to
    /// no one or to this reader, a notice whose sources admit him (his read
    /// then serves the body, or another gate withholds it), and a notice
    /// some other gate of this read withholds as well, a legal order that
    /// keeps it from use included. The waived copy judges the row and
    /// serves nothing.
    pub(crate) fn withheld_notice_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
    ) -> Result<Option<WithheldNotice>> {
        if self.source_floor_waived || !self.actor_key.actor_is_live_owner_in(self.vault, txn)? {
            return Ok(None);
        }
        let Some(record) = self.entity_record_in(txn, &id)? else {
            return Ok(None);
        };
        let raw = record.encode();
        if EntityMetadataHeader::parse(&raw).map(|header| header.entity_type)
            != Some(crate::registry::ENTITY_TYPE_NOTIFICATION)
        {
            return Ok(None);
        }
        let body = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
        let Ok(notice) = crate::inbox::decode_notification_body(body) else {
            return Ok(None);
        };
        let Some(recipient) = notice.recipient else {
            return Ok(None);
        };
        let viewers: Vec<_> = self.actor_key.authenticated_person().into_iter().collect();
        let actor = EntityId::from_hex(self.actor_key.actor_ref()).ok();
        match EntityId::from_hex(&recipient) {
            Ok(person) if !viewers.contains(&person) && actor != Some(person) => {}
            _ => return Ok(None),
        }
        if crate::source_audience::readable_with_read_in(
            self.vault,
            &self.store_read(),
            txn,
            id,
            &raw,
            &viewers,
        )? {
            return Ok(None);
        }
        // A legal order that keeps the notice from use keeps it absent, its
        // silence included: the stub would tell what the order hides.
        if crate::store::legal_hold::use_limit_in_txn(&self.vault.store, txn, &id)?.is_some() {
            return Ok(None);
        }
        let waived = self.with_source_floor_waived()?;
        let (filter, policy) = waived.resolve_retrieval_filter_in(txn, None)?;
        let authority = waived.held_for(None);
        let (row, _) = waived.id_row_in(txn, &policy, &filter, id, ReadMode::Live, &authority)?;
        if row.is_none() {
            return Ok(None);
        }
        Ok(Some(WithheldNotice {
            id,
            kind: notice.kind,
            recipient,
            created_at: notice.created_at,
        }))
    }

    /// This read with its rows' source-audience floor waived, and otherwise
    /// the same: its key, audience, peers, session view, room ceiling,
    /// claim status and filter. Only [`Self::withheld_notice_in`] builds it,
    /// to judge a row it never serves.
    fn with_source_floor_waived(&self) -> Result<ScopedRead<'v>> {
        let room_ceiling = self
            .room_ceiling
            .lock()
            .map_err(|_| Error::InvariantViolation("room ceiling lock"))?
            .clone();
        Ok(ScopedRead {
            vault: self.vault,
            actor_key: self.actor_key.clone(),
            audience: self.audience.clone(),
            peer_reads: self.peer_reads.clone(),
            audience_cache: Mutex::new(Default::default()),
            room_ceiling: Mutex::new(room_ceiling),
            room_ceilings_built: AtomicUsize::new(0),
            session_view: self.session_view,
            stretch: self.stretch,
            claim_status: self.claim_status,
            recall_authority: Mutex::new(None),
            room_peer: self.room_peer,
            own_owner_authority: self.own_owner_authority,
            records_cover: self.records_cover.clone(),
            judged_at: self.judged_at,
            read_filter: self.read_filter.clone(),
            receipts_include_live_grants: self.receipts_include_live_grants,
            cited_support: self.cited_support,
            source_floor_waived: true,
        })
    }
}
