//! The recipient conjunct of a scoped read (FIX
//! RECIPIENT-NOTICE-READ-BY-ANY-READER, Engine TASK 21 Nov 06:27): a
//! NOTIFICATION addressed to one person reads only to that person, to the
//! owner's read, and to the one agent read FIX 5778 lets acknowledge an
//! owner's weave due notice. The inbox list keeps a caller to the notices
//! delivered to it; this holds a read of a notice by id (`vault.get`) to the
//! same audience, whichever producer wrote it.

use super::*;
use crate::edge::EdgeActorClass;

impl ScopedRead<'_> {
    /// Whether the revision `raw` of `id` reads to this read, `viewers`
    /// being the person it authenticates, as far as a notice's recipient
    /// decides. A NOTIFICATION naming a recipient reads only to:
    /// - that recipient, as the person this read authenticates or as its own
    ///   actor (an agent reads the notices addressed to it);
    /// - the owner's read ([`ScopedReadActorKey::actor_is_live_owner_in`]),
    ///   kept as it was until the owner's read of a member's notice follows
    ///   the notice's sources (lead, 21 Nov 06:3x);
    /// - an agent that one live Grant of the owner the notice is addressed to
    ///   covers to acknowledge it ([`Self::delegated_owner_notice_ack_in`],
    ///   FIX 5778): the mark door reads the notice it acknowledges, in its
    ///   admission and again in its writer.
    ///
    /// A recipient that names no entity reads to the owner's read alone. A
    /// thread notice keeps its own rule ([`Self::thread_notice_readable_in`]),
    /// and a notice addressed to no one, one whose body does not decode and
    /// every other row are `true` here.
    pub(in crate::claim::scoped_read) fn notice_recipient_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
        viewers: &[EntityId],
    ) -> Result<bool> {
        if EntityMetadataHeader::parse(raw).map(|header| header.entity_type)
            != Some(crate::registry::ENTITY_TYPE_NOTIFICATION)
        {
            return Ok(true);
        }
        let body = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
        let Ok(notice) = crate::inbox::decode_notification_body(body) else {
            return Ok(true);
        };
        if notice.source.producer == crate::store::conversation_body::THREAD_NOTICE_PRODUCER {
            return Ok(true);
        }
        let Some(recipient) = notice.recipient.as_deref() else {
            return Ok(true);
        };
        let recipient = EntityId::from_hex(recipient).ok();
        let actor = EntityId::from_hex(self.actor_key.actor_ref()).ok();
        if recipient
            .is_some_and(|recipient| viewers.contains(&recipient) || actor == Some(recipient))
        {
            return Ok(true);
        }
        if self.actor_key.actor_is_live_owner_in(self.vault, txn)? {
            return Ok(true);
        }
        let agent_class = [EdgeActorClass::Agent, EdgeActorClass::System]
            .into_iter()
            .find(|class| self.actor_key.actor_class() == Some(class.gate_actor_class()));
        Ok(match (actor, agent_class) {
            (Some(actor), Some(class)) => {
                self.delegated_owner_notice_ack_in(txn, actor, class, *id)
            }
            _ => false,
        })
    }
}
