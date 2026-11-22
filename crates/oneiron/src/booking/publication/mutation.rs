//! Snapshot carried by public attempts, rechecked by the lifecycle writer.
use super::*;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicBookingAuthority {
    #[serde(
        serialize_with = "serialize_page",
        deserialize_with = "deserialize_page"
    )]
    pub page_ref: EntityId,
    pub publication: BookingPagePublication,
    /// The personal link the attempt came through, by its `link_ref`
    /// (BK-PERSONAL-LINKS). Every recheck then also needs that link live, so
    /// a link ended while the attempt ran (revoked, or "not you?") stops it.
    /// `None` for a page token, and absent from such a snapshot's JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub personal_link_ref: Option<String>,
}

/// The refusal of an attempt whose personal link ended while it ran: the
/// public routes answer it as the one 404 of a dead link.
pub const PERSONAL_LINK_ENDED: &str = "personal booking link ended";

fn serialize_page<S: serde::Serializer>(
    id: &EntityId,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(&id.to_hex())
}
fn deserialize_page<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<EntityId, D::Error> {
    EntityId::from_hex(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
}

impl PublicBookingAuthority {
    /// Recheck a public snapshot in a caller-owned transaction. This only
    /// narrows authority; the snapshot itself grants no write permission.
    pub fn recheck_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        now: u64,
    ) -> std::result::Result<(), BookingError> {
        let current = load_public_booking_page_in_txn(
            vault,
            txn,
            self.page_ref,
            now.max(vault.store.clock.now_recorded_at()),
        )
        .map_err(|_| {
            BookingError::InvalidConstraint("public booking authority unavailable".to_owned())
        })?;
        if current.as_ref() != Some(&self.publication) {
            return Err(BookingError::InvalidConstraint(
                "public booking authority ended".to_owned(),
            ));
        }
        if let Some(link_ref) = &self.personal_link_ref
            && !crate::booking::personal_link::personal_link_live_in_txn(
                vault,
                txn,
                link_ref,
                self.page_ref,
            )?
        {
            return Err(BookingError::InvalidConstraint(
                PERSONAL_LINK_ENDED.to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn check_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        page: EntityId,
        event: &EventTypeKey,
        now: u64,
    ) -> std::result::Result<(), BookingError> {
        self.recheck_in_txn(vault, txn, now)?;
        if page != self.page_ref
            || !self
                .publication
                .event_types
                .iter()
                .any(|card| card.key == *event)
        {
            return Err(BookingError::InvalidConstraint(
                "public booking authority ended".to_owned(),
            ));
        }
        Ok(())
    }
}
