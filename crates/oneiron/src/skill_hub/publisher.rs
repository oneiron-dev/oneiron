//! A publisher is a foreign actor with an owner-minted, revocable offer-only grant.
use super::package_codec::invalid;
use super::{SkillHubRecord, decode_skill_hub_record};
use crate::{
    Vault,
    consent::{ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, GrantBound},
    entity_id::EntityId,
    error::{Error, Result},
};

/// A host-identified foreign publisher. No keys, bearer tokens, or authority to activate.
/// Only the authenticated admission door constructs it; its grant is rechecked at use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignSkillPublisher {
    pub(super) identity: String,
    pub(super) hub: EntityId,
    pub(super) grant_ref: String,
}
impl ForeignSkillPublisher {
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }
    #[must_use]
    pub fn grant_ref(&self) -> &str {
        &self.grant_ref
    }
}
impl Vault {
    /// Registers or revises a configured hub on an authenticated owner decision.
    /// A source grants no activation permission. The immutable ask binds this full
    /// row, so changing endpoint or trust invalidates an in-flight install ask.
    pub fn configure_skill_hub(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        record: &SkillHubRecord,
        occurred: crate::temporal::TimeRange,
        learned_at: u64,
    ) -> Result<crate::consent::ConsentReceipt> {
        match record.kind {
            super::SkillHubKind::HttpIndex => {
                super::http_fetch::checked_url(&record.endpoint)?;
            }
            super::SkillHubKind::Git if !std::path::Path::new(&record.endpoint).is_absolute() => {
                super::http_fetch::checked_url(&record.endpoint)?;
            }
            super::SkillHubKind::LocalDir
                if !std::path::Path::new(&record.endpoint).is_absolute() =>
            {
                return Err(invalid(
                    "local hub requires an absolute host-configured path",
                ));
            }
            _ => {}
        }
        let data = super::encode_skill_hub_record(record)?;
        let binding = blake3::hash(&data).to_hex();
        let effect = crate::consent::ComposedEffect::new(crate::consent::EffectFacts::new(
            format!("skill.hub.configure:{}:{binding}:{learned_at}", id.to_hex()),
        )?)
        .digest();
        self.with_write_txn(|txn| {
            let receipt = self.approve_once_in_txn(txn, owner, effect)?;
            let authorization =
                crate::consent::approve_once_authorization_in_txn(&self.store, txn, &effect)?
                    .ok_or_else(|| invalid("hub configuration consent missing"))?;
            crate::batch::apply_ops(
                &self.store,
                &self.config,
                &self.analyzer,
                txn,
                vec![crate::batch::BatchOp::Put {
                    id: *id,
                    entity_type: crate::registry::ENTITY_TYPE_SKILL_HUB,
                    occurred,
                    learned_at,
                    data: data.clone(),
                    allow_maintenance: true,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                }],
                self.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                false,
                true,
            )?;
            crate::consent::spend_approve_once_in_txn(&self.store, txn, &authorization)?;
            Ok(receipt)
        })
    }

    /// Admits an external publisher to offer candidates from one configured hub.
    /// This grant never covers install, activation, arbitrary tools, or reading vault data.
    pub fn admit_skill_publisher(
        &self,
        owner: &AuthenticatedOwner,
        identity: &str,
        hub: EntityId,
    ) -> Result<ForeignSkillPublisher> {
        let txn = self.store.env.read_txn()?;
        self.hub_record_in_txn(&txn, &hub)?;
        drop(txn);
        let actor = ActorBound::new(identity)?.with_actor_class("foreign-publisher")?;
        let bound = GrantBound::action(
            actor,
            ActionClass::new("skill.offer")?,
            ActionEnvelope::new([format!("hub:{}", hub.to_hex())])?,
        )?;
        let grant_ref = bound.digest().to_hex();
        self.create_standing_grant(owner, bound)?;
        Ok(ForeignSkillPublisher {
            identity: identity.to_owned(),
            hub,
            grant_ref,
        })
    }
    pub(super) fn check_publisher_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        publisher: &ForeignSkillPublisher,
    ) -> Result<()> {
        if !crate::consent::standing_grant_is_active_in_txn(&self.store, txn, &publisher.grant_ref)?
        {
            return Err(invalid(
                "publisher is not admitted or its grant was revoked",
            ));
        }
        self.hub_record_in_txn(txn, &publisher.hub)?;
        Ok(())
    }
    pub(super) fn hub_record_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        hub: &EntityId,
    ) -> Result<SkillHubRecord> {
        let raw = self
            .store
            .entities
            .get(txn, hub.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_SKILL_HUB {
            return Err(invalid("hub id is not a SKILL_HUB"));
        }
        decode_skill_hub_record(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
    }
}
