//! Canonical contact value reads with caller-bound memory custody.

use super::codec::{
    CounterpartyContactScalarHeads, decode_counterparty_contact_fields_borrowed, invalid_contact,
    validate_counterparty,
};
use super::types::{
    COUNTERPARTY_CONTACT_CLAIM_PREDICATES, COUNTERPARTY_CONTACT_SCHEMA_VERSION, KEY_COUNTERPARTY,
    KEY_NOTES, KEY_SCHEMA_VERSION,
};
use crate::Vault;
use crate::counterparty_contact::{
    CounterpartyContactRecord, CounterpartyContactStatus, CounterpartyFirstTouch,
    CounterpartyOptOut,
};
use crate::entity_id::EntityId;
pub(super) use crate::write_envelope::claim_body::ClaimValueHead as ContactClaim;
use crate::write_envelope::claim_body::{
    ClaimBodyReadError, ClaimScopeReadMemory, ClaimStringRead, ClaimValueRead,
};

/// Copy-only contact state; string and note backing remains with its reader.
#[derive(Clone, Copy)]
pub struct CounterpartyContactState {
    pub identity_ref: EntityId,
    pub first_touch: CounterpartyFirstTouch,
    pub status: CounterpartyContactStatus,
    pub created_at: u64,
    pub updated_at: u64,
    pub revoked_at: Option<u64>,
    pub opt_out: Option<CounterpartyOptOut>,
    pub promo_consent: bool,
}

impl CounterpartyContactState {
    pub(super) fn from_record(record: &CounterpartyContactRecord) -> Self {
        Self {
            identity_ref: record.identity_ref,
            first_touch: record.first_touch,
            status: record.status,
            created_at: record.created_at,
            updated_at: record.updated_at,
            revoked_at: record.revoked_at,
            opt_out: record.opt_out,
            promo_consent: record.promo_consent,
        }
    }

    pub(super) fn validate(&self, counterparty: &str) -> crate::Result<()> {
        validate_counterparty(counterparty)?;
        if self.updated_at < self.created_at {
            return Err(invalid_contact());
        }
        match (self.status, self.revoked_at) {
            (CounterpartyContactStatus::Active, None) => {}
            (CounterpartyContactStatus::Active, Some(_)) => return Err(invalid_contact()),
            (CounterpartyContactStatus::Revoked, Some(revoked_at))
                if revoked_at >= self.created_at && self.updated_at >= revoked_at => {}
            (CounterpartyContactStatus::Revoked, Some(_))
            | (CounterpartyContactStatus::Revoked, None) => return Err(invalid_contact()),
        }
        if let Some(opt_out) = self.opt_out
            && (opt_out.recorded_at < self.created_at || self.updated_at < opt_out.recorded_at)
        {
            return Err(invalid_contact());
        }
        Ok(())
    }
}

/// An immutable contact read whose original string and note backing keeps its
/// canonical value guards. Borrowed access does not materialize a typed notes vector.
pub struct CounterpartyContactRead {
    counterparty: ClaimStringRead,
    notes: ClaimValueRead,
    pub(super) state: CounterpartyContactState,
}

impl CounterpartyContactRead {
    pub(super) fn from_heads(
        heads: [Option<ClaimValueRead>; COUNTERPARTY_CONTACT_CLAIM_PREDICATES.len()],
    ) -> crate::Result<Self> {
        let schema_version = rmpv::Value::from(COUNTERPARTY_CONTACT_SCHEMA_VERSION);
        let fields = decode_counterparty_contact_fields_borrowed(|key| {
            if key == KEY_SCHEMA_VERSION {
                return Ok(&schema_version);
            }
            COUNTERPARTY_CONTACT_CLAIM_PREDICATES
                .iter()
                .position(|predicate| super::codec::counterparty_contact_body_key(predicate) == key)
                .and_then(|index| heads[index].as_ref())
                .map(|value| &**value)
                .ok_or_else(invalid_contact)
        })?;
        let state = fields.state;
        Ok(Self::from_validated_heads(heads, state))
    }

    pub(super) fn from_staged_heads(
        heads: [Option<ClaimValueRead>; COUNTERPARTY_CONTACT_CLAIM_PREDICATES.len()],
        scalars: CounterpartyContactScalarHeads,
    ) -> crate::Result<Self> {
        let fields = scalars.decode_fields(|key| {
            COUNTERPARTY_CONTACT_CLAIM_PREDICATES
                .iter()
                .position(|predicate| super::codec::counterparty_contact_body_key(predicate) == key)
                .and_then(|index| heads[index].as_ref())
                .map(|value| &**value)
                .ok_or_else(invalid_contact)
        })?;
        let state = fields.state;
        Ok(Self::from_validated_heads(heads, state))
    }

    fn from_validated_heads(
        mut heads: [Option<ClaimValueRead>; COUNTERPARTY_CONTACT_CLAIM_PREDICATES.len()],
        state: CounterpartyContactState,
    ) -> Self {
        let index = |key| {
            COUNTERPARTY_CONTACT_CLAIM_PREDICATES
                .iter()
                .position(|predicate| super::codec::counterparty_contact_body_key(predicate) == key)
                .expect("contact field has a canonical predicate")
        };
        Self {
            counterparty: heads[index(KEY_COUNTERPARTY)]
                .take()
                .expect("validated contact head")
                .try_into_string()
                .unwrap_or_else(|_| unreachable!("validated contact counterparty")),
            notes: heads[index(KEY_NOTES)]
                .take()
                .expect("validated contact head"),
            state,
        }
    }

    pub(crate) fn into_counterparty_value(self) -> ClaimValueRead {
        self.counterparty.into_value()
    }

    pub(super) fn into_unbound_record(self) -> CounterpartyContactRecord {
        assert!(
            !self.counterparty.is_memory_bound() && !self.notes.is_memory_bound(),
            "only an unbound contact read can materialize an unguarded record"
        );
        CounterpartyContactRecord {
            identity_ref: self.state.identity_ref,
            counterparty: self
                .counterparty
                .try_into_unbound_string()
                .unwrap_or_else(|_| unreachable!("unbound contact counterparty")),
            first_touch: self.state.first_touch,
            status: self.state.status,
            created_at: self.state.created_at,
            updated_at: self.state.updated_at,
            revoked_at: self.state.revoked_at,
            opt_out: self.state.opt_out,
            promo_consent: self.state.promo_consent,
            notes: self
                .notes
                .as_array()
                .expect("validated contact notes")
                .iter()
                .map(|note| note.as_str().expect("validated contact note").to_owned())
                .collect(),
        }
    }

    pub(super) fn fold_fields(&mut self) -> (&str, &mut CounterpartyContactState) {
        (&self.counterparty, &mut self.state)
    }

    pub fn identity_ref(&self) -> EntityId {
        self.state.identity_ref
    }
    pub fn counterparty(&self) -> &str {
        &self.counterparty
    }
    pub fn first_touch(&self) -> CounterpartyFirstTouch {
        self.state.first_touch
    }
    pub fn status(&self) -> CounterpartyContactStatus {
        self.state.status
    }
    pub fn created_at(&self) -> u64 {
        self.state.created_at
    }
    pub fn updated_at(&self) -> u64 {
        self.state.updated_at
    }
    pub fn revoked_at(&self) -> Option<u64> {
        self.state.revoked_at
    }
    pub fn opt_out(&self) -> Option<CounterpartyOptOut> {
        self.state.opt_out
    }
    pub fn promo_consent(&self) -> bool {
        self.state.promo_consent
    }
    pub fn notes(&self) -> impl ExactSizeIterator<Item = &str> {
        self.notes
            .as_array()
            .expect("validated contact notes")
            .iter()
            .map(|note| note.as_str().expect("validated contact note"))
    }

    /// Original backing still retained by this read, including array slot capacity.
    pub fn retained_bytes(&self) -> u64 {
        self.counterparty
            .retained_bytes()
            .saturating_add(self.notes.retained_bytes())
    }
}

/// Only the validated fields used by contact existence and interlocutor reads.
pub(crate) struct CounterpartyContactLabelRead {
    counterparty: ClaimStringRead,
    state: CounterpartyContactState,
}

impl CounterpartyContactLabelRead {
    pub(super) fn from_staged_head(
        counterparty: ClaimValueRead,
        scalars: CounterpartyContactScalarHeads,
        notes_validation: crate::Result<()>,
    ) -> crate::Result<Self> {
        let state = scalars.decode_label_state(&counterparty, notes_validation)?;
        Ok(Self {
            counterparty: counterparty
                .try_into_string()
                .unwrap_or_else(|_| unreachable!("validated contact counterparty")),
            state,
        })
    }

    pub(super) fn fold_fields(&mut self) -> (&str, &mut CounterpartyContactState) {
        (&self.counterparty, &mut self.state)
    }

    pub(crate) fn status(&self) -> CounterpartyContactStatus {
        self.state.status
    }

    pub(crate) fn first_touch(&self) -> CounterpartyFirstTouch {
        self.state.first_touch
    }

    pub(crate) fn into_counterparty_value(self) -> ClaimValueRead {
        self.counterparty.into_value()
    }
}

impl Vault {
    /// Answers contact existence after full canonical validation and opt-out folding.
    pub fn has_counterparty_contact_with_memory(
        &self,
        id: &EntityId,
        memory: ClaimScopeReadMemory<'_>,
    ) -> std::result::Result<bool, ClaimBodyReadError> {
        let rtxn = self.store.env.read_txn().map_err(crate::Error::from)?;
        self.get_counterparty_contact_label_with_memory_in_txn(&rtxn, id, Some(memory))
            .map(|record| record.is_some())
    }

    /// Retains canonical head values on the supplied line without materializing
    /// unused relationship sets or copying the returned strings and notes.
    pub fn get_counterparty_contact_with_memory(
        &self,
        id: &EntityId,
        memory: ClaimScopeReadMemory<'_>,
    ) -> std::result::Result<Option<CounterpartyContactRead>, ClaimBodyReadError> {
        let rtxn = self.store.env.read_txn().map_err(crate::Error::from)?;
        self.get_counterparty_contact_with_memory_in_txn(&rtxn, id, Some(memory))
    }
}
