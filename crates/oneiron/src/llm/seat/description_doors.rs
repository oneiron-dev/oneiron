//! The owner's seat description doors (`vault.models.descriptions.set` and
//! `.read`; FIX SEAT-DESCRIPTION-ROW-NO-PUBLIC-DOOR, Engine ACCEPT
//! PLAN-SEAT-DESCRIPTION-DOOR 28 Nov 13:13). A seat is born only on a model
//! whose description row names the task's facet ([`super::SeatPool::birth`]),
//! so the row decides which model a run is born on: an owner act, behind
//! the owner's own proof, revalidated inside the write. The host's
//! `[models.decisions.seat]` names the facet its pick reads; a served door
//! reports it ([`SeatDescriptionWrite::on_host`]), and an in-process call,
//! which has no host, reports none. A row under another facet is stored all
//! the same: vault rows outlive one host's config.

use serde::{Deserialize, Serialize};

use super::{DESCRIPTIONS, ModelDescription, invalid};
use crate::consent::AuthenticatedOwner;
use crate::{ModelId, Vault, error::Result};

/// What one owner's set stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SeatDescriptionWrite {
    /// The row as stored.
    pub description: ModelDescription,
    /// The row this write replaced, as it was stored; none for a model the
    /// vault had not described.
    pub replaced: Option<ModelDescription>,
    /// The facet this host's `[models.decisions.seat]` names; none when the
    /// host binds no seat pick, or the call runs in-process.
    pub seat_facet: Option<String>,
    /// Whether the stored row's facet is `seat_facet`; none when
    /// `seat_facet` is none. False means this host's pick never reads it.
    pub host_facet_matches: Option<bool>,
}

impl SeatDescriptionWrite {
    /// This answer as the host whose seat pick reads `facet` gives it.
    #[must_use]
    pub fn on_host(mut self, facet: Option<&str>) -> Self {
        self.host_facet_matches = facet.map(|facet| facet == self.description.facet);
        self.seat_facet = facet.map(str::to_owned);
        self
    }
}

/// `vault.models.descriptions.read`: every row, or one model's.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SeatDescriptionsRead {
    #[serde(default)]
    pub model: Option<ModelId>,
}

/// The rows a read found, in key order, as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SeatDescriptionsView {
    pub rows: Vec<ModelDescription>,
    /// The facet this host's `[models.decisions.seat]` names; none when the
    /// host binds no seat pick, or the call runs in-process.
    pub seat_facet: Option<String>,
}

impl SeatDescriptionsView {
    /// This answer as the host whose seat pick reads `facet` gives it.
    #[must_use]
    pub fn on_host(mut self, facet: Option<&str>) -> Self {
        self.seat_facet = facet.map(str::to_owned);
        self
    }
}

impl Vault {
    /// `vault.models.descriptions.set` as `owner`: stores `description` as
    /// the seat description row of its model, replacing the model's row.
    /// The owner is checked again, the row passes the seat policy in force
    /// in the same write (a facet and at least one line, each within its
    /// bound), and its model is registered, all inside the write. Answers
    /// the row as stored, read back in the write (the side-row wall puts a
    /// custody handle in place of a secret a line holds), and the row it
    /// replaced; the host's facet is the caller's to add
    /// ([`SeatDescriptionWrite::on_host`]).
    ///
    /// # Errors
    ///
    /// An invalid row; a model the vault has not registered; a stale or
    /// non-owner proof; storage errors. A refusal stores nothing.
    pub fn set_model_description_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        description: ModelDescription,
    ) -> Result<SeatDescriptionWrite> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let policy = self.seat_policy_in_txn(&txn)?;
        description.validate_with(&policy)?;
        if self
            .model_registry_row_in_txn(&txn, &description.model)?
            .is_none()
        {
            return Err(invalid("model description requires a registered model"));
        }
        let key = description.model.as_str().to_owned();
        let replaced = DESCRIPTIONS.get(&self.store, &txn, &key)?;
        DESCRIPTIONS.put(self, &mut txn, &key, &description)?;
        let stored = DESCRIPTIONS
            .get(&self.store, &txn, &key)?
            .ok_or_else(|| invalid("the seat description row did not read back in its write"))?;
        txn.commit()?;
        Ok(SeatDescriptionWrite {
            description: stored,
            replaced,
            seat_facet: None,
            host_facet_matches: None,
        })
    }

    /// `vault.models.descriptions.read` as `owner`: every seat description
    /// row in key order, or `input.model`'s alone, each as stored (a row the
    /// current seat policy would refuse still reads, so the owner sees what
    /// the pick would refuse).
    ///
    /// # Errors
    ///
    /// A stale or non-owner proof; storage errors.
    pub fn model_descriptions_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: SeatDescriptionsRead,
    ) -> Result<SeatDescriptionsView> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let rows = match &input.model {
            Some(model) => DESCRIPTIONS
                .get(&self.store, &txn, &model.as_str().to_owned())?
                .into_iter()
                .collect(),
            None => DESCRIPTIONS
                .scan(&self.store, &txn)?
                .into_iter()
                .map(|(_, row)| row)
                .collect(),
        };
        Ok(SeatDescriptionsView {
            rows,
            seat_facet: None,
        })
    }
}
