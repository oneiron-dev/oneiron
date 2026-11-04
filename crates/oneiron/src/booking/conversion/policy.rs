//! Resolved BK-07 conversion choices, never booking authority.
//!
//! A vault row caps nested choices. The default precedence narrows nested
//! rows, then lets an explicit holder row override those choices only inside
//! the vault cap. Counts and notification content live in policy, not UX code.

use serde::{Deserialize, Serialize};

use super::ux::ReminderAction;
use crate::booking::BookingError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BookingPolicyPrecedence {
    NestedNarrowing,
    HolderOverrideCappedAtVault,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingConversionPolicy {
    pub max_visible_slots: usize,
    pub max_preconfirm_fields: usize,
    pub max_total_fields: usize,
    pub max_snippet_times: usize,
    pub repeat_no_show_at: usize,
    /// Descending offsets, one per wake; empty suppresses the ladder.
    pub reminder_leads_secs: Vec<u64>,
    pub reminder_action: ReminderAction,
    pub precedence: BookingPolicyPrecedence,
}

impl Default for BookingConversionPolicy {
    fn default() -> Self {
        Self {
            max_visible_slots: 5,
            max_preconfirm_fields: 3,
            max_total_fields: 16,
            max_snippet_times: 2,
            repeat_no_show_at: 2,
            reminder_leads_secs: vec![86_400, 7_200],
            reminder_action: ReminderAction::RescheduleFirst,
            precedence: BookingPolicyPrecedence::HolderOverrideCappedAtVault,
        }
    }
}

impl BookingConversionPolicy {
    /// Structural shape only: non-zero counts and a well-formed wake
    /// schedule. Every count the owner chooses is served; none has a
    /// compiled ceiling.
    pub fn validate(&self) -> Result<(), BookingError> {
        if self.max_visible_slots == 0
            || self.max_snippet_times == 0
            || self.repeat_no_show_at == 0
            || self
                .reminder_leads_secs
                .iter()
                .any(|lead| *lead == 0 || *lead > 366 * 86_400)
            || !self
                .reminder_leads_secs
                .windows(2)
                .all(|pair| pair[0] > pair[1])
        {
            return Err(BookingError::InvalidConfig(
                "malformed booking conversion policy".to_owned(),
            ));
        }
        Ok(())
    }

    /// Clamp holder/nested choices to the vault's resolved ceiling. A nested
    /// row only narrows; a holder row may replace that nested choice but not
    /// exceed the vault's ceilings or re-add a lead the vault removed.
    fn narrow(&self, row: &Self) -> Self {
        Self {
            max_visible_slots: self.max_visible_slots.min(row.max_visible_slots),
            max_preconfirm_fields: self.max_preconfirm_fields.min(row.max_preconfirm_fields),
            max_total_fields: self.max_total_fields.min(row.max_total_fields),
            max_snippet_times: self.max_snippet_times.min(row.max_snippet_times),
            repeat_no_show_at: self.repeat_no_show_at.min(row.repeat_no_show_at),
            reminder_leads_secs: row
                .reminder_leads_secs
                .iter()
                .copied()
                .filter(|lead| self.reminder_leads_secs.contains(lead))
                .collect(),
            reminder_action: if self.reminder_action == ReminderAction::Neutral
                || row.reminder_action == ReminderAction::Neutral
            {
                ReminderAction::Neutral
            } else {
                ReminderAction::RescheduleFirst
            },
            precedence: self.precedence,
        }
    }

    /// Two authored vault rows' shared constraints: each holder's choice
    /// binds, whichever row is read first. Holder override survives only
    /// when both rows allow it.
    fn intersect(&self, other: &Self) -> Self {
        let mut both = self.narrow(other);
        if other.precedence == BookingPolicyPrecedence::NestedNarrowing {
            both.precedence = BookingPolicyPrecedence::NestedNarrowing;
        }
        both
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BookingPolicyScope {
    Vault,
    Nested,
    Holder,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingConversionPolicyRow {
    pub scope: BookingPolicyScope,
    pub holder_ref: Option<String>,
    pub policy: BookingConversionPolicy,
}

impl BookingConversionPolicyRow {
    pub fn validate(&self) -> Result<(), BookingError> {
        self.policy.validate()?;
        match (self.scope, self.holder_ref.as_deref()) {
            (BookingPolicyScope::Holder, Some(holder))
                if holder.len() == 32
                    && holder
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) =>
            {
                Ok(())
            }
            (BookingPolicyScope::Vault | BookingPolicyScope::Nested, None) => Ok(()),
            _ => Err(BookingError::InvalidConfig(
                "booking policy row scope is invalid".to_owned(),
            )),
        }
    }
}

/// Fold trusted manifest rows. The shipped vault row is a DEFAULT, not a
/// permanent product-choice ceiling: an explicitly authored vault row
/// replaces it. Differing authored vault rows resolve to their stricter
/// intersection, so no writer's choice is silently dropped. Nested rows
/// narrow one another; a matching holder may override nested values only
/// inside the vault cap.
pub fn resolve_booking_conversion_rows(
    rows: &[BookingConversionPolicyRow],
    holder_ref: Option<&str>,
) -> Result<BookingConversionPolicy, BookingError> {
    let shipped = BookingConversionPolicy::default();
    let mut authored_vault = None::<BookingConversionPolicy>;
    let mut nested = None::<BookingConversionPolicy>;
    let mut holder = None::<BookingConversionPolicy>;
    for row in rows {
        row.validate()?;
        match row.scope {
            BookingPolicyScope::Vault => {
                if row.policy != shipped {
                    authored_vault = Some(authored_vault.map_or_else(
                        || row.policy.clone(),
                        |previous| previous.intersect(&row.policy),
                    ));
                }
            }
            BookingPolicyScope::Nested => {
                nested = Some(nested.map_or_else(
                    || row.policy.clone(),
                    |previous| previous.narrow(&row.policy),
                ));
            }
            BookingPolicyScope::Holder if row.holder_ref.as_deref() == holder_ref => {
                holder = Some(holder.map_or_else(
                    || row.policy.clone(),
                    |previous| previous.narrow(&row.policy),
                ));
            }
            BookingPolicyScope::Holder => {}
        }
    }
    let vault = authored_vault.unwrap_or(shipped);
    let narrowed = nested.map_or_else(|| vault.clone(), |row| vault.narrow(&row));
    let resolved = if vault.precedence == BookingPolicyPrecedence::HolderOverrideCappedAtVault {
        holder.map_or(narrowed, |row| vault.narrow(&row))
    } else {
        narrowed
    };
    resolved.validate()?;
    Ok(resolved)
}

impl crate::Vault {
    /// Read conversion decisions through the vault's resolved manifest in one
    /// snapshot. Host inputs may only narrow this result at presentation time.
    pub fn booking_conversion_policy(
        &self,
        holder_ref: Option<&str>,
    ) -> Result<BookingConversionPolicy, BookingError> {
        let txn =
            self.store.env.read_txn().map_err(|error| {
                BookingError::SlotOracle(format!("booking policy read: {error}"))
            })?;
        let resolved =
            crate::gate::resolve_policy_manifest(&self.store, &txn).map_err(|error| {
                BookingError::SlotOracle(format!("booking policy resolve: {error}"))
            })?;
        resolved
            .booking_conversion_policy(holder_ref)
            .ok_or_else(|| {
                BookingError::InvalidConfig("booking conversion policy is unavailable".to_owned())
            })
    }
}
