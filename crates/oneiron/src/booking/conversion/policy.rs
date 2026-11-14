//! Resolved BK-07 conversion choices, never booking authority.
//!
//! A vault row caps nested choices. The default precedence narrows nested
//! rows, then lets an explicit holder row override those choices only inside
//! the vault cap. Counts and notification content live in policy, not UX code.

use serde::{Deserialize, Serialize};

use super::ux::ReminderAction;
use crate::booking::BookingError;

#[doc(hidden)]
pub use oneiron_records::booking::conversion::policy::{
    BookingConversionPolicy, BookingConversionPolicyRow, BookingPolicyPrecedence,
    BookingPolicyScope,
};

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
