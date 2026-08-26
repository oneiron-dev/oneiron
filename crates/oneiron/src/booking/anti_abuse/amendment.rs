use super::evaluation::scoped_rules;
use super::rules::{
    AmendmentDirection, BookingAntiAbuseRule, BookingAntiAbuseRuleRow,
    BookingRuleOwnerStampBinding, BookingRuleScope, RuleAmendmentOutcome, booking_rule_row_id,
    validate_rule_row,
};
use super::storage::{
    ROW_VERSION_HASH_DOMAIN, decode_row, encode_row, engine_failure, notice_key,
    notice_scan_prefix, refused, rule_row_key, rule_scan_prefix,
};
use crate::booking::config::{decode_event_type_claim_value, is_booking_claim_predicate};
use crate::booking::lifecycle::{booking_writer, digest_with, put_meta, read_meta_bytes};
use crate::booking::{BookingError, EventTypeKey};
use crate::claim::{ClaimSubject, claim_surfaceable};
use crate::{EntityId, Vault};

// -------------------------------------------------------------------------
// Amendment direction
// -------------------------------------------------------------------------

/// Orders `proposed` against `current`. Any loosened axis, a variant drift,
/// or a scope change routes to the owner stamp; only a provable tightening
/// or an exact re-assertion activates automatically.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] when the proposal is malformed,
/// re-scopes the row, or fails to advance the version by exactly one.
pub fn amendment_direction(
    current: &BookingAntiAbuseRuleRow,
    proposed: &BookingAntiAbuseRuleRow,
) -> Result<AmendmentDirection, BookingError> {
    validate_rule_row(proposed)?;
    if proposed.row_id != current.row_id {
        return Err(refused("an amendment may not rename the rule row"));
    }
    if proposed.scope != current.scope {
        return Err(refused("an amendment may not re-scope the rule row"));
    }
    if proposed.version != current.version + 1 {
        return Err(refused("an amendment must advance the version by one"));
    }
    Ok(match rule_ordering(&current.rule, &proposed.rule) {
        RuleOrdering::Same => AmendmentDirection::Equivalent,
        RuleOrdering::Tighter => AmendmentDirection::Tightening,
        RuleOrdering::Looser | RuleOrdering::TighterAndLooser | RuleOrdering::Unorderable => {
            AmendmentDirection::Loosening
        }
    })
}

#[derive(Clone, Copy)]
enum RuleOrdering {
    Same,
    Tighter,
    Looser,
    TighterAndLooser,
    Unorderable,
}

fn fold_axis(ordering: &mut RuleOrdering, proposed: u64, current: u64, lower_is_tighter: bool) {
    if proposed == current {
        return;
    }
    let axis_tightened = if lower_is_tighter {
        proposed < current
    } else {
        proposed > current
    };
    *ordering = match (*ordering, axis_tightened) {
        (RuleOrdering::Same, true) | (RuleOrdering::Tighter, true) => RuleOrdering::Tighter,
        (RuleOrdering::Same, false) | (RuleOrdering::Looser, false) => RuleOrdering::Looser,
        (RuleOrdering::Tighter, false) | (RuleOrdering::Looser, true) => {
            RuleOrdering::TighterAndLooser
        }
        (RuleOrdering::TighterAndLooser, _) => RuleOrdering::TighterAndLooser,
        (RuleOrdering::Unorderable, _) => RuleOrdering::Unorderable,
    };
}

fn fold_flag(ordering: &mut RuleOrdering, proposed: bool, current: bool) {
    if proposed == current {
        return;
    }
    // Enabling a check is the tightening arm; disabling it is the loosening.
    fold_axis(ordering, u64::from(proposed), u64::from(current), false);
}

fn rule_ordering(current: &BookingAntiAbuseRule, proposed: &BookingAntiAbuseRule) -> RuleOrdering {
    use BookingAntiAbuseRule as Rule;
    let mut ordering = RuleOrdering::Same;
    match (current, proposed) {
        (
            Rule::RequiredIntake {
                min_chars: current_min,
            },
            Rule::RequiredIntake {
                min_chars: proposed_min,
            },
        ) => fold_axis(
            &mut ordering,
            proposed_min.get().into(),
            current_min.get().into(),
            false,
        ),
        (
            Rule::MinimumNotice {
                normal_secs: current_normal,
                high_value_secs: current_high,
            },
            Rule::MinimumNotice {
                normal_secs: proposed_normal,
                high_value_secs: proposed_high,
            },
        ) => {
            fold_axis(
                &mut ordering,
                proposed_normal.get(),
                current_normal.get(),
                false,
            );
            fold_axis(
                &mut ordering,
                proposed_high.get(),
                current_high.get(),
                false,
            );
        }
        (
            Rule::HoneypotAndSubmitFloor {
                min_submit_millis: current_floor,
            },
            Rule::HoneypotAndSubmitFloor {
                min_submit_millis: proposed_floor,
            },
        ) => fold_axis(
            &mut ordering,
            proposed_floor.get(),
            current_floor.get(),
            false,
        ),
        (
            Rule::SlotListRate {
                per_minute_per_ip: current_rate,
                cache_ttl_secs: _,
            },
            Rule::SlotListRate {
                per_minute_per_ip: proposed_rate,
                cache_ttl_secs: _,
            },
        ) => {
            // The cache TTL shapes freshness, not admission strictness, so a
            // TTL-only change is an equivalent re-assertion.
            fold_axis(
                &mut ordering,
                proposed_rate.get().into(),
                current_rate.get().into(),
                true,
            );
        }
        (
            Rule::BookRate {
                per_minute_per_ip: current_rate,
                max_active_future_per_email: current_cap,
            },
            Rule::BookRate {
                per_minute_per_ip: proposed_rate,
                max_active_future_per_email: proposed_cap,
            },
        ) => {
            fold_axis(
                &mut ordering,
                proposed_rate.get().into(),
                current_rate.get().into(),
                true,
            );
            fold_axis(
                &mut ordering,
                u64::from(*proposed_cap),
                u64::from(*current_cap),
                true,
            );
        }
        (
            Rule::HoldRate {
                max_active_per_session: current_cap,
                per_minute_per_ip: current_rate,
            },
            Rule::HoldRate {
                max_active_per_session: proposed_cap,
                per_minute_per_ip: proposed_rate,
            },
        ) => {
            fold_axis(
                &mut ordering,
                u64::from(*proposed_cap),
                u64::from(*current_cap),
                true,
            );
            fold_axis(
                &mut ordering,
                proposed_rate.get().into(),
                current_rate.get().into(),
                true,
            );
        }
        (
            Rule::EmailPromptToCorrect {
                check_syntax: current_syntax,
                check_mx: current_mx,
                check_disposable_domain: current_disposable,
            },
            Rule::EmailPromptToCorrect {
                check_syntax: proposed_syntax,
                check_mx: proposed_mx,
                check_disposable_domain: proposed_disposable,
            },
        ) => {
            fold_flag(&mut ordering, *proposed_syntax, *current_syntax);
            fold_flag(&mut ordering, *proposed_mx, *current_mx);
            fold_flag(&mut ordering, *proposed_disposable, *current_disposable);
        }
        (Rule::QuarantineBorderline, Rule::QuarantineBorderline) => {}
        (
            Rule::EmailOtpReserve { enabled: current },
            Rule::EmailOtpReserve { enabled: proposed },
        ) => fold_flag(&mut ordering, *proposed, *current),
        (
            Rule::TentativeConfirmLinkReserve {
                enabled: current_enabled,
                expires_after_secs: current_ttl,
            },
            Rule::TentativeConfirmLinkReserve {
                enabled: proposed_enabled,
                expires_after_secs: proposed_ttl,
            },
        ) => {
            fold_flag(&mut ordering, *proposed_enabled, *current_enabled);
            fold_axis(&mut ordering, proposed_ttl.get(), current_ttl.get(), true);
        }
        _ => return RuleOrdering::Unorderable,
    }
    ordering
}

/// Canonical hash of the exact proposed row, version and every field in it.
/// The owner stamp binds this value, so a stamp minted for one proposal can
/// never activate another.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] when the canonical form cannot encode.
pub fn booking_rule_row_version_hash(
    row: &BookingAntiAbuseRuleRow,
) -> Result<[u8; 32], BookingError> {
    Ok(digest_with(ROW_VERSION_HASH_DOMAIN, &encode_row(row)?))
}

// -------------------------------------------------------------------------
// Activation
// -------------------------------------------------------------------------

fn read_rule_row_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    row_id: &str,
) -> Result<Option<BookingAntiAbuseRuleRow>, BookingError> {
    let Some(raw) = read_meta_bytes(vault, rtxn, &rule_row_key(row_id))? else {
        return Ok(None);
    };
    decode_row(&raw).map(Some)
}

fn put_rule_row_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    row: &BookingAntiAbuseRuleRow,
) -> Result<(), BookingError> {
    let encoded = encode_row(row)?;
    put_meta(vault, wtxn, &rule_row_key(&row.row_id), &encoded)
}

/// The private write surface. [`apply_rule_amendment`] is the only caller;
/// no public path may store a rule row without the versioned transaction.
#[allow(dead_code)]
fn put_booking_anti_abuse_rule(
    vault: &Vault,
    row: &BookingAntiAbuseRuleRow,
) -> Result<(), BookingError> {
    booking_writer(vault, |wtxn| put_rule_row_in_txn(vault, wtxn, row))
}

fn write_notice_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    row: &BookingAntiAbuseRuleRow,
    direction: AmendmentDirection,
) -> Result<(), BookingError> {
    let token = match direction {
        AmendmentDirection::Tightening => "tightening",
        AmendmentDirection::Equivalent => "re-assertion",
        AmendmentDirection::Loosening => "owner-stamped loosening",
    };
    let notice = format!(
        "booking anti-abuse rule {} activated at version {} ({}) by {}",
        row.row_id,
        row.version,
        token,
        row.amended_by.to_hex()
    );
    let key = notice_key(&row.row_id, row.version);
    put_meta(vault, wtxn, &key, notice.as_bytes())
}

/// Validates the scope against the same live configuration truth the solver
/// reads, while borrowing the caller's transaction so no activation can race a
/// page/config removal between validation and row storage.
fn validate_rule_scope_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    scope: &BookingRuleScope,
) -> Result<(), BookingError> {
    if vault
        .get_entity_type_in_txn(rtxn, &scope.page_ref)
        .map_err(|error| engine_failure("booking page lookup", error))?
        .is_none()
    {
        return Err(refused(
            "InvalidBookingPage: rule scope page does not exist",
        ));
    }
    // This is config.rs's canonical fallback lookup, deliberately skipping its
    // node-local shortcut: the claim scan is synced truth and works in this
    // caller-owned write transaction.
    let mut claims = vault
        .claims_for_subject_in_txn(rtxn, &scope.page_ref)
        .map_err(|error| engine_failure("booking event configuration lookup", error))?;
    claims.sort_unstable();
    for id in claims {
        let Some(body) = vault
            .get_claim_in_txn(rtxn, &id)
            .map_err(|error| engine_failure("booking event configuration read", error))?
        else {
            continue;
        };
        if !is_booking_claim_predicate(&body.predicate)
            || body.subject != ClaimSubject::Entity(scope.page_ref)
            || !claim_surfaceable(&body)
        {
            continue;
        }
        let decoded = decode_event_type_claim_value(&body.value).map_err(|error| {
            refused(format!(
                "InvalidBookingPage: rule scope has malformed event configuration: {error}"
            ))
        })?;
        // A page-wide row governs every event on this page, so it may be
        // activated only after at least one live booking configuration proves
        // that this subject is a booking page now.
        let config_matches_scope = match &scope.event_type {
            None => true,
            Some(event_type) => decoded.config.key == *event_type,
        };
        if config_matches_scope {
            return Ok(());
        }
    }
    let detail = match &scope.event_type {
        Some(event_type) => format!(
            "InvalidBookingPage: rule scope has no live event configuration for {}",
            event_type.0
        ),
        None => "InvalidBookingPage: rule scope page has no live booking configuration".to_owned(),
    };
    Err(refused(detail))
}

/// The sole public activation path: a versioned compare-and-set under the
/// booking writer.
///
/// `expected_current_version == 0` activates the row for the first time and
/// the proposal must be version 1. Otherwise the stored row must sit at
/// `expected_current_version`, the proposal must advance it by exactly one,
/// and the direction law applies: tightening and equivalent re-assertions
/// store immediately; a loosening requires `owner_stamp` whose binding
/// equals [`booking_rule_row_version_hash`] of the exact proposed row. The
/// stamp reference is recorded by the transaction — a caller-supplied
/// `owner_stamp_ref` is refused.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] on a stale expected version, a
/// malformed or out-of-order proposal, a stamp declined for loosening, or a
/// stamp that binds anything other than the exact proposed row and version.
pub fn apply_rule_amendment(
    vault: &Vault,
    expected_current_version: u64,
    proposed: BookingAntiAbuseRuleRow,
    owner_stamp: Option<&BookingRuleOwnerStampBinding>,
) -> Result<RuleAmendmentOutcome, BookingError> {
    validate_rule_row(&proposed)?;
    if proposed.row_id != booking_rule_row_id(&proposed.scope, &proposed.rule) {
        return Err(refused(
            "rule row id does not match its canonical scope and rule identity",
        ));
    }
    if proposed.owner_stamp_ref.is_some() {
        return Err(refused(
            "the stamp binding is a transaction input; it is never caller-stored on the row",
        ));
    }
    booking_writer(vault, |wtxn| {
        validate_rule_scope_in_txn(vault, &*wtxn, &proposed.scope)?;
        let current = read_rule_row_in_txn(vault, &*wtxn, &proposed.row_id)?;
        let (stored, direction) = match (expected_current_version, current) {
            (0, None) => {
                if proposed.version != 1 {
                    return Err(refused(
                        "a first activation must be version 1 with expected version 0",
                    ));
                }
                // Activating a control that did not exist is additive; it is
                // the tightening arm.
                (proposed, AmendmentDirection::Tightening)
            }
            (0, Some(current)) => {
                return Err(refused(format!(
                    "rule row already exists at version {}; amend with the current version",
                    current.version
                )));
            }
            (expected, None) => {
                return Err(refused(format!(
                    "no stored rule row matches expected version {expected}"
                )));
            }
            (expected, Some(current)) => {
                if current.version != expected {
                    return Err(refused(format!(
                        "expected current version {expected} is stale; row is at {}",
                        current.version
                    )));
                }
                let direction = amendment_direction(&current, &proposed)?;
                let stored = match direction {
                    AmendmentDirection::Loosening => {
                        let Some(stamp) = owner_stamp else {
                            return Err(refused(
                                "loosening requires a logged owner stamp binding the exact proposed row and version",
                            ));
                        };
                        let bound = booking_rule_row_version_hash(&proposed)?;
                        if stamp.proposed_row_version_hash != bound {
                            return Err(refused(
                                "owner stamp does not bind the exact proposed row and version",
                            ));
                        }
                        BookingAntiAbuseRuleRow {
                            owner_stamp_ref: Some(stamp.stamp_ref),
                            ..proposed
                        }
                    }
                    AmendmentDirection::Tightening | AmendmentDirection::Equivalent => proposed,
                };
                (stored, direction)
            }
        };
        put_rule_row_in_txn(vault, wtxn, &stored)?;
        write_notice_in_txn(vault, wtxn, &stored, direction)?;
        Ok(RuleAmendmentOutcome {
            stored,
            owner_notice_required: true,
        })
    })
}

/// Decodes every stored rule row under the booking prefix. Rule rows are
/// owner-configured and few, so the loaders below both start from one full
/// prefix scan and differ only in their scope predicate.
fn all_rule_rows(vault: &Vault) -> Result<Vec<BookingAntiAbuseRuleRow>, BookingError> {
    let rtxn = vault
        .store
        .env
        .read_txn()
        .map_err(|error| engine_failure("read transaction", error))?;
    let mut rows = Vec::new();
    let prefix = rule_scan_prefix();
    let iter = vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, &prefix)
        .map_err(|error| engine_failure("rule scan", error))?;
    for entry in iter {
        let (_, raw) = entry.map_err(|error| engine_failure("rule scan", error))?;
        rows.push(decode_row(&raw)?);
    }
    Ok(rows)
}

/// Lists the stored rule rows for one exact scope, ordered by row id — the
/// admin/listing view. Request enforcement wants the applicable union
/// instead: [`applicable_booking_anti_abuse_rules`].
///
/// # Errors
///
/// Storage and decode failures, wrapped per the lane's error stance.
pub fn booking_anti_abuse_rules(
    vault: &Vault,
    scope: &BookingRuleScope,
) -> Result<Vec<BookingAntiAbuseRuleRow>, BookingError> {
    let mut rows: Vec<BookingAntiAbuseRuleRow> = all_rule_rows(vault)?
        .into_iter()
        .filter(|row| row.scope == *scope)
        .collect();
    rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
    Ok(rows)
}

/// Lists every stored rule row that governs one request: the page-wide
/// (`event_type: None`) stack for `page_ref` PLUS, when the request names an
/// event type, that event type's exact stack — the same union the
/// evaluator's `scoped_rules` predicate keeps. The HTTP adapter's row
/// loaders go through this door, so a page-wide owner configuration cannot
/// silently stop applying the moment a request carries an event type.
///
/// # Errors
///
/// Storage and decode failures, wrapped per the lane's error stance.
pub fn applicable_booking_anti_abuse_rules(
    vault: &Vault,
    page_ref: &EntityId,
    event_type: &Option<EventTypeKey>,
) -> Result<Vec<BookingAntiAbuseRuleRow>, BookingError> {
    let rows = all_rule_rows(vault)?;
    let mut applicable: Vec<BookingAntiAbuseRuleRow> =
        scoped_rules(&rows, page_ref, event_type).cloned().collect();
    applicable.sort_by(|left, right| left.row_id.cmp(&right.row_id));
    Ok(applicable)
}

/// Every durable activation notice, oldest first by row id then text. The
/// owner-visible companion of [`apply_rule_amendment`]: every stored
/// activation leaves one notice row.
///
/// # Errors
///
/// Storage failures, and [`BookingError::InvalidConstraint`] when a notice is
/// not UTF-8.
pub fn booking_anti_abuse_notices(vault: &Vault) -> Result<Vec<String>, BookingError> {
    let rtxn = vault
        .store
        .env
        .read_txn()
        .map_err(|error| engine_failure("read transaction", error))?;
    let mut notices = Vec::new();
    let prefix = notice_scan_prefix();
    let iter = vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, &prefix)
        .map_err(|error| engine_failure("notice scan", error))?;
    for entry in iter {
        let (_, raw) = entry.map_err(|error| engine_failure("notice scan", error))?;
        let notice = std::str::from_utf8(&raw)
            .map_err(|_| refused("booking anti-abuse notice is not utf-8"))?;
        notices.push(notice.to_owned());
    }
    notices.sort();
    Ok(notices)
}
