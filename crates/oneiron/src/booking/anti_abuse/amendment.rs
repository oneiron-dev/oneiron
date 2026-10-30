//! Booking anti-abuse rule amendments and their owner-stamped activation.
//! Entry: `amendment_direction`.
//! Defines its own items.

use super::evaluation::scoped_rules;
use super::manifest::{
    effective_rule_rows, effective_rule_rows_in_txn, put_manifest_rule_row_in_txn,
};
use super::rules::{
    AmendmentDirection, BookingAntiAbuseRule, BookingAntiAbuseRuleRow,
    BookingRuleOwnerStampBinding, BookingRuleScope, RuleAmendmentOutcome, booking_rule_row_id,
    validate_rule_row,
};
use super::storage::{
    PROPOSAL_KEY_TAG, ROW_VERSION_HASH_DOMAIN, RULE_PROPOSAL, encode_row, engine_failure, refused,
};
use crate::booking::config::{BOOKING_EVENT_TYPE_PREDICATE, decode_event_type_claim_value};
use crate::booking::lifecycle::{booking_writer, digest_with};
use crate::booking::{BookingError, EventTypeKey};
use crate::claim::{ClaimSubject, claim_surfaceable};
use crate::consent::AuthenticatedOwner;
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

/// The row in force under `row_id`, read in the caller's transaction.
fn effective_rule_row_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    row_id: &str,
) -> Result<Option<BookingAntiAbuseRuleRow>, BookingError> {
    Ok(effective_rule_rows_in_txn(vault, rtxn)?
        .into_iter()
        .find(|row| row.row_id == row_id))
}

fn direction_token(direction: AmendmentDirection) -> &'static str {
    match direction {
        AmendmentDirection::Tightening => "tightening",
        AmendmentDirection::Equivalent => "re-assertion",
        AmendmentDirection::Loosening => "loosening",
    }
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
            .get_claim_for_effect_in_txn(rtxn, &id)
            .map_err(|error| engine_failure("booking event configuration read", error))?
        else {
            continue;
        };
        // The booking family also contains publication claims. Only the exact
        // event-type predicate carries the configuration schema decoded below.
        if body.predicate != BOOKING_EVENT_TYPE_PREDICATE
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
/// the proposal must be version 1. Otherwise the row in force must sit at
/// `expected_current_version` and the proposal must advance it by exactly
/// one. `owner` is the amending person's proof and `amended_by` must name
/// that person. Authority is verified inside the writer (FIX 9627): the
/// person must be the rule's holder, a live owner of this vault proven at
/// the owner tier who owns its booking pages, and a loosening must also
/// carry the holder's authenticated, logged approve-once press on
/// [`booking_rule_row_version_hash`] of the exact proposed row, which the
/// transaction spends and records as `owner_stamp_ref`. A caller's
/// `owner_stamp`, when given, must name that logged decision and hash. A
/// change that lacks either is retained as a proposal
/// ([`booking_anti_abuse_rule_proposals`]) and the row in force stays as it
/// was; the owner's press and a resubmission activate it. A caller-supplied
/// `owner_stamp_ref` is refused.
///
/// An activated row is written into the owner-trusted default policy
/// manifest through the owner's manifest writer (FIX 9628), which records
/// the gate receipt of the write, so it reaches every node on the manifest's
/// own sync path.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] on a stale expected version, a
/// malformed or out-of-order proposal, an `amended_by` that is not the
/// authenticated person, or a manifest write the policy writer refuses.
pub fn apply_rule_amendment(
    vault: &Vault,
    owner: &AuthenticatedOwner,
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
    let outcome = booking_writer(vault, |wtxn| {
        let actor = owner
            .revalidate_person_in_txn(vault, &*wtxn)
            .map_err(|error| {
                refused(format!("the amending person is not authenticated: {error}"))
            })?;
        if proposed.amended_by != actor {
            return Err(refused("amended_by must name the authenticated person"));
        }
        validate_rule_scope_in_txn(vault, &*wtxn, &proposed.scope)?;
        let current = effective_rule_row_in_txn(vault, &*wtxn, &proposed.row_id)?;
        let direction = match (expected_current_version, current) {
            (0, None) => {
                if proposed.version != 1 {
                    return Err(refused(
                        "a first activation must be version 1 with expected version 0",
                    ));
                }
                // Activating a control that did not exist is additive; it is
                // the tightening arm.
                AmendmentDirection::Tightening
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
                amendment_direction(&current, &proposed)?
            }
        };
        let bound = booking_rule_row_version_hash(&proposed)?;
        let holder = owner.revalidate_in_txn(vault, &*wtxn).is_ok()
            && crate::memory::verify_public_booking_owner_in_txn(vault, &*wtxn, actor).is_ok();
        // The holder's press, read from the consent ledger rather than taken
        // from the caller. A spent or unreadable marker approves nothing.
        let digest = crate::consent::EffectDigest::from_bytes(bound);
        let approval =
            crate::consent::approve_once_authorization_in_txn(&vault.store, &*wtxn, &digest)
                .ok()
                .flatten();
        let decision = match &approval {
            Some(_) => crate::consent::approve_once_decision_in_txn(&vault.store, &*wtxn, &digest)
                .map_err(|error| engine_failure("approval decision read", error))?
                .and_then(|decision| EntityId::from_bytes(decision.as_bytes()).ok()),
            None => None,
        };
        let stamp_names_decision = owner_stamp.is_none_or(|stamp| {
            Some(stamp.stamp_ref) == decision && stamp.proposed_row_version_hash == bound
        });
        let approved = decision.is_some() && stamp_names_decision;
        let activates = holder
            && match direction {
                AmendmentDirection::Loosening => approved,
                AmendmentDirection::Tightening | AmendmentDirection::Equivalent => true,
            };
        if !activates {
            RULE_PROPOSAL
                .put(&vault.store, wtxn, &(*PROPOSAL_KEY_TAG, bound), &proposed)
                .map_err(|error| engine_failure("rule proposal write", error))?;
            return Ok(RuleAmendmentOutcome {
                stored: proposed,
                owner_notice_required: true,
                activated: false,
            });
        }
        let stored = match (approval, approved) {
            (Some(authorization), true) => {
                crate::consent::spend_approve_once_in_txn(&vault.store, wtxn, &authorization)
                    .map_err(|error| engine_failure("approval spend", error))?;
                BookingAntiAbuseRuleRow {
                    owner_stamp_ref: decision,
                    ..proposed
                }
            }
            _ => proposed,
        };
        RULE_PROPOSAL
            .delete(&vault.store, wtxn, &(*PROPOSAL_KEY_TAG, bound))
            .map_err(|error| engine_failure("rule proposal delete", error))?;
        put_manifest_rule_row_in_txn(vault, owner, wtxn, &stored)?;
        Ok(RuleAmendmentOutcome {
            stored,
            owner_notice_required: true,
            activated: true,
        })
    })?;
    if outcome.activated {
        // A floor this commit moved is judged again at once, as every owner
        // manifest write does.
        vault.apply_pending_rebinds_after_commit();
    }
    Ok(outcome)
}

/// Every retained rule proposal awaiting its holder (FIX 9627), ordered by
/// row id then version: the owner's review list. Approving one is the
/// owner's approve-once press on its [`booking_rule_row_version_hash`],
/// then the same amendment resubmitted.
///
/// # Errors
///
/// Storage and decode failures, wrapped per the lane's error stance.
pub fn booking_anti_abuse_rule_proposals(
    vault: &Vault,
) -> Result<Vec<BookingAntiAbuseRuleRow>, BookingError> {
    let rtxn = vault
        .store
        .env
        .read_txn()
        .map_err(|error| engine_failure("read transaction", error))?;
    let mut rows: Vec<BookingAntiAbuseRuleRow> = RULE_PROPOSAL
        .scan_from(&vault.store, &rtxn, PROPOSAL_KEY_TAG)
        .map_err(|error| engine_failure("rule proposal scan", error))?
        .into_iter()
        .map(|(_, row)| row)
        .collect();
    rows.sort_by(|left, right| {
        left.row_id
            .cmp(&right.row_id)
            .then(left.version.cmp(&right.version))
    });
    Ok(rows)
}

/// Lists the rule rows in force for one exact scope, ordered by row id — the
/// admin/listing view. Request enforcement wants the applicable union
/// instead: [`applicable_booking_anti_abuse_rules`].
///
/// # Errors
///
/// Policy resolution failures, wrapped per the lane's error stance.
pub fn booking_anti_abuse_rules(
    vault: &Vault,
    scope: &BookingRuleScope,
) -> Result<Vec<BookingAntiAbuseRuleRow>, BookingError> {
    let mut rows: Vec<BookingAntiAbuseRuleRow> = effective_rule_rows(vault)?
        .into_iter()
        .filter(|row| row.scope == *scope)
        .collect();
    rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
    Ok(rows)
}

/// Lists every rule row in force that governs one request: the page-wide
/// (`event_type: None`) stack for `page_ref` PLUS, when the request names an
/// event type, that event type's exact stack — the same union the
/// evaluator's `scoped_rules` predicate keeps. The HTTP adapter's row
/// loaders go through this door, so a page-wide owner configuration cannot
/// silently stop applying the moment a request carries an event type.
///
/// # Errors
///
/// Policy resolution failures, wrapped per the lane's error stance.
pub fn applicable_booking_anti_abuse_rules(
    vault: &Vault,
    page_ref: &EntityId,
    event_type: &Option<EventTypeKey>,
) -> Result<Vec<BookingAntiAbuseRuleRow>, BookingError> {
    let rows = effective_rule_rows(vault)?;
    let mut applicable: Vec<BookingAntiAbuseRuleRow> =
        scoped_rules(&rows, page_ref, event_type).cloned().collect();
    applicable.sort_by(|left, right| left.row_id.cmp(&right.row_id));
    Ok(applicable)
}

/// The owner-visible state of every rule, ordered by text: one line per row
/// in force (its version, who amended it, and whether an owner stamp
/// loosened it) and one per retained proposal (with the digest its approval
/// names). Each activation's history is its manifest write's gate receipt.
///
/// # Errors
///
/// Policy resolution, storage and encoding failures.
pub fn booking_anti_abuse_notices(vault: &Vault) -> Result<Vec<String>, BookingError> {
    let rows = effective_rule_rows(vault)?;
    let mut notices: Vec<String> = rows
        .iter()
        .map(|row| {
            let token = if row.owner_stamp_ref.is_some() {
                "owner-stamped loosening"
            } else {
                "tightening or re-assertion"
            };
            format!(
                "booking anti-abuse rule {} activated at version {} ({}) by {}",
                row.row_id,
                row.version,
                token,
                row.amended_by.to_hex()
            )
        })
        .collect();
    for proposal in booking_anti_abuse_rule_proposals(vault)? {
        let token = match rows.iter().find(|row| row.row_id == proposal.row_id) {
            Some(current) => {
                amendment_direction(current, &proposal).map_or("change", direction_token)
            }
            None => direction_token(AmendmentDirection::Tightening),
        };
        notices.push(format!(
            "booking anti-abuse rule {} proposed at version {} ({}) by {}; it activates on the owner's approval of {}",
            proposal.row_id,
            proposal.version,
            token,
            proposal.amended_by.to_hex(),
            crate::booking::lifecycle::hex_lower(&booking_rule_row_version_hash(&proposal)?)
        ));
    }
    notices.sort();
    Ok(notices)
}
