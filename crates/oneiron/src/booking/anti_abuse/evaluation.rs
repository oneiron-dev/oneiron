use std::num::{NonZeroU32, NonZeroU64};

use super::rules::{BookingAntiAbuseRule, BookingAntiAbuseRuleRow};
use super::storage::{
    EMAIL_HASH_DOMAIN, IP_HASH_DOMAIN, QUARANTINE_CLAIM_DOMAIN, RATE_WINDOW_SECS,
    SESSION_HASH_DOMAIN, SUBMISSION_FINGERPRINT_DOMAIN,
};
use crate::EntityId;
use crate::booking::EventTypeKey;
use crate::booking::lifecycle::digest_with;

// -------------------------------------------------------------------------
// Evaluation
// -------------------------------------------------------------------------

/// Evidence about one submitted email address. `mx_present` is tri-state:
/// `None` means the check was not performed and counts as no signal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmailValidationEvidence {
    pub syntax_valid: bool,
    pub mx_present: Option<bool>,
    pub disposable_domain: bool,
}

/// Caller-asserted facts about one incoming booking request. Identity
/// material arrives pre-hashed; raw addresses never reach this module.
#[derive(Clone, Debug, PartialEq)]
pub struct BookingRequestFacts {
    pub page_ref: EntityId,
    pub event_type: Option<EventTypeKey>,
    pub ip_hash: [u8; 32],
    pub email_hash: Option<[u8; 32]>,
    pub session_hash: Option<[u8; 32]>,
    pub started_at_millis: u64,
    pub submitted_at_millis: u64,
    /// Transport placeholder overwritten at the trusted HTTP admission boundary.
    /// The write door also re-derives it from the canonical evidence below.
    pub submission_fingerprint: [u8; 32],
    /// Hash of the canonical selected slot supplied by the booking parser.
    pub selected_slot_hash: [u8; 32],
    /// Hash of the canonical intake bytes supplied by the booking parser.
    pub intake_content_hash: [u8; 32],
    pub honeypot_nonempty: bool,
    pub intake_chars: usize,
    pub active_future_bookings_for_email: u8,
    pub active_holds_for_session: u8,
    pub email: Option<EmailValidationEvidence>,
}

/// Canonical, timing-independent identity material for a submission.
///
/// The production adapter derives this at its trusted boundary and overwrites
/// any transport-provided placeholder. Form timing is deliberately omitted so
/// a retry that changes only untrusted timestamps cannot mint another record.
#[must_use]
pub fn server_submission_fingerprint(facts: &BookingRequestFacts) -> [u8; 32] {
    let mut material = Vec::new();
    material.extend_from_slice(facts.page_ref.as_bytes());
    material.extend_from_slice(&facts.ip_hash);
    match &facts.email_hash {
        Some(value) => {
            material.push(1);
            material.extend_from_slice(value);
        }
        None => material.push(0),
    }
    match &facts.session_hash {
        Some(value) => {
            material.push(1);
            material.extend_from_slice(value);
        }
        None => material.push(0),
    }
    match &facts.event_type {
        Some(value) => {
            material.push(1);
            material.extend_from_slice(&(value.0.len() as u64).to_be_bytes());
            material.extend_from_slice(value.0.as_bytes());
        }
        None => material.push(0),
    }
    // These are hashes of parsed canonical form fields, not presentation
    // shape. Same-length intake or a different selected slot is distinct.
    material.extend_from_slice(&facts.selected_slot_hash);
    material.extend_from_slice(&facts.intake_content_hash);
    material.push(u8::from(facts.honeypot_nonempty));
    if let Some(email) = &facts.email {
        material.push(1);
        material.push(u8::from(email.syntax_valid));
        material.push(match email.mx_present {
            Some(true) => 2,
            Some(false) => 1,
            None => 0,
        });
        material.push(u8::from(email.disposable_domain));
    } else {
        material.push(0);
    }
    digest_with(SUBMISSION_FINGERPRINT_DOMAIN, &material)
}

/// Deterministic quarantine claim identity for trusted canonical submission evidence.
#[must_use]
pub fn quarantine_claim_id(facts: &BookingRequestFacts, reason: &str) -> [u8; 16] {
    let mut material = Vec::new();
    material.extend_from_slice(facts.page_ref.as_bytes());
    material.extend_from_slice(&facts.ip_hash);
    material.extend_from_slice(&server_submission_fingerprint(facts));
    if let Some(email_hash) = &facts.email_hash {
        material.extend_from_slice(email_hash);
    }
    match &facts.event_type {
        Some(event_type) => {
            material.push(0x01);
            let bytes = event_type.0.as_bytes();
            material.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            material.extend_from_slice(bytes);
        }
        None => material.push(0x00),
    }
    material.extend_from_slice(reason.as_bytes());
    let binding = digest_with(QUARANTINE_CLAIM_DOMAIN, &material);
    let mut claim_id = [0_u8; 16];
    claim_id.copy_from_slice(&binding[..16]);
    claim_id
}

/// What the engine concludes about one request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BookingAbuseVerdict {
    Allow,
    /// Reject while answering exactly like an ordinary 200. The adapter
    /// performs no write and reveals nothing.
    SilentHttp200Reject,
    RateLimited {
        retry_after_secs: u64,
    },
    PromptCorrection {
        field: &'static str,
        message: String,
    },
    Quarantine {
        reason: String,
    },
}

pub(super) fn scoped_rules<'r>(
    rows: &'r [BookingAntiAbuseRuleRow],
    page_ref: &EntityId,
    event_type: &Option<EventTypeKey>,
) -> impl Iterator<Item = &'r BookingAntiAbuseRuleRow> {
    rows.iter().filter(move |row| {
        row.scope.page_ref == *page_ref
            && (row.scope.event_type.is_none() || row.scope.event_type == *event_type)
    })
}

/// The strictest slot-list knobs across the rows in scope. A cache-TTL
/// difference resolves toward the shorter (fresher) window, matching the
/// under-block posture on listings.
#[must_use]
pub fn slot_list_rate_knobs(
    rows: &[BookingAntiAbuseRuleRow],
    page_ref: &EntityId,
    event_type: &Option<EventTypeKey>,
) -> Option<(NonZeroU32, NonZeroU64)> {
    let mut merged: Option<(NonZeroU32, NonZeroU64)> = None;
    for row in scoped_rules(rows, page_ref, event_type) {
        if let BookingAntiAbuseRule::SlotListRate {
            per_minute_per_ip,
            cache_ttl_secs,
        } = &row.rule
        {
            merged = Some(match merged {
                None => (*per_minute_per_ip, *cache_ttl_secs),
                Some((rate, ttl)) => (rate.min(*per_minute_per_ip), ttl.min(*cache_ttl_secs)),
            });
        }
    }
    merged
}

/// The strictest book knobs across the rows in scope.
#[must_use]
pub fn book_rate_knobs(
    rows: &[BookingAntiAbuseRuleRow],
    page_ref: &EntityId,
    event_type: &Option<EventTypeKey>,
) -> Option<(NonZeroU32, u8)> {
    let mut merged: Option<(NonZeroU32, u8)> = None;
    for row in scoped_rules(rows, page_ref, event_type) {
        if let BookingAntiAbuseRule::BookRate {
            per_minute_per_ip,
            max_active_future_per_email,
        } = &row.rule
        {
            merged = Some(match merged {
                None => (*per_minute_per_ip, *max_active_future_per_email),
                Some((rate, cap)) => (
                    rate.min(*per_minute_per_ip),
                    cap.min(*max_active_future_per_email),
                ),
            });
        }
    }
    merged
}

/// The strictest hold knobs across the rows in scope.
#[must_use]
pub fn hold_rate_knobs(
    rows: &[BookingAntiAbuseRuleRow],
    page_ref: &EntityId,
    event_type: &Option<EventTypeKey>,
) -> Option<(u8, NonZeroU32)> {
    let mut merged: Option<(u8, NonZeroU32)> = None;
    for row in scoped_rules(rows, page_ref, event_type) {
        if let BookingAntiAbuseRule::HoldRate {
            max_active_per_session,
            per_minute_per_ip,
        } = &row.rule
        {
            merged = Some(match merged {
                None => (*max_active_per_session, *per_minute_per_ip),
                Some((cap, rate)) => (
                    cap.min(*max_active_per_session),
                    rate.min(*per_minute_per_ip),
                ),
            });
        }
    }
    merged
}

/// Pure request evaluation over stored rows plus asserted facts. No storage
/// access, so a honeypot or time-floor hit can be honoured with zero writes.
///
/// Precedence: the silent bot signals first (they must reveal nothing), then
/// the correctable intake and email prompts, then the caps.
#[derive(Clone, Copy)]
enum BookingEvaluationScope {
    All,
    Book,
    Hold,
    SlotList,
}

fn rule_applies_to_evaluation(rule: &BookingAntiAbuseRule, scope: BookingEvaluationScope) -> bool {
    match scope {
        BookingEvaluationScope::All => true,
        // Confirmation owns the submit-time signals, contact correction,
        // quarantine, and active-booking cap. Its minute quota remains an
        // adapter concern below this pure evaluator.
        BookingEvaluationScope::Book => matches!(
            rule,
            BookingAntiAbuseRule::HoneypotAndSubmitFloor { .. }
                | BookingAntiAbuseRule::RequiredIntake { .. }
                | BookingAntiAbuseRule::EmailPromptToCorrect { .. }
                | BookingAntiAbuseRule::QuarantineBorderline
                | BookingAntiAbuseRule::BookRate { .. }
        ),
        // Slot lookup and hold creation have no form evidence. Their only
        // controls are their endpoint counters, consumed by the adapter.
        BookingEvaluationScope::Hold => false,
        BookingEvaluationScope::SlotList => false,
    }
}

fn evaluate_booking_request_for(
    rows: &[BookingAntiAbuseRuleRow],
    facts: &BookingRequestFacts,
    evaluation_scope: BookingEvaluationScope,
) -> BookingAbuseVerdict {
    let scoped: Vec<&BookingAntiAbuseRuleRow> =
        scoped_rules(rows, &facts.page_ref, &facts.event_type)
            .filter(|row| rule_applies_to_evaluation(&row.rule, evaluation_scope))
            .collect();

    // Honeypot and time-to-submit floor are ONE control family: both
    // signals answer with the same indistinguishable rejection, and both are
    // armed only by an activated `HoneypotAndSubmitFloor` row in scope — the
    // sole public activation path decides what fires. A filled honeypot
    // field with no such row is noise, never a rejection.
    let floor = scoped
        .iter()
        .filter_map(|row| match &row.rule {
            BookingAntiAbuseRule::HoneypotAndSubmitFloor { min_submit_millis } => {
                Some(min_submit_millis.get())
            }
            _ => None,
        })
        .max();
    if floor.is_some() && facts.honeypot_nonempty {
        return BookingAbuseVerdict::SilentHttp200Reject;
    }
    if let Some(floor_millis) = floor
        && facts
            .submitted_at_millis
            .saturating_sub(facts.started_at_millis)
            < floor_millis
    {
        return BookingAbuseVerdict::SilentHttp200Reject;
    }

    // Required open-text intake.
    let min_intake = scoped
        .iter()
        .filter_map(|row| match &row.rule {
            BookingAntiAbuseRule::RequiredIntake { min_chars } => Some(min_chars.get()),
            _ => None,
        })
        .max();
    if let Some(min_chars) = min_intake
        && facts.intake_chars < usize::from(min_chars)
    {
        return BookingAbuseVerdict::PromptCorrection {
            field: "intake",
            message: format!(
                "please tell the host a little more — at least {min_chars} characters"
            ),
        };
    }

    // Email evidence: prompts, never a hard block. A `None` MX reading is no
    // signal.
    let (mut check_syntax, mut check_mx, mut check_disposable) = (false, false, false);
    let mut quarantine_enabled = false;
    for row in &scoped {
        match &row.rule {
            BookingAntiAbuseRule::EmailPromptToCorrect {
                check_syntax: syntax,
                check_mx: mx,
                check_disposable_domain: disposable,
            } => {
                check_syntax |= syntax;
                check_mx |= mx;
                check_disposable |= disposable;
            }
            BookingAntiAbuseRule::QuarantineBorderline => quarantine_enabled = true,
            _ => {}
        }
    }
    if let Some(evidence) = &facts.email {
        let mut negatives: u8 = 0;
        if check_syntax && !evidence.syntax_valid {
            negatives += 1;
        }
        if check_mx && evidence.mx_present == Some(false) {
            negatives += 1;
        }
        if check_disposable && evidence.disposable_domain {
            negatives += 1;
        }
        if negatives >= 2 {
            if quarantine_enabled {
                return BookingAbuseVerdict::Quarantine {
                    reason: "booking contact evidence failed several independent checks".to_owned(),
                };
            }
            // Under-block when quarantine is not seeded: prompt instead.
            return BookingAbuseVerdict::PromptCorrection {
                field: "email",
                message: "that email address needs a second look — please correct it".to_owned(),
            };
        }
        if negatives == 1 {
            let message = if check_syntax && !evidence.syntax_valid {
                "that email address does not look complete — please check it"
            } else if check_mx && evidence.mx_present == Some(false) {
                "that email domain does not accept mail — please check for typos"
            } else {
                "please use a permanent email address so the host can reach you"
            };
            return BookingAbuseVerdict::PromptCorrection {
                field: "email",
                message: message.to_owned(),
            };
        }
    }

    // Hold squatter cap: at most the configured number of active holds per
    // session. Transient by nature, so it is a retry, not a record.
    if matches!(evaluation_scope, BookingEvaluationScope::All)
        && let Some((max_active_per_session, _)) =
            hold_rate_knobs(rows, &facts.page_ref, &facts.event_type)
        && facts.active_holds_for_session >= max_active_per_session
    {
        return BookingAbuseVerdict::RateLimited {
            retry_after_secs: RATE_WINDOW_SECS,
        };
    }

    // Active-future-booking cap per email: user-correctable (cancel one), so
    // it prompts rather than blocking or triaging.
    if matches!(
        evaluation_scope,
        BookingEvaluationScope::All | BookingEvaluationScope::Book
    ) && facts.email_hash.is_some()
        && let Some((_, max_active_future_per_email)) =
            book_rate_knobs(rows, &facts.page_ref, &facts.event_type)
        && facts.active_future_bookings_for_email >= max_active_future_per_email
    {
        return BookingAbuseVerdict::PromptCorrection {
            field: "email",
            message:
                "this address already holds the maximum active upcoming bookings — cancel one or let it pass first"
                    .to_owned(),
        };
    }

    BookingAbuseVerdict::Allow
}

/// Full evaluation retained for callers and engine tests.
#[must_use]
pub fn evaluate_booking_request(
    rows: &[BookingAntiAbuseRuleRow],
    facts: &BookingRequestFacts,
) -> BookingAbuseVerdict {
    evaluate_booking_request_for(rows, facts, BookingEvaluationScope::All)
}

/// Confirmation-specific evaluation; it deliberately excludes hold-session caps.
#[must_use]
pub fn evaluate_booking_book_request(
    rows: &[BookingAntiAbuseRuleRow],
    facts: &BookingRequestFacts,
) -> BookingAbuseVerdict {
    evaluate_booking_request_for(rows, facts, BookingEvaluationScope::Book)
}

/// Hold creation has only its endpoint quota, evaluated by the adapter.
#[must_use]
pub fn evaluate_booking_hold_request(
    rows: &[BookingAntiAbuseRuleRow],
    facts: &BookingRequestFacts,
) -> BookingAbuseVerdict {
    evaluate_booking_request_for(rows, facts, BookingEvaluationScope::Hold)
}

/// Slot listing has only its endpoint quota, evaluated by the adapter.
#[must_use]
pub fn evaluate_booking_slot_list_request(
    rows: &[BookingAntiAbuseRuleRow],
    facts: &BookingRequestFacts,
) -> BookingAbuseVerdict {
    evaluate_booking_request_for(rows, facts, BookingEvaluationScope::SlotList)
}

// -------------------------------------------------------------------------
// Request-key hashing (raw identity never touches persistence)
// -------------------------------------------------------------------------

/// Domain-tagged hash of a caller IP. Persisted rate keys derive from this,
/// never from the raw address.
#[must_use]
pub fn booking_ip_hash(ip: &str) -> [u8; 32] {
    digest_with(IP_HASH_DOMAIN, ip.as_bytes())
}

/// Domain-tagged hash of a normalized (trimmed, lowercased) email address.
#[must_use]
pub fn booking_email_hash(email: &str) -> [u8; 32] {
    digest_with(EMAIL_HASH_DOMAIN, email.trim().to_lowercase().as_bytes())
}

/// Domain-tagged hash of an opaque session identifier.
#[must_use]
pub fn booking_session_hash(session: &str) -> [u8; 32] {
    digest_with(SESSION_HASH_DOMAIN, session.as_bytes())
}
