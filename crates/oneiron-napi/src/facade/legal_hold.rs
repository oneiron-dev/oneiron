//! Typed N-API projection of the engine-owned legal-hold notice.

use napi_derive::napi;
use oneiron::error::{LegalHoldBoundKind, LegalHoldNotice};

#[napi(object)]
pub struct NapiLegalHoldBound {
    pub kind: String,
    pub order_ref: Option<String>,
    pub legal_basis_ref: Option<String>,
    pub jurisdiction: Option<String>,
    pub issuing_authority_ref: Option<String>,
    /// Seconds since the epoch, as the other N-API timestamps carry it.
    pub ends_at: Option<i64>,
}

#[napi(object)]
pub struct NapiLegalHoldNotice {
    pub state: String,
    pub bound: NapiLegalHoldBound,
    pub works_self_hosted: bool,
    pub self_hosted_note: String,
}

pub(super) fn legal_hold_from_engine(notice: LegalHoldNotice) -> NapiLegalHoldNotice {
    let bound = notice.bound;
    NapiLegalHoldNotice {
        state: notice.state.as_str().to_owned(),
        bound: NapiLegalHoldBound {
            kind: match bound.kind {
                LegalHoldBoundKind::Law => "law".to_owned(),
            },
            order_ref: bound.order_ref,
            legal_basis_ref: bound.legal_basis_ref,
            jurisdiction: bound.jurisdiction,
            issuing_authority_ref: bound.issuing_authority_ref,
            ends_at: bound
                .ends_at
                .map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
        },
        works_self_hosted: notice.works_self_hosted,
        self_hosted_note: notice.self_hosted_note,
    }
}
