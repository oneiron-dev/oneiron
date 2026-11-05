//! Bounded compilation proposals from principal-bound corrected deltas.

pub use crate::inbox::compilation_target::CompilationTarget;
use rmpv::Value;

use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSubject};
use crate::error::{Error, Result};

/// Claim-dependent validation of an inbox compilation choice.
pub(crate) trait CompilationTargetValidation {
    fn validate(&self) -> Result<()>;
}

impl CompilationTargetValidation for CompilationTarget {
    fn validate(&self) -> Result<()> {
        let Some(text) = self.text() else {
            return Ok(());
        };
        if text.trim().is_empty() || text.len() > 4096 {
            return Err(Error::InvalidClaimBody(
                "invalid preference compilation text",
            ));
        }
        if let Self::StyleRule(token) = self {
            // The OF-332 structural validator owns its token vocabulary.
            let body = ClaimBody::new(
                crate::claim::PREDICATE_COMPANION_EXPRESSION_STYLE,
                ClaimSubject::Entity(crate::entity_id::EntityId::now()),
                Value::from(token.as_str()),
                0.5,
                ClaimApprovalStatus::Proposed,
                crate::claim::ClaimLifecycleStatus::Active,
            )?;
            crate::claim::validate_expression_preference_claim_structure(&body)?;
        }
        Ok(())
    }
}

pub(crate) fn is_compiled_preference(predicate: &str) -> bool {
    matches!(
        predicate,
        "preference.ban"
            | "preference.style_rule"
            | "charter.line"
            | "brief.preference"
            | "preference.affirmed"
    )
}

/// Shared write/replay validation. A proposed routing decision cannot self-approve.
pub(crate) fn validate_compiled_preference(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_))
        || !matches!(
            body.approval,
            ClaimApprovalStatus::Proposed | ClaimApprovalStatus::Approved
        )
        || crate::claim::claim_principal_id(body)?.is_none()
    {
        return Err(Error::InvalidClaimBody(
            "compiled preference requires principal and review",
        ));
    }
    let Value::Map(entries) = &body.value else {
        return Err(Error::InvalidClaimBody(
            "compiled preference value must be a map",
        ));
    };
    let text = entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some("text"))
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>();
    let [Some(text)] = text.as_slice() else {
        return Err(Error::InvalidClaimBody(
            "compiled preference requires one text",
        ));
    };
    let target = match body.predicate.as_str() {
        "preference.ban" => CompilationTarget::Ban((*text).to_owned()),
        "preference.style_rule" => CompilationTarget::StyleRule((*text).to_owned()),
        "charter.line" => CompilationTarget::CharterLine((*text).to_owned()),
        _ => CompilationTarget::BriefUpdate((*text).to_owned()),
    };
    target.validate()
}
