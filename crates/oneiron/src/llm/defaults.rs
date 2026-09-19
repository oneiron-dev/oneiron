//! Central purpose policy. Model bindings and vault overrides remain data.
use super::{CallEnvelope, CallPurpose, ModelLocality, ModelTierRef, TierPrecedence};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurposeDefault {
    pub tier: &'static str,
    pub locality: ModelLocality,
}

/// The seven built-in purpose defaults, in CallPurpose declaration order.
pub const PURPOSE_DEFAULTS: [PurposeDefault; 7] = [
    PurposeDefault {
        tier: "extraction",
        locality: ModelLocality::OnDevice,
    },
    PurposeDefault {
        tier: "consolidation",
        locality: ModelLocality::OwnServer,
    },
    PurposeDefault {
        tier: "answer",
        locality: ModelLocality::OnDevice,
    },
    PurposeDefault {
        tier: "cheap",
        locality: ModelLocality::OwnServer,
    },
    PurposeDefault {
        tier: "tiny-fast",
        locality: ModelLocality::OnDevice,
    },
    PurposeDefault {
        tier: "voice",
        locality: ModelLocality::OnDevice,
    },
    PurposeDefault {
        tier: "eval-pinned",
        locality: ModelLocality::OnDevice,
    },
];
impl CallPurpose {
    pub fn default_policy(&self) -> Option<PurposeDefault> {
        let index = match self {
            Self::Extraction => 0,
            Self::Consolidation => 1,
            Self::AnswerGen => 2,
            Self::AutoCheck => 3,
            Self::ToolRouting => 4,
            Self::Voice => 5,
            Self::Eval => 6,
            Self::Other { .. } => return None,
        };
        Some(PURPOSE_DEFAULTS[index])
    }
}
impl CallEnvelope {
    /// Apply central purpose defaults during construction, before explicit host or
    /// manifest overrides. Custom purposes retain their supplied global defaults.
    pub fn with_purpose_defaults(mut self) -> Self {
        if let Some(policy) = self.purpose.default_policy() {
            self.tier.purpose_default = Some(ModelTierRef(policy.tier.into()));
            self.locality = policy.locality;
        }
        self
    }
}
impl TierPrecedence {
    pub fn for_purpose(purpose: &CallPurpose, global_default: ModelTierRef) -> Self {
        Self {
            per_call: None,
            vault_policy: None,
            purpose_default: purpose
                .default_policy()
                .map(|p| ModelTierRef(p.tier.into())),
            global_default,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_builtin_resolves_to_its_policy_without_overriding_the_vault() {
        let purposes = [
            CallPurpose::Extraction,
            CallPurpose::Consolidation,
            CallPurpose::AnswerGen,
            CallPurpose::AutoCheck,
            CallPurpose::ToolRouting,
            CallPurpose::Voice,
            CallPurpose::Eval,
        ];
        for (purpose, expected) in purposes.iter().zip(PURPOSE_DEFAULTS) {
            assert_eq!(purpose.default_policy(), Some(expected));
            let mut tier = TierPrecedence::for_purpose(purpose, ModelTierRef("global".into()));
            assert_eq!(tier.resolved().as_str(), expected.tier);
            tier.vault_policy = Some(ModelTierRef("vault".into()));
            assert_eq!(tier.resolved().as_str(), "vault");
            let envelope = CallEnvelope {
                purpose: purpose.clone(),
                class: super::super::CallClass::BestEffort,
                tier,
                response_format: super::super::ResponseFormat::Text,
                locality: ModelLocality::ThirdParty,
            }
            .with_purpose_defaults();
            assert_eq!(envelope.locality, expected.locality);
            assert_eq!(envelope.tier.resolved().as_str(), "vault");
        }
    }
}
