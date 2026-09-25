//! Central purpose policy. Model bindings and vault overrides remain data.
use super::{CallEnvelope, CallPurpose, ModelLocality, ModelTierRef, TierPrecedence};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurposeDefault {
    pub tier: &'static str,
    pub locality: ModelLocality,
}

impl CallPurpose {
    pub fn default_policy(&self) -> Option<PurposeDefault> {
        Some(match self {
            Self::Extraction => PurposeDefault {
                tier: "extraction",
                locality: ModelLocality::OnDevice,
            },
            Self::Consolidation => PurposeDefault {
                tier: "consolidation",
                locality: ModelLocality::OwnServer,
            },
            Self::AnswerGen => PurposeDefault {
                tier: "answer",
                locality: ModelLocality::OnDevice,
            },
            Self::AutoCheck => PurposeDefault {
                tier: "cheap",
                locality: ModelLocality::OwnServer,
            },
            Self::ToolRouting => PurposeDefault {
                tier: "tiny-fast",
                locality: ModelLocality::OnDevice,
            },
            Self::Voice => PurposeDefault {
                tier: "voice",
                locality: ModelLocality::OnDevice,
            },
            Self::Eval => PurposeDefault {
                tier: "eval-pinned",
                locality: ModelLocality::OnDevice,
            },
            Self::Other { .. } => return None,
        })
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
            (
                CallPurpose::Extraction,
                PurposeDefault {
                    tier: "extraction",
                    locality: ModelLocality::OnDevice,
                },
            ),
            (
                CallPurpose::Consolidation,
                PurposeDefault {
                    tier: "consolidation",
                    locality: ModelLocality::OwnServer,
                },
            ),
            (
                CallPurpose::AnswerGen,
                PurposeDefault {
                    tier: "answer",
                    locality: ModelLocality::OnDevice,
                },
            ),
            (
                CallPurpose::AutoCheck,
                PurposeDefault {
                    tier: "cheap",
                    locality: ModelLocality::OwnServer,
                },
            ),
            (
                CallPurpose::ToolRouting,
                PurposeDefault {
                    tier: "tiny-fast",
                    locality: ModelLocality::OnDevice,
                },
            ),
            (
                CallPurpose::Voice,
                PurposeDefault {
                    tier: "voice",
                    locality: ModelLocality::OnDevice,
                },
            ),
            (
                CallPurpose::Eval,
                PurposeDefault {
                    tier: "eval-pinned",
                    locality: ModelLocality::OnDevice,
                },
            ),
        ];
        for (purpose, expected) in &purposes {
            assert_eq!(purpose.default_policy(), Some(*expected));
            let mut tier = TierPrecedence::for_purpose(purpose, ModelTierRef("global".into()));
            assert_eq!(tier.resolved().as_str(), expected.tier);
            tier.vault_policy = Some(ModelTierRef("vault".into()));
            assert_eq!(tier.resolved().as_str(), "vault");
            let envelope = CallEnvelope {
                scope: Default::default(),
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
