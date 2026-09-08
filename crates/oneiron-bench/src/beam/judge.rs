//! Pinned majority-judge substrate.

use super::model::JudgeMetadata;
use super::util::hex_lower;
use super::{BeamError, BeamResult};

#[allow(dead_code)]
pub(super) mod majority_judge {
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};

    use super::{BeamError, BeamResult, JudgeMetadata, hex_lower};

    pub(crate) const JUDGE_VOTE_COUNT: usize = 3;

    #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub(crate) struct AnswerPromptPin {
        pub(crate) content: String,
        pub(crate) sha256: String,
    }

    pub(crate) fn single_judge_vote() -> u8 {
        1
    }

    impl AnswerPromptPin {
        /// Pins the answer-generation prompt exactly as it is sent: the unmodified UTF-8 bytes are
        /// hashed with SHA-256 and stored as lowercase hexadecimal beside the verbatim content, so the
        /// card is self-contained and independently checkable. No trimming, newline normalization,
        /// whitespace canonicalization, or second interpolation happens before hashing.
        pub(crate) fn from_exact_text(content: &str) -> Self {
            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            Self {
                content: content.to_owned(),
                sha256: hex_lower(&hasher.finalize()),
            }
        }

        /// True only when this pin is byte-identical to the pin `content` would produce: the stored
        /// content equals `content` and the stored digest is the digest of those exact bytes.
        pub(crate) fn matches_exact_text(&self, content: &str) -> bool {
            *self == Self::from_exact_text(content)
        }
    }

    impl JudgeMetadata {
        /// Gate for the LLM-majority judge boundary: the caller must run this before its first external
        /// judge call. It never repairs the card, substitutes the runtime prompt, or hashes a prompt
        /// label; a missing pin, wrong vote count, malformed digest, or runtime/card prompt mismatch is
        /// reported as [`BeamError::JudgeCardInvalid`] and no judge call is made.
        pub(crate) fn require_majority_vote_card(
            &self,
            exact_answer_prompt: &str,
        ) -> BeamResult<()> {
            if self.judge_id.trim().is_empty() {
                return Err(BeamError::JudgeCardInvalid {
                    reason: "judge ids must not be empty".to_owned(),
                });
            }
            if self.version.trim().is_empty() {
                return Err(BeamError::JudgeCardInvalid {
                    reason: "judge versions must not be empty".to_owned(),
                });
            }
            if usize::from(self.vote_count) != JUDGE_VOTE_COUNT {
                return Err(BeamError::JudgeCardInvalid {
                    reason: format!("majority judgments require voteCount {JUDGE_VOTE_COUNT}"),
                });
            }
            let Some(pin) = self.answer_prompt.as_ref() else {
                return Err(BeamError::JudgeCardInvalid {
                    reason: "majority judgments require a pinned answerPrompt".to_owned(),
                });
            };
            if pin.content.trim().is_empty() {
                return Err(BeamError::JudgeCardInvalid {
                    reason: "pinned answerPrompt content must not be empty".to_owned(),
                });
            }
            if !pin.matches_exact_text(&pin.content) {
                return Err(BeamError::JudgeCardInvalid {
                    reason: "pinned answerPrompt sha256 does not match its content".to_owned(),
                });
            }
            if !pin.matches_exact_text(exact_answer_prompt) {
                return Err(BeamError::JudgeCardInvalid {
                    reason: "runtime answer prompt does not match the card pin".to_owned(),
                });
            }

            Ok(())
        }
    }

    #[derive(Debug)]
    pub(crate) enum MajorityVoteError<V, E> {
        CallFailures {
            attempts: [Result<V, E>; JUDGE_VOTE_COUNT],
        },
        Tie {
            votes: [V; JUDGE_VOTE_COUNT],
        },
    }

    #[derive(Debug)]
    pub(crate) struct MajorityDecision<V> {
        pub(crate) verdict: V,
        pub(crate) vote_count: usize,
    }

    /// Runs one logical judgment as exactly [`JUDGE_VOTE_COUNT`] independent judge calls at indices
    /// `0`, `1`, and `2`, and decides only after all three return.
    ///
    /// The caller supplies the same immutable item, candidate answer, judge instructions, judge
    /// id/version, and pinned answer-prompt declaration to every call, and never feeds an earlier vote,
    /// error, or rationale back in; those are transport obligations this layer cannot verify. What this
    /// layer does enforce is call count, index order, and fail-closed aggregation: two agreeing votes do
    /// not short-circuit the third call, a failing call does not short-circuit the remaining calls, and
    /// a provider-side retry inside one call stays that call's transport policy rather than a fourth
    /// vote. Any call failure yields [`MajorityVoteError::CallFailures`] with the three typed outcomes
    /// and no verdict; three distinct successful votes yield [`MajorityVoteError::Tie`] with no verdict.
    /// A decision therefore always carries the winning tally, `2` or `3`, never the attempted count.
    pub(crate) fn majority_of_three<V, E, F>(
        judge_call: F,
    ) -> Result<MajorityDecision<V>, MajorityVoteError<V, E>>
    where
        V: Clone + Eq,
        F: FnMut(usize) -> Result<V, E>,
    {
        // `from_fn` walks the array forward, so the call indices are 0, 1, 2 in that order, and every
        // index is called before any outcome is inspected.
        let attempts: [Result<V, E>; JUDGE_VOTE_COUNT] = std::array::from_fn(judge_call);
        let votes = match attempts {
            [Ok(first), Ok(second), Ok(third)] => [first, second, third],
            attempts => return Err(MajorityVoteError::CallFailures { attempts }),
        };

        let [first, second, third] = votes;
        if first == second && second == third {
            return Ok(MajorityDecision {
                verdict: first,
                vote_count: JUDGE_VOTE_COUNT,
            });
        }
        if first == second || first == third {
            return Ok(MajorityDecision {
                verdict: first,
                vote_count: 2,
            });
        }
        if second == third {
            return Ok(MajorityDecision {
                verdict: second,
                vote_count: 2,
            });
        }

        Err(MajorityVoteError::Tie {
            votes: [first, second, third],
        })
    }

    #[derive(Debug)]
    pub(crate) enum MajorityJudgeError<V, E> {
        Card(BeamError),
        Vote(MajorityVoteError<V, E>),
    }

    /// Composed LLM-majority judge boundary: validate the card against the runtime answer prompt first,
    /// then run the three-call majority. A rejected card invokes `judge_call` zero times, so no stale
    /// answer-prompt pin can accompany an emitted verdict.
    pub(crate) fn run_majority_judge_card<V, E, F>(
        metadata: &JudgeMetadata,
        exact_answer_prompt: &str,
        judge_call: F,
    ) -> Result<MajorityDecision<V>, MajorityJudgeError<V, E>>
    where
        V: Clone + Eq,
        F: FnMut(usize) -> Result<V, E>,
    {
        metadata
            .require_majority_vote_card(exact_answer_prompt)
            .map_err(MajorityJudgeError::Card)?;
        majority_of_three(judge_call).map_err(MajorityJudgeError::Vote)
    }
}
pub(crate) use majority_judge::*;
