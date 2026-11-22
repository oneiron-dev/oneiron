//! The owner's held-out admission door for a hub skill under the caller's
//! owner proof (FIX [SKILL-HUB-PROMOTION-VERBS]). The ask stays the owner's
//! prepare route and the answer to a permission widening its approve route
//! (`POST /v1/owner/packs/skills/{entity}/activation/{prepare,approve}`).
use std::sync::Arc;

use oneiron::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError};
use oneiron::task_verb::sdk::{self, *};

use super::host_doors::support::Listed;
use super::hub_doors::owner_call;
use crate::auth::CoreAuth;
use crate::replay_judge;
use crate::server::SyncServer;

/// `vault.skills.activation.admit`: the host's registered held-out judge
/// scores the ask; it lists the candidate and the evidence baseline it read.
pub(crate) async fn vault_skills_activation_admit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillActivationAdmitRequest,
) -> Listed<oneiron::task_verb::sdk::SkillActivationAdmitReceipt> {
    owner_call(
        server,
        auth,
        "vault.skills.activation.admit",
        move |server, owner| {
            let judge = replay_judge::registered().ok_or_else(|| {
                MemoryError::new(
                    MEMORY_CODE_MODEL_UNAVAILABLE,
                    "no skill judge is registered",
                    &[],
                )
            })?;
            let answer =
                sdk::skill_activation_admit_as_owner(server.vault(), owner, &input, judge)?;
            Ok((answer, vec![input.entity, input.evidence_skill]))
        },
    )
    .await
}
