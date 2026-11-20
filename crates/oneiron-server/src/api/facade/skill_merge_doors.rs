//! The owner's ingress door for a shared-skill merge offer under the caller's
//! owner proof (FIX [SKILL-HUB-PROMOTION-VERBS]). The merge stays the owner's
//! approve route (`POST /v1/owner/packs/skills/merges/{candidate}/approve`):
//! the useful-upstream question on the host's ladder, then the held-out replay
//! on the host's judge.
use std::sync::Arc;

use oneiron::task_verb::sdk::{self, *};

use super::host_doors::support::Listed;
use super::hub_doors::owner_call;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.skills.merges.offer`: it lists the base it read and the candidate
/// it staged.
pub(crate) async fn vault_skills_merges_offer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillMergeOfferRequest,
) -> Listed<oneiron::task_verb::sdk::SkillMergeOffered> {
    owner_call(
        server,
        auth,
        "vault.skills.merges.offer",
        move |server, owner| {
            let answer = sdk::skill_merge_offer_as_owner(server.vault(), owner, &input)?;
            let rows = vec![input.base, answer.candidate];
            Ok((answer, rows))
        },
    )
    .await
}
