//! Invocation replies live under the actual session and captured mode route.

use super::*;
use crate::runtime_hooks::InvocationId;
use crate::runtime_hooks::verb::InvocationEntry;

pub(super) struct SessionInvocations {
    route: SessionWriteRoute,
    claims: super::super::state::SessionInvocationClaims,
}

impl SessionHookKeep {
    pub(crate) fn claim_invocation(
        &self,
        vault: &Vault,
        key: &SessionHookKey,
        route: &SessionWriteRoute,
        invocation: InvocationId,
        body: [u8; 32],
    ) -> Result<Option<InvocationEntry>> {
        self.with_live(vault, key, |kept| {
            route.revalidate()?;
            if let Some(previous) = &kept.invocations {
                let stale = match previous.route.revalidate() {
                    Ok(()) => !Arc::ptr_eq(previous.route.overlay(), route.overlay()),
                    Err(Error::OffRecord(OffRecordError::OffRecordOverlayLeaseClosed {
                        ..
                    })) => true,
                    Err(error) => return Err(error),
                };
                if stale {
                    kept.invocations = None;
                }
            }
            let owner = kept.invocations.get_or_insert_with(|| SessionInvocations {
                route: route.clone(),
                claims: Default::default(),
            });
            let entry = owner.claims.claim(vault, invocation, body);
            route.revalidate()?;
            Ok(entry)
        })
        .transpose()
    }
}
