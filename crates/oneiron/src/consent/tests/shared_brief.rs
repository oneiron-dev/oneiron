use super::*;

/// A stored share maximum is never static disclosure authority, even when active.
#[test]
fn consent_shared_brief_generic_projection_is_rejected_and_not_active() {
    use std::collections::BTreeSet;

    use crate::access_grant::{
        AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
        decode_access_grant_body, encode_access_grant_body,
    };

    let access = AccessGrant {
        authority_scope: crate::federation::scope_codec::read_preset(),
        principal_ref: entity(0x51),
        scope: AccessGrantScope::SharedBrief {
            brief_ref: "brief:opaque".to_owned(),
            world_refs: BTreeSet::from([entity(0x61), entity(0x62)]),
            facet_refs: BTreeSet::from([entity(0x71)]),
            include_unscoped: false,
        },
        capability: AccessGrantCapability::SharedBriefRead,
        status: AccessGrantStatus::Active,
        created_at: 42,
        revoked_at: None,
        expires_at: None,
    };
    let revoked = access.revoked(50).expect("revoke shared brief");
    for source in [&access, &revoked] {
        let before = encode_access_grant_body(source).expect("encode shared brief");
        assert_eq!(
            disclosure_grant_from_access_grant(source)
                .expect_err("shared brief requires live resolution")
                .kind(),
            ErrorKind::InvalidConsentBound
        );
        // Only Vault::resolve_share_for_view may resolve view authority after
        // rereading revocation and current recipient/claim scope. Neither an
        // active snapshot nor a revoked record may enter the generic live set.
        assert!(!access_grant_projection_is_active(source, 43));
        assert_eq!(
            encode_access_grant_body(source).expect("encode after rejection"),
            before
        );
        assert_eq!(
            decode_access_grant_body(&before).expect("decode shared brief"),
            *source
        );

        // Relabeling the capability cannot turn the owned share scope into
        // legacy selectors; the scope match must independently fail closed.
        for capability in [
            AccessGrantCapability::CompanionProfileRead,
            AccessGrantCapability::CalendarDisclosureRead,
        ] {
            let mispaired = AccessGrant {
                capability,
                ..source.clone()
            };
            assert_eq!(
                disclosure_grant_from_access_grant(&mispaired)
                    .expect_err("shared-brief scope cannot project")
                    .kind(),
                ErrorKind::InvalidConsentBound
            );
        }
    }
}
