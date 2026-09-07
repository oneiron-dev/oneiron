use super::*;

/// Borrowed legacy scopes retain their exact bounds, bytes, and active behavior.
#[test]
fn consent_access_grant_adapter_borrows_legacy_scopes_without_changing_projections() {
    use crate::access_grant::{
        AccessGrant, AccessGrantCapability, decode_access_grant_body, encode_access_grant_body,
    };
    use crate::booking::DisclosureRung;

    let principal = entity(0x51);
    let audience = principal.to_hex();
    let cases = [
        (
            AccessGrant::companion_profile_read(principal, entity(0xB1), entity(0xC1), 42),
            "companion_profile.read",
            [
                format!("person:{}", entity(0xB1).to_hex()),
                format!("persona:{}", entity(0xC1).to_hex()),
            ],
        ),
        (
            AccessGrant::calendar_disclosure(principal, entity(0xB2), DisclosureRung::Titles, 42),
            "calendar.disclosure_read",
            [
                format!("calendar:{}", entity(0xB2).to_hex()),
                "rung:titles".to_owned(),
            ],
        ),
    ];
    for (access, class, selectors) in cases {
        let expected = disclosure_bound(
            &[audience.as_str()],
            class,
            &[selectors[0].as_str(), selectors[1].as_str()],
        );
        let revoked = access.revoked(50).expect("revoke legacy grant");
        for (source, active) in [(&access, true), (&revoked, false)] {
            let before = encode_access_grant_body(source).expect("encode legacy grant");
            let projected =
                disclosure_grant_from_access_grant(source).expect("project borrowed grant");
            assert_eq!(projected.bound(), &expected);
            assert_eq!(access_grant_projection_is_active(source), active);
            assert_eq!(
                disclosure_grant_from_access_grant(source).expect("project same borrow again"),
                projected
            );
            assert_eq!(
                encode_access_grant_body(source).expect("encode after projection"),
                before
            );
            assert_eq!(
                decode_access_grant_body(&before).expect("decode legacy grant"),
                *source
            );
        }

        // An unvalidated legacy scope cannot launder a shared-brief read class.
        let mispaired = AccessGrant {
            capability: AccessGrantCapability::SharedBriefRead,
            ..access
        };
        assert_eq!(
            disclosure_grant_from_access_grant(&mispaired)
                .expect_err("shared-brief capability cannot project")
                .kind(),
            ErrorKind::InvalidConsentBound
        );
        assert!(!access_grant_projection_is_active(&mispaired));
    }
}

/// A stored share maximum is never static disclosure authority, even when active.
#[test]
fn consent_shared_brief_generic_projection_is_rejected_and_not_active() {
    use std::collections::BTreeSet;

    use crate::access_grant::{
        AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
        decode_access_grant_body, encode_access_grant_body,
    };

    let access = AccessGrant {
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
        assert!(!access_grant_projection_is_active(source));
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
