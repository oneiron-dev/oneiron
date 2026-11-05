# Derived standing consent grants

A standing consent-grant row has one issuer:

- `Owner(ConsentOwnerStamp)` records the authenticated owner decision.
- `System { principal_ref, decision_id, setting_ref, setting_owner }` records a closed system path carrying out an existing setting.

The only system origins are signature participation, failure-signal participation and booking-page publication. Each origin admits only its existing native outbound dial. It cannot mint a catastrophe or bypass grant. The ordinary owner-create and bypass doors still require and revalidate `AuthenticatedOwner`.

`setting_owner` is the setter named by the actual setting, when known. Booking publication can supply its recorded setter. Deployment export configuration and publisher settings that name no setter keep `None`. A missing setter does not withhold an otherwise admitted grant and never selects an arbitrary live or recorded owner. It does not require a new authenticated-setting API.

The mint writes the grant and its Approved Gate receipt in the same writer. It uses the existing grant reference and receipt family. A system receipt records `actor_class = "system"`, the system principal and setting reference, and the actual setter as `actor_ref` only when known. Quiet reuse keeps that issuer attribution. Generic grant reads, bound evaluation and revocation work for both issuer variants.

Checks that require an owner's own issuance still require the `Owner` variant. System setting provenance is not an owner delegation, bypass proof, owner-reason confirmation or undo. Owner-reason matching retains both the actual actor and that issuance's decision id. Revoking or replacing a grant still retires its old owner-reason rules.

## Stored format

`CONSENT_GRANT_SCHEMA_VERSION` is **2**. The strict MessagePack row uses `issuer` instead of `owner_stamp`. An owner issuer contains `kind` and `stamp`; a system issuer contains `kind`, `principal_ref`, `decision_id`, `setting_ref` and a required `setting_owner` value that is either an entity reference or Nil. Unknown keys, duplicate keys, malformed references and other schema versions are rejected. There is no old-format reader or migration.

This changes no runtime setting, cap, default, timeout, SDK verb or public registry display field. A rollout uses a matching engine format; it does not upgrade an old vault. No worker, VM, kel or bel action is part of this source change.
