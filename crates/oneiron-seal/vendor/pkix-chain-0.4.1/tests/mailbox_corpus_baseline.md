# Mailbox-binding corpus — pass-rate baseline

Pass-rate baseline for the curated RFC 5280 §4.2.1.6 / RFC 8398 mailbox-
binding corpus exercised by `tests/mailbox_corpus.rs` against
`pkix_chain::verify_smime_signer` and `pkix_chain::verify_smime_recipient`.

Tracks PKIX-fmtv.23. Companion to `tests/fixtures/gen.py` (fixture
production via pyca/cryptography) and `tests/verify_smime.rs` (small
smoke-test surface for the same wrappers).

## Scope

Each corpus case asserts that **both** `verify_smime_signer` and
`verify_smime_recipient` produce the same outcome for a given
`(fixture, target mailbox, profile)` triple. The two wrappers have
byte-identical bodies; the corpus is the regression bar that keeps them
aligned.

## Baseline

22 of 22 corpus tests pass on the current implementation
(`pkix-chain 0.4.0`, `pkix-identity 0.1.0`, `pkix-path 1.2.0`).

| # | Test | Fixture | Target | Profile | Expected | Status |
|---|---|---|---|---|---|---|
| 1 | `rfc822_exact_match` | `mailbox-rfc822-user-example.der` | `user@example.com` | Rfc5280 | Ok | pass |
| 2 | `rfc822_local_part_mismatch` | `mailbox-rfc822-user-example.der` | `other@example.com` | Rfc5280 | NoMatchingSan | pass |
| 3 | `rfc5321_domain_case_insensitive_san_to_target` | `mailbox-rfc822-user-EXAMPLE.der` | `user@example.com` | Rfc5280 | Ok | pass |
| 4 | `rfc5321_domain_case_insensitive_target_to_san` | `mailbox-rfc822-user-example.der` | `user@EXAMPLE.com` | Rfc5280 | Ok | pass |
| 5 | `rfc5321_local_part_case_sensitive_strict` | `mailbox-rfc822-User-example.der` | `user@example.com` | Rfc5280 | NoMatchingSan | pass |
| 6 | `rfc5321_local_part_case_sensitive_strict_inverted` | `mailbox-rfc822-user-example.der` | `User@example.com` | Rfc5280 | NoMatchingSan | pass |
| 7 | `smtputf8_only_internationalized_match` | `mailbox-smtputf8-only.der` | `用户@example.com` | Rfc5280 | Ok | pass |
| 8 | `smtputf8_only_does_not_match_ascii_target` | `mailbox-smtputf8-only.der` | `user@example.com` | Rfc5280 | NoMatchingSan | pass |
| 9 | `mixed_san_ascii_target_binds_rfc822` | `mailbox-mixed.der` | `user@example.com` | Rfc5280 | Ok | pass |
| 10 | `mixed_san_i18n_target_binds_smtputf8` | `mailbox-mixed.der` | `用户@example.com` | Rfc5280 | Ok | pass |
| 11 | `mixed_san_unrelated_target_rejected` | `mailbox-mixed.der` | `stranger@example.com` | Rfc5280 | NoMatchingSan | pass |
| 12 | `multi_rfc822_first_match` | `mailbox-multi-rfc822.der` | `alpha@example.com` | Rfc5280 | Ok | pass |
| 13 | `multi_rfc822_middle_match` | `mailbox-multi-rfc822.der` | `beta@example.com` | Rfc5280 | Ok | pass |
| 14 | `multi_rfc822_last_match` | `mailbox-multi-rfc822.der` | `gamma@example.com` | Rfc5280 | Ok | pass |
| 15 | `multi_rfc822_no_match` | `mailbox-multi-rfc822.der` | `delta@example.com` | Rfc5280 | NoMatchingSan | pass |
| 16 | `dns_only_san_rejects_mailbox_under_rfc5280` | `mailbox-dns-only.der` | `user@example.com` | Rfc5280 | NoMatchingSan | pass |
| 17 | `dns_only_san_rejects_at_path_under_basicsmime` | `mailbox-dns-only.der` | `user@example.com` | BasicSmime | Path(MissingRfc822San) | pass |
| 18 | `missing_san_extension` | `leaf-no-san.der` | `user@example.com` | Rfc5280 | MissingSan | pass |
| 19 | `rfc822_san_without_at_sign_is_not_a_match` | `mailbox-rfc822-malformed-no-at.der` | `user@example.com` | Rfc5280 | NoMatchingSan | pass |
| 20 | `smtputf8_malformed_utf8_is_not_a_match` | `mailbox-smtputf8-bad-utf8.der` | `用户@example.com` | Rfc5280 | NoMatchingSan | pass |
| 21 | `empty_input_rejected_at_parse` | n/a (parse only) | `""` | n/a | parse error | pass |
| 22 | `quoted_local_part_rejected_at_parse` | n/a (parse only) | `"a b"@example.com` | n/a | parse error | pass |

## Decision: RFC 5321 §2.4 local-part case sensitivity

The bead PKIX-fmtv.23 flagged a corpus decision-gate: enforce strict
RFC 5321 §2.4 local-part case sensitivity (byte-equal), or follow
real-world tolerant matching (`equalsIgnoreCase` over the whole
addr-spec)?

**Decision: strict.** The shipped matcher in
`pkix_identity::matches_rfc822_mailbox` compares the local-part with
`!=` (byte equality) and the domain with `eq_ignore_ascii_case`. Tests
5 and 6 above pin that contract.

Rationale:

- RFC 5321 §2.4 reserves the local-part case-sensitivity decision to
  the receiving domain. A consumer verifying *outbound* identity (e.g.
  whom did this S/MIME signature claim to be from) has no way to
  consult the recipient domain's policy, so the conservative choice is
  byte-equal. Loosening to case-insensitive risks accepting a
  signature from `Alice@example.com` against a target of
  `alice@example.com` when the upstream domain treats those as distinct
  mailboxes.
- pyca/cryptography and webpki both make the same choice; matching
  their behavior preserves the cross-implementation invariant the
  workspace's differential testing relies on.

Tolerant matching can be re-introduced as a future opt-in profile
(`TolerantSmimeProfile`?) by adding a flag to `ValidationPolicy` and
threading it into the matcher. Out of scope for PKIX-fmtv.23; would
require its own bead with a clear deployment story.

## Behavior pinned for malformed-but-DER-valid SAN content

Two negative cases exercise the "structurally well-formed SAN entry
whose value bytes violate higher-layer rules" path:

- **`mailbox-rfc822-malformed-no-at.der`** — the rfc822Name SAN value
  is `no-at-sign`, a syntactically valid `IA5String` that does not
  contain `@`. The matcher's `rsplit_once('@')` returns `None`, the
  entry yields no match, and (since this is the only SAN entry) the
  wrapper returns `Err(Error::Identity(IdentityError::NoMatchingSan))`.
  The matcher does **not** treat this as `MalformedSan`.

- **`mailbox-smtputf8-bad-utf8.der`** — the `otherName(SmtpUTF8Mailbox)`
  carries a `UTF8String` whose tag is correct but whose value bytes
  are not valid UTF-8. `decode_utf8_string_any` returns
  `IdentityError::MalformedSan`, but
  `pkix_identity::san_entry_matches_mailbox` swallows the error
  (`Err(_) => false`) and treats the entry as a non-match. The wrapper
  reports `NoMatchingSan`, not `MalformedSan`.

Both behaviors match the shipped implementation in
`pkix-identity/src/lib.rs:458–471`. If a future change wants to
surface malformed entries as `MalformedSan` to the caller, both this
baseline and the matcher need updating in the same change.

## Out of scope

- **Differential testing against OpenSSL.** OpenSSL's `s_smime` /
  `openssl smime -verify` is the differential oracle bead PKIX-fmtv.18
  scopes; the corpus here is the hand-curated cert source it would
  consume.
- **Differential testing against pyca/cryptography.** pyca does not
  ship an S/MIME verifier; PKIX-fmtv.19 documents this scope gap.
- **Code-signing / time-stamping wrappers.** Those wrappers carry no
  caller-supplied identity target and so have no curated-corpus need;
  `tests/verify_code_signing.rs` and `tests/verify_time_stamper.rs`
  cover them with targeted unit tests.
- **Profiles other than `Rfc5280Profile` and `BasicSmimeProfile`.**
  CA/B Forum S/MIME BR adds further constraints (mailbox validation
  levels, key-size floors, validity caps). Those belong to
  `pkix-profiles-cabf::SmimeProfile` and its own coverage.

## How to regenerate the corpus

```sh
/home/mark/PROJECT/PKIX/pkix-difftest/python/.venv/bin/python3 \
    pkix-chain/tests/fixtures/gen.py
cargo test -p pkix-chain --test mailbox_corpus
```

Regenerating issues new keys (P-256 ECDSA) for the root and every leaf;
the `verify_smime.rs` smoke tests are tolerant of the change because
they validate the chain at runtime rather than pinning specific
signatures.
