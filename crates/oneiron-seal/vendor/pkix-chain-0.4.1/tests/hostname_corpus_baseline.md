# Hostname-binding corpus — pass-rate baseline

Pass-rate baseline for the curated RFC 6125 hostname-binding corpus
exercised by `tests/hostname_corpus.rs` against
`pkix_chain::verify_tls_server`.

Tracks PKIX-fmtv.22. Companion to `tests/fixtures/gen.py` (fixture
production via pyca/cryptography) and `tests/verify_tls_server.rs` (the
smaller smoke-test surface for the same wrapper).

## Scope

Each corpus case asserts that `verify_tls_server` produces a specific
outcome for a given `(fixture, target hostname or IP, profile)` triple.
The mailbox-side sibling `tests/mailbox_corpus.rs` does the same for
S/MIME bindings (PKIX-fmtv.23).

## Baseline

27 of 27 corpus tests pass on the current implementation
(`pkix-chain 0.4.0`, `pkix-identity 0.1.0`, `pkix-path 1.2.0`).

| # | Test | Fixture | Target | Expected | Status |
|---|---|---|---|---|---|
| 1 | `exact_match` | `host-exact-foo.der` | `foo.example.com` | Ok | pass |
| 2 | `exact_mismatch` | `host-exact-foo.der` | `bar.example.com` | NoMatchingSan | pass |
| 3 | `exact_parent_does_not_match` | `host-exact-foo.der` | `example.com` | NoMatchingSan | pass |
| 4 | `wildcard_matches_single_label` | `host-wildcard.der` | `foo.example.com` | Ok | pass |
| 5 | `wildcard_does_not_match_parent` | `host-wildcard.der` | `example.com` | NoMatchingSan | pass |
| 6 | `wildcard_does_not_match_deeper_subdomain` | `host-wildcard.der` | `foo.bar.example.com` | NoMatchingSan | pass |
| 7 | `wildcard_partial_label_rejected` | `host-wildcard-partial-label.der` | `foo.example.com` | NoMatchingSan | pass |
| 8 | `wildcard_internal_label_rejected` | `host-wildcard-internal.der` | `foo.bar.example.com` | NoMatchingSan | pass |
| 9 | `wildcard_public_suffix_shape_rejected` | `host-wildcard-tld.der` | `foo.com` | NoMatchingSan | pass |
| 10 | `case_folding_san_upper_target_lower` | `host-mixed-case-san.der` | `foo.example.com` | Ok | pass |
| 11 | `case_folding_san_lower_target_upper` | `host-exact-foo.der` | `FOO.example.com` | Ok | pass |
| 12 | `idn_alabel_san_alabel_target` | `host-idn-alabel.der` | `xn--bcher-kva.example` | Ok | pass |
| 13 | `idn_ulabel_target_normalizes_to_alabel` | `host-idn-alabel.der` | `bücher.example` (U-label) | Ok | pass |
| 14 | `ipv4_san_matches_ipv4_target` | `host-ipv4.der` | `192.0.2.5` | Ok | pass |
| 15 | `ipv4_san_mismatch` | `host-ipv4.der` | `192.0.2.6` | NoMatchingSan | pass |
| 16 | `ipv6_san_matches_ipv6_target` | `host-ipv6.der` | `2001:db8::1` | Ok | pass |
| 17 | `ipv6_san_mismatch` | `host-ipv6.der` | `2001:db8::2` | NoMatchingSan | pass |
| 18 | `ipv4_san_does_not_match_ipv6_target` | `host-ipv4.der` | `2001:db8::42` | NoMatchingSan | pass |
| 19 | `dns_san_does_not_satisfy_ip_target` | `host-exact-foo.der` | `192.0.2.5` (IP) | NoMatchingSan | pass |
| 20 | `multi_san_first_entry_matches` | `host-multi-san.der` | `api.example.com` | Ok | pass |
| 21 | `multi_san_middle_entry_matches` | `host-multi-san.der` | `www.example.com` | Ok | pass |
| 22 | `multi_san_wildcard_entry_matches` | `host-multi-san.der` | `static.cdn.example.com` | Ok | pass |
| 23 | `multi_san_no_entry_matches` | `host-multi-san.der` | `other.example.com` | NoMatchingSan | pass |
| 24 | `missing_san_extension_rejected` | `leaf-no-san.der` | `foo.example.com` | MissingSan | pass |
| 25 | `basictls_profile_exact_match` | `host-exact-foo.der` | `foo.example.com` (BasicTls) | Ok | pass |
| 26 | `empty_target_rejected_at_parse` | n/a (parse only) | `""` | parse error | pass |
| 27 | `wildcard_target_rejected_at_parse` | n/a (parse only) | `*.example.com` | parse error | pass |

## Decisions pinned by the corpus

### Wildcard policy (RFC 6125 §6.4.2 + §7.2)

- **Leftmost-label-only.** Only an entire leftmost label may be `*`.
  Internal wildcards (`foo.*.example.com`) and partial-label wildcards
  (`f*o.example.com`) are not honored. Tests 7, 8.
- **Single-label expansion.** A leftmost `*.` matches exactly one
  label, never zero (no parent-domain match) and never more than one
  (no deeper-subdomain match). Tests 5, 6.
- **Public-suffix-shape refusal.** A SAN whose wildcard remainder has
  no internal `.` separator (`*.com`, `*.org`, etc.) is conservatively
  refused even though Public Suffix List enforcement proper is out of
  scope for the matcher. This matches webpki and browser behavior and
  is universally safe — the cases the structural check catches are
  always wrong even without a PSL. Test 9.

### Case folding (RFC 4343)

- ASCII DNS-name comparison is case-insensitive in both directions.
  `ServerName::dns_name` lowercases the caller-supplied target; the
  matcher additionally compares case-insensitively against SAN entries.
  Tests 10, 11.

### IDN (RFC 5891 + idna 2008)

- SANs are matched as A-labels (real-world CAs do not emit U-labels).
  `ServerName::dns_name` accepts a U-label target and normalizes it to
  A-label form via idna 2008 before the matcher runs. End-to-end:
  caller passes either form, U-label converts client-side, match
  happens in A-label space. Tests 12, 13.

### IP literals (RFC 5280 §4.2.1.6)

- IP SAN entries are byte-equal compared against the target's
  canonical 4- or 16-octet form. Lengths must match exactly: an IPv4
  SAN does not satisfy an IPv6 target (test 18) and vice versa.
- DNS-name SANs never satisfy an IP-literal target, even when the SAN
  entry textually parses as an IP (test 19). The matcher dispatches on
  the SAN entry's `GeneralName` variant.
- `ServerName::ip_address` rejects IPv4-in-IPv6 mapped forms
  (`::ffff:192.0.2.5`) at parse time per RFC 5952 strictness; future
  extension can accept them by canonicalizing to the 4-octet form.

### SAN-absent rejection (RFC 6125 §6.4.4)

- A leaf with no SAN extension is rejected with `MissingSan` regardless
  of what its Subject DN's CN attribute contains. CN-fallback is
  deprecated; the wrapper deliberately does not consult it. Test 24.

## Out of scope

- **Differential testing against OpenSSL.** OpenSSL's
  `X509_check_host` is the differential oracle bead PKIX-fmtv.18
  scopes; the corpus here is the hand-curated cert source it would
  consume.
- **Differential testing against pyca/cryptography.** pyca's
  `ServerVerifier` is PKIX-fmtv.19's oracle; same consumption pattern.
- **x509-limbo `webpki` suite.** x509-limbo contains hundreds of RFC
  6125-shaped cases; consuming it cross-crate would require pulling
  the corpus through pkix-difftest into pkix-chain tests, which crosses
  a layering boundary. The corpus here is hand-curated and
  self-contained inside pkix-chain. Future expansion via x509-limbo
  belongs in pkix-difftest's differential harness, not in this
  per-wrapper corpus.
- **`verify_tls_client_dns` corpus coverage.** The DNS-name client
  wrapper shipped under PKIX-fmtv.11.2 with its own smaller
  smoke-test surface (`tests/verify_tls_client.rs`). Re-running this
  hostname corpus against `verify_tls_client_dns` would duplicate
  identical matcher coverage — `verify_dns_name` is shared by both
  wrappers — and is intentionally not done here.
- **Mailbox / rfc822Name binding.** That's PKIX-fmtv.23 (shipped) —
  see `tests/mailbox_corpus_baseline.md`.
- **Public Suffix List enforcement.** Out of scope per the
  `pkix-identity` rustdoc; the structural single-label-remainder check
  (test 9) is the closest the workspace comes.
- **Malformed iPAddress extension.** `x509.IPAddress` is typed at the
  pyca layer (`ipaddress.IPv4Address`/`IPv6Address`), so producing a
  malformed SAN value requires raw DER construction. Robustness against
  malformed IP SAN encoding is `pkix-identity` unit-test territory; the
  wrapper corpus exercises only the structural behavior.

## How to regenerate the corpus

```sh
/home/mark/PROJECT/PKIX/pkix-difftest/python/.venv/bin/python3 \
    pkix-chain/tests/fixtures/gen.py
cargo test -p pkix-chain --test hostname_corpus
```

Regenerating issues new keys (P-256 ECDSA) for the root and every leaf;
the `verify_tls_server.rs` smoke tests and the sibling
`mailbox_corpus.rs` are tolerant of the change because they validate
the chain at runtime rather than pinning specific signatures.
