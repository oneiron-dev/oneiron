# Seal profiles and audit evidence

A successful seal records each item's actual profile evidence. `SealProfileEvidence`
contains `requested`, `achieved`, and the complete `degraded` list. The profiles are
`baseline_b`, `baseline_t`, `baseline_lt`, and `baseline_lta`.

Each degradation entry retains its own requested and achieved profiles. Its typed
reason is one of the native sealer's codes:

- `timestamp_unavailable`
- `validation_material_unavailable`
- `document_timestamp_unavailable`

The organ host decodes these codes directly into the engine's mirror enum. It does
not infer a reason from prose. The degradation codes and profile fields in the
organ reply are unchanged.

## Persistence and reads

After the existing self-verification, independent verification, profile-coherence
and evidence-hash checks pass, the seal task retains every item's evidence. In the
same existing writer transaction, it writes:

- `SealedItem.profile` in the sealed manifest and completed-attempt result;
- `EsignEvent::Sealed.item_profiles` in the terminal audit event, in the same item
  order as `item_sha256` and the manifest.

`vault.esign.seal.get` returns this evidence in each sealed item's `profile`.
`vault.esign.get` carries it in the existing audit trail. The profile fields are
required in the current record format; there is no old-format reader or backfill.
This records a verified shortfall, including a timestamp outage that reaches only
B-B. It does not change which shortfalls the sealer permits, the verification
verdict, consent, signing authority, provenance, notices, or completion policy.

## Verification reason names

For the standard-covered failures, native reports serialize digest mismatches as
`HASH_FAILURE` and signature-value failures as `SIG_CRYPTO_FAILURE`. Rust variant
names and the corresponding checks are unchanged. PDF-specific findings keep their
existing custom names.

## Active-content observations

Native `VerifyReport.active_content` records the resolved `JavaScript` and `Launch`
action subtypes found in the parsed PDF object graph, including nested arrays,
dictionaries and stream dictionaries. Indirect objects are each visited as roots;
security-name reference chains use the existing resolver. The two boolean fields
are observations, not a safety certificate or a change to verification policy.

The organ reply carries these facts as a typed field beside the full report JSON.
After the existing independent verification and evidence-hash checks, the seal task
stores them in each `SealedItem.active_content`, in the manifest and attempt result.
`vault.esign.seal.get` exposes the same field per item. The public signer's terminal
`SigningOutcome` also carries `sealed_items`, in document item order, with each
sealed SHA-256 and its facts. That optional list is `None` if no receipt can be read;
it does not mean that active content was ruled out. No internal artifact refs are
added to this signer response.

These facts describe the verified sealed bytes, not the original before visual
preparation. Existing preparation refusals, consent, capability and lane checks,
cryptographic checks, profiles, verdicts and terminal outcomes do not change.

## Revision coverage evidence

Each native signature report includes `revision_coverage` alongside the
existing `coverage` value. It is `null` if a valid byte range or a structural
revision boundary cannot be established. Otherwise its typed `kind` is
`whole_revision` or `partial`, with the revision index and its structural
EOF offset in `byte_end`.

A partial fact includes `uncovered` byte ranges with half-open `start` and
`end` offsets. These name unsigned bytes between the signed prefix and the
containing revision's EOF. The required signature `/Contents` exclusion is
not a coverage shortfall. The existing EOF/CR-LF boundary rule is unchanged.
A fact about an older revision does not claim that later appends are signed.

This is additive evidence only. Profiles are not withheld or changed, and
signature integrity, trust, timestamps, modification checks, verdicts and
self-verification keep their existing rules. Rebuild and hash-pin the
native seal organ to publish the new report field.

## Rollout

Use the matching engine/server and regenerated clients for the new manifest/view
fields. Rebuild and hash-pin the matching seal organ to publish the required
active-content facts and corrected verification reason names. The organ's request
schemas and degradation wire codes do not change.
No storage ABI, dependency, config, numerical default, migration, or backward
compatibility path is added. This is reporting carriage, not a runtime seal,
memory-closure, or cryptographic-correctness result.

## Unsupported signature envelopes

Verification includes reachable signature fields with
`/SubFilter /adbe.pkcs7.detached`, including the typeless signature shape.
Each envelope retains its byte-range, coverage and digest evidence. Its
cryptographic and signer-path checks are `not_run` with the typed finding
`unsupported_signature_handler`; the verifier does not parse its CMS or
validate it as CAdES. No signer or timestamp chain, trusted time proof or
PAdES profile is inferred from that envelope.

A structurally valid unsupported envelope has indeterminate integrity and
`not_run` trust. Invalid byte ranges still fail their structural checks.
The existing report rollup remains unchanged: `not_run` is not `pass`, so
an unsupported envelope cannot make the document pass self-verification.
Supported CAdES and document-timestamp handlers retain their validation.
The finding travels in the existing per-envelope `checks` array; the
report's top-level `reasons` does not list it (`reasons` holds failures, and
only the possible-tampering sub-indication below among `not_run` findings).
Rebuild and hash-pin the native seal organ to publish this reporting change.

## Unresolved DSS evidence

DSS verification distinguishes invalid evidence from an unresolved revocation
check. Bound certificate-only material without enough revocation coverage records
`validation_material` as `not_run` with `validation_material_unavailable`.
An authenticated OCSP `unknown` about a covered non-anchor certificate (one in a
signer or TSA chain) records `not_run` with `revocation_status_unknown`. An
`unknown` about any other certificate says nothing about the chain and changes
nothing: material unrelated to the chain never changes a genuine result. An
`unknown` names a certificate by issuer and serial number, so it counts for the
chain certificate with that issuer and serial even when it binds first to
another certificate (a second encoding, or a second certificate with the same
serial).
These typed findings appear in `checks`; the `reasons` list holds failed-check
reasons, plus `validation_material_possible_tampering` (below). A `not_run` check
rolls up to an indeterminate verdict, never a passed B-LT/B-LTA
validation-material check.

The rule, by cause:
- Missing or authenticated-unknown material is unavailable (`not_run`). Material
  that claims nothing about the signer's certificates is missing coverage: a DSS
  with no arrays, a present but empty array, a covered certificate missing from
  `/Certs` and the trust anchors, or a CRL from an unrelated issuer.
- Forged or unverifiable presented material is discarded. It supplies no
  coverage, and wherever the result would otherwise be unavailable or unknown it
  is `not_run` with `validation_material_possible_tampering`; beside complete
  genuine coverage it is disregarded, and the material passes. This covers a
  DSS, array or entry that does not parse (a reference cycle and an undecodable
  stream included); a CRL or OCSP response whose signature no key it claims
  verifies, or whose responder nobody presents; an unsuccessful or empty OCSP
  response; a CertID bound to no validation-set certificate; a CRL issuer
  without cRLSign or an OCSP responder without the delegation, EKU or key usage
  it needs; and a CRL signed by a shadow of a covered certificate's issuer. A
  `/Root` that cannot be read as a catalog reports the same, never absent.
- Genuine material that says no still fails (`fail`,
  `validation_material_invalid`): a CRL or OCSP response stale or future-dated at
  the applicable time, a delta or IDP-scoped CRL, an OCSP delegate outside its
  validity, and a revoked serial or status. Authenticity is judged first, so a
  forged response that claims any of these is unverifiable, never a failure.
  A failure outranks every unresolved result.

A CRL signed by a shadow of a covered certificate's issuer is forged. The shadow
carries the issuer's subject, did not sign the certificate, and holds a key no
trust anchor vouches for: no anchor carries that subject and key, and no anchor
or covered chain certificate issued a certificate for them. A CA's separate
CRL-signing key, a key rollover's link certificate and a same-subject anchored
CA are vouched for, so they are never shadows. A shadow reports possible
tampering wherever the result would otherwise be unavailable or unknown; beside
complete genuine coverage it is disregarded, and the material passes. When a
timestamp's root is unavailable, the retry that treats covered certificates as
provisional roots first re-reads the material under the real anchors at the
retry's time; a shadow found there, even one an earlier failure hid, is reported
as possible tampering, never as a missing trust root.

Anyone holding a signed PDF can append a DSS without breaking its signatures, so
presented material must not turn an unresolved check into a failed verdict. These
cases follow ETSI EN 319 102-1, which discards unusable revocation data and
reports INDETERMINATE: the verdict is indeterminate, and
`validation_material_possible_tampering` is always in `reasons`, so the user sees
the tampering sub-indication.

FIX row [SEAL-REPORT-EN-319-102-1-ROLLUP] holds the EN-aligned rollup for the
genuine failures (EN: TRY_LATER, REVOKED_NO_POE and the rest). Unknown status is
reported only after the whole response's binding, authorization, freshness and
signature checks pass. Seal-time OCSP gathering still accepts only all-good
responses covering the requested certificate.

An optional `/VRI` index does not preempt validation of the existing global DSS
certificate and revocation arrays. The verifier does not parse that index or add
an old-format reader. Global material is judged as above, and an index without
any global arrays does not establish validation material.

Rebuild and hash-pin the native seal organ to publish these three finding codes
and the possible-tampering reason. The report's shape is unchanged: `reasons`
stays a list of finding codes. No configuration or numerical policy changes.
