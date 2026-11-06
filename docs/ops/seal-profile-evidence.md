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
not infer a reason from prose. The codes and organ reply shape are unchanged.

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

## Rollout

Use the matching engine/server and regenerated clients for the new manifest/view
fields. Rebuild and hash-pin the seal organ to publish the corrected verification
reason names. The organ's request schemas and degradation wire codes do not change.
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
report's top-level `reasons` remains failure-only. Rebuild and hash-pin the
native seal organ to publish this reporting change.
