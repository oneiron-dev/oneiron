# Nonce-spend persistence diagnostics

An admitted holder-proof nonce remains spent while its detached durable rows
are being recorded. If all existing three attempts fail, detector
`authority.nonce_spend.v1` records a critical `durable_write_failure` diagnostic.
This names a durable write failure, not a chain verification failure.

The new class uses the ordinary diagnostic codec and event-id derivation. The
class is part of the canonical body, so its corrected value also participates
in that body's existing content-derived id. Existing classes keep their wire
spellings and order; the closed vocabulary now contains 16 classes.

The nonce stays spent. The journal, replay protection, retry count, clock floors,
error handling and evidence fields are unchanged. Journal recovery failures
keep `chain_verify_failure`; they are a different finding. This adds no automatic
repair or retry route. Deploy the matching engine/store vocabulary together;
there is no migration, compatibility reader or new configuration.
