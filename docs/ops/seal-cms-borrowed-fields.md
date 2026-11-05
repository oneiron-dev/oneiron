# Borrowed CMS attribute fields

The native CMS attribute reader borrows its OID bytes and the ESSCertIDv2
certificate-hash, issuer-name DER and serial-number TLV from the input DER.
The caller keeps that input for every comparison. These fields no longer
allocate separate vectors before the operation can account for them.

The same strict DER reader still checks the original tags, single-value and
single-certificate shapes, trailing bytes and issuerSerial directoryName.
The original baseline attribute allowlist, signer SID consistency, certificate
hash, issuer/serial checks and signature algorithms are unchanged. No memory
refusal is converted into a malformed-attribute result: this slice removes the
copies rather than adding a new allocation or refusal path.

This is only the borrowed-field slice of FIX 8452 / FIX 12780. Owned CMS parse
results, certificate decode interiors, other working containers, allocator
slack and retained outputs remain outside this slice. It makes no whole-heap,
compile, runtime or speed claim. No new ledger, cap, default, policy, public
API, wire format or dependency is introduced.
