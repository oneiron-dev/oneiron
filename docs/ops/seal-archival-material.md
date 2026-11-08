# Archival timestamp validation material

A B-LTA seal must embed validation material for the TSA chain selected by its
final document timestamp. The signature-time TSA and archival TSA can differ,
even when the configured endpoint stays the same.

The native seal keeps its original signed revision and complete B-LT material.
If a fitting archival token selects a chain not already covered by that
material or configured trust anchors, the seal gathers the missing certificates'
revocation evidence. It keeps the earlier signer and signature-time TSA evidence,
and adds new certificates, CRLs and OCSP responses without replacing old material.
Already covered certificates do not need another network fetch.

The seal rebuilds DSS from that same signed revision. Changing DSS changes the
document timestamp imprint, so it requests a fresh token. A final timestamp is
published only when its actual selected chain is covered. Another newly selected
chain follows the same path. The signing backend is not called again for a DSS
rebuild. TSA ordering and the timestamp capacity ladder are unchanged.

If archival timestamping or its missing validation evidence is unavailable, the
seal keeps the valid B-LT document and reports `DocumentTimestampUnavailable`.
Memory refusals stay typed seal errors, not TSA failover or profile degradation.
This path uses the existing seal memory ledger and fetch policy. It introduces
no retry count, timeout, resource limit or endpoint pinning.

The native seal organ must be rebuilt to use this behavior. There is no wire,
SDK, configuration or stored-record change.
