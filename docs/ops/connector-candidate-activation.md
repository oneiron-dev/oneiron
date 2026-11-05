# Activating a stored connector-pack Candidate

`vault.packs.connector.qualify` runs the host's real probes against the source
in the reviewed connector basis. The caller supplies the probe kit and optional
runtime recipe, never a qualification grade.

The request's `activate_candidate` choice controls which installation path runs:

- Omitted or `false`: keep the existing owner-put path. The engine builds an
  owner installation from the stored source files.
- `true`: activate the original stored connector Candidate. The install retains
  its hub reference and pin, publisher, and requested permissions. The source
  must still have that exact Candidate receipt when the install writer runs.

The explicit path accepts Candidates held for advisories, code admission, or
qualification. The owner accepts the advisories and admits the connector code;
real source-bound probe evidence must satisfy qualification. The install writer
still validates the current owner, the Candidate, publisher admission, and pack
screening. A failed or changed Candidate is not replaced with an owner put.

This choice does not grant connector authority. The existing pending-key check,
reviewed basis, observed manifest, live credential, slate, stamp and consent
checks remain. Connector qualification still follows its existing catalog door.

Connector Candidates with hooks keep the separate hook-replay qualification.
This path adds no script qualifier. The existing `/v1/owner/packs/activate` route
and native `activate_pack_candidate` method keep their advisories/organs behavior.

Use SDKs generated from the matching engine source to expose the new request
field. Native callers with a real `PackQualifier` can use
`activate_qualified_connector_pack_candidate` on the same stored source id.
