# Known-CSAM Hosted Media Response

This runbook covers knowledge-based response for suspected or confirmed known
CSAM in media hosted or relayed by Oneiron-operated infrastructure. It does not
create a proactive scanning claim; the current v1 implementation ships only an
empty hash-match provider seam for hosted-media ingest.

## Triggers

Act under this runbook when Oneiron gains knowledge through an abuse report,
operator discovery, law-enforcement notice, or a future vetted hash-match
provider result. Cloudflare-proxied public-surface scanning is out of scope for
this runbook.

## Immediate Response

1. Remove public access to the hosted or relayed media.
2. Preserve the relevant evidence needed for reporting and follow-up, including
   media identifiers, content hash, route or artifact pointer, timestamps,
   reporter contact if supplied, and access-control state.
3. Do not redistribute the media internally. Limit access to personnel handling
   the report.
4. Record an operator timeline: when the report arrived, when public access was
   removed, what was preserved, and what notices were filed.

## Reporting

Use the narrowest applicable reporting path based on the known infrastructure
and account nexus.

- United States nexus: file the required report with NCMEC under the
  report-on-knowledge workflow.
- Japan nexus: report to police and submit the voluntary notice path through the
  Internet Hotline Center.
- Vultr-hosted infrastructure: notify Vultr through its AUP abuse channel with
  the preserved identifiers and removal status.

Do not state that Oneiron has live access to NCMEC, IWF, PhotoDNA, Safer, Google
Child Safety API, or other vetted-access hash lists unless that access has been
approved and deployed.

## Preservation Notes

Preservation is for abuse handling, required reporting, and counsel-directed
follow-up. Keep the preserved record minimal and access-controlled. If the
report is later determined to be unrelated to this runbook, close the incident
with that determination and retain only the normal abuse-response audit record.

## Open Items

- U5: JP-entity-on-US-owned-host nexus remains counsel-confirm. Until counsel
  confirms otherwise, treat the case as requiring both the relevant JP reporting
  path and US-nexus assessment before closing the incident.
