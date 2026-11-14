# Gmail import pacing

Gmail gives one user of a new Google Cloud project 6,000 quota units a minute
and 2,500 MB of downloads a day (ARCH-0027 #mail-drive, from RESEARCH-1393
#quotas). Each call costs units: a listing page 5, a metadata read 20, a full
or raw read 60, a history page 2, an attachment 20, and the profile and the
send-as list 1. A big mailbox copy can run out of bytes for the day before it
runs out of units.

Each import step (the host's 300 s pass, or the owner's
`vault.mail.sources.sync`) reads Gmail through a meter that charges every
request before it is made and counts the bytes of every answer. That includes
the requests one call makes past its first: a text part Gmail keeps apart is
read as an attachment (20), and the credential check before a step's first call
reads the profile (1). A label change in the change feed is read again as a
metadata read (20). The meter's windows are kept on the source, so the host's
steps and the owner's steps share them, and a restart does not reset them. One
source's steps run one at a time: a second step waits for the first to end, so
neither overwrites the other's charges or its rest.

- The change feed (`history.list` and the anchor) may spend the whole minute.
- The copy (the newest-first listing, bodies, opened attachments) spends at most
  4,500 units of it, so new mail still reads while a big mailbox copies.
- A call runs only while the day still has room for the largest answer the wire
  reads (32 MiB), so a step never crosses the 2,500 MB cap.
- Gmail's 429, or its 403 with the reason `rateLimitExceeded` or
  `userRateLimitExceeded`, rests the source for 60 s.

A step that runs out stops there. What landed stays, and the step answers
`quota_paused_until` with no error. A step that stops part-way through a
change-feed page keeps how far it got; the next step reads the page again and
goes on after the changes already applied, a message the copy setting skips
included. `vault.mail.sources.sync_status` shows the
same time, and its `last_error` stays empty. Until that time the host's pass
skips the source, and a step of it makes no Gmail call.

Microsoft Graph, IMAP and calendar sources declare no quota, so the meter does
not charge them.
