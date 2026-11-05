# OpenCode runner-seat quota errors

The registered OpenCode runner uses `run --format json`. Its terminal JSONL
API error carries the provider message under `error.data.message`, inside
`type: "error"` and `error.name: "APIError"`. The runner-seat reader projects
that message into the existing native limit classifier before the generic
error branches. Other shapes keep those generic branches unchanged.

This shape was verified from the installed official OpenCode 1.18.35 emitter,
APIError schema and retry-header reader. It is not an inference from a live
quota-driving run. The session-error path emits the event on stdout and exits
with failure. Automatic seat classification still runs only for failed
attempts, reads stdout before stderr and keeps the last recognized limit in
each stream. Successful, cancelled, tool-use and warning events are unchanged.

Only the existing native limit words determine whether the message names a
spent seat. The native credit/window/rate-limit classification and owner-picked
seat policy remain in use. Neither `statusCode` nor `isRetryable` introduces a
new gate or selects a kind. Recognizing the error does not authorize a paid
fallback or change a grant.

Numeric `retry-after-ms` takes precedence over numeric `retry-after`. The first
uses milliseconds; the second uses seconds. A finite nonnegative value is
rounded up to native whole seconds, including a genuine zero wait. A value
outside that native integer range stays unknown instead of saturating to an
invented wait. The optional actual `responseBody` remains available to the
unchanged ISO reset-time scanner; message bar-epoch resets remain unchanged.

HTTP-date retry headers, human duration text, Free-only wording that lacks the
existing limit words and unverified Claude/Codex emission shapes are not newly
recognized. They remain FIX705 residuals, not a claim that all OpenCode or
other official CLI quota errors are handled. No fallback reset or wait is
invented. No argv, thresholds, defaults, caps, public types or storage format
change.
