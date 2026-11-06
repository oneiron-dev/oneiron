# Scoped Session summary pages

A Session summary first uses its normal request and schema corrections. If the
known input window requires pages, every page reads the original source text.
Pages never read another page's generated summary as their input.

When an OpenAI-style HTTP 400 error has a bounded message, its native
`InvalidRequestDetail` also keeps the provider's structured `/error/code`, if
present. Generic request errors keep their existing terminal and fallback rules.

If a **paid schema correction** returns the exact structured code
`context_length_exceeded`, a Session summary with a known window tries a smaller
page layout. It halves the previous layout window and re-tiles all the same source
evidence. The new layout has its own composition identity. Earlier completed
calls and rejected replies remain paid; shrinking never refunds their usage.
The existing deadline still applies. A layout that cannot hold a source character
uses the existing Retry park. No source text, rejected reply or schema is truncated.

This recovery is conditional on the provider actually returning that structured
HTTP error code. It does not infer overflow from error prose, a generic 400 or an
output-length finish reason. Unknown windows and other error codes retain their
previous behavior. Provider-specific tokenizers, output reservations and windows
of individual fallback rungs are separate limitations.
