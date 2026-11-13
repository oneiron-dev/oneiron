(() => {
  "use strict";
  const status = document.getElementById("status");
  const report = document.getElementById("report");
  const token = location.hash.slice(1);
  // The capability leaves the address bar and the history entry before any
  // request is made.
  history.replaceState(null, "", location.pathname);
  const row = (label, value) => {
    const term = document.createElement("dt");
    term.textContent = label;
    const detail = document.createElement("dd");
    detail.textContent = value;
    report.append(term, detail);
  };
  const when = (seconds) => new Date(seconds * 1000).toISOString();
  if (!/^[0-9a-f]{64}$/.test(token)) {
    status.textContent = "This verification link is not valid.";
    return;
  }
  fetch("/esign/verify/report", {
    method: "POST",
    credentials: "omit",
    cache: "no-store",
    referrerPolicy: "no-referrer",
    headers: { "x-oneiron-esign-qr-capability": token },
  })
    .then((response) =>
      response.ok ? response.json() : Promise.reject(response.status),
    )
    .then((page) => {
      status.textContent =
        page.outcome === "completed"
          ? "This document was signed and sealed."
          : "This document was rejected, and the rejection was sealed.";
      row("Document", page.title);
      row("Sealed at", when(page.sealed_at));
      row("Audit chain SHA-256", page.audit_chain_sha256);
      for (const signer of page.signers) {
        row(`Signed (${signer.role})`, `${signer.name}, ${when(signer.signed_at)}`);
      }
      for (const item of page.items) {
        const name = `Item ${item.item + 1}`;
        row(`${name} SHA-256`, item.sha256);
        row(
          `${name} seal`,
          `${item.profile.achieved} of ${item.profile.requested}; self-verification ${item.self_verify}`,
        );
        for (const shortfall of item.profile.degraded) {
          row(`${name} not reached`, `${shortfall.requested}: ${shortfall.reason}`);
        }
      }
    })
    .catch(() => {
      status.textContent =
        "This verification link is not valid, was revoked, or has expired.";
    });
})();
