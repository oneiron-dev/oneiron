(() => {
  "use strict";
  const status = document.getElementById("status");
  const report = document.getElementById("report");
  const reading = document.getElementById("reading");
  const token = location.hash.slice(1);
  // The capability leaves the address bar and the history entry before any
  // request is made.
  history.replaceState(null, "", location.pathname);
  // Another QR opened in this tab changes only the fragment, which reruns
  // nothing here: reload, so its own capability is read, scrubbed and
  // checked, and no earlier report stays on the screen.
  window.addEventListener("hashchange", () => location.reload());
  const row = (label, value) => {
    const term = document.createElement("dt");
    term.textContent = label;
    const detail = document.createElement("dd");
    detail.textContent = value;
    report.append(term, detail);
  };
  const say = (text) => {
    const paragraph = document.createElement("p");
    paragraph.textContent = text;
    reading.append(paragraph);
  };
  const when = (seconds) => new Date(seconds * 1000).toISOString();
  // The owner let this QR download the sealed PDF: one button per item,
  // each posting the capability in its header, never in a URL.
  const download = (item) => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = `Download sealed item ${item + 1}`;
    button.addEventListener("click", () =>
      fetch("/esign/verify/pdf", {
        method: "POST",
        credentials: "omit",
        cache: "no-store",
        referrerPolicy: "no-referrer",
        headers: {
          "x-oneiron-esign-qr-capability": token,
          "content-type": "application/json",
        },
        body: JSON.stringify({ item }),
      })
        .then((response) =>
          response.ok ? response.blob() : Promise.reject(response.status),
        )
        .then((pdf) => {
          const link = document.createElement("a");
          link.href = URL.createObjectURL(pdf);
          link.download = `sealed-document-${item + 1}.pdf`;
          link.click();
          // A revoke at once can cancel the download in some browsers.
          setTimeout(() => URL.revokeObjectURL(link.href), 40000);
        })
        .catch(() => {
          status.textContent = "The sealed PDF is not available from this page.";
        }),
    );
    reading.append(button);
  };
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
        // Only a seal whose own verification passed commits: every
        // applicable check ran and passed on these bytes when they were
        // sealed. What the seal could not reach is listed beside it.
        row(
          `${name} verified when sealed`,
          item.self_verify === "passed"
            ? "every applicable check ran and passed"
            : `verification ${item.self_verify}`,
        );
        row(
          `${name} seal profile`,
          `${item.profile.achieved} of ${item.profile.requested}`,
        );
        for (const shortfall of item.profile.degraded) {
          row(`${name} not reached`, `${shortfall.requested}: ${shortfall.reason}`);
        }
      }
      // Trust and change are two different facts (ARCH-0064a section 9):
      // a reader without the signer's trust root never reads as a change.
      say(
        "If your PDF reader cannot validate the seal's signature, your reader does not have the trust root for this signer. That is a fact about your reader, not about the file.",
      );
      say(
        "If the SHA-256 of your copy differs from the item's SHA-256 above, this document was changed after signing. If it is the same, nothing has changed since it was sealed.",
      );
      // The QR capability is no possession factor: the sealed PDF is read
      // only through a party's own signing link (ARCH-0064a section 6),
      // unless the owner turned on this document's QR PDF download.
      if (page.pdf_download === true) {
        say(
          "The owner lets this page download the sealed PDF. Each party can also download the sealed copy from their own signing link.",
        );
        for (const item of page.items) download(item.item);
      } else {
        say(
          "This page never shows the signed PDF. Each party downloads the sealed copy from their own signing link.",
        );
      }
    })
    .catch(() => {
      status.textContent =
        "This verification link is not valid, was revoked, or has expired.";
    });
})();
