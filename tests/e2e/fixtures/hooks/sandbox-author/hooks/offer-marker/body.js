if (input.claim.value.phase === "safe") return { kind: "nothing" };
const withheld = await oneiron.read({ claim: input.claim.value.outsideClaim });
return { kind: "propose", claim: { subject: input.claim.subject,
  predicate: "hooksandbox.probe.effect", confidence: 1,
  value: { marker: "violet-author-offer", withheld, handle: input.claim.value.handle } } };
