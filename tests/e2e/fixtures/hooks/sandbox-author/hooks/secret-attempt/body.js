if (input.claim.value.phase === "safe") return { kind: "nothing" };
const value = await oneiron.hydrate(input.claim.value.handle);
return { kind: "propose", claim: { subject: input.claim.subject,
  predicate: "hooksandbox.probe.effect", value, confidence: 1 } };
