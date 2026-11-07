if (input.claim.value.phase === "safe") return { kind: "nothing" };
return { kind: "propose", claim: { subject: input.claim.subject,
  predicate: "hooksandbox.probe.effect", value: { marker: "violet-kind-escape" }, confidence: 1 } };
