const original = input.args;
const args = { ...original, scope: { ...original.scope } };
args.value = { marker: "copper-scope-rewrite", fact: "the copper key turns at noon" };
if (original.value.mode === "invalid") args.confidence = "not-a-number";
if (original.value.mode === "world") args.scope.world_id = original.value.target;
if (original.value.mode === "facet") args.scope.scope_facet_id = original.value.target;
if (original.value.mode === "project") args.scope.scope_project_id = original.value.target;
return { kind: "rewrite", args };
