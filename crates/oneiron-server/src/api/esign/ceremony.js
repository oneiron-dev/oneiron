"use strict";
const token = location.hash.slice(1);
history.replaceState(null, "", location.pathname);
const status = document.getElementById("status");
const fields = document.getElementById("fields");
async function post(path, value) {
  const response = await fetch(path, {method: "POST", credentials: "omit", cache: "no-store", headers: {"Content-Type": "application/json"}, body: JSON.stringify({token, ...value})});
  if (!response.ok) throw new Error("The signing request is unavailable. Reopen the invitation or contact its sender.");
  return response;
}
async function action(value) {
  const result = await (await post("/sign/action", {action: value})).json();
  if (result.data?.item_count) {
    const select = document.getElementById("item");
    if (select.options.length !== result.data.item_count) {
      select.replaceChildren();
      for (let i = 0; i < result.data.item_count; i++) { const option = document.createElement("option"); option.value = i; option.textContent = `PDF ${i + 1}`; select.append(option); }
    }
  }
  if (result.outcome !== "page") { status.textContent = result.data?.status || result.outcome.replaceAll("_", " "); return result; }
  status.textContent = "Changes are saved as you fill each field.";
  document.getElementById("title").textContent = result.data.title;
  return result;
}
function report(error) { status.textContent = error.message; }
async function start() {
  const result = await action({action: "load"});
  if (result.outcome !== "page") return;
  for (const field of result.data.fields) {
    const row = document.createElement("label");
    row.append(document.createTextNode(field.meta.kind + (field.required ? " (required) " : " ")));
    const input = document.createElement(field.meta.kind === "select" ? "select" : "input");
    if (field.meta.kind === "select") {
      for (const text of field.meta.options) { const option = document.createElement("option"); option.value = text; option.textContent = text; input.append(option); }
    }
    const value = result.data.values[field.id]?.value;
    if (field.meta.kind !== "select") input.type = field.meta.kind === "checkbox" ? "checkbox" : ["signature", "initials"].includes(field.meta.kind) ? "file" : "text";
    if (input.type === "file") input.accept = "image/png,image/jpeg";
    if (input.type === "checkbox") input.checked = value?.value === true;
    else if (input.type !== "file") input.value = value?.value || "";
    const save = async () => {
      let next;
      if (input.type === "file") {
        const file = input.files[0]; if (!file) return;
        if (file.size > 2 * 1024 * 1024) throw new Error("Use a PNG or JPEG image under 2 MiB.");
        const data = await new Promise((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(reader.result); reader.onerror = reject; reader.readAsDataURL(file); });
        const image = await (await post("/sign/image", {png_or_jpeg_base64: data.split(",")[1]})).json();
        next = {kind: "signature", value: {image_ref: image.image_ref}};
      } else next = input.type === "checkbox" ? {kind: "checked", value: input.checked} : {kind: "text", value: input.value};
      const saved = await action({action: "save_field", field: field.id, value: next});
      const actual = saved.data?.values?.[field.id]?.value;
      if (actual?.kind === "text") input.value = actual.value;
      if (actual?.kind === "signature") status.textContent = "Signature image saved.";
    };
    input.addEventListener("change", () => save().catch(report));
    row.append(input); fields.append(row, document.createElement("br"));
    if (field.meta.kind === "date") { input.readOnly = true; if (!result.data.values[field.id]) await save(); }
  }
}
document.getElementById("complete").onclick = () => action({action: "complete", consent: document.getElementById("consent").checked, next: null}).catch(report);
document.getElementById("reject").onclick = () => { const reason = prompt("Reason for rejection"); if (reason !== null) { const text = reason.trim(); if (!text || new TextEncoder().encode(text).length > 4096) { status.textContent = "Give a non-empty reason of at most 4096 bytes."; return; } action({action: "reject", reason: text}).catch(report); } };
document.getElementById("download").onclick = async () => { try { const response = await post("/sign/pdf", {item: Number(document.getElementById("item").value || 0)}); const url = URL.createObjectURL(await response.blob()); const link = document.createElement("a"); link.href = url; link.download = `document-${Number(document.getElementById("item").value || 0) + 1}.pdf`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); } catch (error) { report(error); } };
start().catch(report);
