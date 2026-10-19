"use strict";
const fragmentToken = location.hash.match(/^#([0-9a-f]{64})$/);
const token = fragmentToken ? fragmentToken[1] : "";
// The public link carries its capability in the fragment, which no request
// target holds, so no server or proxy log sees it (F37). It must not remain
// in browser history or in referrers either. Every later call carries it in
// the x-oneiron-esign-capability header, never in a body (FIX 3808).
history.replaceState(null, "", "/sign");
// Another invitation opened in this tab changes only the fragment, which
// reruns nothing here: reload, so it starts its own ceremony, never this one.
window.addEventListener("hashchange", () => location.reload());
const status = document.getElementById("status");
const fields = document.getElementById("fields");
async function send(path, contentType, body) {
  const response = await fetch(path, {method: "POST", credentials: "omit", cache: "no-store", headers: {"Content-Type": contentType, "x-oneiron-esign-capability": token}, body});
  if (!response.ok) throw new Error("The signing request is unavailable. Reopen the invitation or contact its sender.");
  return response;
}
function post(path, value) { return send(path, "application/json", JSON.stringify(value)); }
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
const imageURLs = new Map();
async function refreshPreview() {
  const model = await (await post("/sign/preview", {item:Number(document.getElementById("item").value || 0)})).json();
  for (const field of model.fields) {
    for (const mark of field.marks) {
      if (mark.kind === "signature" && !imageURLs.has(mark.image_ref)) {
        const response = await post("/sign/signature", {image_ref:mark.image_ref});
        imageURLs.set(mark.image_ref, URL.createObjectURL(await response.blob()));
      }
    }
  }
  EsignFieldRenderer.preview(document.getElementById("preview"), model, ref => imageURLs.get(ref));
}
async function start() {
  if (!/^[0-9a-f]{64}$/.test(token)) throw new Error("The signing request is unavailable. Reopen the invitation or contact its sender.");
  const result = await action({action:"load"});
  if (result.outcome !== "page") return;
  for (const presentation of result.data.presentations) {
    const save = async input => {
      try {
        let next;
        if (presentation.control.kind === "signature") {
          const file=input.files[0]; if (!file) return;
          const image=await (await send("/sign/image",file.type||"application/octet-stream",file)).json();
          next={kind:"signature",value:{image_ref:image.image_ref}};
        } else next=presentation.control.kind==="checkbox"?{kind:"checked",value:input.checked}:{kind:"text",value:input.value};
        const saved=await action({action:"save_field",field:presentation.id,value:next});
        const actual=saved.data?.values?.[presentation.id]?.value;
        if (actual?.kind==="text") input.value=actual.value;
        await refreshPreview();
      } catch (error) {report(error);}
    };
    const {row,input}=EsignFieldRenderer.control(presentation,save);fields.append(row);
    if (presentation.control.server_computed && !presentation.value) await save(input);
  }
  await refreshPreview();
}
document.getElementById("item").onchange=()=>refreshPreview().catch(report);
window.addEventListener("pagehide",()=>{for(const url of imageURLs.values())URL.revokeObjectURL(url);imageURLs.clear();});
document.getElementById("complete").onclick = () => action({action: "complete", consent: document.getElementById("consent").checked, next: null}).catch(report);
document.getElementById("reject").onclick = () => { const reason = prompt("Reason for rejection"); if (reason !== null) { const text = reason.trim(); if (!text) { status.textContent = "Give a reason for the rejection."; return; } action({action: "reject", reason: text}).catch(report); } };
document.getElementById("download").onclick = async () => { try { const response = await post("/sign/pdf", {item: Number(document.getElementById("item").value || 0)}); const url = URL.createObjectURL(await response.blob()); const link = document.createElement("a"); link.href = url; link.download = `document-${Number(document.getElementById("item").value || 0) + 1}.pdf`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); } catch (error) { report(error); } };
start().catch(report);
