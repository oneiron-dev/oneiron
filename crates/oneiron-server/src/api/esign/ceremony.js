"use strict";
const UNAVAILABLE = "The signing request is unavailable. Reopen the invitation or contact its sender.";
const fragment = location.hash;
const fragmentToken = fragment.match(/^#([0-9a-f]{64})$/);
// The public link carries its capability in the fragment, which no request
// target holds, so no server or proxy log sees it (F37). It must not remain
// in browser history or in referrers either. The page trades it once, in the
// x-oneiron-esign-capability header, for a single-use exchange; a top-level
// form POST consumes that and opens the signing session, which lands at its
// ceremony's address, /sign?ceremony=<id> (ARCH-0064a [SGN-03]). Every later
// call names that ceremony, and carries the HttpOnly cookie named for it, so
// this page acts only on the ceremony it shows, whatever invitation another
// tab opens. The page never holds the session itself.
const ceremonyMatch = (location.search || "").match(/^\?ceremony=([0-9a-f]{32})$/);
const ceremony = ceremonyMatch ? ceremonyMatch[1] : null;
history.replaceState(null, "", ceremony ? `/sign?ceremony=${ceremony}` : "/sign");
// Another invitation opened in this tab changes only the fragment, which
// reruns nothing here: reload, so it starts its own ceremony, never this one.
window.addEventListener("hashchange", () => location.reload());
const status = document.getElementById("status");
const fields = document.getElementById("fields");
async function send(path, contentType, body) {
  const response = await fetch(path, {method: "POST", credentials: "same-origin", cache: "no-store", headers: {"Content-Type": contentType, "x-oneiron-sign-ceremony": ceremony}, body});
  if (!response.ok) throw new Error(UNAVAILABLE);
  return response;
}
async function openSession(capability) {
  const response = await fetch("/sign/exchange", {method: "POST", credentials: "same-origin", cache: "no-store", headers: {"x-oneiron-esign-capability": capability}});
  if (!response.ok) throw new Error(UNAVAILABLE);
  const {exchange} = await response.json();
  const form = document.createElement("form");
  form.method = "POST";
  form.action = "/sign/session";
  const field = document.createElement("input");
  field.type = "hidden";
  field.name = "exchange";
  field.value = exchange;
  form.append(field);
  document.body.append(form);
  form.submit();
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
// A link opens its session and comes back at its ceremony's address with no
// fragment, and runs on that ceremony's session. A malformed fragment, or a
// page with no ceremony, sends nothing.
if (fragmentToken) openSession(fragmentToken[1]).catch(report);
else if (fragment || !ceremony) report(new Error(UNAVAILABLE));
else start().catch(report);
